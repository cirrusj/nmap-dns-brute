description = [[
Attempts to find an DNS hostnames by brute force guessing.
]]
-- 2011-01-26

---
-- @usage
-- nmap --script dns-brute --script-args dns-brute.domain=foo.com, dns-brute.threads=6, 
--	dns-brute.cclass, dns-brute.hostlist=./hostfile.txt, newtargets -sS -p 80
-- nmap --script dns-brute www.foo.com
-- @args dns-brute.hostlist The filename of a list of host strings to try.
-- @args dns-brute.threads Thread to use (default 5).
-- @args dns-brute.cclass If specified, adds the reverse DNS for the c-class of all discovered IP addresses. cclass can 
--	also be set to the value 'printall' to print all reverse DNS names instead of only the ones matching the base domain
-- @args dns-brute.domain Domain name to brute force if no host is specified
-- @args newtargets Add discovered targets to nmap scan queue (only applies when dns-brute.domain has been set)
-- @output
-- Pre-scan script results:
-- | dns-brute: 
-- | Result:
-- |   DNS Brute-force hostnames:
-- |   www.foo.com - 127.0.0.1
-- |   mail.foo.com - 127.0.0.2
-- |   blog.foo.com - 127.0.1.3
-- |   ns1.foo.com - 127.0.0.4
-- |   admin.foo.com - 127.0.0.5
-- |   Reverse DNS hostnames:
-- |   srv-32.foo.com - 127.0.0.16
-- |   srv-33.foo.com - 127.0.1.23
-- |   C-Classes:
-- |   127.0.0.0/24
-- |_  127.0.1.0/24

author = "cirrus"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"intrusive", "discovery"}

prerule = function()
	if nmap.registry.args['dns-brute.domain'] then
		local name = nmap.registry.args['dns-brute.domain']
		if(name:match("^(%d*)%.(%d*)%.(%d*)%.(%d*)$")) then
			return false
		else
			return true
		end
	else
		return false
	end
end

hostrule = function(host)
	return true
end


require 'dns'
require 'stdnse'
require 'target'

--- Parse a hostname and try to return a domain name
--@param host Hostname to parse
--@return Domain name
function parse_domain(host)
	local domainname = ''
	if(string.find(host,'%.')) then
		remove = string.sub(host,string.find(host,'%.')+1,string.len(host))
	else
		remove = host
	end
	if(string.find(remove,'%.')) then
		domainname = string.sub(host,string.find(host,'%.')+1,string.len(host))
	else
		domainname = host
	end
	return domainname
end

--- Remove the last octet of an IP address
--@param ip IP address to parse
--@return IP address without the last octet
function iptocclass(ip)
	local o1, o2, o3, o4 = ip:match("^(%d*)%.(%d*)%.(%d*)%.(%d*)$")
	return o1..'.'..o2..'.'..o3
end

--- Check if an element is inside a table
--@param table Table to check
--@param element Element to find in table
--@return boolean Element was found or not
function table.contains(table, element)
	if(type(table) == "table") then
		for _, value in pairs(table) do
			if value == element then
				return true
			end
		end
	end
	return false
end

--- Try to get the A record for a host
--@param host Hostname to resolve
--@result The A records or false
resolve = function (host)
	local dnsname = host..'.'..domainname
	status, result = dns.query(dnsname, {dtype='A',retAll=true})
	if(status == true) then
		return result
	else
		return false
	end
end

--- Convert an IP address to its in-addr.arpa notation
--@param ip IP address to convert
--@result The in-addr.arpa notation
function iprev(ip)
	local o1, o2, o3, o4 = ip:match("^(%d*)%.(%d*)%.(%d*)%.(%d*)$")
	return o4..'.'..o3..'.'..o2..'.'..o1..'.in-addr.arpa'
end

--- Try to get the PTR record for an in-addr.arpa address
--@param host Host to resolve
--@result The PTR records or false
revresolve = function (host)
	local ipaddress = iprev(host)
	status, result = dns.query(ipaddress, {dtype='PTR',retAll=true})
	if(status == true) then
		return result
	else
		return false
	end
end

--- Verbose printing function when -v flag is specified
--@param msg The message to print
print_verb = function(msg)
	local verbosity, debugging = nmap.verbosity, nmap.debugging
	if verbosity() >= 2 or debugging() > 0 then
		print(msg)
	end
end

thread_main = function( results, ... )
	local condvar = nmap.condvar( results )
	local what = {n = select("#", ...), ...}
	for i = 1, what.n do
		local res = resolve(what[i])
		if(res) then
			for _,addr in ipairs(res) do
				local hostn = what[i]..'.'..domainname
				if nmap.registry.args['dns-brute.domain'] and target.ALLOW_NEW_TARGETS then
					stdnse.print_debug("Added target: "..hostn)
					local status,err = target.add(hostn)
				end
				print_verb("Hostname: "..hostn.." IP: "..addr)
				results[#results+1] = { hostname=hostn, address=addr }
			end
		end
	end
end

reverse_main = function( revresults, ... )
	local condvar = nmap.condvar( revresults )
	local what = {n = select("#", ...), ...}
	for i = 1, what.n do
		local res = revresolve(what[i])
		if(res) then
			for _,host in ipairs(res) do
				if(revcclass == 'printall') then
					if(not string.match(host,'addr.arpa$')) then
						if nmap.registry.args['dns-brute.domain'] and target.ALLOW_NEW_TARGETS then
							stdnse.print_debug("Added target: "..what[i])
							local status,err = target.add(what[i])
						end
						print_verb("Hostname: "..host.." IP: "..what[i])
						revresults[#revresults+1] = { hostname=host, address=what[i] }
					end
				else
					if(string.match(host,domainname..'$')) then
						if nmap.registry.args['dns-brute.domain'] and target.ALLOW_NEW_TARGETS then
							stdnse.print_debug("Added target: "..what[i])
							local status,err = target.add(what[i])
						end
						print_verb("Hostname: "..host.." IP: "..what[i])
						revresults[#revresults+1] = { hostname=host, address=what[i] }
					end
				end
			end
		end
	end
end

action = function(host)
	if nmap.registry.args['dns-brute.domain'] then
		domainname = parse_domain(nmap.registry.args['dns-brute.domain'])
	else
		domainname = parse_domain(stdnse.get_hostname(host))
	end
	if not nmap.registry.bruteddomains then
		nmap.registry.bruteddomains = {}
	end
	if(not table.contains(nmap.registry.bruteddomains,domainname)) then
		table.insert(nmap.registry.bruteddomains, domainname)
		print_verb("Starting dns-brute at: "..domainname)
		local max_threads = nmap.registry.args['dns-brute.threads'] and tonumber( nmap.registry.args['dns-brute.threads'] ) or 5
		revcclass = stdnse.get_script_args("dns-brute.cclass") or false
		stdnse.print_debug("THREADS: "..max_threads)
		local fileName = nmap.registry.args['dns-brute.hostlist']
		local commFile = fileName and nmap.fetchfile(fileName)
		local hostlist
		if commFile then
			local file = io.open(commFile)
			if file then
				hostlist = {}
				while true do
					local l = file:read()
					if not l then
						break
					end
					if not l:match("#!comment:") then
						table.insert(hostlist, l)
					end
				end
				file:close()
			end
		end
		if (not hostlist) then	hostlist = {'www', 'mail', 'blog', 'ns0', 'ns1', 'mail2','mail3', 'admin','ads','ssh','voip','sip','dns','ns2','ns3','dns0','dns1','dns2','eshop','shop','forum','ftp', 'ftp0', 'host','log', 'mx0', 'mx1', 'mysql', 'sql', 'news', 'noc', 'ns', 'auth', 'administration', 'adserver', 'alerts', 'alpha', 'ap', 'app', 'apache', 'apps' ,'appserver', 'gw', 'backup', 'beta', 'cdn', 'chat', 'citrix', 'cms', 'erp', 'corp', 'intranet', 'crs', 'svn', 'cvs', 'git', 'db', 'database', 'demo', 'dev', 'devsql', 'dhcp', 'dmz', 'download', 'en', 'f5', 'fileserver', 'firewall', 'help', 'http', 'id', 'info', 'images', 'internal', 'internet', 'lab', 'ldap', 'linux', 'local', 'log', 'syslog', 'mailgate', 'main', 'manage', 'mgmt', 'monitor', 'mirror', 'mobile', 'mssql', 'oracle', 'exchange', 'owa', 'mta', 'mx', 'mx0', 'mx1', 'ntp', 'ops', 'pbx', 'whois', 'ssl', 'secure', 'server', 'smtp', 'squid', 'stage', 'stats', 'test', 'upload', 'vm', 'vnc', 'vpn', 'wiki', 'xml'} end
		local threads, results, revresults = {}, {}, {}
		results['name'] = "Result:"
		local condvar = nmap.condvar( results )
		local i = 1
		local howmany = math.floor(#hostlist/max_threads)+1
		if (howmany > 7900) then
			--Cannot unpack a list with more than 7900 items so we will set it to 7900
			stdnse.print_debug("Hostlist items per thread is more than 7900. Setting to 7900.")
			howmany = 7900
		end
		stdnse.print_debug("Hosts per thread: "..howmany)
		repeat
			local j = math.min(i+howmany, #hostlist)
			-- TODO: fix bug with very large hostlist on unpack
			threads[stdnse.new_thread( thread_main,results, unpack(hostlist, i, j)  )] = true
			i = j+1
		until i > #hostlist
		local done
		-- wait for all threads to finish
		while( not(done) ) do
			condvar("wait")
			done = true
			for thread in pairs(threads) do
				if (coroutine.status(thread) ~= "dead") then done = false end
			end
		end
		if revcclass then
			stdnse.print_debug("Running reverse DNS in identified c-classes")
			cclasses = {}
			ipaddresses = {}
			local i = 1
			for _, res in ipairs(results) do
				local class = iptocclass(res['address'])
				if(not table.contains(cclasses,class)) then
					print_verb("C-Class: "..class..".0/24")
					table.insert(cclasses,class)
				end
			end
			for _,class in ipairs(cclasses) do
				for v=1,254,1 do
					table.insert(ipaddresses, class..'.'..v)
				end
			end
			stdnse.print_debug("Will reverse lookup "..#ipaddresses.." IPs")
			local threads = {}
			local howmany_ip = math.floor(#ipaddresses/max_threads)+1
			local condvar = nmap.condvar( revresults )
			stdnse.print_debug("IP's per thread: "..howmany_ip)
			repeat
				local j = math.min(i+howmany_ip, #ipaddresses)	
				threads[stdnse.new_thread( reverse_main,revresults, unpack(ipaddresses, i, j)  )] = true
				i = j+1
			until i > #ipaddresses
			local done
			-- wait for all threads to finish
			while( not(done) ) do
				condvar("wait")
				done = true
				for thread in pairs(threads) do
					if (coroutine.status(thread) ~= "dead") then done = false end
				end
			end
		end
		response = {}
		response['name'] = "Result:"
		table.insert(response,"DNS Brute-force hostnames:")
		if(#results==0) then
			table.insert(response,"No results.")
		end
		for _, res in ipairs(results) do
			table.insert(response, res['hostname'].." - "..res['address'])
		end
		if revcclass then
			table.insert(response,"Reverse DNS hostnames:")
			if(#revresults==0) then
				table.insert(response,"No results.")
			end
			for _, res in ipairs(revresults) do
				table.insert(response, res['hostname'].." - "..res['address'])
			end
			if(#cclasses>0) then
				table.insert(response,"C-Classes:")
				for _, res in ipairs(cclasses) do
					table.insert(response, res..".0/24")
				end
			end
		end
		return stdnse.format_output(true, response)
	end
end

