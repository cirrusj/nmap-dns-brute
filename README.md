dns-brute.nse is an Nmap script that will brute-force DNS names for a given domain. The script can:

* Use a file containing list of host to try
* Reverse DNS the identified C-Classes in order to discover more DNS names for the domain
* Use multiple threads for the DNS resolving
* Add discovered targets to the Nmap scanning queue

More info in the Usage wiki page
