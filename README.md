# NSLookup-clone

Our version of NSlookup currently supports for the following options:
1. port (port)
2. query type (rtype)
3. timeout (timeout)
4. dns (dns_ip)
5. recurse (recurse)

Of the above mentioned ones, the more commonly used options are:
1. A
2. NS
3. CNAME
4. SOA
5. PTR
6. MX
7. TXT
8. AAAA
9. ANY

Important Note:
	
  1. The above have been implemented thoroughly however due to not having much information
	about the rest, we cannot for sure say that the other options function correctly.
  2. The additional records do not get correctly displayed.

The syntax for our version of nslookup is as follows:
  python dns.py --rtype=A --dns_ip=1.1.1.1 --port=53 --timeout=10 --recurse=0 google.com 

Defaults:
1. If rtype is not mentioned then, it will be the 'A' and 'AAAA' answer.
2. If dns IP is not provided, it will get the localhost dns IP from /etc/resolv.conf
3. If the port is not mentioned, it is 53 by default.
4. The timeout is by default taken as 5 seconds.
5. The query is non-recursive by default, to set it to recursive set it to 1.

The modules used are as follows:
1. socket: For creating a UDP socket for the data transmition. 
2. argparse: For command-line argument parsing
3. sys: For getting the exit function to exit the function in case of some failure

The package is consisting of:
1. dns.py: The main driver file responsible for creating the UDP socket and pretty-printing the DNS answer
2. response.py: It has the DnsResponseBuilder class that has the functions parse the DNS answer
3. query.py: It has the DnsQueryBuilder class that is used to create the query packet containing the DNS Question
