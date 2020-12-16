# NSLookup-clone

Our version of NSlookup currently supports for the following options:
-> port (port)
-> query type (rtype)
-> timeout (timeout)
-> dns (dns_ip)
-> recurse (recurse)

The types of query that our version supports include:
	-> A
	-> NS
	-> CNAME
	-> SOA
	-> PTR
-> HINFO
-> MINFO
-> MX
-> TXT
-> WKS
-> RP
-> AFSDB
-> X25
-> ISDN
-> RT
-> NSAP
-> NSAP-PTR
-> SIG
-> KEY
-> PX
-> GPOS
-> AAAA
-> ANY

Of the above mentioned ones, the more commonly used options are:
-> A
-> NS
-> CNAME
-> SOA
-> PTR
-> MX
-> TXT
-> AAAA
-> ANY

Important Note:
	
  1. The above have been implemented thoroughly however due to not having much information
	about the rest, we cannot for sure say that the other options function correctly.
  2. The additional records do not get correctly displayed.

The syntax for our version of nslookup is as follows:
  python dns.py --rtype=A --dns_ip=1.1.1.1 --port=53 --timeout=10 --recurse=0 google.com 

Defaults:
-> If rtype is not mentioned then, it will be the 'A' and 'AAAA' answer.
-> If dns IP is not provided, it will get the localhost dns IP from /etc/resolv.conf
-> If the port is not mentioned, it is 53 by default.
-> The timeout is by default taken as 5 seconds.
-> The query is non-recursive by default, to set it to recursive set it to 1.

The modules used are as follows:
-> socket: For creating a UDP socket for the data transmition. 
-> argparse: For command-line argument parsing
-> sys: For getting the exit function to exit the function in case of some failure

The package is consisting of:
-> dns.py: The main driver file responsible for creating the UDP socket and pretty-printing the DNS answer
-> response.py: It has the DnsResponseBuilder class that has the functions parse the DNS answer
-> query.py: It has the DnsQueryBuilder class that is used to create the query packet containing the DNS Question
