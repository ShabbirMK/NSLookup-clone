import socket
import argparse
from sys import exit
from response import DnsResponseBuilder
from query import DnsQueryBuilder
'''
https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
Most commonly used types are:
-> A
-> AAAA
-> NS
-> MX
-> TXT
-> SOA
-> PTR
'''

# Defining certain global parameters
port_number = 53
error_flag = 0
time_out = 50
mismatch_error = False
any_flag = False
list_of_choices = ["A", "NS", "CNAME", "SOA", "PTR", "HINFO",
                   "MINFO", "MX", "TXT", "WKS", "RP", "AFSDB",
                   "X25", "ISDN", "RT", "NSAP", "NSAP-PTR",
                   "SIG", "KEY", "PX", "GPOS", "AAAA", "ANY"]


def get_default():
    dns = open('/etc/resolv.conf')

    for line in dns.readlines():
        if line != '\n' and line[0] != '#':
            data = line.split()
            if data[0] == 'nameserver':
                return data[1]

    return '127.0.0.53'


def args_handler():
    '''
    Function handles commandline arguments
    It is also the driver function
    this is also helps to give proper arguents hence improves efficinecy
    argparse() module is used for this purpose.
    '''
    p = argparse.ArgumentParser(description='Nslookup by Shabbir and Sushant')
    p.add_argument('url', help='Enter URl for DNS Query ')
    p.add_argument('--dns_ip', default=get_default(),
                   help='IP Adress of DNS Server, eg: --dns_ip=127.0.0.53')
    p.add_argument('--rtype', default="default", choices=list_of_choices,
                   type=str.upper, help='Request Query type, eg: --rtype MX')
    p.add_argument('--port', default=53, help='Port number of the DNS server, \
                    eg: --port=53')
    p.add_argument('--timeout', default=50, help='Time-out period for the answer, \
                    eg: --timeout=50')
    p.add_argument('--recurse', default=False, help='Type of query: Recursive and \
                    Non-Recursive eg: --recurse=0')
    args = p.parse_args()
    # Now, we want to get the responses
    main(args)


def main(args):
    '''
    Function that handles the arguments,
    Creates the socket and
    Prints all the output
    '''
    # First we obtain data regarding the dns server i.e. its name.
    global port_number, time_out
    port_number = int(args.port)
    time_out = int(args.timeout)
    print('Server: {}'.format(args.dns_ip))
    print('Address: {}#{}\n'.format(args.dns_ip, port_number))
    # Encoding the into arguments into byte format for use
    url = args.url
    dns = args.dns_ip.encode('utf-8')
    port_number = int(args.port)
    time_out = int(args.timeout)
    recurse = int(args.recurse)
    if args.rtype == 'DEFAULT' and not url[0].isnumeric():
        rtype = 'A'.encode('utf-8')
        get_response(url, dns, port_number, rtype, time_out, recurse)
        rtype = 'AAAA'.encode('utf-8')
        get_response(url, dns, port_number, rtype, time_out, recurse)

    elif args.rtype == 'ANY' and not url[0].isnumeric():
        global any_flag
        any_flag = True
        rtype = 'A'.encode('utf-8')
        get_response(url, dns, port_number, rtype, time_out, recurse)
        rtype = 'NS'.encode('utf-8')
        get_response(url, dns, port_number, rtype, time_out, recurse)
        rtype = 'SOA'.encode('utf-8')
        get_response(url, dns, port_number, rtype, time_out, recurse)
        rtype = 'MX'.encode('utf-8')
        get_response(url, dns, port_number, rtype, time_out, recurse)
        rtype = 'TXT'.encode('utf-8')
        get_response(url, dns, port_number, rtype, time_out, recurse)
        rtype = 'AAAA'.encode('utf-8')
        get_response(url, dns, port_number, rtype, time_out, recurse)

    else:
        rtype = args.rtype.encode('utf-8')
        # Then we obtain data regarding the the requested URL.
        get_response(url, dns, port_number, rtype, time_out, recurse)


def get_response(url, dns, port=53, rtype='A', timeout=50, recurse=False):
    '''
    Main function to get the response and
    format it into required format
    It requires:
        The url
        The dns server to connect
        The Port number of the Dns server
    '''
    builder = DnsQueryBuilder()
    packet = builder.build_query_packet(url, rtype, recurse)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 8888))

    try:
        sock.settimeout(timeout)

    except Exception:
        global error_flag
        if error_flag == 0:
            error_flag = 1
            print('Connection Timed Out')
            exit()

    sock.sendto(bytes(packet), (dns, port))
    data, addr = sock.recvfrom(1024)
    decode_response(data, builder.length, builder.url, builder.q_id, rtype)
    sock.close()


def decode_response(data, length, url, q_id, rtype):

    response = DnsResponseBuilder(data, length, url, q_id)
    response.create_header()
    response.error_check()
    if response.is_valid:

        if (response.header['num_response'] == 0 and response.header['num_authority'] == 0):
            print('Non-authoritative answer:')
            print("*** Can't find {}: No answer\n".format(response.url))
            print('Authoritative answers can be found from here\n')

        else:
            response.parse()
            response.decode_response()
            mismatch(rtype, q_id)
            global any_flag
            if not any_flag:
                if (response.qtype == 1 or response.qtype == 28) and not mismatch_error:
                    print('Non-authoritative answer:')
                    print(response.answer)

                else:
                    if not response.header['auth_ans']:
                        print('Non-authoritative answer:')
                        if response.header['num_response']:
                            print(response.answer)

                        else:
                            print("*** Can't find {}: No answer\n".format(response.url))
                        print('Authoritative answers can be found from here')
                        if response.header['num_authority']:
                            print(response.answer)
                        elif response.header['num_additional'] != 0:
                            print(response.additional)
                        else:
                            print('\n')
                    else:
                        print('Authoritative answers can be found from here\n')
                        print(response.answer)
            else:
                print(response.answer)

    else:
        if response.error[0] == -1:
            print(response.error[1] + '\n')
        else:
            print('Error No.: {}\n{}'.format(
                response.error[0], response.error[1]))


def mismatch(typeofquery, typeofresponse):
    global mismatch_error
    if typeofquery == 28 and typeofresponse == 28:
        mismatch_error = True
    mismatch_error = False


if __name__ == "__main__":
    args_handler()
