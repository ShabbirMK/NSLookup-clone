import struct
from random import randint


class DnsQueryBuilder:

    def __init__(self):
        self.url = ""
        self.rtype = "A"
        self.reverse = False
        self.q_id = randint(0, 65535)
        self.length = 0

    def build_query_packet(self, url, rtype, recurse):
        '''
        The function builds the query for the entered URL and type
        of query. The query has a format in which it is made. The
        '''
        query_packet = struct.pack(">H", self.q_id)  # Query Ids

        '''Making the query allow for non-authoritative response'''
        if not recurse:
            query_packet += struct.pack(">H", 256)
        else:
            query_packet += struct.pack(">H", 384)

        '''Remaining values are generic and default values for query'''
        query_packet += struct.pack(">H", 1)
        query_packet += struct.pack(">H", 0)
        query_packet += struct.pack(">H", 0)
        query_packet += struct.pack(">H", 0)

        split_url = url.split(".")
        try:
            '''If reverse, the split_url will be int, this block will be used'''
            if isinstance(int(split_url[0]), int):
                split_url = split_url[::-1]
                split_url.append('in-addr')
                split_url.append('arpa')
                self.url = '.'.join(split_url)
                for split in split_url:
                    query_packet += struct.pack('B', len(split))
                    for byte in split:
                        query_packet += struct.pack('c', byte.encode('utf-8'))
            query_packet += struct.pack("B", 0)
            '''End of string is achieved above'''
            '''For inverse, the Query Type has been added hard-coded'''
            query_packet += struct.pack(">H", 12)
            query_packet += struct.pack(">H", 1)  # Query Class
            self.reverse = True

        except ValueError:
            self.url = url
            for part in split_url:
                query_packet += struct.pack("B", len(part))
                for byte in part:
                    query_packet += struct.pack("c", byte.encode('utf-8'))
            query_packet += struct.pack("B", 0)  # End of String

            '''
            Options omitted are the obsolete and experimental ones:
            MD ==> 3
            MF ==> 4
            MB ==> 7
            MG ==> 8
            MR ==> 9
            NULL ==> 10
            '''
            if rtype == b"NS":
                query_packet += struct.pack(">H", 2)
            elif rtype == b"CNAME":
                query_packet += struct.pack(">H", 5)
            elif rtype == b"SOA":
                query_packet += struct.pack(">H", 6)
            elif rtype == b'WKS':
                query_packet += struct.pack(">H", 11)
            elif rtype == b'PTR':
                query_packet += struct.pack(">H", 12)
            elif rtype == b'HINFO':
                query_packet += struct.pack(">H", 13)
            elif rtype == b'MINFO':
                query_packet += struct.pack(">H", 14)
            elif rtype == b"MX":
                query_packet += struct.pack(">H", 15)
            elif rtype == b"TXT":
                query_packet += struct.pack(">H", 16)
            elif rtype == b'RP':
                query_packet += struct.pack(">H", 17)
            elif rtype == b'AFSDB':
                query_packet += struct.pack(">H", 18)
            elif rtype == b'X25':
                query_packet += struct.pack(">H", 19)
            elif rtype == b'ISDN':
                query_packet += struct.pack(">H", 20)
            elif rtype == b'RT':
                query_packet += struct.pack(">H", 21)
            elif rtype == b'NSAP':
                query_packet += struct.pack(">H", 22)
            elif rtype == b'NSAP-PTR':
                query_packet += struct.pack(">H", 23)
            elif rtype == b'SIG':
                query_packet += struct.pack(">H", 24)
            elif rtype == b'KEY':
                query_packet += struct.pack(">H", 25)
            elif rtype == b'PX':
                query_packet += struct.pack(">H", 26)
            elif rtype == b'GPOS':
                query_packet += struct.pack(">H", 27)
            elif rtype == b"AAAA":
                query_packet += struct.pack(">H", 28)
            else:
                query_packet += struct.pack(">H", 1)

            query_packet += struct.pack(">H", 1)  # Query Class

        self.length = len(query_packet)
        return query_packet


if __name__ == '__main__':
    print('This is the file for the query class, run dns.py instead')
