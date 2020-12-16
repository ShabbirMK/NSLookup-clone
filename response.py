import struct


class DnsResponseBuilder():

    def __init__(self, data, query_length, url, q_id):
        self.header = {}
        self.records = []
        self.data = data
        self.is_valid = False
        self.length = query_length
        self.qtype = None
        self.url = url
        self.q_id = q_id
        self.additional = []
        self.answer = None

    def create_header(self):
        '''
        The DNS Header has exactly 12 butes, each equally divided into 2 bytes,
        namely identification number, flags, number of queries, number of
        responses, number of authoratative responses and number of additional
        answers
        '''
        tuple_data_dns = struct.unpack('!HHHHHH', self.data[:12])
        data_to_pass = {}
        identification = tuple_data_dns[0]
        '''
        Identifcation number to match the response with the query when
        multiple dns requests are made by the same machine.
        '''
        flags = tuple_data_dns[1]
        '''
        Flags contain 16-bits, and the order is:
        16 - QR (1 = Response)
        17, 20 - Opcode (0 = Standard Query, 1 = Inverse Query)
        21 - Authoratative flag (1 = Authoratative Answer)
        22 - Truncated flag (1 = Truncated)
        23 - Recursion desired (1 = Desired)
        24 - Recursion available (1 = Support available)
        25 - Z
        26, 27 - Not important for now
        28, 31 - Response code.
        '''
        data_to_pass['is_query'] = (flags & 32768) != 0
        data_to_pass['opcode'] = (flags & 30720) >> 11
        data_to_pass['auth_ans'] = (flags & 1024) != 0
        data_to_pass['truncated'] = (flags & 512) != 0
        data_to_pass['recursion_wanted'] = (flags & 256) != 0
        data_to_pass['recursion_supported'] = (flags & 128) != 0
        data_to_pass['present_in_zone'] = not(bool((flags & 112) >> 4))
        data_to_pass['rcode'] = flags & 15
        data_to_pass['identification'] = identification
        data_to_pass['num_queries'] = tuple_data_dns[2]
        data_to_pass['num_response'] = tuple_data_dns[3]
        data_to_pass['num_authority'] = tuple_data_dns[4]
        data_to_pass['num_additional'] = tuple_data_dns[5]
        self.header = data_to_pass

    def error_check(self):

        rcode = self.header['rcode']
        if rcode == 0:
            self.is_valid = True
            self.error = (0, 'NOERROR: Query Completed Successfully')

            if self.header['identification'] != self.q_id:
                self.error = (-1, 'Query ID and Response ID mismatch')
                self.is_valid = False

        else:
            self.is_valid = False
            if rcode == 1:
                self.error = (1, 'FORMERR: Query Format Error')

            elif rcode == 2:
                self.error = (
                    2, 'SERVFAIL: Server failed to complete DNS request')

            elif rcode == 3:
                self.error = (3, 'NXDOMAIN: Domain Name does not exist')

            elif rcode == 4:
                self.error = (4, 'NOTIMP: Function not implemented')

            elif rcode == 5:
                self.error = (
                    5, 'REFUSED: The server refused to answer for the query')

            elif rcode == 6:
                self.error = (
                    6, 'YXDOMAIN: Name that should not exist, does exist')

            elif rcode == 7:
                self.error = (
                    7, 'XRRSET: RRset that should not exist, does exist')

            elif rcode == 8:
                self.error = (
                    8, 'NOTAUTH: Server not authoritative for the zone')

            elif rcode == 9:
                self.error = (9, 'NOTZONE: Name not in zone')

    def parse(self):
        num = 0
        start = self.length
        while num < self.header['num_response'] or num < self.header['num_authority'] or num < self.header['num_additional']:
            tuple_data_dns = struct.unpack(
                '!HHHLH', self.data[start:start + 12])
            data_to_pass = {}
            data_to_pass['name'] = tuple_data_dns[0]
            data_to_pass['qtype'] = tuple_data_dns[1]
            data_to_pass['qclass'] = tuple_data_dns[2]
            data_to_pass['ttl'] = tuple_data_dns[3]
            data_to_pass['response_length'] = tuple_data_dns[4]
            data_to_pass['response_data'] = self.data[start +12:start + 12 + tuple_data_dns[4]]
            num += 1
            start += data_to_pass['response_length'] + 12
            self.records.append(data_to_pass)
        self.qtype = self.records[0]['qtype']

    def decode_response(self):
        if self.qtype == 1:
            result = self.decode_A(self.records[:self.header['num_response']])
            answer = 'Name: ' + result[0] + '\n' + 'Address: ' + result[1]
            self.answer = answer

        elif self.qtype == 28:
            result = self.decode_AAAA(self.records[:self.header['num_response']])
            answer = 'Name: ' + result[0] + '\n' + 'Address: ' + result[1]
            self.answer = answer

        elif self.qtype == 2:
            result = self.decode_NS(self.records[:self.header['num_response']])
            answer = ''
            for line in result:
                answer += self.url + '\t nameserver = ' + line + '\n'

            self.answer = answer

        elif self.qtype == 6:
            result = self.decode_SOA(self.records[:self.header['num_response']])
            answer = self.url + '\n'
            answer += '\t orgin: ' + result[0] + '\n'
            answer += '\t mail addr: ' + result[1] + '\n'
            answer += '\t serial: ' + str(result[2]) + '\n'
            answer += '\t refresh: ' + str(result[3]) + '\n'
            answer += '\t retry: ' + str(result[4]) + '\n'
            answer += '\t expire: ' + str(result[5]) + '\n'
            answer += '\t minimum: ' + str(result[6]) + '\n'

            self.answer = answer

        elif self.qtype == 16:
            result = self.decode_TXT(self.records[:self.header['num_response']])
            answer = ''
            for line in result:
                answer += self.url + '\t' + line + '\n'

            self.answer = answer

        elif self.qtype == 15:
            result = self.decode_MX(self.records[:self.header['num_response']])
            answer = ''
            for line in result:
                answer += self.url + '\t mail exchanger = ' + \
                    str(line[0]) + ' ' + line[1] + '\n'

            self.answer = answer

        elif self.qtype == 12:
            result = self.decode_PTR(self.records[:self.header['num_response']])
            answer = ''
            for line in result:
                answer += self.url + '\t name = ' + line

            self.answer = answer

        else:
            self.answer = 'The option is invalid'

        if self.header['num_additional'] != 0:
            temp = self.decode_NS(self.records[:self.header['num_response']])
            index = 0
            for record in self.records[self.header['num_response']:]:
                if record['qtype'] == 1:
                    self.additional.append("{} has an internet address = {}\n".format(temp[index], self.decode_A([record])[1]))
                    index += 1
                elif record['qtype'] == 28:
                    index -= 1
                    self.additional.append("{} has AAAA address = {}\n".format(temp[index], self.decode_AAAA([record])[1]))
                    index += 1

        self.additional = ''.join(self.additional)

    def decode_A(self, records):
        data = struct.unpack('!BBBB', records[0]['response_data'])
        data = list(map(lambda num: str(num), data))
        return (self.url, ('.'.join(data)))

    def decode_AAAA(self, records):
        data = struct.unpack('!LLLL', records[0]['response_data'])
        result = []
        for num in data:
            test = str(hex(num)[2:])
            test = '0' * (8 - len(test)) + test
            result.append(test[:4])
            result.append(test[4:])

        final = []
        for index, num in enumerate(result):
            test = num.lstrip('0')
            if test != '':
                final.append(test)
            else:
                temp = ''
                flag = 0
                while temp == '':
                    temp = result[index + 1].lstrip('0')
                    if temp == '':
                        result.pop(index + 1)
                        flag = 1

                if flag == 0:
                    final.append('0')
                else:
                    final.append('')

        answer = ':'.join(final)
        return (self.url, answer)

    def decode_NS(self, records):

        first_record = records[0]
        length = first_record['response_data'][0]
        bstream = 'c' * length
        data = struct.unpack(
            bstream, first_record['response_data'][1: length + 1])
        data = list(map(lambda letter: str(letter, 'utf-8'), data))
        result = [''.join(data)]

        try:
            pointer = struct.unpack(
                'BB', first_record['response_data'][length + 1:])
            if pointer[0] >> 6 == 3:
                suffix = self.solve_pointer(pointer[1])
        except Exception:
            length = length + 1
            suffix = ''
            while length < first_record['response_length'] - 1:
                newlen = first_record['response_data'][length]
                if newlen == 192:
                    suffix += self.solve_pointer(first_record['response_data'][length + 1])
                    break
                bstream = 'c' * newlen
                data = struct.unpack(
                    bstream, first_record['response_data'][length + 1: length + 1 + newlen])
                data = list(map(lambda letter: str(letter, 'utf-8'), data))
                suffix += ''.join(data) + '.'
                length += newlen + 1

        result[0] += '.' + suffix

        for record in records[1:]:
            length = first_record['response_data'][0]
            bstream = 'c' * length
            data = struct.unpack(
                bstream, record['response_data'][1: length + 1])
            data = list(map(lambda letter: str(letter, 'utf-8'), data))
            result.append(''.join(data) + '.' + suffix)

        return result

    def decode_TXT(self, records):
        result = []
        for record in records:
            result.append(str(record['response_data'][1:], 'utf-8'))

        return result

    def decode_MX(self, records):
        answer = []
        for record in records:
            pref = record['response_data'][1]
            i = 2
            result = ''
            while i < record['response_length'] - 2:
                length = record['response_data'][i]
                if length != 192:
                    bstream = 'c' * length
                    data = struct.unpack(
                        bstream, record['response_data'][i + 1: i + 1 + length])
                    data = list(map(lambda letter: str(letter, 'utf-8'), data))
                    data = ''.join(data)
                    result += data + '.'
                    i += 1 + length
                else:
                    result += self.solve_pointer(
                        record['response_data'][i + 1])
                    i += 1

            if record['response_data'][i] == 192:
                result += self.solve_pointer(
                    record['response_data'][i + 1]) + '.'

            answer.append((pref, result))

        return answer

    def decode_SOA(self, records):
        i = 0
        answer = []
        result = ''
        record = records[0]
        while True:
            length = record['response_data'][i]
            if length == 192:
                result += self.solve_pointer(
                    record['response_data'][i + 1]) + '.'
                i += 2
                break
            elif length == 0:
                i += 1
                break
            else:
                bstream = 'c' * length
                data = struct.unpack(
                    bstream, record['response_data'][i + 1: i + 1 + length])
                data = list(map(lambda letter: str(letter, 'utf-8'), data))
                result += ''.join(data) + '.'
                i += length + 1

        answer.append(result)

        j = i
        while j < len(record['response_data']) and record['response_data'][j] != 192:
            j += 1

        result = ''
        if j != len(record['response_data']):
            bstream = 'c' * record['response_data'][i]
            data = struct.unpack(bstream, record['response_data'][i + 1: j])
            data = list(map(lambda letter: str(letter, 'utf-8'), data))
            result += ''.join(data) + '.' + \
                self.solve_pointer(record['response_data'][j + 1])
            i = j + 2
        else:
            while True:
                length = record['response_data'][i]
                if length == 192:
                    result += self.solve_pointer(
                        record['response_data'][i + 1]) + '.'
                    i += 2
                    break
                elif length == 0:
                    i += 1
                    break
                else:
                    bstream = 'c' * length
                    data = struct.unpack(
                        bstream, record['response_data'][i + 1: i + 1 + length])
                    data = list(map(lambda letter: str(letter, 'utf-8'), data))
                    result += ''.join(data) + '.'
                    i += length + 1

        answer.append(result)

        for index in range(0, len(record['response_data'][i:]), 4):
            data = struct.unpack(
                'BBBB', record['response_data'][i + index: i + index + 4])
            result = []
            for index, num in enumerate(data):
                result.append(data[index] * (16 ** (2 * (3 - index))))

            answer.append(sum(result))

        return answer

    def decode_PTR(self, records):
        final = []
        for record in records:
            newlen = 0
            data = record['response_data']
            result = ''
            answer = []
            while newlen < len(record['response_data']):
                length = data[newlen]
                if length == 0:
                    break
                if length == 192:
                    answer.append(self.solve_pointer(
                        record['response_data'][newlen + 1]))
                    break
                bstream = 'c' * length
                result = struct.unpack(
                    bstream, data[newlen + 1: newlen + 1 + length])
                newlen += length + 1
                result = list(map(lambda letter: str(letter, 'utf-8'), result))
                answer.append(''.join(result))
            final.append('.'.join(answer))

        return final

    def solve_pointer(self, start):
        i = start
        result = []
        while True:
            length = self.data[i]
            if length == 0:
                break
            elif length == 192:
                result.append(self.solve_pointer(self.data[i + 1]))

            try:
                bstream = length * 'c'
                data = struct.unpack(bstream, self.data[i + 1: i + 1 + length])
                data = list(map(lambda letter: str(letter, 'utf-8'), data))
                data = ''.join(data)
                i += 1 + length
                result.append(data)
            except Exception:
                break

        return '.'.join(result)


if __name__ == '__main__':
    print('This is the file for the query class, run dns.py instead')
