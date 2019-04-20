import socket
import struct


class NetworkSniffer:

    def __init__(self):
        print('Initializing socket connection')
        self.conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

    def filter_mac_address(self, raw_data: bytes):
        """
        This Method filters source and destination mac address and Network Protocol
        :param raw_data: raw network bytes
        :return: destination mac address, source_mac address ,network protocol and data
        """
        dest_mac, source_mac, protocol = struct.unpack('! 6s 6s H', raw_data[:14])
        return self.format_mac_address(dest_mac), self.format_mac_address(source_mac), socket.htons(protocol), raw_data[
                                                                                                               14:]

    @staticmethod
    def format_mac_address(bytes_addr):
        """
        Formats byte mac address to human readable mac address string. Ex: XX:XX:XX:XX:XX:XX
        :param bytes_addr: bytes
        :return: Mac address: str
        """
        bytes_str = b':'.join(["%02X" % (ord(x)) for x in bytes_addr])
        return bytes_str.upper()

    def unpack_ipv4_packet(self, data):
        iph = struct.unpack('!BBHHHBBH4s4s', data[:20])
        version_header_len = iph[0]
        version = version_header_len >> 4
        header_len = (version_header_len & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_len, ttl, proto, self.format_ipv4(src), self.format_ipv4(target), data[header_len:]

    @staticmethod
    def format_ipv4(raw_address):
        return socket.inet_ntoa(raw_address)

    def unpack_icmp_packet(self, data):
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]

    def unpack_udp_packet(self, data):
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, size, data[8:]

    def unpack_tcp_segment(self, data):
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flag = struct.unpack('! H H L L H', data[:14])

        return src_port, dest_port, sequence, acknowledgment, offset_reserved_flag, data[14:]

    def run(self):
        print('Starting main loop')
        while True:
            raw_data, addr = self.conn.recvfrom(65535)

            print("""
            ==========================================================
            ********************** Packet Start **********************
            """)
            dest_mac, source_mac, network_protocol, data = self.filter_mac_address(raw_data)
            print('Network frame' + '\n\tSource Mac Address :- ' + str(source_mac) + '\n\tDestination Mac Address :-' +
                  str(dest_mac) + '\n\tNetwork protocol :- ' + str(network_protocol))

            if network_protocol == 8:
                version, header_length, ttl, ipv4_protocol, source_ip, target_ip, payload_data = self.unpack_ipv4_packet(
                    data)
                print('\nIPV4 frame' + '\n\tVersion :- ' + str(version) + '\n\tHeader length :- ' + str(header_length) +
                      '\n\tTime to live :- ' + str(ttl) + '\n\tIPv4 protocol :- ' + str(ipv4_protocol) +
                      '\n\tSource IP address :- ' + source_ip + '\n\tDestination IP address :- ' + target_ip)

                if ipv4_protocol == 1:
                    icmp_type, code, checksum, icmp_data = self.unpack_icmp_packet(payload_data)
                    print('\nICMP data packet' + '\n\t ICMP type :- ' + str(icmp_type) + '\n\t code :- ' +
                          str(code) + '\n\tchecksum :- ' + str(checksum))

                if ipv4_protocol == 17:
                    src_port, dest_port, size, upd_data = self.unpack_udp_packet(payload_data)
                    print('\n UDP packet \n\t Source Port :- ' + str(src_port) + '\n\t Destinantion Port :- ' +
                          str(dest_port) + '\n\t Size :-' + str(size))

                if ipv4_protocol == 6:
                    src_port, dest_port, sequence, acknowledgment, offset_reserved_flag, tcp_data = self.unpack_tcp_segment(
                        payload_data)

                    print(
                        '\nTCP packet \n\t Source Port :- {}\n\t Destinantion Port :- {}\n\t Acknowledgement :- {}'
                        ' \n\t Flags {}'.format(src_port, dest_port, acknowledgment, offset_reserved_flag))

            print("""
            ********************** Packet End ************************
            ==========================================================\n\n
            """)


if __name__ == '__main__':
    sniffer = NetworkSniffer()
    print('Running sniffer')
    sniffer.run()
