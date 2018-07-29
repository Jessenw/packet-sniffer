#!/usr/bin/env python3

'''
sniffer.py -- Python packet sniffer
By Jordan Ansell (jordan.ansell@ecs.vuw.ac.nz) July 2017
Use as-is, modification, and/or inclusion in derivative works is permitted only if the original author is credited.
Requires the pcapy library.
To install: python3 -m pip install pcapy -t ./pcapy/
To run:     python3 sniffer.py packets_file.pcap
Or:         tcpdump -w - | python3 ./sniffer.py -

Resources used:
IP Version numbers: https://www.iana.org/assignments/version-numbers/version-numbers.xhtml
Python Socket Docs: https://docs.python.org/3/library/socket.html
IP Protocol Numbers: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers 
Pacpy Docs: https://rawgit.com/CoreSecurity/pcapy/master/pcapy.html
Python Struct Docs: https://docs.python.org/3/library/struct.html

Most of my string formatters came from this example code:
https://www.binarytides.com/code-a-packet-sniffer-in-python-with-pcapy-extension/
'''

from pcapy import pcapy
from hexdump import hexdump

import binascii
import struct
import sys
import ipaddress
import socket

'''
Minimum Header sizes (in bytes)
'''
ETHERNET_HDR_SIZE = 14
IPV4_HDR_SIZE = 20
IPV6_HDR_SIZE = 40
TCP_HDR_SIZE = 20
ICMP_HDR_SIZE = 4
UDP_HDR_SIZE = 8

def mac2str(mac_bytes):
    mac_string = binascii.hexlify(mac_bytes).decode('ascii')
    mac_pairs = [i+j for i,j in zip(mac_string[0::2], mac_string[1::2])]
    return ':'.join(mac_pairs)

'''
Handles the DataLink header. For this assignment, we only care about IPv4 and IPv6.
'''
class EthernetHandler:
    def __init__(self, pkt_dict, data, hdr_length):
        # print('Ethernet Header Length: {}'.format(hdr_length))

        src_mac_addr = mac2str(pkt_dict['source'])
        dest_mac_addr = mac2str(pkt_dict['dest'])
        print('Source MAC: {} | Destination MAC: {}'.format(src_mac_addr, dest_mac_addr))

        protocol = pkt_dict['type']
        if protocol == 2048: # IPv4 = 0x86DD = 2048
            IPv4Handler(data, hdr_length)
        elif protocol == 34525: # IPv6 = 0x86DD = 34525
            IPv6Handler(data, hdr_length)
        else: # unknown protocol
            print('DataLink Type: Unknown. Type = {}'.format(type))
            hexdump.hexdump(data[total_hdr_size:])

class IPv4Handler:
    def __init__(self, data, hdr_length):
        print('Ethernet Protocol: IPv4')

        ip_hdr_ = data[hdr_length : hdr_length + IPV4_HDR_SIZE]
        ip_hdr = struct.unpack('!BBHHHBBH4s4s', ip_hdr_)

        version_ = ip_hdr[0]
        version = version_ >> 4 # bit shift to get the first 4 bits only
        ihl = (version_ & 0xf) * 4 # set first 4 bits to 0 to get last 4 bits only
        # print('Internet Header Length (IHL): {}'.format(ihl))

        # The idea of using the socket lib came from this example code
        # https://www.binarytides.com/code-a-packet-sniffer-in-python-with-pcapy-extension/
        src_addr = socket.inet_ntoa(ip_hdr[8])
        dest_addr = socket.inet_ntoa(ip_hdr[9])
        print('Source Address: {} | Destination Address: {}'.format(src_addr, dest_addr))
        
        protocol = ip_hdr[6]
        total_hdr_size = ihl + hdr_length # the total size of the currently processed headers
        # ICMPv4
        if protocol == 1:
            ICMPHandler(data, total_hdr_size, ihl)
        # TCP
        elif protocol == 6:
            print('Protocol: TCP')
            TCPHandler(data, total_hdr_size, ihl)
        # UDP
        elif protocol == 17:
            print('Protocol: UDP')
            UDPHandler(data, total_hdr_size, ihl)
        # unknown
        else:
            print('Protocol: Unknown')
            print('Data:')
            hexdump.hexdump(data[total_hdr_size:])

class IPv6Handler:
    def __init__(self, data, hdr_length):
        print('Ethernet Protocol: IPv6')

        ip_hdr_ = data[hdr_length:hdr_length + IPV6_HDR_SIZE]
        ip_hdr = struct.unpack('!LHBB16s16s', ip_hdr_)

        src_addr = mac2str(ip_hdr[4])
        dest_addr = mac2str(ip_hdr[5])
        print('Source Address: {} | Destination Address: {}'.format(src_addr, dest_addr))

        next_header = ip_hdr[2]
        # ICMPv6
        if next_header == 58:
            print('Protocol: ICMPv6')
        # TCP
        elif next_header == 6:
            TCPHandler(data, IPV6_HDR_SIZE + hdr_length, IPV6_HDR_SIZE)
        # UDP
        elif next_header == 17:
            UDPHandler(data, IPV6_HDR_SIZE + hdr_length, IPV6_HDR_SIZE)
        # Hop-by-hop options header
        elif next_header == 0:
            print('Protocol: Hop-by-hop options header')
            IPv6ExtentionHandler(data, hdr_length + IPV6_HDR_SIZE)
        # Routing header
        elif next_header == 43:
            print('Protocol: Routing header')
            IPv6ExtentionHandler(data, hdr_length + IPV6_HDR_SIZE)
        # Fragment header
        elif next_header == 44:
            print('Protocol: Fragment header')
            IPv6ExtentionHandler(data, hdr_length + IPV6_HDR_SIZE)
        # Destination options header
        elif next_header == 60:
            print('Protocol: Destination options header')
            IPv6ExtentionHandler(data, hdr_length + IPV6_HDR_SIZE)
        # Authentication header
        elif next_header == 51:
            print('Protocol: Authentication header')
            IPv6ExtentionHandler(data, hdr_length + IPV6_HDR_SIZE)
        # Encapsulating security payload header
        elif next_header == 50:
            print('Protocol: Encapsulating security payload header')
            IPv6ExtentionHandler(data, hdr_length + IPV6_HDR_SIZE)
        # unknown
        else:
            print('Protocol: unknown')

class IPv6ExtentionHandler:
    def __init__(self, data, hdr_length):
        ipe_hdr = data[hdr_length:hdr_length + 2]
        ipe_hdr_ = struct.unpack('!BB', ipe_hdr)
        next_header = ipe_hdr_[0]
        next_header_len = (ipe_hdr_[1] + 1) * 8 
        print('Next header: {}\nNext header length: {} (bytes)'.format(next_header, next_header_len))
        if next_header == 58: # ICMPv6
            print('Protocol: ICMPv6')
        elif next_header == 6: # TCP
            print('TCP')
            TCPHandler(data, next_header_len + hdr_length, next_header_len)
        elif next_header == 17: # UDP
            print('UDP')
        # Extension headers
        elif next_header == 0: # Hop-by-hop options header
            print('Protocol: Hop-by-hop options header')
            IPv6ExtentionHandler(data, next_header_len + hdr_length)
        elif next_header == 43: # Routing header
            print('Protocol: Routing header')
            IPv6ExtentionHandler(data, next_header_len + hdr_length)
        elif next_header == 44: # Fragment header
            print('Protocol: Fragment header')
            IPv6ExtentionHandler(data, next_header_len + hdr_length)
        elif next_header == 60: # Destination options header
            print('Protocol: Destination options header')
            IPv6ExtentionHandler(data, next_header_len + hdr_length)
        elif next_header == 51: # Authentication header
            print('Protocol: Authentication header')
            IPv6ExtentionHandler(data, next_header_len + hdr_length)
        elif next_header == 50: # Encapsulating security payload header
            print('Protocol: Encapsulating security payload header')
            
        elif next_header == 41: # IPv6
            print('Protocol: IPv6')
            IPv6Handler(data, next_header_len + hdr_length)
        else: # undefined
            print('Protocol: undefined')

class ICMPHandler:
    def __init__(self, data, hdr_length, ihl):
        print('Protocol: ICMP')

        icmp_hdr = data[hdr_length : hdr_length + ICMP_HDR_SIZE]
        icmp_hdr_ = struct.unpack('!BBH', icmp_hdr)
        
        type = str(icmp_hdr_[0])
        code = str(icmp_hdr_[1])
        checksum = str(icmp_hdr_[2])
        print('Type: {} | Code: {} | Checksum: {}'.format(type, code, checksum))

        '''
        Not entirely sure why the + 4 is necessary here but i noticed that my
        destination address was the source address on wireshark
        '''
        IPv4Handler(data, hdr_length + ICMP_HDR_SIZE + 4)


class TCPHandler:
    def __init__(self, data, hdr_length, ihl):
        print('Protocol: TCP')

        tcp_hdr = data[hdr_length : hdr_length + TCP_HDR_SIZE]
        tcp_hdr_ = struct.unpack('!HHLLBBHHH', tcp_hdr)

        src_port = str(tcp_hdr_[0])
        dest_port = str(tcp_hdr_[1])
        print('Source Port: {} | Destination Port: {}'.format(src_port, dest_port))

        tcp_hdr_size = tcp_hdr_[4] >> 4
        total_hdr_size = ETHERNET_HDR_SIZE + ihl + tcp_hdr_size * 4
        payload_size = len(data) - total_hdr_size
        print('Payload Size: ({})'.format(payload_size))
        print("Data:")
        hexdump.hexdump(data[total_hdr_size:])

class UDPHandler:
    def __init__(self, data, hdr_length, ihl):
        print('Protocol: UDP')
        
        udp_hdr = data[hdr_length : hdr_length + UDP_HDR_SIZE]
        udp_hdr_ = struct.unpack('!HHHH', udp_hdr)

        src_port = str(udp_hdr_[0])
        dest_port = str(udp_hdr_[1])
        print('Source Port: {} | Destination Port: {}'.format(src_port, dest_port))

        total_hdr_size = ETHERNET_HDR_SIZE + ihl + UDP_HDR_SIZE
        payload_size = len(data) - total_hdr_size
        print('Payload Size: ({})'.format(payload_size))
        print("Data:")
        hexdump.hexdump(data[total_hdr_size:])

class PacketHeaderBase:
    ''' Base class for packet headers. '''

    def __init__(self, hdr_format, field_names, data):
        ''' Creates a header object from the packet data given.
            Field names are given as an array of strings.
            For more information on struct format strings see:
              https://docs.python.org/3/library/struct.html '''
        self.data = data
        self.hdr_length = struct.calcsize(hdr_format)
        self.field_values = struct.unpack(
            hdr_format, 
            data[:self.hdr_length])

        pkt_dict = dict(zip(field_names, self.field_values))
        for k, v in pkt_dict.items():
            setattr(self, k, v)

        EthernetHandler(pkt_dict, data, self.hdr_length)

class Ethernet(PacketHeaderBase):
    ''' Ethernet header class. '''
    # _fmt and _fields define the structure of an Ethernet packet
    fmt = '!6s6sH'
    fields = ['dest', 'source', 'type', 'data']

    def __init__(self, data):
        super().__init__(Ethernet.fmt, Ethernet.fields, data)

    def __str__(self):
        return "Ethernet payload {}, ".format( binascii.hexlify(self.payload) )  # what information needs to be printed?

def process_packet(packet_data):
    ''' Function for processing a single packet '''
    parsed_pkt = dict()

    # process the datalink header
    parsed_pkt['ethernet'] = Ethernet(packet_data)

def main(pcap_filename):
    ''' Main function, loops over packets in the given file, counting and processing each. '''
    print( "Opening file: '{}'".format(pcap_filename) )
    pcap_reader = pcapy.open_offline( pcap_filename )

    count = 0
    while True:
        meta, data = pcap_reader.next()
        if len(data) < 1:
            break  # no more packets 
        
        count += 1
        print('\nPacket #: {}'.format(count))
        process_packet( data )

    print("Complete. {} packets processed.".format(count))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Please supply pcap file argument: python3 sniffer.py packets.pcap")
        exit()

    main(sys.argv[1])