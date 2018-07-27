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

NWEN302 Lecture slides
'''

from pcapy import pcapy  

import binascii
import struct
import sys
import ipaddress
import socket

def mac2str(mac_bytes):
    mac_string = binascii.hexlify(mac_bytes).decode('ascii')
    mac_pairs = [i+j for i,j in zip(mac_string[0::2], mac_string[1::2])]
    return ':'.join(mac_pairs)

'''
Handles the DataLink header. For this assignment, we only care about ethernet.
Ethernet format diagram can be found here:
http://microchipdeveloper.com/tcpip:tcp-ip-data-link-layer-layer-2
'''
class DataLinkLayerHandler:
    def __init__(self, pkt_dict, data, hdr_length):
        #type = socket.ntohs(pkt_dict['type'])
        type = str(pkt_dict['type'])
        # IPv4 = 0x86DD = 2048
        # IPv6 = 0x86DD = 34525
        if type == '2048' or type == '34525':
            NetworkLayerHandler(data, hdr_length)
        elif type == '34525':
        else:
            print('DataLink Type: undefined. Type = {}'.format(type))

class NetworkLayerHandler:
    def __init__(self, data, hdr_length):
        ip_hdr = data[hdr_length:hdr_length + 20]
        ip_hdr_ = struct.unpack('!BBHHHBBH4s4s', ip_hdr) # 8,8,16,16,16,8,8,16
        version = ip_hdr_[0]
        version_ = version >> 4 # we only want the first 4 bits
        ihl = (version & 0xf) * 4
        if version_ == 4:
            print('Ethernet Type: IPv4')
            # Source and Destination IP Address
            source_addr = socket.inet_ntoa(ip_hdr_[8])
            dest_addr = socket.inet_ntoa(ip_hdr_[9])
            print('From: {}\nTo: {}'.format(source_addr, dest_addr))
        elif version_ == 6:
            print('Ethernet Type: IPv6')
        else:
            print('Ethernet Type: undefined')
        
        protocol = ip_hdr_[6]
        if protocol == 1 and version == 4: # ICMPv4
            print('Protocol: ICMPv4')
        elif protocol == 1 and version == 6: # ICMPv6
            print('Protocol: ICMPv6')
        elif protocol == 6: # TCP
            TCPHandler(data, ihl + hdr_length, ihl)
        elif protocol == 17: # UDP
            print('Protocol: UDP')
            UDPHandler(data, ihl + hdr_length, ihl)
        else: # undefined
            print('Protocol: undefined')

class TCPHandler:
    def __init__(self, data, hdr_length, ihl):
        print("Protocol: TCP")
        tcp_hdr = data[hdr_length:hdr_length + 20]
        tcp_hdr_ = struct.unpack('!HHLLBBHHH', tcp_hdr) # HHLLBBHHH
        src_port = tcp_hdr_[0]
        dest_port = tcp_hdr_[1]
        print('Src Port: {}\nDst Port: {}'.format(str(src_port), str(dest_port)))
        tcp_hdr_size = tcp_hdr_[4] >> 4
        total_hdr_size = 14 + ihl + tcp_hdr_size * 4
        payload_size = len(data) - total_hdr_size
        print('Payload: ({})'.format(payload_size))
        print("Data: \n{}".format(binascii.hexlify(data[total_hdr_size:])))

class UDPHandler:
    def __init__(self, data, hdr_length, ihl):
        udp_hdr_size = 8
        udp_hdr = data[hdr_length:hdr_length + udp_hdr_size]
        udp_hdr_ = struct.unpack('!HHHH', udp_hdr)
        src_port = udp_hdr_[0]
        dest_port = udp_hdr_[1]
        print('Src Port: {}\nDst Port: {}'.format(str(src_port), str(dest_port)))
        total_hdr_size = 14 + ihl + udp_hdr_size
        payload_size = len(data) - total_hdr_size
        print('Payload: ({})'.format(payload_size))
        print("Data: \n{}".format(binascii.hexlify(data[total_hdr_size:])))

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

        DataLinkLayerHandler(pkt_dict, data, self.hdr_length)

class Ethernet(PacketHeaderBase):
    ''' Ethernet header class. '''
    # Ethernet frame (bytes): 6 6 2 x x
    # _fmt and _fields define the structure of an Ethernet packet
    fmt = '!6s6sH'  # TODO: format string for Ethernet
    fields = ['dest', 'source', 'type', 'data']  # TODO: list of Ethernet fields

    def __init__(self, data):
        super().__init__(Ethernet.fmt, Ethernet.fields, data)

    def __str__(self):
        return "Ethernet payload {}, ".format( binascii.hexlify(self.payload) )  # what information needs to be printed?

def process_packet(packet_data):
    ''' Function for processing a single packet '''
    parsed_pkt = dict()

    # print( binascii.hexlify(packet_data) )

    # process the datalink header
    parsed_pkt['ethernet'] = Ethernet(packet_data)

    # use Ethernet header to decide what the next header type is, process that header.

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