#!/usr/bin/env python3

'''
sniffer.py -- Python packet sniffer

By Jordan Ansell (jordan.ansell@ecs.vuw.ac.nz) July 2017

Use as-is, modification, and/or inclusion in derivative works is permitted only if the original author is credited.

Requires the pcapy library.
To install: python3 -m pip install pcapy -t ./pcapy/

To run:     python3 sniffer.py packets_file.pcap
Or:         tcpdump -w - | python3 ./sniffer.py -
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

def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

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

        eth_proto = socket.ntohs(pkt_dict['type'])
        '''
        dest_mac = eth_addr(str(pkt_dict['dest']))
        source_mac = eth_addr(str(pkt_dict['source']))
        print('Destination MAC: {} | Source MAC: {} | Protocol: {}'.format(dest_mac, source_mac, eth_proto))
        '''
        # IP protocol
        if eth_proto == 8:
            min_length = 20 # min number of bytes the ip header can be
            ip_hdr = data[self.hdr_length:min_length + self.hdr_length]
            # 8 8 16 16 16 8 8 16
            ip_hdr_ = struct.unpack('!BBHHHBBH4s4s', ip_hdr)

            source_addr = socket.inet_ntoa(ip_hdr_[8])
            dest_addr = socket.inet_ntoa(ip_hdr_[9])
            print('From: {}\nTo: {}'.format(source_addr, dest_addr))
            protocol = ip_hdr_[6]
            '''
            Protocol numbers were found at this webpage
            https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
            '''
             # ICMP packet
            if protocol == 1:
                print('Protocol: ICMP packet')
            # TCP packet
            elif protocol == 6:
                print('Protocol: TCP packet')
            # UDP packet
            elif protocol == 17:
                print('Protocol: UDP packet')
            # undefined packet
            else:
                print('Protocol: undefined')

class Ethernet(PacketHeaderBase):
    ''' Ethernet header class. '''
    # Ethernet frame (bytes): 6 6 2 x x
    # _fmt and _fields define the structure of an Ethernet packet
    fmt = '!6s6sH'  # TODO: format string for Ethernet
    fields = ['dest', 'source', 'type']  # TODO: list of Ethernet fields

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
        print("#### Packet {}:".format(count))
        process_packet( data )

    print("Complete. {} packets processed.".format(count))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Please supply pcap file argument: python3 sniffer.py packets.pcap")
        exit()

    main(sys.argv[1])