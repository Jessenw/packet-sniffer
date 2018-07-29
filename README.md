# packet-sniffer
Includes a python version and a C version. Lab 1 for NWEN302.

The Github repo for this assignment can be found at:
https://github.com/Jessenw/packet-sniffer

To install: python3 -m pip install pcapy -t ./pcapy/
            python3 -m pip install hexdump -t ./hexdump/
To run:     python3 sniffer.py packets_file.pcap
Or:         tcpdump -w - | python3 ./sniffer.py -
