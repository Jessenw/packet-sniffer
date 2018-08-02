/*
 * sniffer.c
 *
 * By David C Harrison (david.harrison@ecs.vuw.ac.nz) July 2015
 *
 * Use as-is, modification, and/or inclusion in derivative works is permitted only if 
 * the original author is credited. 
 *
 * To compile: gcc -o sniffer sniffer.c -l pcap 
 *
 * To run: tcpdump -s0 -w - | ./sniffer -
 *     Or: ./sniffer <some file captured from tcpdump or wireshark>
 * 
 * struct pcap_pkthdr {
 *		struct timeval ts; // time stamp 
 *		bpf_u_int32 caplen; // length of portion present
 *		bpf_u_int32 len; // length this packet (off wire)
 *	};
 *
 * REFERENCES:
 * https://www.tcpdump.org/pcap.html
 */

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6

/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};

/*
 * args = user arguments, in this case NULL from pcap_loop.
 * header = information about when the packet was sniffed.
 * packet = pointer to the first byte of a chunk of data containing the entire packet
 *          packet should be thought as a collection of structs instead of a string.
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1;

    const struct sniff_ethernet *ethernet; /* Ethernet handler function */
    const struct sniff_ip *ip;

    printf("Packet #%d\n", count);
    count++;

    ethernet = (struct sniff_ethernet*)(packet); /* Type case packet to ethernet header */

    /* IPv4 */
    if(ntohs(ethernet->ether_type) == 2048) {
        printf("Protocol: IPv4\n");
    }
    /* IPv6 */
    else if(ntohs(ethernet->ether_type) == 34525) {
        printf("Protocol: IPv6\n");
    } 
    /* Unknown */
    else {
        printf("Protocol: Unknown\n");
    }

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Must have an argument, either a file name or '-'\n");
        return -1;
    }

    pcap_t *handle = pcap_open_offline(argv[1], NULL); // create session handler
    pcap_loop(handle, 1024*1024, got_packet, NULL);
    pcap_close(handle); 

    return 0;
}