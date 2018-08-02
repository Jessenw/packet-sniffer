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
	u_short ether_type;                 /* IPv4, IPv6, unknown */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

#define IP_HL(ip)(((ip)->ip_vhl) & 0x0f)

/*
 * args = user arguments, in this case NULL from pcap_loop.
 * header = information about when the packet was sniffed.
 * packet = pointer to the first byte of a chunk of data containing the entire packet
 *          packet should be thought as a collection of structs instead of a string.
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("\n");
    static int count = 1;

    const struct sniff_ethernet *ethernet; /* Ethernet handler function */
    const struct sniff_ip *ip;

    int size_ip;

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
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

    /* print source and destination IP addresses */
	printf("From: %s\n", inet_ntoa(ip->ip_src));
	printf("To: %s\n", inet_ntoa(ip->ip_dst));
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("Protocol: IP\n");
			return;
		default:
			printf("Protocol: unknown\n");
			return;
	}
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