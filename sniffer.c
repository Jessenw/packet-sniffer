/*
 * sniffer.c
 *
 * By David C Harrison (david.harrison@ecs.vuw.ac.nz) July 2015, Modified by Jesse Williams
 *
 * Use as-is, modification, and/or inclusion in derivative works is permitted only if 
 * the original author is credited. 
 *
 * To compile: gcc -o sniffer sniffer.c -l pcap 
 *
 * To run: tcpdump -s0 -w - | ./sniffer -
 *     Or: ./sniffer <some file captured from tcpdump or wireshark>
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

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define SIZE_IPV6 40
#define SIZE_UDP 4

#define IP_HL(ip)(((ip)->ip_vhl) & 0x0f)

/* IPv6 extension header protocol numbers */
#define IP6EXTENSION_HOP_BY_HOP 0
#define IP6EXTENSION_ROUTING 43
#define IP6EXTENSION_FRAGMENT 44
#define IPVEXTENSION_DESTINATION_OPTIONS 60
#define IP6EXTENSION_AUTHENTICATION 51
#define IP6EXTENSION_SECURITY_PAYLOAD 50

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* sestination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
	u_short ether_type;                 /* IPv4, IPv6, unknown */
};

/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                 	/* version << 4 | header length >> 2 */
    u_char  ip_tos;                 	/* type of service */
    u_short ip_len;                 	/* total length */
    u_short ip_id;                  	/* identification */
    u_short ip_off;                 	/* fragment offset field */
    #define IP_RF 0x8000            	/* reserved fragment flag */
    #define IP_DF 0x4000            	/* dont fragment flag */
    #define IP_MF 0x2000            	/* more fragments flag */
    #define IP_OFFMASK 0x1fff       	/* mask for fragmenting bits */
    u_char  ip_ttl;                 	/* time to live */
    u_char  ip_p;                   	/* protocol */
    u_short ip_sum;                 	/* checksum */
    struct  in_addr ip_src,ip_dst;  	/* source and dest address */
};

/* IPv6 header */
struct sniff_ipv6 {
	uint32_t ip_vtf;							/* version then traffic class and flow label */
    u_short ip_len;								/* header length */
    u_int8_t  ip_nxt_hdr;						/* next header */
    u_char  ip_hop_len;							/* hop limit (ttl) */
    struct in6_addr ip_src;						/* source address */
	struct in6_addr ip_dest;					/* destination address */
};

/* IPv6 extension header */
struct sniff_ipv6_extension {

};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* UDP header */
struct sniff_udp {
    u_short th_sport;					/* source port */
	u_short th_dport;					/* destination port */
	u_short len;						/* length */
	u_short cs;							/* checksum */
};

/* ICMP header */
struct sniff_icmp {
	u_char type;
	u_char code;
	u_short checksum;
	u_long payload;
};

/* ICMPv6 header */
struct sniff_icmpv6 {
	u_char type;
	u_char code;
	u_short checksum;
	u_long payload;
};

/* prototype functions */
void ipv4_handler(const u_char *);
void ipv6_handler(const u_char *);
void tcp_handler(const u_char *, const int, const struct sniff_ip *);
void udp_handler(const u_char *, const int, const struct sniff_ip *);
void icmp_handler(const u_char *, const int, const struct sniff_ip *);
void icmpv6_handler(const u_char *, const int, const struct sniff_ip *);
void print_hex_ascii_line(const u_char *, int, int);
void print_payload(const u_char *, int);

void 
ipv4_handler(const u_char *packet)
{
    const struct sniff_ip *ip;
    int size_ip;

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
            tcp_handler(packet, size_ip, ip);
			break;
		case IPPROTO_UDP:
			printf("Protocol: UDP\n");
			udp_handler(packet, size_ip, ip);
			return;
		case IPPROTO_ICMP:
			printf("Protocol: ICMP\n");
			icmp_handler(packet, size_ip, ip);
			return;
		default:
			printf("Protocol: unknown\n");
			return;
	}
}

void
ipv6_handler(const u_char *packet)
{
	const struct sniff_ipv6 *ipv6;
	int protocol;

	ipv6 = (struct sniff_ipv6*)(packet + SIZE_ETHERNET);

	char src_addr[INET6_ADDRSTRLEN];
	char dest_addr[INET6_ADDRSTRLEN];
	printf("Src address: %s\n", inet_ntop(AF_INET6, &ipv6->ip_src, src_addr, INET6_ADDRSTRLEN));
	printf("Dest address: %s\n", inet_ntop(AF_INET6, &ipv6->ip_dest, dest_addr, INET6_ADDRSTRLEN));

	protocol = ipv6->ip_nxt_hdr;
	switch(protocol) {
		case IPPROTO_TCP:
			printf("Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("Protocol: UDP\n");
			return;
		case IPPROTO_ICMPV6:
			printf("ProtocolL ICMPv6\n");
			return;
		case IP6EXTENSION_HOP_BY_HOP:
			printf("Protocol: Hop-by-hop Header\n");
			return;
		case IP6EXTENSION_ROUTING:
			printf("Protocol: Routing Header\n");
			return;
		case IP6EXTENSION_FRAGMENT:
			printf("Protocol: Fragment Header\n");
			return;
		case IPVEXTENSION_DESTINATION_OPTIONS:
			printf("Protocol: Destinations Options Header\n");
			return;
		case IP6EXTENSION_AUTHENTICATION:
			printf("Protocol: Authentication Header\n");
			return;
		case IP6EXTENSION_SECURITY_PAYLOAD:
			printf("Protocol: Security Payload Header\n");
			return;
		default:
			printf("Protocol: unknown\n");
			return;
	}
}

void
tcp_handler(const u_char *packet, const int size_ip_, const struct sniff_ip *ip)
{
    const struct sniff_tcp *tcp; /* The TCP header */
    const char *payload;         /* Packet payload */

    int size_ip = size_ip_;
    int size_tcp;
    int size_payload;

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("* Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	printf("Src port: %d\n", ntohs(tcp->th_sport));
	printf("Dst port: %d\n", ntohs(tcp->th_dport));
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf("Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}
}

void
udp_handler(const u_char *packet, const int size_ip_, const struct sniff_ip *ip)
{
	const struct sniff_udp *udp; /* The UDP header */
	const char *payload;		 /* Packet payload */

	int size_ip = size_ip_;
	int size_payload;

	udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);

	printf("Src port: %d\n", ntohs(udp->th_sport));
	printf("Dst port: %d\n", ntohs(udp->th_dport));

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + SIZE_UDP);

	/* compute udp payload (segment) size */
	
}

void
icmp_handler(const u_char *packet, const int size_ip_, const struct sniff_ip *ip)
{
	const struct sniff_icmp *icmp; /* The ICMP header */
	const char *payload;		   /* Packet payload */

	int size_ip = size_ip_;

	icmp = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);

	printf("Type: %d\n", icmp->type);
	printf("Code: %d\n", icmp->code);
}

void
icmpv6_handler(const u_char *packet, const int size_ip_, const struct sniff_ip *ip)
{
	const struct sniff_icmpv6 *icmpv6; /* The ICMPv6 header */
	const char *payload;			   /* Packet payload */

	int size_ip = size_ip_;

	icmpv6 = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);

	printf("Type: %d\n", icmpv6->type);
	printf("Code: %d\n", icmpv6->code);
}

/*
 * args = user arguments, in this case NULL from pcap_loop.
 * header = information about when the packet was sniffed.
 * packet = pointer to the first byte of a chunk of data containing the entire packet
 *          packet should be thought as a collection of structs instead of a string.
 */
void 
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("\n");
    static int count = 1;

    const struct sniff_ethernet *ethernet; /* Ethernet handler function */

    printf("Packet #%d\n", count);
    count++;

    ethernet = (struct sniff_ethernet*)(packet); /* Type case packet to ethernet header */

    /* IPv4 */
    if(ntohs(ethernet->ether_type) == 2048) {
        printf("Protocol: IPv4\n");
        ipv4_handler(packet);
    }
    /* IPv6 */
    else if(ntohs(ethernet->ether_type) == 34525) {
        printf("Protocol: IPv6\n");
		ipv6_handler(packet);
    } 
    /* Unknown */
    else {
        printf("Protocol: Unknown\n");
    }
}

int 
main(int argc, char **argv)
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

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 * 
 * [1]
 */
void 
print_hex_ascii_line(const u_char *payload, int len, int offset)
{
	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

    return;
}