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
 */

#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>

const struct ether_header *ether;

char* mac2str(const char* arr)
{
    char mac_str[18]; // stored mac address

    if(arr == NULL) return "";
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
         arr[0], arr[1], arr[2], arr[3], arr[4], arr[5]);

    return mac_str;
}

// https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/if_ether.h.html
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    char* src_mac_addr = mac2str(ether->ether_shost);
    printf("%s\n", src_mac_addr);
    //printf("Source MAC: %s | Destination MAC: %s\n", ether->ether_shost, ether->ether_dhost);
    if(ether->ether_type == ntohs(ETHERTYPE_IP)) {
        printf("Ethernet Protocol: IPv4\n");
    } else if(ether->ether_type == ntohs(ETHERTYPE_IPV6)) {
        printf("Ethernet Protocol: IPv6\n");
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Must have an argument, either a file name or '-'\n");
        return -1;
    }

    pcap_t *handle = pcap_open_offline(argv[1], NULL);
    pcap_loop(handle, 1024*1024, got_packet, NULL);
    pcap_close(handle);

    return 0;
}