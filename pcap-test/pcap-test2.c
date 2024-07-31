#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> // For ETHERTYPE_IP and related constants
#include "mylibnet-headers.h"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        // Ethernet header
        struct libnet_ethernet_hdr* eth_header = (struct libnet_ethernet_hdr*)packet;
        printf("[MAC ] from(src) %02x:%02x:%02x:%02x:%02x:%02x ==> to(dst) %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
               eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5],
               eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
               eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

        // Check if the packet is IP packet
        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            // IP header
            struct libnet_ipv4_hdr* ip_header = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
            printf("[ IP ] from(src) %08x ==> to(dst) %08x\n",
                   ntohl(ip_header->ip_src.s_addr),
                   ntohl(ip_header->ip_dst.s_addr));

            // Check if the packet is TCP packet
            if (ip_header->ip_p == IPPROTO_TCP) {
                // TCP header
                struct libnet_tcp_hdr* tcp_header = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + ip_header->ip_hl * 4);
                printf("[Port] from(src) %04x ==> to(dst) %04x\n",
                       ntohs(tcp_header->th_sport),
                       ntohs(tcp_header->th_dport));

                // Data payload (start of TCP data)
                const u_char* data = packet + sizeof(struct libnet_ethernet_hdr) + ip_header->ip_hl * 4 + tcp_header->th_off * 4;
                int data_len = header->caplen - (data - packet);

                // 최대 20바이트만 출력
                int max_data_len = data_len > 20 ? 20 : data_len;

                printf("[Data] (HEX) ");
                for (int i = 0; i < max_data_len; i++) {
                    printf("%02x ", data[i]);
                }
                printf("\n");
            }
        }
    }

    pcap_close(pcap);
    return 0;
}

