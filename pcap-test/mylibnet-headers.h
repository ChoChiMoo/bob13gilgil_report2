#ifndef MYLIBNET_HEADERS_H
#define MYLIBNET_HEADERS_H

#include <stdint.h>

// Ethernet header
struct libnet_ethernet_hdr {
    uint8_t  ether_dhost[ETHER_ADDR_LEN];    /* Destination Ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];    /* Source Ethernet address */
    uint16_t ether_type;                     /* Protocol type (IP, ARP, etc) */
};

// IPv4 header
struct libnet_ipv4_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ip_hl:4,                /* Header length */
            ip_v:4;                 /* Version */
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip_v:4,                 /* Version */
            ip_hl:4;                /* Header length */
#else
# error "Please fix <endian.h>"
#endif
    uint8_t ip_tos;                 /* Type of service */
    uint16_t ip_len;                /* Total length */
    uint16_t ip_id;                 /* Identification */
    uint16_t ip_off;                /* Fragment offset field */
    uint8_t ip_ttl;                 /* Time to live */
    uint8_t ip_p;                   /* Protocol */
    uint16_t ip_sum;                /* Checksum */
    struct in_addr ip_src, ip_dst;  /* Source and destination IP address */
};

// TCP header
struct libnet_tcp_hdr {
    uint16_t th_sport;              /* Source port */
    uint16_t th_dport;              /* Destination port */
    uint32_t th_seq;                /* Sequence number */
    uint32_t th_ack;                /* Acknowledgement number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t th_x2:4,                /* (Unused) */
            th_off:4;               /* Data offset */
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t th_off:4,               /* Data offset */
            th_x2:4;                /* (Unused) */
#else
# error "Please fix <endian.h>"
#endif
    uint8_t  th_flags;              /* TCP flags */
    uint16_t th_win;                /* Window size */
    uint16_t th_sum;                /* Checksum */
    uint16_t th_urp;                /* Urgent pointer */
};

#endif /* MYLIBNET_HEADERS_H */

