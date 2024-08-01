#ifndef MYLIBNET_HEADERS_H
#define MYLIBNET_HEADERS_H

#include <stdint.h>

// Ethernet header
struct libnet_ethernet_hdr {
    uint8_t  ether_dhost[ETHER_ADDR_LEN];    /* DST Ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];    /* SRC Ethernet address */
    uint16_t ether_type;                     /* Protocol (IP, ARP, etc) */
};

// IPv4 header
struct libnet_ipv4_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ip_hl:4,                /* Header 길이*/
            ip_v:4;                 /* Version */
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip_v:4,                 /* Version */
            ip_hl:4;                /* Header 길이*/
#else
# error "Please fix <endian.h>"
#endif
    uint8_t ip_tos;                 /* Type of service */
    uint16_t ip_len;                /* Total length */
    uint16_t ip_id;                 /* ID */
    uint16_t ip_off;                /* Fragment offset*/
    uint8_t ip_ttl;                 
    uint8_t ip_p;                   /* Protocol */
    uint16_t ip_sum;                /* Checksum */
    struct in_addr ip_src, ip_dst;  /* SRC, DST IP address */
};

// TCP header
struct libnet_tcp_hdr {
    uint16_t th_sport;              /* SRC port */
    uint16_t th_dport;              /* DST port */
    uint32_t th_seq;                /* Seq number */
    uint32_t th_ack;                /* Ack number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t th_x2:4,                
            th_off:4;               /* Data offset */
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t th_off:4,               /* Data offset */
            th_x2:4;                
#else
# error "Please fix <endian.h>"
#endif
    uint8_t  th_flags;              /* TCP flags */
    uint16_t th_win;                /* Window size */
    uint16_t th_sum;                /* Checksum */
    uint16_t th_urp;                /* Urgent pointer */
};

#endif /* MYLIBNET_HEADERS_H */

