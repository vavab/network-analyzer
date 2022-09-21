#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <net/if_arp.h>

#define UDP_HLEN 8


struct dns {
    u_int16_t id;
    u_char qr;
    unsigned int opcode:4;
    u_int flags:4;
    u_int reserved:4;
    unsigned int rcode:4;
    uint16_t qdcount;
    uint16_t ancount;   
    uint16_t nscount;
    uint16_t arcount;
};

void panik(char *function, char *error);

void got_packet1(u_char *user, const struct pcap_pkthdr *h, const u_char *packet);

void got_packet2(u_char *user, const struct pcap_pkthdr *h, const u_char *packet);

void got_packet3(u_char *user, const struct pcap_pkthdr *h, const u_char *packet);

#endif
