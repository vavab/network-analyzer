#include "capture.h"
#include "bootp.h"

void panik(char *function, char *error)
{
    fprintf(stderr, "\nError: %s: %s\n", function, error) ;
}

int count = 0;

// Callback functions
void got_packet3(u_char *user, const struct pcap_pkthdr *h, const u_char *packet)
{
    printf("\n|---------------- Packet number %d ----------------\n|\n", ++count);

    // On 'cast' le paquet récupéré

    const struct ether_header *eth;
    eth = (struct ether_header*)(packet);

    const struct ip *ip4;
    const struct arphdr *arp;
    ip4 = (struct ip*)(packet + ETH_HLEN);
    arp = (struct arphdr*)(packet + ETH_HLEN);

    const struct tcphdr *tcp;
    const struct udphdr *udp;

    const struct bootp *bootp;
    const struct dns* dns;

    const char *telnet;
    const char *payload = NULL;
        

    int i;

    printf("|----------------- Ethernet header ----------------\n| Ethernet destination address: ");
    for(i=0 ; i<ETHER_ADDR_LEN ; i++)
        printf("%02X:", (eth->ether_dhost)[i]);

    printf("\n| Ethernet source address: ");
    for(i=0 ; i<ETHER_ADDR_LEN ; i++)
        printf("%02X:", (eth->ether_shost)[i]);     
    printf("\n| ");

    printf("Data type: ");
    

    int type = ntohs(eth->ether_type);
    switch (type)
    {
        case ETHERTYPE_IP :
            printf("IPv4\n");
            printf("      |---------------- IPv4 header ---------------\n") ;
            printf("      | Version: %d\n", ip4->ip_v);
            printf("      | Header lenght: %d\n", ip4->ip_hl);
            tcp = (struct tcphdr*)(packet + ETH_HLEN + 4*ip4->ip_hl);
            udp = (struct udphdr*)(packet + ETH_HLEN + 4*ip4->ip_hl);
            printf("      | Type of service: %d\n", ip4->ip_tos);
            printf("      | Total lenght: %d\n", ntohs(ip4->ip_len));
            printf("      | Identification number: %d\n", ntohs(ip4->ip_id));
            printf("      | Fragment offset: ");
            switch (ntohs(ip4->ip_off))
            {
                case IP_RF:
                    printf("Reserved fragment flag\n");
                    break;
                case IP_DF:
                    printf("No flag fragmentation\n");
                    break;
                case IP_MF:
                    printf("More fragments to come...\n");
                    break;
                default :
                    printf("%d\n", ntohs(ip4->ip_off));
            }
            printf("      | Time to live: %d\n", ntohs(ip4->ip_ttl));
            printf("      | Source IP address: %s\n", inet_ntoa(ip4->ip_src));
            printf("      | Destination IP address: %s\n", inet_ntoa(ip4->ip_dst));
            printf("      | Protocol: number %d, ", ip4->ip_p);
            switch (ip4->ip_p)
                {
                case IPPROTO_ICMP:
                    printf("ICMP\n");
                    break;
                case IPPROTO_IGMP:
                    printf("IGMP\n");
                    break;
                case IPPROTO_TCP:
                    printf("TCP\n");
                    payload = (char *)(packet + ETH_HLEN + 4*(ip4->ip_hl) + 4*(tcp->th_off));
                    printf("            |------------- TCP header --------------\n") ;
                    printf("            | Sequence number: %d\n", ntohs(tcp->th_seq));
                    printf("            | Acknowledgement number: %d\n", ntohs(tcp->th_ack));
                    printf("            | Source port: %d, ", ntohs(tcp->th_sport));
                    switch(ntohs(tcp->th_sport))
                    {
                        case 1:
                            printf("TCP Port Multiplexer\n");
                            break;
                        case 7:
                            printf("echo\n");
                            break;
                        case 23:
                            printf("Telnet\n");
                            telnet = (char*)(packet + ETH_HLEN + 4*(ip4->ip_hl) + 4*(tcp->th_off));
                            printf("                  |--------------- Telnet frame -----------------|\n") ;
                            printf("__________________|                                              |_______________________\n\n");
                            printf("%s\n", telnet);
                            printf("_________________________________________________________________________________________\n");
                            break;
                        case 53:
                            printf("Domain Name Server (DNS)\n");
                            dns = (struct dns*)(packet + ETH_HLEN + 4*(ip4->ip_hl) + 4*(tcp->th_off));
                            printf("                  |--------------- DNS header -----------------|\n") ;
                            printf("                  | Identifier: %d\n", ntohs(dns->id));
                            switch(ntohs(dns->qr))
                            {
                                case 0 :
                                    printf("                  | Query\n");
                                    break;
                                case 1:
                                    printf("                  | Response\n");
                                    break;
                            }
                            switch(ntohs(dns->opcode))
                            {
                                case 0:
                                    printf("                  | Standard query (QUERY)\n");
                                    break;
                                case 1:
                                    printf("                  | Inverse query (IQUERY)\n");
                                    break;
                                case 2:
                                    printf("                  | Server status request (STATUS)\n");
                                    break;
                            }
                            switch(ntohs(dns->rcode))
                            {
                                case 0:
                                    printf("                  | No error condition\n");
                                    break;
                                case 1:
                                    printf("                  | Format error - The name server was unable to interpret the query\n");
                                    break;
                                case 2:
                                    printf("                  | Server failure - The name server was unable to process this query due to a problem with the name server\n");
                                    break;
                                case 3:
                                    printf("                  | Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist\n");
                                    break;
                                case 4:
                                    printf("                  | Not Implemented - The name server does not support the requested kind of query\n");
                                    break;
                                case 5:
                                    printf("                  | Refused - The name server refuses to perform the specified operation for policy reasons\n");
                                    break;
                                default:
                                    break;
                            }
                            break;
                        case 443:
                            printf("HTTP protocol over TLS/SSL\n");
                            break;
                        default:
                            printf("Unknown port\n");
                            break;
                    }
                    printf("            | Destination port: %d, ", ntohs(tcp->th_dport));
                    switch(ntohs(tcp->th_dport))
                    {
                        case 1:
                            printf("TCP Port Multiplexer\n");
                            break;
                        case 7:
                            printf("echo\n");
                            break;
                        case 23:
                            printf("Telnet\n");
                            telnet = (char*)(packet + ETH_HLEN + 4*(ip4->ip_hl) + 4*(tcp->th_off));
                            printf("                  |--------------- Telnet frame -----------------|\n") ;
                            printf("__________________|                                              |_______________________\n\n");
                            printf("%s\n", telnet);
                            printf("_________________________________________________________________________________________\n");
                            break;
                        case 53:
                            printf("Domain Name Server (DNS)\n");
                            break;
                        case 443:
                            printf("HTTP protocol over TLS/SSL\n");
                            break;
                        default:
                            printf("Unknown port\n");
                            break;
                    }
                    
                    printf("                  |--------------- Data payload -----------------|\n") ;
                    printf("__________________|                                              |_______________________\n\n");
                    printf("%s\n", payload);
                    printf("_________________________________________________________________________________________\n");
                    break;
                case IPPROTO_UDP:
                    printf("UDP\n");
                    payload = (char*)(packet + ETH_HLEN + 4*(ip4->ip_hl) + 4*(udp->uh_ulen));
                    printf("            |------------- UDP header --------------\n") ;
                    printf("            | Source port: %d\n", ntohs(udp->uh_sport));
                    printf("            | Destination port: %d, ", ntohs(udp->uh_dport));
                    switch (udp->uh_dport)
                    {
                        case 7:
                            printf("echo\n");
                            break;
                        case 21:
                            printf("FTP\n");
                            break;
                        case 22:
                            printf("SSH\n");
                            break;
                        
                        case 25:
                            printf("SMTP\n");
                            break;
                        case 67||68:
                            printf("bootp\n");
                            bootp = (struct bootp*)(packet + ETH_HLEN + 4*(ip4->ip_hl) + UDP_HLEN);
                            printf("                  |------------- bootp frame --------------\n") ;
                            switch (bootp->opcode)
                            {
                                case 1:
                                    printf("                  | bootp request\n");
                                    break;
                                case 2:
                                    printf("                  | bootp response\n");
                                    break;
                            }
                            printf("                  | Hop count: %d\n", ntohs(bootp->hops));
                            printf("                  | Transaction id: %d\n", ntohs(bootp->id));
                            printf("                  | Server name: %s\n", bootp->sname);
                            printf("                  | Server IP address: %d\n", ntohs(bootp->siaddr));
                            printf("                  | Gateway IP address: %d\n", ntohs(bootp->giaddr));
                            printf("                  | Boot file name: %s\n", bootp->bootfile);
                            
                            break;
                        
                        case 80:
                            printf("HTTP\n");
                            break;
                        default:
                            printf("Unknown\n");
                            break;
                    }
                    printf("            | Lenght: %d\n", ntohs(udp->uh_ulen));
                    break;
                case IPPROTO_EGP:
                    printf("EGP\n");
                    break;

                default:
                    printf("Unknown\n");
                    break;
                }
            break;
        
        case ETHERTYPE_ARP :
            printf("ARP\n");
            printf("      |--------------- ARP header -----------------\n      |\n") ;
            printf("      | Operation: ");
            switch (ntohs(arp->ar_op))
            {
                case ARPOP_REQUEST:
                    printf("ARP request\n");
                    break;
                case ARPOP_REPLY:
                    printf("ARP reply\n");
                    break;
                case ARPOP_NAK:
                    printf("ARP NACK\n");
                    break;
                default:
                    printf("Unknown opcode\n");
                    break;
            }
            break;
        
        case ETHERTYPE_REVARP :
            printf("RARP\n");
            printf("      |--------------- RARP header -----------------\n      |\n") ;
            printf("      | Operation: \n");
            switch (arp->ar_op)
            {
                case ARPOP_RREQUEST:
                    printf("RARP request\n");
                    break;
                case ARPOP_RREPLY:
                    printf("RARP reply\n");
                    break;
                default:
                    printf("Unknown opcode\n");
                    break;
            }
            break;

        case ETHERTYPE_IPV6 :
            printf("IPv6\n");
            printf("      |--------------- IPv6 header -----------------\n      |\n") ;
            printf("      |\n");
            break;

        case ETHERTYPE_AT :
            printf("EtherTalk\n");
            break;

        case 0x880B :
            printf("PPP\n");
            break;
        
        case 0x8863 :
            printf("PPPoE Discovery\n");
            break;

        case 0x8864 :
            printf("PPPoE Session\n");
            break;

        case 0x814C :
            printf("SNMP\n");
            break;

        case ETHERTYPE_LOOPBACK :
            printf("Loopback, used to test interfaces\n");
            break;
        
        case ETHERTYPE_PUP :
            printf("Xerox PUP\n");
            break;

        case ETHERTYPE_SPRITE :
            printf("Sprite\n");
            break;

        case ETHERTYPE_AARP :
            printf("AppleTalk ARP\n");
            break;

        case ETHERTYPE_VLAN :
            printf("IEEE 802.1Q VLAN tagging\n");
            break;

        case ETHERTYPE_IPX :
            printf("IPX\n");
            break;

        default :
            printf("Unknown\n");

    }
    

    
}


void got_packet1(u_char *user, const struct pcap_pkthdr *h, const u_char *packet)
{
    printf("\n\n|--------------------- Packet number %d ---------------------\n|\n", ++count);

    // On 'cast' le paquet récupéré

    const struct ether_header *eth;
    eth = (struct ether_header*)(packet);

    const struct ip *ip4;
    const struct arphdr *arp;
    ip4 = (struct ip*)(packet + ETH_HLEN);
    arp = (struct arphdr*)(packet + ETH_HLEN);

    const struct tcphdr *tcp;
    const struct udphdr *udp;

    const struct bootp *bootp;
      

    printf("| The protocols used are: Ethernet, ");
    

    int type = ntohs(eth->ether_type);
    switch (type)
    {
        case ETHERTYPE_IP :
            printf("IPv4, ");
            
            tcp = (struct tcphdr*)(packet + ETH_HLEN + 4*ip4->ip_hl);
            udp = (struct udphdr*)(packet + ETH_HLEN + 4*ip4->ip_hl);

            switch (ip4->ip_p)
                {
                case IPPROTO_ICMP:
                    printf("ICMP.\n ");
                    break;
                case IPPROTO_IGMP:
                    printf("IGMP.\n ");
                    break;
                case IPPROTO_TCP:
                    printf("TCP ");
                    
                    switch(ntohs(tcp->th_sport))
                    {
                        case 1:
                            printf("(TCP Port Multiplexer).\n");
                            break;
                        case 7:
                            printf("(echo).\n");
                            break;
                        case 23:
                            printf("(Telnet).\n");
                            break;
                        case 53:
                            printf("(Domain Name Server (DNS)).\n");
                            break;
                        case 443:
                            printf("(HTTP protocol over TLS/SSL).\n");
                            break;
                        default:
                            printf("(Unknown port).\n");
                            break;
                    }
                    break;

                case IPPROTO_UDP:
                    printf("UDP ");

                    switch (udp->uh_dport)
                    {
                        case 7:
                            printf("(echo).\n");
                            break;
                        case 21:
                            printf("(FTP).\n");
                            break;
                        case 22:
                            printf("(SSH).\n");
                            break;
                        
                        case 25:
                            printf("(SMTP).\n");
                            break;
                        case 67||68:
                            bootp = (struct bootp*)(packet + ETH_HLEN + 4*(ip4->ip_hl) + UDP_HLEN);

                            switch (bootp->opcode)
                            {
                                case 1:
                                    printf("(bootp request).\n");
                                    break;
                                case 2:
                                    printf("(bootp response).\n");
                                    break;
                            }
                            break;
                        
                        case 80:
                            printf("(HTTP).\n");
                            break;
                        default:
                            printf("(Unknown).\n");
                            break;
                    }
                    break;
                case IPPROTO_EGP:
                    printf("(EGP).\n");
                    break;

                default:
                    printf("Unknown\n");
                    break;
                }
            break;
        
        case ETHERTYPE_ARP :
            printf("ARP ");
            switch (ntohs(arp->ar_op))
            {
                case ARPOP_REQUEST:
                    printf("(request).\n");
                    break;
                case ARPOP_REPLY:
                    printf("(reply).\n");
                    break;
                case ARPOP_NAK:
                    printf("(NACK).\n");
                    break;
                default:
                    printf("(Unknown).\n");
                    break;
            }
            break;
        
        case ETHERTYPE_REVARP :
            printf("RARP\n");
            switch (arp->ar_op)
            {
                case ARPOP_RREQUEST:
                    printf("(request).\n");
                    break;
                case ARPOP_RREPLY:
                    printf("(reply).\n");
                    break;
                default:
                    printf("(Unknown).\n");
                    break;
            }
            break;

        case ETHERTYPE_IPV6 :
            printf("IPv6.\n");
            break;

        case ETHERTYPE_AT :
            printf("EtherTalk.\n");
            break;

        case 0x880B :
            printf("PPP.\n");
            break;
        
        case 0x8863 :
            printf("PPPoE Discovery.\n");
            break;

        case 0x8864 :
            printf("PPPoE Session.\n");
            break;

        case 0x814C :
            printf("SNMP.\n");
            break;

        case ETHERTYPE_LOOPBACK :
            printf("Loopback.\n");
            break;
        
        case ETHERTYPE_PUP :
            printf("Xerox PUP.\n");
            break;

        case ETHERTYPE_SPRITE :
            printf("Sprite.\n");
            break;

        case ETHERTYPE_AARP :
            printf("AppleTalk ARP.\n");
            break;

        case ETHERTYPE_VLAN :
            printf("IEEE 802.1Q VLAN tagging.\n");
            break;

        case ETHERTYPE_IPX :
            printf("IPX.\n");
            break;

        default :
            break;

    }
    printf("|------------------------------------------------------------\n");

    
}


void got_packet2(u_char *user, const struct pcap_pkthdr *h, const u_char *packet)
{
    printf("\n|---------------- Packet number %d ----------------\n|\n", ++count);

    // On 'cast' le paquet récupéré

    const struct ether_header *eth;
    eth = (struct ether_header*)(packet);

    const struct ip *ip4;
    const struct arphdr *arp;
    ip4 = (struct ip*)(packet + ETH_HLEN);
    arp = (struct arphdr*)(packet + ETH_HLEN);

    const struct tcphdr *tcp;
    const struct udphdr *udp;

    const struct bootp *bootp;
    const struct dns* dns;

    const char *telnet;
    const char *payload = NULL;
        

    int i;
    printf("| This frame is\n");
    printf("|----------------- Ethernet header ----------------\n| Ethernet destination address: ");
    for(i=0 ; i<ETHER_ADDR_LEN ; i++)
        printf("%02X:", (eth->ether_dhost)[i]);

    printf("\n| Ethernet source address: ");
    for(i=0 ; i<ETHER_ADDR_LEN ; i++)
        printf("%02X:", (eth->ether_shost)[i]);     
    printf("\n| ");

    printf("Data type: ");
    

    int type = ntohs(eth->ether_type);
    switch (type)
    {
        case ETHERTYPE_IP :
            printf("IPv4\n");
            printf("      |---------------- IPv4 header ---------------\n") ;
            printf("      | Version: %d\n", ip4->ip_v);
            printf("      | Header lenght: %d\n", ip4->ip_hl);
            tcp = (struct tcphdr*)(packet + ETH_HLEN + 4*ip4->ip_hl);
            udp = (struct udphdr*)(packet + ETH_HLEN + 4*ip4->ip_hl);
            printf("      | Type of service: %d\n", ip4->ip_tos);
            printf("      | Total lenght: %d\n", ntohs(ip4->ip_len));
            printf("      | Identification number: %d\n", ntohs(ip4->ip_id));
            printf("      | Fragment offset: ");
            switch (ntohs(ip4->ip_off))
            {
                case IP_RF:
                    printf("Reserved fragment flag\n");
                    break;
                case IP_DF:
                    printf("No flag fragmentation\n");
                    break;
                case IP_MF:
                    printf("More fragments to come...\n");
                    break;
                default :
                    printf("%d\n", ntohs(ip4->ip_off));
            }
            printf("      | Time to live: %d\n", ntohs(ip4->ip_ttl));
            printf("      | Source IP address: %s\n", inet_ntoa(ip4->ip_src));
            printf("      | Destination IP address: %s\n", inet_ntoa(ip4->ip_dst));
            printf("      | Protocol: number %d, ", ip4->ip_p);
            switch (ip4->ip_p)
                {
                case IPPROTO_ICMP:
                    printf("ICMP\n");
                    break;
                case IPPROTO_IGMP:
                    printf("IGMP\n");
                    break;
                case IPPROTO_TCP:
                    printf("TCP\n");
                    payload = (char *)(packet + ETH_HLEN + 4*(ip4->ip_hl) + 4*(tcp->th_off));
                    printf("            |------------- TCP header --------------\n") ;
                    printf("            | Sequence number: %d\n", ntohs(tcp->th_seq));
                    printf("            | Acknowledgement number: %d\n", ntohs(tcp->th_ack));
                    printf("            | Source port: %d, ", ntohs(tcp->th_sport));
                    switch(ntohs(tcp->th_sport))
                    {
                        case 1:
                            printf("TCP Port Multiplexer\n");
                            break;
                        case 7:
                            printf("echo\n");
                            break;
                        case 23:
                            printf("Telnet\n");
                            telnet = (char*)(packet + ETH_HLEN + 4*(ip4->ip_hl) + 4*(tcp->th_off));
                            printf("                  |--------------- Telnet frame -----------------|\n") ;
                            printf("__________________|                                              |_______________________\n\n");
                            printf("%s\n", telnet);
                            printf("_________________________________________________________________________________________\n");
                            break;
                        case 53:
                            printf("Domain Name Server (DNS)\n");
                            dns = (struct dns*)(packet + ETH_HLEN + 4*(ip4->ip_hl) + 4*(tcp->th_off));
                            printf("                  |--------------- DNS header -----------------|\n") ;
                            printf("                  | Identifier: %d\n", ntohs(dns->id));
                            switch(ntohs(dns->qr))
                            {
                                case 0 :
                                    printf("                  | Query\n");
                                    break;
                                case 1:
                                    printf("                  | Response\n");
                                    break;
                            }
                            switch(ntohs(dns->opcode))
                            {
                                case 0:
                                    printf("                  | Standard query (QUERY)\n");
                                    break;
                                case 1:
                                    printf("                  | Inverse query (IQUERY)\n");
                                    break;
                                case 2:
                                    printf("                  | Server status request (STATUS)\n");
                                    break;
                            }
                            switch(ntohs(dns->rcode))
                            {
                                case 0:
                                    printf("                  | No error condition\n");
                                    break;
                                case 1:
                                    printf("                  | Format error - The name server was unable to interpret the query\n");
                                    break;
                                case 2:
                                    printf("                  | Server failure - The name server was unable to process this query due to a problem with the name server\n");
                                    break;
                                case 3:
                                    printf("                  | Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist\n");
                                    break;
                                case 4:
                                    printf("                  | Not Implemented - The name server does not support the requested kind of query\n");
                                    break;
                                case 5:
                                    printf("                  | Refused - The name server refuses to perform the specified operation for policy reasons\n");
                                    break;
                                default:
                                    break;
                            }
                            break;
                        case 443:
                            printf("HTTP protocol over TLS/SSL\n");
                            break;
                        default:
                            printf("Unknown port\n");
                            break;
                    }
                    printf("            | Destination port: %d, ", ntohs(tcp->th_dport));
                    switch(ntohs(tcp->th_dport))
                    {
                        case 1:
                            printf("TCP Port Multiplexer\n");
                            break;
                        case 7:
                            printf("echo\n");
                            break;
                        case 23:
                            printf("Telnet\n");
                            telnet = (char*)(packet + ETH_HLEN + 4*(ip4->ip_hl) + 4*(tcp->th_off));
                            printf("                  |--------------- Telnet frame -----------------|\n") ;
                            printf("__________________|                                              |_______________________\n\n");
                            printf("%s\n", telnet);
                            printf("_________________________________________________________________________________________\n");
                            break;
                        case 53:
                            printf("Domain Name Server (DNS)\n");
                            break;
                        case 443:
                            printf("HTTP protocol over TLS/SSL\n");
                            break;
                        default:
                            printf("Unknown port\n");
                            break;
                    }
                    
                    printf("                  |--------------- Data payload -----------------|\n") ;
                    printf("__________________|                                              |_______________________\n\n");
                    printf("%s\n", payload);
                    printf("_________________________________________________________________________________________\n");
                    break;
                case IPPROTO_UDP:
                    printf("UDP\n");
                    payload = (char*)(packet + ETH_HLEN + 4*(ip4->ip_hl) + 4*(udp->uh_ulen));
                    printf("            |------------- UDP header --------------\n") ;
                    printf("            | Source port: %d\n", ntohs(udp->uh_sport));
                    printf("            | Destination port: %d, ", ntohs(udp->uh_dport));
                    switch (udp->uh_dport)
                    {
                        case 7:
                            printf("echo\n");
                            break;
                        case 21:
                            printf("FTP\n");
                            break;
                        case 22:
                            printf("SSH\n");
                            break;
                        
                        case 25:
                            printf("SMTP\n");
                            break;
                        case 67||68:
                            printf("bootp\n");
                            bootp = (struct bootp*)(packet + ETH_HLEN + 4*(ip4->ip_hl) + UDP_HLEN);
                            printf("                  |------------- bootp frame --------------\n") ;
                            switch (bootp->opcode)
                            {
                                case 1:
                                    printf("                  | bootp request\n");
                                    break;
                                case 2:
                                    printf("                  | bootp response\n");
                                    break;
                            }
                            printf("                  | Hop count: %d\n", ntohs(bootp->hops));
                            printf("                  | Transaction id: %d\n", ntohs(bootp->id));
                            printf("                  | Server name: %s\n", bootp->sname);
                            printf("                  | Server IP address: %d\n", ntohs(bootp->siaddr));
                            printf("                  | Gateway IP address: %d\n", ntohs(bootp->giaddr));
                            printf("                  | Boot file name: %s\n", bootp->bootfile);
                            
                            break;
                        
                        case 80:
                            printf("HTTP\n");
                            break;
                        default:
                            printf("Unknown\n");
                            break;
                    }
                    printf("            | Lenght: %d\n", ntohs(udp->uh_ulen));
                    break;
                case IPPROTO_EGP:
                    printf("EGP\n");
                    break;

                default:
                    printf("Unknown\n");
                    break;
                }
            break;
        
        case ETHERTYPE_ARP :
            printf("ARP\n");
            printf("      |--------------- ARP header -----------------\n      |\n") ;
            printf("      | Operation: ");
            switch (ntohs(arp->ar_op))
            {
                case ARPOP_REQUEST:
                    printf("ARP request\n");
                    break;
                case ARPOP_REPLY:
                    printf("ARP reply\n");
                    break;
                case ARPOP_NAK:
                    printf("ARP NACK\n");
                    break;
                default:
                    printf("Unknown opcode\n");
                    break;
            }
            break;
        
        case ETHERTYPE_REVARP :
            printf("RARP\n");
            printf("      |--------------- RARP header -----------------\n      |\n") ;
            printf("      | Operation: \n");
            switch (arp->ar_op)
            {
                case ARPOP_RREQUEST:
                    printf("RARP request\n");
                    break;
                case ARPOP_RREPLY:
                    printf("RARP reply\n");
                    break;
                default:
                    printf("Unknown opcode\n");
                    break;
            }
            break;

        case ETHERTYPE_IPV6 :
            printf("IPv6\n");
            printf("      |--------------- IPv6 header -----------------\n      |\n") ;
            printf("      |\n");
            break;

        case ETHERTYPE_AT :
            printf("EtherTalk\n");
            break;

        case 0x880B :
            printf("PPP\n");
            break;
        
        case 0x8863 :
            printf("PPPoE Discovery\n");
            break;

        case 0x8864 :
            printf("PPPoE Session\n");
            break;

        case 0x814C :
            printf("SNMP\n");
            break;

        case ETHERTYPE_LOOPBACK :
            printf("Loopback, used to test interfaces\n");
            break;
        
        case ETHERTYPE_PUP :
            printf("Xerox PUP\n");
            break;

        case ETHERTYPE_SPRITE :
            printf("Sprite\n");
            break;

        case ETHERTYPE_AARP :
            printf("AppleTalk ARP\n");
            break;

        case ETHERTYPE_VLAN :
            printf("IEEE 802.1Q VLAN tagging\n");
            break;

        case ETHERTYPE_IPX :
            printf("IPX\n");
            break;

        default :
            printf("Unknown\n");
    }
}
