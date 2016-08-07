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

/* Modified by: Matt Byers (byersmatt@ecs.vuw.ac.nz) */


#include <stdio.h>
#include <pcap.h>

#include <sys/socket.h>
#include <net/ethernet.h>       //ethernet header decleration
#include <arpa/inet.h>         //Definitions for internet operations
#include <netinet/in.h>       //Internet Adress Protocol Family
#include <netinet/ether.h>      //ethernet header decleration
#include <netinet/icmp6.h>      //icmpv6 header decleration
#include <netinet/ip.h>         //IPv4 header decleration
#include <netinet/ip6.h>        //IPv6 header decleration
#include <netinet/tcp.h>        //TCP header decleration
#include <netinet/udp.h>        //UDP header decleration
#include <netinet/ip_icmp.h>    //ICMP header decleration


/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

//Sourced from: http://www.bortzmeyer.org/files/readfile-ipv6.c
//IPV6 Header structure, as the netinet version was being difficult
struct ipv6_hdr {
    uint32_t        ip_vtcfl;	/* version then traffic class and flow label
                                 */
    uint16_t        ip_len;	/* payload length */
    uint8_t         ip_nxt;	/* next header (protocol) */
    uint8_t         ip_hopl;	/* hop limit (ttl) */
    struct in6_addr ip_src, ip_dst;	/* source and dest address */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void ipv4(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void ipv6(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_payload(const u_char *payload, int len);


/* declare pointers to packet headers */
const struct ether_header *ethernet;  /* The ethernet header [1] */
const struct ip *ip;              /* The IP header */
const struct ipv6_hdr *ip6;			/*The IPV6 Header*/
const struct tcphdr *tcp;            /* The TCP header */
const struct udphdr *udp;		/*The UDP header*/
const struct icmphdr *icmp;		/*The ICMP header*/
const char *payload;                    /* Packet payload */

int size_ip;
int size_ip6;
int size_tcp;
int size_udp;
int size_icmp;
int size_payload;


/* Takes packets from the pcap loop method and gets the ethernet header, then calls the appropriate method depending on whether it gets an IPv6 or IPv4 packet */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    static int count = 1;                   /* packet counter */
    
    printf("\nPacket number %d:\n", count);
    
    ethernet = (struct ether_header*)(packet);
    
    //Check the ethernet type, to see if the packet is IPV6 or IPV4
    if(ethernet->ether_type == ntohs(ETHERTYPE_IPV6)) {
        printf("       Type: IPV6 Packet\n");
        ipv6(args, header, packet);
    }
    else if(ethernet->ether_type == ntohs(ETHERTYPE_IP)) {
        printf("       Type: IPV4 Packet\n");
        ipv4(args, header, packet);
    }
    else {
        printf("       Type: Unknown Packet\n");
        size_payload = 0; //Set to 0 to stop the payload being printed
    }
    
    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
    if (size_payload > 0) {
        printf("   Payload (%d bytes):\n", size_payload);
        print_payload(payload, size_payload);
    }
    
    count++;
    
}


// Partially sourced and lots of guidance from: http://www.tcpdump.org/sniffex.c
/* Handles IPv4 packets, switches based protocols, to retrieve the correct protocol header and size the payload accordingly */
void ipv4(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    
    ip = (struct ip*)(packet + SIZE_ETHERNET);
    size_ip = sizeof(struct ip);
    
    //Check paket is of a valid size
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    
    //Source and destination addresses
    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));
    
    //determine protocol
    switch(ip->ip_p) {
            
        case IPPROTO_TCP: //TCP protocol
            printf("   Protocol: TCP\n");
            tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = sizeof(struct tcphdr);
            if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
            }
            
            printf("   Src port: %d\n", ntohs(tcp->th_sport));
            printf("   Dst port: %d\n", ntohs(tcp->th_dport));
            
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
            size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
            break;
            
        case IPPROTO_UDP: //UDP protocol
            printf("   Protocol: UDP\n");
            udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);
            size_udp = sizeof(struct udphdr);
            if(size_udp < 8){
                printf("   * Invalid UDP header length: %u bytes\n", size_udp);
                return;
            }
            
            printf("   Src port: %d\n", ntohs(udp->uh_sport));
            printf("   Dst port: %d\n", ntohs(udp->uh_dport));
            
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
            size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
            break;
            
        case IPPROTO_ICMP: //ICMP protocol
            printf("   Protocol: ICMP\n");
            icmp = (struct icmphdr*)(packet + SIZE_ETHERNET + size_ip);
            size_icmp = sizeof(struct icmphdr);
            if(size_icmp < 8){
                printf("   * Invalid UDP header length: %u bytes\n", size_udp);
                return;
            }
            
            //Switch on the ICMP types, lots of types not added here.
            switch(icmp->type){
                    
                case 0:
                    printf("    Type: Echo Reply\n");
                    break;
                case 3:
                    printf("    Type: Destination Unreachable\n");
                    break;
                case 4:
                    printf("    Type: Source Quench (Deprecated)\n");
                    break;
                //More Types here, just haven't added them....
                default:
                    printf("    Type: Unknown");
                    break;
                    
            }
            
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
            size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
            break;
            
        default:
            printf("   Protocol: unknown\n");
            size_payload = 0; //Set to 0 to stop the payload being printed
            return;
    }
    
}

/* Processes IPv6 packets, to retrieve the source/destination address and the protocol type */
void ipv6(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    ip6 = (struct ipv6_hdr*)(packet + SIZE_ETHERNET);
    size_ip6 = sizeof(struct ipv6_hdr);
    char *src, *dst;
    
    //Checks for invalid packet length
    if (size_ip6 < 40) {
        printf("   * Invalid IPV6 header length: %u bytes\n", size_ip6);
        return;
    }

    src = malloc(INET6_ADDRSTRLEN);
    dst = malloc(INET6_ADDRSTRLEN);
    
    inet_ntop(AF_INET6, &ip6->ip_src, src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6->ip_dst, dst, INET6_ADDRSTRLEN);
    
    printf("       From: %s\n", src);
    printf("         To: %s\n", dst);
    
    printf("   Protocol: %d\n", ip6->ip_nxt);
    //Not sure how to then get the next header from the IPv6 packet....
    
    size_payload = 0; //Set to 0 to stop the payload being printed
}


/*============================ Helper Methods ============================*/


//Sourced from: http://www.tcpdump.org/sniffex.c
/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset) {
    
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


//Sourced from: http://www.tcpdump.org/sniffex.c
/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len) {
    
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


int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Must have an argument, either a file name or '-'\n");
        return -1;
    }
    
    pcap_t *handle = pcap_open_offline(argv[1], NULL);
    pcap_loop(handle, 30, got_packet, NULL); // Capture 30 packets, to make debug less painful
    //pcap_loop(handle, 1024*1024, got_packet, NULL);
    pcap_close(handle);
    
    return 0;
}
