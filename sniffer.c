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




void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  static int count = 1;                   /* packet counter */

  /* declare pointers to packet headers */
  const struct ether_header *ethernet;  /* The ethernet header [1] */
  const struct ip *ip;              /* The IP header */
  const struct tcphdr *tcp;            /* The TCP header */
  const char *payload;                    /* Packet payload */

  int size_ip;
  int size_tcp;
  int size_payload;

  printf("\nPacket number %d:\n", count);
  count++;

  /* define ethernet header */
  ethernet = (struct ether_header*)(packet);

  /* define/compute ip header offset */
  ip = (struct ip*)(packet + SIZE_ETHERNET);
  size_ip = sizeof(struct ip);
  if (size_ip < 20) {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }

  /* print source and destination IP addresses */
  printf("       From: %s\n", inet_ntoa(ip->ip_src));
  printf("         To: %s\n", inet_ntoa(ip->ip_dst));

  /* determine protocol */
  switch(ip->ip_p) {
    case IPPROTO_TCP:
      printf("   Protocol: TCP\n");
      break;
    case IPPROTO_UDP:
      printf("   Protocol: UDP\n");
      return;
    case IPPROTO_ICMP:
      printf("   Protocol: ICMP\n");
      return;
    case IPPROTO_IP:
      printf("   Protocol: IP\n");
      return;
    default:
      printf("   Protocol: unknown\n");
      return;
  }

  /*
   *  OK, this packet is TCP.
   */

  /* define/compute tcp header offset */
  tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
  size_tcp = sizeof(struct tcphdr);
  if (size_tcp < 20) {
    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
    return;
  }

  printf("   Src port: %d\n", ntohs(tcp->th_sport));
  printf("   Dst port: %d\n", ntohs(tcp->th_dport));

  /* define/compute tcp payload (segment) offset */
  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

  /* compute tcp payload (segment) size */
  size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

  /*
   * Print payload data; it might be binary, so don't just
   * treat it as a string.
   */
  if (size_payload > 0) {
    printf("   Payload (%d bytes):\n", size_payload);
    print_payload(payload, size_payload);
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
    pcap_loop(handle, 1024*1024, got_packet, NULL);
    pcap_close(handle);

    return 0;
}
