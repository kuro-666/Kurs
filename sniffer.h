#ifndef SNIFFER_H
#define SNIFFER_H

#include <ncurses.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#define SIZE_ETHERNET 14 /* Ethernet headers size in bytes   */

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

/* IP header */
struct sniff_ip;

/* TCP header */
struct sniff_tcp;

/* Callback function used in pcap_loop() */
void process_packet(u_char *args,const struct pcap_pkthdr *header,
 const u_char *packet);

/* Prints packet payload */
void print_payload(const char *payload, int len);

/* Prints packet payload line */
void print_hex_ascii_line(const u_char *payload, int len, int offset);

/* Presents essential functionality using pcap library */
void sniffer(WINDOW *window, FILE *f, char *filter, char *device,
  int num_packets);

#endif
