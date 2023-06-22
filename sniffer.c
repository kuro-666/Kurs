#include "sniffer.h"

struct sniff_ip {
  u_char  ip_vhl;                 /* Version << 4 | Header length >> 2 */
  u_char  ip_tos;                 /* Type of service                   */
  u_short ip_len;                 /* Total length                      */
  u_short ip_id;                  /* Identification                    */
  u_short ip_off;                 /* Fragment offset field             */
#define IP_RF 0x8000              /* Reserved fragment flag            */
#define IP_DF 0x4000              /* Dont fragment flag                */
#define IP_MF 0x2000              /* More fragments flag               */
#define IP_OFFMASK 0x1fff         /* Mask for fragmenting bits         */
  u_char  ip_ttl;                 /* Time to live                      */
  u_char  ip_p;                   /* Protocol                          */
  u_short ip_sum;                 /* Checksum                          */
  struct  in_addr ip_src,ip_dst;  /* Src and dst address               */
};

struct sniff_tcp {
        u_short th_sport;               /* Source port                 */
        u_short th_dport;               /* Destination port            */
        tcp_seq th_seq;                 /* Sequence number             */
        tcp_seq th_ack;                 /* Acknowledgement number      */
        u_char  th_offx2;               /* Data offset, rsvd           */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* Window */
        u_short th_sum;                 /* Checksum */
        u_short th_urp;                 /* Urgent pointer */
};

WINDOW *win;
FILE *f;

void process_packet(u_char *args, const struct pcap_pkthdr *header,
  const u_char *packet) {

	static int count = 1;                   /* packet counter */

	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	wprintw(win, "Processing packet %d...\n", count);
  fprintf(f, "\nPacket %d: \n", count);
  count++;
  wrefresh(win);

	/* Define/compute IP header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		wprintw(win, "Invalid IP header length: %u bytes\n", size_ip);
    wrefresh(win);
		return;
	}

	/* Print source and destination IP addresses */
	fprintf(f, "       From: %s\n", inet_ntoa(ip->ip_src));
	fprintf(f, "         To: %s\n", inet_ntoa(ip->ip_dst));

	/* Determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			fprintf(f, "   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			fprintf(f, "   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			fprintf(f, "   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			fprintf(f, "   Protocol: IP\n");
			return;
		default:
			fprintf(f, "   Protocol: unknown\n");
			return;
	}

	/* Define/compute TCP header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		wprintw(win, "Invalid TCP header length: %u bytes\n", size_tcp);
    wrefresh(win);
		return;
	}

	fprintf(f, "   Src port: %d\n", ntohs(tcp->th_sport));
	fprintf(f, "   Dst port: %d\n", ntohs(tcp->th_dport));

	/* Define/compute TCP payload (segment) offset */
	payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* Compute TCP payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	if (size_payload > 0) {
		fprintf(f, "   Payload: %d bytes\n", size_payload);
		print_payload(payload, size_payload);
	}

  return;
}

void print_payload(const char *payload, int len) {

	int len_rem = len;
	int line_width = 16;			/* Number of bytes per line */
	int line_len;
	int offset = 0;					  /* Zero-based offset counter */
	const u_char *ch = (u_char *)payload;

	if (len <= 0)
		return;

	/* Data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* Data spans multiple lines */
	while(1) {
		line_len = line_width % len_rem;            /* Current line length */
		print_hex_ascii_line(ch, line_len, offset); /* Print line          */
		len_rem = len_rem - line_len;               /* Remaining           */
		ch = ch + line_len;                         /* Shift pointer       */
		offset = offset + line_width;               /* Add offset          */

		if (len_rem <= line_width) {                /* Last line           */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

  return;
}

void print_hex_ascii_line(const u_char *payload, int len, int offset) {

	int i;
	int gap;
	const u_char *ch;

	fprintf(f, "%05d   ", offset); /* Line offset */

	ch = payload;
	for(i = 0; i < len; i++) {
		fprintf(f, "%02x ", *ch);
		ch++;

		if (i == 7)
			fprintf(f, " ");
	}

	if (len < 8)
		fprintf(f, " ");

	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			fprintf(f, "   ");
		}
	}
	fprintf(f, "   ");

	/* Ascii if printable */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			fprintf(f, "%c", *ch);
		else
			fprintf(f, ".");
		ch++;
	}

	fprintf(f, "\n");

  return;
}

void sniffer(WINDOW *window, FILE *file, char *filter, char *device,
  int num_packets) {

  f = file;
  win = window;

  char errbuf[PCAP_ERRBUF_SIZE]; /* Error buffer                         */
  pcap_t* descr;                 /*                                      */
  struct bpf_program fp;         /* Compiled filter program (expression) */
  bpf_u_int32 maskp;             /* Subnet mask                          */
  bpf_u_int32 netp;              /* IP                                   */

  /* Get device */
  if(!device[0]) {
    device = pcap_lookupdev(errbuf);

    if(device == NULL) {
      wprintw(win, "%s\nPress any button to exit...", errbuf);
      wrefresh(win);
      return;
    }
  }

  /* Get the network address and mask */
  pcap_lookupnet(device, &netp, &maskp, errbuf);

  /* Open device for reading in promiscuous mode */
  descr = pcap_open_live(device, BUFSIZ, 1, -1, errbuf);
  if(descr == NULL) {
    wprintw(win, "pcap_open_live(): %s\nPress any button to exit...", errbuf);
    wrefresh(win);
    return;
  }

  /* Make sure we're capturing on an Ethernet device */
  if (pcap_datalink(descr) != DLT_EN10MB) {
    wprintw(win,
      "%s is not an Ethernet. Press any button to exit...\n",
      device
    );
    wrefresh(win);
    return;
  }

  /* Compile the filter expression */
  if(pcap_compile(descr, &fp, filter, 0, netp) == -1) {
    wprintw(win, "Error calling pcap_compile. Press any button to exit...\n");
    wrefresh(win);
    return;;
  }

  /* Set the filter */
  if(pcap_setfilter(descr, &fp) == -1) {
    wprintw(win, "Error setting filter. Press any button to exit...\n");
    wrefresh(win);
    return;
  }

  /* Loop for callback function */
  pcap_loop(descr, num_packets, process_packet, NULL);

  pcap_freecode(&fp);
  pcap_close(descr);

  wprintw(
    win,
    "\n%d captured packet(s) were printed in specified file. \
    \nPress any button to exit...",
    num_packets
  );
  wrefresh(win);

  return;
}
