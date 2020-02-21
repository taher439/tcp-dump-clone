#ifndef _PROTOCOLS_H
#define _PROTOCOLS_H
#define _GNU_SOURCE
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include "bootp.h"
#include "dns.h"
#include <ctype.h>

extern int verb_level;

#define ERR(x, fn) do {if(x){\
  perror(fn); \
  exit(EXIT_FAILURE);}\
}while(0)
void          analyze_http         (const u_char *, u_int);
void          analyze_telnet       (const u_char *, u_int);
void          analyze_ftp          (const u_char *, u_int);
void          analyze_dns          (const u_char *, u_int);
void          print_dhcp_msg_type  (const u_char *);
void          analyze_dhcp_options (u_char *, u_int); 
void          analyze_bootp        (const u_char *, u_int);
void          analyze_tcp          (const u_char *, u_int);
void          analyze_udp          (const u_char *);
void          print_mac_addr       (const u_char *);
void          analyze_packet       (u_char*,
                                    const struct pcap_pkthdr*, 
                                    const u_char*);
#endif
