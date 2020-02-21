#include "protocols.h"
// print udp and tcp flags
// add filter

void 
print_mac_addr(const u_char * addr) 
  {
    int i = 0;
    while (i < ETHER_ADDR_LEN) {
      fprintf(stdout,"%s%x", (i == 0) ? " " : ":", addr[i]);
      i++;
    }
    fflush(stdout);
  }

void 
analyze_packet(u_char *arg, 
               const struct pcap_pkthdr* pkthdr, 
               const u_char* packet)
  {
    fprintf(stdout, "\n\nGrabbed packet of length %d, ", pkthdr->len);
    fprintf(stdout, "Received at ..... %s,", ctime((const time_t*) &pkthdr->ts.tv_sec));
    
    const struct ether_header *ether_header = (struct ether_header*) packet;
    const struct iphdr *ip;
    const struct ether_arp *arp;
    char net[16];
      
    if (ntohs(ether_header->ether_type) == ETHERTYPE_IP) {
      fprintf(stdout, " IP packet => ");
      ip = (struct iphdr*) (packet + ETHER_HDR_LEN);
      
      fprintf(stdout, "IP version: %d, ", ip->version);
      struct in_addr src_addr = {ip->saddr};
      struct in_addr dst_addr = {ip->daddr};
      fprintf(stdout, "SRC Address: %s, ", inet_ntoa(src_addr));
      fprintf(stdout, "DST Address: %s, ", inet_ntoa(dst_addr));
      
      switch(ip->protocol) {
        case 6:
          fprintf(stdout, "TCP packet ");
          analyze_tcp((u_char*) ip + (ip->ihl * 4), ntohs(ip->tot_len) - (ip->ihl * 4));
          break;

        case 17:
          fprintf(stdout, " UDP packet ");
          analyze_udp((u_char*) ip + ip->ihl * 4);
        default:
          break;
      }
    }

    if (ntohs(ether_header->ether_type) == ETHERTYPE_ARP) {
      fprintf(stdout, " ARP packet => ");
      arp = (struct ether_arp*) (packet + ETHER_HDR_LEN);
      struct in_addr arp_spa = {arp->arp_spa};
      fprintf(stdout, " ARP sender protocol addr: %s, ", inet_ntoa(arp_spa));
      u_char * chr = arp->arp_sha;
      fprintf(stdout, "ARP sender hardware addr: ");
      print_mac_addr(chr);
    }

    if (ntohs(ether_header->ether_type) == ETHERTYPE_IPV6) {
      fprintf(stdout, " IPV6 packet => ");
      struct ip6_hdr *ip6 = (struct ip6_hdr *) (packet + ETHER_HDR_LEN);
      u_int16_t len = htons(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);

      char ipstr[INET6_ADDRSTRLEN];
      memset(ipstr, 0, INET6_ADDRSTRLEN);
      fprintf(stdout, "SRC address: %s, ", inet_ntop(AF_INET6, &(ip6->ip6_src), ipstr, INET6_ADDRSTRLEN));
      memset(ipstr, 0, INET6_ADDRSTRLEN);
      fprintf(stdout, "DST address: %s, ", inet_ntop(AF_INET6, &(ip6->ip6_dst), ipstr, INET6_ADDRSTRLEN));

      switch(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
        case 6:
          fprintf(stdout, "TCP packet ");
          analyze_tcp((u_char*) ip6 + sizeof(struct ip6_hdr), len);
          break;

        case 17:
          fprintf(stdout, " UDP packet ");
          analyze_udp((u_char*) ip + sizeof(struct ip6_hdr));
        default:
          break;
      }
    }
  }


