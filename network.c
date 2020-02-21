#include "protocols.h"



void 
analyze_tcp(const u_char *packet, u_int total_size) 
  {
    struct tcphdr *tcphdr = (struct tcphdr*) packet;
    u_char flags;
    if (verb_level > 1) {
      fprintf(stdout, "=>\n\tsource port: %hu\n", ntohs(tcphdr->th_sport));
      fprintf(stdout, "\tdest port: %hu\n", ntohs(tcphdr->th_dport));
      //check applications protocols here
    }

    if (verb_level > 2) {
      fprintf(stdout, "\tack number: %hu\n", ntohs(tcphdr->th_ack));
      fprintf(stdout, "\tdata offset: %hu\n", ntohs(tcphdr->th_off * 4));
     
      if ((flags = tcphdr->th_flags) & (TH_SYN|TH_FIN|TH_RST|TH_PUSH)) {
        fprintf(stdout, "\tFlags => \n");
		if (flags & TH_SYN)
			fprintf(stdout, "\t\tSYN\n");
		if (flags & TH_FIN)
			fprintf(stdout, "\t\tFIN\n");
		if (flags & TH_RST)
			fprintf(stdout, "\t\tRESET\n");
		if (flags & TH_PUSH)
			fprintf(stdout, "\t\tPUSH\n");
	}
      fprintf(stdout, "\twindow: %hu\n", ntohs(tcphdr->th_win));
      fprintf(stdout, "\tchecksum: %hu\n", ntohs(tcphdr->th_sum));
      fprintf(stdout, "\turgent pointer: %hu\n", ntohs(tcphdr->th_urp));
    }

    if (ntohs(tcphdr->th_sport) == 21 || 
        ntohs(tcphdr->th_sport) == 20 || 
        ntohs(tcphdr->th_dport) == 21 ||
        ntohs(tcphdr->th_dport) == 20) {
          u_int size = tcphdr->th_off * 4;
          analyze_ftp(packet + size, total_size - size);
        }

    if (ntohs(tcphdr->th_dport) == 80) {
          u_int size = tcphdr->th_off * 4;
          analyze_http(packet + size, total_size - size);
    }

    if (ntohs(tcphdr->th_sport) == 23 || 
        ntohs(tcphdr->th_dport) == 23) {
            u_int size = tcphdr->th_off * 4;
            analyze_ftp(packet + size, total_size - size);
        }
  }

void 
analyze_udp(const u_char *packet) 
  {
    struct udphdr *udp = (struct udphdr*) packet;
    
    if (verb_level > 1) {
      fprintf(stdout, "=>\n\tsource port: %hu\n", ntohs(udp->source));
      fprintf(stdout, "\tdest port: %hu\n", ntohs(udp->dest));
    }
  
    if (verb_level > 2) {
      fprintf(stdout, "\tlength: %hu\n", ntohs(udp->len));
      fprintf(stdout, "\tchecksum: %hu\n", ntohs(udp->check));
    }

    u_int  data_size = ntohs(udp->len) - sizeof(struct udphdr);
    if  (ntohs(udp->source) == 67 
      || ntohs(udp->source) == 68 
      || ntohs(udp->dest) == 67 
      || ntohs(udp->dest) == 68)
        analyze_bootp((u_char *) udp + sizeof(struct udphdr), data_size);

    if (ntohs(udp->source) == 53 || ntohs(udp->dest) == 53)
        analyze_dns((u_char *) udp + sizeof(struct udphdr), data_size);
  }
