#include "protocols.h"

void
analyze_bootp(const u_char *packet, u_int size) 
  {
    struct bootp * bp = (struct bootp*) packet;
    const u_int8_t magic_cookie[] = VM_RFC1048;
    bool is_dhcp = false;

    if (memcmp(bp->bp_vend, magic_cookie, 4) != 0)
      fprintf(stdout,"\tBOOTP ");
    else {
      fprintf(stdout,"\tDHCP ");
      is_dhcp = true;
    }

    if (verb_level > 1) {
      fprintf(stdout, "=>\n\t\tclient ip addr: %s\n", inet_ntoa(bp->bp_ciaddr));
      fprintf(stdout, "\t\tyour ip addr: %s\n", inet_ntoa(bp->bp_yiaddr));
      fprintf(stdout, "\t\tserver ip addr: %s\n", inet_ntoa(bp->bp_siaddr));
      fprintf(stdout, "\t\tgateway ip addr: %s\n", inet_ntoa(bp->bp_giaddr));
      fprintf(stdout, "\t\tserver hostname: %s\n", bp->bp_sname);
      fprintf(stdout, "\t\tClient hardware addr:");
      print_mac_addr((u_char *) bp->bp_chaddr);
      printf("\n");
    }

   if (verb_level > 2) {
     switch (ntohs(bp->bp_op)) {
        case 1:
          fprintf(stdout, "\t\tOPCODE: boot request\n");
          break;
        case 2:
          fprintf(stdout, "\t\tOPCODE: boot reply\n");
          break;
      }

     fprintf(stdout,"\t\tSecs: %hu\n", ntohs(bp->bp_secs));
     fprintf(stdout,"\t\tHops: %hu\n", ntohs(bp->bp_hops));
     fprintf(stdout,"\t\tHardware addr length: %hu\n", ntohs(bp->bp_hlen));
     fprintf(stdout,"\t\tHardware addr type: ethernet\n");
     fprintf(stdout,"\t\ttransaction id: %u\n", ntohl(bp->bp_xid));
     //flags
   }

    if (is_dhcp)
      analyze_dhcp_options((u_char *) bp->bp_vend + 4, size - sizeof(struct bootp));
  }

void analyze_dhcp_options(u_char *packet, u_int size) 
  {
    u_char * option = packet;
    struct in_addr addr;
    u_int32_t tmp_addr;
    int i = 0;
    int n = 0;
    u_int total = 0;
    
    while (option[0] != 0xff && verb_level == 3 && total < size) {
      switch(option[0]) {
        case 0x35:
          option += 2;
          print_dhcp_msg_type(option);
          option++;
          total += 2;
          break;

        case 0x3d:
          n = (int) option[1];
          if (option[2] == 1) 
            fprintf(stdout, "\t\tHardware type: ETHERNET\n");
          else
            fprintf(stdout, "\t\tHardware type: IEE 802 networks\n");
          
          
          option+=3;
          u_char *client_id = (u_char *) malloc(sizeof(u_char) *n);
          memcpy(client_id, option, n);
          fprintf(stdout, "\t\tClient id: ");
          print_mac_addr(client_id);
          fprintf(stdout, "\t\t\n");
          option += n - 1;
          total += 2 + n;
          free(client_id);

          break;
        
        case 0x33:
          n = (int) option[1];
          fprintf(stdout, "\t\tLease time: ");
          i = 0;
          option+=2;
          while (i < n) {
            fprintf(stdout, "\t\t%x ", option[i]);
            i++;
          }
          fprintf(stdout, "\t\t\n");
          option += n - 1;
          total += 1 + n;
          break;
        
        case 0x36:
          n = (int) option[1];
          option+=2;
          memset(&tmp_addr, 0, sizeof(u_int32_t));
          memcpy(&tmp_addr, option, (size_t) n);
          addr.s_addr = tmp_addr;
          fprintf(stdout, "\t\tServer identifier: %s\n", inet_ntoa(addr));
          option += n - 1;
          total += 1 + n;
          break;
        
        case 0x32:
          n = (int) option[1];
          option += 2;
          memset(&tmp_addr, 0, sizeof(u_int32_t));
          memcpy(&tmp_addr, option, (size_t) n);
          addr.s_addr = tmp_addr;
          fprintf(stdout, "\t\trequested IP addr: %s\n", inet_ntoa(addr));
          option += n - 1;
          total += 1 + n;
          break;
        
        case 0x37:
          n = (int) option[1];
          option += 2;
          i = 0;
          fprintf(stdout, "\t\tparameter request list: ");
          while (i < n) {
            if (option[i] == 0xff) {
              printf("END\n");
              return;
            }
            printf("%x ", option[i]);
            i++;
          }
          fprintf(stdout, "\t\tEND\n");
          option += n - 1;
          total += 1 + n;
          break;
        
        case 0x2c:
          n = (int) option[1];
          option += 2;
          i = 0;
          fprintf(stdout, "\t\tNetBios over TCP/IP: ");
          while (n > 0) {
            memset(&tmp_addr, 0, sizeof(u_int32_t));
            fflush(stdout);
            memcpy(&tmp_addr, option, sizeof(u_int32_t));
            addr.s_addr = tmp_addr;
            fprintf(stdout, "\t\tname server addr: %s\n", inet_ntoa(addr));
            option += 4;
            n -= 4;
          }
          total += 1 + n;
          printf("\n");
          break;
        
        case 0x1c:
          n = (int) option[1];
          option += 2;
          memset(&tmp_addr, 0, sizeof(u_int32_t));
          memcpy(&tmp_addr, option, (size_t) n);
          addr.s_addr = tmp_addr;
          fprintf(stdout, "\t\tBroadcast addr: %s\n", inet_ntoa(addr));
          option += n - 1;
          total += 1 + n;
          break;
        
        case 0x0f:
          n = (int) option[1];
          option += 2;
          char * domain_name = (char *) malloc(sizeof(char) * n);
          memcpy(domain_name, option, (size_t) n);
          fprintf(stdout, "\t\tDomain Name: %s\n", domain_name);
          option += n - 1;
          total += 1 + n;
          break;
        
        default: 
          option++;
          n = (int) option[0];
          total += n - 1;
          option += n - 1;
          break;
      }
    }
  }

void 
print_dhcp_msg_type(const u_char *option)
  {
    switch(option[0]) {
      case DHCPDISCOVER:
        fprintf(stdout, "\t\tDHCP DISCOVER\n");
        return;
      case DHCPOFFER:
        fprintf(stdout, "\t\tDHCP OFFER\n");
        return;
      case DHCPREQUEST:
        fprintf(stdout, "\t\tDHCP REQUEST\n");
        return;
      case DHCPACK:
        fprintf(stdout, "\t\tDHCP ACK\n");
        return;
      case DHCPRELEASE:
        fprintf(stdout, "\t\tDHCP RELEASE\n");
        return;
    }
    fflush(stdout);
  }

void analyze_dns(const u_char *packet, u_int data_size)
  {
    fprintf(stdout,"\tDNS");
    struct dnshdr *hdr = (struct dnshdr *) packet;
    
    char stored_name_BUF[192];
    memset(stored_name_BUF, 0, 192);

    u_int buf_off = 0;
    u_int offset = 0;

    if (verb_level > 1) {
      fprintf(stdout, " =>\n\t\tDNS query id: %hu\n", ntohs(hdr->id));
      fprintf(stdout, "\t\tQuestion count: %hu\n", ntohs(hdr->qcount)); 
      fprintf(stdout, "\t\tAnswer record count: %hu\n", ntohs(hdr->ancount)); 
      fprintf(stdout, "\t\tName server count: %hu\n", ntohs(hdr->nscount)); 
      fprintf(stdout, "\t\tAdditional record count: %hu\n", ntohs(hdr->adcount));
    }
    
    if (verb_level > 2) {
      const u_char *question = packet + sizeof(struct dnshdr);
      if (ntohs(hdr->qcount) > 0) {
        fprintf(stdout, "\t\tquestions: \n");
        fflush(stdout);
        u_int16_t n = ntohs(hdr->qcount); 
        u_char size = 0;

        while (n > 0) {
          fprintf(stdout, "\t\t\tname: ");
          if (question[0] == 0xc0) {
            //not implemented
            question += 2;
          } else {
            while (question[0] != 0x00) {
              if (question[0] == 0xc0) {
                question++;
                break;
              }
              size = question[0];
              question++;
              u_int16_t i = 0;
              while (i < size) {
                if (isprint(question[i])) {
                  fprintf(stdout, "%c", question[i]);
                  stored_name_BUF[buf_off] = question[i];
                  buf_off++;
                }
                i++;
              }

              question += size;
              fprintf(stdout, ".");
              stored_name_BUF[buf_off] = '.';
              buf_off++;
            }
            question++;
          }
          u_int16_t *type = (u_int16_t *) malloc(sizeof(u_int16_t));
          memcpy(type, question, sizeof(u_int16_t));

          fprintf(stdout, "\n\t\t\ttype: %hu\n", ntohs(*type));
          question+=2;
          u_int16_t *class = (u_int16_t *) malloc(sizeof(u_int16_t));
          memcpy(class, question, sizeof(u_int16_t));
          
          fprintf(stdout, "\t\t\tclass: %hu\n", ntohs(*class));
          question+=2;
          n--;
        }
      }

      if (ntohs(hdr->ancount) > 0) {
        fprintf(stdout, "\t\tanswers: \n");
        u_int16_t n = ntohs(hdr->ancount);
        const u_char * answer = question;
        u_char size = 0;
        
        while (n > 0) {
          if (answer[0] == 0xc0) {
            //not implemented
            answer += 2;
            if (stored_name_BUF[0] != '\0') {
              fprintf(stdout, "\t\t\tname: %s\n", stored_name_BUF);
            }
          } else {
            fprintf(stdout, "\t\t\tname: ");
            while (answer[0] != 0x00) {
              if (answer[0] == 0xc0) {
                if (stored_name_BUF[0] != '\0')
                  fprintf(stdout, "\t\t\t.%s\n", stored_name_BUF);
                answer++;
                break;
              }
              size =  answer[0];
              answer++;
              int i = 0;

              while (i < size) {
                if (isprint(answer[i]))
                  fprintf(stdout, "%c", answer[i]);
                i++;
              }

              answer += size;
              fprintf(stdout, ".");
            }
            answer++;
          }
          u_int16_t *type = (u_int16_t *) malloc(sizeof(u_int16_t));
          memcpy(type, answer, sizeof(u_int16_t));

          fprintf(stdout, "\n\t\t\ttype: %hu\n", ntohs(*type));
          answer+=2;

          u_int16_t *class = (u_int16_t *) malloc(sizeof(u_int16_t));
          memcpy(class, answer, sizeof(u_int16_t));

          fprintf(stdout, "\t\t\tclass: %hu\n", ntohs(*class));
          answer+=2;

          u_int32_t *ttl = (u_int32_t *) malloc(sizeof(u_int32_t));
          memcpy(ttl, answer, sizeof(u_int32_t));

          fprintf(stdout, "\t\t\tTTL: %u\n", ntohl(*ttl));
          answer+=4;

          u_int16_t *len = (u_int16_t *) malloc(sizeof(u_int16_t));
          memcpy(len, answer, sizeof(u_int16_t));

          fprintf(stdout, "\t\t\trd length: %hu\n", ntohs(*len));
          answer+=2;
          answer+=ntohs(*len);
          fprintf(stdout, "\n");
          n--;
        }
      }
    }
  }


void analyze_ftp(const u_char * packet, u_int size) {
  fprintf(stdout, "\tFTP");
  u_int i = 0;
  if (verb_level > 1) {
      fprintf(stdout, " =>\n\t\t");

      while(i < size) {
        if (isprint(packet[i])) fprintf(stdout, "%c", packet[i]);
        i++;
    }
    fprintf(stdout, "\n");
  }
}

void analyze_http(const u_char *packet, u_int size) {
  fprintf(stdout, "\tHTTP");
  u_int i = 0;

  if (verb_level > 1) {
      fprintf(stdout, " =>\n\t\t");

      while(i < size) {
        if (isprint(packet[i])) fprintf(stdout, "%c", packet[i]);
        i++;
    }
    fprintf(stdout, "\n");
  }

}


void analyze_telnet(const u_char *packet, u_int size) 
  {
      fprintf(stdout, "\nTELNET\n");
  }