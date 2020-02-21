#include "protocols.h"

int verb_level = 0;

int 
main(int argc, char *argv[])
  {
    char *interface = NULL, *filename = NULL;
    FILE * r = NULL;
    bpf_u_int32 mask_bpf;	
	  bpf_u_int32 net_bpf;
    struct bpf_program fp;
    char * filter_exp;
    bool filter = false;
    int opt;
    u_int32_t arglen = 0;

    while ((opt = getopt(argc, argv, "i:o:f:v:")) != -1) {
        switch (opt) {
          case 'i':
            arglen = strlen(optarg);
            interface = (char *) malloc(sizeof(char) * arglen);
            strncpy(interface, optarg, arglen);
            printf("interface: %s\n", interface);
            break; 

          case 'o':
            arglen = strlen(optarg);
            filename = (char *) malloc(sizeof(char) * arglen);
            strncpy(filename, optarg, arglen);
            printf("output: %s\n", filename);
            r = freopen(filename, "w", stdout);
            break;

          case 'f':
            filter = true;
            arglen = strlen(optarg);
            filter_exp = (char *) malloc(sizeof(char) * arglen);
            strncpy(filter_exp, optarg, arglen);
            printf("using filter: %s\n", filter_exp);
            puts("filter on");
            break;

          case 'v':
            verb_level = atoi(optarg);
            printf("verbosity: %d\n", verb_level);
            break;
        }
      }

      char *net, *mask, *dev, errbuf[PCAP_ERRBUF_SIZE];
      struct in_addr addr;
      int ret;
      bpf_u_int32 netp;
      bpf_u_int32 maskp;

      dev = pcap_lookupdev(errbuf);
      ERR((dev == NULL), "pcap_lookupdev");
      printf("device found: %s\n", dev);
      
      addr.s_addr = netp;
      net = inet_ntoa(addr);
      ret = pcap_lookupnet(dev, &netp, &maskp, errbuf); 
      printf("address: %s\n", net);
      ERR((ret == -1), "pcap_lookupnet");
      
      addr.s_addr = maskp;
      net = inet_ntoa(addr);
      ERR((net == NULL), "inet_ntoa");
      printf("net mask: %s\n", net);
      
      if (interface != NULL)
        dev = interface;

      pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
      ERR((handle == NULL), "pcap_open_live");
      
      if (filter) {
        int ret;
        ret = pcap_compile(handle, &fp, filter_exp, 0, net_bpf);
        ERR((ret == -1), "pcap_compile");
	      ret = pcap_setfilter(handle, &fp);
        ERR((ret == -1), "pcap_setfilter");
      }

      pcap_loop(handle, -1, analyze_packet, NULL);
      pcap_close(handle);
      if (r != NULL)
        fclose(r);
      return 0;
  }
