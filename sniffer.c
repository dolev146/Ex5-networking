#include <sys/socket.h>
#include <stdlib.h>

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

struct ethheader
{
  u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};

struct ipheader
{
  unsigned char iph_ihl : 4,       // IP header length
      iph_ver : 4;                 // IP version
  unsigned char iph_tos;           // Type of service
  unsigned short int iph_len;      // IP Packet length (data + header)
  unsigned short int iph_ident;    // Identification
  unsigned short int iph_flag : 3, // Fragmentation flags
      iph_offset : 13;             // Flags offset
  unsigned char iph_ttl;           // Time to Live
  unsigned char iph_protocol;      // Protocol type
  unsigned short int iph_chksum;   // IP datagram checksum
  struct in_addr iph_sourceip;     // Source IP address
  struct in_addr iph_destip;       // Destination IP address
};

struct icmpheader
{
  unsigned char icmp_type;        // ICMP message type
  unsigned char icmp_code;        // Error code
  unsigned short int icmp_chksum; // Checksum for ICMP Header and data
  unsigned short int icmp_id;     // Used for identifying request
  unsigned short int icmp_seq;    // Sequence number
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800)
  { // 0x0800 is IP type
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    printf(
        "|From (%s)                                                       | |\n"
        "|To %s                                                                   | |\n"
        "|                                                                     | |\n",
        , inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));

    // getting the pointer to the ICMP part of the packet
    int ip_header_len = ip->iph_ihl * 4;
    struct icmpheader *icmp = (struct icmpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

    printf("Type: %d\n", icmp->icmp_type);
    printf("Code: %d\n\n", icmp->icmp_code);

    printf(
        "|Type (%d)                                                       | |\n"
        "|Code %d                                                                   | |\n"
        "|                                                                     | |\n",
        , icmp->icmp_type, icmp->icmp_code);
  }
}

int main()
{
  printf("_________________________________________________________________________\n"
         "|[] MySnif by Yakov and Dolev                                     |X]|!|_\n"
         "|_____________________________________________________________________||_\n"
         "|                                                                     | |\n");
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name eth3.
  // Students need to change "eth3" to the name found on their own
  // machines (using ifconfig). The interface to the 10.9.0.0/24
  // network has a prefix "br-" (if the container setup is used).
  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) != 0)
  {
    pcap_perror(handle, "Error:");
    exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);
  pcap_close(handle); // Close the handle
  printf("|                                                                     |_|\n"
         "|all copyright reserverd Ariel University_____________________________|/|\n\n");

  return 0;
}
