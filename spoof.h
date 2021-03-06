

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <string.h>


struct icmpheader {
	unsigned char icmp_type; // ICMP message type
	unsigned char icmp_code; // Error code
	unsigned short int icmp_chksum; // Checksum for ICMP header and data
	unsigned short int icmp_id; // used for identifying request
	unsigned short int icmp_seq; // sequence number
};

/* ip header */
struct ipheader {
	unsigned char iph_ihl:4,	//version 4
	iph_ver:4;
	unsigned char iph_tos; //type of service
	unsigned short int iph_len; //header length
	unsigned short int iph_ident; //identifier
	unsigned short int iph_flag:3,iph_offset:13; //flags, fragment offset
	unsigned char iph_ttl; //time to live
	unsigned char iph_protocol; //protocol type
	unsigned short int iph_chksum; //checksum
	struct in_addr iph_sourceip; //source ip
	struct in_addr iph_destip; //dest ip
};



unsigned short in_cksum (unsigned short *buf, int length);
unsigned short calculate_tcp_checksum(struct ipheader *ip);
void send_raw_ip_packet(struct ipheader* ip);
void tester();
void finish_him(char* src, char* dest, int argc);
