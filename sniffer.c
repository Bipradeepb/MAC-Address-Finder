#include<stdio.h>
#include<stdlib.h>
#include<errno.h>

#include<string.h>
#include<signal.h>
#include<stdbool.h>

#include<sys/socket.h>
#include<sys/types.h>
#include<unistd.h>

#include<linux/if_packet.h>
#include<netinet/in.h>		 
#include<netinet/if_ether.h>    // for ethernet header

#include<netinet/ip.h>		// for ip header
#include<netinet/udp.h>		// for udp header
#include<netinet/tcp.h>

#include<arpa/inet.h>           // to avoid warning at inet_ntoa
#include<linux/if.h>


// Declare the variables
int sock_r,saddr_len,buflen;
unsigned char* buffer;
struct sockaddr saddr;
struct sockaddr_in source,dest;

#define MAXBUFLEN 60

//Define the arp structure
struct arp_header {
    unsigned short  ar_hrd;         /* Format of hardware address */
    unsigned short  ar_pro;         /* Format of protocol address */
    unsigned char   ar_hln;         /* Length of hardware address */
    unsigned char   ar_pln;         /* Length of protocol address */
    unsigned short  ar_op;          /* ARP opcode (command) */
/* Hardware and protocol address */
    unsigned char   __ar_sha[ETH_ALEN];  /* Sender hardware address */
    unsigned char   __ar_sip[4];     /* Sender IP address */
    unsigned char   __ar_dha[ETH_ALEN];  /* Target hardware address */
    unsigned char   __ar_dip[4];     /* Target IP address */
};


void arpheader()
{
	struct arp_header *arp = (struct arp_header*)(buffer + sizeof(struct ethhdr));

	//store the source ip into an integer first
	memset(&source, 0, sizeof(source));
	// Extract the source IP address
    char sourceip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp->__ar_sip, sourceip, INET_ADDRSTRLEN);
	
	//store the destination ip into an integer 
	memset(&dest, 0, sizeof(dest));
    // Extract the destination IP address
    char destip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp->__ar_dip, destip, INET_ADDRSTRLEN);

	fprintf(stdout , "\nARP Header\n");

	fprintf(stdout , "\t|-Hardware Type  : %d\n",ntohs(arp->ar_hrd));
	fprintf(stdout , "\t|-Protocol Type  : %d\n",ntohs(arp->ar_pro));
	fprintf(stdout , "\t|-Hardware Size  : %d\n",arp->ar_hln);
	fprintf(stdout , "\t|-Protocol Size  : %d\n",arp->ar_pln);
	fprintf(stdout , "\t|-Opcode         : %d\n",ntohs(arp->ar_op));
	fprintf(stdout , "\t|-Sender MAC     : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",arp->__ar_sha[0],arp->__ar_sha[1],
	arp->__ar_sha[2],arp->__ar_sha[3],arp->__ar_sha[4],arp->__ar_sha[5]);
	fprintf(stdout , "\t|-Sender IP      : %s\n",sourceip);

	fprintf(stdout , "\t|-Target MAC   	 : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",arp->__ar_dha[0],arp->__ar_dha[1],
	arp->__ar_dha[2],arp->__ar_dha[3],arp->__ar_dha[4],arp->__ar_dha[5]);
	fprintf(stdout , "\t|-Target IP      : %s\n",destip);

	fprintf(stdout,"\n---------------------------------------------------------------------------------\n");

}


void ethernet_header()
{
	struct ethhdr *eth = (struct ethhdr *)(buffer);

	if(eth->h_proto==htons(ETH_P_ARP))
	{
		fprintf(stdout,"\n--------------------------Packet Details-----------------------------------------\n");
		fprintf(stdout,"\nEthernet Header\n");
		fprintf(stdout,"\t|-Source Address	    : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
		fprintf(stdout,"\t|-Destination Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
		fprintf(stdout,"\t|-Protocol		    : %d\n",ntohs(eth->h_proto));

		arpheader();
	}
}


int main()
{
	buffer = (unsigned char *)malloc(60); 
	memset(buffer,0,60);

	//open a raw socket
	sock_r=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)); 
	if(sock_r<0)
	{
		perror("error in socket\n");
		return -1;
	}

	while(1)
	{
		//continuous polling for packets at the network interface
		saddr_len=sizeof saddr;
		buflen=recvfrom(sock_r,buffer,MAXBUFLEN,0,&saddr,(socklen_t *)&saddr_len);


		if(buflen<0)
		{
			perror("error in reading recvfrom function\n");
			exit(1);
		}

		//extract ethernet header
		ethernet_header();
		//it will check protocol and if ARP then print arp header
	}

	close(sock_r);// use signals to close socket 
	printf("DONE!!!!\n");

}
