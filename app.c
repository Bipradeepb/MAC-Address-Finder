/*------------------------------------------Header Files----------------------------------------------*/
#include<stdio.h>
#include<string.h>
#include<malloc.h>
#include<errno.h>
#include<stdlib.h>

#include<sys/socket.h>
#include<sys/types.h>
#include<sys/ioctl.h>

#include<net/if.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/if_ether.h>
#include<netinet/udp.h>

#include<linux/if_packet.h>

#include<arpa/inet.h>
#include<net/if.h>
#include<unistd.h>
#include<linux/if.h>

#include<pthread.h>
#include <signal.h>
#include <time.h>


/*------------------------------------------------------------------------------------------------------*/




/*------------------------------------------Constants definition----------------------------------------*/
//Define other constants

//Set destination address as broadcast
#define DESTMAC0	0xff
#define DESTMAC1	0xff
#define DESTMAC2	0xff
#define DESTMAC3	0xff
#define DESTMAC4	0xff
#define DESTMAC5	0xff

#define INTERFACE "enp0s17"

int total_len=0,send_len;
int sock_r,saddr_len,buflen;
unsigned char* buffer;
struct sockaddr saddr;
struct sockaddr_in source,dest;

pthread_t thread;
pthread_t timerid;
timer_t timer_id;

int status=0;

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


// Declare data structures for sockets
struct ifreq ifreq_c,ifreq_i,ifreq_ip; //for each ioctl keep diffrent ifreq structure otherwise error may come in sending(sendto )
int sock_raw;
unsigned char *sendbuff;

/*------------------------------------------------------------------------------------------------------*/





/*----------------------------------Packet Sending Functions-------------------------------------------*/

// Get the interface ID of the network interface that we want to use
// On virtual machine using the interface :enp0s17

void getEthernetIndex()
{
	memset(&ifreq_i,0,sizeof(ifreq_i));
	strncpy(ifreq_i.ifr_name,INTERFACE,IFNAMSIZ-1);

	if((ioctl(sock_raw,SIOCGIFINDEX,&ifreq_i))<0)
		printf("error in index ioctl reading");

	printf("index=%d\n",ifreq_i.ifr_ifindex);
}

void getMAC()
{
    memset(&ifreq_c,0,sizeof(ifreq_c));
	strncpy(ifreq_c.ifr_name,INTERFACE,IFNAMSIZ-1);

	if((ioctl(sock_raw,SIOCGIFHWADDR,&ifreq_c))<0)
		printf("error in SIOCGIFHWADDR ioctl reading");

	printf("Mac= %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]),(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]));

}


void getIP()
{
    memset(&ifreq_ip,0,sizeof(ifreq_ip));
	strncpy(ifreq_ip.ifr_name,INTERFACE,IFNAMSIZ-1);
  	 if(ioctl(sock_raw,SIOCGIFADDR,&ifreq_ip)<0)
 	 {
		printf("error in SIOCGIFADDR \n");
	 }
	
	printf("%s\n",inet_ntoa((((struct sockaddr_in*)&(ifreq_ip.ifr_addr))->sin_addr)));
}


void packEthernetHeader()
{
    printf("ethernet packaging start ... \n");
	
	struct ethhdr *eth = (struct ethhdr *)(sendbuff);
  	eth->h_source[0] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]);
  	eth->h_source[1] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]);
   	eth->h_source[2] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]);
   	eth->h_source[3] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]);
   	eth->h_source[4] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]);
   	eth->h_source[5] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]);

   	eth->h_dest[0]    =  DESTMAC0;
   	eth->h_dest[1]    =  DESTMAC1;
   	eth->h_dest[2]    =  DESTMAC2;
  	eth->h_dest[3]    =  DESTMAC3;
   	eth->h_dest[4]    =  DESTMAC4;
   	eth->h_dest[5]    =  DESTMAC5;

   	eth->h_proto = htons(ETH_P_ARP);   //0x0806

   	printf("ethernet packaging done.\n");

	total_len+=sizeof(struct ethhdr);
}


void packARPHeader(const char*destination_ip)
{
    printf("ARP header packaging starting...\n");

    struct arp_header *arph =(struct arp_header*)(sendbuff +sizeof(struct ethhdr));

    arph->ar_hrd=htons(0x01);         // Format of hardware address
    arph->ar_pro=htons(0x800);         // Format of protocol address
    arph->ar_hln=6;         // Length of hardware address
    arph->ar_pln=4;         // Length of protocol address
    arph->ar_op=htons(0x01);          // ARP opcode (command)
    // unsigned char   __ar_sha[ETH_ALEN]; // Sender hardware address
    // unsigned char   __ar_sip[4];    // Sender IP address
    // unsigned char   __ar_dha[ETH_ALEN]; // Target hardware address
    // unsigned char   __ar_dip[4];    // Target IP address

    arph->__ar_sha[0] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]);
  	arph->__ar_sha[1] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]);
   	arph->__ar_sha[2] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]);
   	arph->__ar_sha[3] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]);
   	arph->__ar_sha[4] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]);
   	arph->__ar_sha[5] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]);

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifreq_ip.ifr_addr;
    uint32_t ip_addr = addr->sin_addr.s_addr;

    // Assign the IP address to the __ar_sip field
    memcpy(&arph->__ar_sip, &ip_addr, sizeof(ip_addr));

    arph->__ar_dha[0]    =  0x00;
   	arph->__ar_dha[1]    =  0x00;
   	arph->__ar_dha[2]    =  0x00;
  	arph->__ar_dha[3]    =  0x00;
   	arph->__ar_dha[4]    =  0x00;
   	arph->__ar_dha[5]    =  0x00;

    uint32_t dest_ip_addr = inet_addr(destination_ip);

    // Assign the destination IP address to the __ar_dip field via the pointer
    memcpy(&arph->__ar_dip, &dest_ip_addr, sizeof(dest_ip_addr));

    total_len+= sizeof(struct arp_header);

    printf("ARP header packaging finished.\n");
}

void fillData()
{

    for(int index=total_len;index<60;index++)
    {
        sendbuff[index]=0xDD;
    }
}

/*------------------------------------------------------------------------------------------------------*/





/*----------------------------------Packet Sniffer Functions--------------------------------------------*/

static inline int arpheader(const char* destination_ip)
{
	struct arp_header *arp = (struct arp_header*)(buffer + sizeof(struct ethhdr));

    //check whether the opcode is of response type

    if(arp->ar_op==htons(0x02))
    {
        //check the if the response is from that ip
        memset(&source, 0, sizeof(source));

        char sourceip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET,arp->__ar_sip,sourceip,INET_ADDRSTRLEN);

        memset(&dest, 0, sizeof(dest));

        char destip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp->__ar_dip, destip, INET_ADDRSTRLEN);

        //compare if destination mac matches local mac
        for(int i=0;i<6;i++)
        {
            if(arp->__ar_dha[i]==(unsigned char)(ifreq_c.ifr_hwaddr.sa_data[i]))
            {
                continue;
            }
            else{
                return 0;
            }
        }

        //compare if the destination ip matches source ip
        for(int i=0;i<4;i++)
        {
            if(sourceip[i]==destination_ip[i])
            {
                continue;
            }
            else{
                return 0;
            }
        }

        return 1;
    }

    return 0;
}


static inline int check_packet(const char* destination_ip)
{
    //check whether it is arp packet or not
	struct ethhdr *eth = (struct ethhdr *)(buffer);

	if(eth->h_proto==htons(ETH_P_ARP))
	{
		if(arpheader(destination_ip)) //call arp header
        {
            return 1;
        } 
	}

    return 0;
}

void* pollpacket(void *arg)
{

    const char *destination_ip=(char*)arg;

    buffer = (unsigned char *)malloc(60); 
	memset(buffer,0,60);
	
    int response=0;

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
		if(check_packet(destination_ip))
        {
            //response received
            response=1;
            status=1;
            break;

        }
	}

    struct arp_header *arp = (struct arp_header*)(buffer + sizeof(struct ethhdr));

    fprintf(stdout , "\t|-Target IP      : %s\n",destination_ip);

    fprintf(stdout , "\t|-Target MAC     : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",arp->__ar_sha[0],arp->__ar_sha[1],
	arp->__ar_sha[2],arp->__ar_sha[3],arp->__ar_sha[4],arp->__ar_sha[5]);

	printf("DONE!!!!\n");

    return NULL;
}

void cancel_thread() {
    printf("Timer expired. Cancelling thread.\n");
    pthread_cancel(thread);
}

void *timer_thread(void *arg) {
    struct sigevent sev;
    struct itimerspec its;
    struct sigaction sa;
    
    sa.sa_handler = cancel_thread;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, NULL);

    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGALRM;
    sev.sigev_value.sival_ptr = &timer_id;

    if (timer_create(CLOCK_REALTIME, &sev, &timer_id) == -1) {
        perror("timer_create");
        exit(EXIT_FAILURE);
    }

    its.it_value.tv_sec = 5; // Set the expiration time to 5 seconds
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    if (timer_settime(timer_id, 0, &its, NULL) == -1) {
        perror("timer_settime");
        exit(EXIT_FAILURE);
    }

    pthread_exit(NULL);
}

/*------------------------------------------------------------------------------------------------------*/




/*------------------------------------------main Caller Function----------------------------------------*/
int main(int argc, char*argv[])
{
    if(argc<2)
    {
        fprintf(stderr,"You did not feed me enough arguments.\n");
        exit(1);
    }

    char *destination_ip=argv[1];

   
    /*--------------------------Send Packet------------------------------------------------------------*/
    sock_raw=socket(AF_PACKET,SOCK_RAW,IPPROTO_RAW);

    if(sock_raw == -1)
        printf("error in socket opening");
    

    sock_r=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)); 
	if(sock_r<0)
	{
		perror("error in socket\n");
		exit(1);
	}


    sendbuff=(unsigned char*)malloc(60); // increase in case of large data. Here data is of only 60 bytes
	memset(sendbuff,0,60);

    getEthernetIndex(); 
    //network interface is set

    getMAC();
    //MAC address burnt onto the interface so get the MAC.
    //must also be the source MAC

	getIP();
    //configure the raw socket with the IP of the machine

    struct sockaddr_ll sadr_ll;
	sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex;
	sadr_ll.sll_halen   = ETH_ALEN;
	sadr_ll.sll_addr[0]  = DESTMAC0;
	sadr_ll.sll_addr[1]  = DESTMAC1;
	sadr_ll.sll_addr[2]  = DESTMAC2;
	sadr_ll.sll_addr[3]  = DESTMAC3;
	sadr_ll.sll_addr[4]  = DESTMAC4;
	sadr_ll.sll_addr[5]  = DESTMAC5;


    //pack ethernet header
    packEthernetHeader();

    //pack ARP header
    packARPHeader(destination_ip);

    fillData();

    printf("sending...\n");

    /*-----------Start a thread for polling packets separate from the main thread---------------------*/

  

    // Create a thread
    if (pthread_create(&thread, NULL, pollpacket, destination_ip) != 0) {
        perror("pthread_create");
        exit(EXIT_FAILURE);
    }

    
    
    send_len = sendto(sock_raw,sendbuff,60,0,(const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll));
    if(send_len<0)
    {
        printf("error in sending....sendlen=%d....errno=%d\n",send_len,errno);
        return -1;

    }

    printf("Packet Sent.\n");
    
	
    close(sock_raw);// use signals to close socket 


    /*--------Packet Sent. Start Sniffing------------------------------------------------------*/

    //start timer
    if (pthread_create(&timerid, NULL, &timer_thread, NULL) != 0) {
        perror("pthread_create");
        exit(EXIT_FAILURE);
    }
    //wait for the thread to find response
    pthread_join(thread, NULL);

    if (pthread_cancel(timerid) != 0) {
        perror("pthread_cancel");
        exit(EXIT_FAILURE);
    }

    if(!status)
    {
        printf("Invalid ip.\n");
    }

    close(sock_r);// use signals to close socket 
    exit(0);
	
}