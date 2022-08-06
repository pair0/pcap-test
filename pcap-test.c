#include <pcap.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include "ethernet.h"
#include "ip.h"
#include "tcp.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	int count = 1;
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
		const struct ethernet_header* ether_h = (struct ethernet_header*)malloc(sizeof(struct ethernet_header));
		const struct ip_header* ip_h = (struct ip_header*)malloc(sizeof(struct ip_header));
		const struct tcp_header* tcp_h = (struct tcp_header*)malloc(sizeof(struct tcp_header));
		const u_char* packet;
		const u_char* data;
		char *str;
		
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		ether_h = (struct ethernet_header*)(packet);
		ip_h = (struct ip_header*)(packet+14);
		tcp_h = (struct tcp_header *) (packet + 14 + IP_HL(ip_h) * 4);
		data = (char *)(packet + 14 + IP_HL(ip_h) * 4 + TH_OFF(tcp_h) * 4);

		if(ntohs(ether_h->ether_type)==ETHERTYPE_IP && ip_h->ip_p == IPPROTO_TCP){
			printf("--------------------NO.%d Frame : %u bytes caputred--------------------\n", count, header->caplen);
			printf("-------------------------------------------------------------------------\n");
			printf("*** Ethernet ***\n");
			printf("Source_MAC : ");
			for(int i=0; i < ETHER_ADDR_LEN; i++) {
				printf("%02x", ether_h->ether_shost[i]);
				if(i<ETHER_ADDR_LEN-1) printf(":");
			}
			printf("\n");
			printf("Destination_MAC : ");
			for(int i=0; i < ETHER_ADDR_LEN; i++) {
				printf("%02x", ether_h->ether_dhost[i]);
				if(i<ETHER_ADDR_LEN-1) printf(":");
			}
			printf("\n");
			printf("-------------------------------------------------------------------------\n");
			printf("*** Internet Protocol Version 4 ***\n");
			printf("Source_IP : %s\n",  inet_ntoa(*(struct in_addr *)&ip_h->ip_src));
			printf("Destination_IP : %s\n", inet_ntoa(*(struct in_addr *)&ip_h->ip_dst));
			printf("-------------------------------------------------------------------------\n");
			printf("*** Transmission Control Protocol ***\n");
			printf("Source_PORT: %d\n", ntohs(tcp_h->th_sport));
			printf("Destination_PORT: %d\n", ntohs(tcp_h->th_dport));
			printf("-------------------------------------------------------------------------\n");
			printf("*** Paylad ***\n");
			printf("Data : ");
			for(int i=0; i<10; i++){
				if(*(data+i)==0) break;
				printf("%02x ", *(data+i));
			}
			printf("\n");
			printf("-------------------------------------------------------------------------\n");
			printf("\n\n");
			}
			count ++;
		}
	pcap_close(pcap);
}
