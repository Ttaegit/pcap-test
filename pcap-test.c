#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

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
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) 
        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
		
        printf("\n###########################################");
        printf("\n%u bytes captured\n", header->caplen);
        printf("\nDestination MAC : [%02x:%02x:%02x:%02x:%02x:%02x]",packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);
        printf("\nSource MAC : [%02x:%02x:%02x:%02x:%02x:%02x]",packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
        printf("\nTYPE : 0x%02x%02x\n",packet[12],packet[13]);
        printf("\nSource IP : %d.%d.%d.%d",packet[26],packet[27],packet[28],packet[29]);
        printf("\nDestination IP : %d.%d.%d.%d\n",packet[30],packet[31],packet[32],packet[33]);
        printf("\nSource Port : %d%d\nDestination Port :  %d%d\n" ,packet[34],packet[35],packet[36],packet[37]);

                int i;
                printf("\nDATA : ");
                for(i=54; i<62; i++) {
                    printf("%02x",packet[i]);


            }
        printf("\n");
        printf("#############################################\n");
        }

        pcap_close(pcap);
        return 0;
    }

