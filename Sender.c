#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define MAC_ADDR_LEN 6
#define BUFFER_SIZE 2000

unsigned short in_cksum(unsigned short *addr,int len)
{
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)  {
            sum += *w++;
            nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
            *(u_char *)(&answer) = *(u_char *)w ;
            sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);                     /* add carry */
    answer = ~sum;                          /* truncate to 16 bits */
    return(answer);
}

typedef struct pacoteIPv6{ 

	unsigned char version:4;
	unsigned char trafficClass;
	unsigned int flowLabel:20;
	unsigned char payload[2];
	unsigned char nextHeader;
	unsigned char hopLimit;
	unsigned char protocol;
	unsigned char ipSource[16];
	unsigned char ipDestination[16];
}pacoteIPv6; 

typedef struct pacoteTCP {
	unsigned char portSource[2];
    unsigned char portDestination[2];
	unsigned char sequenceNumber[4];
	unsigned char ackNumber[4];
	unsigned char dataOffSet:4;
	unsigned char reserved:3;
    unsigned int flags:9;
    unsigned char windowSize[2];
    unsigned short checksum;
    unsigned char urgentPointer[2];
    //talvez precise do campo option
} pacoteTCP;


int main(int argc, char *argv[])
{
	int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	char ifname[IFNAMSIZ];
	int frame_len = 0;
	char buffer[BUFFER_SIZE];
	short int ethertype = htons(0x0800);
	unsigned char alvoIp[4];
	unsigned char saidaIp[4];
    unsigned char localMac[6];
	char destMac[] = {0xA4, 0x1F, 0x72, 0xF5, 0x90, 0xC4};
    char letra;

	pacoteIPv6 *pPacoteIPv6 = malloc(sizeof(struct pacoteIPv6));
	pacoteTCP *pPacoteTCP = malloc(sizeof(struct pacoteTCP));

	if (argc != 5) {
		printf("Usage: %s iface ipAlvo ipSaida letra \n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

	inet_pton(AF_INET, argv[2], alvoIp);
	inet_pton(AF_INET, argv[3], saidaIp);
    letra = *argv[4];

	/* Cria um descritor de socket do tipo RAW */
	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	memset(&if_idx, 0, sizeof (struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		exit(1);
	}

	/* Obtem o endereco MAC da interface local */
	memset(&if_mac, 0, sizeof (struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		exit(1);
	}

	/* Indice da interface de rede */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	/* Tamanho do endereco (ETH_ALEN = 6) */
	socket_address.sll_halen = ETH_ALEN;

	/* Endereco MAC de destino */
	memcpy(socket_address.sll_addr, destMac, MAC_ADDR_LEN);

	/* Preenche o buffer com 0s */
	memset(buffer, 0, BUFFER_SIZE);

	/* Monta o cabecalho Ethernet */

	/* Preenche o campo de endereco MAC de destino */	
	memcpy(buffer, destMac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;
	memcpy(localMac, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);

	/* Preenche o campo EtherType */
	memcpy(buffer + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);	

	pPacoteIPv6->version = 0x6;

	pPacoteIPv6->trafficClass = 0x5;

	pPacoteIPv6->flowLabel = 0x01;

	pPacoteIPv6->payload[0] = 0x00;
    pPacoteIPv6->payload[1] = 0xDB;

	pPacoteIPv6->nextHeader = 0x00;

	pPacoteIPv6->hopLimit = 0x80;

	pPacoteIPv6->protocol = 0x11;

	pPacoteIPv6->ipSource[0] = saidaIp[0];
	pPacoteIPv6->ipSource[1] = saidaIp[1];
	pPacoteIPv6->ipSource[2] = saidaIp[2];
	pPacoteIPv6->ipSource[3] = saidaIp[3];

	pPacoteIPv6->ipDestination[0] = alvoIp[0];
	pPacoteIPv6->ipDestination[1] = alvoIp[1];
	pPacoteIPv6->ipDestination[2] = alvoIp[2];
	pPacoteIPv6->ipDestination[3] = alvoIp[3];

	/* InserePacote Ipv6 */
	memcpy(buffer + frame_len, pPacoteIPv6, sizeof(struct pacoteIPv6));
	frame_len += sizeof(struct pacoteIPv6);

	//Preenche campos de cabeçalho TCP
	
	pPacoteTCP->portSource[0] = 0x59;
	pPacoteTCP->portSource[1] = 0x00;

	pPacoteTCP->portDestination[0] = 0x59;
	pPacoteTCP->portDestination[1] = 0x00;

	pPacoteTCP->sequenceNumber[0] = 0x00;
    pPacoteTCP->sequenceNumber[1] = 0x00;
    pPacoteTCP->sequenceNumber[2] = 0x00;
	pPacoteTCP->sequenceNumber[3] = 0x09;

    pPacoteTCP->ackNumber[0] = 0x00;
    pPacoteTCP->ackNumber[1] = 0x00;
    pPacoteTCP->ackNumber[2] = 0x00;
	pPacoteTCP->ackNumber[3] = 0x09;

    pPacoteTCP->dataOffSet = letra;

    pPacoteTCP->reserved = letra;

    pPacoteTCP->flags = letra;

	pPacoteTCP->windowSize[0] = 0x00;
	pPacoteTCP->windowSize[1] = 0x05;

	pPacoteTCP->checksum = letra;

    pPacoteTCP->urgentPointer[0] = 0x00;
	pPacoteTCP->urgentPointer[1] = 0x05;

	/* InserePacote UDP */
	memcpy(buffer + frame_len, pPacoteTCP, sizeof(struct pacoteTCP));
	frame_len += sizeof(struct pacoteTCP);


	/* Envia pacote */
	if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
		perror("send");
		close(fd);
		exit(1);
	}


	frame_len -= sizeof(struct pacoteIPv6) + 1;
	usleep(500);

	close(fd);
	return 0;
}
