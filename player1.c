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

typedef struct pacoteIPv6 { 
	unsigned char ihl:4;
	unsigned char versao:4;
	unsigned int typeOfService:20;
	unsigned char totalLength[2];
	unsigned char identification[2];
	unsigned char flagsAndOffset[2];
	unsigned char timeToLive;
	unsigned char protocol;
	unsigned char checksum[2];
	unsigned char saidaIp[4];
	unsigned char alvoIp[4];
}pacoteIPv6; 

typedef struct pacoteUDP {
	unsigned char portaOrigem[2];
	unsigned char portaDestino[2];
	unsigned char tamanho[2];
	unsigned char checksum[2];
	unsigned char letra;
} pacoteUDP;

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
	pacoteUDP *pPacoteUDP = malloc(sizeof(struct pacoteUDP));

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

	pPacoteIPv6->versao = 0x4;

	pPacoteIPv6->ihl = 0x5;

	pPacoteIPv6->typeOfService = 0x01;

	pPacoteIPv6->totalLength[0] = 0x00;
    	pPacoteIPv6->totalLength[1] = 0xDB;

	pPacoteIPv6->identification[0] = 0x00;
	pPacoteIPv6->identification[1] = 0x01;

	pPacoteIPv6->flagsAndOffset[0] = 0x00;
	pPacoteIPv6->flagsAndOffset[1] = 0x00;

	pPacoteIPv6->timeToLive = 0x80;

	pPacoteIPv6->protocol = 0x11;

	pPacoteIPv6->checksum[0] = 0x25;
	pPacoteIPv6->checksum[1] = 0xfc;

	pPacoteIPv6->saidaIp[0] = saidaIp[0];
	pPacoteIPv6->saidaIp[1] = saidaIp[1];
	pPacoteIPv6->saidaIp[2] = saidaIp[2];
	pPacoteIPv6->saidaIp[3] = saidaIp[3];

	pPacoteIPv6->alvoIp[0] = alvoIp[0];
	pPacoteIPv6->alvoIp[1] = alvoIp[1];
	pPacoteIPv6->alvoIp[2] = alvoIp[2];
	pPacoteIPv6->alvoIp[3] = alvoIp[3];

	/* InserePacote Ipv4 */
	memcpy(buffer + frame_len, pPacoteIPv6, sizeof(struct pacoteIPv6));
	frame_len += sizeof(struct pacoteIPv6);

	//Preenche campos de cabeçalho UDP
	
	pPacoteUDP->portaOrigem[0] = 0x59;
	pPacoteUDP->portaOrigem[1] = 0x00;

	pPacoteUDP->portaDestino[0] = 0x59;
	pPacoteUDP->portaDestino[1] = 0x00;

	pPacoteUDP->tamanho[0] = 0x00;
	pPacoteUDP->tamanho[1] = 0x09;

	pPacoteUDP->checksum[0] = 0x00;
	pPacoteUDP->checksum[1] = 0x05;

	pPacoteUDP->letra = letra;
	

	/* InserePacote UDP */
	memcpy(buffer + frame_len, pPacoteUDP, sizeof(struct pacoteUDP));
	frame_len += sizeof(struct pacoteUDP);


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
