#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define BUFFER_SIZE 2000
#define ETHERTYPE 0x0800


typedef struct pacoteIPv4 { 
	unsigned char versao:4;
	unsigned char ihl:4;
	unsigned char typeOfService;
	unsigned char totalLength[2];
	unsigned char identification[2];
	unsigned char flagsAndOffset[2];
	unsigned char timeToLive;
	unsigned char protocol;
	unsigned char checksum[2];
	unsigned char saidaIp[4];
	unsigned char alvoIp[4];
}pacoteIPv4; 

typedef struct pacoteUDP {
	unsigned char portaOrigem[2];
	unsigned char portaDestino[2];
	unsigned char tamanho[2];
	unsigned char checksum[2];
	unsigned char letra;
} pacoteUDP;

int contemCaracter(char palavra[], char letra) 
{
    for (int i = 0; palavra[i]; i++) {
        if(palavra[i] == letra) {
            return 1;
        }
    }
    return 0;
}

void mostraResultado(char palavra[], char encontradas[]) 
{
    int flagEncontrada = 0;
    for (int i = 0; palavra[i]; i++) {
        for(int j = 0; encontradas[j]; j++){
            if(palavra[i] == encontradas[j]) {
                printf("%c ", encontradas[j]);
                flagEncontrada = 1;
            }
        }
        if(!flagEncontrada){
            printf("_ ");
        }
        flagEncontrada = 0;
    }
}

int main(int argc, char *argv[])
{
	int fd;
    int tentativas = 8;
    int qntLetrasEnc = 0;
	unsigned char buffer[BUFFER_SIZE];
	struct ifreq ifr;
	char ifname[IFNAMSIZ];
	pacoteIPv4 *pPacoteIPv4 = NULL;
	pacoteUDP *pPacoteUDP = NULL;
    char palavra[30];
    char letrasEncontradas[30];

	if (argc != 3) {
		printf("Usage: %s iface palavra\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);
    strcpy(palavra, argv[2]);

	/* Cria um descritor de socket do tipo RAW */
	fd = socket(PF_PACKET,SOCK_RAW, htons(ETH_P_ALL));
	if(fd < 0) {
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	strcpy(ifr.ifr_name, ifname);
	if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl");
		exit(1);
	}

	/* Obtem as flags da interface */
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0){
		perror("ioctl");
		exit(1);
	}

	/* Coloca a interface em modo promiscuo */
	ifr.ifr_flags |= IFF_PROMISC;
	if(ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		perror("ioctl");
		exit(1);
	}

	printf("Esperando pacotes ... \n");
	while (1) {
		unsigned char mac_dst[6];
		unsigned char mac_src[6];
		short int ethertype;

		/* Recebe pacotes */
		if (recv(fd,(char *) &buffer, BUFFER_SIZE, 0) < 0) {
			perror("recv");
			close(fd);
			exit(1);
		}
        
		/* Copia o conteudo do cabecalho Ethernet */
		memcpy(mac_dst, buffer, sizeof(mac_dst));
		memcpy(mac_src, buffer+sizeof(mac_dst), sizeof(mac_src));
		memcpy(&ethertype, buffer+sizeof(mac_dst)+sizeof(mac_src), sizeof(ethertype));
		ethertype = ntohs(ethertype);

		pPacoteIPv4 = (struct pacoteIPv4 *)(buffer+sizeof(mac_dst)+sizeof(mac_src)+sizeof(ethertype));

		pPacoteUDP = (struct pacoteUDP *)(buffer+sizeof(mac_dst)+sizeof(mac_src)+sizeof(ethertype)+(sizeof(struct pacoteIPv4)));

		if (pPacoteIPv4->identification[0] == 0x00 && pPacoteIPv4->identification[1] == 0x01) {
			printf("Cabecalho Ethernet: \n");

			printf("MAC destino: %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);

			printf("MAC origem:  %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);

			printf("EtherType: 0x%04x\n", ethertype);

			printf("\n\nCabecalho Ipv4: \n");
			
			printf("Versão: 0x%01x\n", pPacoteIPv4->versao);

			printf("IHL: 0x%01x\n", pPacoteIPv4->ihl);
			
			printf("Hlen: 0x%02x\n", pPacoteIPv4->typeOfService);

			printf("Total Length: 0x%02x%02x\n", pPacoteIPv4->totalLength[0], pPacoteIPv4->totalLength[1]);
			
			printf("Identification: 0x%02x%02x\n", pPacoteIPv4->identification[0], pPacoteIPv4->identification[1]);

			printf("Flags and Offset: %02x%02x\n", pPacoteIPv4->flagsAndOffset[0], pPacoteIPv4->flagsAndOffset[1]);

			printf("Time to Live: 0x%02x\n", pPacoteIPv4->timeToLive);

			printf("Protocolo: 0x%02x\n", pPacoteIPv4->protocol);

			printf("Checksum: %02x%02x\n", pPacoteIPv4->checksum[0], pPacoteIPv4->checksum[1]);

			printf("IP Origem: %d.%d.%d.%d\n", pPacoteIPv4->saidaIp[0], pPacoteIPv4->saidaIp[1], 
			pPacoteIPv4->saidaIp[2], pPacoteIPv4->saidaIp[3]);

			printf("IP Destino: %d.%d.%d.%d\n", pPacoteIPv4->alvoIp[0], pPacoteIPv4->alvoIp[1], 
			pPacoteIPv4->alvoIp[2], pPacoteIPv4->alvoIp[3]);
			
			printf("\n\nCabecalho UDP: \n");

			printf("Porta Origem: 0x%02x%02x\n", pPacoteUDP->portaOrigem[0], pPacoteUDP->portaOrigem[1]);

			printf("Porta Dentino: 0x%02x%02x\n", pPacoteUDP->portaDestino[0], pPacoteUDP->portaDestino[1]);

			printf("Tamanho: 0x%02x%02x\n", pPacoteUDP->tamanho[0], pPacoteUDP->tamanho[1]);

			printf("Checksum: 0x%02x%02x\n", pPacoteUDP->checksum[0], pPacoteUDP->checksum[1]);

			printf("Letra da jogada: %c\n", pPacoteUDP->letra);

			printf("\n\n");
            
            if(tentativas > 0)
            {
                if(contemCaracter(palavra, pPacoteUDP->letra)){
                    letrasEncontradas[qntLetrasEnc] = pPacoteUDP->letra;
                    qntLetrasEnc++;
                    mostraResultado(palavra, letrasEncontradas);
                    printf("\nTentativas restantes: %d\n", tentativas);
                }else{
                    tentativas--;
                    mostraResultado(palavra, letrasEncontradas);
                    printf("\nLetra Inexistente, Tentativas restantes: %d\n", tentativas);
                }
            }else{
                printf("\nAcabaram suas tentativas\n");
            }

            printf("\n\n");

		}
	}

	close(fd);
	return 0;
}
