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


