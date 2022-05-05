
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h> // gettimeofday()
#include <stdio.h>
#include <time.h>

 // IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8 

// Checksum algo
unsigned short calculate_checksum(unsigned short * paddress, int len);

#define SOURCE_IP "127.0.0.1" // Source IP address
// i.e the gateway or ping to google.com for their ip-address
#define DESTINATION_IP "8.8.4.4" // Destination IP address



int main ()
{
    struct icmp icmphdr; // ICMP-header
    char data[IP_MAXPACKET] = "This is the ping.\n";

    int datalen = strlen(data) + 1;

    //===================
    // ICMP header
    //===================

    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHO;

    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18; // hai

    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    // Combine the packet 
    char packet[IP_MAXPACKET];

    // Next, ICMP header
    memcpy ((packet), &icmphdr, ICMP_HDRLEN);

    // After ICMP header, add the ICMP data.
    memcpy (packet + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

    // Calculate the ICMP header checksum

((struct icmp *)packet)->icmp_cksum = calculate_checksum((unsigned short *) packet, ICMP_HDRLEN + datalen);

    //icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet + IP4_HDRLEN), ICMP_HDRLEN + datalen);
    //memcpy ((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);



    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    
    // set the destination to send ICMP ping request to
    dest_in.sin_addr.s_addr = inet_addr (DESTINATION_IP);

    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1;
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) <  0)
    {
        fprintf(stderr, "socket() failed with error: %d", errno);
        fprintf(stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }
    
    // countdown timer for ping
    struct timespec start, end;
    clock_gettime(CLOCK_REALTIME, &start);

    // Send the packet
    if (sendto(sock, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof (struct sockaddr_in)) < 0)
    {
        fprintf(stderr, "sendto() failed with error: %d", errno);
        return -1;
    }

    printf("Ping (%s) with %d bytes of data.\n", DESTINATION_IP, ICMP_HDRLEN + datalen);

    //receiving the pong reply
    bzero(&packet, sizeof(packet));
    socklen_t len = sizeof(dest_in);
    int size_recv = -1;
    while (size_recv < 0)
    {
        size_recv = recvfrom(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest_in, &len);
    }
    if (size_recv == 0)
    {
        printf("error aquired while waiting for the message\n");
    }
    else
    {
        clock_gettime(CLOCK_REALTIME, &end);

        double time_spent = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000.0;
        printf("\tReply from %s: bytes=%d time=%.3fms \n\n", DESTINATION_IP, size_recv, time_spent);
    }

    close(sock);
  return 0;
}




//// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits

	return answer;
}

