#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h> // Include this header for inet_ntop

void processPacket(unsigned char *, int);

int main() {
    int rawSocket;
    struct sockaddr_in server;
    socklen_t serverLength = sizeof(server);
    unsigned char packetBuffer[65536]; // Buffer to store incoming packets

    // Create a raw socket with IPPROTO_TCP to capture TCP packets
    rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (rawSocket == -1) {
        perror("Failed to create socket");
        exit(1);
    }

    while (1) {
        int dataSize = recvfrom(rawSocket, packetBuffer, sizeof(packetBuffer), 0,
                                (struct sockaddr *)&server, &serverLength);
        if (dataSize < 0) {
            perror("Failed to receive");
            exit(1);
        }

        // Process the received packet to identify TCP flows
        processPacket(packetBuffer, dataSize);
    }

    return 0;
}

void processPacket(unsigned char *packet, int dataSize) {
    struct ip *ipHeader = (struct ip *)packet;
    struct tcphdr *tcpHeader = (struct tcphdr *)(packet + ipHeader->ip_hl * 4); // Calculate TCP header position

    // Extract source and destination IP addresses
    char sourceIP[INET_ADDRSTRLEN], destIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

    // Extract source and destination port numbers
    unsigned short sourcePort = ntohs(tcpHeader->th_sport);
    unsigned short destPort = ntohs(tcpHeader->th_dport);

    printf("Source IP: %s\n", sourceIP);
    printf("Destination IP: %s\n", destIP);
    printf("Source Port: %d\n", sourcePort);
    printf("Destination Port: %d\n", destPort);
    printf("\n");
}


// parts of this code is written with the help of chat GPT.