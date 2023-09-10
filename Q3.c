#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#define PACKET_BUFFER_SIZE 65536

// Function prototypes
void processPacket(unsigned char *, int);
void findProcessID(int);

void processPacket(unsigned char *packet, int packetSize) {
    struct ip *ipHeader = (struct ip *)(packet);
    struct tcphdr *tcpHeader = (struct tcphdr *)(packet + ipHeader->ip_hl * 4);

    char srcIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];

    // Convert source and destination IP addresses to a human-readable format
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

    // Print source and destination IP addresses and ports
    printf("Source IP: %s\n", srcIP);
    printf("Source Port: %d\n", ntohs(tcpHeader->th_sport));
    printf("Destination IP: %s\n", destIP);
    printf("Destination Port: %d\n", ntohs(tcpHeader->th_dport));

    printf("\n");
}

void findProcessID(int port) {
    char command[128];
    sprintf(command, "lsof -i :%d | awk '{print $2}' | tail -n +2", port);
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        printf("Failed to execute the command\n");
        return;
    }

    char output[128];
    if (fgets(output, sizeof(output) - 1, fp) != NULL) {
        printf("Process ID: %s", output);
    } else {
        printf("No process is currently using port %d\n", port);
    }

    pclose(fp);
}

int main() {
    int rawSocket;
    struct sockaddr_in server;
    socklen_t serverLen = sizeof(server);
    unsigned char packetBuffer[PACKET_BUFFER_SIZE];

    // Create a raw socket to capture all packets
    rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rawSocket == -1) {
        perror("Error creating the socket");
        exit(1);
    }

    // Receive packets and print information
    while (1) {
        int packetSize = recvfrom(rawSocket, packetBuffer, PACKET_BUFFER_SIZE, 0, (struct sockaddr *)&server, &serverLen);
        if (packetSize == -1) {
            perror("Error receiving packets");
            close(rawSocket);
            exit(1);
        }

        processPacket(packetBuffer, packetSize);

        // Prompt the user for a port number
        int port;
        printf("Enter a port number: ");
        scanf("%d", &port);

        // Get the process ID associated with the entered port
        findProcessID(port);
    }

    close(rawSocket);
    return 0;
}

// portions of this code is written by chat-GPT