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

void process_packet(unsigned char *, int);
void get_process_id(int);

int main() {
    int raw_socket;
    struct sockaddr_in server;
    socklen_t server_len = sizeof(server);
    unsigned char packet_buffer[PACKET_BUFFER_SIZE];

    // Create a raw socket to capture all packets
    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket == -1) {
        perror("Socket creation error");
        exit(1);
    }

    // Receive packets and print information
    while (1) {
        int packet_size = recvfrom(raw_socket, packet_buffer, PACKET_BUFFER_SIZE, 0, (struct sockaddr *)&server, &server_len);
        if (packet_size == -1) {
            perror("Packet receive error");
            close(raw_socket);
            exit(1);
        }

        process_packet(packet_buffer, packet_size);

        // Prompt the user for a port number
        int port;
        printf("Enter a port number (or -1 to exit): ");
        scanf("%d", &port);
        
        if (port == -1) {
            break; // Exit the loop if -1 is entered
        }

        // Get the process ID for the entered port
        get_process_id(port);
    }

    close(raw_socket);
    return 0;
}

void process_packet(unsigned char *packet, int packet_size) {
    struct ip *ip_header = (struct ip *)(packet);
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + ip_header->ip_hl * 4);

    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    // Convert source and destination IP addresses to human-readable format
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

    // Print source and destination IP addresses and ports
    printf("Source IP: %s\n", src_ip);
    printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
    printf("Destination IP: %s\n", dest_ip);
    printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));

    printf("\n");
}

void get_process_id(int port) {
    char command[128];
    sprintf(command, "lsof -i :%d -t", port);
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        printf("Failed to run command\n");
        return;
    }

    char output[128];
    if (fgets(output, sizeof(output)-1, fp) != NULL) {
        printf("Process ID: %s", output);
    } else {
        printf("No process is using port %d\n", port);
    }

    pclose(fp);
}