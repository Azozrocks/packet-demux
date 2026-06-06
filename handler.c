#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Parses captured packets, filters for TCP, extracts connection tuples,
 * and saves the raw packet data to a file.
 */
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)args; // Prevent unused parameter warning

    // 1. Parse Ethernet Header
    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return; // Not IPv4
    }

    // 2. Parse IP Header
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    if (ip_header->ip_p != IPPROTO_TCP) {
        return; // Not TCP
    }

    // Calculate dynamic IP header length (usually 20 bytes, but can be larger)
    int ip_len = ip_header->ip_hl * 4;

    // 3. Parse TCP Header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_len);

    // 4. Extract IPs and Ports
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);

    // 5. Generate Timestamp
    char timestamp[64];
    struct tm *tm_info = localtime(&header->ts.tv_sec);
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);

    // 6. Format Filename: [timestamp] sourceip.sourceport-destip.destport
    char filename[256];
    snprintf(filename, sizeof(filename), "[%s] %s.%d-%s.%d.bin", 
             timestamp, src_ip, src_port, dst_ip, dst_port);

    // 7. Store Data in File (Append Mode)
    FILE *file = fopen(filename, "ab");
    if (file == NULL) {
        perror("Error opening file for packet storage");
        return;
    }

    // Write raw packet bytes to the file
    size_t written = fwrite(packet, 1, header->caplen, file);
    if (written != header->caplen) {
        fprintf(stderr, "Error: Incomplete write to %s\n", filename);
    }

    fclose(file);
    printf("Demultiplexed and saved: %s\n", filename);
}