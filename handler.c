#include <sys/types.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Callback function invoked by pcap_loop for every captured packet.
 * Filters for TCP over IPv4, extracts source/destination IPs and ports,
 * and saves the raw packet data to a dynamically named binary file.
 */
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    // Prevent compiler warnings for unused callback arguments
    (void)args;

    // --- 1. Ethernet Layer Parsing ---
    // Cast the raw packet bytes to an Ethernet header structure.
    struct ether_header *eth_header = (struct ether_header *)packet;

    // Ensure the encapsulated protocol is IPv4 (0x0800).
    // ntohs converts the network byte order to host byte order.
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
    {
        return; // Drop non-IPv4 packets
    }

    // --- 2. IP Layer Parsing ---
    // Offset the pointer by the size of the Ethernet header to read the IP header.
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

    // Ensure the transport layer protocol is TCP (Protocol number 6).
    if (ip_header->ip_p != IPPROTO_TCP)
    {
        return; // Drop non-TCP packets
    }

    // Calculate the actual length of the IP header.
    // ip_hl stores the length in 32-bit words, so multiply by 4 to get bytes.
    int ip_len = ip_header->ip_hl * 4;

    // --- 3. TCP Layer Parsing ---
    // Offset the pointer past both Ethernet and IP headers to reach the TCP header.
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_len);

    // --- 4. Data Extraction ---
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    // Convert IP addresses from network byte format (binary) to presentation format (string).
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Extract and convert source and destination ports.
    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);

    // --- 5. File Naming & Timestamps ---
    char timestamp[64];

    // Convert the packet capture timestamp (Unix epoch) to a local time structure.
    struct tm *tm_info = localtime(&header->ts.tv_sec);

    // Format the time as YYYYMMDD_HHMMSS
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);

    // Construct the output filename string based on the project requirements.
    char filename[256];
    snprintf(filename, sizeof(filename), "[%s] %s.%d-%s.%d.bin",
             timestamp, src_ip, src_port, dst_ip, dst_port);

    // --- 6. Data Storage ---
    // Open the file in binary append mode ("ab").
    // This ensures subsequent packets in the same connection append to the same file.
    FILE *file = fopen(filename, "ab");
    if (file == NULL)
    {
        perror("Error opening file for packet storage");
        return;
    }

    // Write the exact number of captured bytes to the file.
    size_t written = fwrite(packet, 1, header->caplen, file);

    // Verify that the full payload was written successfully.
    if (written != header->caplen)
    {
        fprintf(stderr, "Error: Incomplete write to %s\n", filename);
    }

    fclose(file);
    printf("Demultiplexed and saved: %s\n", filename);
}