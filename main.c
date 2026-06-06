#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

// Declare Person 2's packet_handler callback
extern void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

/*
 * Purpose: Sets up packet capture (live or offline) and starts the loop.
 * Live Usage: sudo ./demultiplexer <interface_name>
 * Offline Usage: ./demultiplexer -r <file.pcap>
 */
int main(int argc, char *argv[]) {
    pcap_t *capture_handle;
    char error_buffer[PCAP_ERRBUF_SIZE];

    // Offline Mode: Read from a saved .pcap file
    if (argc == 3 && strcmp(argv[1], "-r") == 0) {
        printf("Initializing offline capture from file: %s\n", argv[2]);
        capture_handle = pcap_open_offline(argv[2], error_buffer);
        if (capture_handle == NULL) {
            fprintf(stderr, "Error opening pcap file %s: %s\n", argv[2], error_buffer);
            return 1;
        }
    } 
    // Live Mode: Capture from a network interface
    else if (argc == 2) {
        printf("Initializing live capture on interface: %s\n", argv[1]);
        capture_handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, error_buffer);
        if (capture_handle == NULL) {
            fprintf(stderr, "Error opening device %s: %s\n", argv[1], error_buffer);
            return 1;
        }
    } 
    // Invalid Arguments
    else {
        fprintf(stderr, "Usage (Live): %s <interface_name>\n", argv[0]);
        fprintf(stderr, "Usage (Offline): %s -r <file.pcap>\n", argv[0]);
        return 1;
    }

    printf("Capture loop started. Press Ctrl+C to stop.\n");

    // Start the capture loop using pcap_loop, passing Person 2's callback
    if (pcap_loop(capture_handle, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(capture_handle));
        pcap_close(capture_handle);
        return 1;
    }

    // Clean up resources on exit
    pcap_close(capture_handle);
    return 0;
}