#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    // Cast to void to prevent "unused parameter" warnings from GCC during testing
    (void)args;
    (void)packet; 
    
    printf("Packet captured! Capture length: %d bytes\n", header->caplen);
}

int main(int argc, char *argv[]) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;

    // Ensure the user provides a network interface argument
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        fprintf(stderr, "Example: sudo %s eth0\n", argv[0]);
        return 1;
    }
    dev = argv[1];

    // Open the network device for live capture
    // Parameters: device, snapshot length (BUFSIZ), promiscuous mode (1), timeout (1000ms), error buffer
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
        return 1;
    }

    printf("Listening on interface %s...\n", dev);

    // Enter the capture loop. 
    // Parameter '0' indicates it should loop indefinitely until an error occurs or pcap_breakloop is called.
    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    // Clean up
    pcap_close(handle);
    return 0;
}