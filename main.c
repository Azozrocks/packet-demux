#include "capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pcap.h>

// Global handle required for the signal handler to break the loop
pcap_t *global_handle = NULL;

/*
 * Signal handler for graceful shutdown on SIGINT (Ctrl+C).
 */
void handle_sigint(int sig) {
    (void)sig;
    if (global_handle != NULL) {
        printf("\nSIGINT received. Initiating graceful shutdown...\n");
        pcap_breakloop(global_handle);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    char *iface = argv[1];
    
    // Register the SIGINT handler
    signal(SIGINT, handle_sigint);

    // Initialize capture and set BPF filter
    global_handle = init_capture(iface);
    if (global_handle == NULL) {
        return 1;
    }

    printf("Listening on interface: %s\n", iface);
    
    // Start blocking capture loop
    start_capture(global_handle);

    // Print capture statistics upon loop exit
    struct pcap_stat stats;
    if (pcap_stats(global_handle, &stats) >= 0) {
        printf("\n--- Capture Statistics ---\n");
        printf("Packets received by filter: %d\n", stats.ps_recv);
        printf("Packets dropped by kernel: %d\n", stats.ps_drop);
    }

    pcap_close(global_handle);
    return 0;
}