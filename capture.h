#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

// Expose the init function to main.c
pcap_t* init_capture(const char* iface);

// Start the capture loop
void start_capture(pcap_t* handle);

#endif