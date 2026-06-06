#ifndef PACKET_INFO_H
#define PACKET_INFO_H

#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdint.h>

// Shared struct defining the interface contract between Person 1 and Person 2
typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    struct timeval timestamp;
    const unsigned char* payload;
    int payload_len;
} packet_info_t;

// Prototype for Person 2's function (implemented in demux.c)
extern void demux_packet(packet_info_t* pkt);

#endif