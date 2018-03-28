#pragma once

#include <stdint.h>

#define SCANNER_RAW_PPS 128
#define SCANNER_MAX_CONNS 128

typedef uint32_t ipv4_t;

struct scanner_connection {
    int fd;
    enum {
        SC_CLOSED,
        SC_CONNECTING,
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    uint8_t tries;
};

void syn_scan(void);
