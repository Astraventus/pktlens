#ifndef PKTLENS_PARSERPACKET_H
#define PKTLENS_PARSERPACKET_H

#include "ProtoId.h"
#include <cstdint>

namespace pktlens {
    
    // Flat cache of the fields that UI needs to display for every row.
    // Built once per packet at load time.
    struct ParsedPacket {
        double timestamp;     // seconds
        uint32_t src_ip;
        uint32_t dst_ip;
        // both of above are in network byte order; 0 if not ipv4
        uint16_t src_port;
        uint16_t dst_port;
        // both of above are 0 if not tcp/udp
        uint32_t length_orig; // wire length
        uint32_t length_cap;  // captured length
        ProtoId top_proto;    // highest recognised protocol
        uint8_t tcp_flags; // TCP flags byte, 0 if not tcp
    };
}

#endif