#ifndef NETSCOPE_TCPDISSECTOR_H
#define NETSCOPE_TCPDISSECTOR_H

#include "./DissectorRegistry.h"

namespace pktlens {
    
bool dissect_tcp(const uint8_t* data,
                 size_t len,
                 uint16_t offset,
                 ParsedPacket& pkt,
                 Node& node,
                 DissectorContext& ctx);
}

#endif