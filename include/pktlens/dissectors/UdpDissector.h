#ifndef PKTLENS_UDPDISSECTOR_H
#define PKTLENS_UDPDISSECTOR_H
#include "DissectorRegistry.h"
namespace pktlens {
    bool dissect_udp(const uint8_t* data, size_t len, uint16_t offset,
                    ParsedPacket& pkt, Node& node, DissectorContext& ctx);
}
#endif