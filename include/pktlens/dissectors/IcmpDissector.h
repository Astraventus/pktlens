#ifndef PKTLENS_ICMPDISSECTOR_H
#define PKTLENS_ICMPDISSECTOR_H
#include "DissectorRegistry.h"
namespace pktlens {
    bool dissect_icmp(const uint8_t* data, size_t len, uint16_t offset,
                    ParsedPacket& pkt, Node& node, DissectorContext& ctx);
    bool dissect_icmpv6(const uint8_t* data, size_t len, uint16_t offset,
                        ParsedPacket& pkt, Node& node, DissectorContext& ctx);
}
#endif