#ifndef PKTLENS_IPV6DISSECTOR_H
#define PKTLENS_IPV6DISSECTOR_H
#include "DissectorRegistry.h"
namespace pktlens {
    bool dissect_ipv6(const uint8_t* data, size_t len, uint16_t offset,
                    ParsedPacket& pkt, Node& node, DissectorContext& ctx);
}
#endif