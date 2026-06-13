#ifndef PKTLENS_ARPDISSECTOR_H
#define PKTLENS_ARPDISSECTOR_H
#include "DissectorRegistry.h"
namespace pktlens {
    bool dissect_arp(const uint8_t* data, size_t len, uint16_t offset,
                     ParsedPacket& pkt, Node& node, DissectorContext& ctx);
}
#endif