#ifndef PKTLENS_IPV4DISSECTOR_H
#define PKTLENS_IPV4DISSECTOR_H

#include "./DissectorRegistry.h"

namespace pktlens {

bool dissect_ipv4(const uint8_t* data,
                  size_t len,
                  uint16_t offset,
                  ParsedPacket& pkt,
                  Node& node,
                  DissectorContext& ctx);

}

#endif