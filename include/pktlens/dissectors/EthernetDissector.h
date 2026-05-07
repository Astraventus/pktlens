#ifndef NETSCOPE_ETHERNETDISSECTOR_H
#define NETSCOPE_ETHERNETDISSECTOR_H

#include "./DissectorRegistry.h"

namespace pktlens {

bool dissect_ethernet(const uint8_t* data,
                      size_t len,
                      uint16_t offset,
                      ParsedPacket& pkt,
                      Node& node,
                      DissectorContext& ctx);

}

#endif