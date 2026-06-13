#ifndef PKTLENS_APPDISSECTORS_H
#define PKTLENS_APPDISSECTORS_H

// All application-layer dissectors share this single header.
// Each takes the transport payload and decorates pkt.top_proto + node.

#include "DissectorRegistry.h"

namespace pktlens {

    bool dissect_dns (const uint8_t* data, size_t len, uint16_t offset,
                    ParsedPacket& pkt, Node& node, DissectorContext& ctx);

    bool dissect_dhcp(const uint8_t* data, size_t len, uint16_t offset,
                    ParsedPacket& pkt, Node& node, DissectorContext& ctx);

    bool dissect_http(const uint8_t* data, size_t len, uint16_t offset,
                    ParsedPacket& pkt, Node& node, DissectorContext& ctx);

    bool dissect_tls (const uint8_t* data, size_t len, uint16_t offset,
                    ParsedPacket& pkt, Node& node, DissectorContext& ctx);

    bool dissect_ssh (const uint8_t* data, size_t len, uint16_t offset,
                    ParsedPacket& pkt, Node& node, DissectorContext& ctx);

    bool dissect_ftp (const uint8_t* data, size_t len, uint16_t offset,
                    ParsedPacket& pkt, Node& node, DissectorContext& ctx);

    bool dissect_smtp(const uint8_t* data, size_t len, uint16_t offset,
                    ParsedPacket& pkt, Node& node, DissectorContext& ctx);

    bool dissect_ntp (const uint8_t* data, size_t len, uint16_t offset,
                    ParsedPacket& pkt, Node& node, DissectorContext& ctx);

}  // namespace pktlens

#endif  // PKTLENS_APPDISSECTORS_H