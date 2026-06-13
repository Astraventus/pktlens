#ifndef PKTLENS_PARSEDPACKET_H
#define PKTLENS_PARSEDPACKET_H

#include "ProtoId.h"
#include <array>
#include <cstdint>

namespace pktlens {

    struct ParsedPacket {
        double timestamp;
        uint32_t length_orig;
        uint32_t length_cap;
        ProtoId top_proto;

        // IPv4 addresses (zero if not IPv4)
        uint32_t src_ip;
        uint32_t dst_ip;

        // TCP/UDP ports
        uint16_t src_port;
        uint16_t dst_port;

        // TCP flags (only valid for TCP)
        uint8_t tcp_flags;

        // IPv6 support
        bool is_ipv6;
        std::array<uint8_t, 16> src_ip6;
        std::array<uint8_t, 16> dst_ip6;

        ParsedPacket()
            : timestamp(0.0)
            , length_orig(0)
            , length_cap(0)
            , top_proto(ProtoId::Unknown)
            , src_ip(0)
            , dst_ip(0)
            , src_port(0)
            , dst_port(0)
            , tcp_flags(0)
            , is_ipv6(false)
            , src_ip6{}
            , dst_ip6{} {}
    };

} // namespace pktlens

#endif