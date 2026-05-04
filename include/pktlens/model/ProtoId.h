#ifndef PKTLENS_PROTOID_H
#define PKTLENS_PROTOID_H

#include <cstdint>
#include <cstddef>

namespace pktlens {

    // Enum of all supported protocols
    enum ProtoId : uint8_t {
        Unknown = 0,
        Ethernet, 
        ARP,
        IPv4,
        IPv6,
        TCP,
        UDP,
        ICMP,
        HTTP,
        DNS,
        _Count
    };

    // Function returns the count of ProtoId enum
    inline constexpr size_t proto_count() {
        return static_cast<size_t>(ProtoId::_Count);
    }

    // Function that returns text representation of id for display
    inline const char* proto_name(ProtoId id) {

        const char* names[] = {
            "???",      // Unknown
            "Ethernet",
            "ARP",
            "IPv4",
            "IPv6",
            "TCP",
            "UDP",
            "ICMP",
            "HTTP",
            "DNS",
        };

        static_assert((sizeof(names)/sizeof(names[0])) == static_cast<size_t>(ProtoId::_Count), 
            "proto_name array out of sync with ProtoId enum");

        size_t idx = static_cast<size_t>(id);
        if (idx >= proto_count()) { return "???"; }
        return names[idx];
    }
}

#endif