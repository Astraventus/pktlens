#ifndef PKTLENS_PROTOID_H
#define PKTLENS_PROTOID_H

#include <cstdint>
#include <cstddef>

namespace pktlens {

    enum ProtoId : uint8_t {
        Unknown = 0,
        Ethernet,
        VLAN,       // 802.1Q
        MPLS,
        ARP,
        IPv4,
        IPv6,
        TCP,
        UDP,
        ICMP,
        ICMPv6,
        DNS,
        DHCP,
        HTTP,
        HTTPS,      // TLS on 443
        TLS,        // TLS on other ports
        SSH,
        FTP,
        SMTP,
        NTP,
        _Count
    };

    inline constexpr size_t proto_count() {
        return static_cast<size_t>(ProtoId::_Count);
    }

    inline const char* proto_name(ProtoId id) {
        static const char* names[] = {
            "???",      // Unknown
            "Ethernet",
            "VLAN",
            "MPLS",
            "ARP",
            "IPv4",
            "IPv6",
            "TCP",
            "UDP",
            "ICMP",
            "ICMPv6",
            "DNS",
            "DHCP",
            "HTTP",
            "HTTPS",
            "TLS",
            "SSH",
            "FTP",
            "SMTP",
            "NTP",
        };

        static_assert((sizeof(names)/sizeof(names[0])) == static_cast<size_t>(ProtoId::_Count),
            "proto_name array out of sync with ProtoId enum");

        size_t idx = static_cast<size_t>(id);
        if (idx >= proto_count()) { return "???"; }
        return names[idx];
    }
}

#endif