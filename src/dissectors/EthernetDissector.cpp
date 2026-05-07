#include "pktlens/dissectors/DissectorRegistry.h"
#include "pktlens/dissectors/IPv4Dissector.h"
#include "pktlens/model/ProtocolTree.h"
#include <arpa/inet.h>
#include <cstdio>

namespace pktlens {

    // Format 6 MAC bytes as "aa:bb:cc:dd:ee:ff"
    static std::string format_mac(const uint8_t* b) {
        char buf[18];
        std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
              b[0], b[1], b[2], b[3], b[4], b[5]);
        return std::string(buf);
    }

    bool dissect_ethernet(const uint8_t* data, 
                                size_t len,
                                uint16_t offset,
                                ParsedPacket& pkt,
                                Node& node,
                                DissectorContext& ctx)
    {
        // Ethernet header is exactly 14 bytes.
        // Reject anything shorter — there's no valid ethernet frame here.
        if (len < 14) {
            return false;
        }

        node.protocol = ProtoId::Ethernet;

        // dst MAC: bytes 0-5
        node.fields.push_back(make_field("dst_MAC", format_mac(data + 0), offset, 6));
        // src MAC: bytes 6-11
        node.fields.push_back(make_field("src_MAC", format_mac(data + 6), offset + 6, 6));

        // EtherType: bytes 12-13, big-endian
        uint16_t ethertype;
        memcpy(&ethertype, data+12, 2);
        ethertype = htons(ethertype);

        char ethtype_buf[7];
        std::snprintf(ethtype_buf, sizeof(ethtype_buf), "0x%04x", ethertype);
        node.fields.push_back(make_field("ethertype", ethtype_buf, offset + 12, 2));

        // Payload starts at byte 14
        const uint8_t* payload = data + 14;
        size_t payload_len = len - 14;
        uint16_t payload_offset = offset + 14;

        // Routing to the next dissector based on Ethertype
        switch (ethertype) {
            case 0x0800: 
            {  // IPv4
            Node ipv4_node;
            dissect_ipv4(payload, payload_len, payload_offset, pkt, ipv4_node, ctx);
            node.children.push_back(std::move(ipv4_node));
            break;
            }
            case 0x0806:    // ARP - later
                pkt.top_proto = ProtoId::ARP;
                break;
            case 0x86DD:    // IPv6 — later
                pkt.top_proto = ProtoId::IPv6;
                break;
            default:
                pkt.top_proto = ProtoId::Unknown;
                break;

        } 
    }
}