#include "pktlens/dissectors/EthernetDissector.h"
#include "pktlens/dissectors/ArpDissector.h"
#include "pktlens/dissectors/IPv4Dissector.h"
#include "pktlens/dissectors/IPv6Dissector.h"
#include "pktlens/model/ProtocolTree.h"
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>

namespace pktlens {

static std::string format_mac(const uint8_t* b) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  b[0], b[1], b[2], b[3], b[4], b[5]);
    return std::string(buf);
}

// Forward declaration — handles inner ethertype after VLAN/MPLS stripping.
static bool route_ethertype(uint16_t ethertype,
                             const uint8_t* payload, size_t payload_len,
                             uint16_t payload_offset,
                             ParsedPacket& pkt, Node& parent,
                             DissectorContext& ctx);

bool dissect_ethernet(const uint8_t* data, size_t len, uint16_t offset,
                      ParsedPacket& pkt, Node& node, DissectorContext& ctx)
{
    if (len < 14) { return false; }

    node.protocol = ProtoId::Ethernet;
    node.fields.push_back(make_field("dst_MAC", format_mac(data + 0), offset,      6));
    node.fields.push_back(make_field("src_MAC", format_mac(data + 6), offset + 6,  6));

    uint16_t ethertype;
    memcpy(&ethertype, data + 12, 2);
    ethertype = ntohs(ethertype);

    char ethtype_buf[7];
    std::snprintf(ethtype_buf, sizeof(ethtype_buf), "0x%04x", ethertype);
    node.fields.push_back(make_field("ethertype", ethtype_buf, offset + 12, 2));

    route_ethertype(ethertype,
                    data + 14, len - 14, offset + 14,
                    pkt, node, ctx);
    return true;
}

// ── Ethertype routing ────────────────────────────────────────────────────────

static bool route_ethertype(uint16_t ethertype,
                             const uint8_t* payload, size_t payload_len,
                             uint16_t payload_offset,
                             ParsedPacket& pkt, Node& parent,
                             DissectorContext& ctx)
{
    switch (ethertype) {

    case 0x0800: {  // IPv4
        Node child;
        dissect_ipv4(payload, payload_len, payload_offset, pkt, child, ctx);
        parent.children.push_back(std::move(child));
        return true;
    }

    case 0x86DD: {  // IPv6
        Node child;
        dissect_ipv6(payload, payload_len, payload_offset, pkt, child, ctx);
        parent.children.push_back(std::move(child));
        return true;
    }

    case 0x0806: {  // ARP
        Node child;
        dissect_arp(payload, payload_len, payload_offset, pkt, child, ctx);
        parent.children.push_back(std::move(child));
        return true;
    }

    case 0x8100:    // 802.1Q VLAN
    case 0x88A8: {  // 802.1ad Q-in-Q outer tag
        if (payload_len < 4) {
            pkt.top_proto = ProtoId::VLAN;
            return false;
        }
        Node vlan_node;
        vlan_node.protocol = ProtoId::VLAN;

        // Bytes 0-1: TCI (PCP 3 bits | DEI 1 bit | VID 12 bits)
        uint16_t tci;
        memcpy(&tci, payload, 2);
        tci = ntohs(tci);
        uint16_t vid = tci & 0x0FFF;
        uint8_t  pcp = (tci >> 13) & 0x07;

        char vid_buf[8], pcp_buf[4];
        std::snprintf(vid_buf, sizeof(vid_buf), "%u", vid);
        std::snprintf(pcp_buf, sizeof(pcp_buf), "%u", pcp);
        vlan_node.fields.push_back(make_field("vlan_id",  vid_buf, payload_offset,     2));
        vlan_node.fields.push_back(make_field("priority", pcp_buf, payload_offset,     2));

        // Bytes 2-3: inner ethertype
        uint16_t inner_ethertype;
        memcpy(&inner_ethertype, payload + 2, 2);
        inner_ethertype = ntohs(inner_ethertype);

        char inner_buf[7];
        std::snprintf(inner_buf, sizeof(inner_buf), "0x%04x", inner_ethertype);
        vlan_node.fields.push_back(make_field("inner_ethertype", inner_buf,
                                              payload_offset + 2, 2));

        pkt.top_proto = ProtoId::VLAN;
        route_ethertype(inner_ethertype,
                        payload + 4, payload_len - 4,
                        payload_offset + 4,
                        pkt, vlan_node, ctx);

        parent.children.push_back(std::move(vlan_node));
        return true;
    }

    case 0x8847:    // MPLS unicast
    case 0x8848: {  // MPLS multicast
        if (payload_len < 4) {
            pkt.top_proto = ProtoId::MPLS;
            return false;
        }
        Node mpls_node;
        mpls_node.protocol = ProtoId::MPLS;

        // Walk MPLS label stack — each entry is 4 bytes.
        // Label: bits 31-12 (20 bits)
        // TC:    bits 11-9  (3 bits, formerly EXP)
        // S:     bit 8      (bottom-of-stack)
        // TTL:   bits 7-0
        size_t pos = 0;
        bool bottom = false;
        int stack_depth = 0;
        while (pos + 4 <= payload_len && !bottom && stack_depth < 8) {
            uint32_t entry;
            memcpy(&entry, payload + pos, 4);
            entry = ntohl(entry);
            uint32_t label = (entry >> 12) & 0xFFFFF;
            uint8_t  tc    = (entry >>  9) & 0x07;
            bottom         = (entry >>  8) & 0x01;
            uint8_t  ttl   =  entry        & 0xFF;

            char lbl_buf[16], tc_buf[4], ttl_buf[4];
            std::snprintf(lbl_buf, sizeof(lbl_buf), "%u", label);
            std::snprintf(tc_buf,  sizeof(tc_buf),  "%u", tc);
            std::snprintf(ttl_buf, sizeof(ttl_buf), "%u", ttl);

            char field_name[16];
            std::snprintf(field_name, sizeof(field_name),
                          "label[%d]", stack_depth);
            mpls_node.fields.push_back(make_field(field_name, lbl_buf,
                                                   payload_offset + pos, 4));
            mpls_node.fields.push_back(make_field("tc",  tc_buf,
                                                   payload_offset + pos, 4));
            mpls_node.fields.push_back(make_field("ttl", ttl_buf,
                                                   payload_offset + pos, 4));
            pos += 4;
            ++stack_depth;
        }

        pkt.top_proto = ProtoId::MPLS;

        // After label stack, try to identify inner packet by inspecting first nibble.
        if (pos < payload_len) {
            uint8_t first_nibble = (payload[pos] >> 4) & 0x0F;
            if (first_nibble == 4) {
                route_ethertype(0x0800, payload + pos, payload_len - pos,
                                payload_offset + pos, pkt, mpls_node, ctx);
            } else if (first_nibble == 6) {
                route_ethertype(0x86DD, payload + pos, payload_len - pos,
                                payload_offset + pos, pkt, mpls_node, ctx);
            }
        }

        parent.children.push_back(std::move(mpls_node));
        return true;
    }

    default:
        pkt.top_proto = ProtoId::Unknown;
        return false;
    }
}

}  // namespace pktlens