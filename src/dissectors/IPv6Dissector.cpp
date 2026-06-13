#include "pktlens/dissectors/IPv6Dissector.h"
#include "pktlens/dissectors/IcmpDissector.h"
#include "pktlens/dissectors/TcpDissector.h"
#include "pktlens/dissectors/UdpDissector.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstdio>
#include <cstring>

namespace pktlens {

static std::string format_ipv6(const uint8_t* b) {
    struct in6_addr addr;
    memcpy(&addr, b, 16);
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
    return std::string(buf);
}

bool dissect_ipv6(const uint8_t* data, size_t len, uint16_t offset,
                  ParsedPacket& pkt, Node& node, DissectorContext& ctx)
{
    // Fixed IPv6 header is exactly 40 bytes
    if (len < 40) { return false; }

    node.protocol = ProtoId::IPv6;
    pkt.top_proto = ProtoId::IPv6;

    uint8_t version     = (data[0] >> 4) & 0x0F;
    uint8_t traffic_cls = ((data[0] & 0x0F) << 4) | ((data[1] >> 4) & 0x0F);
    uint32_t flow_label = ((uint32_t)(data[1] & 0x0F) << 16)
                        | ((uint32_t)data[2] << 8)
                        |  (uint32_t)data[3];
    uint16_t payload_length;
    memcpy(&payload_length, data + 4, 2);
    payload_length = ntohs(payload_length);
    uint8_t next_header = data[6];
    uint8_t hop_limit   = data[7];

    char ver_buf[4], tc_buf[8], fl_buf[12], pl_buf[8], hl_buf[4];
    std::snprintf(ver_buf, sizeof(ver_buf), "%u",    version);
    std::snprintf(tc_buf,  sizeof(tc_buf),  "0x%02x", traffic_cls);
    std::snprintf(fl_buf,  sizeof(fl_buf),  "0x%05x", flow_label);
    std::snprintf(pl_buf,  sizeof(pl_buf),  "%u",    payload_length);
    std::snprintf(hl_buf,  sizeof(hl_buf),  "%u",    hop_limit);

    node.fields.push_back(make_field("version",        ver_buf, offset + 0, 1));
    node.fields.push_back(make_field("traffic_class",  tc_buf,  offset + 0, 2));
    node.fields.push_back(make_field("flow_label",     fl_buf,  offset + 1, 3));
    node.fields.push_back(make_field("payload_length", pl_buf,  offset + 4, 2));
    node.fields.push_back(make_field("hop_limit",      hl_buf,  offset + 7, 1));

    node.fields.push_back(make_field("src_ip", format_ipv6(data +  8), offset +  8, 16));
    node.fields.push_back(make_field("dst_ip", format_ipv6(data + 24), offset + 24, 16));

    // Store IPv6 addresses in ParsedPacket for list display
    pkt.is_ipv6 = true;
    memcpy(pkt.src_ip6.data(), data + 8, 16);
    memcpy(pkt.dst_ip6.data(), data + 24, 16);

    // IPv4 fields are zeroed
    pkt.src_ip = 0;
    pkt.dst_ip = 0;

    const uint8_t* payload    = data + 40;
    size_t         payload_len = (len > 40) ? len - 40 : 0;
    uint16_t       payload_off = offset + 40;

    // Walk extension headers until we find a recognized upper-layer protocol.
    uint8_t nh = next_header;
    while (payload_len > 0) {
        switch (nh) {
        case 6: {  // TCP
            Node child;
            dissect_tcp(payload, payload_len, payload_off, pkt, child, ctx);
            node.children.push_back(std::move(child));
            return true;
        }
        case 17: {  // UDP
            Node child;
            dissect_udp(payload, payload_len, payload_off, pkt, child, ctx);
            node.children.push_back(std::move(child));
            return true;
        }
        case 58: {  // ICMPv6
            Node child;
            dissect_icmpv6(payload, payload_len, payload_off, pkt, child, ctx);
            node.children.push_back(std::move(child));
            return true;
        }
        // Extension headers with a standard length field at byte 1
        case 0:   // Hop-by-Hop Options
        case 43:  // Routing
        case 60: {// Destination Options
            if (payload_len < 8) { return true; }
            nh = payload[0];
            size_t ext_len = (static_cast<size_t>(payload[1]) + 1) * 8;
            if (ext_len > payload_len) { return true; }
            payload     += ext_len;
            payload_len -= ext_len;
            payload_off += static_cast<uint16_t>(ext_len);
            break;
        }
        case 44: {  // Fragment — fixed 8-byte header
            if (payload_len < 8) { return true; }
            nh = payload[0];
            payload     += 8;
            payload_len -= 8;
            payload_off += 8;
            break;
        }
        default:
            // Unknown next header — stop walking
            return true;
        }
    }

    return true;
}

}  // namespace pktlens