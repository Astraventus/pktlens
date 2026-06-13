#include "pktlens/dissectors/UdpDissector.h"
#include "pktlens/dissectors/AppDissectors.h"
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>

namespace pktlens {

bool dissect_udp(const uint8_t* data, size_t len, uint16_t offset,
                 ParsedPacket& pkt, Node& node, DissectorContext& ctx)
{
    // UDP header is exactly 8 bytes
    if (len < 8) { return false; }

    node.protocol = ProtoId::UDP;

    uint16_t src_port, dst_port, udp_len, checksum;
    memcpy(&src_port, data + 0, 2); src_port = ntohs(src_port);
    memcpy(&dst_port, data + 2, 2); dst_port = ntohs(dst_port);
    memcpy(&udp_len,  data + 4, 2); udp_len  = ntohs(udp_len);
    memcpy(&checksum, data + 6, 2); checksum = ntohs(checksum);

    pkt.src_port = src_port;
    pkt.dst_port = dst_port;

    char sp_buf[8], dp_buf[8], ul_buf[8], cs_buf[8];
    std::snprintf(sp_buf, sizeof(sp_buf), "%u", src_port);
    std::snprintf(dp_buf, sizeof(dp_buf), "%u", dst_port);
    std::snprintf(ul_buf, sizeof(ul_buf), "%u", udp_len);
    std::snprintf(cs_buf, sizeof(cs_buf), "0x%04x", checksum);

    node.fields.push_back(make_field("src_port", sp_buf, offset + 0, 2));
    node.fields.push_back(make_field("dst_port", dp_buf, offset + 2, 2));
    node.fields.push_back(make_field("length",   ul_buf, offset + 4, 2));
    node.fields.push_back(make_field("checksum", cs_buf, offset + 6, 2));

    const uint8_t* payload    = data + 8;
    size_t         payload_len = (len > 8) ? len - 8 : 0;
    uint16_t       payload_off = offset + 8;

    // ── Application-layer routing ────────────────────────────────────────────
    // Checked before the generic UDP fallback so the most specific match wins.

    // DNS: port 53 (query or response)
    if (src_port == 53 || dst_port == 53) {
        Node child;
        if (payload_len > 0)
            dissect_dns(payload, payload_len, payload_off, pkt, child, ctx);
        else
            pkt.top_proto = ProtoId::DNS;
        if (!child.fields.empty()) node.children.push_back(std::move(child));
        return true;
    }

    // DHCP: server 67, client 68
    if (src_port == 67 || dst_port == 67 ||
        src_port == 68 || dst_port == 68) {
        Node child;
        if (payload_len > 0)
            dissect_dhcp(payload, payload_len, payload_off, pkt, child, ctx);
        else
            pkt.top_proto = ProtoId::DHCP;
        if (!child.fields.empty()) node.children.push_back(std::move(child));
        return true;
    }

    // NTP: port 123
    if (src_port == 123 || dst_port == 123) {
        Node child;
        if (payload_len > 0)
            dissect_ntp(payload, payload_len, payload_off, pkt, child, ctx);
        else
            pkt.top_proto = ProtoId::NTP;
        if (!child.fields.empty()) node.children.push_back(std::move(child));
        return true;
    }

    // Generic UDP
    pkt.top_proto = ProtoId::UDP;
    return true;
}

}  // namespace pktlens