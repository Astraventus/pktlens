#include "pktlens/dissectors/IPv4Dissector.h"
#include "pktlens/dissectors/TcpDissector.h"
#include "pktlens/dissectors/UdpDissector.h"
#include "pktlens/dissectors/IcmpDissector.h"
#include "pktlens/model/ProtocolTree.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstdio>
#include <cstring>

namespace pktlens {

static std::string format_ipv4(uint32_t ip_nbo) {
    struct in_addr addr;
    addr.s_addr = ip_nbo;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}

bool dissect_ipv4(const uint8_t* data, size_t len, uint16_t offset,
                  ParsedPacket& pkt, Node& node, DissectorContext& ctx)
{
    if (len < 20) { return false; }

    node.protocol = ProtoId::IPv4;

    const uint8_t version = (data[0] >> 4) & 0x0F;
    const uint8_t ihl     = (data[0])      & 0x0F;
    size_t ihl_bytes      = static_cast<size_t>(ihl) * 4;

    if (ihl < 5 || ihl_bytes > len) { return false; }

    // DSCP / ECN (byte 1)
    uint8_t dscp = (data[1] >> 2) & 0x3F;
    uint8_t ecn  =  data[1]       & 0x03;

    uint16_t total_length;
    memcpy(&total_length, data + 2, 2);
    total_length = ntohs(total_length);

    uint16_t identification;
    memcpy(&identification, data + 4, 2);
    identification = ntohs(identification);

    uint16_t flags_frag;
    memcpy(&flags_frag, data + 6, 2);
    flags_frag = ntohs(flags_frag);
    uint8_t  flags     = (flags_frag >> 13) & 0x07;
    uint16_t frag_off  =  flags_frag        & 0x1FFF;

    uint8_t ttl       = data[8];
    uint8_t proto_num = data[9];

    uint16_t checksum;
    memcpy(&checksum, data + 10, 2);
    checksum = ntohs(checksum);

    uint32_t src_ip, dst_ip;
    memcpy(&src_ip, data + 12, 4);
    memcpy(&dst_ip, data + 16, 4);

    pkt.src_ip = src_ip;
    pkt.dst_ip = dst_ip;

    char ver_buf[4], ihl_buf[4], dscp_buf[8], ecn_buf[4];
    char tl_buf[8],  id_buf[8],  fl_buf[4],   fo_buf[8];
    char ttl_buf[6], pr_buf[4],  cs_buf[8];

    std::snprintf(ver_buf,  sizeof(ver_buf),  "%u",    version);
    std::snprintf(ihl_buf,  sizeof(ihl_buf),  "%u",    ihl);
    std::snprintf(dscp_buf, sizeof(dscp_buf), "0x%02x", dscp);
    std::snprintf(ecn_buf,  sizeof(ecn_buf),  "%u",    ecn);
    std::snprintf(tl_buf,   sizeof(tl_buf),   "%u",    total_length);
    std::snprintf(id_buf,   sizeof(id_buf),   "0x%04x", identification);
    std::snprintf(fl_buf,   sizeof(fl_buf),   "%u",    flags);
    std::snprintf(fo_buf,   sizeof(fo_buf),   "%u",    frag_off);
    std::snprintf(ttl_buf,  sizeof(ttl_buf),  "%u",    ttl);
    std::snprintf(pr_buf,   sizeof(pr_buf),   "%u",    proto_num);
    std::snprintf(cs_buf,   sizeof(cs_buf),   "0x%04x", checksum);

    node.fields.push_back(make_field("version",        ver_buf,  offset + 0,  1));
    node.fields.push_back(make_field("ihl",            ihl_buf,  offset + 0,  1));
    node.fields.push_back(make_field("dscp",           dscp_buf, offset + 1,  1));
    node.fields.push_back(make_field("ecn",            ecn_buf,  offset + 1,  1));
    node.fields.push_back(make_field("total_length",   tl_buf,   offset + 2,  2));
    node.fields.push_back(make_field("identification", id_buf,   offset + 4,  2));
    node.fields.push_back(make_field("flags",          fl_buf,   offset + 6,  1));
    node.fields.push_back(make_field("frag_offset",    fo_buf,   offset + 6,  2));
    node.fields.push_back(make_field("ttl",            ttl_buf,  offset + 8,  1));
    node.fields.push_back(make_field("protocol",       pr_buf,   offset + 9,  1));
    node.fields.push_back(make_field("checksum",       cs_buf,   offset + 10, 2));
    node.fields.push_back(make_field("src_ip", format_ipv4(src_ip), offset + 12, 4));
    node.fields.push_back(make_field("dst_ip", format_ipv4(dst_ip), offset + 16, 4));

    const uint8_t* payload    = data + ihl_bytes;
    size_t         payload_len = (len > ihl_bytes) ? len - ihl_bytes : 0;
    uint16_t       payload_off = static_cast<uint16_t>(offset + ihl_bytes);

    switch (proto_num) {
    case 6: {   // TCP
        Node child;
        dissect_tcp(payload, payload_len, payload_off, pkt, child, ctx);
        node.children.push_back(std::move(child));
        break;
    }
    case 17: {  // UDP
        Node child;
        dissect_udp(payload, payload_len, payload_off, pkt, child, ctx);
        node.children.push_back(std::move(child));
        break;
    }
    case 1: {   // ICMP
        Node child;
        dissect_icmp(payload, payload_len, payload_off, pkt, child, ctx);
        node.children.push_back(std::move(child));
        break;
    }
    default:
        pkt.top_proto = ProtoId::IPv4;
        break;
    }

    return true;
}

}  // namespace pktlens