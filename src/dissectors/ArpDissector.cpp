#include "pktlens/dissectors/ArpDissector.h"
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

static std::string format_ipv4(const uint8_t* b) {
    char buf[INET_ADDRSTRLEN];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return std::string(buf);
}

bool dissect_arp(const uint8_t* data, size_t len, uint16_t offset,
                 ParsedPacket& pkt, Node& node, DissectorContext& /*ctx*/)
{
    // ARP fixed header: 8 bytes + 2*(hlen+plen)
    // For Ethernet/IPv4: hlen=6, plen=4 → total 28 bytes
    if (len < 8) { return false; }

    node.protocol = ProtoId::ARP;
    pkt.top_proto = ProtoId::ARP;

    uint16_t htype, ptype;
    memcpy(&htype, data + 0, 2); htype = ntohs(htype);
    memcpy(&ptype, data + 2, 2); ptype = ntohs(ptype);
    uint8_t hlen = data[4];
    uint8_t plen = data[5];
    uint16_t oper;
    memcpy(&oper, data + 6, 2); oper = ntohs(oper);

    // Validate we have enough bytes for SHA+SPA+THA+TPA
    size_t addrs_size = 2u * (hlen + plen);
    if (len < 8u + addrs_size) { return false; }

    const char* op_str = (oper == 1) ? "request" :
                         (oper == 2) ? "reply"   : "unknown";

    char htype_buf[8], ptype_buf[8];
    std::snprintf(htype_buf, sizeof(htype_buf), "0x%04x", htype);
    std::snprintf(ptype_buf, sizeof(ptype_buf), "0x%04x", ptype);

    node.fields.push_back(make_field("htype",    htype_buf,  offset + 0, 2));
    node.fields.push_back(make_field("ptype",    ptype_buf,  offset + 2, 2));
    node.fields.push_back(make_field("operation", op_str,    offset + 6, 2));

    // For the common Ethernet/IPv4 case add the MAC and IP addresses
    if (hlen == 6 && plen == 4) {
        const uint8_t* sha = data + 8;
        const uint8_t* spa = data + 8 + 6;
        const uint8_t* tha = data + 8 + 6 + 4;
        const uint8_t* tpa = data + 8 + 6 + 4 + 6;

        node.fields.push_back(make_field("sender_MAC", format_mac(sha), offset + 8,       6));
        node.fields.push_back(make_field("sender_IP",  format_ipv4(spa), offset + 14,     4));
        node.fields.push_back(make_field("target_MAC", format_mac(tha), offset + 18,      6));
        node.fields.push_back(make_field("target_IP",  format_ipv4(tpa), offset + 24,     4));

        // Put sender/target IPs into ParsedPacket for filter support
        memcpy(&pkt.src_ip, spa, 4);
        memcpy(&pkt.dst_ip, tpa, 4);
    }

    return true;
}

}  // namespace pktlens