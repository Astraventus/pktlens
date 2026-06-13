#include "pktlens/dissectors/IcmpDissector.h"
#include <cstdio>
#include <cstring>
#include <netinet/in.h>

namespace pktlens {

// ── ICMP type/code → human label ────────────────────────────────────────────

static const char* icmp_type_name(uint8_t type) {
    switch (type) {
    case 0:  return "Echo Reply";
    case 3:  return "Destination Unreachable";
    case 4:  return "Source Quench";
    case 5:  return "Redirect";
    case 8:  return "Echo Request";
    case 9:  return "Router Advertisement";
    case 10: return "Router Solicitation";
    case 11: return "Time Exceeded";
    case 12: return "Parameter Problem";
    case 13: return "Timestamp";
    case 14: return "Timestamp Reply";
    default: return "Unknown";
    }
}

static const char* icmpv6_type_name(uint8_t type) {
    switch (type) {
    case 1:   return "Destination Unreachable";
    case 2:   return "Packet Too Big";
    case 3:   return "Time Exceeded";
    case 4:   return "Parameter Problem";
    case 128: return "Echo Request";
    case 129: return "Echo Reply";
    case 133: return "Router Solicitation";
    case 134: return "Router Advertisement";
    case 135: return "Neighbor Solicitation";
    case 136: return "Neighbor Advertisement";
    case 137: return "Redirect";
    default:  return "Unknown";
    }
}

// ── ICMPv4 ──────────────────────────────────────────────────────────────────

bool dissect_icmp(const uint8_t* data, size_t len, uint16_t offset,
                  ParsedPacket& pkt, Node& node, DissectorContext& /*ctx*/)
{
    // ICMP header: 4 bytes minimum (type + code + checksum)
    if (len < 4) { return false; }

    node.protocol = ProtoId::ICMP;
    pkt.top_proto = ProtoId::ICMP;

    uint8_t  type = data[0];
    uint8_t  code = data[1];
    uint16_t csum;
    memcpy(&csum, data + 2, 2);
    csum = ntohs(csum);

    char type_buf[48], code_buf[4], csum_buf[8];
    std::snprintf(type_buf, sizeof(type_buf), "%u (%s)", type, icmp_type_name(type));
    std::snprintf(code_buf, sizeof(code_buf), "%u", code);
    std::snprintf(csum_buf, sizeof(csum_buf), "0x%04x", csum);

    node.fields.push_back(make_field("type",     type_buf, offset + 0, 1));
    node.fields.push_back(make_field("code",     code_buf, offset + 1, 1));
    node.fields.push_back(make_field("checksum", csum_buf, offset + 2, 2));

    // Echo request/reply carry identifier and sequence number
    if ((type == 0 || type == 8) && len >= 8) {
        uint16_t id, seq;
        memcpy(&id,  data + 4, 2); id  = ntohs(id);
        memcpy(&seq, data + 6, 2); seq = ntohs(seq);

        char id_buf[8], seq_buf[8];
        std::snprintf(id_buf,  sizeof(id_buf),  "%u", id);
        std::snprintf(seq_buf, sizeof(seq_buf), "%u", seq);
        node.fields.push_back(make_field("identifier",       id_buf,  offset + 4, 2));
        node.fields.push_back(make_field("sequence_number",  seq_buf, offset + 6, 2));
    }

    // Destination Unreachable / Time Exceeded carry an embedded IP header
    if ((type == 3 || type == 11) && len >= 8) {
        char payload_note[32];
        std::snprintf(payload_note, sizeof(payload_note),
                      "%zu bytes", len - 8);
        node.fields.push_back(make_field("embedded_packet", payload_note,
                                         offset + 8,
                                         static_cast<uint16_t>(len - 8)));
    }

    return true;
}

// ── ICMPv6 ──────────────────────────────────────────────────────────────────

bool dissect_icmpv6(const uint8_t* data, size_t len, uint16_t offset,
                    ParsedPacket& pkt, Node& node, DissectorContext& /*ctx*/)
{
    if (len < 4) { return false; }

    node.protocol = ProtoId::ICMPv6;
    pkt.top_proto = ProtoId::ICMPv6;

    uint8_t  type = data[0];
    uint8_t  code = data[1];
    uint16_t csum;
    memcpy(&csum, data + 2, 2);
    csum = ntohs(csum);

    char type_buf[64], code_buf[4], csum_buf[8];
    std::snprintf(type_buf, sizeof(type_buf), "%u (%s)", type, icmpv6_type_name(type));
    std::snprintf(code_buf, sizeof(code_buf), "%u", code);
    std::snprintf(csum_buf, sizeof(csum_buf), "0x%04x", csum);

    node.fields.push_back(make_field("type",     type_buf, offset + 0, 1));
    node.fields.push_back(make_field("code",     code_buf, offset + 1, 1));
    node.fields.push_back(make_field("checksum", csum_buf, offset + 2, 2));

    // Echo request (128) / reply (129)
    if ((type == 128 || type == 129) && len >= 8) {
        uint16_t id, seq;
        memcpy(&id,  data + 4, 2); id  = ntohs(id);
        memcpy(&seq, data + 6, 2); seq = ntohs(seq);

        char id_buf[8], seq_buf[8];
        std::snprintf(id_buf,  sizeof(id_buf),  "%u", id);
        std::snprintf(seq_buf, sizeof(seq_buf), "%u", seq);
        node.fields.push_back(make_field("identifier",      id_buf,  offset + 4, 2));
        node.fields.push_back(make_field("sequence_number", seq_buf, offset + 6, 2));
    }

    // Neighbor Solicitation (135) / Advertisement (136): target address at bytes 8-23
    if ((type == 135 || type == 136) && len >= 24) {
        char addr_buf[INET6_ADDRSTRLEN];
        // Format 16 raw bytes as hex groups without inet_ntop dependency here
        const uint8_t* a = data + 8;
        std::snprintf(addr_buf, sizeof(addr_buf),
                      "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                      "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                      a[0], a[1], a[2],  a[3],  a[4],  a[5],  a[6],  a[7],
                      a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
        node.fields.push_back(make_field("target_address", addr_buf, offset + 8, 16));
    }

    return true;
}

}  // namespace pktlens