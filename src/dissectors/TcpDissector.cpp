#include "pktlens/dissectors/TcpDissector.h"
#include "pktlens/model/ProtocolTree.h"
#include <arpa/inet.h>  // ntohs, ntohl
#include <cstdio>
#include <cstring>

namespace pktlens {

// Decode TCP flags byte into a human-readable string like "SYN ACK"
static std::string format_tcp_flags(uint8_t flags) {
    // Flags bit positions (low to high): FIN SYN RST PSH ACK URG ECE CWR
    char buf[32];
    buf[0] = '\0';
    if (flags & 0x02) std::strncat(buf, "SYN ", sizeof(buf) - 1);
    if (flags & 0x10) std::strncat(buf, "ACK ", sizeof(buf) - 1);
    if (flags & 0x01) std::strncat(buf, "FIN ", sizeof(buf) - 1);
    if (flags & 0x04) std::strncat(buf, "RST ", sizeof(buf) - 1);
    if (flags & 0x08) std::strncat(buf, "PSH ", sizeof(buf) - 1);
    if (flags & 0x20) std::strncat(buf, "URG ", sizeof(buf) - 1);
    // Strip trailing space
    size_t slen = std::strlen(buf);
    if (slen > 0 && buf[slen - 1] == ' ') {
        buf[slen - 1] = '\0';
    }
    if (buf[0] == '\0') {
        return "none";
    }
    return std::string(buf);
}

bool dissect_tcp(const uint8_t* data,
                 size_t len,
                 uint16_t offset,
                 ParsedPacket& pkt,
                 Node& node,
                 DissectorContext& ctx)
{
    // Minimum TCP header: 20 bytes
    if (len < 20) {
        return false;
    }

    node.protocol = ProtoId::TCP;

    // Bytes 0-1: source port (big-endian)
    // Bytes 2-3: destination port (big-endian)
    uint16_t src_port;
    memcpy(&src_port, data + 0, 2);
    src_port = ntohs(src_port);
    uint16_t dst_port;
    memcpy(&dst_port, data + 2, 2);
    dst_port = ntohs(dst_port);

    pkt.src_port = src_port;
    pkt.dst_port = dst_port;

    char port_buf[8];
    std::snprintf(port_buf, sizeof(port_buf), "%u",src_port);
    node.fields.push_back(make_field("src_port", port_buf, offset + 0, 2));
    std::snprintf(port_buf, sizeof(port_buf), "%u",dst_port);
    node.fields.push_back(make_field("dst_port", port_buf, offset + 0, 2));

    // Bytes 4-7: sequence number (big-endian)
    uint32_t seq;
    memcpy(&seq, data + 4, 4);
    seq = ntohs(seq);

    char seq_buf[12];
    std::snprintf(seq_buf, sizeof(seq_buf), "%u", seq);
    node.fields.push_back(make_field("seq", seq_buf, offset + 4, 4));

    // Bytes 8-11: acknowledgment number
    uint32_t ack;
    memcpy(&ack, data + 8, 4);
    ack = ntohs(ack);

    char ack_buf[12];
    std::snprintf(ack_buf, sizeof(ack_buf), "%u", ack);
    node.fields.push_back(make_field("ack", ack_buf, offset + 8, 4));

    // Byte 12: data offset (high nibble, in 32-bit words)
    uint8_t data_offset_words = (data[12] >> 4) & 0x0F;
    size_t header_bytes = static_cast<size_t>(data_offset_words) * 4;

    // Reject if data offset < 5 (malformed) or header > available bytes
    if (data_offset_words < 5 || header_bytes > len) {
            return false;
    }

    // Byte 13: flags
    uint8_t flags = data[13];
    pkt.tcp_flags = flags;

    node.fields.push_back(make_field("flags", format_tcp_flags(flags), offset + 13, 1));

    // Bytes 14-15: window size
    uint16_t window;
    memcpy(&window, data + 14, 2);

    char win_buf[8];
    std::snprintf(win_buf, sizeof(win_buf), "%u", window);
    node.fields.push_back(make_field("window", win_buf, offset + 14, 2));

    // Determine top_proto.
    // HTTP heuristic: port 80 or 8080, and there is a payload after the header.
    size_t payload_len = len - header_bytes;
    if ((dst_port == 80 || dst_port == 8080 ||
         src_port == 80 || src_port == 8080) && payload_len > 0) {
        pkt.top_proto = ProtoId::HTTP;
    } else if (dst_port == 53 || src_port == 53) {
        // DNS over TCP also uses port 53
        pkt.top_proto = ProtoId::DNS;
    } else {
        pkt.top_proto = ProtoId::TCP;
    }


    // ctx is unused in v1 — parameter exists for v3 TCP reassembly
    (void)ctx;

    return true;
}

}