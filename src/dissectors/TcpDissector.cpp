#include "pktlens/dissectors/TcpDissector.h"
#include "pktlens/dissectors/AppDissectors.h"
#include "pktlens/model/ProtocolTree.h"
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>

namespace pktlens {

static std::string format_tcp_flags(uint8_t flags) {
    char buf[32];
    buf[0] = '\0';
    if (flags & 0x02) std::strncat(buf, "SYN ", sizeof(buf) - 1);
    if (flags & 0x10) std::strncat(buf, "ACK ", sizeof(buf) - 1);
    if (flags & 0x01) std::strncat(buf, "FIN ", sizeof(buf) - 1);
    if (flags & 0x04) std::strncat(buf, "RST ", sizeof(buf) - 1);
    if (flags & 0x08) std::strncat(buf, "PSH ", sizeof(buf) - 1);
    if (flags & 0x20) std::strncat(buf, "URG ", sizeof(buf) - 1);
    size_t slen = std::strlen(buf);
    if (slen > 0 && buf[slen - 1] == ' ') { buf[slen - 1] = '\0'; }
    return (buf[0] == '\0') ? "none" : std::string(buf);
}

bool dissect_tcp(const uint8_t* data, size_t len, uint16_t offset,
                 ParsedPacket& pkt, Node& node, DissectorContext& ctx)
{
    if (len < 20) { return false; }

    node.protocol = ProtoId::TCP;

    uint16_t src_port, dst_port;
    memcpy(&src_port, data + 0, 2); src_port = ntohs(src_port);
    memcpy(&dst_port, data + 2, 2); dst_port = ntohs(dst_port);

    uint32_t seq, ack_num;
    memcpy(&seq,     data + 4, 4); seq     = ntohl(seq);
    memcpy(&ack_num, data + 8, 4); ack_num = ntohl(ack_num);

    uint8_t data_offset_words = (data[12] >> 4) & 0x0F;
    size_t  header_bytes      = static_cast<size_t>(data_offset_words) * 4;

    if (data_offset_words < 5 || header_bytes > len) { return false; }

    uint8_t  flags = data[13];

    uint16_t window, checksum, urgent;
    memcpy(&window,   data + 14, 2); window   = ntohs(window);
    memcpy(&checksum, data + 16, 2); checksum = ntohs(checksum);
    memcpy(&urgent,   data + 18, 2); urgent   = ntohs(urgent);

    pkt.src_port = src_port;
    pkt.dst_port = dst_port;
    pkt.tcp_flags = flags;

    char sp_buf[8], dp_buf[8], seq_buf[12], ack_buf[12];
    char doff_buf[4], win_buf[8], cs_buf[8], urg_buf[8];

    std::snprintf(sp_buf,   sizeof(sp_buf),   "%u",    src_port);
    std::snprintf(dp_buf,   sizeof(dp_buf),   "%u",    dst_port);
    std::snprintf(seq_buf,  sizeof(seq_buf),  "%u",    seq);
    std::snprintf(ack_buf,  sizeof(ack_buf),  "%u",    ack_num);
    std::snprintf(doff_buf, sizeof(doff_buf), "%u",    data_offset_words);
    std::snprintf(win_buf,  sizeof(win_buf),  "%u",    window);
    std::snprintf(cs_buf,   sizeof(cs_buf),   "0x%04x", checksum);
    std::snprintf(urg_buf,  sizeof(urg_buf),  "%u",    urgent);

    node.fields.push_back(make_field("src_port",    sp_buf,                    offset + 0,  2));
    node.fields.push_back(make_field("dst_port",    dp_buf,                    offset + 2,  2));
    node.fields.push_back(make_field("seq",         seq_buf,                   offset + 4,  4));
    node.fields.push_back(make_field("ack",         ack_buf,                   offset + 8,  4));
    node.fields.push_back(make_field("data_offset", doff_buf,                  offset + 12, 1));
    node.fields.push_back(make_field("flags",       format_tcp_flags(flags),   offset + 13, 1));
    node.fields.push_back(make_field("window",      win_buf,                   offset + 14, 2));
    node.fields.push_back(make_field("checksum",    cs_buf,                    offset + 16, 2));
    node.fields.push_back(make_field("urgent_ptr",  urg_buf,                   offset + 18, 2));

    // TCP options (if any)
    if (header_bytes > 20) {
        char opt_buf[32];
        std::snprintf(opt_buf, sizeof(opt_buf), "%zu bytes",
                      header_bytes - 20);
        node.fields.push_back(make_field("options", opt_buf,
                                         offset + 20,
                                         static_cast<uint16_t>(header_bytes - 20)));
    }

    const uint8_t* payload    = data + header_bytes;
    size_t         payload_len = (len > header_bytes) ? len - header_bytes : 0;
    uint16_t       payload_off = static_cast<uint16_t>(offset + header_bytes);

    // ── Application-layer routing ────────────────────────────────────────────

    // Helper: try both directions so we catch responses as well as requests
    auto port_match = [&](uint16_t p) {
        return src_port == p || dst_port == p;
    };

    if (port_match(80) || port_match(8080) || port_match(8000)) {
        Node child;
        if (payload_len > 0)
            dissect_http(payload, payload_len, payload_off, pkt, child, ctx);
        else
            pkt.top_proto = ProtoId::HTTP;
        if (!child.fields.empty()) node.children.push_back(std::move(child));
        return true;
    }

    if (port_match(443) || port_match(8443)) {
        Node child;
        if (payload_len > 0)
            dissect_tls(payload, payload_len, payload_off, pkt, child, ctx);
        else
            pkt.top_proto = ProtoId::HTTPS;
        if (!child.fields.empty()) node.children.push_back(std::move(child));
        return true;
    }

    // TLS on other common ports (IMAPS 993, SMTPS 465/587, FTPS 990, LDAPS 636)
    if (port_match(993) || port_match(465) || port_match(587) ||
        port_match(990) || port_match(636)) {
        Node child;
        if (payload_len > 0)
            dissect_tls(payload, payload_len, payload_off, pkt, child, ctx);
        else
            pkt.top_proto = ProtoId::TLS;
        if (!child.fields.empty()) node.children.push_back(std::move(child));
        return true;
    }

    if (port_match(53)) {
        Node child;
        if (payload_len > 0)
            dissect_dns(payload, payload_len, payload_off, pkt, child, ctx);
        else
            pkt.top_proto = ProtoId::DNS;
        if (!child.fields.empty()) node.children.push_back(std::move(child));
        return true;
    }

    if (port_match(22)) {
        Node child;
        if (payload_len > 0)
            dissect_ssh(payload, payload_len, payload_off, pkt, child, ctx);
        else
            pkt.top_proto = ProtoId::SSH;
        if (!child.fields.empty()) node.children.push_back(std::move(child));
        return true;
    }

    if (port_match(21)) {
        Node child;
        if (payload_len > 0)
            dissect_ftp(payload, payload_len, payload_off, pkt, child, ctx);
        else
            pkt.top_proto = ProtoId::FTP;
        if (!child.fields.empty()) node.children.push_back(std::move(child));
        return true;
    }

    if (port_match(25) || port_match(587) || port_match(2525)) {
        Node child;
        if (payload_len > 0)
            dissect_smtp(payload, payload_len, payload_off, pkt, child, ctx);
        else
            pkt.top_proto = ProtoId::SMTP;
        if (!child.fields.empty()) node.children.push_back(std::move(child));
        return true;
    }

    // Payload present but no recognised application protocol
    if (payload_len > 0) {
        char data_buf[32];
        std::snprintf(data_buf, sizeof(data_buf), "%zu bytes", payload_len);
        node.fields.push_back(make_field("data", data_buf, payload_off,
                                         static_cast<uint16_t>(
                                             payload_len > 0xFFFF ? 0xFFFF : payload_len)));
    }

    pkt.top_proto = ProtoId::TCP;
    (void)ctx;
    return true;
}

}  // namespace pktlens