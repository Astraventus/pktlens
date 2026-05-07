#include "pktlens/dissectors/IPv4Dissector.h"
#include "pktlens/dissectors/TcpDissector.h"
#include "pktlens/model/ProtocolTree.h"
#include <arpa/inet.h>  // ntohs, ntohl, inet_ntop
#include <netinet/in.h> // struct in_addr
#include <cstdio>

namespace pktlens {

    // Format a uint32_t IP (network byte order) as "A.B.C.D"
    static std::string format_ipv4(uint32_t ip_nbo) {
        struct in_addr addr;
        addr.s_addr = ip_nbo;  // already in network byte order
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        return std::string(buf);
    }

    bool dissect_ipv4(const uint8_t* data,
                    size_t len,
                    uint16_t offset,
                    ParsedPacket& pkt,
                    Node& node,
                    DissectorContext& ctx)
    {
        // Minimum IPv4 header: 20 bytes
        if (len < 20) {
            return false;
        }

        node.protocol = ProtoId::IPv4;

        // Byte 0: version (high nibble) + IHL (low nibble)
        const uint8_t version = (data[0] >> 4) & 0x0F;
        const uint8_t ihl = (data[0]) & 0x0F;

        // IHL is in 32-bit words. Minimum valid value is 5 (= 20 bytes).
        // Reject if IHL < 5 (malformed) or IHL*4 > len (truncated).
        size_t ihl_bytes = static_cast<size_t>(ihl) * 4;
        if (ihl < 5 || ihl > len) {
            return false;
        }

        char ver_buf[4];
        std::snprintf(ver_buf, sizeof(ver_buf), "%u", version);
        node.fields.push_back(make_field("version", ver_buf, offset + 0, 1));

        char ihl_buf[4];
        std::snprintf(ihl_buf, sizeof(ihl_buf), "%u", ihl);
        node.fields.push_back(make_field("ihl", ihl_buf, offset + 0, 1));

        // Bytes 2-3: total length (big-endian)
        uint16_t total_length;
        memcpy(&total_length, data + 2, 2);

        char tl_buf[8];
        std::snprintf(tl_buf, sizeof(tl_buf), "%u", total_length);
        node.fields.push_back(make_field("total_length", tl_buf, offset + 2, 2));

        // Byte 8: TTL
        uint8_t ttl = data[8];

        char ttl_buf[6];
        std::snprintf(ttl_buf, sizeof(ttl_buf), "%u", ttl);
        node.fields.push_back(make_field("ttl", ttl_buf, offset + 8, 1));

        // Byte 9: protocol number
        uint8_t proto_num = data[9];
        char proto_buf[4];
        std::snprintf(proto_buf, sizeof(proto_buf), "%u", proto_num);
        node.fields.push_back(make_field("protocol", proto_buf, offset + 9, 1));

        // Bytes 12-15: source IP
        uint32_t src_ip;
        memcpy(&src_ip, data + 12, 4);
        uint32_t dst_ip;
        memcpy(&dst_ip, data + 16, 4);

        // Store binary in ParsedPacket (for sort/filter)
        pkt.src_ip = src_ip;
        pkt.dst_ip = dst_ip;

        // Store formatted string in ProtocolTree (for display)
        node.fields.push_back(make_field("src_ip", format_ipv4(src_ip), offset + 12, 4));
        node.fields.push_back(make_field("dst_ip", format_ipv4(dst_ip), offset + 16, 4));

        // Payload starts after the IP header (which may include options)
        const uint8_t* payload     = data + ihl_bytes;
        size_t payload_len = len - ihl_bytes;
        uint16_t payload_off = static_cast<uint16_t>(offset + ihl_bytes);


        // Hand off based on protocol number
        switch (proto_num) {
            case 6: {   // TCP
                Node tcp_node;
                dissect_tcp(payload, payload_len, payload_off, pkt, tcp_node, ctx);
                node.children.push_back(std::move(tcp_node));
                break;
            }
            case 17:    // UDP
                pkt.top_proto = ProtoId::UDP;
                break;
            case 1:     // ICMP
                pkt.top_proto = ProtoId::ICMP;
                break;
            default:
                pkt.top_proto = ProtoId::IPv4;  // IP but unknown transport
                break;
        }

    return true;
    }

}