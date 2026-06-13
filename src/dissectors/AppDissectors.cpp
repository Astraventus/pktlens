#include "pktlens/dissectors/AppDissectors.h"
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <cctype>
#include <string>
#include <algorithm>

namespace pktlens {

// ============================================================================
// DNS  (RFC 1035)
// ============================================================================

static const char* dns_qtype_name(uint16_t t) {
    switch (t) {
    case 1:   return "A";
    case 2:   return "NS";
    case 5:   return "CNAME";
    case 6:   return "SOA";
    case 12:  return "PTR";
    case 15:  return "MX";
    case 16:  return "TXT";
    case 28:  return "AAAA";
    case 33:  return "SRV";
    case 255: return "ANY";
    default:  return "?";
    }
}

// Decode a DNS name starting at data[pos], following pointers.
// Returns the decoded name and advances pos past the label sequence.
static std::string dns_decode_name(const uint8_t* base, size_t base_len,
                                   size_t& pos, int depth = 0)
{
    if (depth > 10) { return "<loop>"; }
    std::string name;
    while (pos < base_len) {
        uint8_t len = base[pos];
        if (len == 0) { ++pos; break; }

        if ((len & 0xC0) == 0xC0) {
            // Pointer
            if (pos + 1 >= base_len) { break; }
            size_t ptr = ((size_t)(len & 0x3F) << 8) | base[pos + 1];
            pos += 2;
            std::string rest = dns_decode_name(base, base_len, ptr, depth + 1);
            name += rest;
            return name;
        }

        ++pos;
        if (!name.empty()) { name += '.'; }
        if (pos + len > base_len) { name += "?"; break; }
        name.append(reinterpret_cast<const char*>(base + pos), len);
        pos += len;
    }
    if (name.empty()) { name = "."; }
    return name;
}

bool dissect_dns(const uint8_t* data, size_t len, uint16_t offset,
                 ParsedPacket& pkt, Node& node, DissectorContext& /*ctx*/)
{
    // DNS header: 12 bytes
    if (len < 12) { return false; }

    node.protocol = ProtoId::DNS;
    pkt.top_proto = ProtoId::DNS;

    uint16_t txid, flags_w, qdcount, ancount, nscount, arcount;
    memcpy(&txid,    data + 0,  2); txid    = ntohs(txid);
    memcpy(&flags_w, data + 2,  2); flags_w = ntohs(flags_w);
    memcpy(&qdcount, data + 4,  2); qdcount = ntohs(qdcount);
    memcpy(&ancount, data + 6,  2); ancount = ntohs(ancount);
    memcpy(&nscount, data + 8,  2); nscount = ntohs(nscount);
    memcpy(&arcount, data + 10, 2); arcount = ntohs(arcount);

    bool     is_response = (flags_w >> 15) & 0x01;
    uint8_t  opcode      = (flags_w >> 11) & 0x0F;
    uint8_t  rcode       =  flags_w        & 0x0F;

    const char* rcode_str = "NOERROR";
    switch (rcode) {
    case 1: rcode_str = "FORMERR";  break;
    case 2: rcode_str = "SERVFAIL"; break;
    case 3: rcode_str = "NXDOMAIN"; break;
    case 4: rcode_str = "NOTIMP";   break;
    case 5: rcode_str = "REFUSED";  break;
    }

    char txid_buf[8], fl_buf[8], qd_buf[4], an_buf[4];
    std::snprintf(txid_buf, sizeof(txid_buf), "0x%04x", txid);
    std::snprintf(fl_buf,   sizeof(fl_buf),   "0x%04x", flags_w);
    std::snprintf(qd_buf,   sizeof(qd_buf),   "%u",     qdcount);
    std::snprintf(an_buf,   sizeof(an_buf),   "%u",     ancount);

    node.fields.push_back(make_field("transaction_id",   txid_buf,               offset + 0,  2));
    node.fields.push_back(make_field("type",             is_response ? "response" : "query",
                                                                                 offset + 2,  2));
    node.fields.push_back(make_field("flags",            fl_buf,                 offset + 2,  2));
    node.fields.push_back(make_field("rcode",            rcode_str,              offset + 2,  2));
    node.fields.push_back(make_field("questions",        qd_buf,                 offset + 4,  2));
    node.fields.push_back(make_field("answer_rrs",       an_buf,                 offset + 6,  2));

    // Decode the first question
    size_t pos = 12;
    if (qdcount > 0 && pos < len) {
        std::string qname = dns_decode_name(data, len, pos);
        if (pos + 4 <= len) {
            uint16_t qtype, qclass;
            memcpy(&qtype,  data + pos,     2); qtype  = ntohs(qtype);
            memcpy(&qclass, data + pos + 2, 2); qclass = ntohs(qclass);
            pos += 4;

            node.fields.push_back(make_field("query_name",  qname,
                                             offset + 12,
                                             static_cast<uint16_t>(pos - 12)));
            node.fields.push_back(make_field("query_type",  dns_qtype_name(qtype),
                                             static_cast<uint16_t>(offset + pos - 4), 2));
            (void)qclass;
        }
    }

    // Decode first answer RR if present
    if (ancount > 0 && pos < len) {
        std::string aname = dns_decode_name(data, len, pos);
        if (pos + 10 <= len) {
            uint16_t atype, aclass, rdlength;
            uint32_t ttl_rr;
            memcpy(&atype,    data + pos,     2); atype    = ntohs(atype);
            memcpy(&aclass,   data + pos + 2, 2); aclass   = ntohs(aclass);
            memcpy(&ttl_rr,   data + pos + 4, 4); ttl_rr   = ntohl(ttl_rr);
            memcpy(&rdlength, data + pos + 8, 2); rdlength = ntohs(rdlength);
            pos += 10;
            (void)aclass;

            char ttl_buf[16];
            std::snprintf(ttl_buf, sizeof(ttl_buf), "%u", ttl_rr);
            node.fields.push_back(make_field("answer_name", aname,
                                             static_cast<uint16_t>(offset + pos - 10), 2));
            node.fields.push_back(make_field("answer_type", dns_qtype_name(atype),
                                             static_cast<uint16_t>(offset + pos - 10), 2));
            node.fields.push_back(make_field("answer_ttl",  ttl_buf,
                                             static_cast<uint16_t>(offset + pos - 6), 4));

            // For A records decode the IPv4 address
            if (atype == 1 && rdlength == 4 && pos + 4 <= len) {
                char ip_buf[INET_ADDRSTRLEN];
                std::snprintf(ip_buf, sizeof(ip_buf), "%u.%u.%u.%u",
                              data[pos], data[pos+1], data[pos+2], data[pos+3]);
                node.fields.push_back(make_field("answer_addr", ip_buf,
                                                 static_cast<uint16_t>(offset + pos), 4));
            }
        }
    }

    (void)opcode;
    return true;
}

// ============================================================================
// DHCP  (RFC 2131)
// ============================================================================

static const char* dhcp_msg_type_name(uint8_t t) {
    switch (t) {
    case 1: return "DISCOVER";
    case 2: return "OFFER";
    case 3: return "REQUEST";
    case 4: return "DECLINE";
    case 5: return "ACK";
    case 6: return "NAK";
    case 7: return "RELEASE";
    case 8: return "INFORM";
    default: return "?";
    }
}

bool dissect_dhcp(const uint8_t* data, size_t len, uint16_t offset,
                  ParsedPacket& pkt, Node& node, DissectorContext& /*ctx*/)
{
    // DHCP fixed header: 236 bytes
    if (len < 236) { return false; }

    node.protocol = ProtoId::DHCP;
    pkt.top_proto = ProtoId::DHCP;

    uint8_t  op    = data[0];
    uint8_t  htype = data[1];
    uint8_t  hlen  = data[2];
    uint32_t xid;
    memcpy(&xid, data + 4, 4); xid = ntohl(xid);

    const uint8_t* ciaddr = data + 12;
    const uint8_t* yiaddr = data + 16;
    const uint8_t* siaddr = data + 20;
    const uint8_t* chaddr = data + 28;

    char xid_buf[12], ciaddr_buf[20], yiaddr_buf[20];
    std::snprintf(xid_buf,    sizeof(xid_buf),    "0x%08x", xid);
    std::snprintf(ciaddr_buf, sizeof(ciaddr_buf),  "%u.%u.%u.%u",
                  ciaddr[0], ciaddr[1], ciaddr[2], ciaddr[3]);
    std::snprintf(yiaddr_buf, sizeof(yiaddr_buf),  "%u.%u.%u.%u",
                  yiaddr[0], yiaddr[1], yiaddr[2], yiaddr[3]);

    char mac_buf[18];
    if (htype == 1 && hlen == 6) {
        std::snprintf(mac_buf, sizeof(mac_buf),
                      "%02x:%02x:%02x:%02x:%02x:%02x",
                      chaddr[0], chaddr[1], chaddr[2],
                      chaddr[3], chaddr[4], chaddr[5]);
    } else {
        std::snprintf(mac_buf, sizeof(mac_buf), "?");
    }

    node.fields.push_back(make_field("op",        op == 1 ? "BOOTREQUEST" : "BOOTREPLY",
                                     offset + 0, 1));
    node.fields.push_back(make_field("xid",       xid_buf,    offset + 4,  4));
    node.fields.push_back(make_field("ciaddr",    ciaddr_buf, offset + 12, 4));
    node.fields.push_back(make_field("yiaddr",    yiaddr_buf, offset + 16, 4));
    node.fields.push_back(make_field("chaddr",    mac_buf,    offset + 28, 6));
    (void)siaddr; (void)htype; (void)hlen;

    // Parse options (magic cookie at byte 236: 99.130.83.99)
    if (len < 240) { return true; }
    uint32_t magic;
    memcpy(&magic, data + 236, 4);
    if (ntohl(magic) != 0x63825363u) { return true; }

    size_t pos = 240;
    while (pos < len) {
        uint8_t opt = data[pos++];
        if (opt == 255) { break; }  // End option
        if (opt == 0)   { continue; } // Pad

        if (pos >= len) { break; }
        uint8_t olen = data[pos++];
        if (pos + olen > len) { break; }

        // Option 53 = DHCP Message Type
        if (opt == 53 && olen == 1) {
            node.fields.push_back(make_field("msg_type",
                                             dhcp_msg_type_name(data[pos]),
                                             static_cast<uint16_t>(offset + pos), 1));
        }
        // Option 1 = Subnet Mask
        else if (opt == 1 && olen == 4) {
            char mask_buf[20];
            std::snprintf(mask_buf, sizeof(mask_buf), "%u.%u.%u.%u",
                          data[pos], data[pos+1], data[pos+2], data[pos+3]);
            node.fields.push_back(make_field("subnet_mask", mask_buf,
                                             static_cast<uint16_t>(offset + pos), 4));
        }
        // Option 3 = Router
        else if (opt == 3 && olen >= 4) {
            char gw_buf[20];
            std::snprintf(gw_buf, sizeof(gw_buf), "%u.%u.%u.%u",
                          data[pos], data[pos+1], data[pos+2], data[pos+3]);
            node.fields.push_back(make_field("router", gw_buf,
                                             static_cast<uint16_t>(offset + pos), 4));
        }
        // Option 51 = IP Address Lease Time
        else if (opt == 51 && olen == 4) {
            uint32_t lease;
            memcpy(&lease, data + pos, 4); lease = ntohl(lease);
            char lt_buf[16];
            std::snprintf(lt_buf, sizeof(lt_buf), "%u s", lease);
            node.fields.push_back(make_field("lease_time", lt_buf,
                                             static_cast<uint16_t>(offset + pos), 4));
        }

        pos += olen;
    }

    return true;
}

// ============================================================================
// HTTP  (RFC 9112 / RFC 7230)
// ============================================================================

// Read a line (up to \r\n or \n) from the payload, advancing pos.
static std::string read_line(const uint8_t* data, size_t len, size_t& pos) {
    size_t start = pos;
    while (pos < len && data[pos] != '\n') { ++pos; }
    size_t end = pos;
    if (end > start && data[end - 1] == '\r') { --end; }
    if (pos < len) { ++pos; }  // consume \n
    return std::string(reinterpret_cast<const char*>(data + start), end - start);
}

bool dissect_http(const uint8_t* data, size_t len, uint16_t offset,
                  ParsedPacket& pkt, Node& node, DissectorContext& /*ctx*/)
{
    // Must start with a printable ASCII character
    if (len == 0 || !std::isprint(data[0])) { 
        pkt.top_proto = ProtoId::HTTP;
        return false; 
    }

    node.protocol = ProtoId::HTTP;
    pkt.top_proto = ProtoId::HTTP;

    size_t pos = 0;
    std::string first_line = read_line(data, len, pos);
    if (first_line.empty()) { return true; }

    node.fields.push_back(make_field("first_line", first_line, offset, 
                                     static_cast<uint16_t>(
                                         pos > 0xFFFF ? 0xFFFF : pos)));

    // Determine request vs response
    bool is_request  = (first_line.substr(0, 4) == "GET "  ||
                        first_line.substr(0, 5) == "POST " ||
                        first_line.substr(0, 4) == "PUT "  ||
                        first_line.substr(0, 7) == "DELETE " ||
                        first_line.substr(0, 5) == "HEAD " ||
                        first_line.substr(0, 8) == "OPTIONS " ||
                        first_line.substr(0, 6) == "PATCH ");
    bool is_response = (first_line.substr(0, 5) == "HTTP/");

    if (is_request) {
        // "METHOD /path HTTP/1.x"
        size_t sp1 = first_line.find(' ');
        if (sp1 != std::string::npos) {
            std::string method = first_line.substr(0, sp1);
            size_t sp2 = first_line.find(' ', sp1 + 1);
            std::string path = (sp2 != std::string::npos)
                ? first_line.substr(sp1 + 1, sp2 - sp1 - 1)
                : first_line.substr(sp1 + 1);
            node.fields.push_back(make_field("method", method, offset, 
                                             static_cast<uint16_t>(sp1)));
            node.fields.push_back(make_field("uri",    path,   offset,
                                             static_cast<uint16_t>(path.size())));
        }
    } else if (is_response) {
        // "HTTP/1.x NNN Reason"
        size_t sp1 = first_line.find(' ');
        if (sp1 != std::string::npos) {
            std::string version = first_line.substr(0, sp1);
            size_t sp2 = first_line.find(' ', sp1 + 1);
            std::string status_code = (sp2 != std::string::npos)
                ? first_line.substr(sp1 + 1, sp2 - sp1 - 1)
                : first_line.substr(sp1 + 1);
            std::string reason = (sp2 != std::string::npos)
                ? first_line.substr(sp2 + 1) : "";
            node.fields.push_back(make_field("version",     version,     offset, 8));
            node.fields.push_back(make_field("status_code", status_code, offset, 3));
            if (!reason.empty())
                node.fields.push_back(make_field("reason", reason, offset,
                                                 static_cast<uint16_t>(reason.size())));
        }
    }

    // Parse a handful of important headers
    int headers_parsed = 0;
    while (pos < len && headers_parsed < 16) {
        std::string line = read_line(data, len, pos);
        if (line.empty()) { break; }  // blank line = end of headers

        size_t colon = line.find(':');
        if (colon == std::string::npos) { break; }

        std::string hname = line.substr(0, colon);
        std::string hval  = line.substr(colon + 1);
        // Trim leading space from value
        size_t vs = hval.find_first_not_of(" \t");
        if (vs != std::string::npos) { hval = hval.substr(vs); }

        // Lower-case the header name for matching
        std::string lname = hname;
        std::transform(lname.begin(), lname.end(), lname.begin(),
                       [](unsigned char c){ return std::tolower(c); });

        if (lname == "host"           ||
            lname == "content-type"   ||
            lname == "content-length" ||
            lname == "user-agent"     ||
            lname == "location"       ||
            lname == "server"         ||
            lname == "connection"     ||
            lname == "authorization") {
            node.fields.push_back(make_field(hname, hval, 
                                             static_cast<uint16_t>(offset + pos),
                                             static_cast<uint16_t>(line.size())));
        }
        ++headers_parsed;
    }

    return true;
}

// ============================================================================
// TLS  (RFC 8446 / RFC 5246)
// ============================================================================

static const char* tls_content_type_name(uint8_t ct) {
    switch (ct) {
    case 20: return "ChangeCipherSpec";
    case 21: return "Alert";
    case 22: return "Handshake";
    case 23: return "ApplicationData";
    case 24: return "Heartbeat";
    default: return "Unknown";
    }
}

static const char* tls_handshake_type_name(uint8_t ht) {
    switch (ht) {
    case 1:  return "ClientHello";
    case 2:  return "ServerHello";
    case 4:  return "NewSessionTicket";
    case 8:  return "EncryptedExtensions";
    case 11: return "Certificate";
    case 12: return "ServerKeyExchange";
    case 13: return "CertificateRequest";
    case 14: return "ServerHelloDone";
    case 15: return "CertificateVerify";
    case 16: return "ClientKeyExchange";
    case 20: return "Finished";
    default: return "Unknown";
    }
}

bool dissect_tls(const uint8_t* data, size_t len, uint16_t offset,
                 ParsedPacket& pkt, Node& node, DissectorContext& /*ctx*/)
{
    // TLS record: content_type(1) + version(2) + length(2) = 5 bytes
    if (len < 5) {
        pkt.top_proto = (pkt.dst_port == 443 || pkt.src_port == 443)
                        ? ProtoId::HTTPS : ProtoId::TLS;
        return false;
    }

    uint8_t  content_type = data[0];
    uint8_t  ver_major    = data[1];
    uint8_t  ver_minor    = data[2];
    uint16_t record_len;
    memcpy(&record_len, data + 3, 2);
    record_len = ntohs(record_len);

    // Sanity check: TLS version bytes should be 3.x
    if (ver_major != 3) {
        pkt.top_proto = ProtoId::TLS;
        return false;
    }

    node.protocol = ProtoId::TLS;
    pkt.top_proto = (pkt.dst_port == 443 || pkt.src_port == 443)
                    ? ProtoId::HTTPS : ProtoId::TLS;

    char ver_buf[8], len_buf[8];
    std::snprintf(ver_buf, sizeof(ver_buf), "%u.%u", ver_major, ver_minor);
    std::snprintf(len_buf, sizeof(len_buf), "%u", record_len);

    node.fields.push_back(make_field("content_type", tls_content_type_name(content_type),
                                     offset + 0, 1));
    node.fields.push_back(make_field("version",      ver_buf, offset + 1, 2));
    node.fields.push_back(make_field("length",       len_buf, offset + 3, 2));

    // Decode handshake details for the first record
    if (content_type == 22 && len >= 6) {
        uint8_t hs_type = data[5];
        node.fields.push_back(make_field("handshake_type",
                                         tls_handshake_type_name(hs_type),
                                         offset + 5, 1));

        // ClientHello: try to extract SNI from extensions
        // Structure: hs_type(1) + length(3) + legacy_version(2) + random(32)
        //            + session_id_len(1) + ... 
        // Only attempt for ClientHello (type=1) with enough data
        if (hs_type == 1 && len >= 43) {
            size_t pos = 6 + 3 + 2 + 32;  // past hs header, version, random
            if (pos < len) {
                uint8_t sid_len = data[pos++];
                pos += sid_len;  // skip session id
            }
            if (pos + 2 <= len) {
                uint16_t cs_len;
                memcpy(&cs_len, data + pos, 2); cs_len = ntohs(cs_len);
                pos += 2 + cs_len;  // skip cipher suites
            }
            if (pos + 1 <= len) {
                uint8_t cm_len = data[pos++];
                pos += cm_len;  // skip compression methods
            }
            // Extensions length
            if (pos + 2 <= len) {
                uint16_t ext_total;
                memcpy(&ext_total, data + pos, 2); ext_total = ntohs(ext_total);
                pos += 2;
                size_t ext_end = pos + ext_total;

                while (pos + 4 <= len && pos < ext_end) {
                    uint16_t ext_type, ext_len;
                    memcpy(&ext_type, data + pos,     2); ext_type = ntohs(ext_type);
                    memcpy(&ext_len,  data + pos + 2, 2); ext_len  = ntohs(ext_len);
                    pos += 4;

                    // Extension 0 = SNI
                    if (ext_type == 0 && ext_len >= 5 && pos + ext_len <= len) {
                        // sni_list_len(2) + name_type(1) + name_len(2) + name
                        uint16_t name_len;
                        memcpy(&name_len, data + pos + 3, 2); name_len = ntohs(name_len);
                        if (pos + 5 + name_len <= len) {
                            std::string sni(reinterpret_cast<const char*>(data + pos + 5),
                                            name_len);
                            node.fields.push_back(make_field("sni", sni,
                                                             static_cast<uint16_t>(offset + pos + 5),
                                                             name_len));
                        }
                        break;
                    }
                    pos += ext_len;
                }
            }
        }
    }

    return true;
}

// ============================================================================
// SSH  (RFC 4253)
// ============================================================================

bool dissect_ssh(const uint8_t* data, size_t len, uint16_t offset,
                 ParsedPacket& pkt, Node& node, DissectorContext& /*ctx*/)
{
    node.protocol = ProtoId::SSH;
    pkt.top_proto = ProtoId::SSH;

    if (len == 0) { return true; }

    // The first packet sent on an SSH connection is a plaintext version string:
    // "SSH-2.0-<software>\r\n"
    if (len >= 4 && memcmp(data, "SSH-", 4) == 0) {
        // Find end of version string
        size_t end = 0;
        while (end < len && data[end] != '\n') { ++end; }
        std::string version(reinterpret_cast<const char*>(data), end);
        // Strip trailing \r if present
        if (!version.empty() && version.back() == '\r') { version.pop_back(); }
        node.fields.push_back(make_field("version_string", version, offset,
                                         static_cast<uint16_t>(end)));
        return true;
    }

    // Binary SSH packet: packet_length(4) + padding_length(1) + msg_type(1) + ...
    if (len < 6) { return true; }

    uint32_t pkt_len;
    memcpy(&pkt_len, data, 4); pkt_len = ntohl(pkt_len);
    uint8_t  pad_len  = data[4];
    uint8_t  msg_type = data[5];

    const char* msg_name = "Encrypted";
    // Only decode message types that appear before key exchange completes
    switch (msg_type) {
    case 1:  msg_name = "Disconnect";         break;
    case 2:  msg_name = "Ignore";             break;
    case 20: msg_name = "KeyExchangeInit";    break;
    case 21: msg_name = "NewKeys";            break;
    case 30: msg_name = "KeyExchangeDHInit";  break;
    case 31: msg_name = "KeyExchangeDHReply"; break;
    }

    char plen_buf[12], pad_buf[4];
    std::snprintf(plen_buf, sizeof(plen_buf), "%u", pkt_len);
    std::snprintf(pad_buf,  sizeof(pad_buf),  "%u", pad_len);

    node.fields.push_back(make_field("packet_length",  plen_buf, offset + 0, 4));
    node.fields.push_back(make_field("padding_length", pad_buf,  offset + 4, 1));
    node.fields.push_back(make_field("msg_type",       msg_name, offset + 5, 1));

    return true;
}

// ============================================================================
// FTP  (RFC 959)
// ============================================================================

bool dissect_ftp(const uint8_t* data, size_t len, uint16_t offset,
                 ParsedPacket& pkt, Node& node, DissectorContext& /*ctx*/)
{
    if (len == 0 || !std::isprint(data[0])) {
        pkt.top_proto = ProtoId::FTP;
        return false;
    }

    node.protocol = ProtoId::FTP;
    pkt.top_proto = ProtoId::FTP;

    // FTP is line-oriented text. Read the first line.
    size_t end = 0;
    while (end < len && data[end] != '\n') { ++end; }
    std::string line(reinterpret_cast<const char*>(data), end);
    if (!line.empty() && line.back() == '\r') { line.pop_back(); }

    node.fields.push_back(make_field("line", line, offset,
                                     static_cast<uint16_t>(end)));

    // If first 3 chars are digits it's a reply; otherwise it's a command.
    if (len >= 3 && std::isdigit(data[0]) &&
                    std::isdigit(data[1]) &&
                    std::isdigit(data[2])) {
        std::string code = line.substr(0, 3);
        std::string msg  = (line.size() > 4) ? line.substr(4) : "";
        node.fields.push_back(make_field("reply_code", code, offset, 3));
        if (!msg.empty())
            node.fields.push_back(make_field("message", msg, offset + 4,
                                             static_cast<uint16_t>(msg.size())));
    } else {
        // Command: first word up to space
        size_t sp = line.find(' ');
        std::string cmd  = (sp != std::string::npos) ? line.substr(0, sp) : line;
        std::string args = (sp != std::string::npos) ? line.substr(sp + 1) : "";
        node.fields.push_back(make_field("command", cmd, offset,
                                         static_cast<uint16_t>(cmd.size())));
        if (!args.empty())
            node.fields.push_back(make_field("argument", args,
                                             static_cast<uint16_t>(offset + sp + 1),
                                             static_cast<uint16_t>(args.size())));
    }

    return true;
}

// ============================================================================
// SMTP  (RFC 5321)
// ============================================================================

bool dissect_smtp(const uint8_t* data, size_t len, uint16_t offset,
                  ParsedPacket& pkt, Node& node, DissectorContext& /*ctx*/)
{
    if (len == 0 || !std::isprint(data[0])) {
        pkt.top_proto = ProtoId::SMTP;
        return false;
    }

    node.protocol = ProtoId::SMTP;
    pkt.top_proto = ProtoId::SMTP;

    size_t end = 0;
    while (end < len && data[end] != '\n') { ++end; }
    std::string line(reinterpret_cast<const char*>(data), end);
    if (!line.empty() && line.back() == '\r') { line.pop_back(); }

    node.fields.push_back(make_field("line", line, offset,
                                     static_cast<uint16_t>(end)));

    if (len >= 3 && std::isdigit(data[0]) &&
                    std::isdigit(data[1]) &&
                    std::isdigit(data[2])) {
        std::string code = line.substr(0, 3);
        std::string msg  = (line.size() > 4) ? line.substr(4) : "";

        const char* code_str = "?";
        int c = std::stoi(code);
        if      (c == 220) code_str = "Service Ready";
        else if (c == 221) code_str = "Closing";
        else if (c == 250) code_str = "OK";
        else if (c == 354) code_str = "Start mail input";
        else if (c == 421) code_str = "Service unavailable";
        else if (c == 550) code_str = "Mailbox unavailable";

        node.fields.push_back(make_field("reply_code",    code,     offset, 3));
        node.fields.push_back(make_field("reply_meaning", code_str, offset, 3));
        if (!msg.empty())
            node.fields.push_back(make_field("message", msg, offset + 4,
                                             static_cast<uint16_t>(msg.size())));
    } else {
        // Command
        size_t sp  = line.find(' ');
        std::string cmd  = (sp != std::string::npos) ? line.substr(0, sp) : line;
        std::string args = (sp != std::string::npos) ? line.substr(sp + 1) : "";

        // Upper-case for normalisation
        std::transform(cmd.begin(), cmd.end(), cmd.begin(),
                       [](unsigned char c){ return std::toupper(c); });

        node.fields.push_back(make_field("command", cmd, offset,
                                         static_cast<uint16_t>(cmd.size())));
        if (!args.empty())
            node.fields.push_back(make_field("argument", args,
                                             static_cast<uint16_t>(offset + sp + 1),
                                             static_cast<uint16_t>(args.size())));
    }

    return true;
}

// ============================================================================
// NTP  (RFC 5905)
// ============================================================================

static const char* ntp_mode_name(uint8_t m) {
    switch (m) {
    case 1: return "Symmetric active";
    case 2: return "Symmetric passive";
    case 3: return "Client";
    case 4: return "Server";
    case 5: return "Broadcast";
    case 6: return "NTP control";
    case 7: return "Private";
    default: return "Reserved";
    }
}

bool dissect_ntp(const uint8_t* data, size_t len, uint16_t offset,
                 ParsedPacket& pkt, Node& node, DissectorContext& /*ctx*/)
{
    // NTP fixed header: 48 bytes
    if (len < 48) { return false; }

    node.protocol = ProtoId::NTP;
    pkt.top_proto = ProtoId::NTP;

    uint8_t li_vn_mode = data[0];
    uint8_t leap        = (li_vn_mode >> 6) & 0x03;
    uint8_t version     = (li_vn_mode >> 3) & 0x07;
    uint8_t mode        =  li_vn_mode        & 0x07;
    uint8_t stratum     = data[1];
    int8_t  poll        = static_cast<int8_t>(data[2]);
    int8_t  precision   = static_cast<int8_t>(data[3]);

    char ver_buf[4], st_buf[4], poll_buf[8], prec_buf[8];
    std::snprintf(ver_buf,  sizeof(ver_buf),  "%u", version);
    std::snprintf(st_buf,   sizeof(st_buf),   "%u", stratum);
    std::snprintf(poll_buf, sizeof(poll_buf), "%d (%.3f s)",
                  poll, (poll >= 0) ? (1 << poll) : 1.0 / (1 << -poll));
    std::snprintf(prec_buf, sizeof(prec_buf), "%d", precision);

    const char* leap_str = "no warning";
    if      (leap == 1) leap_str = "+1 second";
    else if (leap == 2) leap_str = "-1 second";
    else if (leap == 3) leap_str = "alarm";

    node.fields.push_back(make_field("leap_indicator", leap_str,           offset + 0, 1));
    node.fields.push_back(make_field("version",        ver_buf,            offset + 0, 1));
    node.fields.push_back(make_field("mode",           ntp_mode_name(mode),offset + 0, 1));
    node.fields.push_back(make_field("stratum",        st_buf,             offset + 1, 1));
    node.fields.push_back(make_field("poll_interval",  poll_buf,           offset + 2, 1));
    node.fields.push_back(make_field("precision",      prec_buf,           offset + 3, 1));

    // Reference ID (bytes 12-15): for stratum 0/1 this is an ASCII code;
    // for stratum >= 2 it's the reference server IP.
    if (stratum <= 1) {
        char refid[5] = {0};
        memcpy(refid, data + 12, 4);
        // Blank out non-printable bytes
        for (int i = 0; i < 4; ++i) {
            if (!std::isprint((unsigned char)refid[i])) { refid[i] = '?'; }
        }
        node.fields.push_back(make_field("reference_id", refid, offset + 12, 4));
    } else {
        char refid_buf[20];
        std::snprintf(refid_buf, sizeof(refid_buf), "%u.%u.%u.%u",
                      data[12], data[13], data[14], data[15]);
        node.fields.push_back(make_field("reference_id", refid_buf, offset + 12, 4));
    }

    // Transmit timestamp (bytes 40-47): NTP epoch is 1900-01-01.
    // Convert the seconds part to Unix time (subtract 70 years = 2208988800).
    uint32_t tx_sec;
    memcpy(&tx_sec, data + 40, 4); tx_sec = ntohl(tx_sec);
    if (tx_sec > 2208988800u) {
        uint32_t unix_sec = tx_sec - 2208988800u;
        char ts_buf[32];
        std::snprintf(ts_buf, sizeof(ts_buf), "%u (unix)", unix_sec);
        node.fields.push_back(make_field("transmit_timestamp", ts_buf, offset + 40, 8));
    }

    return true;
}

}  // namespace pktlens