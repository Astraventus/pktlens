#include "pktlens/filter/FilterParser.h"
#include "pktlens/filter/FilterNodes.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <utility>

namespace pktlens {

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

enum class TokenType {
    // Protocol keywords
    Kw_tcp, Kw_udp, Kw_dns, Kw_http, Kw_https, Kw_tls,
    Kw_icmp, Kw_icmpv6, Kw_arp, Kw_ipv6,
    Kw_ssh, Kw_ftp, Kw_smtp, Kw_ntp, Kw_dhcp,
    Kw_vlan, Kw_mpls,
    // Address/port keywords
    Kw_ip, Kw_src, Kw_dst, Kw_port, Kw_len,
    // Logic keywords
    Kw_and, Kw_or, Kw_not,
    // Operators
    Op_gt, Op_lt, Op_eq,
    // Values
    Val_ipv4, Val_number,
    // Structure
    LParen, RParen,
    // Sentinels
    Eof, Unknown,
};

struct Token {
    TokenType   type;
    std::string text;
};

struct Tokenizer {
    const std::string& input;
    size_t             pos;

    explicit Tokenizer(const std::string& s) : input(s), pos(0) {}

    void skip_whitespace() {
        while (pos < input.size() && std::isspace((unsigned char)input[pos]))
            ++pos;
    }

    std::string read_word() {
        size_t start = pos;
        while (pos < input.size() &&
               (std::isalnum((unsigned char)input[pos]) || input[pos] == '.'))
            ++pos;
        return input.substr(start, pos - start);
    }

    Token next() {
        skip_whitespace();
        if (pos >= input.size()) { return {TokenType::Eof, ""}; }

        char c = input[pos];

        if (c == '>') { ++pos; return {TokenType::Op_gt, ">"}; }
        if (c == '<') { ++pos; return {TokenType::Op_lt, "<"}; }
        if (c == '=') { ++pos; return {TokenType::Op_eq, "="}; }
        if (c == '(') { ++pos; return {TokenType::LParen, "("}; }
        if (c == ')') { ++pos; return {TokenType::RParen, ")"}; }

        if (std::isalnum((unsigned char)c)) {
            std::string word = read_word();

            // Protocol keywords
            if (word == "tcp")    return {TokenType::Kw_tcp,    word};
            if (word == "udp")    return {TokenType::Kw_udp,    word};
            if (word == "dns")    return {TokenType::Kw_dns,    word};
            if (word == "http")   return {TokenType::Kw_http,   word};
            if (word == "https")  return {TokenType::Kw_https,  word};
            if (word == "tls")    return {TokenType::Kw_tls,    word};
            if (word == "icmp")   return {TokenType::Kw_icmp,   word};
            if (word == "icmpv6") return {TokenType::Kw_icmpv6, word};
            if (word == "arp")    return {TokenType::Kw_arp,    word};
            if (word == "ipv6")   return {TokenType::Kw_ipv6,   word};
            if (word == "ssh")    return {TokenType::Kw_ssh,    word};
            if (word == "ftp")    return {TokenType::Kw_ftp,    word};
            if (word == "smtp")   return {TokenType::Kw_smtp,   word};
            if (word == "ntp")    return {TokenType::Kw_ntp,    word};
            if (word == "dhcp")   return {TokenType::Kw_dhcp,   word};
            if (word == "vlan")   return {TokenType::Kw_vlan,   word};
            if (word == "mpls")   return {TokenType::Kw_mpls,   word};
            // Address/port keywords
            if (word == "ip")     return {TokenType::Kw_ip,     word};
            if (word == "src")    return {TokenType::Kw_src,    word};
            if (word == "dst")    return {TokenType::Kw_dst,    word};
            if (word == "port")   return {TokenType::Kw_port,   word};
            if (word == "len")    return {TokenType::Kw_len,    word};
            // Logic
            if (word == "and")    return {TokenType::Kw_and,    word};
            if (word == "or")     return {TokenType::Kw_or,     word};
            if (word == "not")    return {TokenType::Kw_not,    word};

            // IPv4 address (contains a dot)
            if (word.find('.') != std::string::npos)
                return {TokenType::Val_ipv4, word};

            // Pure number
            bool all_digits = true;
            for (char ch : word)
                if (!std::isdigit((unsigned char)ch)) { all_digits = false; break; }
            if (all_digits) return {TokenType::Val_number, word};

            return {TokenType::Unknown, word};
        }

        ++pos;
        return {TokenType::Unknown, std::string(1, c)};
    }

    std::vector<Token> tokenize() {
        std::vector<Token> tokens;
        while (true) {
            Token t = next();
            tokens.push_back(t);
            if (t.type == TokenType::Eof) { break; }
        }
        return tokens;
    }
};

// ---------------------------------------------------------------------------
// Parser — recursive descent
// ---------------------------------------------------------------------------

struct Parser {
    const std::vector<Token>& tokens;
    size_t                    pos;
    std::string               error;

    explicit Parser(const std::vector<Token>& t) : tokens(t), pos(0) {}

    const Token& peek() const { return tokens[pos]; }

    const Token& consume() { return tokens[pos++]; }

    bool at(TokenType t) const { return peek().type == t; }

    FilterNodePtr parse_expr() {
        FilterNodePtr left = parse_term();
        if (!left) { return nullptr; }

        while (at(TokenType::Kw_and) || at(TokenType::Kw_or)) {
            TokenType op = consume().type;
            FilterNodePtr right = parse_term();
            if (!right) { return nullptr; }
            if (op == TokenType::Kw_and)
                left = FilterNodePtr(new AndNode(std::move(left), std::move(right)));
            else
                left = FilterNodePtr(new OrNode(std::move(left), std::move(right)));
        }
        return left;
    }

    FilterNodePtr parse_term() {
        if (at(TokenType::Kw_not)) {
            consume();
            FilterNodePtr child = parse_term();
            if (!child) { return nullptr; }
            return FilterNodePtr(new NotNode(std::move(child)));
        }
        if (at(TokenType::LParen)) {
            consume();
            FilterNodePtr inner = parse_expr();
            if (!inner) { return nullptr; }
            if (!at(TokenType::RParen)) {
                error = "expected ')'";
                return nullptr;
            }
            consume();
            return inner;
        }
        return parse_atom();
    }

    // Map a protocol keyword token to a ProtoId
    FilterNodePtr proto_node(ProtoId id) {
        return FilterNodePtr(new ProtoNode(id));
    }

    FilterNodePtr parse_atom() {
        const Token& t = peek();

        switch (t.type) {
        // Protocol atoms
        case TokenType::Kw_tcp:    consume(); return proto_node(ProtoId::TCP);
        case TokenType::Kw_udp:    consume(); return proto_node(ProtoId::UDP);
        case TokenType::Kw_dns:    consume(); return proto_node(ProtoId::DNS);
        case TokenType::Kw_http:   consume(); return proto_node(ProtoId::HTTP);
        case TokenType::Kw_https:  consume(); return proto_node(ProtoId::HTTPS);
        case TokenType::Kw_tls:    consume(); return proto_node(ProtoId::TLS);
        case TokenType::Kw_icmp:   consume(); return proto_node(ProtoId::ICMP);
        case TokenType::Kw_icmpv6: consume(); return proto_node(ProtoId::ICMPv6);
        case TokenType::Kw_arp:    consume(); return proto_node(ProtoId::ARP);
        case TokenType::Kw_ipv6:   consume(); return proto_node(ProtoId::IPv6);
        case TokenType::Kw_ssh:    consume(); return proto_node(ProtoId::SSH);
        case TokenType::Kw_ftp:    consume(); return proto_node(ProtoId::FTP);
        case TokenType::Kw_smtp:   consume(); return proto_node(ProtoId::SMTP);
        case TokenType::Kw_ntp:    consume(); return proto_node(ProtoId::NTP);
        case TokenType::Kw_dhcp:   consume(); return proto_node(ProtoId::DHCP);
        case TokenType::Kw_vlan:   consume(); return proto_node(ProtoId::VLAN);
        case TokenType::Kw_mpls:   consume(); return proto_node(ProtoId::MPLS);

        // ip <addr>
        case TokenType::Kw_ip: {
            consume();
            if (!at(TokenType::Val_ipv4)) {
                error = "expected IPv4 address after 'ip'";
                return nullptr;
            }
            return parse_ip_addr(FilterDir::Any);
        }

        // src <addr>  or  src port <n>
        case TokenType::Kw_src: {
            consume();
            if (at(TokenType::Kw_port)) {
                consume();
                return parse_port(FilterDir::Src);
            }
            return parse_ip_addr(FilterDir::Src);
        }

        // dst <addr>  or  dst port <n>
        case TokenType::Kw_dst: {
            consume();
            if (at(TokenType::Kw_port)) {
                consume();
                return parse_port(FilterDir::Dst);
            }
            return parse_ip_addr(FilterDir::Dst);
        }

        // port <n>
        case TokenType::Kw_port: {
            consume();
            return parse_port(FilterDir::Any);
        }

        // len > <n> | len < <n> | len = <n>
        case TokenType::Kw_len: {
            consume();
            LenOp op;
            if      (at(TokenType::Op_gt)) { consume(); op = LenOp::Gt; }
            else if (at(TokenType::Op_lt)) { consume(); op = LenOp::Lt; }
            else if (at(TokenType::Op_eq)) { consume(); op = LenOp::Eq; }
            else {
                error = "expected '>', '<', or '=' after 'len'";
                return nullptr;
            }
            if (!at(TokenType::Val_number)) {
                error = "expected number after len operator";
                return nullptr;
            }
            uint32_t val = static_cast<uint32_t>(
                std::stoul(consume().text));
            return FilterNodePtr(new LenNode(val, op));
        }

        default:
            error = "unexpected token '" + t.text + "'";
            return nullptr;
        }
    }

    FilterNodePtr parse_ip_addr(FilterDir dir) {
        const std::string& text = peek().text;
        struct in_addr addr;
        if (inet_pton(AF_INET, text.c_str(), &addr) != 1) {
            error = "invalid IPv4 address '" + text + "'";
            return nullptr;
        }
        consume();
        return FilterNodePtr(new IpNode(addr.s_addr, dir));
    }

    FilterNodePtr parse_port(FilterDir dir) {
        if (!at(TokenType::Val_number)) {
            error = "expected port number";
            return nullptr;
        }
        uint16_t port = static_cast<uint16_t>(
            std::stoul(consume().text));
        return FilterNodePtr(new PortNode(port, dir));
    }
};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

ParseResult parse_filter(const std::string& input) {
    ParseResult result;

    Tokenizer tokenizer(input);
    std::vector<Token> tokens = tokenizer.tokenize();

    Parser parser(tokens);
    FilterNodePtr node = parser.parse_expr();

    if (!node || !parser.error.empty()) {
        result.error = parser.error.empty()
                       ? "parse error near end of input"
                       : parser.error;
        return result;
    }

    if (!parser.at(TokenType::Eof)) {
        result.error = "unexpected token '" + parser.peek().text
                       + "' after expression";
        return result;
    }

    result.node = std::move(node);
    return result;
}

}  // namespace pktlens