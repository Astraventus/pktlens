#include "pktlens/filter/FilterParser.h"
#include "pktlens/filter/FilterNodes.h"
#include <arpa/inet.h>   // inet_pton
#include <netinet/in.h>
#include <cctype>        // isspace, isdigit, isalpha
#include <stdlib.h>       // strtoul
#include <cstring>       // strcmp
#include <vector>
#include <utility>

namespace pktlens {

    // -----------------------------------------------------------------------
    // Tokenizer
    // -----------------------------------------------------------------------

    enum class TokenType {
        // Keywords
        Kw_tcp, Kw_udp, Kw_dns, Kw_http, Kw_icmp, Kw_arp,
        Kw_ip, Kw_src, Kw_dst, Kw_port, Kw_len,
        Kw_and, Kw_or, Kw_not,
        // Operators
        Op_gt,    // >
        Op_lt,    // 
        Op_eq,    // =
        // Values
        Val_ipv4,   // e.g. 192.168.1.5
        Val_number, // e.g. 80, 512
        // Structure
        LParen, RParen,
        // Sentinels
        Eof,
        Unknown,
    };

    struct Token {
        TokenType   type;
        std::string text;     // original text — used for Val_ipv4, Val_number
    };

    // Tokenizer state — walks the input string
    struct Tokenizer {
        const std::string& input;
        size_t             pos;

        explicit Tokenizer(const std::string& s) : input(s), pos(0) {}

        void skip_whitespace() {
            while (pos < input.size() && std::isspace((unsigned char)input[pos])) {
                ++pos;
            }
        }

        // Read an alphanumeric word (keyword or IP or partial number)
        std::string read_word() {
            size_t start = pos;
            // IPv4 addresses contain dots; keywords and numbers don't
            while (pos < input.size() &&
                (std::isalnum((unsigned char)input[pos]) || input[pos] == '.')) {
                ++pos;
            }
            return input.substr(start, pos - start);
        }

        Token next() {
            skip_whitespace();

            if (pos >= input.size()) {
                return {TokenType::Eof, ""};
            }

            char c = input[pos];

            // Single-character operators
            if (c == '>') { ++pos; return {TokenType::Op_gt, ">"}; }
            if (c == '<') { ++pos; return {TokenType::Op_lt, "<"}; }
            if (c == '=') { ++pos; return {TokenType::Op_eq, "="}; }
            if (c == '(') { ++pos; return {TokenType::LParen, "("}; }
            if (c == ')') { ++pos; return {TokenType::RParen, ")"}; }

            // Words: keywords, IP addresses, numbers
            if (std::isalnum((unsigned char)c)) {
                std::string word = read_word();

                // Keywords (case-insensitive compare via tolower would be cleaner,
                // but strcmp is explicit and we control the input — fine for v1)
                if (word == "tcp")  return {TokenType::Kw_tcp,  word};
                if (word == "udp")  return {TokenType::Kw_udp,  word};
                if (word == "dns")  return {TokenType::Kw_dns,  word};
                if (word == "http") return {TokenType::Kw_http, word};
                if (word == "icmp") return {TokenType::Kw_icmp, word};
                if (word == "arp")  return {TokenType::Kw_arp,  word};
                if (word == "ip")   return {TokenType::Kw_ip,   word};
                if (word == "src")  return {TokenType::Kw_src,  word};
                if (word == "dst")  return {TokenType::Kw_dst,  word};
                if (word == "port") return {TokenType::Kw_port, word};
                if (word == "len")  return {TokenType::Kw_len,  word};
                if (word == "and")  return {TokenType::Kw_and,  word};
                if (word == "or")   return {TokenType::Kw_or,   word};
                if (word == "not")  return {TokenType::Kw_not,  word};

                // IPv4: contains a dot
                if (word.find('.') != std::string::npos) {
                    return {TokenType::Val_ipv4, word};
                }

                // Pure number
                bool all_digits = true;
                for (char ch : word) {
                    if (!std::isdigit((unsigned char)ch)) {
                        all_digits = false;
                        break;
                    }
                }
                if (all_digits) {
                    return {TokenType::Val_number, word};
                }

                // Unknown identifier
                return {TokenType::Unknown, word};
            }

            // Unrecognized character
            ++pos;
            return {TokenType::Unknown, std::string(1, c)};
        }

        // Tokenize the entire input into a flat vector
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

    // -----------------------------------------------------------------------
    // Parser — recursive descent
    // -----------------------------------------------------------------------
    //
    // Grammar:
    //   expr := term (('and' | 'or') term)*
    //   term := 'not' term | '(' expr ')' | atom
    //   atom := proto | ip_filter | port_filter | len_filter
    //
    // Each function returns FilterNodePtr (non-null on success) or
    // sets error_ and returns nullptr.

    struct Parser {
        const std::vector<Token>& tokens;
        size_t                    pos;
        std::string               error;

        explicit Parser(const std::vector<Token>& t) : tokens(t), pos(0) {}

        // --- Token stream helpers ---

        const Token& peek() const {
            return tokens[pos];  // Eof is always the last token
        }

        Token consume() {
            Token t = tokens[pos];
            if (t.type != TokenType::Eof) { ++pos; }
            return t;
        }

        bool at_end() const {
            return tokens[pos].type == TokenType::Eof;
        }

        // --- IP address parsing ---

        // Parse "192.168.1.5" into a uint32_t (network byte order).
        // Returns false and sets error on invalid address.
        bool parse_ipv4(const std::string& text, uint32_t& out) {
            struct in_addr addr;
            if (inet_pton(AF_INET, text.c_str(), &addr) != 1) {
                error = "invalid IPv4 address: " + text;
                return false;
            }
            out = addr.s_addr;  // already in network byte order
            return true;
        }

        // --- Number parsing ---

        bool parse_number(const std::string& text, uint32_t& out) {
            char* end = nullptr;
            unsigned long v = strtoul(text.c_str(), &end, 10);
            if (end == text.c_str() || *end != '\0') {
                error = "invalid number: " + text;
                return false;
            }
            out = static_cast<uint32_t>(v);
            return true;
        }

        // --- Grammar rules ---

        // atom := proto_keyword
        //       | ('ip' | 'src' | 'dst') ipv4
        //       | 'port' number
        //       | 'len' ('>' | '<' | '=') number
        FilterNodePtr parse_atom() {
            const Token& t = peek();

            // Protocol keywords
            switch (t.type) {
                case TokenType::Kw_tcp:  consume(); return FilterNodePtr(new ProtoNode(ProtoId::TCP));
                case TokenType::Kw_udp:  consume(); return FilterNodePtr(new ProtoNode(ProtoId::UDP));
                case TokenType::Kw_dns:  consume(); return FilterNodePtr(new ProtoNode(ProtoId::DNS));
                case TokenType::Kw_http: consume(); return FilterNodePtr(new ProtoNode(ProtoId::HTTP));
                case TokenType::Kw_icmp: consume(); return FilterNodePtr(new ProtoNode(ProtoId::ICMP));
                case TokenType::Kw_arp:  consume(); return FilterNodePtr(new ProtoNode(ProtoId::ARP));
                default: break;
            }

            // ip / src / dst <ipv4>
            if (t.type == TokenType::Kw_ip  ||
                t.type == TokenType::Kw_src ||
                t.type == TokenType::Kw_dst)
            {
                FilterDir dir = FilterDir::Any;
                if (t.type == TokenType::Kw_src) { dir = FilterDir::Src; }
                if (t.type == TokenType::Kw_dst) { dir = FilterDir::Dst; }
                consume();  // eat 'ip'/'src'/'dst'

                if (peek().type != TokenType::Val_ipv4) {
                    error = "expected IPv4 address after '" + t.text + "'";
                    return nullptr;
                }
                std::string addr_text = consume().text;
                uint32_t addr = 0;
                if (!parse_ipv4(addr_text, addr)) { return nullptr; }
                return FilterNodePtr(new IpNode(addr, dir));
            }

            // port <number>
            if (t.type == TokenType::Kw_port) {
                consume();
                if (peek().type != TokenType::Val_number) {
                    error = "expected port number after 'port'";
                    return nullptr;
                }
                uint32_t port_val = 0;
                if (!parse_number(consume().text, port_val)) { return nullptr; }
                return FilterNodePtr(new PortNode(static_cast<uint16_t>(port_val),
                                                FilterDir::Any));
            }

            // len > / < / = <number>
            if (t.type == TokenType::Kw_len) {
                consume();
                TokenType op_type = peek().type;
                if (op_type != TokenType::Op_gt &&
                    op_type != TokenType::Op_lt &&
                    op_type != TokenType::Op_eq)
                {
                    error = "expected '>', '<', or '=' after 'len'";
                    return nullptr;
                }
                consume();  // eat operator

                if (peek().type != TokenType::Val_number) {
                    error = "expected number after 'len' operator";
                    return nullptr;
                }
                uint32_t len_val = 0;
                if (!parse_number(consume().text, len_val)) { return nullptr; }

                LenOp op = LenOp::Eq;
                if (op_type == TokenType::Op_gt) { op = LenOp::Gt; }
                if (op_type == TokenType::Op_lt) { op = LenOp::Lt; }
                return FilterNodePtr(new LenNode(len_val, op));
            }

            error = "unexpected token: '" + t.text + "'";
            return nullptr;
        }

        // term := 'not' term | '(' expr ')' | atom
        FilterNodePtr parse_term() {
            // 'not' term
            if (peek().type == TokenType::Kw_not) {
                consume();
                FilterNodePtr child = parse_term();
                if (!child) { return nullptr; }
                return FilterNodePtr(new NotNode(std::move(child)));
            }

            // '(' expr ')'
            if (peek().type == TokenType::LParen) {
                consume();  // eat '('
                FilterNodePtr inner = parse_expr();
                if (!inner) { return nullptr; }
                if (peek().type != TokenType::RParen) {
                    error = "expected ')' to close '('";
                    return nullptr;
                }
                consume();  // eat ')'
                return inner;
            }

            return parse_atom();
        }

        // expr := term (('and' | 'or') term)*
        FilterNodePtr parse_expr() {
            FilterNodePtr left = parse_term();
            if (!left) { return nullptr; }

            while (peek().type == TokenType::Kw_and ||
                peek().type == TokenType::Kw_or)
            {
                TokenType op = peek().type;
                consume();  // eat 'and'/'or'

                FilterNodePtr right = parse_term();
                if (!right) { return nullptr; }

                if (op == TokenType::Kw_and) {
                    left = FilterNodePtr(new AndNode(std::move(left), std::move(right)));
                } else {
                    left = FilterNodePtr(new OrNode(std::move(left), std::move(right)));
                }
            }

            return left;
        }

        FilterNodePtr parse() {
            if (tokens.empty() || tokens[0].type == TokenType::Eof) {
                error = "empty filter expression";
                return nullptr;
            }

            FilterNodePtr root = parse_expr();
            if (!root) { return nullptr; }

            // If there are unconsumed tokens, the expression was malformed
            if (!at_end()) {
                error = "unexpected token after expression: '" + peek().text + "'";
                return nullptr;
            }

            return root;
        }
    };

    // -----------------------------------------------------------------------
    // Public entry point
    // -----------------------------------------------------------------------

    ParseResult parse_filter(const std::string& input) {
        ParseResult result;

        if (input.empty()) {
            result.error = "empty filter expression";
            return result;
        }

        Tokenizer tokenizer(input);
        std::vector<Token> tokens = tokenizer.tokenize();

        Parser parser(tokens);
        result.node = parser.parse();

        if (!result.node) {
            result.error = parser.error;
        }

        return result;
    }

}