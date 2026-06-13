#ifndef PKTLENS_FILTERNODES_H
#define PKTLENS_FILTERNODES_H

#include "FilterNode.h"
#include "pktlens/model/ProtoId.h"
#include <cstdint>

namespace pktlens {

    // --- Boolean combinators ---

    struct AndNode : FilterNode {
        FilterNodePtr left, right;
        AndNode(FilterNodePtr l, FilterNodePtr r)
            : left(std::move(l)), right(std::move(r)) {}
        bool evaluate(const ParsedPacket& pkt) const override {
            return left->evaluate(pkt) && right->evaluate(pkt);
        }
    };

    struct OrNode : FilterNode {
        FilterNodePtr left, right;
        OrNode(FilterNodePtr l, FilterNodePtr r)
            : left(std::move(l)), right(std::move(r)) {}
        bool evaluate(const ParsedPacket& pkt) const override {
            return left->evaluate(pkt) || right->evaluate(pkt);
        }
    };

    struct NotNode : FilterNode {
        FilterNodePtr child;
        explicit NotNode(FilterNodePtr c) : child(std::move(c)) {}
        bool evaluate(const ParsedPacket& pkt) const override {
            return !child->evaluate(pkt);
        }
    };

    // --- Protocol match ---
    // Matches by protocol family so that e.g. `tcp` also matches HTTP/HTTPS/TLS/SSH
    // (all of which ride on TCP), and `udp` matches DNS/DHCP/NTP.
    struct ProtoNode : FilterNode {
        ProtoId proto;
        explicit ProtoNode(ProtoId p) : proto(p) {}

        bool evaluate(const ParsedPacket& pkt) const override {
            ProtoId top = pkt.top_proto;

            // Exact match always wins
            if (top == proto) { return true; }

            // Family expansions
            switch (proto) {
            case ProtoId::TCP:
                // Any application protocol that runs over TCP
                return top == ProtoId::HTTP  ||
                       top == ProtoId::HTTPS ||
                       top == ProtoId::TLS   ||
                       top == ProtoId::SSH   ||
                       top == ProtoId::FTP   ||
                       top == ProtoId::SMTP;
            case ProtoId::UDP:
                return top == ProtoId::DNS  ||
                       top == ProtoId::DHCP ||
                       top == ProtoId::NTP;
            case ProtoId::IPv4:
                // Any packet whose network layer is IPv4
                return top == ProtoId::TCP   ||
                       top == ProtoId::UDP   ||
                       top == ProtoId::ICMP  ||
                       top == ProtoId::HTTP  ||
                       top == ProtoId::HTTPS ||
                       top == ProtoId::TLS   ||
                       top == ProtoId::SSH   ||
                       top == ProtoId::FTP   ||
                       top == ProtoId::SMTP  ||
                       top == ProtoId::DNS   ||
                       top == ProtoId::DHCP  ||
                       top == ProtoId::NTP;
            case ProtoId::IPv6:
                return top == ProtoId::ICMPv6;
            default:
                return false;
            }
        }
    };

    // Direction for IP and port filters
    enum class FilterDir { Any, Src, Dst };

    struct IpNode : FilterNode {
        uint32_t addr;   // network byte order
        FilterDir dir;
        IpNode(uint32_t a, FilterDir d) : addr(a), dir(d) {}

        bool evaluate(const ParsedPacket& pkt) const override {
            switch (dir) {
            case FilterDir::Any: return pkt.src_ip == addr || pkt.dst_ip == addr;
            case FilterDir::Src: return pkt.src_ip == addr;
            case FilterDir::Dst: return pkt.dst_ip == addr;
            }
            return false;
        }
    };

    struct PortNode : FilterNode {
        uint16_t port;
        FilterDir dir;
        PortNode(uint16_t p, FilterDir d) : port(p), dir(d) {}

        bool evaluate(const ParsedPacket& pkt) const override {
            switch (dir) {
            case FilterDir::Any: return pkt.src_port == port || pkt.dst_port == port;
            case FilterDir::Src: return pkt.src_port == port;
            case FilterDir::Dst: return pkt.dst_port == port;
            }
            return false;
        }
    };

    enum class LenOp { Gt, Lt, Eq };

    struct LenNode : FilterNode {
        uint32_t value;
        LenOp op;
        LenNode(uint32_t v, LenOp o) : value(v), op(o) {}

        bool evaluate(const ParsedPacket& pkt) const override {
            switch (op) {
            case LenOp::Gt: return pkt.length_orig > value;
            case LenOp::Lt: return pkt.length_orig < value;
            case LenOp::Eq: return pkt.length_orig == value;
            }
            return false;
        }
    };

}  // namespace pktlens

#endif  // PKTLENS_FILTERNODES_H