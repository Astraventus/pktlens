#ifndef PKTLENS_FILTERNODES_H
#define PKTLENS_FILTERNODES_H

#include "FilterNode.h"
#include "pktlens/model/ProtoId.h"
#include <cstdint>

namespace pktlens {

    // --- Boolean combinators ---

    struct AndNode : FilterNode {
        FilterNodePtr left;
        FilterNodePtr right;

        AndNode(FilterNodePtr l, FilterNodePtr r)
            : left(std::move(l)), right(std::move(r)) {}

        bool evaluate(const ParsedPacket& pkt) const override {
            // Short-circuit: don't evaluate right if left is false
            return left->evaluate(pkt) && right->evaluate(pkt);
        }
    };

    struct OrNode : FilterNode {
        FilterNodePtr left;
        FilterNodePtr right;

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

    // --- Leaf nodes ---

    // Matches packets whose top_proto == proto.
    // E.g. ProtoNode(TCP) matches TCP and HTTP (HTTP is TCP underneath),
    // but only if top_proto is exactly TCP or HTTP.
    // For v1: exact match on top_proto only.
    struct ProtoNode : FilterNode {
        ProtoId proto;

        explicit ProtoNode(ProtoId p) : proto(p) {}

        bool evaluate(const ParsedPacket& pkt) const override {
            return pkt.top_proto == proto;
        }
    };

    // Direction for IP and port filters
    enum class FilterDir { Any, Src, Dst };

    // Matches packets where src and/or dst IP equals addr (network byte order)
    struct IpNode : FilterNode {
        uint32_t addr;  // network byte order
        FilterDir dir;

        IpNode(uint32_t a, FilterDir d) : addr(a), dir(d) {}

        bool evaluate(const ParsedPacket& pkt) const override {
            switch (dir) {
                case FilterDir::Any:
                    return pkt.src_ip == addr || pkt.dst_ip == addr;
                case FilterDir::Src:
                    return pkt.src_ip == addr;
                case FilterDir::Dst:
                    return pkt.dst_ip == addr;
            }
            return false;
        }
    };

    // Matches packets where src and/or dst port equals port
    struct PortNode : FilterNode {
        uint16_t port;
        FilterDir dir;

        PortNode(uint16_t p, FilterDir d) : port(p), dir(d) {}

        bool evaluate(const ParsedPacket& pkt) const override {
            switch (dir) {
                case FilterDir::Any:
                    return pkt.src_port == port || pkt.dst_port == port;
                case FilterDir::Src:
                    return pkt.src_port == port;
                case FilterDir::Dst:
                    return pkt.dst_port == port;
            }
            return false;
        }
    };

    // Matches packets by wire length with comparison operator
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

}

#endif