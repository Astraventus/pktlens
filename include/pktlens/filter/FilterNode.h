#ifndef PKTLENS_FILTERNODE_H
#define PKTLENS_FILTERNODE_H

#include "pktlens/model/ParsedPacket.h"
#include <memory>

namespace pktlens {
    
    struct FilterNode {
        virtual bool evaluate(const ParsedPacket& pkt) const = 0;
        virtual ~FilterNode() = default;

        FilterNode(const FilterNode&) = delete;
        FilterNode& operator=(const FilterNode&) = delete;
        FilterNode() = default; 
    };

    using FilterNodePtr = std::unique_ptr<FilterNode>;
}

#endif