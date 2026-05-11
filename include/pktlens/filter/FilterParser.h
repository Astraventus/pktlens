#ifndef PKTLENS_FILTERPARSER_H
#define PKTLENS_FILTERPARSER_H

#include "FilterNode.h"
#include <string>

namespace pktlens {

    // Result of a parse attempt.
    // On success: node is non-null, error is empty.
    // On failure: node is null, error describes the problem.
    // No exceptions. Caller checks node == nullptr.
    struct ParseResult {
        FilterNodePtr node;
        std::string error;

        bool ok() const { return node != nullptr; }
    };

    // Parse a filter expression string into an AST.
    // Returns a ParseResult — check .ok() before using .node.
    ParseResult parse_filter(const std::string& input);

}

#endif