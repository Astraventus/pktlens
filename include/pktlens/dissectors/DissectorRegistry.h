#ifndef PKTLENS_DISSECTORREGISTRY_H
#define PKTLENS_DISSECTORREGISTRY_H

#include "./DissectorContext.h"
#include "../capture/RawPacket.h"
#include "../model/ParsedPacket.h"
#include "../model/ProtocolTree.h"
#include <cstdint>
#include <string.h>

namespace pktlens {

    // A dissector function takes:
    //   data     — pointer to start of this layer's header (not start of packet)
    //   len      — bytes available from data onward
    //   offset   — byte offset of data from start of raw packet (for Field::offset)
    //   pkt      — flat cache to fill
    //   node     — tree node for this layer to fill
    //   ctx      — shared session context
    //
    // Returns true if dissection succeeded (even partially).
    // Returns false only on hard failure (truncated before minimum header).
    typedef bool (*DissectorFn)(const uint8_t* data, 
                                size_t len,
                                uint16_t offset,
                                ParsedPacket& pkt,
                                Node& node,
                                DissectorContext& ctx);
    
    // Entry point: dissect a full raw packet into pkt + tree.
    void dissect(const RawPacket& raw,
                ParsedPacket& pkt,
                ProtocolTree& tree,
                DissectorContext& ctx);

}

#endif