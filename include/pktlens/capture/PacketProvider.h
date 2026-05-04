#ifndef PKTLENS_PACKETPROVIDER_H
#define PKTLENS_PACKETPROVIDER_H

#include "RawPacket.h"

namespace pktlens {

    class PacketProvider {
        public:
        // Returns true and fills 'out' if packet was aviable
        // Returns false at EOF or error
        virtual bool next_packet(RawPacket& out) = 0;

        virtual ~PacketProvider() = default;
    };
}

#endif