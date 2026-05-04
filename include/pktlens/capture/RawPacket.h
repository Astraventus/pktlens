#ifndef PKTLENS_RAWPACKET_H
#define PKTLENS_RAWPACKET_H

#include <cstdint>

namespace pktlens {

    struct RawPacket
    {
        uint8_t* data;
        uint32_t caplen;
        uint32_t origlen;
        double timestamp;
    };
    
}

#endif