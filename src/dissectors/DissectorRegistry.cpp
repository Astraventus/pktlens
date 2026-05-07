#include "pktlens/dissectors/DissectorRegistry.h"
#include "pktlens/dissectors//EthernetDissector.h"

namespace pktlens {

void dissect(const RawPacket& raw,
             ParsedPacket& pkt,
             ProtocolTree& tree,
             DissectorContext& ctx)
{
    // Zero-initialize the flat cache before filling it
    pkt = ParsedPacket{};
    pkt.timestamp   = raw.timestamp;
    pkt.length_orig = raw.origlen;
    pkt.length_cap  = raw.caplen;
    pkt.top_proto   = ProtoId::Unknown;

    // All pcap files captured on Ethernet start here.
    // In v2, the provider will tell us the link type (pcap_datalink).
    // But for now we always assume Ethernet.
    dissect_ethernet(raw.data, raw.caplen, 0, pkt, tree.root, ctx);
}

}