#include "pktlens/capture/PcapFileProvider.h"
#include "pktlens/dissectors/DissectorRegistry.h"
#include <cstdio>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: pktlens_test_reader <file.pcap>\n");
        return 1;
    }

    pktlens::PcapFileProvider provider(argv[1]);
    if (!provider.is_open()) {
        std::fprintf(stderr, "error: %s\n", provider.error_message().c_str());
        return 1;
    }

    pktlens::DissectorContext ctx;
    pktlens::RawPacket        raw;
    size_t                     count = 0;

    while (provider.next_packet(raw)) {
        pktlens::ParsedPacket pkt;
        pktlens::ProtocolTree tree;

        pktlens::dissect(raw, pkt, tree, ctx);
        ++count;

        if (count <= 5) {
            std::printf("pkt %zu: proto=%-4s  src=%08x:%u  dst=%08x:%u  "
                        "cap=%u orig=%u  flags=%02x\n",
                        count,
                        pktlens::proto_name(pkt.top_proto),
                        pkt.src_ip,   pkt.src_port,
                        pkt.dst_ip,   pkt.dst_port,
                        pkt.length_cap, pkt.length_orig,
                        pkt.tcp_flags);
        }
    }

    std::printf("total: %zu packets\n", count);
    return 0;
}