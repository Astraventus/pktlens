#include "pktlens/capture/PcapFileProvider.h"
#include "pktlens/model/PacketStore.h"
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
    pktlens::PacketStore      store;

    size_t n = store.load(provider, ctx);
    std::printf("loaded: %zu packets\n", n);

    // Print first 5 in default (time) order
    std::printf("\n--- default order (time asc) ---\n");
    size_t limit = std::min(n, size_t(6));
    for (size_t i = 0; i < limit; ++i) {
        const pktlens::ParsedPacket& p = store.packet_at(i);
        std::printf("  [%zu] proto=%-4s  ts=%.6f  len=%u\n",
                    i,
                    pktlens::proto_name(p.top_proto),
                    p.timestamp,
                    p.length_orig);
    }

    // Sort by size descending, print top 5 largest
    store.sort(pktlens::SortField::Size, pktlens::SortDirection::Descending);
    std::printf("\n--- top 5 by size (desc) ---\n");
    for (size_t i = 0; i < limit; ++i) {
        const pktlens::ParsedPacket& p = store.packet_at(i);
        std::printf("  [%zu] proto=%-4s  len=%u\n",
                    i,
                    pktlens::proto_name(p.top_proto),
                    p.length_orig);
    }

    // Filter to TCP only, print count
    store.apply_filter([](const pktlens::ParsedPacket& p) {
        return p.top_proto == pktlens::ProtoId::TCP;
    });
    std::printf("\n--- filter: TCP only ---\n");
    std::printf("  %zu packets match\n", store.view_count());

    return 0;
}