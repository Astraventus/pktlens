#include "pktlens/capture/PcapFileProvider.h"
#include "pktlens/session/SessionModel.h"
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

    pktlens::SessionModel model;
    if (!model.load(provider)) {
        std::fprintf(stderr, "load error: %s\n", model.error_message().c_str());
        return 1;
    }

    std::printf("loaded %zu packets\n\n", model.total_count());

    // Print first 5 packets
    size_t limit = std::min(model.filtered_count(), size_t(5));
    for (size_t i = 0; i < limit; ++i) {
        const pktlens::ParsedPacket& p = model.packet_at(i);
        std::printf("  [%zu] %-4s  ts=%.6f  len=%u\n",
                    i, pktlens::proto_name(p.top_proto),
                    p.timestamp, p.length_orig);
    }

    // Select packet 0, inspect its tree
    model.select(0);
    const pktlens::ProtocolTree& tree = model.selected_tree();
    std::printf("\nprotocol tree for packet 0:\n");
    // Walk root fields
    for (const auto& field : tree.root.fields) {
        std::printf("  ETH  %-12s = %s\n",
                    field.name.c_str(), field.value.c_str());
    }
    // Walk one level of children
    for (const auto& child : tree.root.children) {
        for (const auto& field : child.fields) {
            std::printf("  %-4s %-12s = %s\n",
                        pktlens::proto_name(child.protocol),
                        field.name.c_str(), field.value.c_str());
        }
    }

    // Filter
    if (model.apply_filter("tcp")) {
        std::printf("\nafter filter 'tcp': %zu packets\n",
                    model.filtered_count());
    }

    // Bad filter — should not crash or clear current filter
    bool ok = model.apply_filter("tcp and");
    std::printf("bad filter result: %s — error: %s\n",
                ok ? "ok" : "failed",
                model.filter_error().c_str());
    std::printf("filter still active: %s (%zu packets)\n",
                model.filter_expression().c_str(),
                model.filtered_count());

    // Sort cycle
    pktlens::SortField f = model.cycle_sort_field();
    std::printf("\nafter cycle_sort: now sorting by %d\n",
                static_cast<int>(f));

    // Hex bytes of selected packet
    const std::vector<uint8_t>& raw = model.selected_raw_bytes();
    std::printf("\nraw bytes of selected packet (%zu bytes): ", raw.size());
    size_t hex_limit = std::min(raw.size(), size_t(16));
    for (size_t i = 0; i < hex_limit; ++i) {
        std::printf("%02x ", raw[i]);
    }
    std::printf("\n");

    return 0;
}