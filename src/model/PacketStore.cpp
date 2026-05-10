#include "pktlens/model/PacketStore.h"
#include <algorithm>
#include <cstdio>

namespace pktlens {

    PacketStore::PacketStore() : sort_field_(SortField::Time), sort_dir_(SortDirection::Ascending) {}

    size_t PacketStore::load(PacketProvider& provider, DissectorContext& ctx) {
        packets_.clear();
        view_.clear();
        error_.clear();

        // Pass 1: count packets
        packets_.reserve(65536);

        RawPacket raw;
        while (provider.next_packet(raw)) {
            ParsedPacket pkt;
            ProtocolTree tree; // discarded - we rebuild on demand for selected pkt
            dissect(raw, pkt, tree, ctx);
            packets_.push_back(pkt);
        }

        if (packets_.empty()) {
            std::printf("Empty pcap!\n");
        }

        packets_.shrink_to_fit();

        reset_view();
        sort(sort_field_, sort_dir_);

        return packets_.size();
    }

    const ParsedPacket& PacketStore::packet_at(size_t view_index) const {
        // No bounds check — called in render loop.
        return packets_[view_[view_index]];
    }

    size_t PacketStore::raw_index_at(size_t view_index) const {
        return view_[view_index];
    }

    void PacketStore::clear_filter() {
        reset_view();
        sort(sort_field_, sort_dir_);
    }

    void PacketStore::sort(SortField field, SortDirection dir) {
        sort_field_ = field;
    sort_dir_   = dir;

    // stable_sort preserves relative order of equal elements.
    // Important for Time sort: packets with identical timestamps
    // stay in file order. Important for Protocol sort: packets
    // of the same protocol stay in time order within the group.
    std::stable_sort(view_.begin(), view_.end(),
        [this, field, dir](size_t a, size_t b) {
            const ParsedPacket& pa = packets_[a];
            const ParsedPacket& pb = packets_[b];

            bool less_than = false;

            switch (field) {
                case SortField::Time:
                    less_than = pa.timestamp < pb.timestamp;
                    break;
                case SortField::Size:
                    less_than = pa.length_orig < pb.length_orig;
                    break;
                case SortField::Protocol:
                    less_than = static_cast<uint8_t>(pa.top_proto)
                              < static_cast<uint8_t>(pb.top_proto);
                    break;
            }

            // Flip for descending
            return (dir == SortDirection::Ascending) ? less_than : !less_than;
        });
    }

    void PacketStore::reset_view() {
        view_.resize(packets_.size());
        for (size_t i = 0; i < packets_.size(); ++i) {
            view_[i] = i;
        }
    }
}
