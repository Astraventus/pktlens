#include "pktlens/model/PacketStore.h"
#include <algorithm>

namespace pktlens {

    PacketStore::PacketStore()
        : sort_field_(SortField::Time)
        , sort_dir_(SortDirection::Ascending)
    {}

    size_t PacketStore::load(PacketProvider& provider, DissectorContext& ctx)
    {
        packets_.clear();
        view_.clear();
        error_.clear();

        packets_.reserve(65536);

        RawPacket raw;
        while (provider.next_packet(raw)) {
            ParsedPacket pkt;
            ProtocolTree tree;  // discarded — SessionModel builds on demand
            dissect(raw, pkt, tree, ctx);
            packets_.push_back(pkt);
        }

        packets_.shrink_to_fit();
        reset_view();
        sort(sort_field_, sort_dir_);
        return packets_.size();
    }

    void PacketStore::load_from_vector(std::vector<ParsedPacket> packets)
    {
        packets_ = std::move(packets);
        error_.clear();
        reset_view();
        sort(sort_field_, sort_dir_);
    }

    const ParsedPacket& PacketStore::packet_at(size_t view_index) const
    {
        return packets_[view_[view_index]];
    }

    const ParsedPacket& PacketStore::packet_at_raw(size_t raw_index) const
    {
        return packets_[raw_index];
    }

    size_t PacketStore::raw_index_at(size_t view_index) const
    {
        return view_[view_index];
    }

    void PacketStore::clear_filter()
    {
        reset_view();
        sort(sort_field_, sort_dir_);
    }

    void PacketStore::sort(SortField field, SortDirection dir)
    {
        sort_field_ = field;
        sort_dir_   = dir;

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
                return (dir == SortDirection::Ascending) ? less_than : !less_than;
            });
    }

    void PacketStore::reset_view()
    {
        view_.resize(packets_.size());
        for (size_t i = 0; i < packets_.size(); ++i) {
            view_[i] = i;
        }
    }

}  // namespace pktlens