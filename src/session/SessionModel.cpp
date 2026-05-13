#include "pktlens/session/SessionModel.h"
#include "pktlens/filter/FilterParser.h"
#include <cstring>

namespace pktlens {

    SessionModel::SessionModel() : selected_index_(0), loaded_(false) {}

    bool SessionModel::load(PacketProvider &provider)
    {
        loaded_ = false;
        error_.clear();
        raw_bytes_.clear();

        // We shall intercept each raw pcket during loading to store it's bytes.
        // We can't hook packetstore::load() in here. So we have to duplicate
        // manual loading here.

        RawPacket raw;
        std::vector<ParsedPacket> packets;
        packets.reserve(65536);
        raw_bytes_.reserve(65536);

        while (provider.next_packet(raw))
        {
            // Copy raw bytes before dissecting —
            // raw.data is only valid until the next next_packet() call
            raw_bytes_.push_back(std::vector<uint8_t>(raw.data,
                                                      raw.data + raw.caplen));

            ParsedPacket pkt;
            ProtocolTree tree; // discarded
            dissect(raw, pkt, tree, ctx_);
            packets.push_back(pkt);
        }

        if (packets.empty())
        {
            // Empty file is not an error — just nothing to show
            loaded_ = true;
            return true;
        }

        store_.load_from_vector(std::move(packets));

        if (store_.view_count() > 0)
        {
            select(0);
        }

        loaded_ = true;
        return true;
    }

    size_t SessionModel::filtered_count() const
    {
        return store_.view_count();
    }

    size_t SessionModel::total_count() const
    {
        return store_.packet_count();
    }

    const ParsedPacket &SessionModel::packet_at(size_t view_index) const
    {
        return store_.packet_at(view_index);
    }

    void SessionModel::select(size_t view_index)
    {
        if (view_index >= store_.view_count())
        {
            return;
        }
        selected_index_ = view_index;
        size_t raw_idx = store_.raw_index_at(view_index);
        build_tree_for(raw_idx);
    }

    const std::vector<uint8_t> &SessionModel::selected_raw_bytes() const
    {
        if (store_.view_count() == 0)
        {
            static const std::vector<uint8_t> empty;
            return empty;
        }
        size_t raw_idx = store_.raw_index_at(selected_index_);
        return raw_bytes_[raw_idx];
    }

    bool SessionModel::apply_filter(const std::string &expression)
    {
        if (expression.empty())
        {
            clear_filter();
            return true;
        }

        ParseResult result = parse_filter(expression);
        if (!result.ok())
        {
            filter_error_ = result.error;
            // Leave previous filter intact — don't clear on bad input
            return false;
        }

        filter_error_.clear();
        filter_node_ = std::move(result.node);
        filter_expr_ = expression;
        reapply_filter();
        return true;
    }

    void SessionModel::clear_filter()
    {
        filter_node_.reset();
        filter_expr_.clear();
        filter_error_.clear();
        store_.clear_filter();

        // Re-select: clamp to new view bounds
        if (store_.view_count() > 0)
        {
            if (selected_index_ >= store_.view_count())
            {
                selected_index_ = store_.view_count() - 1;
            }
            select(selected_index_);
        }
    }

    void SessionModel::set_sort(SortField field, SortDirection dir)
    {
        store_.sort(field, dir);
        if (store_.view_count() > 0)
        {
            select(0);
        }
    }

    SortField SessionModel::cycle_sort_field()
    {
        SortField current = store_.current_sort_field();
        SortField next = SortField::Time;

        switch (current)
        {
        case SortField::Time:
            next = SortField::Size;
            break;
        case SortField::Size:
            next = SortField::Protocol;
            break;
        case SortField::Protocol:
            next = SortField::Time;
            break;
        }

        set_sort(next, store_.current_sort_dir());
        return next;
    }

    void SessionModel::toggle_sort_direction()
    {
        SortDirection flipped =
            (store_.current_sort_dir() == SortDirection::Ascending)
                ? SortDirection::Descending
                : SortDirection::Ascending;

        set_sort(store_.current_sort_field(), flipped);
    }

    SortField SessionModel::current_sort_field() const
    {
        return store_.current_sort_field();
    }

    SortDirection SessionModel::current_sort_dir() const
    {
        return store_.current_sort_dir();
    }

    void SessionModel::build_tree_for(size_t raw_index)
    {
        selected_tree_ = ProtocolTree{};

        if (raw_index >= raw_bytes_.size())
        {
            return;
        }

        const std::vector<uint8_t> &bytes = raw_bytes_[raw_index];

        // Reconstruct a RawPacket pointing into our stored bytes
        RawPacket raw;
        raw.data = bytes.data();
        raw.caplen = static_cast<uint32_t>(bytes.size());
        raw.origlen = store_.packet_at_raw(raw_index).length_orig;
        raw.timestamp = store_.packet_at_raw(raw_index).timestamp;

        ParsedPacket throwaway;
        dissect(raw, throwaway, selected_tree_, ctx_);
    }

    void SessionModel::reapply_filter()
    {
        if (!filter_node_)
        {
            store_.clear_filter();
            return;
        }

        // Capture raw pointer for lambda — unique_ptr can't be captured by value
        const FilterNode *node = filter_node_.get();
        store_.apply_filter([node](const ParsedPacket &pkt)
                            { return node->evaluate(pkt); });

        // Clamp selection to new view
        if (store_.view_count() > 0)
        {
            if (selected_index_ >= store_.view_count())
            {
                selected_index_ = store_.view_count() - 1;
            }
            select(selected_index_);
        }
        else
        {
            selected_index_ = 0;
            selected_tree_ = ProtocolTree{};
        }
    }
}