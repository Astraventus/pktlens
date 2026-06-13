#include "pktlens/session/SessionModel.h"
#include "pktlens/capture/PcapWriter.h"
#include "pktlens/filter/FilterParser.h"
#include <cstring>
#include <sys/stat.h>  // stat()

namespace pktlens {

    SessionModel::SessionModel()
        : selected_index_(0)
        , loaded_(false)
        , last_polled_count_(0)
    {}

    bool SessionModel::load(PacketProvider &provider)
    {
        loaded_ = false;
        error_.clear();
        raw_bytes_.clear();

        RawPacket raw;
        std::vector<ParsedPacket> packets;
        packets.reserve(65536);
        raw_bytes_.reserve(65536);

        while (provider.next_packet(raw))
        {
            raw_bytes_.push_back(std::vector<uint8_t>(raw.data,
                                                      raw.data + raw.caplen));
            ParsedPacket pkt;
            ProtocolTree tree;
            dissect(raw, pkt, tree, ctx_);
            packets.push_back(pkt);
        }

        if (packets.empty())
        {
            loaded_ = true;
            return true;
        }

        store_.load_from_vector(std::move(packets));

        if (store_.view_count() > 0)
        {
            select(0);
        }

        last_polled_count_ = store_.packet_count();
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
        case SortField::Time:     next = SortField::Size;     break;
        case SortField::Size:     next = SortField::Protocol; break;
        case SortField::Protocol: next = SortField::Time;     break;
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

        RawPacket raw;
        raw.data      = bytes.data();
        raw.caplen    = static_cast<uint32_t>(bytes.size());
        raw.origlen   = store_.packet_at_raw(raw_index).length_orig;
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

        const FilterNode *node = filter_node_.get();
        store_.apply_filter([node](const ParsedPacket &pkt)
                            { return node->evaluate(pkt); });

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
            selected_tree_  = ProtocolTree{};
        }
    }

    // -------------------------------------------------------------------------
    // Export (Step 2)
    // -------------------------------------------------------------------------

    bool SessionModel::export_to_pcap(const std::string& path)
    {
        error_.clear();

        PcapWriter writer(path);
        if (!writer.is_open()) {
            error_ = writer.error_message();
            return false;
        }

        for (size_t i = 0; i < store_.view_count(); ++i) {
            size_t raw_idx                    = store_.raw_index_at(i);
            const ParsedPacket&         pkt   = store_.packet_at_raw(raw_idx);
            const std::vector<uint8_t>& bytes = raw_bytes_[raw_idx];

            if (!writer.write_packet(bytes, pkt.timestamp, pkt.length_orig)) {
                error_ = writer.error_message();
                return false;
            }
        }

        return true;
    }

    // static
    bool SessionModel::file_exists(const std::string& path)
    {
        struct stat st;
        return ::stat(path.c_str(), &st) == 0;
    }

    // -------------------------------------------------------------------------
    // Live capture (Step 6)
    // -------------------------------------------------------------------------

    // Called by CaptureThread while holding the mutex.
    void SessionModel::append_packet(ParsedPacket pkt,
                                     std::vector<uint8_t> raw_bytes)
    {
        // raw_bytes_ and the store must stay in sync: push to raw_bytes_ first
        // so the index PacketStore will compute (packets_.size() before push)
        // matches the index we'll use in raw_bytes_.
        raw_bytes_.push_back(std::move(raw_bytes));

        // Build a trivial predicate: pass through if no filter, or evaluate.
        // The lambda captures filter_node_ by raw pointer (safe — the capture
        // thread holds the mutex, so apply_filter/clear_filter can't run).
        const FilterNode* node = filter_node_.get();
        if (node) {
            store_.append(std::move(pkt),
                          [node](const ParsedPacket& p) {
                              return node->evaluate(p);
                          });
        } else {
            store_.append(std::move(pkt),
                          [](const ParsedPacket&) { return true; });
        }
    }

    // Called by the UI thread on each getch() timeout iteration.
    size_t SessionModel::poll_new_packets()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t current = store_.packet_count();
        last_polled_count_ = current;
        return current;
    }

}  // namespace pktlens