#ifndef PKTLENS_PACKETSTORE_H
#define PKTLENS_PACKETSTORE_H

#include "ParsedPacket.h"
#include "ProtocolTree.h"
#include "pktlens/capture/PacketProvider.h"
#include "pktlens/dissectors/DissectorRegistry.h"
#include <vector>
#include <cstddef>
#include <cstdint>

namespace pktlens {

    // How to sort the view
    enum class SortField {
        Time,
        Size,
        Protocol
    };

    enum class SortDirection {
        Ascending,
        Descending,
    };

    class PacketStore {
        private:
        std::vector<ParsedPacket> packets_; // all packets, stable order
        std::vector<size_t> view_; // indices into packets_, sorted

        SortField sort_field_;
        SortDirection sort_dir_;
        std::string error_;

        void reset_view(); // rebuild view_ to identity (0, 1, 2....)

        public:
        PacketStore();

        // Load all packets from provider, return the number of packets loaded.
        // 0 on failure.
        size_t load(PacketProvider& provider, DissectorContext& ctx);

        // Append a single packet (live capture mode).
        // CALLER must hold the SessionModel mutex before calling this.
        // If no filter is active, appends the new index to view_ directly
        // (O(1)). If a filter is active, evaluates it against the new packet
        // and appends conditionally.  In both cases the current sort order is
        // maintained only for time-ascending (the live-mode default): the new
        // packet is simply pushed to the back of view_, which is correct
        // because packets arrive in chronological order. For other sort modes
        // the UI is responsible for triggering a full re-sort when it catches
        // up (poll_new_packets()).
        template<typename Predicate>
        void append(ParsedPacket pkt, Predicate filter_pred) {
            size_t new_idx = packets_.size();
            packets_.push_back(std::move(pkt));

            // For time-ascending (default live sort) we just push_back — O(1).
            // For other sort orders the caller (SessionModel) will trigger a
            // reapply_filter() / sort() after releasing the lock, so we still
            // push_back here and let the next poll cycle re-sort.
            if (filter_pred(packets_[new_idx])) {
                view_.push_back(new_idx);
            }
        }

        // Total packets loaded (grows in live mode)
        size_t packet_count() const { return packets_.size(); }

        // Number of packets currently in the view (after filtering)
        size_t view_count() const { return view_.size(); }

        // Access a packet by view index.
        const ParsedPacket& packet_at(size_t view_index) const;

        // Raw packet index for a given view index.
        size_t raw_index_at(size_t view_index) const;

        // reset view_ to all packets (no filter)
        void clear_filter();

        template<typename Predicate>
        void apply_filter(Predicate pred) {
            view_.clear();
            for (size_t i = 0; i < packets_.size(); ++i) {
                if (pred(packets_[i])) {
                    view_.push_back(i);
                }
            }
            sort(sort_field_, sort_dir_);
        }

        void sort(SortField field, SortDirection dir);

        SortField     current_sort_field() const { return sort_field_; }
        SortDirection current_sort_dir()   const { return sort_dir_; }

        std::string error_message() const { return error_; }

        void load_from_vector(std::vector<ParsedPacket> packets);

        const ParsedPacket& packet_at_raw(size_t raw_index) const;
    };
}

#endif