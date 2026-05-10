#ifndef NETSCOPE_PACKETSTORE_H
#define NETSCOPE_PACKETSTORE_H

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
        // Performs two passes internally: count and dissect.
        size_t load(PacketProvider& provider, DissectorContext& ctx);

        // Total packets loaded (never changes after load)
        size_t packet_count() const { return packets_.size(); }

        // Number of packets currently in the view (after filtering)
        size_t view_count() const { return view_.size(); }

        // Acess a packet by view index.
        // Will be called in the render loop for every single row.
        const ParsedPacket& packet_at(size_t view_index) const;

        // Raw packet index for a given view index.
        // Needed for SessionModel to build a ProtocolTree on demand. 
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
            // Re-apply current sort to filtered view
            sort(sort_field_, sort_dir_);
        }

        void sort(SortField field, SortDirection dir);

        SortField current_sort_field() const { return sort_field_; }
        SortDirection current_sort_dir() const { return sort_dir_; }

        std::string error_message() const { return error_; }
    };

}

#endif
