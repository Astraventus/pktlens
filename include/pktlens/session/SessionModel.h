#ifndef PKTLENS_SESSIONMODEL_H
#define PKTLENS_SESSIONMODEL_H

#include "pktlens/capture/PacketProvider.h"
#include "pktlens/dissectors/DissectorRegistry.h"
#include "pktlens/model/PacketStore.h"
#include "pktlens/model/ProtocolTree.h"
#include "pktlens/filter/FilterNode.h"
#include <cstring>
#include <mutex>
#include <vector>
#include <cstdint>
#include <string>

namespace pktlens {

    class SessionModel {
        private:
            DissectorContext ctx_;
            PacketStore store_;

            // Every packet's raw bytes, stored by index.
            // In future versions this will be replaced with file-offset seek.
            std::vector<std::vector<uint8_t>> raw_bytes_;

            FilterNodePtr filter_node_; // null = no filter active
            std::string filter_expr_;   // for display
            std::string filter_error_;  // last parse/apply error

            size_t selected_index_;      // index currently selected in view
            ProtocolTree selected_tree_; // built on demand for selected packet

            bool loaded_;
            std::string error_;

            // -----------------------------------------------------------------
            // Live-capture state (Step 6)
            // -----------------------------------------------------------------

            // Guards raw_bytes_, store_.packets_/view_, and last_polled_count_.
            // Held by the capture thread during append_packet(),
            // and briefly by the UI thread during poll_new_packets().
            mutable std::mutex mutex_;

            // The total packet count seen by the UI on the last poll call.
            // Compared against store_.packet_count() to detect new arrivals.
            size_t last_polled_count_;

            // -----------------------------------------------------------------

            void build_tree_for(size_t raw_index);
            void reapply_filter();

        public:
            SessionModel();

            // Load all packets from provider (file mode).
            bool load(PacketProvider& provider);

            // --- Packet access ---

            size_t filtered_count() const;
            size_t total_count()    const;
            const ParsedPacket& packet_at(size_t view_index) const;

            // --- Selection ---

            void   select(size_t view_index);
            size_t selected_index() const { return selected_index_; }

            const ProtocolTree& selected_tree()      const { return selected_tree_; }
            const std::vector<uint8_t>& selected_raw_bytes() const;

            // --- Filtering ---

            bool apply_filter(const std::string& expression);
            void clear_filter();
            bool        has_filter()          const { return filter_node_ != nullptr; }
            const std::string& filter_expression() const { return filter_expr_; }
            const std::string& filter_error()       const { return filter_error_; }

            // --- Sorting ---

            void      set_sort(SortField field, SortDirection dir);
            SortField cycle_sort_field();
            void      toggle_sort_direction();

            SortField     current_sort_field() const;
            SortDirection current_sort_dir()   const;

            // --- Export (Step 2) ---

            bool export_to_pcap(const std::string& path);
            static bool file_exists(const std::string& path);

            // --- Live capture (Step 6) ---

            // Called by CaptureThread under the mutex.
            // Appends one packet to the store and raw_bytes_.
            void append_packet(ParsedPacket pkt, std::vector<uint8_t> raw_bytes);

            // Called by the UI thread on each event-loop iteration.
            // Returns the current total packet count.  If the count is
            // higher than last time, the UI should redraw.
            // Thread-safe (acquires mutex briefly).
            size_t poll_new_packets();

            // Acquire / release the session mutex.
            // CaptureThread uses these to bracket append_packet().
            void lock()   { mutex_.lock(); }
            void unlock() { mutex_.unlock(); }

            // --- Status ---

            const std::string& error_message() const { return error_; }
            bool is_loaded() const { return loaded_; }
    };
}

#endif