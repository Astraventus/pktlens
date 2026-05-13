#ifndef PKTLENS_SESSIONMODEL_H
#define PKTLENS_SESSIONMODEL_H

#include "pktlens/capture/PacketProvider.h"
#include "pktlens/dissectors/DissectorRegistry.h"
#include "pktlens/model/PacketStore.h"
#include "pktlens/model/ProtocolTree.h"
#include "pktlens/filter/FilterNode.h"
#include <cstring>
#include <vector>
#include <cstdint>

namespace pktlens {

    class SessionModel {
        private:
            DissectorContext ctx_;
            PacketStore store_;

            // Every packet's raw bytes, stored by index.
            // in future versions it shall be replaced with file-offset seek.
            std::vector<std::vector<uint8_t>> raw_bytes_;

            FilterNodePtr filter_node_; // null = no filter active
            std::string filter_expr_; // for display
            std::string filter_error_; // last parse/apply error

            size_t selected_index_; // index currently selected
            ProtocolTree selected_tree_; // built on demand for selected packet

            bool loaded_; // True if load() succeeded
            std::string error_; // Last error from loading or other operations

            void build_tree_for(size_t raw_index); // build tree out of raw packet index
            void reapply_filter(); // Takes the current filter_node_ and tells the PacketStore to filter packets using it.

        public:
            SessionModel();

            // Load all packets from provider.
            // Returns true on success. On failure, error_message() is set.
            // Provider must outlive this call (we read it fully here).
            bool load(PacketProvider& provider);

            // --- packet access ---

            // Number pf packets currently visible (after filter) 
            size_t filtered_count() const;

            // Total packets loaded
            size_t total_count() const;

            // Access a packet by view index.
            // view_index shall be less than filtered_count().
            const ParsedPacket& packet_at(size_t view_index) const;

            // --- Selection ---

            // Set the selected packet by view index.
            // Triggers lazy ProtocolTree build for that packet.
            void select(size_t view_index);

            size_t selected_index() const { return selected_index_; }

            // Returns the ProtocolTree for the currently selected packet.
            // Tree is built on demand when select() is called.
            // Returns an empty tree if nothing is selected.
            const ProtocolTree& selected_tree() const { return selected_tree_; }

            // Raw bytes of selected packet (for hex dump panel)
            const std::vector<uint8_t>& selected_raw_bytes() const;

            // --- Filtering ---

            // Compile and apply a filter expression.
            // Returns true on success. On failure, returns false and
            // sets filter_error() — the previous filter remains active.
            bool apply_filter(const std::string& expression);

            // Clear the current filter — show all packets.
            void clear_filter();

            // True if a filter is currently active
            bool has_filter() const { return filter_node_ != nullptr; }

            // The current filter expression string (for display in header bar)
            const std::string& filter_expression() const { return filter_expr_; }

            // Non-empty if the last apply_filter() call failed
            const std::string& filter_error() const { return filter_error_; }

            // --- Sorting ---

            void set_sort(SortField field, SortDirection dir);

            // Cycle through sort fields: Time -> Size -> Protocol -> Time
            // Returns the new sort field.
            SortField cycle_sort_field();

            // Toggle sort direction
            void toggle_sort_direction();

            SortField current_sort_field() const;
            SortDirection current_sort_dir()   const;

            // --- Status ---

            const std::string& error_message() const { return error_; }
            bool is_loaded() const { return loaded_; }

    };
}

#endif