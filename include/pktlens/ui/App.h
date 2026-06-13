#ifndef PKTLENS_APP_H
#define PKTLENS_APP_H

#include "TerminalGuard.h"
#include "PacketListPanel.h"
#include "DetailPanel.h"
#include "FilterBar.h"
#include "ExportBar.h"
#include "pktlens/capture/LiveCaptureProvider.h"
#include "pktlens/capture/CaptureThread.h"
#include "pktlens/session/SessionModel.h"
#include <memory>
#include <string>
#include <chrono>

namespace pktlens
{

    class App
    {
    public:
        // File mode (v1 unchanged)
        explicit App(const std::string& filename);

        // Live mode (-i <interface>)
        explicit App(const std::string& interface, bool /*live_tag*/);

        // Returns exit code
        int run();

    private:
        enum class Focus { List, Detail };

        // ── identity ────────────────────────────────────────────────────────
        std::string  source_;       // filename or interface name
        bool         live_mode_;

        // ── core ────────────────────────────────────────────────────────────
        SessionModel  model_;
        TerminalGuard term_;

        // ── panels (raw non-owning pointers into run()-local storage) ───────
        PacketListPanel* list_panel_;
        DetailPanel*     detail_panel_;
        FilterBar*       filter_bar_;
        ExportBar*       export_bar_;

        // ── state ───────────────────────────────────────────────────────────
        bool   running_;
        Focus  focus_;

        // ── live-mode state ─────────────────────────────────────────────────
        bool   paused_;             // Space toggles
        bool   auto_scroll_;        // false when user has scrolled up
        size_t last_packet_count_;  // for [+N new] indicator and rate calc
        size_t new_since_scroll_;   // packets that arrived while scrolled up

        // Rate calculation: packets per second shown in header
        size_t   rate_snapshot_count_;
        std::chrono::steady_clock::time_point rate_snapshot_time_;
        double   packets_per_sec_;

        // Error from crashed capture thread (shown in header)
        std::string capture_error_;

        // ── helpers ─────────────────────────────────────────────────────────
        void layout();
        void render_header();
        void render_all();
        void handle_key(int ch);

        // Live-mode only
        int  run_live();
        void tick_live();           // called on each getch() timeout in live mode
        void toggle_pause();
    };

}  // namespace pktlens

#endif  // PKTLENS_APP_H