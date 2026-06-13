#include "pktlens/ui/App.h"
#include "pktlens/capture/PcapFileProvider.h"
#include <ncurses.h>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <csignal>

extern volatile sig_atomic_t g_terminal_resized;

namespace pktlens
{

// =============================================================================
// Construction
// =============================================================================

App::App(const std::string& filename)
    : source_(filename)
    , live_mode_(false)
    , term_()
    , list_panel_(nullptr)
    , detail_panel_(nullptr)
    , filter_bar_(nullptr)
    , export_bar_(nullptr)
    , running_(true)
    , focus_(Focus::List)
    , paused_(false)
    , auto_scroll_(true)
    , last_packet_count_(0)
    , new_since_scroll_(0)
    , rate_snapshot_count_(0)
    , packets_per_sec_(0.0)
{}

App::App(const std::string& interface, bool /*live_tag*/)
    : source_(interface)
    , live_mode_(true)
    , term_()
    , list_panel_(nullptr)
    , detail_panel_(nullptr)
    , filter_bar_(nullptr)
    , export_bar_(nullptr)
    , running_(true)
    , focus_(Focus::List)
    , paused_(false)
    , auto_scroll_(true)
    , last_packet_count_(0)
    , new_since_scroll_(0)
    , rate_snapshot_count_(0)
    , packets_per_sec_(0.0)
{}

// =============================================================================
// run() — dispatches to file or live path
// =============================================================================

int App::run()
{
    if (live_mode_) { return run_live(); }

    // ── File mode (unchanged from v1 / step 3) ─────────────────────────────
    {
        PcapFileProvider provider(source_);
        if (!provider.is_open())
        {
            endwin();
            std::fprintf(stderr, "error: cannot open '%s': %s\n",
                         source_.c_str(),
                         provider.error_message().c_str());
            return 1;
        }

        mvprintw(0, 0, "Loading %s ...", source_.c_str());
        refresh();

        if (!model_.load(provider))
        {
            endwin();
            std::fprintf(stderr, "error: %s\n", model_.error_message().c_str());
            return 1;
        }
    }

    PacketListPanel list(model_);
    DetailPanel     detail(model_);
    FilterBar       filter(model_);
    ExportBar       exporter(model_);

    list_panel_   = &list;
    detail_panel_ = &detail;
    filter_bar_   = &filter;
    export_bar_   = &exporter;

    layout();
    render_all();

    while (running_)
    {
        int ch = getch();

        if (g_terminal_resized)
        {
            g_terminal_resized = 0;
            endwin(); refresh(); clear();
            layout();
            render_all();
        }

        handle_key(ch);
        render_all();
    }

    return 0;
}

// =============================================================================
// run_live() — live capture event loop
// =============================================================================

int App::run_live()
{
    // Open the interface before initialising the TUI so we can print a clean
    // error to stderr if the open fails (no endwin() needed yet).
    LiveCaptureProvider provider(source_);
    if (!provider.is_open())
    {
        endwin();
        std::fprintf(stderr, "pktlens: cannot open interface '%s': %s\n",
                     source_.c_str(), provider.error_message().c_str());
#ifdef __linux__
        std::fprintf(stderr,
                     "hint: run as root, or: sudo setcap cap_net_raw+eip pktlens\n");
#endif
        return 1;
    }

    // Blank loading screen while capture thread starts
    mvprintw(0, 0, "Capturing on %s ...", source_.c_str());
    refresh();

    // getch() must time out periodically so the UI can poll for new packets.
    // 100 ms matches the pcap heartbeat — responsive without busy-spinning.
    halfdelay(1);   // 100 ms timeout on getch() (value is tenths of a second)

    PacketListPanel list(model_);
    DetailPanel     detail(model_);
    FilterBar       filter(model_);
    ExportBar       exporter(model_);

    list_panel_   = &list;
    detail_panel_ = &detail;
    filter_bar_   = &filter;
    export_bar_   = &exporter;

    layout();

    // Seed the rate calculator
    rate_snapshot_time_  = std::chrono::steady_clock::now();
    rate_snapshot_count_ = 0;

    // Launch the capture thread
    CaptureThread capture(provider, model_);
    capture.start();

    render_all();

    while (running_)
    {
        int ch = getch();  // returns ERR after 100 ms timeout

        if (g_terminal_resized)
        {
            g_terminal_resized = 0;
            endwin(); refresh(); clear();
            layout();
        }

        // Always poll for new packets on every iteration (timeout or keypress)
        if (!paused_)
        {
            tick_live();
        }

        if (ch != ERR)
        {
            handle_key(ch);
        }

        render_all();
    }

    // Graceful shutdown: signal the provider, then wait for the thread.
    provider.stop();
    capture.join();

    // Restore blocking getch() for any future use
    nocbreak();
    cbreak();

    return 0;
}

// =============================================================================
// tick_live() — called every event-loop iteration in live mode
// =============================================================================

void App::tick_live()
{
    // Check if the capture thread crashed
    // (We query via the provider; CaptureThread sets has_error_ but we surface
    //  it here by checking whether poll has stalled for too long — simpler than
    //  passing CaptureThread* through.  We detect it via error_message() set by
    //  append_packet exceptions if any, but the simplest signal is just checking
    //  whether new_count stopped changing while running_.)
    // For now we poll the count and surface the error string if non-empty.

    size_t new_count = model_.poll_new_packets();

    if (new_count == last_packet_count_) { return; }

    size_t arrived = new_count - last_packet_count_;

    // Update packets-per-second rate every second
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(
        now - rate_snapshot_time_).count();
    if (elapsed >= 1.0)
    {
        packets_per_sec_     = (new_count - rate_snapshot_count_) / elapsed;
        rate_snapshot_count_ = new_count;
        rate_snapshot_time_  = now;
    }

    last_packet_count_ = new_count;

    if (auto_scroll_)
    {
        // Jump to the new tail
        list_panel_->scroll_to_bottom();
        new_since_scroll_ = 0;
    }
    else
    {
        // User is reviewing old packets; accumulate the unseen count
        new_since_scroll_ += arrived;
    }
}

// =============================================================================
// toggle_pause()
// =============================================================================

void App::toggle_pause()
{
    paused_ = !paused_;

    if (!paused_)
    {
        // Resume: catch up to current tail
        size_t current = model_.poll_new_packets();
        last_packet_count_ = current;
        new_since_scroll_  = 0;
        list_panel_->scroll_to_bottom();
        auto_scroll_ = true;
    }
}

// =============================================================================
// layout()
// =============================================================================

void App::layout()
{
    int rows, cols;
    TerminalGuard::get_dimensions(rows, cols);

    int usable   = rows - 2;
    int list_h   = std::max(3, (usable * 6) / 10);
    int detail_h = std::max(3, usable - list_h - 1);

    list_panel_->resize(list_h,   cols, 1,              0);
    detail_panel_->resize(detail_h, cols, 1 + list_h,   0);

    int bar_y = 1 + list_h + detail_h;
    filter_bar_->resize(1, cols, bar_y, 0);
    export_bar_->resize(1, cols, bar_y, 0);
}

// =============================================================================
// render_header()
// =============================================================================

void App::render_header()
{
    int rows, cols;
    TerminalGuard::get_dimensions(rows, cols);
    (void)rows;

    const char* sort_name = "time";
    switch (model_.current_sort_field())
    {
    case SortField::Size:     sort_name = "size";  break;
    case SortField::Protocol: sort_name = "proto"; break;
    default:                  sort_name = "time";  break;
    }
    const char* sort_dir =
        (model_.current_sort_dir() == SortDirection::Ascending) ? "^" : "v";

    char header[512];

    if (live_mode_)
    {
        // ── Live header ───────────────────────────────────────────────────
        // "pktlens  [LIVE: eth0]  [4,821 packets, +12/s]  filter: tcp  sort: time^"
        // Paused or scrolled-up variants replace the counter segment.

        const char* filter_str = model_.has_filter()
                                 ? model_.filter_expression().c_str()
                                 : "none";

        if (paused_)
        {
            std::snprintf(header, sizeof(header),
                          " pktlens  [LIVE: %s]  [PAUSED - %zu packets]"
                          "  filter: %s  sort: %s%s",
                          source_.c_str(),
                          model_.total_count(),
                          filter_str,
                          sort_name, sort_dir);
        }
        else if (!auto_scroll_ && new_since_scroll_ > 0)
        {
            std::snprintf(header, sizeof(header),
                          " pktlens  [LIVE: %s]  [%zu packets, +%zu new, %.0f/s]"
                          "  filter: %s  sort: %s%s",
                          source_.c_str(),
                          model_.total_count(),
                          new_since_scroll_,
                          packets_per_sec_,
                          filter_str,
                          sort_name, sort_dir);
        }
        else
        {
            std::snprintf(header, sizeof(header),
                          " pktlens  [LIVE: %s]  [%zu packets, %.0f/s]"
                          "  filter: %s  sort: %s%s",
                          source_.c_str(),
                          model_.total_count(),
                          packets_per_sec_,
                          filter_str,
                          sort_name, sort_dir);
        }

        // Surface capture thread errors if any
        if (!capture_error_.empty())
        {
            std::snprintf(header, sizeof(header),
                          " pktlens  [LIVE: %s]  [CAPTURE ERROR: %s]",
                          source_.c_str(),
                          capture_error_.c_str());
        }
    }
    else
    {
        // ── File header (unchanged from v1) ───────────────────────────────
        const char* focus_str =
            (focus_ == Focus::Detail) ? "  [focus: DETAIL]" : "  [focus: LIST]";

        std::snprintf(header, sizeof(header),
                      " pktlens  %s  [%zu/%zu]  filter: %s  sort: %s%s%s",
                      source_.c_str(),
                      model_.filtered_count(),
                      model_.total_count(),
                      model_.has_filter()
                          ? model_.filter_expression().c_str() : "none",
                      sort_name, sort_dir,
                      focus_str);
    }

    std::string h_str(header);
    while (static_cast<int>(h_str.size()) < cols) { h_str += ' '; }
    h_str = h_str.substr(0, static_cast<size_t>(cols));

    attron(COLOR_PAIR(colors::HEADER_BAR) | A_BOLD);
    mvprintw(0, 0, "%s", h_str.c_str());
    attroff(COLOR_PAIR(colors::HEADER_BAR) | A_BOLD);
}

// =============================================================================
// render_status_bar()   (free function, private to this TU)
// =============================================================================

static void render_status_bar(int rows, int cols, bool live_mode)
{
    const char* keys = live_mode
        ? " [Arrow Up/Arrow Down] navigate  [TAB] focus  [/] filter  "
          "[w] export  [Esc] clear  [s] sort  [r] reverse  "
          "[h] hex  [Space] pause  [G] resume scroll  [q] quit"
        : " [Arrow Up/Arrow Down] navigate  [TAB] focus  [/] filter  "
          "[w] export  [Esc] clear  [s] sort  [r] reverse  [h] hex  [q] quit";

    std::string bar(keys);
    while (static_cast<int>(bar.size()) < cols) { bar += ' '; }
    bar = bar.substr(0, static_cast<size_t>(cols));

    attron(COLOR_PAIR(colors::STATUS_BAR));
    mvprintw(rows - 1, 0, "%s", bar.c_str());
    attroff(COLOR_PAIR(colors::STATUS_BAR));
}

// =============================================================================
// render_all()
// =============================================================================

void App::render_all()
{
    int rows, cols;
    TerminalGuard::get_dimensions(rows, cols);

    detail_panel_->set_focused(focus_ == Focus::Detail);

    render_header();
    list_panel_->render();
    detail_panel_->render();

    if (export_bar_->is_active()) {
        export_bar_->render();
    } else {
        filter_bar_->render();
    }

    render_status_bar(rows, cols, live_mode_);
    refresh();
}

// =============================================================================
// handle_key()
// =============================================================================

void App::handle_key(int ch)
{
    if (export_bar_->is_active())
    {
        export_bar_->handle_key(ch);
        return;
    }

    if (filter_bar_->is_active())
    {
        filter_bar_->handle_key(ch);
        return;
    }

    switch (ch)
    {
    case 'q':
        running_ = false;
        return;

    case '/':
        filter_bar_->activate();
        return;

    case 'w':
        export_bar_->activate();
        return;

    case 27:  // Escape — clear filter
        model_.clear_filter();
        return;

    case 's':
        model_.cycle_sort_field();
        // Non-time sort disables auto-scroll (spec §1.8)
        if (live_mode_ && model_.current_sort_field() != SortField::Time)
            auto_scroll_ = false;
        return;

    case 'r':
        model_.toggle_sort_direction();
        return;

    case '\t':
        focus_ = (focus_ == Focus::List) ? Focus::Detail : Focus::List;
        return;

    case 'h':
        detail_panel_->handle_key(ch);
        return;

    case ' ':
        if (live_mode_) { toggle_pause(); }
        return;

    case 'G':
        // In live mode 'G' also resumes auto-scroll
        if (live_mode_)
        {
            list_panel_->scroll_to_bottom();
            auto_scroll_      = true;
            new_since_scroll_ = 0;
        }
        else
        {
            list_panel_->handle_key(ch);
        }
        return;

    default:
        break;
    }

    // Navigation keys: detect manual upward scroll to disable auto-scroll
    if (live_mode_ && focus_ == Focus::List)
    {
        bool was_at_bottom = list_panel_->is_at_bottom();
        list_panel_->handle_key(ch);
        // If the user scrolled up away from the bottom, disable auto-scroll
        if (was_at_bottom && !list_panel_->is_at_bottom())
        {
            auto_scroll_      = false;
            new_since_scroll_ = 0;
        }
        return;
    }

    if (focus_ == Focus::Detail)
        detail_panel_->handle_key(ch);
    else
        list_panel_->handle_key(ch);
}

}  // namespace pktlens