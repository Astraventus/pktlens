#include "pktlens/ui/TerminalGuard.h"
#include "pktlens/ui/Panel.h"   // color indices
#include <ncurses.h>
#include <csignal>
#include <cstdlib>

volatile sig_atomic_t g_terminal_resized = 0;

namespace pktlens {

    static void signal_handler(int sig) {
        if (sig == SIGWINCH) {
            g_terminal_resized = 1;
            return;
        }
        // For fatal signals: restore terminal then re-raise
        endwin();
        std::signal(sig, SIG_DFL);
        std::raise(sig);
    }

    TerminalGuard::TerminalGuard() : has_colors_(false) {
        initscr();
        cbreak();           // no line buffering — get keys immediately
        noecho();           // don't echo typed characters
        keypad(stdscr, TRUE); // enable arrow keys, function keys
        curs_set(0);        // hide cursor
        nodelay(stdscr, FALSE); // blocking getch() — no busy loop

        setup_signals();

        if (::has_colors()) {
            start_color();
            use_default_colors();
            has_colors_ = true;
            setup_colors();
        }
    }

    TerminalGuard::~TerminalGuard() {
        endwin();
    }

    void TerminalGuard::get_dimensions(int& rows, int& cols) {
        getmaxyx(stdscr, rows, cols);
    }

    void TerminalGuard::setup_signals() {
        std::signal(SIGINT,  signal_handler);
        std::signal(SIGTERM, signal_handler);
        std::signal(SIGSEGV, signal_handler);
        std::signal(SIGABRT, signal_handler);
        std::signal(SIGWINCH, signal_handler);
    }

    void TerminalGuard::setup_colors() {
        // -1 = terminal default background (transparent)
        init_pair(colors::HEADER_BAR,  COLOR_WHITE,  COLOR_CYAN);
        init_pair(colors::STATUS_BAR,  COLOR_BLACK,  COLOR_WHITE);
        init_pair(colors::SELECTED,    COLOR_BLACK,  COLOR_WHITE);
        init_pair(colors::PROTO_TCP,   COLOR_CYAN,   -1);
        init_pair(colors::PROTO_UDP,   COLOR_GREEN,  -1);
        init_pair(colors::PROTO_DNS,   COLOR_YELLOW, -1);
        init_pair(colors::PROTO_HTTP,  COLOR_WHITE,  -1);
        init_pair(colors::PROTO_ICMP,  COLOR_CYAN,   -1);
        init_pair(colors::PROTO_ARP,   COLOR_MAGENTA,-1);
        init_pair(colors::PROTO_OTHER, COLOR_WHITE,  -1);
        init_pair(colors::FILTER_ERR,  COLOR_RED,    -1);
    }

}