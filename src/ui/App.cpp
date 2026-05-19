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

    App::App(const std::string &filename)
        : filename_(filename), term_(), list_panel_(nullptr), detail_panel_(nullptr), filter_bar_(nullptr), running_(true), focus_(Focus::List)
    {
    }

    int App::run()
    {
        {
            PcapFileProvider provider(filename_);
            if (!provider.is_open())
            {
                endwin();
                std::fprintf(stderr, "error: cannot open '%s': %s\n",
                             filename_.c_str(),
                             provider.error_message().c_str());
                return 1;
            }

            mvprintw(0, 0, "Loading %s ...", filename_.c_str());
            refresh();

            if (!model_.load(provider))
            {
                endwin();
                std::fprintf(stderr, "error: %s\n",
                             model_.error_message().c_str());
                return 1;
            }
        }

        PacketListPanel list(model_);
        DetailPanel detail(model_);
        FilterBar filter(model_);

        list_panel_ = &list;
        detail_panel_ = &detail;
        filter_bar_ = &filter;

        layout();
        render_all();

        while (running_)
        {
            int ch = getch();

            if (g_terminal_resized)
            {
                g_terminal_resized = 0;
                endwin();
                refresh();
                clear();
                layout();
                render_all();
            }

            handle_key(ch);
            render_all();
        }

        return 0;
    }

    void App::layout()
    {
        int rows, cols;
        TerminalGuard::get_dimensions(rows, cols);

        int usable = rows - 2; // header + status bar
        int list_h = std::max(3, (usable * 6) / 10);
        int detail_h = std::max(3, usable - list_h - 1); // minus filter bar

        list_panel_->resize(list_h, cols, 1, 0);
        detail_panel_->resize(detail_h, cols, 1 + list_h, 0);
        filter_bar_->resize(1, cols, 1 + list_h + detail_h, 0);
    }

    void App::render_header()
    {
        int rows, cols;
        TerminalGuard::get_dimensions(rows, cols);
        (void)rows;

        const char *sort_name = "time";
        switch (model_.current_sort_field())
        {
        case SortField::Size:
            sort_name = "size";
            break;
        case SortField::Protocol:
            sort_name = "proto";
            break;
        default:
            sort_name = "time";
            break;
        }
        const char *sort_dir =
            (model_.current_sort_dir() == SortDirection::Ascending) ? "^" : "v";

        // Focus indicator — makes it unambiguous which panel has keyboard focus
        const char *focus_str =
            (focus_ == Focus::Detail) ? "  [focus: DETAIL]" : "  [focus: LIST]";

        char header[512];
        std::snprintf(header, sizeof(header),
                      " pktlens  %s  [%zu/%zu]  filter: %s  sort: %s%s%s",
                      filename_.c_str(),
                      model_.filtered_count(),
                      model_.total_count(),
                      model_.has_filter() ? model_.filter_expression().c_str() : "none",
                      sort_name,
                      sort_dir,
                      focus_str);

        std::string h_str(header);
        while (static_cast<int>(h_str.size()) < cols)
        {
            h_str += ' ';
        }
        h_str = h_str.substr(0, static_cast<size_t>(cols));

        attron(COLOR_PAIR(colors::HEADER_BAR) | A_BOLD);
        mvprintw(0, 0, "%s", h_str.c_str());
        attroff(COLOR_PAIR(colors::HEADER_BAR) | A_BOLD);
    }

    static void render_status_bar(int rows, int cols)
    {
        const char *keys =
            " [Arrow Up/Arrow Down] navigate  [TAB] switch focus  [/] filter  "
            "[Esc] clear filter  [s] sort  [r] reverse  [h] hex  [q] quit";

        std::string bar(keys);
        while (static_cast<int>(bar.size()) < cols)
        {
            bar += ' ';
        }
        bar = bar.substr(0, static_cast<size_t>(cols));

        attron(COLOR_PAIR(colors::STATUS_BAR));
        mvprintw(rows - 1, 0, "%s", bar.c_str());
        attroff(COLOR_PAIR(colors::STATUS_BAR));
    }

    void App::render_all()
    {
        int rows, cols;
        TerminalGuard::get_dimensions(rows, cols);

        // Tell detail panel whether it owns focus so it can draw its border differently
        detail_panel_->set_focused(focus_ == Focus::Detail);

        render_header();
        list_panel_->render();
        detail_panel_->render();
        filter_bar_->render();
        render_status_bar(rows, cols);

        refresh();
    }

    void App::handle_key(int ch)
    {
        // Filter bar eats everything while active
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

        case 27: // Escape
            model_.clear_filter();
            return;

        case 's':
            model_.cycle_sort_field();
            return;

        case 'r':
            model_.toggle_sort_direction();
            return;

        case '\t': // Tab — toggle focus between list and detail
            focus_ = (focus_ == Focus::List) ? Focus::Detail : Focus::List;
            return;

        case 'h':
            // 'h' always goes to detail panel regardless of focus
            detail_panel_->handle_key(ch);
            return;

        default:
            break;
        }

        // Navigation keys go to whichever panel has focus
        if (focus_ == Focus::Detail)
        {
            detail_panel_->handle_key(ch);
        }
        else
        {
            list_panel_->handle_key(ch);
        }
    }

}