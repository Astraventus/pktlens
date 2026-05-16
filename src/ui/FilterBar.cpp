#include "pktlens/ui/FilterBar.h"
#include <ncurses.h>
#include <cstdio>

namespace pktlens {

    FilterBar::FilterBar(SessionModel& model)
        : model_(model)
        , win_(new Window(1, 1, 0, 0))
        , active_(false)
    {}

    void FilterBar::activate() {
        active_ = true;
        input_  = model_.filter_expression();
        curs_set(1);  // show cursor while typing
    }

    void FilterBar::render() {
        win_->clear();
        int w = win_->width();

        if (!active_) {
            // Show current filter status passively
            std::string label = "filter: ";
            if (model_.has_filter()) {
                label += model_.filter_expression();
            } else {
                label += "(none)";
            }
            if (!model_.filter_error().empty()) {
                label += "  ERR: " + model_.filter_error();
                win_->print(0, 0, label, COLOR_PAIR(colors::FILTER_ERR));
            } else {
                win_->print(0, 0, label, A_DIM);
            }
        } else {
            // Active input mode
            std::string prompt = "filter> " + input_ + "_";
            // Pad to width
            while (static_cast<int>(prompt.size()) < w) { prompt += ' '; }
            win_->print(0, 0, prompt, A_BOLD);
        }

        win_->refresh();
    }

    bool FilterBar::handle_key(int ch) {
        if (!active_) { return false; }

        switch (ch) {
            case '\n':
            case KEY_ENTER:
                apply();
                return true;

            case 27:  // Escape
                cancel();
                return true;

            case KEY_BACKSPACE:
            case 127:
            case '\b':
                if (!input_.empty()) { input_.pop_back(); }
                return true;

            default:
                // Printable ASCII only
                if (ch >= 32 && ch < 127) {
                    input_ += static_cast<char>(ch);
                }
                return true;
        }
    }

    void FilterBar::apply() {
        active_ = false;
        curs_set(0);

        if (input_.empty()) {
            model_.clear_filter();
        } else {
            model_.apply_filter(input_);
            // Error (if any) is visible via model_.filter_error()
            // The filter bar will display it on next render
        }
    }

    void FilterBar::cancel() {
        active_ = false;
        curs_set(0);
        input_.clear();
    }

    void FilterBar::resize(int height, int width, int y, int x) {
        win_->resize(height, width, y, x);
    }

}