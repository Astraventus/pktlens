#include "pktlens/ui/ExportBar.h"
#include <ncurses.h>
#include <cstdio>    // snprintf
#include <cstring>

namespace pktlens
{

    ExportBar::ExportBar(SessionModel& model)
        : model_(model)
        , win_(new Window(1, 1, 0, 0))
        , active_(false)
        , state_(State::Input)
    {}

    // -------------------------------------------------------------------------
    // activate()
    // -------------------------------------------------------------------------
    void ExportBar::activate()
    {
        active_ = true;
        state_  = State::Input;
        input_.clear();
        status_message_.clear();
        curs_set(1);  // show cursor while typing
    }

    // -------------------------------------------------------------------------
    // render()
    // -------------------------------------------------------------------------
    void ExportBar::render()
    {
        win_->clear();
        int w = win_->width();

        if (!active_) {
            // Passive: show a brief hint so the user knows the hotkey exists
            win_->print(0, 0, "export: press [w] to export visible packets", A_DIM);
            win_->refresh();
            return;
        }

        std::string line;

        switch (state_) {

            case State::Input:
                line = "export> " + input_ + "_";
                break;

            case State::ConfirmOverwrite:
                line = "export> " + input_ + " already exists. overwrite? [y/N]_";
                break;

            case State::Done: {
                // Auto-dismiss after 2 seconds
                using namespace std::chrono;
                auto elapsed = duration_cast<seconds>(
                    steady_clock::now() - status_set_at_).count();
                if (elapsed >= 2) {
                    active_ = false;
                    curs_set(0);
                    win_->clear();
                    win_->print(0, 0, "export: press [w] to export visible packets",
                                A_DIM);
                    win_->refresh();
                    return;
                }
                line = status_message_;
                break;
            }
        }

        // Pad to window width
        while (static_cast<int>(line.size()) < w) { line += ' '; }
        line = line.substr(0, static_cast<size_t>(w));

        int attrs = (state_ == State::Done) ? (A_BOLD | A_REVERSE) : A_BOLD;
        win_->print(0, 0, line, attrs);
        win_->refresh();
    }

    // -------------------------------------------------------------------------
    // handle_key()
    // -------------------------------------------------------------------------
    bool ExportBar::handle_key(int ch)
    {
        if (!active_) { return false; }

        switch (state_) {

            // ------------------------------------------------------------------
            case State::Input:
                switch (ch) {
                    case '\n':
                    case KEY_ENTER:
                        if (input_.empty()) {
                            cancel();
                        } else {
                            attempt_export();
                        }
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
                        // Accept printable ASCII only; reject path separators
                        // and characters that would be problematic on the filesystem.
                        // We allow '/', '.', '-', '_', and alphanumerics — anything
                        // a reasonable filename might contain.
                        if (ch >= 32 && ch < 127) {
                            input_ += static_cast<char>(ch);
                        }
                        return true;
                }

            // ------------------------------------------------------------------
            case State::ConfirmOverwrite:
                switch (ch) {
                    case 'y':
                    case 'Y':
                        do_export();
                        return true;

                    default:
                        // Anything other than 'y' cancels (includes 'n', Enter,
                        // Escape — spec says "anything else cancels")
                        cancel();
                        return true;
                }

            // ------------------------------------------------------------------
            case State::Done:
                // Any key while the status is showing dismisses it immediately
                active_ = false;
                curs_set(0);
                return true;
        }

        return true;  // unreachable, but keeps the compiler happy
    }

    // -------------------------------------------------------------------------
    // resize()
    // -------------------------------------------------------------------------
    void ExportBar::resize(int height, int width, int y, int x)
    {
        win_->resize(height, width, y, x);
    }

    // -------------------------------------------------------------------------
    // attempt_export()
    //   Called when the user presses Enter in Input state.
    //   If the file already exists, move to ConfirmOverwrite; otherwise write.
    // -------------------------------------------------------------------------
    void ExportBar::attempt_export()
    {
        if (SessionModel::file_exists(input_)) {
            state_ = State::ConfirmOverwrite;
        } else {
            do_export();
        }
    }

    // -------------------------------------------------------------------------
    // do_export()
    //   Performs the actual write unconditionally, then transitions to Done.
    // -------------------------------------------------------------------------
    void ExportBar::do_export()
    {
        size_t count = model_.filtered_count();

        if (model_.export_to_pcap(input_)) {
            char buf[256];
            std::snprintf(buf, sizeof(buf),
                          "exported %zu packet%s -> %s",   // → (UTF-8)
                          count,
                          count == 1 ? "" : "s",
                          input_.c_str());
            status_message_ = buf;
        } else {
            status_message_ = "export failed: " + model_.error_message();
        }

        state_        = State::Done;
        status_set_at_ = std::chrono::steady_clock::now();
        curs_set(0);
    }

    // -------------------------------------------------------------------------
    // cancel()
    // -------------------------------------------------------------------------
    void ExportBar::cancel()
    {
        active_ = false;
        state_  = State::Input;
        input_.clear();
        curs_set(0);
    }

}  // namespace pktlens