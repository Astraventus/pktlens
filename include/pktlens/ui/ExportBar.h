#ifndef PKTLENS_EXPORTBAR_H
#define PKTLENS_EXPORTBAR_H

#include "Panel.h"
#include "pktlens/session/SessionModel.h"
#include <chrono>
#include <memory>
#include <string>

namespace pktlens
{

    // Single-line bar that appears when the user presses 'w'.
    // Mirrors FilterBar's two-state design (passive / active) and occupies
    // the same screen row.  Adds a confirm-overwrite state and a timed
    // status message after a successful export.
    class ExportBar : public Panel
    {
    public:
        explicit ExportBar(SessionModel& model);

        void render()  override;
        bool handle_key(int ch) override;
        void resize(int height, int width, int y, int x) override;

        bool is_active() const { return active_; }

        // Activate the bar and enter filename-input mode.
        void activate();

    private:
        SessionModel&           model_;
        std::unique_ptr<Window> win_;

        bool        active_;
        std::string input_;       // current filename being typed

        // Three internal states while active_==true:
        //   Input           — user is typing a filename
        //   ConfirmOverwrite — file exists; waiting for y/N
        //   Done            — export finished; showing timed status
        enum class State { Input, ConfirmOverwrite, Done };
        State       state_;

        // Status message shown in Done state
        std::string status_message_;
        std::chrono::steady_clock::time_point status_set_at_;

        void attempt_export();   // called on Enter in Input state
        void do_export();        // unconditionally performs the write
        void cancel();           // Escape / empty filename / 'N' on confirm
    };

}  // namespace pktlens

#endif  // PKTLENS_EXPORTBAR_H