#ifndef PKTLENS_FILTERBAR_H
#define PKTLENS_FILTERBAR_H

#include "Panel.h"
#include "pktlens/session/SessionModel.h"
#include <memory>
#include <string>

namespace pktlens
{

    // Single-line input bar that appears when user presses '/'.
    // Disappears after Enter (apply) or Esc (cancel).
    class FilterBar : public Panel
    {
    public:
        explicit FilterBar(SessionModel &model);

        void render() override;
        bool handle_key(int ch) override;
        void resize(int height, int width, int y, int x) override;

        bool is_active() const { return active_; }
        void activate();

    private:
        SessionModel &model_;
        std::unique_ptr<Window> win_;

        bool active_;
        std::string input_;

        void apply();
        void cancel();
    };

}

#endif