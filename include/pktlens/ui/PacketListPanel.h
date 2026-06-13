#ifndef PKTLENS_PACKETLISTPANEL_H
#define PKTLENS_PACKETLISTPANEL_H

#include "Panel.h"
#include "pktlens/session/SessionModel.h"
#include <memory>

namespace pktlens
{

    class PacketListPanel : public Panel
    {
    public:
        explicit PacketListPanel(SessionModel& model);

        void render()  override;
        bool handle_key(int ch) override;
        void resize(int height, int width, int y, int x) override;

        size_t selected_index() const { return model_.selected_index(); }

        // --- Live-mode helpers (Step 7) ---

        // True when the list is scrolled all the way to the bottom (or empty).
        // App uses this to decide whether auto-scroll should fire.
        bool is_at_bottom() const;

        // Unconditionally jump selection and scroll to the last visible packet.
        // Called by App when new packets arrive and auto-scroll is active,
        // and when the user presses 'G' in live mode to resume auto-scroll.
        void scroll_to_bottom();

    private:
        SessionModel&           model_;
        std::unique_ptr<Window> win_;

        size_t scroll_offset_;  // first visible row index into the view

        void scroll_to_selection();
        int  color_for_proto(ProtoId proto) const;

        static std::string fmt_ip(uint32_t ip_nbo);
    };

}  // namespace pktlens

#endif  // PKTLENS_PACKETLISTPANEL_H