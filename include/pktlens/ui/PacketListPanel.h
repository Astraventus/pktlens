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
        explicit PacketListPanel(SessionModel &model);

        void render() override;
        bool handle_key(int ch) override;
        void resize(int height, int width, int y, int x) override;

        size_t selected_index() const { return model_.selected_index(); }

    private:
        SessionModel &model_;
        std::unique_ptr<Window> win_;

        size_t scroll_offset_; // first visible row index into view

        void scroll_to_selection();
        int color_for_proto(ProtoId proto) const;

        // Format a 4-byte IP (network byte order) as "A.B.C.D"
        // Done here at render time, not at dissect time
        static std::string fmt_ip(uint32_t ip_nbo);
    };

}

#endif