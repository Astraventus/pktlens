#include "pktlens/ui/PacketListPanel.h"
#include "pktlens/model/ProtoId.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstdio>
#include <algorithm>

namespace pktlens {

    PacketListPanel::PacketListPanel(SessionModel& model)
        : model_(model)
        , win_(new Window(1, 1, 0, 0))  // resized immediately by App
        , scroll_offset_(0)
    {}

    std::string PacketListPanel::fmt_ip(uint32_t ip_nbo) {
        if (ip_nbo == 0) { return "\xe2\x80\x94"; }  // em-dash
        struct in_addr addr;
        addr.s_addr = ip_nbo;
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        return std::string(buf);
    }

    int PacketListPanel::color_for_proto(ProtoId proto) const {
        switch (proto) {
            case ProtoId::TCP:  return COLOR_PAIR(colors::PROTO_TCP);
            case ProtoId::UDP:  return COLOR_PAIR(colors::PROTO_UDP);
            case ProtoId::DNS:  return COLOR_PAIR(colors::PROTO_DNS);
            case ProtoId::HTTP: return COLOR_PAIR(colors::PROTO_HTTP);
            case ProtoId::ICMP: return COLOR_PAIR(colors::PROTO_ICMP);
            case ProtoId::ARP:  return COLOR_PAIR(colors::PROTO_ARP);
            default:            return COLOR_PAIR(colors::PROTO_OTHER);
        }
    }

    void PacketListPanel::render() {
        win_->clear();

        int h = win_->height();
        int w = win_->width();

        // Column header row
        char header[256];
        std::snprintf(header, sizeof(header),
                    " %-6s %-12s %-18s %-18s %-6s %s",
                    "#", "Time", "Source", "Destination", "Proto", "Len");
        win_->print(0, 0, header, A_BOLD | COLOR_PAIR(colors::HEADER_BAR));
        win_->draw_hline(0, 0, ' ', w);
        win_->print(0, 0, header, A_BOLD | COLOR_PAIR(colors::HEADER_BAR));

        int visible_rows = h - 1;
        size_t total     = model_.filtered_count();
        size_t sel       = model_.selected_index();

        scroll_to_selection();

        for (int row = 0; row < visible_rows; ++row) {
            size_t idx = scroll_offset_ + static_cast<size_t>(row);
            if (idx >= total) { break; }

            const ParsedPacket& pkt = model_.packet_at(idx);
            bool is_selected        = (idx == sel);

            std::string idx_str = std::to_string(idx + 1);
            if (idx_str.size() > 6) { idx_str = idx_str.substr(0, 6); }

            char time_buf[16];
            std::snprintf(time_buf, sizeof(time_buf), "%.6f", pkt.timestamp);
            std::string time_str(time_buf);
            if (time_str.size() > 12) { time_str = time_str.substr(0, 12); }

            std::string src = fmt_ip(pkt.src_ip);
            std::string dst = fmt_ip(pkt.dst_ip);

            std::string proto = proto_name(pkt.top_proto);
            if (proto.size() > 6) { proto = proto.substr(0, 6); }

            char len_buf[16];
            std::snprintf(len_buf, sizeof(len_buf), "%u", pkt.length_orig);
            std::string len_str(len_buf);
            if (len_str.size() > 6) { len_str = len_str.substr(0, 6); }

            char line[512];
            std::snprintf(line, sizeof(line),
                        " %-6s %-12s %-18s %-18s %-6s %s",
                        idx_str.c_str(), time_str.c_str(),
                        src.c_str(), dst.c_str(),
                        proto.c_str(), len_str.c_str());

            int attrs = color_for_proto(pkt.top_proto);
            if (is_selected) {
                attrs = COLOR_PAIR(colors::SELECTED) | A_BOLD;
                win_->print(row + 1, 0, ">", attrs);
                std::string line_without_arrow(line);
                while (static_cast<int>(line_without_arrow.size()) < w - 1)
                    line_without_arrow += ' ';
                line_without_arrow = line_without_arrow.substr(0, static_cast<size_t>(w - 1));
                win_->print(row + 1, 1, line_without_arrow, attrs);
            } else {
                std::string line_str(line);
                while (static_cast<int>(line_str.size()) < w) line_str += ' ';
                line_str = line_str.substr(0, static_cast<size_t>(w));
                win_->print(row + 1, 0, line_str, attrs);
            }
        }

        win_->refresh();
    }

    bool PacketListPanel::handle_key(int ch) {
        size_t total = model_.filtered_count();
        if (total == 0) { return false; }

        size_t sel = model_.selected_index();

        switch (ch) {
            case KEY_UP:
                if (sel > 0) { model_.select(sel - 1); }
                return true;

            case KEY_DOWN:
                if (sel + 1 < total) { model_.select(sel + 1); }
                return true;

            case KEY_PPAGE: {
                int page = std::max(1, win_->height() - 2);
                size_t new_sel = (sel > static_cast<size_t>(page))
                                 ? sel - static_cast<size_t>(page) : 0;
                model_.select(new_sel);
                return true;
            }

            case KEY_NPAGE: {
                int page = std::max(1, win_->height() - 2);
                size_t new_sel = std::min(sel + static_cast<size_t>(page), total - 1);
                model_.select(new_sel);
                return true;
            }

            case 'g':
                model_.select(0);
                return true;

            case 'G':
                model_.select(total - 1);
                return true;

            default:
                return false;
        }
    }

    void PacketListPanel::resize(int height, int width, int y, int x) {
        win_->resize(height, width, y, x);
    }

    void PacketListPanel::scroll_to_selection() {
        int visible = win_->height() - 1;
        if (visible <= 0) { return; }

        size_t sel = model_.selected_index();

        if (sel < scroll_offset_) {
            scroll_offset_ = sel;
        } else if (sel >= scroll_offset_ + static_cast<size_t>(visible)) {
            scroll_offset_ = sel - static_cast<size_t>(visible) + 1;
        }
    }

    // -------------------------------------------------------------------------
    // Live-mode helpers (Step 7)
    // -------------------------------------------------------------------------

    bool PacketListPanel::is_at_bottom() const {
        size_t total = model_.filtered_count();
        if (total == 0) { return true; }

        int visible = win_->height() - 1;
        if (visible <= 0) { return true; }

        // Bottom is reached when the last packet is visible in the window,
        // i.e. scroll_offset_ + visible >= total.
        return scroll_offset_ + static_cast<size_t>(visible) >= total;
    }

    void PacketListPanel::scroll_to_bottom() {
        size_t total = model_.filtered_count();
        if (total == 0) { return; }

        // Select the last packet — scroll_to_selection() will pin scroll_offset_
        // correctly on the next render() call.
        model_.select(total - 1);

        // Also update scroll_offset_ immediately so is_at_bottom() returns true
        // right away (before the next render).
        int visible = win_->height() - 1;
        if (visible > 0 && total > static_cast<size_t>(visible)) {
            scroll_offset_ = total - static_cast<size_t>(visible);
        } else {
            scroll_offset_ = 0;
        }
    }

}  // namespace pktlens