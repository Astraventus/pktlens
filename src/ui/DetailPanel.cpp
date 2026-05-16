#include "pktlens/ui/DetailPanel.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace pktlens
{

    DetailPanel::DetailPanel(SessionModel &model)
        : model_(model), win_(new Window(1, 1, 0, 0)), hex_mode_(false), focused_(false), hex_scroll_(0), tree_scroll_(0), total_tree_lines_(0)
    {
    }

    // ----------------------------------------------------------------------
    // Flatten the protocol tree into a flat list of printable lines.
    // Doing this once per render keeps render_tree() simple: it just
    // slices the vector with arithmetic, no recursion during drawing.
    // ----------------------------------------------------------------------
    void DetailPanel::flatten_node(const Node &node, int indent,
                                   std::vector<TreeLine> &out) const
    {
        char buf[256];

        // Protocol header line — use node.proto (not node.protocol)
        std::snprintf(buf, sizeof(buf),
                      "%*s[ %s ]", indent * 2, "", proto_name(node.protocol));
        out.push_back({std::string(buf), true});

        // One line per field
        for (const auto &field : node.fields)
        {
            std::snprintf(buf, sizeof(buf),
                          "%*s  %-16s %s",
                          indent * 2, "",
                          field.name.c_str(),
                          field.value.c_str());
            out.push_back({std::string(buf), false});
        }

        // Recurse into child layers (e.g. IPv4 inside Ethernet, TCP inside IPv4)
        for (const auto &child : node.children)
        {
            flatten_node(child, indent + 1, out);
        }
    }

    // ----------------------------------------------------------------------
    // Tree view
    // ----------------------------------------------------------------------
    void DetailPanel::render_tree()
    {
        const ProtocolTree &tree = model_.selected_tree();
        if (tree.empty())
        {
            win_->print(1, 2, "no dissection available", A_DIM);
            return;
        }

        std::vector<TreeLine> lines;
        flatten_node(tree.root, 0, lines);
        total_tree_lines_ = static_cast<int>(lines.size());

        int h = win_->height();
        int w = win_->width();
        int visible_rows = h - 2; // inside box borders

        // Clamp scroll so we never show blank space at the bottom
        int max_scroll = total_tree_lines_ - visible_rows;
        if (max_scroll < 0)
            max_scroll = 0;
        if (tree_scroll_ > max_scroll)
            tree_scroll_ = max_scroll;
        if (tree_scroll_ < 0)
            tree_scroll_ = 0;

        // Draw the visible slice
        for (int i = 0; i < visible_rows; ++i)
        {
            size_t idx = static_cast<size_t>(tree_scroll_ + i);
            if (idx >= lines.size())
            {
                break;
            }

            std::string text = lines[idx].text;
            if (static_cast<int>(text.size()) > w - 4)
            {
                text = text.substr(0, static_cast<size_t>(w - 4));
            }

            win_->print(i + 1, 2, text, lines[idx].bold ? A_BOLD : 0);
        }

        // Scroll indicator — only shown when content overflows the panel
        if (total_tree_lines_ > visible_rows)
        {
            char info[32];
            std::snprintf(info, sizeof(info),
                          " %d/%d ", tree_scroll_ + 1, max_scroll + 1);
            win_->print(h - 1,
                        w - static_cast<int>(std::strlen(info)) - 2,
                        info, A_DIM);
        }
    }

    // ----------------------------------------------------------------------
    // Hex dump view
    // ----------------------------------------------------------------------
    void DetailPanel::render_hex()
    {
        const std::vector<uint8_t> &raw = model_.selected_raw_bytes();
        if (raw.empty())
        {
            win_->print(1, 2, "no data", A_DIM);
            return;
        }

        int h = win_->height();
        int w = win_->width();
        int visible_rows = h - 2;

        const size_t bytes_per_row = 16;
        size_t total_rows = (raw.size() + bytes_per_row - 1) / bytes_per_row;

        // Clamp scroll
        if (hex_scroll_ < 0)
            hex_scroll_ = 0;
        if (static_cast<size_t>(hex_scroll_) >= total_rows && total_rows > 0)
            hex_scroll_ = static_cast<int>(total_rows - 1);

        for (int r = 0; r < visible_rows; ++r)
        {
            size_t row_idx = static_cast<size_t>(hex_scroll_ + r);
            if (row_idx >= total_rows)
            {
                break;
            }

            size_t byte_offset = row_idx * bytes_per_row;

            char offset_str[20];
            std::snprintf(offset_str, sizeof(offset_str), "%04zx  ", byte_offset);
            std::string line(offset_str);

            // Hex bytes (two groups of 8, separated by an extra space)
            for (size_t b = 0; b < bytes_per_row; ++b)
            {
                if (byte_offset + b < raw.size())
                {
                    char byte_str[4];
                    std::snprintf(byte_str, sizeof(byte_str),
                                  "%02x ", raw[byte_offset + b]);
                    line += byte_str;
                }
                else
                {
                    line += "   ";
                }
                if (b == 7)
                {
                    line += ' ';
                }
            }
            line += ' ';

            // ASCII column
            for (size_t b = 0; b < bytes_per_row; ++b)
            {
                if (byte_offset + b < raw.size())
                {
                    uint8_t byte = raw[byte_offset + b];
                    line += (byte >= 0x20 && byte < 0x7f)
                                ? static_cast<char>(byte)
                                : '.';
                }
            }

            if (static_cast<int>(line.size()) > w - 4)
                line = line.substr(0, static_cast<size_t>(w - 4));

            win_->print(r + 1, 2, line);
        }

        // Scroll indicator
        if (total_rows > static_cast<size_t>(visible_rows))
        {
            char info[32];
            std::snprintf(info, sizeof(info),
                          " %d/%zu ", hex_scroll_ + 1, total_rows);
            win_->print(h - 1,
                        w - static_cast<int>(std::strlen(info)) - 2,
                        info, A_DIM);
        }

        // Truncation notice (wire length > captured length)
        const ParsedPacket &pkt = model_.packet_at(model_.selected_index());
        if (pkt.length_cap < pkt.length_orig)
        {
            char notice[64];
            std::snprintf(notice, sizeof(notice),
                          " [truncated: wire=%u cap=%u] ",
                          pkt.length_orig, pkt.length_cap);
            win_->print(h - 1, 2, notice, A_DIM | COLOR_PAIR(colors::FILTER_ERR));
        }
    }

    // ----------------------------------------------------------------------
    // Main render entry point
    // ----------------------------------------------------------------------
    void DetailPanel::render()
    {
        win_->clear();

        // Draw border — bold when this panel has keyboard focus
        if (focused_)
        {
            wattron(win_->raw(), A_BOLD);
            win_->box();
            wattroff(win_->raw(), A_BOLD);
        }
        else
        {
            win_->box();
        }

        int h = win_->height();
        int w = win_->width();

        // Title inside the top border
        char title[64];
        if (model_.filtered_count() > 0)
        {
            std::snprintf(title, sizeof(title),
                          " %s — Packet #%zu ",
                          hex_mode_ ? "HEX DUMP" : "DETAIL",
                          model_.selected_index() + 1);
        }
        else
        {
            std::snprintf(title, sizeof(title), " DETAIL ");
        }
        win_->print(0, 2, title, A_BOLD);

        // Focus hint in top-right corner of the border
        if (focused_)
        {
            const char *hint = " [TAB to return] ";
            int hint_col = w - static_cast<int>(std::strlen(hint)) - 1;
            if (hint_col > static_cast<int>(std::strlen(title)) + 4)
            {
                win_->print(0, hint_col, hint, A_DIM);
            }
        }

        if (model_.filtered_count() == 0)
        {
            win_->print(h / 2, w / 2 - 5, "no packets", A_DIM);
            win_->refresh();
            return;
        }

        if (hex_mode_)
        {
            render_hex();
        }
        else
        {
            render_tree();
        }

        win_->refresh();
    }

    // ----------------------------------------------------------------------
    // Keyboard handling — only called when this panel has focus (or for 'h')
    // ----------------------------------------------------------------------
    bool DetailPanel::handle_key(int ch)
    {
        switch (ch)
        {
        case 'h':
            hex_mode_ = !hex_mode_;
            hex_scroll_ = 0;
            tree_scroll_ = 0;
            return true;

        case KEY_UP:
            if (hex_mode_)
            {
                if (hex_scroll_ > 0)
                {
                    --hex_scroll_;
                }
            }
            else
            {
                if (tree_scroll_ > 0)
                {
                    --tree_scroll_;
                }
            }
            return true;

        case KEY_DOWN:
            if (hex_mode_)
            {
                ++hex_scroll_;
            }
            else
            {
                ++tree_scroll_;
            }
            return true;

        case KEY_PPAGE:
        {
            int page = std::max(1, win_->height() - 2);
            if (hex_mode_)
            {
                hex_scroll_ -= page;
                if (hex_scroll_ < 0)
                {
                    hex_scroll_ = 0;
                }
            }
            else
            {
                tree_scroll_ -= page;
                if (tree_scroll_ < 0)
                {
                    tree_scroll_ = 0;
                }
            }
            return true;
        }

        case KEY_NPAGE:
        {
            int page = std::max(1, win_->height() - 2);
            if (hex_mode_)
            {
                hex_scroll_ += page;
            }
            else
            {
                tree_scroll_ += page;
            }
            return true;
        }

        case KEY_HOME:
            if (hex_mode_)
            {
                hex_scroll_ = 0;
            }
            else
            {
                tree_scroll_ = 0;
            }
            return true;

        case KEY_END:
            if (hex_mode_)
            {
                const std::vector<uint8_t> &raw = model_.selected_raw_bytes();
                const size_t bytes_per_row = 16;
                size_t total_rows =
                    (raw.size() + bytes_per_row - 1) / bytes_per_row;
                int page = win_->height() - 2;
                hex_scroll_ = (static_cast<int>(total_rows) > page)
                                  ? static_cast<int>(total_rows) - page
                                  : 0;
            }
            else
            {
                int page = win_->height() - 2;
                int max_scroll = total_tree_lines_ - page;
                tree_scroll_ = (max_scroll > 0) ? max_scroll : 0;
            }
            return true;

        default:
            return false;
        }
    }

    // ----------------------------------------------------------------------
    // Resize
    // ----------------------------------------------------------------------
    void DetailPanel::resize(int height, int width, int y, int x)
    {
        win_->resize(height, width, y, x);
    }

}