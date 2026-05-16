#ifndef PKTLENS_DETAILPANEL_H
#define PKTLENS_DETAILPANEL_H

#include "Panel.h"
#include "pktlens/session/SessionModel.h"
#include <memory>
#include <vector>
#include <string>

namespace pktlens
{

    class DetailPanel : public Panel
    {
    public:
        explicit DetailPanel(SessionModel &model);

        void render() override;
        bool handle_key(int ch) override;
        void resize(int height, int width, int y, int x) override;

        bool hex_mode() const { return hex_mode_; }

        // Called by App before render() so the panel can draw its border accordingly
        void set_focused(bool f) { focused_ = f; }

    private:
        SessionModel &model_;
        std::unique_ptr<Window> win_;

        bool hex_mode_;
        bool focused_;
        int hex_scroll_;
        int tree_scroll_;
        int total_tree_lines_; // set by render_tree(), read by handle_key() for KEY_END

        struct TreeLine
        {
            std::string text;
            bool bold;
        };

        void flatten_node(const Node &node, int indent,
                          std::vector<TreeLine> &out) const;

        void render_tree();
        void render_hex();
    };

}

#endif