#ifndef PKTLENS_APP_H
#define PKTLENS_APP_H

#include "TerminalGuard.h"
#include "PacketListPanel.h"
#include "DetailPanel.h"
#include "FilterBar.h"
#include "pktlens/session/SessionModel.h"
#include <string>

namespace pktlens
{

    class App
    {
    public:
        explicit App(const std::string &filename);

        // Returns exit code
        int run();

    private:
        enum class Focus
        {
            List,
            Detail
        };

        std::string filename_;
        SessionModel model_;
        TerminalGuard term_;

        PacketListPanel *list_panel_;
        DetailPanel *detail_panel_;
        FilterBar *filter_bar_;

        bool running_;
        Focus focus_;

        void layout();
        void render_header();
        void render_all();
        void handle_key(int ch);
    };

}

#endif