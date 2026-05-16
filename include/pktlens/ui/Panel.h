#ifndef PKTLENS_PANEL_H
#define PKTLENS_PANEL_H

#include "Window.h"

namespace pktlens
{

    // Abstract panel interface.
    // Each panel owns a Window and knows how to draw itself and handle keys.
    class Panel
    {
    public:
        virtual void render() = 0;
        virtual bool handle_key(int ch) = 0; // returns true if key was consumed
        virtual void resize(int height, int width, int y, int x) = 0;
        virtual ~Panel() = default;
    };

    // Color pair indices.
    // Indexed by ProtoId where applicable.
    namespace colors
    {
        static const int HEADER_BAR = 1;
        static const int STATUS_BAR = 2;
        static const int SELECTED = 3;
        static const int PROTO_TCP = 4;
        static const int PROTO_UDP = 5;
        static const int PROTO_DNS = 6;
        static const int PROTO_HTTP = 7;
        static const int PROTO_ICMP = 8;
        static const int PROTO_ARP = 9;
        static const int PROTO_OTHER = 10;
        static const int FILTER_ERR = 11;
    }

}

#endif