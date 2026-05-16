#include "pktlens/ui/App.h"
#include <cstdio>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: pktlens <file.pcap>\n");
        return 1;
    }

    if (argc == 2) {
        std::string arg(argv[1]);
        if (arg == "--help" || arg == "-h") {
            std::fprintf(stdout,
                "pktlens — terminal pcap viewer\n"
                "usage: pktlens <file.pcap>\n\n"
                "keys: ↑↓ navigate  / filter  Esc clear  "
                "s sort  r reverse  h hex  q quit\n");
            return 0;
        }
        if (arg == "--version" || arg == "-v") {
            std::fprintf(stdout, "pktlens 1.0.0\n");
            return 0;
        }
    }

    pktlens::App app(argv[1]);
    return app.run();
}