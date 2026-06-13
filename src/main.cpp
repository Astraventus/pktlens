#include "pktlens/ui/App.h"
#include <pcap/pcap.h>
#include <cstdio>
#include <cstring>
#include <string>

// ---------------------------------------------------------------------------
// --list-interfaces
// ---------------------------------------------------------------------------
static void list_interfaces()
{
    pcap_if_t* devs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&devs, errbuf) == -1) {
        std::fprintf(stderr, "pktlens: cannot enumerate interfaces: %s\n", errbuf);
        return;
    }

    for (pcap_if_t* d = devs; d != nullptr; d = d->next) {
        const char* desc = (d->description && d->description[0])
                           ? d->description : "(no description)";
        std::fprintf(stdout, "%-16s %s\n", d->name, desc);
    }

    pcap_freealldevs(devs);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::fprintf(stderr,
            "usage: pktlens <file.pcap>\n"
            "       pktlens -i <interface>\n"
            "       pktlens --list-interfaces\n");
        return 1;
    }

    std::string arg1(argv[1]);

    // ── Informational flags ─────────────────────────────────────────────────

    if (arg1 == "--help" || arg1 == "-h") {
        std::fprintf(stdout,
            "pktlens v2.0 — terminal pcap viewer and live capture tool\n\n"
            "usage:\n"
            "  pktlens <file.pcap>          open a capture file\n"
            "  pktlens -i <interface>       live capture on an interface\n"
            "  pktlens --list-interfaces    print available interfaces\n\n"
            "keys (file mode):\n"
            "  \xe2\x86\x91\xe2\x86\x93        navigate packets\n"
            "  Tab       switch focus list \xe2\x86\x94 detail\n"
            "  /         open filter input\n"
            "  Esc       clear active filter\n"
            "  s         cycle sort field (time/size/proto)\n"
            "  r         reverse sort direction\n"
            "  h         toggle hex dump\n"
            "  w         export visible packets to pcap file\n"
            "  q         quit\n\n"
            "keys (live mode, additional):\n"
            "  Space     pause / resume display\n"
            "  G         jump to latest packet, resume auto-scroll\n");
        return 0;
    }

    if (arg1 == "--version" || arg1 == "-v") {
        std::fprintf(stdout, "pktlens 2.0.0\n");
        return 0;
    }

    if (arg1 == "--list-interfaces") {
        list_interfaces();
        return 0;
    }

    // ── Live capture: pktlens -i <interface> ───────────────────────────────

    if (arg1 == "-i") {
        if (argc < 3) {
            std::fprintf(stderr,
                "pktlens: -i requires an interface name\n"
                "usage: pktlens -i <interface>\n"
                "       pktlens --list-interfaces\n");
            return 1;
        }
        std::string iface(argv[2]);
        pktlens::App app(iface, true /*live_tag*/);
        return app.run();
    }

    // ── File mode: pktlens <file.pcap> ─────────────────────────────────────

    pktlens::App app(arg1);
    return app.run();
}