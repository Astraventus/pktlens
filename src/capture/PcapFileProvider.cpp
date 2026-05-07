#include "pktlens/capture/PcapFileProvider.h"

namespace pktlens {

    PcapFileProvider::PcapFileProvider(const std::string& path) : handle_(nullptr) {
        char errbuf[PCAP_ERRBUF_SIZE];
        errbuf[0] = '\0';

        handle_ = pcap_open_offline(path.c_str(), errbuf);

        if (handle_ == nullptr) {
            error_ = errbuf;
        }
    }

    PcapFileProvider::~PcapFileProvider() {
        if (handle_ != nullptr) {
            pcap_close(handle_);
            handle_ = nullptr;
        }
    }

    bool PcapFileProvider::next_packet(RawPacket& out) {
        if (handle_ == nullptr) {
            return false;
        }

        struct pcap_pkthdr* header = nullptr;
        const u_char* data = nullptr;

        int result = pcap_next_ex(handle_, &header, &data);

        if (result != 1) {
            return false;
        }

        out.data = reinterpret_cast<const uint8_t*>(data);
        out.caplen = header->caplen;
        out.origlen = header->len;
        out.timestamp = static_cast<double>(header->ts.tv_sec) + static_cast<double>(header->ts.tv_usec) * 1e-6;

        return true;
    }
}