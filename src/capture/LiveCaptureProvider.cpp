#include "pktlens/capture/LiveCaptureProvider.h"

namespace pktlens {

    LiveCaptureProvider::LiveCaptureProvider(const std::string& interface,
                                             int snaplen,
                                             int promisc,
                                             int timeout_ms)
        : handle_(nullptr)
        , interface_(interface)
        , stop_requested_(false)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        errbuf[0] = '\0';

        handle_ = pcap_open_live(interface.c_str(),
                                 snaplen,
                                 promisc,
                                 timeout_ms,
                                 errbuf);

        if (handle_ == nullptr) {
            error_ = errbuf;
            // On Linux, a permission failure comes through errbuf as
            // "eth0: You don't have permission to capture on that device
            //  (socket: Operation not permitted)"
            // The caller (App) is responsible for printing the setcap hint.
        } else if (errbuf[0] != '\0') {
            // Non-fatal warning (e.g. "promiscuous mode was not enabled")
            // Store it but keep handle_ — capture is still functional.
            error_ = errbuf;
        }
    }

    LiveCaptureProvider::~LiveCaptureProvider()
    {
        if (handle_ != nullptr) {
            pcap_close(handle_);
            handle_ = nullptr;
        }
    }

    void LiveCaptureProvider::stop()
    {
        stop_requested_.store(true, std::memory_order_relaxed);
    }

    bool LiveCaptureProvider::next_packet(RawPacket& out)
    {
        if (handle_ == nullptr) {
            return false;
        }

        // Check stop flag before every call so the capture thread unblocks
        // as soon as possible after stop() is called.
        if (stop_requested_.load(std::memory_order_relaxed)) {
            return false;
        }

        struct pcap_pkthdr* header = nullptr;
        const u_char*       data   = nullptr;

        int result = pcap_next_ex(handle_, &header, &data);

        // result == 1  → packet available
        // result == 0  → timeout (no packet within timeout_ms) — keep going
        // result == -1 → error
        // result == -2 → EOF (only on offline handles, not live)

        if (result == 1) {
            out.data      = reinterpret_cast<const uint8_t*>(data);
            out.caplen    = header->caplen;
            out.origlen   = header->len;
            out.timestamp = static_cast<double>(header->ts.tv_sec)
                          + static_cast<double>(header->ts.tv_usec) * 1e-6;
            return true;
        }

        if (result == 0) {
            // Timeout — no packet yet. Return true so the capture loop continues.
            // The caller should check stop_requested on the next iteration,
            // which next_packet() handles at the top of this function.
            return !stop_requested_.load(std::memory_order_relaxed);
        }

        // result == -1: fatal error
        error_ = pcap_geterr(handle_);
        return false;
    }

}  // namespace pktlens