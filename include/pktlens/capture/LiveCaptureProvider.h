#ifndef PKTLENS_LIVECAPTUREPROVIDER_H
#define PKTLENS_LIVECAPTUREPROVIDER_H

#include "PacketProvider.h"
#include <pcap/pcap.h>
#include <string>
#include <atomic>

namespace pktlens {

    // PacketProvider implementation backed by a live network interface.
    //
    // Uses pcap_open_live() instead of pcap_open_offline(); everything
    // downstream (dissectors, PacketStore, SessionModel) is identical —
    // that is the payoff of the PacketProvider abstraction.
    //
    // next_packet() blocks for up to timeout_ms then returns true (timeout,
    // keep going) or false (stop() called, or unrecoverable error).
    // It never returns false on a mere timeout, so the capture thread loop is:
    //
    //     while (provider.next_packet(raw)) {
    //         // process raw …
    //     }
    //     // here: stop() was called or pcap reported a fatal error
    //
    class LiveCaptureProvider : public PacketProvider {
    public:
        // Opens the interface for live capture.
        // On failure is_open() returns false and error_message() explains why.
        //
        //   interface  — e.g. "eth0", "wlan0", "any"
        //   snaplen    — max bytes captured per packet (65535 = whole packet)
        //   promisc    — 1 = promiscuous mode, 0 = own traffic only
        //   timeout_ms — pcap read timeout; controls heartbeat cadence
        explicit LiveCaptureProvider(const std::string& interface,
                                     int snaplen    = 65535,
                                     int promisc    = 1,
                                     int timeout_ms = 100);

        ~LiveCaptureProvider() override;

        // Non-copyable — owns pcap_t*
        LiveCaptureProvider(const LiveCaptureProvider&)            = delete;
        LiveCaptureProvider& operator=(const LiveCaptureProvider&) = delete;

        // Pull one packet.
        // Returns true and fills 'out' when a packet arrives.
        // Returns true (out untouched) on timeout — keep calling.
        // Returns false only when stop() has been called or on a fatal pcap error.
        bool next_packet(RawPacket& out) override;

        // Request a graceful stop. next_packet() will return false after the
        // current pcap_next_ex() call completes (up to timeout_ms).
        void stop();

        bool        is_open()        const { return handle_ != nullptr; }
        std::string error_message()  const { return error_; }
        std::string interface_name() const { return interface_; }

    private:
        pcap_t*            handle_;
        std::string        interface_;
        std::string        error_;
        std::atomic<bool>  stop_requested_;
    };

}  // namespace pktlens

#endif  // PKTLENS_LIVECAPTUREPROVIDER_H