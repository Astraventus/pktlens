#include "pktlens/capture/CaptureThread.h"
#include "pktlens/capture/RawPacket.h"
#include "pktlens/dissectors/DissectorRegistry.h"
#include "pktlens/model/ParsedPacket.h"
#include "pktlens/model/ProtocolTree.h"
#include <stdexcept>
#include <vector>

namespace pktlens {

    CaptureThread::CaptureThread(LiveCaptureProvider& provider,
                                 SessionModel&        model)
        : provider_(provider)
        , model_(model)
        , has_error_(false)
    {}

    CaptureThread::~CaptureThread()
    {
        join();
    }

    void CaptureThread::start()
    {
        thread_ = std::thread(&CaptureThread::run, this);
    }

    void CaptureThread::join()
    {
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    void CaptureThread::run()
    {
        try {
            RawPacket raw;

            // next_packet() returns false only when stop() was called or a
            // fatal pcap error occurs — never on a mere timeout (result == 0).
            while (provider_.next_packet(raw)) {

                // Copy raw bytes immediately: raw.data is only valid until the
                // next pcap_next_ex() call.
                std::vector<uint8_t> raw_bytes(raw.data, raw.data + raw.caplen);

                // Dissect on the capture thread — no lock needed for the tree
                // since it is local and discarded right here.
                ParsedPacket pkt;
                ProtocolTree tree;  // discarded after dissection
                dissect(raw, pkt, tree, ctx_);

                // append() acquires the SessionModel mutex internally.
                model_.append_packet(pkt, std::move(raw_bytes));
            }

        } catch (const std::exception& ex) {
            has_error_.store(true);
            error_ = ex.what();
        } catch (...) {
            has_error_.store(true);
            error_ = "unknown exception in capture thread";
        }
    }

}  // namespace pktlens