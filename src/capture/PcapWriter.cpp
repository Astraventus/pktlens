#include "pktlens/capture/PcapWriter.h"

#include <pcap/pcap.h>
#include <cstring>  // memset

namespace pktlens {

    PcapWriter::PcapWriter(const std::string& path, int link_type)
        : handle_(nullptr)
        , dumper_(nullptr)
        , count_(0)
    {
        // pcap_open_dead() creates a dummy pcap_t* with no live capture behind it.
        // snaplen 65535 is the conventional "capture everything" value.
        handle_ = pcap_open_dead(link_type, 65535);
        if (handle_ == nullptr) {
            error_ = "pcap_open_dead() failed (out of memory?)";
            return;
        }

        // pcap_dump_open() opens the output file and writes the pcap global header.
        dumper_ = pcap_dump_open(handle_, path.c_str());
        if (dumper_ == nullptr) {
            error_ = pcap_geterr(handle_);
            pcap_close(handle_);
            handle_ = nullptr;
            return;
        }
    }

    PcapWriter::~PcapWriter() {
        if (dumper_ != nullptr) {
            pcap_dump_close(dumper_);
            dumper_ = nullptr;
        }
        if (handle_ != nullptr) {
            pcap_close(handle_);
            handle_ = nullptr;
        }
    }

    bool PcapWriter::write_packet(const std::vector<uint8_t>& raw_bytes,
                                  double   timestamp,
                                  uint32_t orig_len)
    {
        if (dumper_ == nullptr) {
            return false;
        }

        // Build a pcap_pkthdr from our stored metadata.
        struct pcap_pkthdr hdr;
        memset(&hdr, 0, sizeof(hdr));

        // Split the fractional timestamp into seconds and microseconds.
        hdr.ts.tv_sec  = static_cast<time_t>(timestamp);
        hdr.ts.tv_usec = static_cast<suseconds_t>(
            (timestamp - static_cast<double>(hdr.ts.tv_sec)) * 1e6 + 0.5);

        hdr.caplen = static_cast<bpf_u_int32>(raw_bytes.size());
        hdr.len    = orig_len;

        // pcap_dump() writes one packet record (header + bytes) to the file.
        // It does not return an error code — failures are silent at this level.
        // Callers can detect them via pcap_dump_flush() if needed, but for our
        // use case (bulk file write, checked at open time) this is sufficient.
        pcap_dump(reinterpret_cast<u_char*>(dumper_),
                  &hdr,
                  raw_bytes.data());

        ++count_;
        return true;
    }

}  // namespace pktlens