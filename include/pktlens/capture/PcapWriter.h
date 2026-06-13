#ifndef PKTLENS_PCAPWRITER_H
#define PKTLENS_PCAPWRITER_H

#include <pcap/pcap.h>
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

namespace pktlens {

    // Writes packets to a pcap file using the standard libpcap pattern:
    //   pcap_open_dead() + pcap_dump_open() + pcap_dump() + pcap_dump_close()
    //
    // Zero UI dependency — pure engine layer.
    class PcapWriter {
    public:
        // Open a pcap file for writing.
        // link_type: pcap datalink type (DLT_EN10MB = 1 for Ethernet).
        // On failure, is_open() returns false and error_message() explains why.
        explicit PcapWriter(const std::string& path,
                            int link_type = DLT_EN10MB);

        ~PcapWriter();  // closes file if open

        // Non-copyable — owns the pcap handles
        PcapWriter(const PcapWriter&)            = delete;
        PcapWriter& operator=(const PcapWriter&) = delete;

        // Write one packet. raw_bytes contains the complete captured frame.
        // timestamp is seconds since epoch (fractional).
        // orig_len is the wire length (may differ from raw_bytes.size() if the
        // capture was truncated).
        // Returns false on write error.
        bool write_packet(const std::vector<uint8_t>& raw_bytes,
                          double   timestamp,
                          uint32_t orig_len);

        bool        is_open()        const { return dumper_ != nullptr; }
        std::string error_message()  const { return error_; }
        size_t      packets_written() const { return count_; }

    private:
        pcap_t*       handle_;   // dummy handle created by pcap_open_dead()
        pcap_dumper_t* dumper_;  // file handle created by pcap_dump_open()
        std::string   error_;
        size_t        count_;
    };

}  // namespace pktlens

#endif  // PKTLENS_PCAPWRITER_H