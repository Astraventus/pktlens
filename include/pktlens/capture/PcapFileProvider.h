#ifndef PKTLENS_PCAPFILEPROVIDER_H
#define PKTLENS_PCAPFILEPROVIDER_H

#include "PacketProvider.h"
#include <pcap/pcap.h>
#include <string>

namespace pktlens {

    class PcapFileProvider : public PacketProvider {
        private:
            pcap_t* handle_;
            std::string error_;

        public:
            explicit PcapFileProvider(const std::string& path);

            ~PcapFileProvider() override;

            // Class is non-copyable due to possible fatal errors with pcap_t* in case of mishandling
            PcapFileProvider(const PcapFileProvider&) = delete;
            PcapFileProvider& operator=(const PcapFileProvider&) = delete;

            bool next_packet(RawPacket& out) override;

            bool is_open() const { return handle_ != nullptr; }
            std::string error_message() const { return error_; }
    };
}

#endif