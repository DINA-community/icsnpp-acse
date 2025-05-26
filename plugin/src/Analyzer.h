#pragma once

#include <zeek/analyzer/protocol/tcp/TCP.h>
#include "asn1c/Association-data.h"

using namespace zeek;

namespace zeek::plugin::acse {
   
    class Analyzer : public zeek::analyzer::Analyzer {
        public:
            explicit Analyzer(const char *name, zeek::Connection* conn);
            void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const zeek::IP_Hdr* ip, int caplen);

            static Analyzer* Instantiate(const char* name, zeek::Connection* conn) { return new Analyzer(name, conn); }

        private:
            void extract_payload_and_forward(IntrusivePtr<RecordVal> pdu, bool orig);
            void forward(IntrusivePtr<IntVal> cid, IntrusivePtr<StringVal> data, bool orig);

    };

} // namespace zeek::plugin::acse
