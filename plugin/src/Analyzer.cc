#include <utility>
#include <map>
#include <vector>

#include <zeek/analyzer/Manager.h>

#include "Analyzer.h"
#include "Plugin.h"
#include "process.h"

#define CONTEXT_TABLE_NAME "iso_pres_context_identifier"

using namespace zeek;

namespace zeek::plugin::acse {

Analyzer::Analyzer(const char* name, zeek::Connection* c) : zeek::analyzer::Analyzer(name, c) {}

void Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t, const IP_Hdr*, int) {
    static const auto event = event_registry->Lookup(ACSE_PDU_EVENT);

    ACSE_apdu *pdu_raw = NULL;
    auto desc = &asn_DEF_ACSE_apdu;

    asn_dec_rval_t rval = ber_decode(nullptr, desc, reinterpret_cast<void**>(&pdu_raw), data, len);
    if(rval.code != RC_OK) {
        Weird("acse_parse_error", "unable to parse packet");
        return;
    }
    // For debugging purposes
    //asn_fprint(stdout, desc, pdu_raw);

    char errbuf[128];
    size_t errlen = sizeof(errbuf)/sizeof(errbuf[0]);
    if(asn_check_constraints(desc, pdu_raw, errbuf, &errlen)) {
        Weird("acse_constraint_error", errbuf);
        desc->free_struct(desc, pdu_raw, 0);
        return;
    }

    auto pdu=cast_intrusive<RecordVal>(process_ACSE_apdu(pdu_raw));
    desc->free_struct(desc, pdu_raw, 0);

    extract_payload_and_forward(pdu, orig);
    EnqueueConnEvent(event, ConnVal(), val_mgr->Bool(orig), pdu);
}

void Analyzer::extract_payload_and_forward(IntrusivePtr<RecordVal> pdu, bool orig) {

    /* user information are stored in the field "user-information",
     * except for A-DT-apdu. There it is named "a-user-data".
     */
    auto *_type=pdu->GetType()->AsRecordType();
    for(int i=0; i<_type->NumFields(); i++) {
        if(!pdu->HasField(i))
            continue;
        auto *rec=pdu->GetFieldAs<RecordVal>(i);

        const char* fieldname;
        if(rec->HasField("user_information")) {
            fieldname="user_information";
        } else if(rec->HasField("a_user_data")) {
            fieldname="a_user_data";
        } else {
            /* user information are optional.
             * So it is perfectly fine if we don't find any.
             */
            continue;
        }
        auto user_info=rec->GetFieldAs<VectorVal>(fieldname);

        for(unsigned int j=0; j<user_info->Size(); j++) {
            auto ext=user_info->RecordValAt(j);
            
            if(!ext->HasField("indirect_reference")) {
                Weird("acse_no_indirect_reference_found", "No indirect reference found");
                continue;
            }
            auto cid=cast_intrusive<IntVal>(ext->GetField("indirect_reference"));
            
            if(!ext->HasField("encoding")) {
                Weird("acse_no_encoding", "no encoding found");
                continue;
            }
            auto encoding=ext->GetFieldAs<RecordVal>("encoding");

            /* 
             * It is not an error per se if no ASN1 decoding is used.
             * However, this is so atypical that we consider it weird.
             */
            if(!encoding->HasField("single_ASN1_type")) {
                Weird("acse_unsupported_encoding", "Unsupported encoding");
                continue;
            }
            auto data=cast_intrusive<StringVal>(encoding->GetField("single_ASN1_type"));

            forward(cid, data, orig);
        }
    }

}

void Analyzer::forward(IntrusivePtr<IntVal> cid, IntrusivePtr<StringVal> data, bool orig) {
    /* ACSE is only used over ISO 8823 otherwise we
       wouldn't know what to do with the payload */
    auto *table=ConnVal()->GetField(CONTEXT_TABLE_NAME)->AsTableVal();
    if(!table)
        return;
    auto oid=table->Find(cid);
    if(!oid) {
        Weird("acse_unknown_context_id", "unknown context id");
        return;
    }

    std::string analyzer_name = util::canonify_name("ISO:" + oid->AsStringVal()->ToStdString());
    auto *analyzer=FindChild(analyzer_name.c_str());
    if(!analyzer) {
        analyzer=analyzer_mgr->InstantiateAnalyzer(analyzer_name.c_str(), Conn());
        /* it is totally OK if we don't have a suitable analyzer */
        if(!analyzer)
            return;
        AddChildAnalyzer(analyzer);
    }
    analyzer->NextPacket(data->Len(), data->Bytes(), orig);
}

} // namespace zeek::plugin::acse
