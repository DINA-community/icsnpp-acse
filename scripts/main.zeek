module acse;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:                  time       &log;
        uid:                 string     &log;
        id:                  conn_id    &log;
        context_name:        string     &log &optional;
        calling_ap_title:    string     &log &optional;
        called_ap_title:     string     &log &optional;
        auth_mechanism:      string     &log &optional;
        result:              string     &log;
        diag:                string     &log &optional;
    };
}

redef record connection += {
    acse_aarq_apdu: AARQ_apdu &optional;
};

function ap_title_to_str(title: AP_title): string {
    if(title ?$ ap_title_form1) {
        return cat(title $ ap_title_form1);
    } else if(title ?$ ap_title_form2) {
        return title $ ap_title_form2;
    } else if(title ?$ ap_title_form3) {
        return title $ ap_title_form3;
    } else {
        return "<UNKNOWN>";
    }
}

event zeek_init() &priority=5 {
    Log::create_stream(LOG, [
        $columns=Info,
        $path="acse",
    ]);
}

event aarq_apdu(c: connection, is_orig: bool, apdu: AARQ_apdu) {
    c $ acse_aarq_apdu = apdu;
}

event aare_apdu(c: connection, is_orig: bool, aare: AARE_apdu) {
    local info: Info = [
        $ts =  network_time(),
        $uid = c $ uid,
        $id = c $ id,
        $context_name = aare $ aSO_context_name,
        $result = split_string1(cat(aare $ result), /::/)[-1]
    ];

    if(c ?$ acse_aarq_apdu && c $ acse_aarq_apdu ?$ calling_AP_title)
        info $ calling_ap_title = ap_title_to_str(c$acse_aarq_apdu $ calling_AP_title);

    # if the responding ap is different from the called ap the answering ap is logged
    if(aare ?$ responding_AP_title) {
        info $ called_ap_title = ap_title_to_str(aare $ responding_AP_title);
    } else if(c ?$ acse_aarq_apdu && c $ acse_aarq_apdu ?$ called_AP_title) {
        info $ called_ap_title = ap_title_to_str(c $ acse_aarq_apdu $ called_AP_title);
    }

    if(aare ?$ mechanism_name)
        info $ auth_mechanism = aare $ mechanism_name;
    if(aare ?$ result_source_diagnostic && aare $ result_source_diagnostic $ service_user != acse::null)
        info $ diag = cat(aare $ result_source_diagnostic $ service_user);

    Log::write(LOG, info);
}
