# @TEST-DOC: Test Zeek parsing a trace file through the acse analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/accept.pcap ${PACKAGE} %INPUT >accept
# @TEST-EXEC: btest-diff accept
# @TEST-EXEC: mv acse.log accept.log; btest-diff accept.log
#
#
# @TEST-EXEC: zeek -Cr ${TRACES}/refuse.pcapng ${PACKAGE} %INPUT >refuse
# @TEST-EXEC: btest-diff refuse
# @TEST-EXEC: mv acse.log refuse.log; btest-diff refuse.log
#

module acse;

event zeek_init() &priority=5 {
    # the script of tpkt is not loaded even if the tpkt plugin is installed
    Analyzer::register_for_port(Analyzer::ANALYZER_TPKT, 102/tcp);
}

event acse::acse_apdu(c: connection, is_orig: bool, apdu: ACSE_apdu) {
  print("Testing acse: "+cat(apdu)+"\n");
}
