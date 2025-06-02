module acse;

global aarq_apdu: event(c: connection, is_orig: bool, apdu: AARQ_apdu);
global aare_apdu: event(c: connection, is_orig: bool, apdu: AARE_apdu);
global rlrq_apdu: event(c: connection, is_orig: bool, apdu: RLRQ_apdu);
global rlre_apdu: event(c: connection, is_orig: bool, apdu: RLRE_apdu);
global abrt_apdu: event(c: connection, is_orig: bool, apdu: ABRT_apdu);
global adt_apdu:  event(c: connection, is_orig: bool, apdu: A_DT_apdu);
global acrq_apdu: event(c: connection, is_orig: bool, apdu: ACRQ_apdu);
global acrp_apdu: event(c: connection, is_orig: bool, apdu: ACRP_apdu);

event acse::acse_apdu(c: connection, is_orig: bool, apdu: ACSE_apdu) {
	if(apdu ?$ aarq) {
		event aarq_apdu(c, is_orig, apdu $ aarq);
	} else if(apdu ?$ aare) {
		event aare_apdu(c, is_orig, apdu $ aare);
	} else if(apdu ?$ rlrq) {
		event rlrq_apdu(c, is_orig, apdu $ rlrq);
	} else if(apdu ?$ rlre) {
		event rlre_apdu(c, is_orig, apdu $ rlre);
	} else if(apdu ?$ abrt) {
		event abrt_apdu(c, is_orig, apdu $ abrt);
	} else if(apdu ?$ adt) {
		event adt_apdu(c, is_orig, apdu $ adt);
	} else if(apdu ?$ acrq) {
		event acrq_apdu(c, is_orig, apdu $ acrq);
	} else if(apdu ?$ acrp) {
		event acrp_apdu(c, is_orig, apdu $ acrp);
	}
}
