/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "ACSE"
 * 	found in "../../../../utils/acse.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_Release_request_reason_H_
#define	_Release_request_reason_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Release_request_reason {
	Release_request_reason_normal	= 0,
	Release_request_reason_urgent	= 1,
	Release_request_reason_user_defined	= 30
} e_Release_request_reason;

/* Release-request-reason */
typedef long	 Release_request_reason_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Release_request_reason;
asn_struct_free_f Release_request_reason_free;
asn_struct_print_f Release_request_reason_print;
asn_constr_check_f Release_request_reason_constraint;
ber_type_decoder_f Release_request_reason_decode_ber;
der_type_encoder_f Release_request_reason_encode_der;
xer_type_decoder_f Release_request_reason_decode_xer;
xer_type_encoder_f Release_request_reason_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _Release_request_reason_H_ */
#include <asn_internal.h>
