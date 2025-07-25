/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "ACSE"
 * 	found in "../../../../utils/acse.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_EXTERNALt_H_
#define	_EXTERNALt_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OBJECT_IDENTIFIER.h>
#include <NativeInteger.h>
#include <ObjectDescriptor.h>
#include <ANY.h>
#include <OCTET_STRING.h>
#include <BIT_STRING.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum EXTERNALt__encoding_PR {
	EXTERNALt__encoding_PR_NOTHING,	/* No components present */
	EXTERNALt__encoding_PR_single_ASN1_type,
	EXTERNALt__encoding_PR_octet_aligned,
	EXTERNALt__encoding_PR_arbitrary
} EXTERNALt__encoding_PR;

/* EXTERNALt */
typedef struct EXTERNALt {
	OBJECT_IDENTIFIER_t	*direct_reference	/* OPTIONAL */;
	long	*indirect_reference	/* OPTIONAL */;
	ObjectDescriptor_t	*data_value_descriptor	/* OPTIONAL */;
	struct EXTERNALt__encoding {
		EXTERNALt__encoding_PR present;
		union EXTERNALt__encoding_u {
			ANY_t	 single_ASN1_type;
			OCTET_STRING_t	 octet_aligned;
			BIT_STRING_t	 arbitrary;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} encoding;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} EXTERNALt_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_EXTERNALt;

#ifdef __cplusplus
}
#endif

#endif	/* _EXTERNALt_H_ */
#include <asn_internal.h>
