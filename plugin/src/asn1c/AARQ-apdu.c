/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "ACSE"
 * 	found in "../../../../utils/acse.asn"
 * 	`asn1c -fcompound-names`
 */

#include "AARQ-apdu.h"

static asn_TYPE_member_t asn_MBR_AARQ_apdu_1[] = {
	{ ATF_POINTER, 1, offsetof(struct AARQ_apdu, protocol_version),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"protocol-version"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AARQ_apdu, aSO_context_name),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_ASO_context_name,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"aSO-context-name"
		},
	{ ATF_POINTER, 17, offsetof(struct AARQ_apdu, called_AP_title),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_AP_title,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"called-AP-title"
		},
	{ ATF_POINTER, 16, offsetof(struct AARQ_apdu, called_AE_qualifier),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_AE_qualifier,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"called-AE-qualifier"
		},
	{ ATF_POINTER, 15, offsetof(struct AARQ_apdu, called_AP_invocation_identifier),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_AP_invocation_identifier,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"called-AP-invocation-identifier"
		},
	{ ATF_POINTER, 14, offsetof(struct AARQ_apdu, called_AE_invocation_identifier),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_AE_invocation_identifier,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"called-AE-invocation-identifier"
		},
	{ ATF_POINTER, 13, offsetof(struct AARQ_apdu, calling_AP_title),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_AP_title,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"calling-AP-title"
		},
	{ ATF_POINTER, 12, offsetof(struct AARQ_apdu, calling_AE_qualifier),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_AE_qualifier,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"calling-AE-qualifier"
		},
	{ ATF_POINTER, 11, offsetof(struct AARQ_apdu, calling_AP_invocation_identifier),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_AP_invocation_identifier,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"calling-AP-invocation-identifier"
		},
	{ ATF_POINTER, 10, offsetof(struct AARQ_apdu, calling_AE_invocation_identifier),
		(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_AE_invocation_identifier,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"calling-AE-invocation-identifier"
		},
	{ ATF_POINTER, 9, offsetof(struct AARQ_apdu, sender_acse_requirements),
		(ASN_TAG_CLASS_CONTEXT | (10 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ACSE_requirements,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"sender-acse-requirements"
		},
	{ ATF_POINTER, 8, offsetof(struct AARQ_apdu, mechanism_name),
		(ASN_TAG_CLASS_CONTEXT | (11 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Mechanism_name,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"mechanism-name"
		},
	{ ATF_POINTER, 7, offsetof(struct AARQ_apdu, calling_authentication_value),
		(ASN_TAG_CLASS_CONTEXT | (12 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_Authentication_value,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"calling-authentication-value"
		},
	{ ATF_POINTER, 6, offsetof(struct AARQ_apdu, aSO_context_name_list),
		(ASN_TAG_CLASS_CONTEXT | (13 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ASO_context_name_list,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"aSO-context-name-list"
		},
	{ ATF_POINTER, 5, offsetof(struct AARQ_apdu, implementation_information),
		(ASN_TAG_CLASS_CONTEXT | (29 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Implementation_data,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"implementation-information"
		},
	{ ATF_POINTER, 4, offsetof(struct AARQ_apdu, p_context_definition_list),
		(ASN_TAG_CLASS_CONTEXT | (14 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_Syntactic_context_list,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"p-context-definition-list"
		},
	{ ATF_POINTER, 3, offsetof(struct AARQ_apdu, called_asoi_tag),
		(ASN_TAG_CLASS_CONTEXT | (15 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ASOI_tag,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"called-asoi-tag"
		},
	{ ATF_POINTER, 2, offsetof(struct AARQ_apdu, calling_asoi_tag),
		(ASN_TAG_CLASS_CONTEXT | (16 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ASOI_tag,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"calling-asoi-tag"
		},
	{ ATF_POINTER, 1, offsetof(struct AARQ_apdu, user_information),
		(ASN_TAG_CLASS_CONTEXT | (30 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Association_data,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"user-information"
		},
};
static const ber_tlv_tag_t asn_DEF_AARQ_apdu_tags_1[] = {
	(ASN_TAG_CLASS_APPLICATION | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_AARQ_apdu_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* protocol-version */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* aSO-context-name */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* called-AP-title */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* called-AE-qualifier */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* called-AP-invocation-identifier */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* called-AE-invocation-identifier */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* calling-AP-title */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* calling-AE-qualifier */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 }, /* calling-AP-invocation-identifier */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 9, 0, 0 }, /* calling-AE-invocation-identifier */
    { (ASN_TAG_CLASS_CONTEXT | (10 << 2)), 10, 0, 0 }, /* sender-acse-requirements */
    { (ASN_TAG_CLASS_CONTEXT | (11 << 2)), 11, 0, 0 }, /* mechanism-name */
    { (ASN_TAG_CLASS_CONTEXT | (12 << 2)), 12, 0, 0 }, /* calling-authentication-value */
    { (ASN_TAG_CLASS_CONTEXT | (13 << 2)), 13, 0, 0 }, /* aSO-context-name-list */
    { (ASN_TAG_CLASS_CONTEXT | (14 << 2)), 15, 0, 0 }, /* p-context-definition-list */
    { (ASN_TAG_CLASS_CONTEXT | (15 << 2)), 16, 0, 0 }, /* called-asoi-tag */
    { (ASN_TAG_CLASS_CONTEXT | (16 << 2)), 17, 0, 0 }, /* calling-asoi-tag */
    { (ASN_TAG_CLASS_CONTEXT | (29 << 2)), 14, 0, 0 }, /* implementation-information */
    { (ASN_TAG_CLASS_CONTEXT | (30 << 2)), 18, 0, 0 } /* user-information */
};
static asn_SEQUENCE_specifics_t asn_SPC_AARQ_apdu_specs_1 = {
	sizeof(struct AARQ_apdu),
	offsetof(struct AARQ_apdu, _asn_ctx),
	asn_MAP_AARQ_apdu_tag2el_1,
	19,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	14,	/* Start extensions */
	20	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_AARQ_apdu = {
	"AARQ-apdu",
	"AARQ-apdu",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_AARQ_apdu_tags_1,
	sizeof(asn_DEF_AARQ_apdu_tags_1)
		/sizeof(asn_DEF_AARQ_apdu_tags_1[0]) - 1, /* 1 */
	asn_DEF_AARQ_apdu_tags_1,	/* Same as above */
	sizeof(asn_DEF_AARQ_apdu_tags_1)
		/sizeof(asn_DEF_AARQ_apdu_tags_1[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_AARQ_apdu_1,
	19,	/* Elements count */
	&asn_SPC_AARQ_apdu_specs_1	/* Additional specs */
};

