/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "ACSE"
 * 	found in "../../../../utils/acse.asn"
 * 	`asn1c -fcompound-names`
 */

#include "RelativeDistinguishedName.h"

static asn_TYPE_member_t asn_MBR_RelativeDistinguishedName_1[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_AttributeTypeAndDistinguishedValue,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		""
		},
};
static const ber_tlv_tag_t asn_DEF_RelativeDistinguishedName_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (17 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_RelativeDistinguishedName_specs_1 = {
	sizeof(struct RelativeDistinguishedName),
	offsetof(struct RelativeDistinguishedName, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
asn_TYPE_descriptor_t asn_DEF_RelativeDistinguishedName = {
	"RelativeDistinguishedName",
	"RelativeDistinguishedName",
	SET_OF_free,
	SET_OF_print,
	SET_OF_constraint,
	SET_OF_decode_ber,
	SET_OF_encode_der,
	SET_OF_decode_xer,
	SET_OF_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_RelativeDistinguishedName_tags_1,
	sizeof(asn_DEF_RelativeDistinguishedName_tags_1)
		/sizeof(asn_DEF_RelativeDistinguishedName_tags_1[0]), /* 1 */
	asn_DEF_RelativeDistinguishedName_tags_1,	/* Same as above */
	sizeof(asn_DEF_RelativeDistinguishedName_tags_1)
		/sizeof(asn_DEF_RelativeDistinguishedName_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_RelativeDistinguishedName_1,
	1,	/* Single element */
	&asn_SPC_RelativeDistinguishedName_specs_1	/* Additional specs */
};

