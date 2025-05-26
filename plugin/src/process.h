/* THIS CODE IS GENERATED. DON'T CHANGE MANUALLY! */

#pragma once

#include "zeek/Val.h"
#include <A-DT-apdu.h>
#include <AARE-apdu.h>
#include <AARQ-apdu.h>
#include <ABRT-apdu.h>
#include <ACRP-apdu.h>
#include <ACRQ-apdu.h>
#include <ACSE-apdu.h>
#include <ACSE-requirements.h>
#include <AE-qualifier.h>
#include <AE-title-form1.h>
#include <AE-title.h>
#include <AP-title-form1.h>
#include <AP-title.h>
#include <ASO-context-name-list.h>
#include <ASO-qualifier-form1.h>
#include <ASO-qualifier.h>
#include <ASOI-tag.h>
#include <Application-context-name.h>
#include <Associate-source-diagnostic.h>
#include <Association-data.h>
#include <AttributeTypeAndDistinguishedValue.h>
#include <Authentication-value-other.h>
#include <Authentication-value.h>
#include <Concrete-syntax-name.h>
#include <Context-list.h>
#include <Context.h>
#include <Default-Context-List.h>
#include <EXTERNALt.h>
#include <Name.h>
#include <P-context-result-list.h>
#include <PDV-list.h>
#include <RLRE-apdu.h>
#include <RLRQ-apdu.h>
#include <RelativeDistinguishedName.h>
#include <Syntactic-context-list.h>
#include <User-Data.h>
#include <User-information.h>

using namespace zeek;

namespace zeek::plugin::acse {

IntrusivePtr<Val> process_Name(Name_t *src);
IntrusivePtr<Val>
process_RelativeDistinguishedName(RelativeDistinguishedName_t *src);
IntrusivePtr<Val> process_Context(Context_t *src);
IntrusivePtr<Val> process_AttributeTypeAndDistinguishedValue(
    AttributeTypeAndDistinguishedValue_t *src);
IntrusivePtr<Val> process_EXTERNALt(EXTERNALt_t *src);
IntrusivePtr<Val> process_ACSE_apdu(ACSE_apdu_t *src);
IntrusivePtr<Val> process_AARQ_apdu(AARQ_apdu_t *src);
IntrusivePtr<Val> process_AARE_apdu(AARE_apdu_t *src);
IntrusivePtr<Val> process_RLRQ_apdu(RLRQ_apdu_t *src);
IntrusivePtr<Val> process_RLRE_apdu(RLRE_apdu_t *src);
IntrusivePtr<Val> process_ABRT_apdu(ABRT_apdu_t *src);
IntrusivePtr<Val> process_A_DT_apdu(A_DT_apdu_t *src);
IntrusivePtr<Val> process_ACRQ_apdu(ACRQ_apdu_t *src);
IntrusivePtr<Val> process_ACRP_apdu(ACRP_apdu_t *src);
IntrusivePtr<Val> process_ACSE_requirements(ACSE_requirements_t *src);
IntrusivePtr<Val>
process_Application_context_name(Application_context_name_t *src);
IntrusivePtr<Val> process_AP_title(AP_title_t *src);
IntrusivePtr<Val> process_AE_qualifier(AE_qualifier_t *src);
IntrusivePtr<Val> process_ASO_qualifier(ASO_qualifier_t *src);
IntrusivePtr<Val> process_AP_title_form1(AP_title_form1_t *src);
IntrusivePtr<Val> process_ASO_qualifier_form1(ASO_qualifier_form1_t *src);
IntrusivePtr<Val> process_AE_title(AE_title_t *src);
IntrusivePtr<Val> process_AE_title_form1(AE_title_form1_t *src);
IntrusivePtr<Val> process_ASOI_tag(ASOI_tag_t *src);
IntrusivePtr<Val> process_ASO_context_name_list(ASO_context_name_list_t *src);
IntrusivePtr<Val> process_Syntactic_context_list(Syntactic_context_list_t *src);
IntrusivePtr<Val> process_Context_list(Context_list_t *src);
IntrusivePtr<Val> process_Default_Context_List(Default_Context_List_t *src);
IntrusivePtr<Val> process_P_context_result_list(P_context_result_list_t *src);
IntrusivePtr<Val> process_Concrete_syntax_name(Concrete_syntax_name_t *src);
IntrusivePtr<Val>
process_Associate_source_diagnostic(Associate_source_diagnostic_t *src);
IntrusivePtr<Val> process_User_information(User_information_t *src);
IntrusivePtr<Val> process_Association_data(Association_data_t *src);
IntrusivePtr<Val> process_User_Data(User_Data_t *src);
IntrusivePtr<Val> process_PDV_list(PDV_list_t *src);
IntrusivePtr<Val>
process_Authentication_value_other(Authentication_value_other_t *src);
IntrusivePtr<Val> process_Authentication_value(Authentication_value_t *src);

} // namespace zeek::plugin::acse
