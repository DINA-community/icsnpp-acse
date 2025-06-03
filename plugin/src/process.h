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

IntrusivePtr<Val> process_Name(const Name_t *src);
IntrusivePtr<Val>
process_RelativeDistinguishedName(const RelativeDistinguishedName_t *src);
IntrusivePtr<Val> process_Context(const Context_t *src);
IntrusivePtr<Val> process_AttributeTypeAndDistinguishedValue(
    const AttributeTypeAndDistinguishedValue_t *src);
IntrusivePtr<Val> process_EXTERNALt(const EXTERNALt_t *src);
IntrusivePtr<Val> process_ACSE_apdu(const ACSE_apdu_t *src);
IntrusivePtr<Val> process_AARQ_apdu(const AARQ_apdu_t *src);
IntrusivePtr<Val> process_AARE_apdu(const AARE_apdu_t *src);
IntrusivePtr<Val> process_RLRQ_apdu(const RLRQ_apdu_t *src);
IntrusivePtr<Val> process_RLRE_apdu(const RLRE_apdu_t *src);
IntrusivePtr<Val> process_ABRT_apdu(const ABRT_apdu_t *src);
IntrusivePtr<Val> process_A_DT_apdu(const A_DT_apdu_t *src);
IntrusivePtr<Val> process_ACRQ_apdu(const ACRQ_apdu_t *src);
IntrusivePtr<Val> process_ACRP_apdu(const ACRP_apdu_t *src);
IntrusivePtr<Val> process_ACSE_requirements(const ACSE_requirements_t *src);
IntrusivePtr<Val>
process_Application_context_name(const Application_context_name_t *src);
IntrusivePtr<Val> process_AP_title(const AP_title_t *src);
IntrusivePtr<Val> process_AE_qualifier(const AE_qualifier_t *src);
IntrusivePtr<Val> process_ASO_qualifier(const ASO_qualifier_t *src);
IntrusivePtr<Val> process_AP_title_form1(const AP_title_form1_t *src);
IntrusivePtr<Val> process_ASO_qualifier_form1(const ASO_qualifier_form1_t *src);
IntrusivePtr<Val> process_AE_title(const AE_title_t *src);
IntrusivePtr<Val> process_AE_title_form1(const AE_title_form1_t *src);
IntrusivePtr<Val> process_ASOI_tag(const ASOI_tag_t *src);
IntrusivePtr<Val>
process_ASO_context_name_list(const ASO_context_name_list_t *src);
IntrusivePtr<Val>
process_Syntactic_context_list(const Syntactic_context_list_t *src);
IntrusivePtr<Val> process_Context_list(const Context_list_t *src);
IntrusivePtr<Val>
process_Default_Context_List(const Default_Context_List_t *src);
IntrusivePtr<Val>
process_P_context_result_list(const P_context_result_list_t *src);
IntrusivePtr<Val>
process_Concrete_syntax_name(const Concrete_syntax_name_t *src);
IntrusivePtr<Val>
process_Associate_source_diagnostic(const Associate_source_diagnostic_t *src);
IntrusivePtr<Val> process_User_information(const User_information_t *src);
IntrusivePtr<Val> process_Association_data(const Association_data_t *src);
IntrusivePtr<Val> process_User_Data(const User_Data_t *src);
IntrusivePtr<Val> process_PDV_list(const PDV_list_t *src);
IntrusivePtr<Val>
process_Authentication_value_other(const Authentication_value_other_t *src);
IntrusivePtr<Val>
process_Authentication_value(const Authentication_value_t *src);

} // namespace zeek::plugin::acse
