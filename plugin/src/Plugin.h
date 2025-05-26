#pragma once

#include <zeek/plugin/Plugin.h>
#include <zeek/analyzer/Component.h>

using namespace zeek;

namespace zeek::plugin::acse {

constexpr const char* ACSE_PDU_EVENT="acse::acse_apdu";

class Plugin : public zeek::plugin::Plugin
{
protected:
    Configuration Configure() override;
    void InitPreScript() override;
};

} // namespace zeek::plugin::acse
