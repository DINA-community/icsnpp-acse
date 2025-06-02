#pragma once

#include <zeek/plugin/Plugin.h>
#include <zeek/analyzer/Component.h>

using namespace zeek;

namespace zeek::plugin::acse {

class Plugin : public zeek::plugin::Plugin
{
protected:
    Configuration Configure() override;
};

} // namespace zeek::plugin::acse
