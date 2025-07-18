# This file is maintained by zkg. Do not edit.
# Put required additional cmake functionality into plugin.cmake.
cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

project(ZeekPluginACSE)

# Establish version numbers in config.h
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

string(REGEX REPLACE "[.-]" " " version_numbers ${VERSION})
separate_arguments(version_numbers)
list(GET version_numbers 0 VERSION_MAJOR)
list(GET version_numbers 1 VERSION_MINOR)
list(GET version_numbers 2 VERSION_PATCH)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/plugin/src/config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)

# Process any package-specific customizations
include(plugin.cmake OPTIONAL)

# Our plugin source and scripts are in a subdirectory
set(BRO_PLUGIN_BASE "${CMAKE_CURRENT_SOURCE_DIR}/plugin")

# Workaround to make header files in plugin sources available to BiFs.
include_directories("${BRO_PLUGIN_BASE}/src")

include(ZeekPlugin)

zeek_plugin_begin(OSS ACSE)

# The following line is manually added!
zeek_plugin_link_library(asn1c)

file(GLOB cc_files RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "plugin/src/*.cc")
foreach(file ${cc_files})
    zeek_plugin_cc(${file})
endforeach ()

file(GLOB bif_files RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "plugin/src/*.bif")
foreach(file ${bif_files})
    zeek_plugin_bif(${file})
endforeach ()

zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_end()

zeek_get_dynamic_plugin_target(target_name OSS ACSE)
add_custom_command(TARGET "${target_name}_symlink" POST_BUILD COMMAND "${CMAKE_COMMAND}" -E create_symlink "${CMAKE_CURRENT_SOURCE_DIR}/plugin/scripts" scripts)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
