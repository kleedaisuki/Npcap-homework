cmake_minimum_required(VERSION 3.25)
project(NpcapHomework LANGUAGES CXX)

if(NOT WIN32 OR NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    message(FATAL_ERROR "Configure on Windows with the MSVC toolchain.")
endif()

set(NPCAP_SDK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/external/npcap-sdk-1.17"
    CACHE PATH "Extracted Npcap SDK")
set(npcap_lib_dir "${NPCAP_SDK_ROOT}/Lib")
if(MSVC_CXX_ARCHITECTURE_ID STREQUAL "ARM64")
    string(APPEND npcap_lib_dir "/ARM64")
elseif(MSVC_CXX_ARCHITECTURE_ID STREQUAL "x64")
    string(APPEND npcap_lib_dir "/x64")
elseif(NOT MSVC_CXX_ARCHITECTURE_ID STREQUAL "X86")
    message(FATAL_ERROR "Unsupported Npcap SDK architecture: ${MSVC_CXX_ARCHITECTURE_ID}")
endif()

if(NOT EXISTS "${NPCAP_SDK_ROOT}/Include/pcap.h" OR
   NOT EXISTS "${npcap_lib_dir}/wpcap.lib")
    message(FATAL_ERROR "Extract the Npcap SDK and set NPCAP_SDK_ROOT. See README.md.")
endif()

add_library(Npcap::pcap UNKNOWN IMPORTED)
set_target_properties(Npcap::pcap PROPERTIES
    IMPORTED_LOCATION "${npcap_lib_dir}/wpcap.lib"
    INTERFACE_INCLUDE_DIRECTORIES "${NPCAP_SDK_ROOT}/Include")

add_executable(npcap-homework src/main.cpp src/capture.cpp)
set_target_properties(npcap-homework PROPERTIES
    CXX_STANDARD 23 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
target_compile_definitions(npcap-homework PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(npcap-homework PRIVATE /W4 /permissive- /utf-8)
target_link_libraries(npcap-homework PRIVATE Npcap::pcap delayimp)
target_link_options(npcap-homework PRIVATE /DELAYLOAD:wpcap.dll)
