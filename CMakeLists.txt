cmake_minimum_required(VERSION 3.25)
project(NpcapHomework LANGUAGES CXX)

if(NOT WIN32 OR NOT (MINGW OR MSVC))
    message(FATAL_ERROR "Configure with a native Windows toolchain: MSYS2 MinGW GCC or MSVC.")
endif()

set(NPCAP_SDK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/external/npcap-sdk-1.17"
    CACHE PATH "Extracted Npcap SDK")
if(NOT EXISTS "${NPCAP_SDK_ROOT}/Include/pcap.h")
    message(FATAL_ERROR "Extract the Npcap SDK and set NPCAP_SDK_ROOT. See README.md.")
endif()

add_executable(npcap-homework src/main.cpp src/capture.cpp)
set_target_properties(npcap-homework PROPERTIES
    CXX_STANDARD 23 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
target_compile_definitions(npcap-homework PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_include_directories(npcap-homework SYSTEM PRIVATE "${NPCAP_SDK_ROOT}/Include")
if(MSVC)
    target_compile_options(npcap-homework PRIVATE /W4 /permissive- /utf-8)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(npcap-homework PRIVATE -Wall -Wextra -Wpedantic)
    # The executable should also run from PowerShell without the MSYS2 bin directory.
    target_link_options(npcap-homework PRIVATE -static)
endif()
