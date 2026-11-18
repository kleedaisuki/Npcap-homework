#include "capture.hpp"

#include <windows.h>
#include <delayimp.h>

#include <array>
#include <cstring>
#include <filesystem>
#include <format>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace {
HMODULE wpcap;

FARPROC WINAPI use_npcap(unsigned notification, PDelayLoadInfo info)
{
    if (notification == dliNotePreLoadLibrary && std::strcmp(info->szDll, "wpcap.dll") == 0)
        return reinterpret_cast<FARPROC>(wpcap);
    return nullptr;
}

HMODULE load_npcap()
{
    std::array<wchar_t, MAX_PATH> dir{};
    const auto size = GetSystemDirectoryW(dir.data(), static_cast<UINT>(dir.size()));
    if (size == 0 || size >= dir.size())
        throw std::runtime_error("GetSystemDirectoryW failed.");

    const auto path = std::filesystem::path(dir.data()) / L"Npcap" / L"wpcap.dll";
    if (auto module = LoadLibraryExW(path.c_str(), nullptr,
                                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32))
        return module;
    if (auto module = LoadLibraryExW(L"wpcap.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32))
        return module;
    // An explicitly staged DLL beside the executable is useful for local validation.
    if (auto module = LoadLibraryExW(L"wpcap.dll", nullptr,
                                    LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32))
        return module;

    throw std::runtime_error("Cannot load Npcap wpcap.dll (Windows error " +
                             std::to_string(GetLastError()) +
                             "). Install or repair the Npcap runtime for this architecture.");
}

void set_filter(pcap_t* capture, const std::string& expression)
{
    bpf_program program{};
    if (pcap_compile(capture, &program, expression.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0)
        throw std::runtime_error(std::string("pcap_compile: ") + pcap_geterr(capture));

    const auto status = pcap_setfilter(capture, &program);
    pcap_freecode(&program);
    if (status < 0)
        throw std::runtime_error(std::string("pcap_setfilter: ") + pcap_geterr(capture));
}
}

extern "C" const PfnDliHook __pfnDliNotifyHook2 = use_npcap;

void init_npcap()
{
    wpcap = load_npcap();
    if (!GetProcAddress(wpcap, "pcap_init") ||
        !std::string_view(pcap_lib_version()).starts_with("Npcap"))
        throw std::runtime_error("Loaded wpcap.dll is not a supported Npcap runtime.");

    char error[PCAP_ERRBUF_SIZE]{};
    if (pcap_init(PCAP_CHAR_ENC_UTF_8, error) != 0)
        throw std::runtime_error(std::string("pcap_init: ") + error);
}

std::vector<Device> list_devices()
{
    char error[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* head = nullptr;
    if (pcap_findalldevs(&head, error) < 0)
        throw std::runtime_error(std::string("pcap_findalldevs: ") + error);
    const std::unique_ptr<pcap_if_t, decltype(&pcap_freealldevs)> devices(head, pcap_freealldevs);

    std::vector<Device> result;
    for (auto* device = devices.get(); device; device = device->next)
        result.push_back({device->name, device->description ? device->description : ""});
    return result;
}

Capture open_ethernet(const Device& device, const std::string& filter)
{
    constexpr int snaplen = 64;
    constexpr int read_timeout_ms = 200;
    char error[PCAP_ERRBUF_SIZE]{};
    Capture capture(pcap_open_live(device.name.c_str(), snaplen, 0, read_timeout_ms, error),
                    pcap_close);
    if (!capture)
        throw std::runtime_error("pcap_open_live (" + device.name + "): " + error);
    if (error[0])
        std::cerr << "Npcap warning: " << error << '\n';

    const auto link_type = pcap_datalink(capture.get());
    if (link_type < 0)
        throw std::runtime_error(std::string("pcap_datalink: ") + pcap_geterr(capture.get()));
    if (link_type != DLT_EN10MB)
        throw std::runtime_error(std::format("Link type {} is not Ethernet; select another adapter.",
                                             link_type));
    if (!filter.empty())
        set_filter(capture.get(), filter);
    return capture;
}
