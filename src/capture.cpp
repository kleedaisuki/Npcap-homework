#include "capture.hpp"

#include <windows.h>

#include <array>
#include <bit>
#include <filesystem>
#include <format>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <type_traits>

namespace {
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

template<class Function>
Function bind(HMODULE module, const char* symbol)
{
    if (const auto address = GetProcAddress(module, symbol))
        return std::bit_cast<Function>(address);
    throw std::runtime_error(std::string("Npcap wpcap.dll is missing ") + symbol +
                             ". Install or repair the Npcap runtime.");
}

struct PcapApi {
    std::unique_ptr<std::remove_pointer_t<HMODULE>, decltype(&FreeLibrary)> module{
        load_npcap(), FreeLibrary};

#define PCAP_EXPORT(name) \
    decltype(&::pcap_##name) name = bind<decltype(name)>(module.get(), "pcap_" #name)
    PCAP_EXPORT(lib_version);
    PCAP_EXPORT(init);
    PCAP_EXPORT(findalldevs);
    PCAP_EXPORT(freealldevs);
    PCAP_EXPORT(open_live);
    PCAP_EXPORT(close);
    PCAP_EXPORT(datalink);
    PCAP_EXPORT(geterr);
    PCAP_EXPORT(compile);
    PCAP_EXPORT(setfilter);
    PCAP_EXPORT(freecode);
    PCAP_EXPORT(next_ex);
#undef PCAP_EXPORT

    PcapApi()
    {
        if (!std::string_view(lib_version()).starts_with("Npcap"))
            throw std::runtime_error("Loaded wpcap.dll is not an Npcap runtime.");

        char error[PCAP_ERRBUF_SIZE]{};
        if (init(PCAP_CHAR_ENC_UTF_8, error) != 0)
            throw std::runtime_error(std::string("pcap_init: ") + error);
    }
};

const PcapApi& api()
{
    static const PcapApi loaded;
    return loaded;
}

void set_filter(pcap_t* capture, const std::string& expression)
{
    const auto& pcap = api();
    bpf_program program{};
    if (pcap.compile(capture, &program, expression.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0)
        throw std::runtime_error(std::string("pcap_compile: ") + pcap.geterr(capture));

    const auto status = pcap.setfilter(capture, &program);
    pcap.freecode(&program);
    if (status < 0)
        throw std::runtime_error(std::string("pcap_setfilter: ") + pcap.geterr(capture));
}
}

const char* npcap_version()
{
    return api().lib_version();
}

std::vector<Device> list_devices()
{
    const auto& pcap = api();
    char error[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* head = nullptr;
    if (pcap.findalldevs(&head, error) < 0)
        throw std::runtime_error(std::string("pcap_findalldevs: ") + error);
    const std::unique_ptr<pcap_if_t, decltype(&pcap_freealldevs)> devices(head, pcap.freealldevs);

    std::vector<Device> result;
    for (auto* device = devices.get(); device; device = device->next)
        result.push_back({device->name, device->description ? device->description : ""});
    return result;
}

Capture open_ethernet(const Device& device, const std::string& filter)
{
    const auto& pcap = api();
    constexpr int snaplen = 64;
    constexpr int read_timeout_ms = 200;
    char error[PCAP_ERRBUF_SIZE]{};
    Capture capture(pcap.open_live(device.name.c_str(), snaplen, 0, read_timeout_ms, error),
                    pcap.close);
    if (!capture)
        throw std::runtime_error("pcap_open_live (" + device.name + "): " + error);
    if (error[0])
        std::cerr << "Npcap warning: " << error << '\n';

    const auto link_type = pcap.datalink(capture.get());
    if (link_type < 0)
        throw std::runtime_error(std::string("pcap_datalink: ") + pcap.geterr(capture.get()));
    if (link_type != DLT_EN10MB)
        throw std::runtime_error(std::format("Link type {} is not Ethernet; select another adapter.",
                                             link_type));
    if (!filter.empty())
        set_filter(capture.get(), filter);
    return capture;
}

bool read_packet(pcap_t* capture, pcap_pkthdr*& header, const u_char*& data)
{
    const auto& pcap = api();
    const auto status = pcap.next_ex(capture, &header, &data);
    if (status < 0)
        throw std::runtime_error(std::string("pcap_next_ex: ") +
                                 (status == PCAP_ERROR_BREAK ? "capture ended unexpectedly"
                                                             : pcap.geterr(capture)));
    return status != 0;
}
