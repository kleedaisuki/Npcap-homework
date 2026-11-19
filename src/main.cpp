#include "capture.hpp"
#include "ethernet.hpp"

#include <windows.h>

#include <atomic>
#include <charconv>
#include <format>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace {
struct Options {
    bool help{};
    bool list{};
    bool details{};
    std::size_t interface{};
    std::size_t count = std::numeric_limits<std::size_t>::max();
    std::string filter;
};

std::atomic_bool stop;
static_assert(std::atomic_bool::is_always_lock_free);

BOOL WINAPI stop_capture(DWORD event)
{
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT)
        return FALSE;
    stop.store(true, std::memory_order_relaxed);
    return TRUE;
}

struct ConsoleStop {
    ConsoleStop()
    {
        if (!SetConsoleCtrlHandler(stop_capture, TRUE))
            throw std::runtime_error("SetConsoleCtrlHandler failed: " +
                                     std::to_string(GetLastError()));
    }

    ~ConsoleStop() { SetConsoleCtrlHandler(stop_capture, FALSE); }
    ConsoleStop(const ConsoleStop&) = delete;
    ConsoleStop& operator=(const ConsoleStop&) = delete;
};

std::size_t positive_number(std::string_view text)
{
    std::size_t number{};
    const auto end = text.data() + text.size();
    const auto [next, error] = std::from_chars(text.data(), end, number);
    if (error != std::errc{} || next != end || number == 0)
        throw std::runtime_error("Expected a positive integer, got: " + std::string(text));
    return number;
}

Options parse_options(std::span<char*> args)
{
    Options options;
    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string_view key = args[i];
        if (key == "--help" || key == "-h") {
            options.help = true;
        } else if (key == "--list") {
            options.list = true;
        } else if (key == "--details") {
            options.details = true;
        } else if (key == "--interface" || key == "--count" || key == "--filter") {
            if (++i == args.size())
                throw std::runtime_error("Missing value for " + std::string(key));
            const std::string_view value = args[i];
            if (key == "--interface")
                options.interface = positive_number(value);
            else if (key == "--count")
                options.count = positive_number(value);
            else
                options.filter = value;
        } else {
            throw std::runtime_error("Unknown option: " + std::string(key) + " (see --help)");
        }
    }
    return options;
}

void print_devices(std::span<const Device> devices)
{
    for (std::size_t i = 0; i < devices.size(); ++i) {
        const auto& [name, description] = devices[i];
        std::cout << std::format("  [{}] {}\n      {}\n", i + 1,
                                 description.empty() ? "(no description)" : description, name);
    }
}

std::size_t choose_device(std::span<const Device> devices)
{
    print_devices(devices);
    std::string line;
    std::cout << "Select an adapter number (Enter to quit): " << std::flush;
    if (!std::getline(std::cin, line) || line.empty())
        return 0;
    return positive_number(line);
}

std::string_view mac_text(const Mac& mac, std::array<char, 17>& buffer)
{
    std::format_to(buffer.begin(), "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return {buffer.data(), buffer.size()};
}

void print_frame(std::size_t row, const Ethernet& frame,
                 const pcap_pkthdr& header, bool details)
{
    std::array<char, 17> source{}, destination{};
    std::array<char, 4> byte{};
    std::string_view next = "--";
    if (frame.next_byte) {
        std::format_to(byte.begin(), "0x{:02X}", *frame.next_byte);
        next = {byte.data(), byte.size()};
    }

    std::array<char, 128> line{};
    auto end = std::format_to(line.begin(), "{:>6}  {}  {}  0x{:04X}       {}",
                              row, mac_text(frame.source, source),
                              mac_text(frame.destination, destination), frame.type_length,
                              details ? std::string_view{} : next);
    if (details)
        end = std::format_to(end, "{:<9}  {:>10}  {:>10}", next, header.len, header.caplen);
    *end++ = '\n';
    std::cout.write(line.data(), end - line.begin());
}

void show_frames(pcap_t* capture, std::size_t limit, bool details)
{
    const ConsoleStop ctrl;
    std::cout << "Capturing (Ctrl+C to stop; no packet file is written).\n"
                 "     #  Source MAC         Destination MAC    Type/Length  Next byte";
    if (details)
        std::cout << "  Wire bytes   Cap bytes";
    std::cout << '\n' << std::flush;

    std::size_t shown{}, short_frames{};
    while (shown < limit && !stop.load(std::memory_order_relaxed)) {
        pcap_pkthdr* header = nullptr;
        const u_char* data = nullptr;
        if (!read_packet(capture, header, data)) {
            std::cout.flush();
            continue;
        }
        const auto frame = decode_ethernet({data, header->caplen});
        if (!frame) {
            ++short_frames;
            continue;
        }
        print_frame(++shown, *frame, *header, details);
        if (shown % 32 == 0)
            std::cout.flush();
    }
    std::cout << std::format("Stopped: {} shown, {} shorter than the Ethernet header.\n",
                             shown, short_frames);
}

int run(std::span<char*> args)
{
    const auto options = parse_options(args);
    if (options.help) {
        std::cout << "Usage: npcap-homework [--list | --interface NUMBER] "
                     "[--count NUMBER] [--filter EXPRESSION] [--details]\n"
                     "With no adapter specified, select one from the console menu.\n";
        return 0;
    }

    std::cout << npcap_version() << '\n';
    const auto devices = list_devices();
    if (devices.empty())
        throw std::runtime_error("Npcap did not report any adapters.");
    if (options.list) {
        print_devices(devices);
        return 0;
    }
    const auto choice = options.interface ? options.interface : choose_device(devices);
    if (choice == 0)
        return 0;
    if (choice > devices.size())
        throw std::runtime_error("Adapter number is out of range; use --list.");

    const auto capture = open_ethernet(devices[choice - 1], options.filter);
    show_frames(capture.get(), options.count, options.details);
    return 0;
}
}

int main(int argc, char** argv)
{
    SetConsoleOutputCP(CP_UTF8);
    std::ios::sync_with_stdio(false);
    try {
        return run({argv + 1, static_cast<std::size_t>(argc - 1)});
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
