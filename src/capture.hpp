#pragma once

#include <pcap.h>

#include <memory>
#include <string>
#include <vector>

struct Device {
    std::string name;
    std::string description;
};

using Capture = std::unique_ptr<pcap_t, decltype(&pcap_close)>;

const char* npcap_version();
std::vector<Device> list_devices();
Capture open_ethernet(const Device& device, const std::string& filter);
bool read_packet(pcap_t* capture, pcap_pkthdr*& header, const u_char*& data);
