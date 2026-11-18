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

void init_npcap();
std::vector<Device> list_devices();
Capture open_ethernet(const Device& device, const std::string& filter);
