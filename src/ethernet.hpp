#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <span>

using Mac = std::array<std::uint8_t, 6>;

struct Ethernet {
    Mac destination;
    Mac source;
    std::uint16_t type_length;
    std::optional<std::uint8_t> next_byte;
};

constexpr std::optional<Ethernet> decode_ethernet(std::span<const std::uint8_t> bytes)
{
    constexpr std::size_t field = 2 * Mac{}.size();
    constexpr std::size_t next = field + 2;
    if (bytes.size() < next)
        return std::nullopt;

    Ethernet frame{};
    std::ranges::copy(bytes.first<6>(), frame.destination.begin());
    std::ranges::copy(bytes.subspan<6, 6>(), frame.source.begin());
    frame.type_length = static_cast<std::uint16_t>((bytes[field] << 8) | bytes[field + 1]);
    if (bytes.size() > next)
        frame.next_byte = bytes[next];
    return frame;
}
