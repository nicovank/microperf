#include <uperf/maps.hpp>

#include <cassert>
#include <ranges>

#include <fmt/core.h>

void uperf::maps::Maps::addMap(std::uint64_t addr, std::uint64_t len, std::uint64_t pgoff, std::string filename) {
    // Verify that there is no overlap with any existing maps.
    // for (const auto& map : maps) {
    //     if ((addr >= map.addr && addr < map.addr + map.len) || (map.addr >= addr && map.addr < addr + len)) {
    //         fmt::println("Overlap detected between the following maps:");
    //         fmt::println("\t{}-{} {}", map.addr, map.addr + map.len, map.filename);
    //         fmt::println("\t{}-{} {}", addr, addr + len, filename);
    //         std::abort();
    //     }
    // }

    // ffffffff9ff9fcf4

    maps.emplace_back(addr, len, pgoff, std::move(filename));
}

void uperf::maps::Maps::removeMap(std::uint64_t addr, std::uint64_t len) {
    const auto erased = std::erase_if(maps, [&](const auto& map) { return map.addr == addr && map.len == len; });
    if (erased != 1) {
        fmt::println("Failed to remove map at {}-{}", addr, addr + len);
        std::abort();
    }
}

std::optional<std::pair<std::string, std::uint64_t>> uperf::maps::Maps::resolve(std::uint64_t addr) const {
    for (const auto& map : maps | std::views::reverse) {
        if (addr >= map.addr && addr < map.addr + map.len) {
            return std::make_pair(map.filename, addr - map.addr + map.pgoff);
        }
    }

    return std::nullopt;
}

const std::vector<uperf::maps::Map>& uperf::maps::Maps::getMaps() const {
    return maps;
}
