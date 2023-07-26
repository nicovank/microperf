#include <uperf/maps.hpp>

#include <cassert>

void uperf::maps::Maps::addMap(std::uint64_t addr, std::uint64_t len, std::uint64_t pgoff, std::string filename) {
    // Verify that there is no overlap with any existing maps.
    assert(([&] {
        for (const auto& map : maps) {
            if (addr >= map.addr && addr < map.addr + map.len) {
                return false;
            }
            if (map.addr >= addr && map.addr < addr + len) {
                return false;
            }
        }
        return true;
    })());

    maps.emplace_back(addr, len, pgoff, std::move(filename));
}

void uperf::maps::Maps::removeMap(std::uint64_t addr, std::uint64_t len) {
    const auto erased = std::erase_if(maps, [&](const auto& map) { return map.addr == addr && map.len == len; });
    assert(erased == 1);
}

std::optional<std::pair<std::string, std::uint64_t>> uperf::maps::Maps::resolve(std::uint64_t addr) const {
    for (const auto& map : maps) {
        if (addr >= map.addr && addr < map.addr + map.len) {
            return std::make_pair(map.filename, addr - map.addr + map.pgoff);
        }
    }

    return std::nullopt;
}

const std::vector<uperf::maps::Map>& uperf::maps::Maps::getMaps() const {
    return maps;
}
