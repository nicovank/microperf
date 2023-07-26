#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <numeric>
#include <unordered_map>
#include <vector>

#include <linux/perf_event.h>
#include <sys/mman.h>
#include <unistd.h>

#include <fmt/core.h>

#include <uperf/maps.hpp>
#include <uperf/parser.hpp>
#include <uperf/perf_types.hpp>

[[maybe_unused]] void printEventTypeHistogram(const std::string& filename) {
    const auto stream = fopen(filename.c_str(), "r");
    if (!stream) {
        fmt::println(stderr, "Failed to open {}", filename);
        std::abort();
    }

    const auto header = uperf::parser::readHeader(stream);

    std::unordered_map<std::uint32_t, std::uint64_t> histogram;
    auto offset = header.data.offset;
    while (offset < header.data.offset + header.data.size) {
        fseek(stream, offset, SEEK_SET);
        const auto event_header = uperf::parser::readEventHeader(stream);
        ++histogram[event_header.type];
        offset += event_header.size;
    }

    std::vector<std::pair<std::uint32_t, std::uint64_t>> sorted_histogram(histogram.begin(), histogram.end());
    std::sort(sorted_histogram.begin(), sorted_histogram.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    fmt::println("Total events: {}", std::accumulate(sorted_histogram.begin(), sorted_histogram.end(), 0,
                                                     [](auto a, const auto& b) { return a + b.second; }));
    for (const auto& [type, count] : sorted_histogram) {
        fmt::println("{}: {}", type, count);
    }

    if (fclose(stream) != 0) {
        fmt::println(stderr, "Failed to close {}", filename);
        std::abort();
    }
}

#define PERF_FILENAME "perf.data"

int main() {
    const auto stream = fopen(PERF_FILENAME, "r");
    if (!stream) {
        fmt::println(stderr, "Failed to open perf.data");
        std::abort();
    }

    const auto header = uperf::parser::readHeader(stream);

    // For now, we only support single event profiles.
    assert(header.attr_size == header.attrs.size);
    fseek(stream, header.attrs.offset, SEEK_SET);
    const auto attr = uperf::parser::readEventAttributes(stream);
    assert(attr.sample_type & PERF_SAMPLE_CALLCHAIN);

    std::unordered_map<pid_t, uperf::maps::Maps> maps;

    auto offset = header.data.offset;
    while (offset < header.data.offset + header.data.size) {
        fseek(stream, offset, SEEK_SET);
        const auto event_header = uperf::parser::readEventHeader(stream);

        if (event_header.type == PERF_RECORD_EXIT) {
            const auto event = uperf::parser::readExitEvent(stream, attr, event_header);
            maps.erase(event.pid);
        } else if (event_header.type == PERF_RECORD_FORK) {
            const auto event = uperf::parser::readForkEvent(stream, attr, event_header);
            const auto it = maps.find(event.ppid);
            if (it != maps.end()) {
                maps.emplace(event.pid, it->second);
            } else {
                maps.emplace(event.pid, uperf::maps::Maps());
            }
        } else if (event_header.type == PERF_RECORD_MMAP || event_header.type == PERF_RECORD_MMAP2) {
            const auto event = uperf::parser::readMmapEvent(stream, attr, event_header);
            if (!event.prot.has_value() || event.prot.value() & PROT_EXEC) {
                maps[event.pid].addMap(event.addr, event.len, event.pgoff, event.filename);
            }
        } else if (event_header.type == PERF_RECORD_SAMPLE) {
            const auto event = uperf::parser::readSampleEvent(stream, attr, event_header);
            assert(event.pid.has_value());
            assert(event.ip.has_value());
            assert(event.callchain.has_value());

            if (const auto map = maps.find(event.pid.value()); map != maps.end()) {
                const auto [filename, offset]
                    = map->second.resolve(event.ip.value())
                          .value_or(std::make_pair(std::string("[unknown]"), event.ip.value()));
                fmt::println("{} {:x}", filename, offset);

                if (event.callchain.value().size() > 0) {
                    for (const auto ip : event.callchain.value()) {
                        const auto [filename, offset]
                            = map->second.resolve(ip).value_or(std::make_pair(std::string("[unknown]"), ip));
                        fmt::println("\t{} {:x}", filename, offset);
                    }
                }
            }
        }

        offset += event_header.size;
    }

    for (const auto& [pid, map] : maps) {
        fmt::println("PID {}", pid);
        for (const auto& map : map.getMaps()) {
            fmt::println("\t{:x} {:x} {:x} {}", map.addr, map.len, map.pgoff, map.filename);
        }
    }

    if (fclose(stream) != 0) {
        fmt::println(stderr, "Failed to close {}", PERF_FILENAME);
        std::abort();
    }
}
