#include <algorithm>
#include <cassert>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <span>
#include <unordered_map>
#include <vector>

#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fmt/core.h>
#include <fmt/ranges.h>

#define PAGE_SIZE 4096
#define N 3 // We need to mmap 2^N+1 pages with perf_event_open.

namespace {
int perf_event_open(perf_event_attr* attr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int perf_event_open_fallback_precise_ip(perf_event_attr* attr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    for (std::uint64_t precise_ip = 3; precise_ip <= 3; --precise_ip) {
        attr->precise_ip = precise_ip;
        const auto fd = syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
        if (fd != -1) {
            return fd;
        }
    }
    return -1;
}
} // namespace

namespace perf::sample {
std::size_t offset_for_sample_id(const perf_event_header* header, std::uint64_t sample_type) {
    return sizeof(perf_event_header);
}

std::uint64_t get_sample_id(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_IDENTIFIER);
    const auto offset = offset_for_sample_id(header, sample_type);
    return *reinterpret_cast<const std::uint64_t*>(reinterpret_cast<uintptr_t>(header) + offset);
}

std::size_t offset_for_ip(const perf_event_header* header, std::uint64_t sample_type) {
    return offset_for_sample_id(header, sample_type)
           + ((sample_type & PERF_SAMPLE_IDENTIFIER) ? sizeof(std::uint64_t) : 0);
}

std::uint64_t get_ip(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_IP);
    const auto offset = offset_for_ip(header, sample_type);
    return *reinterpret_cast<const std::uint64_t*>(reinterpret_cast<uintptr_t>(header) + offset);
}

std::size_t offset_for_pid(const perf_event_header* header, std::uint64_t sample_type) {
    return offset_for_ip(header, sample_type) + ((sample_type & PERF_SAMPLE_IP) ? sizeof(std::uint64_t) : 0);
}

std::uint32_t get_pid(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_TID);
    const auto offset = offset_for_pid(header, sample_type);
    return *reinterpret_cast<const std::uint32_t*>(reinterpret_cast<uintptr_t>(header) + offset);
}

std::uint32_t get_tid(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_TID);
    const auto offset = offset_for_pid(header, sample_type) + sizeof(std::uint32_t);
    return *reinterpret_cast<const std::uint32_t*>(reinterpret_cast<uintptr_t>(header) + offset);
}

std::size_t offset_for_time(const perf_event_header* header, std::uint64_t sample_type) {
    return offset_for_pid(header, sample_type) + ((sample_type & PERF_SAMPLE_TID) ? 2 * sizeof(std::uint32_t) : 0);
}

std::uint64_t get_time(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_TIME);
    const auto offset = offset_for_time(header, sample_type);
    return *reinterpret_cast<const std::uint64_t*>(reinterpret_cast<uintptr_t>(header) + offset);
}

std::size_t offset_for_addr(const perf_event_header* header, std::uint64_t sample_type) {
    return offset_for_time(header, sample_type) + ((sample_type & PERF_SAMPLE_TIME) ? sizeof(std::uint64_t) : 0);
}

std::uint64_t get_addr(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_ADDR);
    const auto offset = offset_for_addr(header, sample_type);
    return *reinterpret_cast<const std::uint64_t*>(reinterpret_cast<uintptr_t>(header) + offset);
}

std::size_t offset_for_id(const perf_event_header* header, std::uint64_t sample_type) {
    return offset_for_addr(header, sample_type) + ((sample_type & PERF_SAMPLE_ADDR) ? sizeof(std::uint64_t) : 0);
}

std::uint64_t get_id(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_ID);
    const auto offset = offset_for_id(header, sample_type);
    return *reinterpret_cast<const std::uint64_t*>(reinterpret_cast<uintptr_t>(header) + offset);
}

std::size_t offset_for_stream_id(const perf_event_header* header, std::uint64_t sample_type) {
    return offset_for_id(header, sample_type) + ((sample_type & PERF_SAMPLE_ID) ? sizeof(std::uint64_t) : 0);
}

std::uint64_t get_stream_id(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_STREAM_ID);
    const auto offset = offset_for_stream_id(header, sample_type);
    return *reinterpret_cast<const std::uint64_t*>(reinterpret_cast<uintptr_t>(header) + offset);
}

std::size_t offset_for_cpu(const perf_event_header* header, std::uint64_t sample_type) {
    return offset_for_stream_id(header, sample_type)
           + ((sample_type & PERF_SAMPLE_STREAM_ID) ? sizeof(std::uint64_t) : 0);
}

std::uint32_t get_cpu(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_CPU);
    const auto offset = offset_for_cpu(header, sample_type);
    return *reinterpret_cast<const std::uint32_t*>(reinterpret_cast<uintptr_t>(header) + offset);
}

std::uint32_t get_res(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_CPU);
    const auto offset = offset_for_pid(header, sample_type) + sizeof(std::uint32_t);
    return *reinterpret_cast<const std::uint32_t*>(reinterpret_cast<uintptr_t>(header) + offset);
}

std::size_t offset_for_period(const perf_event_header* header, std::uint64_t sample_type) {
    return offset_for_cpu(header, sample_type) + ((sample_type & PERF_SAMPLE_CPU) ? 2 * sizeof(std::uint32_t) : 0);
}

std::uint64_t get_period(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_PERIOD);
    const auto offset = offset_for_period(header, sample_type);
    return *reinterpret_cast<const std::uint64_t*>(reinterpret_cast<uintptr_t>(header) + offset);
}

std::size_t offset_for_v(const perf_event_header* header, std::uint64_t sample_type) {
    return offset_for_period(header, sample_type) + ((sample_type & PERF_SAMPLE_PERIOD) ? sizeof(std::uint64_t) : 0);
}

std::size_t offset_for_ips(const perf_event_header* header, std::uint64_t sample_type, std::uint64_t read_format) {
    auto offset = offset_for_v(header, sample_type);
    if (sample_type & PERF_SAMPLE_READ) {
        if (read_format & PERF_FORMAT_GROUP) {
            const auto nr = *reinterpret_cast<const std::uint64_t*>(reinterpret_cast<uintptr_t>(header) + offset);
            offset += sizeof(std::uint64_t);
            offset += ((read_format & PERF_FORMAT_TOTAL_TIME_ENABLED) ? sizeof(std::uint64_t) : 0);
            offset += ((read_format & PERF_FORMAT_TOTAL_TIME_RUNNING) ? sizeof(std::uint64_t) : 0);
            offset += nr * sizeof(std::uint64_t)
                      * (1 + ((read_format & PERF_FORMAT_ID) ? 1 : 0) + ((read_format & PERF_FORMAT_LOST) ? 1 : 0));
        } else {
            offset += sizeof(std::uint64_t);
            offset += ((read_format & PERF_FORMAT_TOTAL_TIME_ENABLED) ? sizeof(std::uint64_t) : 0);
            offset += ((read_format & PERF_FORMAT_TOTAL_TIME_RUNNING) ? sizeof(std::uint64_t) : 0);
            offset += ((read_format & PERF_FORMAT_ID) ? sizeof(std::uint64_t) : 0);
            offset += ((read_format & PERF_FORMAT_LOST) ? sizeof(std::uint64_t) : 0);
        }
    }
    return offset;
}

std::span<const std::uint64_t> get_ips(const perf_event_header* header, std::uint64_t sample_type,
                                       std::uint64_t read_format) {
    assert(sample_type & PERF_SAMPLE_CALLCHAIN);
    const auto offset = offset_for_ips(header, sample_type, read_format);
    const auto nr = *reinterpret_cast<const std::uint64_t*>(reinterpret_cast<uintptr_t>(header) + offset);
    return std::span(
        reinterpret_cast<const std::uint64_t*>(reinterpret_cast<uintptr_t>(header) + offset + sizeof(std::uint64_t)),
        nr);
}
} // namespace perf::sample

// Returns true if the process should keep being tracked.
bool process_samples(perf_event_mmap_page* metadata) {
    const auto head = metadata->data_head;
    // TODO: smp_rmb()?
    const auto tail = metadata->data_tail;

    while (metadata->data_tail < head) {
        const auto* record
            = reinterpret_cast<perf_event_header*>(reinterpret_cast<uintptr_t>(metadata) + metadata->data_offset
                                                   + (metadata->data_tail % ((1 << N) * PAGE_SIZE)));

        if (record->type == PERF_RECORD_EXIT) {
            fmt::println("exit");
            return false;
        }

        if (record->type == PERF_RECORD_SAMPLE) {
            // fmt::println("{}, {}", record->type, record->size);
            // fmt::println("{} {} {} {}", perf::sample::get_ip(record, attr.sample_type),
            //              perf::sample::get_pid(record, attr.sample_type),
            //              perf::sample::get_tid(record, attr.sample_type),
            //              perf::sample::get_ips(record, attr.sample_type, attr.read_format));
            // fmt::println("sample");
        } else {
            fmt::println("{}, {}", record->type, record->size);
        }

        metadata->data_tail += record->size;
    }

    return true;
}

// Split string on whitespace.
std::vector<std::string_view> split(const std::string& s) {
    std::vector<std::string_view> parts;
    auto begin = std::find_if(s.begin(), s.end(), [](char c) { return !std::isspace(c); });
    auto end = std::find_if(begin, s.end(), [](char c) { return std::isspace(c); });
    while (begin != s.end()) {
        parts.emplace_back(begin, end);
        begin = std::find_if(end, s.end(), [](char c) { return !std::isspace(c); });
        end = std::find_if(begin, s.end(), [](char c) { return std::isspace(c); });
    }
    return parts;
}

struct MapInfo {
    std::size_t begin;
    std::size_t end;
    std::size_t offset;
    std::string filename;
};

std::vector<MapInfo> getMaps(pid_t pid) {
    std::vector<MapInfo> maps;
    std::ifstream file(fmt::format("/proc/{}/maps", pid));
    std::string line;
    while (std::getline(file, line)) {
        const auto v = split(line);
        if (v.at(1).at(2) != 'x' || v.size() != 6) {
            continue;
        }
        const auto i = v.at(0).find('-');
        assert(i != v.at(0).npos);

        const auto hex_to_size_t = [](const std::string_view& s) {
            std::size_t x;
            const auto [ptr, ec] = std::from_chars(s.begin(), s.end(), x, 16);
            assert(ptr == s.end() && ec == std::errc());
            return x;
        };

        maps.push_back(MapInfo{.begin = hex_to_size_t(v.at(0).substr(0, i)),
                               .end = hex_to_size_t(v.at(0).substr(i + 1)),
                               .offset = hex_to_size_t(v.at(2)),
                               .filename = std::string(v.at(5))});
    }
    return maps;
}

int main(int argc, char** argv) {
    // FIXME: For now, no options other than the command are passed.
    // FIXME: In the future, we should parse arguments and maybe isolate command with `---`.

    const auto pid = fork();

    if (pid == -1) {
        fmt::println(stderr, "failed fork: {}", std::strerror(errno));
        std::exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        execvp(argv[1], argv + 1);
        fmt::println(stderr, "failed exec: {}", std::strerror(errno));
        std::exit(EXIT_FAILURE);
    }

    perf_event_attr attr;
    std::memset(&attr, 0, sizeof(perf_event_attr));
    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof(perf_event_attr);
    attr.config = PERF_COUNT_HW_INSTRUCTIONS;
    attr.sample_freq = 10; // TODO.
    attr.freq = 1;         // TODO REPLACE.
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_WEIGHT | PERF_SAMPLE_CALLCHAIN;
    attr.disabled = 1;
    // attr.inherit = 1;
    attr.mmap = 1;
    attr.task = 1;
    attr.mmap2 = 1;
    // TODO use_clockid.
    attr.wakeup_events = 1 << N;

    const auto fd = perf_event_open_fallback_precise_ip(&attr, pid, -1, -1, 0);
    if (fd == -1) {
        fmt::println(stderr, "failed perf_event_open: {}", std::strerror(errno));
        std::exit(EXIT_FAILURE);
    }

    std::vector<pollfd> fds;
    fds.push_back({.fd = fd, .events = POLL_IN, .revents = 0});

    std::unordered_map<int, perf_event_mmap_page*> metadataByDescriptor;
    perf_event_mmap_page* metadata = static_cast<perf_event_mmap_page*>(
        mmap(nullptr, ((1 << N) + 1) * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
    if (metadata == MAP_FAILED) {
        fmt::println(stderr, "failed mmap: {}", std::strerror(errno));
        std::exit(EXIT_FAILURE);
    }
    metadataByDescriptor.emplace(fd, metadata);

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    // TODO: Store maps.

    while (!fds.empty()) {
        const auto status = poll(fds.data(), fds.size(), 1000); // TODO Adjust timeout?
        if (status == -1) {
            fmt::println(stderr, "failed poll: {}", std::strerror(errno));
            std::exit(EXIT_FAILURE);
        }
        if (status == 0) {
            fmt::println(stderr, "poll timeout");
            continue;
        }

        for (auto it = fds.begin(); it != fds.end();) {
            if (it->revents) {
                auto jt = metadataByDescriptor.find(it->fd);
                assert(jt != metadataByDescriptor.end());
                if (process_samples(jt->second)) {
                    ++it;
                } else {
                    munmap(jt->second, ((1 << N) + 1) * PAGE_SIZE);
                    close(it->fd);
                    it = fds.erase(it);
                    metadataByDescriptor.erase(jt);
                }
            } else {
                ++it;
            }
        }
    }
}
