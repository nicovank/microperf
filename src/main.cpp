#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <span>
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
int perf_event_open(struct perf_event_attr* attr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int perf_event_open_fallback_precise_ip(struct perf_event_attr* attr, pid_t pid, int cpu, int group_fd,
                                        unsigned long flags) {
    for (std::uint64_t precise_ip = 3; precise_ip <= 3; --precise_ip) {
        attr->precise_ip = precise_ip;
        const auto fd = syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
        if (fd != -1) {
            fmt::println("precise_ip: {}", precise_ip);
            return fd;
        }
    }
    return -1;
}
} // namespace

namespace perf::sample {
std::uint64_t get_sample_id(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_IDENTIFIER);
    std::size_t offset = sizeof(perf_event_header);
    return *reinterpret_cast<const std::uint64_t*>(header + offset);
}

std::uint64_t get_ip(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_IP);
    std::size_t offset = sizeof(perf_event_header);
    offset += (sample_type & PERF_SAMPLE_IDENTIFIER) ? sizeof(std::uint64_t) : 0;
    return *reinterpret_cast<const std::uint64_t*>(header + offset);
}

std::uint32_t get_pid(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_TID);
    std::size_t offset = sizeof(perf_event_header);
    offset += (sample_type & PERF_SAMPLE_IDENTIFIER) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_IP) ? sizeof(std::uint64_t) : 0;
    return *reinterpret_cast<const std::uint32_t*>(header + offset);
}

std::uint32_t get_tid(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_TID);
    std::size_t offset = sizeof(perf_event_header);
    offset += (sample_type & PERF_SAMPLE_IDENTIFIER) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_IP) ? sizeof(std::uint64_t) : 0;
    return *reinterpret_cast<const std::uint32_t*>(header + offset + sizeof(std::uint32_t));
}

std::uint64_t get_time(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_TIME);
    std::size_t offset = sizeof(perf_event_header);
    offset += (sample_type & PERF_SAMPLE_IDENTIFIER) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_IP) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_TID) ? 2 * sizeof(std::uint32_t) : 0;
    return *reinterpret_cast<const std::uint64_t*>(header + offset);
}

std::uint64_t get_addr(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_ADDR);
    std::size_t offset = sizeof(perf_event_header);
    offset += (sample_type & PERF_SAMPLE_IDENTIFIER) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_IP) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_TID) ? 2 * sizeof(std::uint32_t) : 0;
    offset += (sample_type & PERF_SAMPLE_TIME) ? sizeof(std::uint64_t) : 0;
    return *reinterpret_cast<const std::uint64_t*>(header + offset);
}

std::uint64_t get_id(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_ID);
    std::size_t offset = sizeof(perf_event_header);
    offset += (sample_type & PERF_SAMPLE_IDENTIFIER) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_IP) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_TID) ? 2 * sizeof(std::uint32_t) : 0;
    offset += (sample_type & PERF_SAMPLE_TIME) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_ADDR) ? sizeof(std::uint64_t) : 0;
    return *reinterpret_cast<const std::uint64_t*>(header + offset);
}

std::uint64_t get_stream_id(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_STREAM_ID);
    std::size_t offset = sizeof(perf_event_header);
    offset += (sample_type & PERF_SAMPLE_IDENTIFIER) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_IP) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_TID) ? 2 * sizeof(std::uint32_t) : 0;
    offset += (sample_type & PERF_SAMPLE_TIME) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_ADDR) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_ID) ? sizeof(std::uint64_t) : 0;
    return *reinterpret_cast<const std::uint64_t*>(header + offset);
}

std::uint32_t get_cpu(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_CPU);
    std::size_t offset = sizeof(perf_event_header);
    offset += (sample_type & PERF_SAMPLE_IDENTIFIER) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_IP) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_TID) ? 2 * sizeof(std::uint32_t) : 0;
    offset += (sample_type & PERF_SAMPLE_TIME) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_ADDR) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_ID) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_STREAM_ID) ? sizeof(std::uint64_t) : 0;
    return *reinterpret_cast<const std::uint32_t*>(header + offset);
}

std::uint32_t get_res(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_CPU);
    std::size_t offset = sizeof(perf_event_header);
    offset += (sample_type & PERF_SAMPLE_IDENTIFIER) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_IP) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_TID) ? 2 * sizeof(std::uint32_t) : 0;
    offset += (sample_type & PERF_SAMPLE_TIME) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_ADDR) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_ID) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_STREAM_ID) ? sizeof(std::uint64_t) : 0;
    return *reinterpret_cast<const std::uint32_t*>(header + offset + sizeof(std::uint32_t));
}

std::uint64_t get_period(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_PERIOD);
    std::size_t offset = sizeof(perf_event_header);
    offset += (sample_type & PERF_SAMPLE_IDENTIFIER) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_IP) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_TID) ? 2 * sizeof(std::uint32_t) : 0;
    offset += (sample_type & PERF_SAMPLE_TIME) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_ADDR) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_ID) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_STREAM_ID) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_CPU) ? 2 * sizeof(std::uint32_t) : 0;
    return *reinterpret_cast<const std::uint64_t*>(header + offset);
}

struct read_format {
    std::uint64_t value;
    std::uint64_t time_enabled;
    std::uint64_t time_running;
    std::uint64_t id;
    std::uint64_t lost;
};

const read_format& get_v(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_READ);
    assert(!(sample_type & PERF_SAMPLE_READ)); // PERF_FORMAT_GOUP not supported.
    std::size_t offset = sizeof(perf_event_header);
    offset += (sample_type & PERF_SAMPLE_IDENTIFIER) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_IP) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_TID) ? 2 * sizeof(std::uint32_t) : 0;
    offset += (sample_type & PERF_SAMPLE_TIME) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_ADDR) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_ID) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_STREAM_ID) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_CPU) ? 2 * sizeof(std::uint32_t) : 0;
    offset += (sample_type & PERF_SAMPLE_PERIOD) ? sizeof(std::uint64_t) : 0;
    return *reinterpret_cast<const read_format*>(header + offset);
}

std::span<const std::uint64_t> get_ips(const perf_event_header* header, std::uint64_t sample_type) {
    assert(sample_type & PERF_SAMPLE_CALLCHAIN);
    assert(!(sample_type & PERF_SAMPLE_READ)); // PERF_FORMAT_GOUP not supported.
    std::size_t offset = sizeof(perf_event_header);
    offset += (sample_type & PERF_SAMPLE_IDENTIFIER) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_IP) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_TID) ? 2 * sizeof(std::uint32_t) : 0;
    offset += (sample_type & PERF_SAMPLE_TIME) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_ADDR) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_ID) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_STREAM_ID) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_CPU) ? 2 * sizeof(std::uint32_t) : 0;
    offset += (sample_type & PERF_SAMPLE_PERIOD) ? sizeof(std::uint64_t) : 0;
    offset += (sample_type & PERF_SAMPLE_READ) ? sizeof(read_format) : 0;
    const auto nr = *reinterpret_cast<const std::uint64_t*>(header + offset);
    return std::span(reinterpret_cast<const std::uint64_t*>(header + offset + sizeof(std::uint64_t)), nr);
}
} // namespace perf::sample

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

    struct perf_event_attr attr;
    std::memset(&attr, 0, sizeof(struct perf_event_attr));
    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof(struct perf_event_attr);
    attr.config = PERF_COUNT_HW_INSTRUCTIONS;
    attr.sample_freq = 10; // TODO.
    attr.freq = 1;         // TODO REPLACE.
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_WEIGHT | PERF_SAMPLE_CALLCHAIN;
    attr.disabled = 1;
    // attr.inherit = 1;
    // attr.mmap = 1;
    // attr.task = 1;
    // attr.mmap2 = 1;
    // TODO use_clockid.
    attr.wakeup_events = 1 << N;

    const auto fd = perf_event_open_fallback_precise_ip(&attr, pid, -1, -1, 0);
    if (fd == -1) {
        fmt::println(stderr, "failed perf_event_open: {}", std::strerror(errno));
        std::exit(EXIT_FAILURE);
    }

    std::vector<struct pollfd> fds;
    fds.push_back({.fd = fd, .events = POLL_IN, .revents = 0});

    auto* buffer = mmap(nullptr, ((1 << N) + 1) * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buffer == MAP_FAILED) {
        fmt::println(stderr, "failed mmap: {}", std::strerror(errno));
        std::exit(EXIT_FAILURE);
    }
    auto* metadata = static_cast<perf_event_mmap_page*>(buffer);

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    while (true) {
        {
            const auto status = waitpid(pid, nullptr, WNOHANG);
            if (status == -1) {
                fmt::println(stderr, "failed waitpid: {}", std::strerror(errno));
                std::exit(EXIT_FAILURE);
            }
            if (status != 0) {
                break;
            }
        }

        const auto status = poll(fds.data(), fds.size(), 1000);
        if (status == -1) {
            fmt::println(stderr, "failed poll: {}", std::strerror(errno));
            std::exit(EXIT_FAILURE);
        }
        if (status == 0) {
            fmt::println(stderr, "poll timeout");
        } else {
            const auto head = metadata->data_head;
            // TODO: smp_rmb()?
            const auto tail = metadata->data_tail;

            int n = 0;
            while (metadata->data_tail < head) {
                const auto* record
                    = reinterpret_cast<perf_event_header*>(reinterpret_cast<uintptr_t>(buffer) + metadata->data_offset
                                                           + (metadata->data_tail % ((1 << N) * PAGE_SIZE)));
                metadata->data_tail += record->size;
                fmt::println("{}, {}", record->type, record->size);
                fmt::println("{} {} {}", perf::sample::get_ip(record, attr.sample_type),
                             perf::sample::get_pid(record, attr.sample_type),
                             perf::sample::get_tid(record, attr.sample_type));
                ++n;
            }
            metadata->data_tail = head;
        }
        // fmt::println("status: {}", status);
    }

    munmap(buffer, ((1 << N) + 1) * PAGE_SIZE);
    close(fd);
}
