#include <cerrno>
#include <cstdio>
#include <cstring>
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
    attr.sample_freq = 4000; // TODO.
    attr.freq = 1;           // TODO REPLACE.
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
    fmt::println("{}", metadata->data_head);
    fmt::println("{}", metadata->data_tail);
    fmt::println("{}", metadata->data_offset);
    fmt::println("{}", metadata->data_size);
    fmt::println("{}", metadata->time_enabled);
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
            fmt::println("poll event {}", metadata->data_head);
            metadata->data_tail = metadata->data_head;
        }
        // fmt::println("status: {}", status);
    }

    fmt::println("{}", metadata->data_head);
    fmt::println("{}", metadata->data_tail);
    fmt::println("{}", metadata->data_offset);
    fmt::println("{}", metadata->data_size);
    fmt::println("{}", metadata->time_enabled);

    munmap(buffer, ((1 << N) + 1) * PAGE_SIZE);
    close(fd);
}
