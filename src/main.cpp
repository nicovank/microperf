#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <span>
#include <sstream>
#include <string>

#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <boost/program_options.hpp>

#include <fmt/core.h>
#include <fmt/ranges.h>

#define RING_BUFFER_SIZE 1 // A power of 2.

template <>
struct fmt::formatter<boost::program_options::options_description> {
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const boost::program_options::options_description& description, FormatContext& ctx) {
        std::ostringstream oss;
        oss << description;
        return format_to(ctx.out(), "{}", oss.view());
    }
};

namespace {
const auto options = [] {
    boost::program_options::options_description description("Options");

    // clang-format off
    description.add_options()
        ("pid,p", boost::program_options::value<pid_t>(), "Profile an existing process. This option should be present when the command is ommitted and vice-versa.")
        // TODO: Specify if this behavior also covers pre-existing children in the case of an existing process.
        ("inherit", boost::program_options::value<bool>()->default_value(true), "Start profiling child processes as they spawn.")
        ("help,h", "Produce a help message and exit.");
    // clang-format on

    return description;
}();

void printHelp() {
    fmt::println("Usage: uperf [OPTIONS...] [--- COMMAND ARGS...]");
    fmt::println("");
    fmt::println("{}", options);
}

boost::program_options::variables_map parse_args(int argc, char** argv) {
    boost::program_options::variables_map vm;

    for (int i = 0; i < argc; ++i) {
        if (strncmp(argv[i], "---", 3) == 0) {
            if (i + 1 != argc) {
                vm.emplace("command", boost::program_options::variable_value(argv + i + 1, false));
            }
            argc = i;
            break;
        }
    }

    try {
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, options), vm);

        if (vm.contains("help")) {
            printHelp();
            exit(EXIT_SUCCESS);
        }

        if (!(vm.contains("pid") ^ vm.contains("command"))) {
            fmt::println("Error: A PID or a command must be specified, but not both.");
            printHelp();
            exit(EXIT_FAILURE);
        }

        boost::program_options::notify(vm);
    } catch (const boost::program_options::error& e) {
        fmt::println("Error: {}", e.what());
        printHelp();
        exit(EXIT_FAILURE);
    }

    return vm;
}

int perf_event_open(struct perf_event_attr* attr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}
} // namespace

int main(int argc, char** argv) {
    [[maybe_unused]] auto vm = parse_args(argc, argv);

    const auto it = vm.find("command");
    if (it != vm.end()) {
        const auto pid = fork();
        if (pid == -1) {
            fmt::println("Error (fork): {}", strerror(errno));
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            const auto command = it->second.as<char**>();
            execvp(command[0], command);
            fmt::println(stderr, "Error (exec): {}\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        vm.erase(it);
        vm.emplace("pid", boost::program_options::variable_value(pid, false));
    }

    perf_event_attr attr;
    memset(&attr, 0, sizeof(perf_event_attr));
    attr.size = sizeof(perf_event_attr);

    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN;
    attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
    attr.disabled = 0; // TODO: Maybe start disabled.

    // We call perf_event_open separately for each child process.
    attr.inherit = 0;

    // We only support period profiling.
    // For now, it is set to every 1e9 cycles, or twice a second on a 2GHz chip.
    attr.freq = 0;
    attr.sample_period = 1e9;

    // Generate MMAP records.
    attr.mmap = 1;
    attr.mmap_data = 0;
    attr.mmap2 = 1;

    // Generate FORK/EXIT records.
    attr.task = 1;

    // TODO: We may not care for this.
    attr.comm = 1;

    // We lower this progressively to obtain the best possible precision.
    attr.precise_ip = 3;

    // TODO: We may possibly want this.
    attr.build_id = 0;

    // Wake up every N events, matching the size of the ring buffer.
    attr.watermark = 0;
    attr.wakeup_events = RING_BUFFER_SIZE;
    attr.write_backward = 1;

    auto fd = perf_event_open(&attr, vm.at("pid").as<pid_t>(), -1, -1, 0);
    while (fd == -1 && attr.precise_ip > 0) {
        fmt::println(stderr, "Error (perf_event_open): {}\n", strerror(errno));
        fmt::println(stderr, "Error (perf_event_open): Lowering precise_ip to {}...", (int) attr.precise_ip - 1);
        --attr.precise_ip;
        fd = perf_event_open(&attr, vm.at("pid").as<pid_t>(), -1, -1, 0);
    }

    if (fd == -1) {
        fmt::println("Error (perf_event_open): {}", strerror(errno));
        exit(EXIT_FAILURE);
    }

    fmt::println("It worked!");
    void* buffer = mmap(nullptr, 1 + RING_BUFFER_SIZE, PROT_READ, MAP_SHARED, fd, 0);
    if (buffer == MAP_FAILED) {
        fmt::println("Error (mmap): {}", strerror(errno));
        exit(EXIT_FAILURE);
    }

    const perf_event_mmap_page& header = *static_cast<perf_event_mmap_page*>(buffer);

    auto pfd = pollfd{.fd = fd, .events = POLLIN, .revents = 0};
    poll(&pfd, 1, -1);

    fmt::println("header.version = {}", header.version);
    fmt::println("header.time_enabled = {}", header.time_enabled);
    fmt::println("header.time_running = {}", header.time_running);

    waitpid(vm.at("pid").as<pid_t>(), nullptr, 0);

    return EXIT_SUCCESS;
}
