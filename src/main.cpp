#include <cstdlib>
#include <cstring>
#include <optional>
#include <span>
#include <sstream>
#include <string>

#include <unistd.h>

#include <boost/program_options.hpp>

#include <fmt/core.h>
#include <fmt/ranges.h>

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
    std::optional<std::pair<int, char**>> command;
    for (int i = 0; i < argc; ++i) {
        if (strncmp(argv[i], "---", 3) == 0) {
            if (i + 1 != argc) {
                command = std::make_pair(argc - i - 1, argv + i + 1);
            }
            argc = i;
            break;
        }
    }

    boost::program_options::variables_map vm;
    try {
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, options), vm);

        if (vm.contains("help")) {
            printHelp();
            exit(EXIT_SUCCESS);
        }

        if (!(vm.contains("pid") ^ command.has_value())) {
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
} // namespace

int main(int argc, char** argv) {
    [[maybe_unused]] auto vm = parse_args(argc, argv);

    return EXIT_SUCCESS;
}
