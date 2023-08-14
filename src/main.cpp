#include <cstdlib>
#include <cstring>
#include <string>

#include <boost/program_options.hpp>

#include <fmt/core.h>

int main(int argc, char** argv) {
    fmt::println("Hello, World!");
    for (int i = 0; i < argc; ++i) {
        if (strncmp(argv[i], "---", 3) == 0) {
            fmt::println("Found overflow arguments...");
        }
    }
    return EXIT_SUCCESS;
}
