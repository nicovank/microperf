#pragma once

// These types are different from the ones in the kernel.
// Some C++ features are used to make them easier to handle.
// They may be also be simplified with some fields removed, so care is needed when parsing them.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace perf {
struct file_section {
    std::uint64_t offset;
    std::uint64_t size;
};

struct header {
    std::array<char, 8> magic;
    std::uint64_t size;
    std::uint64_t attr_size;
    perf::file_section attrs;
    perf::file_section data;
    perf::file_section event_types;
    std::array<std::uint64_t, 4> flags;
};

// Most of these are only documented in perf_event.h.
namespace events {
struct header {
    std::uint32_t type;
    std::uint16_t misc;
    std::uint16_t size;
};

struct attr {
    std::uint32_t type;
    std::uint32_t size;
    std::uint64_t config;
    // 8 ignored bytes.
    std::uint64_t sample_type;
    std::uint64_t read_format;
};

struct exit {
    perf::events::header header;
    std::uint32_t pid, ppid;
    std::uint32_t tid, ptid;
    std::uint64_t time;
};

struct fork {
    perf::events::header header;
    std::uint32_t pid, ppid;
    std::uint32_t tid, ptid;
    std::uint64_t time;
};

struct mmap {
    perf::events::header header;
    std::uint32_t pid, tid;
    std::uint64_t addr;
    std::uint64_t len;
    std::uint64_t pgoff;
    // 24 ignored bytes in the MMAP2 case.
    std::optional<std::uint32_t> prot, flags; // prot and flags are only present in the MMAP2 case.
    std::string filename;
};

struct sample {
    perf::events::header header;
    std::optional<std::uint64_t> id;
    std::optional<std::uint64_t> ip;
    std::optional<std::uint32_t> pid, tid;
    std::optional<std::uint64_t> time;
    std::optional<std::uint64_t> addr;
    std::optional<std::uint64_t> stream_id;
    std::optional<std::uint32_t> cpu, res;
    std::optional<std::uint64_t> period;

    std::optional<std::vector<std::uint64_t>> callchain;
};
} // namespace events
} // namespace perf
