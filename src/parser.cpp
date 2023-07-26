#include <uperf/parser.hpp>

#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <ranges>
#include <vector>

#include <linux/perf_event.h>

#include <fmt/core.h>

namespace {
template <typename T>
std::vector<T> read(FILE* stream, std::size_t nmemb) {
    std::vector<T> buffer(nmemb);
    if (::fread(buffer.data(), sizeof(T), nmemb, stream) != nmemb) {
        fmt::println(stderr, "Failed to read from stream");
        std::abort();
    }
    return buffer;
}

template <typename T>
T read(FILE* stream) {
    T buffer;
    if (::fread(&buffer, sizeof(T), 1, stream) != 1) {
        fmt::println(stderr, "Failed to read from stream");
        std::abort();
    }
    return buffer;
}
} // namespace

perf::header uperf::parser::readHeader(FILE* stream) {
    perf::header header;
    for (std::size_t i = 0; i < header.magic.size(); ++i) {
        header.magic[i] = read<char>(stream);
    }
    header.size = read<std::uint64_t>(stream);
    header.attr_size = read<std::uint64_t>(stream);
    header.attrs = readFileSection(stream);
    header.data = readFileSection(stream);
    header.event_types = readFileSection(stream);
    for (std::size_t i = 0; i < header.flags.size(); ++i) {
        header.flags[i] = read<std::uint64_t>(stream);
    }
    return header;
}

perf::file_section uperf::parser::readFileSection(FILE* stream) {
    perf::file_section section;
    section.offset = read<std::uint64_t>(stream);
    section.size = read<std::uint64_t>(stream);
    return section;
}

perf::events::header uperf::parser::readEventHeader(FILE* stream) {
    perf::events::header header;
    header.type = read<std::uint32_t>(stream);
    header.misc = read<std::uint16_t>(stream);
    header.size = read<std::uint16_t>(stream);
    return header;
}

perf::events::attr uperf::parser::readEventAttributes(FILE* stream) {
    perf::events::attr attr;
    attr.type = read<std::uint32_t>(stream);
    attr.size = read<std::uint32_t>(stream);
    attr.config = read<std::uint64_t>(stream);
    fseek(stream, 8, SEEK_CUR);
    attr.sample_type = read<std::uint64_t>(stream);
    attr.read_format = read<std::uint64_t>(stream);
    return attr;
}

perf::events::exit uperf::parser::readExitEvent(FILE* stream, const perf::events::attr&, perf::events::header header) {
    perf::events::exit event;
    event.header = header;
    event.pid = read<std::uint32_t>(stream);
    event.ppid = read<std::uint32_t>(stream);
    event.tid = read<std::uint32_t>(stream);
    event.ptid = read<std::uint32_t>(stream);
    event.time = read<std::uint64_t>(stream);
    return event;
}

perf::events::fork uperf::parser::readForkEvent(FILE* stream, const perf::events::attr&, perf::events::header header) {
    perf::events::fork event;
    event.header = header;
    event.pid = read<std::uint32_t>(stream);
    event.ppid = read<std::uint32_t>(stream);
    event.tid = read<std::uint32_t>(stream);
    event.ptid = read<std::uint32_t>(stream);
    event.time = read<std::uint64_t>(stream);
    return event;
}

perf::events::mmap uperf::parser::readMmapEvent(FILE* stream, const perf::events::attr&, perf::events::header header) {
    perf::events::mmap event;
    event.header = header;
    event.pid = read<std::uint32_t>(stream);
    event.tid = read<std::uint32_t>(stream);
    event.addr = read<std::uint64_t>(stream);
    event.len = read<std::uint64_t>(stream);
    event.pgoff = read<std::uint64_t>(stream);
    if (header.type == PERF_RECORD_MMAP2) {
        fseek(stream, 24, SEEK_CUR);
        event.prot = read<std::uint32_t>(stream);
        event.flags = read<std::uint32_t>(stream);
    }
    std::vector<char> filename;
    for (char c = read<char>(stream); c != '\0'; c = read<char>(stream)) {
        filename.push_back(c);
    }
    event.filename = std::string(filename.begin(), filename.end());
    return event;
}

perf::events::sample uperf::parser::readSampleEvent(FILE* stream, const perf::events::attr& attr,
                                                    perf::events::header header) {
    perf::events::sample event;
    event.header = header;

    if (attr.sample_type & PERF_SAMPLE_IDENTIFIER) {
        event.id = read<std::uint64_t>(stream);
    }

    if (attr.sample_type & PERF_SAMPLE_IP) {
        event.ip = read<std::uint64_t>(stream);
    }

    if (attr.sample_type & PERF_SAMPLE_TID) {
        event.pid = read<std::uint32_t>(stream);
        event.tid = read<std::uint32_t>(stream);
    }

    if (attr.sample_type & PERF_SAMPLE_TIME) {
        event.time = read<std::uint64_t>(stream);
    }

    if (attr.sample_type & PERF_SAMPLE_ADDR) {
        event.addr = read<std::uint64_t>(stream);
    }

    if (attr.sample_type & PERF_SAMPLE_ID) {
        event.id = read<std::uint64_t>(stream);
    }

    if (attr.sample_type & PERF_SAMPLE_STREAM_ID) {
        event.stream_id = read<std::uint64_t>(stream);
    }

    if (attr.sample_type & PERF_SAMPLE_CPU) {
        event.cpu = read<std::uint32_t>(stream);
        event.res = read<std::uint32_t>(stream);
    }

    if (attr.sample_type & PERF_SAMPLE_PERIOD) {
        event.period = read<std::uint64_t>(stream);
    }

    assert(!(attr.sample_type & PERF_SAMPLE_READ));

    if (attr.sample_type & PERF_SAMPLE_CALLCHAIN) {
        event.callchain = read<std::uint64_t>(stream, read<std::uint64_t>(stream));
    }

    return event;
}
