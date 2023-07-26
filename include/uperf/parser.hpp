#pragma once

#include <cstdio>

#include <uperf/perf_types.hpp>

namespace uperf::parser {
perf::header readHeader(FILE* stream);
perf::file_section readFileSection(FILE* stream);
perf::events::header readEventHeader(FILE* stream);
perf::events::attr readEventAttributes(FILE* stream);
perf::events::exit readExitEvent(FILE* stream, const perf::events::attr& attr, perf::events::header header);
perf::events::fork readForkEvent(FILE* stream, const perf::events::attr& attr, perf::events::header header);
perf::events::mmap readMmapEvent(FILE* stream, const perf::events::attr& attr, perf::events::header header);
perf::events::sample readSampleEvent(FILE* stream, const perf::events::attr& attr, perf::events::header header);
// perf::events::sample readSampleEvent(FILE* stream, perf::events::header header);
} // namespace uperf::parser
