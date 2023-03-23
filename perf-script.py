import os
import sys

print(os.environ["PERF_EXEC_PATH"])

sys.path.append(
    f"{os.environ['PERF_EXEC_PATH']}/scripts/python/Perf-Trace-Util/lib/Perf/Trace"
)

from perf_trace_context import perf_script_context, perf_sample_srcline


# FIXME: This will remove the < and > from operator< and operator>.
def strip_cxx_templates(symbol):
    depth = 0
    result = ""
    for c in symbol:
        if c == "<":
            depth += 1
        elif c == ">":
            depth -= 1
        elif depth == 0:
            result += c
    return result


def process_event(event):
    assert "callchain" in event

    for frame in event["callchain"]:
        symbol = "[unknown]"
        if "sym" in frame and "name" in frame["sym"]:
            symbol = strip_cxx_templates(frame["sym"]["name"])

        location = frame.get("sym_srcline", "[unknown]")
        print("{}@{}".format(symbol, location))
    print()


# ./local/bin/perf script -s perf-script.py -F+srcline --full-source-path
