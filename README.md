# microperf

[![PyPI](https://img.shields.io/pypi/v/microperf.svg)](https://pypi.org/project/microperf/)
[![downloads](https://static.pepy.tech/badge/microperf)](https://pepy.tech/project/microperf)

`microperf` is a [`perf`](https://perfwiki.github.io) wrapper. The basic idea is
that it converts a `perf.data` file by inserting all samples into a database,
making it then easier to query for specific patterns or code smells.

## Usage

### Generating a Profile

First, note that your executable should be compiled with debug symbols (`-g`,
`-DCMAKE_BUILD_TYPE=RelWithDebInfo`, ...).

Since `microperf` is simply a wrapper, generating a profile can be done directly
with `perf`.
```bash
perf record -F99 --call-graph=dwarf -- <COMMAND>
```

Alternatively, `microperf perf` provides a convenience passthrough to `perf`.
This can be useful when a different `perf` executable should be used (see
`MICROPERF_PERF_EXE` option below).

## Options

The environment variable `MICROPERF_PERF_EXE` can be set to the path of a `perf`
executable to be used instead of the default `perf` command.

## Presto

A Docker image is provided to run Presto with this suite of tools.
It differs slightly from the official image, for example removing the `-Xmx1G`
JVM flag to allow processing of larger profiles.

```
% docker image build microperf/presto --compress --tag perf-presto
% docker run -d -p 8080:8080 --name perf-presto perf-presto
```
