# microperf

[![PyPI](https://img.shields.io/pypi/v/microperf.svg)](https://pypi.org/project/microperf/)
[![downloads](https://static.pepy.tech/badge/microperf)](https://pepy.tech/project/microperf)

> **Warning**
> This is a work in progress.

## Presto

A Docker image is provided to run Presto with this suite of tools.
It differs slightly from the official image, for example removing the `-Xmx1G`
JVM flag to allow processing of larger profiles.

```
% docker image build microperf/presto --compress --tag perf-presto
% docker run -d -p 8080:8080 --name perf-presto perf-presto
```
