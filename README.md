# MicroPerf

> **Warning**
> This is a work in progress.

## `perf`

I recommend the following commands to build this project on Ubuntu.
Most packages are needed to enable perf features, some may not be necessary.
They may be named differently on other distributions.

```
[~] sudo apt update

[~] sudo apt install -y       \
        binutils-dev          \
        bison                 \
        flex                  \
        g++                   \
        git                   \
        libdw-dev             \
        libbabeltrace-ctf-dev \
        libtraceevent-dev     \
        libcap-dev            \
        libelf-dev            \
        libiberty-dev         \
        liblzma-dev           \
        libnuma-dev           \
        libperl-dev           \
        libpfm4-dev           \
        libslang2-dev         \
        libssl-dev            \
        libunwind-dev         \
        libzstd-dev           \
        make                  \
        openjdk-11-jdk        \
        pkg-config            \
        python3-dev           \
        python3-setuptools    \
        systemtap-sdt-dev

[microperf] python3 build.py
```

## Presto

A Docker image is provided to run Presto with this suite of tools.
It differs slightly from the official image, for example removing the `-Xmx1G`
JVM flag to allow processing of larger profiles.

```
[perf-tools] docker image build presto --compress --tag perf-presto
[perf-tools] docker run -d -p 8080:8080 --name perf-presto perf-presto
```
