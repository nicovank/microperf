# Bad Patterns


> **Warning**
> This is a work in progress.

## Build

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

[badpatterns] python3 build.py
```
