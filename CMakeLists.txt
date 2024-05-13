cmake_minimum_required(VERSION 3.25)
project(microperf)

include(FetchContent)

FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG e69e5f977d458f2650bb346dadf2ad30c5320281 # 10.2.1
)

message(STATUS "Downloading and configuring {fmt}")
FetchContent_MakeAvailable(fmt)

add_executable(uperf src/main.cpp)
target_link_libraries(uperf PRIVATE fmt::fmt)

add_executable(benchmark src/benchmark.cpp)
