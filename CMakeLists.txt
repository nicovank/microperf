cmake_minimum_required(VERSION 3.25)
project(microperf)

include(FetchContent)

FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG e69e5f977d458f2650bb346dadf2ad30c5320281 # 10.2.1
)

FetchContent_Declare(
  cpp-subprocess
  GIT_REPOSITORY https://github.com/arun11299/cpp-subprocess.git
  GIT_TAG master
)

message(STATUS "Downloading and configuring {fmt}")
FetchContent_MakeAvailable(fmt)

message(STATUS "Downloading and configuring cpp-subprocess")
FetchContent_MakeAvailable(cpp-subprocess)

add_executable(uperf src/main.cpp)
target_link_libraries(uperf PRIVATE fmt::fmt)
target_link_libraries(uperf PRIVATE subprocess)
set_property(TARGET uperf PROPERTY CXX_STANDARD 20)
set_property(TARGET uperf PROPERTY CXX_STANDARD_REQUIRED ON)


add_executable(benchmark src/benchmark.cpp)
