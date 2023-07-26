cmake_minimum_required(VERSION 3.16)

project(microperf)

include(FetchContent)
include(CheckIPOSupported)

set(CMAKE_CXX_STANDARD 20)

check_ipo_supported(RESULT IPO_SUPPORTED)
if(IPO_SUPPORTED)
    message(STATUS "IPO/LTO supported")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
else()
    message(STATUS "IPO/LTO not supported")
endif()

FetchContent_Declare(
    fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG a0b8a92e3d1532361c2f7feb63babc5c18d00ef2 # 10.0.0
)

message(STATUS "Downloading and configuring {fmt}")
FetchContent_MakeAvailable(fmt)

file(GLOB SOURCES ${PROJECT_SOURCE_DIR}/src/*.cpp)
add_executable(microperf ${SOURCES})
target_compile_options(microperf PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_include_directories(microperf PRIVATE include)
target_link_libraries(microperf PRIVATE fmt)
