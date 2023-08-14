cmake_minimum_required(VERSION 3.16)

project(microperf)

include(FetchContent)
include(CheckIPOSupported)

set(CMAKE_CXX_STANDARD 20)

check_ipo_supported(RESULT IPO_SUPPORTED)
if(IPO_SUPPORTED)
    message(STATUS "IPO/LTO supported")
else()
    message(STATUS "IPO/LTO not supported")
endif()

FetchContent_Declare(
    boost
    GIT_REPOSITORY https://github.com/boostorg/boost.git
    GIT_TAG b6928ae5c92e21a04bbe17a558e6e066dbe632f6 # boost-1.82.0
)

FetchContent_Declare(
    fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG a0b8a92e3d1532361c2f7feb63babc5c18d00ef2 # 10.0.0
)

message(STATUS "Downloading and configuring Boost")
FetchContent_MakeAvailable(boost)

message(STATUS "Downloading and configuring {fmt}")
FetchContent_MakeAvailable(fmt)

file(GLOB SOURCES ${PROJECT_SOURCE_DIR}/src/*.cpp)
add_executable(uperf ${SOURCES})
set_property(TARGET uperf PROPERTY INTERPROCEDURAL_OPTIMIZATION ${IPO_SUPPORTED})
target_compile_options(uperf PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_include_directories(uperf PRIVATE include)
target_link_libraries(uperf PRIVATE Boost::program_options)
target_link_libraries(uperf PRIVATE fmt)
