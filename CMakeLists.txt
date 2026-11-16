# This is an integration of this project for CMake. See
# `bindings/c/examples/CMakeLists.txt` for an example of how to use it in your
# own projects.

cmake_minimum_required(VERSION 3.22)
project(zeek-websocket)

include(FetchContent)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_SHALLOW ON
    GIT_TAG v0.6.1
)
FetchContent_MakeAvailable(Corrosion)

corrosion_import_crate(MANIFEST_PATH Cargo.toml CRATES zeek-websocket-c)

corrosion_experimental_cbindgen(
  TARGET
  zeek_websocket_c
  HEADER_NAME
  "zeek-websocket.h"
  FLAGS
  --config
  ${CMAKE_CURRENT_SOURCE_DIR}/bindings/c/cbindgen.toml
)

# Wrap the library for easier consumption.
add_library(ZeekWebSocket INTERFACE)

# cmake-lint: disable=C0301
target_include_directories(
    ZeekWebSocket
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/corrosion_generated/cbindgen/zeek_websocket_c/include
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(ZeekWebSocket INTERFACE zeek_websocket_c)

option(ZEEK_WEBSOCKET_TESTING "Enable test targets" ON)
if(ZEEK_WEBSOCKET_TESTING)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        URL
            https://github.com/google/googletest/releases/download/v1.17.0/googletest-1.17.0.tar.gz
    )
    FetchContent_MakeAvailable(googletest)

    enable_testing()

    add_executable(
        test-cxx
        ${CMAKE_CURRENT_SOURCE_DIR}/bindings/c/tests/test.cc
    )
    target_link_libraries(test-cxx GTest::gtest_main ZeekWebSocket)

    include(GoogleTest)
    gtest_discover_tests(test-cxx)
endif(ZEEK_WEBSOCKET_TESTING)
