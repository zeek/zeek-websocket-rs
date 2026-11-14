cmake_minimum_required(VERSION 3.22)
project(foo C CXX)

include(FetchContent)

# Pull in the library.
FetchContent_Declare(
    ZeekWebsocket
    GIT_SHALLOW ON
    GIT_REPOSITORY https://github.com/bbannier/zeek-websocket-rs.git
    # TODO: replace `main` with a Git tag or revision.
    GIT_TAG main
)
FetchContent_MakeAvailable(ZeekWebsocket)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(example-c example.c)
target_link_libraries(example-c ZeekWebSocket)

add_executable(example-cxx example.cc)
target_link_libraries(example-cxx ZeekWebSocket)
