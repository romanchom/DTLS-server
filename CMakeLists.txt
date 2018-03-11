cmake_minimum_required(VERSION 3.7)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_BUILD_TYPE Debug)

project(server)

add_subdirectory(tls)
add_subdirectory(echo_server)
add_subdirectory(echo_client)
