cmake_minimum_required(VERSION 3.7)

set(CMAKE_CXX_STANDARD 14)

project(server)

add_subdirectory(tls)
add_subdirectory(echo_server)
add_subdirectory(echo_client)
