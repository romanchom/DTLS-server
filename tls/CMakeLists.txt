cmake_minimum_required(VERSION 3.9)

project(tls)

set(SOURCES
    source/exception.cpp
    source/client.cpp
    source/server.cpp
    source/session_listener.cpp
    source/session.cpp
)

add_library(tls ${SOURCES})
target_include_directories(tls PUBLIC include)
target_include_directories(tls PRIVATE include/tls)
target_link_libraries(tls
    -lmbedtls
    -lmbedcrypto
    -lmbedx509
    -pthread
)
