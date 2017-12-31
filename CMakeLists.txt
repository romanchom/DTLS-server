cmake_minimum_required(VERSION 3.9)

set (CMAKE_CXX_STANDARD 14)
set(CMAKE_BUILD_TYPE Debug)

project(server)

add_executable(server 
    main.cpp
    server.cpp
    session.cpp
    session_listener.cpp) 

target_link_libraries(server
    -lmbedtls
    -lmbedcrypto
    -lmbedx509
    -pthread)
    

add_executable(client client.cpp)
target_link_libraries(client -lssl -lcrypto -pthread)