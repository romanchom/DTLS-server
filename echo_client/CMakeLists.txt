add_executable(echo_client main.cpp)
target_link_libraries(echo_client -lssl -lcrypto -pthread)
