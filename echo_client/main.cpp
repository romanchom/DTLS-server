#include <tls/client.hpp>
#include <tls/private_key.hpp>
#include <tls/certificate.hpp>

#include <iostream>
#include <cstring>

int main(int argc, char ** argv) {
    if (4 != argc) {
        std::cout << "Wrong number of arguments, expected (ip port message)" << std::endl;
        return -1;
    }

    const char * ip = argv[1];
    const char * port = argv[2];
    const char * message = argv[3];

    tls::certificate certificate;
    certificate.parse_file("ca.crt");

    tls::private_key key;
    key.parse_file("ca.key", nullptr);
    tls::client client(&key, &certificate, &certificate);

    if (client.connect(ip, port)) {
        client.write(message, strlen(message) + 1);

        char buffer[1024];
        int size = sizeof(buffer);
        size = client.read(buffer, size);
        if (size > 0) {
            std::cout << buffer << std::endl;
        }
    } else {
        std::cout << "Failed to connect" << std::endl;
    }
        
    return 0;
}