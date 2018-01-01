#include <tls/client.hpp>
#include <iostream>

const char message[] = "Ala ma kota i kot ma ale";

int main(int argc, char ** argv) {
    tls::certificate certificate;
    certificate.parse_file("ca.crt");

    tls::private_key key;
    key.parse_file("ca.key", nullptr);
    tls::client client(&key, &certificate, &certificate);

    if (client.connect("127.0.0.1", "2345")) {
        client.write(message, sizeof(message));

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