#pragma once

#include "standard_entropy.hpp"
#include "counter_deterministic_random_generator.hpp"
#include "configuration.hpp"
#include "ssl.hpp"
#include "socket_input_output.hpp"
#include "standard_timer.hpp"

namespace tls {
    class private_key;
    class certificate;
    
    class client {
    public:
        client(private_key * own_key, certificate * own_certificate, certificate * ca_certificate);
        ~client();

        bool connect(const char * address, const char * port);
        void disconnect();
        int read(uint8_t * data, size_t data_length);
        int write(uint8_t const * data, size_t data_length);
    private:
        standard_entropy m_entropy;
        counter_deterministic_random_generator m_random;
        standard_timer m_timer;

        configuration m_tls_configuration;
        ssl m_ssl;
        socket_input_output m_socket;
        bool m_is_connected;
    };
}
