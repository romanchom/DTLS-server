#pragma once

#include <list>
#include <cstdint>
#include <functional>

#include "certificate.hpp"
#include "private_key.hpp"
#include "standard_entropy.hpp"
#include "counter_deterministic_random_generator.hpp"
#include "configuration.hpp"
#include "standard_cookie.hpp"
#include "session_listener.hpp"
#include "session.hpp"

namespace tls {
    class server {
    public:
        using session_listener_factory_t = std::function<std::unique_ptr<session_listener>()>;
        
        server(const char * key_name, const char* certificate_name);
        ~server();
        void listen(uint16_t port);
        void set_session_listener_factory(session_listener_factory_t callback) {
            m_session_listener_factory = callback;
        }
    private:
        void create_socket();
        void create_ssl();
        void accept_client();

        uint16_t m_port;
        tls::certificate m_certificate;
        tls::private_key m_key;
        tls::standard_entropy m_entropy;
        tls::counter_deterministic_random_generator m_random;
        tls::configuration m_tls_configuration;
        tls::standard_cookie m_cookie;

        session_listener_factory_t m_session_listener_factory;

        std::list<session> m_sessions;
    };
}
