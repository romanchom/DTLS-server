#include "server.hpp"

#include <stdexcept>
#include <iostream>
#include <memory>

#include "socket_input_output.hpp"
#include "standard_timer.hpp"
#include "ssl.hpp"

using namespace std;
namespace tls {
    server::server(private_key * own_key, certificate * own_certificate, certificate * ca_certificate)
    {
        m_random.seed(&m_entropy, "ASDQWE", 6);

        m_cookie.setup(&m_random);

        m_tls_configuration.set_defaults(endpoint::server, transport::datagram, preset::default_);
        m_tls_configuration.set_authentication_mode(authentication_mode::required);
        m_tls_configuration.set_random_generator(&m_random);
        m_tls_configuration.set_certifiate_authority_chain(ca_certificate);
        m_tls_configuration.set_own_certificate(own_certificate, own_key);
        m_tls_configuration.set_dtls_cookies(&m_cookie);
    }

    server::~server() {
    }

    void server::listen(uint16_t port) {
        standard_timer dtls_timer;

        auto m_listening_io = std::make_unique<socket_input_output>();
        
        cout << "Binding socket" << endl;
        m_listening_io->bind(nullptr, "2345", protocol::udp);

        cout << "Creating ssl session" << endl;
        auto current_ssl = std::make_unique<ssl>();
        current_ssl->setup(&m_tls_configuration);
        current_ssl->set_timer(&dtls_timer);

        for (;;) {
            cout << "Reseting state" << endl;
            auto client = std::make_unique<socket_input_output>();
            
            cout << "Waiting for clients" << endl;
            address client_address;
            m_listening_io->accept(client.get(), &client_address);

            cout << "Client requests connection" << endl;
            current_ssl->set_client_id(
                reinterpret_cast<unsigned char *>(client_address.data),
                client_address.size);
                
            current_ssl->set_input_output(client.get());

            cout << "Performing handshake" << endl;
            auto handshake_succesful = current_ssl->handshake();

            if (handshake_succesful) {
                cout << "Handshake successful" << endl;
                cout << "Allocating session" << endl;
                m_sessions.emplace_front(this, std::move(current_ssl), std::move(client));

                auto & sess = m_sessions.front();

                sess.set_listener(m_session_listener_factory());
                sess.start();

                cout << "Restoring state" << endl;
                current_ssl = std::make_unique<ssl>();
                current_ssl->setup(&m_tls_configuration);
                current_ssl->set_timer(&dtls_timer);
            } else {
                current_ssl->reset_session();
            }
        }
    }
}