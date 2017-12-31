#include "server.hpp"

#include <stdexcept>
#include <iostream>
#include <memory>

#include "tls/socket_input_output.hpp"
#include "tls/standard_timer.hpp"
#include "tls/ssl.hpp"

using namespace tls;
using namespace std;

server::server(const char * key_name, const char* certificate_name)
{
    m_certificate.parse_file(certificate_name);
    m_key.parse_file(key_name, nullptr);
    
    m_random.seed(&m_entropy, "ASDQWE", 6);

    m_cookie.setup(&m_random);

    m_tls_configuration.set_defaults(endpoint::server, transport::datagram, preset::default_);
    m_tls_configuration.set_random_generator(&m_random);
    m_tls_configuration.set_certifiate_authority_chain(&m_certificate);
    m_tls_configuration.set_own_certificate(&m_certificate, &m_key);
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
        current_ssl->reset_session();
        
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
        }
    }
}
