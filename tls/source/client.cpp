#include "client.hpp"

namespace tls {
    client::client(private_key * own_key, certificate * own_certificate, certificate * ca_certificate) :
        m_is_connected(false)
    {
        m_random.seed(&m_entropy, "ASDQWE", 6);

        m_tls_configuration.set_defaults(endpoint::client, transport::datagram, preset::default_);
        m_tls_configuration.set_authentication_mode(authentication_mode::required);
        m_tls_configuration.set_random_generator(&m_random);
        m_tls_configuration.set_certifiate_authority_chain(ca_certificate);
        m_tls_configuration.set_own_certificate(own_certificate, own_key);

        m_ssl.setup(&m_tls_configuration);
        m_ssl.set_timer(&m_timer);
    }

    client::~client() {
        disconnect();
    }

    bool client::connect(const char * address, const char * port) {
        disconnect();
        
        m_socket.connect(address, port, protocol::udp);
        //m_ssl.set_host_name("");
        m_ssl.set_input_output(&m_socket);
        m_is_connected = m_ssl.handshake();
        return m_is_connected;
    }

    void client::disconnect() {
        if (m_is_connected) {
            m_ssl.close_notify();
            m_ssl.reset_session();
            m_is_connected = false;
        }
    }
    
    int client::read(char * data, size_t data_length) {
        int ret = m_ssl.read(data, data_length);
        if (ret < 0) {
            m_is_connected = false;
        }
        return ret;
    }

    int client::write(const char * data, size_t data_length) {
        return m_ssl.write(data, data_length);
    }
}
