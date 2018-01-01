
#include <iostream>
#include <tls/session_listener.hpp>
#include <tls/server.hpp>

class echo : public tls::session_listener {
public:
    void on_session_started() {
        std::cout << "Echo started" << std::endl;
    }

    void on_data_received(const char * data, size_t data_length) {
        std::cout << "Received " << data << std::endl;
        m_session->write(data, data_length);
    }

    void on_session_ended(tls::session_end_reason reason) {
        std::cout << "Echo ended " << std::endl;
    }
};

int main(int argc, char ** argv) {
    tls::certificate certificate;
    certificate.parse_file("ca.crt");

    tls::private_key key;
    key.parse_file("ca.key", nullptr);
    tls::server serv(&key, &certificate, &certificate);

    serv.set_session_listener_factory([](){
        return std::make_unique<echo>();
    });

    serv.listen(2345);

    return 0;
}