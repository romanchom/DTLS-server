#include "server.hpp"

#include <iostream>
#include "session_listener.hpp"

class echo : public session_listener {
public:
    void on_session_started() {
        std::cout << "Echo started" << std::endl;
    }
    void on_data_received(const char * data, size_t data_length) {
        std::cout << "Received " << data << std::endl;
        m_session->write(data, data_length);
    }
    void on_session_ended() {
        std::cout << "Echo ended " << std::endl;
    }

};

int main(int argc, char ** argv) {
    auto serv = new server("key.pem", "cert.pem");

    serv->set_session_listener_factory([](){
        return std::make_unique<echo>();
    });

    serv->listen(2345);
    delete serv;
    return 0;
}