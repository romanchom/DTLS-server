#include "session.hpp"

#include <unistd.h>
#include <iostream>

namespace tls {
    session::session(class server * parent, std::unique_ptr<tls::ssl> && a_ssl, std::unique_ptr<tls::basic_input_output> && a_io) :
        m_should_run(true),
        m_parent_server(parent),
        m_ssl(std::move(a_ssl)),
        m_io(std::move(a_io)),
        m_buffer(1024 * 8)
    {}

    session::~session() {
        m_should_run.store(false);
        m_thread.join();
    }

    int session::write(const char * data, int size) {
        return m_ssl->write(data, size);
    }

    void session::set_listener(std::unique_ptr<session_listener> && a_listener) {
        m_listener = std::move(a_listener);
        m_listener->set_session(this);
    }

    void session::start() {
        m_thread = std::thread([this]() {
            session_end_reason reason(session_end_reason::user_request);
            std::cout << "Session started" << std::endl;
            m_listener->on_session_started();
            while (m_should_run.load()) {
                int size = m_ssl->read(m_buffer.data(), m_buffer.size());

                if(size >= 0) {
                    std::cout << "Received " << size << " bytes" << std::endl;
                    m_listener->on_data_received(m_buffer.data(), size);
                } else {
                    reason = session_end_reason::peer_request;
                    break;
                }
            }

            if (session_end_reason::user_request == reason
                || session_end_reason::timeout == reason)
            {
                m_ssl->close_notify();
            }

            m_listener->on_session_ended(reason);
        });
    }

    void session::end() {
        m_should_run.store(false);
    }
}
