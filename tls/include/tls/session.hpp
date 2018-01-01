#pragma once

#include <thread>
#include <atomic>
#include <vector>
#include <memory>

#include "ssl.hpp"
#include "basic_input_output.hpp"
#include "session_listener.hpp"

namespace tls {
    class session {
    public:
        session(class server * parent, std::unique_ptr<tls::ssl> && a_ssl, std::unique_ptr<tls::basic_input_output> && a_io);
        ~session();
        void set_listener(std::unique_ptr<session_listener> && a_listener);
        void start();
        void end();
        int write(const char * data, int size);
    private:
        void thread_function();
        
        std::thread m_thread;
        std::atomic_bool m_should_run;

        class server * m_parent_server;
        std::unique_ptr<session_listener> m_listener;
        std::unique_ptr<tls::ssl> m_ssl;
        std::unique_ptr<tls::basic_input_output> m_io;

        std::vector<char> m_buffer;
    };
}