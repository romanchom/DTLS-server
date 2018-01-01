#pragma once

#include <cstdlib>

namespace tls {
    enum class session_end_reason {
        user_request,
        peer_request,
        timeout,
        error,
    };

    class session_listener {
    protected:
        class session * m_session;
    public:
        session_listener();
        virtual ~session_listener();

        void set_session(class session * a_session);
        virtual void on_session_started() = 0;
        virtual void on_data_received(const char * data, size_t data_length) = 0;
        virtual void on_session_ended(session_end_reason reason) = 0;
    };
}
