#include "session_listener.hpp"

session_listener::session_listener() :
    m_session(nullptr) 
{}

session_listener::~session_listener() {}

void session_listener::set_session(class session * a_session) {
    m_session = a_session;
}
