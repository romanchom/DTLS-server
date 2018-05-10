#pragma once 

#include <stdexcept>
#include <iostream>
#include <string>

#include <mbedtls/ssl.h>

#include "configuration.hpp"
#include "timer.hpp"
#include "basic_input_output.hpp"
#include "exception.hpp"

namespace tls {
    class ssl {
    private:
        mbedtls_ssl_context m_ssl;
    public:
        ssl() {
            mbedtls_ssl_init(&m_ssl);
        }

        ~ssl() {
            mbedtls_ssl_free(&m_ssl);
        }

        void setup(configuration * a_configuration) {
            auto error = mbedtls_ssl_setup(&m_ssl, a_configuration->get());
            if (0 != error) {
                throw tls::exception(error);
            }
        }

        void reset_session() {
            auto error = mbedtls_ssl_session_reset(&m_ssl);
            if (0 != error) {
                throw tls::exception(error);
            }
        }

        void set_timer(timer * a_timer) {
            mbedtls_ssl_set_timer_cb(&m_ssl,
                a_timer->get_data(),
                a_timer->get_delay_setter(),
                a_timer->get_delay_getter());
        }

        void set_client_id(const unsigned char * data, size_t data_length) {
            auto error = mbedtls_ssl_set_client_transport_id(&m_ssl, data, data_length);
            if (0 != error) {
                throw tls::exception(error);
            }
        }

        void set_input_output(basic_input_output * bio) {
            mbedtls_ssl_set_bio(&m_ssl,
                bio->get_context(),
                bio->get_sender(),
                bio->get_receiver(),
                bio->get_receiver_timeout());
        }

        void set_host_name(const char * host_name) {
            int error = mbedtls_ssl_set_hostname(&m_ssl, host_name);
            if (0 != error) {
                throw tls::exception(error);
            }
        }

        bool handshake() {
            int error;
            do {
                error = mbedtls_ssl_handshake(&m_ssl);
            } while(error == MBEDTLS_ERR_SSL_WANT_READ
                 || error == MBEDTLS_ERR_SSL_WANT_WRITE);

            if (0 != error && MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED != error) {
                std::cout << error_string(error) << std::endl;
            }

            return 0 == error;
        }

        int read(uint8_t * data, size_t data_length) {
            int ret;
            do {
                ret = mbedtls_ssl_read(&m_ssl, data, data_length);
            } while (MBEDTLS_ERR_SSL_WANT_READ == ret
                  || MBEDTLS_ERR_SSL_WANT_WRITE == ret);

            if (ret < 0) {
                switch (ret) {
                    case MBEDTLS_ERR_SSL_TIMEOUT:
                        ret = 0;
                        break;
                    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                        ret = -1;
                        break;
                    default:
                        throw tls::exception(ret);
                }
            }

            return ret;
        }

        int write(const uint8_t * data, size_t data_length) {
            int ret;
            do {
                ret = mbedtls_ssl_write(&m_ssl, data, data_length);
            } while (MBEDTLS_ERR_SSL_WANT_READ == ret
                  || MBEDTLS_ERR_SSL_WANT_WRITE == ret);

            if (ret < 0) {
                throw tls::exception(ret);
            }

            return ret;
        }

        void close_notify() {
            int ret;
            do {
                ret = mbedtls_ssl_close_notify(&m_ssl);
            } while(MBEDTLS_ERR_SSL_WANT_WRITE == ret);
        }
    };
}
