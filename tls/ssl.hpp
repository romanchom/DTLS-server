#pragma once 

#include <stdexcept>

#include <mbedtls/config.h>
#include <mbedtls/ssl.h>

#include "configuration.hpp"
#include "timer.hpp"
#include "basic_input_output.hpp"
#include <mbedtls/error.h>

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
                throw std::runtime_error("Failed to setup ssl.");
            }
        }

        void reset_session() {
            auto error = mbedtls_ssl_session_reset(&m_ssl);
            if (0 != error) {
                throw std::runtime_error("Failed to reset ssl session.");
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
                throw std::runtime_error("Failed to set client id.");
            }
        }

        void set_input_output(basic_input_output * bio) {
            mbedtls_ssl_set_bio(&m_ssl,
                bio->get_context(),
                bio->get_sender(),
                bio->get_receiver(),
                bio->get_receiver_timeout());
        }

        bool handshake() {
            int error;
            do {
                error = mbedtls_ssl_handshake(&m_ssl);
            } while(error == MBEDTLS_ERR_SSL_WANT_READ
                 || error == MBEDTLS_ERR_SSL_WANT_WRITE);

            if (error == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
                return false;
            } else if (0 != error) {
                constexpr int size = 1024;
                char error_buf[size];
                mbedtls_strerror(error, error_buf, size);
                std::cout << error_buf << std::endl;
                return false;
                //throw std::runtime_error("Failed to perform handshake.");
            }

            return true;
        }

        int read(char * data, size_t data_length) {
            int ret;
            do {
                ret = mbedtls_ssl_read(&m_ssl,
                    reinterpret_cast<unsigned char *>(data),
                    data_length);
            } while (MBEDTLS_ERR_SSL_WANT_READ == ret
                  || MBEDTLS_ERR_SSL_WANT_WRITE == ret);

            if (ret < 0) {
                switch (ret) {
                    case MBEDTLS_ERR_SSL_TIMEOUT:
                        ret = 0;
                        break;
                    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                        // TODO invoke callback
                        ret = 0;
                        break;
                    default:
                        throw std::runtime_error("Failed to read data.");
                }
            }

            return ret;
        }

        int write(const char * data, size_t data_length) {
            int ret;
            do {
                ret = mbedtls_ssl_write(&m_ssl, 
                    reinterpret_cast<const unsigned char *>(data),
                    data_length);
            } while (MBEDTLS_ERR_SSL_WANT_READ == ret
                  || MBEDTLS_ERR_SSL_WANT_WRITE == ret);

            if (ret < 0) {
                throw std::runtime_error("Failed to write data.");
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