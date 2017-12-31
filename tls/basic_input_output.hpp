#pragma once

#include <mbedtls/config.h>
#include <mbedtls/ssl.h>

namespace tls {
    class basic_input_output {
    public:
        virtual ~basic_input_output() {}

        virtual void * get_context() = 0;
        virtual mbedtls_ssl_send_t * get_sender() = 0;
        virtual mbedtls_ssl_recv_t * get_receiver() = 0;
        virtual mbedtls_ssl_recv_timeout_t * get_receiver_timeout() = 0;
    };
}