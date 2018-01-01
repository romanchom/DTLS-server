#pragma once

#include <mbedtls/ssl.h>

namespace tls {
    class timer {
    public:
        virtual ~timer() {}

        virtual mbedtls_ssl_set_timer_t * get_delay_setter() = 0;
        virtual mbedtls_ssl_get_timer_t * get_delay_getter() = 0;
        virtual void * get_data() = 0;
    };
}