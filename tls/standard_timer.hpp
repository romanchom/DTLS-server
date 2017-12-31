#pragma once

#include "timer.hpp"

#include <mbedtls/config.h>
#include <mbedtls/ssl.h>
#include <mbedtls/timing.h>

namespace tls {
    class standard_timer : public timer {
    private:
        mbedtls_timing_delay_context m_timer;
    public:
        mbedtls_ssl_set_timer_t * get_delay_setter() override {
            return &mbedtls_timing_set_delay;
        }

        mbedtls_ssl_get_timer_t * get_delay_getter() override {
            return &mbedtls_timing_get_delay;
        }

        void * get_data() override {
            return &m_timer;
        }
    };
}