#pragma once

#include "cookie.hpp"

#include <mbedtls/config.h>
#include <mbedtls/ssl_cookie.h>

#include "random_generator.hpp"

namespace tls {
    class standard_cookie : public cookie {
    private:
        mbedtls_ssl_cookie_ctx  m_cookie;
    public:
        standard_cookie() {
            mbedtls_ssl_cookie_init(&m_cookie);
        }

        ~standard_cookie() {
            mbedtls_ssl_cookie_free(&m_cookie);
        }

        mbedtls_ssl_cookie_write_t * get_writer() override {
            return &mbedtls_ssl_cookie_write;
        }

        mbedtls_ssl_cookie_check_t * get_checker() {
            return &mbedtls_ssl_cookie_check;
        }

        void * get_data() override {
            return reinterpret_cast<void *>(&m_cookie);   
        }
        
        void setup(random_generator * rg) {
            mbedtls_ssl_cookie_setup(&m_cookie, rg->get_callback(), rg->get_data());
        }
    };
}