#pragma once

#include <mbedtls/config.h>
#include <mbedtls/ssl_cookie.h>

#include "random_generator.hpp"

namespace tls {
    class cookie {
    public:
        virtual ~cookie() {}
        
        virtual mbedtls_ssl_cookie_write_t * get_writer() = 0;
        virtual mbedtls_ssl_cookie_check_t * get_checker() = 0;
        virtual void * get_data() = 0;
    };
}