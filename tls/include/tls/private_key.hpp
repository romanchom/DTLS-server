#pragma once

#include <cstdint> 

#include <mbedtls/pk.h>

#include "exception.hpp"

namespace tls {
    class private_key {
    private:
        mbedtls_pk_context m_private_key;
    public:
        private_key() {
            mbedtls_pk_init(&m_private_key);
        }

        ~private_key() {
            mbedtls_pk_free(&m_private_key);
        }

        mbedtls_pk_context * get() {
            return &m_private_key;
        }

        void parse(const uint8_t * data, size_t data_lenght) {
            int error = mbedtls_pk_parse_key(&m_private_key, data, data_lenght, NULL, 0);
            if (0 != error) {
                throw tls::exception(error);
            }
        }

        void parse_file(const char * file_name, const char * password) {
            int error = mbedtls_pk_parse_keyfile(&m_private_key, file_name, password);
            if (0 != error) {
                throw tls::exception(error);
            }
        }
    };
}