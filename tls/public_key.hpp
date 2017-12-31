#pragma once

#include <cstdint> 
#include <stdexcept>

#include <mbedtls/config.h>
#include <mbedtls/pk.h>

namespace tls {
    class public_key {
    private:
        mbedtls_pk_context m_public_key;
    public:
        public_key() {
            mbedtls_pk_init(&m_public_key);
        }

        ~public_key() {
            mbedtls_pk_free(&m_public_key);
        }

        mbedtls_pk_context * get() {
            return &m_public_key;
        }

        void parse(const uint8_t * data, size_t data_lenght) {
            int error = mbedtls_pk_parse_key(&m_public_key, data, data_lenght, NULL, 0);
            if (0 != error) {
                throw std::runtime_error("Failed to parse public key");
            }
        }

        void parse_file(const char * file_name, const char * password) {
            int error = mbedtls_pk_parse_keyfile(&m_public_key, file_name, password);
            if (0 != error) {
                throw std::runtime_error("Failed to parse public key");
            }
        }
    };
}