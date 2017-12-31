#pragma once

#include <cstdint>
#include <stdexcept>

#include <mbedtls/config.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509.h>
#include <mbedtls/certs.h>

namespace tls {
    class certificate {
    private:
        mbedtls_x509_crt m_certificate;
    public:
        certificate() {
            mbedtls_x509_crt_init(&m_certificate);
        }

        ~certificate() {
            mbedtls_x509_crt_free(&m_certificate);
        }

        mbedtls_x509_crt * get() {
            return &m_certificate;
        }

        certificate * next() {
            return reinterpret_cast<certificate *>(m_certificate.next);
        }

        void parse(const uint8_t * buffer, size_t buffer_length) {
            int error = mbedtls_x509_crt_parse(&m_certificate, buffer, buffer_length);
            if (0 != error) {
                throw std::runtime_error("Failed to parse certificate");
            }
        }

        void parse_file(const char * file_name) {
            int error = mbedtls_x509_crt_parse_file(&m_certificate, file_name);
            if (0 != error) {
                throw std::runtime_error("Failed to parse certificate");
            }
        }
    };
}