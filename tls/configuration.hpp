#pragma once

#include <stdexcept>

#include <mbedtls/config.h>
#include <mbedtls/ssl.h>

#include "certificate.hpp"
#include "public_key.hpp"
#include "cookie.hpp"
#include "random_generator.hpp"

#include <iostream>

namespace tls {
    enum class endpoint : int {
        client = MBEDTLS_SSL_IS_CLIENT,
        server = MBEDTLS_SSL_IS_SERVER,
    };

    enum class transport : int {
        stream = MBEDTLS_SSL_TRANSPORT_STREAM,
        datagram  = MBEDTLS_SSL_TRANSPORT_DATAGRAM,
    };

    enum class preset : int {
        default_ = MBEDTLS_SSL_PRESET_DEFAULT,
        suiteb = MBEDTLS_SSL_PRESET_SUITEB,
    };

    class configuration {
    private:
        mbedtls_ssl_config m_configuration;
    public:
        configuration() {
            mbedtls_ssl_config_init(&m_configuration);
        }

        ~configuration() {
            mbedtls_ssl_config_free(&m_configuration);
        }

        mbedtls_ssl_config * get() {
            return &m_configuration;
        }

        void set_defaults(endpoint ep, transport tp, preset p) {
            auto error = mbedtls_ssl_config_defaults(
                &m_configuration,
                static_cast<int>(ep),
                static_cast<int>(tp),
                static_cast<int>(p));

            if (0 != error) {
                throw std::runtime_error("Failed to set configuration defaults.");
            }
        }

        void set_random_generator(random_generator * rg) {
            mbedtls_ssl_conf_rng(&m_configuration, rg->get_callback(), rg->get_data());
        }

        void set_certifiate_authority_chain(certificate * cert) {
            mbedtls_ssl_conf_ca_chain(&m_configuration, cert->get(), nullptr);
        }

        void set_own_certificate(certificate * cert, public_key * key) {
            auto ret = mbedtls_ssl_conf_own_cert(&m_configuration, cert->get(), key->get());
            if (0 != ret) {
                throw std::runtime_error("Failed to set own certificate and key.");
            }
        }

        void set_dtls_cookies(cookie * a_cookie) {
            mbedtls_ssl_conf_dtls_cookies(&m_configuration, a_cookie->get_writer(), a_cookie->get_checker(), a_cookie->get_data());
        }

        
    };
}