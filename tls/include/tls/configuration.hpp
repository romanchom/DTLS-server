#pragma once

#include <stdexcept>

#include <mbedtls/ssl.h>
#include <mbedtls/debug.h>

#include "certificate.hpp"
#include "private_key.hpp"
#include "cookie.hpp"
#include "random_generator.hpp"
#include "exception.hpp"

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

    enum class authentication_mode : int {
        none = MBEDTLS_SSL_VERIFY_NONE,
        optional = MBEDTLS_SSL_VERIFY_OPTIONAL,
        required = MBEDTLS_SSL_VERIFY_REQUIRED,
    };

    class configuration {
    private:
        mbedtls_ssl_config m_configuration;
        debug_callback_t debug_callback;
    public:
        using debug_callback_t = void (void *, int, const char *, int, const char *);
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
                throw tls::exception(error);
            }
        }

        void set_random_generator(random_generator * rg) {
            mbedtls_ssl_conf_rng(&m_configuration, rg->get_callback(), rg->get_data());
        }

        void set_certifiate_authority_chain(certificate * cert) {
            mbedtls_ssl_conf_ca_chain(&m_configuration, cert->get(), nullptr);
        }

        void set_own_certificate(certificate * cert, private_key * key) {
            auto error = mbedtls_ssl_conf_own_cert(&m_configuration, cert->get(), key->get());
            if (0 != error) {
                throw tls::exception(error);
            }
        }

        void set_dtls_cookies(cookie * a_cookie) {
            mbedtls_ssl_conf_dtls_cookies(&m_configuration, a_cookie->get_writer(), a_cookie->get_checker(), a_cookie->get_data());
        }

        void set_authentication_mode(authentication_mode mode) {
            mbedtls_ssl_conf_authmode(&m_configuration,
                static_cast<int>(mode));
        }

        void enable_debug(debug_callback_t * callback, int debug_threshold) {
            mbedtls_ssl_conf_dbg(&m_configuration, callback, NULL);
            mbedtls_debug_set_threshold(debug_threshold);
        }
    };
}