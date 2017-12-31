#pragma once

#include <stdexcept>

#include <mbedtls/config.h>
#include <mbedtls/ctr_drbg.h>

#include "random_generator.hpp"

namespace tls {
    class counter_deterministic_random_generator : public random_generator {
    private:
        mbedtls_ctr_drbg_context m_generator;
    public:
        counter_deterministic_random_generator() {
            mbedtls_ctr_drbg_init(&m_generator);
        }

        ~counter_deterministic_random_generator() {
            mbedtls_ctr_drbg_free(&m_generator);
        }

        virtual generator_callback_t * get_callback() override {
            return &mbedtls_ctr_drbg_random;
        };

        virtual void * get_data() override {
            return reinterpret_cast<void *>(&m_generator);   
        }
        
        void seed(entropy * a_entropy, const char * data, size_t data_length) {
            auto error = mbedtls_ctr_drbg_seed(&m_generator, 
                a_entropy->get_callback(), a_entropy->get_data(),
                reinterpret_cast<const unsigned char *>(data), data_length);
            if (0 != error) {
                throw std::runtime_error("Failed to seed random byte generator");
            }
        }
    };
}