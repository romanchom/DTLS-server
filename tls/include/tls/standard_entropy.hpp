#pragma once

#include "entropy.hpp"

#include <mbedtls/entropy.h>

namespace tls {
    class standard_entropy : public entropy {
    private:
        mbedtls_entropy_context m_entropy;
    public:
        standard_entropy() { 
            mbedtls_entropy_init(&m_entropy);
        }

        ~standard_entropy() {
            mbedtls_entropy_free(&m_entropy);
        }
        
        entropy_callback_t * get_callback() override {
            return &mbedtls_entropy_func;
        }
        
        void * get_data() override {
            return &m_entropy;
        }
    };
}

