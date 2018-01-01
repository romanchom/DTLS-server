#pragma once

#include "entropy.hpp"

namespace tls {
    class random_generator {
    public:
        using generator_callback_t = int(void *, unsigned char *, size_t);

        virtual ~random_generator() {}

        virtual generator_callback_t * get_callback() = 0;
        virtual void * get_data() = 0;
    };
}