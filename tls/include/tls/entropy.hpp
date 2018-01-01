#pragma once

namespace tls {
    class entropy {
    public:
        using entropy_callback_t = int (void *, unsigned char *, size_t);

        virtual ~entropy() {}
        
        virtual entropy_callback_t * get_callback() = 0;
        virtual void * get_data() = 0;
    };
}