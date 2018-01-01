#include "exception.hpp"

#include <cstring>

#include <mbedtls/error.h>

namespace tls {
    namespace detail {
        std::shared_ptr<char> error_shared_string(int error_code) {
            constexpr int size = 128;
            char error_buffer[size];
            mbedtls_strerror(error_code, error_buffer, size);
            int length = strlen(error_buffer);

            std::shared_ptr<char> ret(new char[length + 1], std::default_delete<char[]>());
            memcpy(ret.get(), error_buffer, length + 1);
            return ret;
        }
    }

    std::string error_string(int error_code) {
        constexpr int size = 128;
        char error_buffer[size];
        mbedtls_strerror(error_code, error_buffer, size);
        return std::string(error_buffer);
    }

    exception::exception(int code) :
        m_error_code(code),
        m_message(detail::error_shared_string(code))
    {}

    const char * exception::what() const noexcept {
        return m_message.get();
    }

    int exception::error_code() const noexcept {
        return m_error_code;
    }
}