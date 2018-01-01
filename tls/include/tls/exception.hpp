#pragma once

#include <stdexcept>
#include <memory>


namespace tls {
    namespace detail {
        std::shared_ptr<char> error_shared_string(int error_code);
    }

    std::string error_string(int error_code);

    class exception : public std::exception {
    private:
        int m_error_code;
        std::shared_ptr<char> m_message;
    public:
        exception(int code);

        const char * what() const noexcept override;
        int error_code() const noexcept;
    };
}