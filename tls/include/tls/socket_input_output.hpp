#pragma once

#include "basic_input_output.hpp"

#include <string>
#include <sstream>
#include <iomanip>

#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>

#include "exception.hpp"

namespace tls {
    enum class protocol : int {
        tcp = MBEDTLS_NET_PROTO_TCP,
        udp = MBEDTLS_NET_PROTO_UDP,
    };

    struct address {
        char data[16];
        size_t size;
        std::string to_string() const {
            std::stringstream ss;
            if (4 == size) {
                int i = 0;
                while (true) {
                    ss << static_cast<int>(data[i]);
                    ++i;
                    if (i >= 4) { break; }
                    ss << '.';
                }
            } else if (16 == size) {
                ss << std::uppercase << std::setfill('0') << std::setw(4) << std::hex;
                int i = 0;
                while (true) {
                    ss << static_cast<int>(data[i]);
                    ++i;
                    if (i >= 16) { break; }
                    ss << ':';
                }
            } else {
                throw std::runtime_error("Unrepresentable ip address.");
            }
            return ss.str();
        }
    };

    class socket_input_output : public basic_input_output {
    private:
        mbedtls_net_context m_net;
    public:
        socket_input_output() {
            mbedtls_net_init(&m_net);
        }

        ~socket_input_output() {
            mbedtls_net_free(&m_net);
        }

        void * get_context() override {
            return &m_net;
        }

        mbedtls_ssl_send_t * get_sender() override {
            return &mbedtls_net_send;
        }

        mbedtls_ssl_recv_t * get_receiver()  override{
            return &mbedtls_net_recv;
        }

        mbedtls_ssl_recv_timeout_t * get_receiver_timeout() override {
            return &mbedtls_net_recv_timeout;
        }

        void bind(const char * bind_ip, const char *port, protocol proto) {
            auto error = mbedtls_net_bind(&m_net, bind_ip, port, static_cast<int>(proto));
            if (0 != error) {
                throw tls::exception(error);
            }
        }

        void accept(socket_input_output * client, address * a_address) {
            auto error = mbedtls_net_accept(&m_net, &client->m_net,
                reinterpret_cast<void *>(&a_address->data),
                sizeof(a_address->data),
                &a_address->size);
            if (0 != error) {
                throw tls::exception(error);
            }
        }

        void connect(const char * ip, const char *port, protocol proto) {
            int error = mbedtls_net_connect(&m_net, ip, port, static_cast<int>(proto));
            if (0 != error) {
                throw tls::exception(error);
            }
        }        
    };
}
