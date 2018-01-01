
#include <arpa/inet.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdexcept>
#include <iostream>


int main(int argc, char ** argv) {
    SSL_load_error_strings(); /* readable error messages */
    SSL_library_init(); /* initialize library */

    SSL_CTX * ctx = SSL_CTX_new(DTLSv1_2_client_method());
    SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

    SSL_CTX_use_certificate_chain_file(ctx, "client.crt");
    SSL_CTX_use_PrivateKey_file(ctx, "client.key", SSL_FILETYPE_PEM);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int enable = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server_addr.sin_port = htons(2345);
    connect(fd, (sockaddr *) &server_addr, sizeof(sockaddr_in));
    
    BIO *bio = BIO_new_dgram(fd, BIO_CLOSE);
    BIO_ctrl_set_connected(bio, 0, &server_addr);
    SSL *ssl = SSL_new(ctx);
    SSL_set_bio(ssl, bio, bio);
    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
    
    /* Perform handshake */
    int ret = SSL_connect(ssl);
    std::cout << ret << std::endl;
    
    const char message[] = "Ala ma kota i kot ma ale";
    SSL_write(ssl, message, sizeof(message));

    char buffer[1024];
    int size = sizeof(buffer);
    size = SSL_read(ssl, buffer, size);
    std::cout << buffer << std::endl;
    
    return 0;
}