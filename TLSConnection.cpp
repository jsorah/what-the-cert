//
// Created by jsorah on 6/12/21.
//

#include "TLSConnection.h"
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <iostream>

Handshake TLSConnection::connect() {

    init_ssl();
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());

    SSL *ssl = nullptr;

    BIO *bio = BIO_new_ssl_connect(ctx);

    BIO_get_ssl(bio, &ssl);

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    BIO_set_conn_hostname(bio, (host + ":" + port).c_str());

    if (sni_value.length() > 0 && sni_enabled) {
        SSL_set_tlsext_host_name(ssl, sni_value.c_str());
    } else {
        SSL_set_tlsext_host_name(ssl, nullptr);
    }

    if (BIO_do_connect(bio) <= 0) {
        std::cout << "WARNING: Unable to connect to " << (host + ":" + port) << std::endl;
        // TODO dump error message to stderr
    }

    Handshake handshake;
    handshake.parse(ssl);

    if (bio != nullptr)
        BIO_free_all(bio);

    if (ctx != nullptr)
        SSL_CTX_free(ctx);

    return handshake;

}

void TLSConnection::init_ssl() {
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
}