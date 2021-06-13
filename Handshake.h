//
// Created by jsorah on 6/12/21.
//

#include <string>
#include <vector>
#include <openssl/ssl.h>
#include "X509.h"

#ifndef WHAT_THE_CERT_HANDSHAKE_H
#define WHAT_THE_CERT_HANDSHAKE_H


class Handshake {
public:
    std::vector<x509> chain;
    x509 peer;
    std::string host;
    std::string s_port;
    std::string sni;
    std::string tls;
    std::string cipher;

    void parse(SSL *);

private:
    x509 parse_cert(X509 *);
    void parse_peer_cert_chain(SSL *);
    void parse_peer_cert(SSL *);

};


#endif //WHAT_THE_CERT_HANDSHAKE_H
