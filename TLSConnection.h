//
// Created by jsorah on 6/12/21.
//

#include <string>
#include "Handshake.h"

#ifndef WHAT_THE_CERT_TLSCONNECTION_H
#define WHAT_THE_CERT_TLSCONNECTION_H


class TLSConnection {
public:
    std::string host;
    std::string port;
    std::string sni_value;
    bool sni_enabled;

    Handshake connect();
private:
    static void init_ssl();

};



#endif //WHAT_THE_CERT_TLSCONNECTION_H
