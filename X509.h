//
// Created by jsorah on 6/12/21.
//
#include <string>
#include <vector>
#ifndef WHAT_THE_CERT_X509_H
#define WHAT_THE_CERT_X509_H

class x509 {
public:
    std::string issuer;
    std::string subject;
    std::string serial;
    std::string after;
    std::string before;
    std::string after_parsed;
    std::string before_parsed;
    std::vector<std::string> sans;
    int extension_count = 0;
    std::string expires_message;
    std::string expires_in;
};


#endif //WHAT_THE_CERT_X509_H
