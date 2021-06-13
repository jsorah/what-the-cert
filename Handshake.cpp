//
// Created by jsorah on 6/12/21.
//
#include <openssl/ssl.h>
#include <iostream>
#include <sstream>
#include <openssl/x509v3.h>
#include "Handshake.h"

void Handshake::parse(SSL* ssl) {
    // TODO can you get what was negotiated?
    if(ssl == nullptr) {
        return;
    }

    const SSL_CIPHER * ssl_cipher = SSL_get_current_cipher(ssl);

    if (ssl_cipher != nullptr) {
        std::stringstream ss;
        ss << SSL_CIPHER_description(ssl_cipher, nullptr, 0);
        cipher = ss.str();
    }
    parse_peer_cert_chain(ssl);
    parse_peer_cert(ssl);
}

x509 Handshake::parse_cert(X509 *cert) {
    x509 return_cert;

    return_cert.issuer = std::string(X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0));
    return_cert.subject = std::string(X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0));

    // TODO cleanup ptr?
    ASN1_INTEGER *serialNumber = X509_get_serialNumber(cert);

    return_cert.serial = std::string(BN_bn2hex(ASN1_INTEGER_to_BN(serialNumber, nullptr)));

    // TODO lots of cleanup
    std::stringstream ss;
    ss << X509_get0_notBefore(cert)->data;
    return_cert.before = ss.str();

    ss.str(std::string());

    ss << X509_get0_notAfter(cert)->data;
    return_cert.after = ss.str();

//TODO I'd like a better time format, but what I have now works.
//
//        struct tm stm;
//        ASN1_STRING *as = X509_getm_notBefore(cert);
//        ASN1_TIME_to_tm(as, &stm);
//
//        //before parsed
//        std::cout << "Not before:\t" << 20 << stm.tm_year % 100
//                  << "-" << (stm.tm_mon + 1) << "-" << stm.tm_mday
//                  << " " << stm.tm_hour << ":" << stm.tm_min << ":" << stm.tm_sec
//                  << std::endl;
//
//        struct tm stm2;
//        ASN1_STRING *af = X509_getm_notAfter(cert);
//        ASN1_TIME_to_tm(af, &stm2);
//
//        //after parsed
//        std::cout << "Not after:\t" << 20 << stm2.tm_year % 100
//                  << "-" << (stm2.tm_mon + 1) << "-" << stm2.tm_mday
//                  << " " << stm2.tm_hour << ":" << stm2.tm_min << ":" << stm2.tm_sec
//                  << std::endl;

    int day, sec;
    ASN1_TIME_diff(&day, &sec, nullptr, X509_get0_notAfter(cert));

    std::stringstream expires_in_ss;

    expires_in_ss << day << "d " << sec / 3600 << "h " << (sec % 3600) / 60 << "m " << ((sec % 3600) % 60) << "s" << std::endl;

    return_cert.expires_in = expires_in_ss.str();

    if (day < 1) {
        return_cert.expires_message = "STOP WHAT YOU ARE DOING AND RENEW THIS CERT";
    } else if (day < 10) {
        return_cert.expires_message = "Renew VERY SOON";
    } else if (day < 30) {
        return_cert.expires_message = "Renew SOON";
    } else if (day < 60) {
        return_cert.expires_message = "Renew soonish";
    }

    int count = X509_get_ext_count(cert);
    return_cert.extension_count = count;

    GENERAL_NAMES *gs;
    gs = static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));

    int general_name_count = sk_GENERAL_NAME_num(gs);

    if (general_name_count > 0) {


        for (int i = 0; i < sk_GENERAL_NAME_num(gs); i++) {
            std::stringstream name_ss;
            name_ss << (sk_GENERAL_NAME_value(gs, i)->d.dNSName)->data;
            return_cert.sans.push_back(name_ss.str());
        }

    }

    return return_cert;
}

void Handshake::parse_peer_cert_chain(SSL* ssl) {
    STACK_OF(X509) *chain_certs = SSL_get_peer_cert_chain(ssl);

    if (chain_certs == nullptr) return;

    for (int i = sk_X509_num(chain_certs) - 1; i >= 0; i--) {

        X509 *current_cert = sk_X509_value(chain_certs, i);
        x509 cert_data = parse_cert(current_cert);

        chain.push_back(cert_data);
    }
}

void Handshake::parse_peer_cert(SSL *ssl) {
    X509 *peer_cert = SSL_get_peer_certificate(ssl);
    if (peer_cert != nullptr) {
        peer = parse_cert(peer_cert);
    }
}