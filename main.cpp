#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <boost/program_options.hpp>

#include <iostream>

namespace po = boost::program_options;
class WhatTheCertOptions {
public:
    std::string target;
    std::string s_port;
    std::string sni;
    bool show_san = false;
    bool no_sni = false;

    std::string host_and_port() const {
        return target + ":" + s_port;
    }

    bool parse_args(int argc, char **argv) {

        po::options_description desc("Allowed options");
        desc.add_options()
                ("help", "produce help message")
                ("target", po::value<std::string>(&target)->required(), "target host")
                ("port", po::value<std::string>(&s_port)->default_value("443"), "port (default 443)")
                ("sni", po::value<std::string>(&sni), "sni value")
                ("no-sni", po::bool_switch(&no_sni), "whether to use SNI at all")
                ("show-sans", po::bool_switch(&show_san), "Whether to show sans in the output");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            return false;
        }

        if (!vm.count("sni")) {
            sni = target;
        }

        return true;
    }
};

void init_ssl() {
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
}

int main(int argc, char **argv) {

    WhatTheCertOptions opts;
    if (!opts.parse_args(argc, argv)) {
        return -1;
    }

    std::cout << "Connecting to " << (opts.host_and_port());
    if (opts.no_sni) {
        std::cout << " without SNI";
    } else {
        std::cout << " with SNI value of " << opts.sni;
    }

    std::cout << std::endl;

    init_ssl();

    SSL_CTX *ctx = SSL_CTX_new(TLS_method());

    SSL *ssl;
    BIO *bio;

    bio = BIO_new_ssl_connect(ctx);

    BIO_get_ssl(bio, &ssl);

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    BIO_set_conn_hostname(bio, (opts.host_and_port()).c_str());

    if (!opts.no_sni) {
        SSL_set_tlsext_host_name(ssl, opts.sni.c_str());
    } else {
        SSL_set_tlsext_host_name(ssl, nullptr);
    }

    if (BIO_do_connect(bio) <= 0) {
        std::cout << "WARNING: Unable to connect to " << (opts.target + ":" + opts.s_port) << std::endl;
        // TODO dump error message to stderr
    }

    STACK_OF(X509) *chain_certs = SSL_get_peer_cert_chain(ssl);

    if (chain_certs != nullptr) {
        for (int i = sk_X509_num(chain_certs) - 1; i >= 0; i--) {

            X509 *current_cert = sk_X509_value(chain_certs, i);
            std::cout << "CHAIN " << i << std::endl;
            std::cout << "----------------" << std::endl;
            std::cout << "ISSUER: \t" << X509_NAME_oneline(X509_get_issuer_name(current_cert), nullptr, 0) << std::endl;
            std::cout << "Subject: \t" << X509_NAME_oneline(X509_get_subject_name(current_cert), nullptr, 0)
                      << std::endl;

            // TODO lots of cleanup
            ASN1_INTEGER *serialNumber = X509_get_serialNumber(current_cert);

            std::cout << "SERIAL: \t" << BN_bn2hex(ASN1_INTEGER_to_BN(serialNumber, nullptr)) << std::endl;
            std::cout << "Not before\t" << X509_get0_notBefore(current_cert)->data << std::endl;
            std::cout << "Not after\t" << X509_get0_notAfter(current_cert)->data << std::endl;
//        std::cout << std::endl;

            struct tm stm;
            ASN1_STRING *as = X509_getm_notBefore(current_cert);
            ASN1_TIME_to_tm(as, &stm);
            std::cout << "Not before:\t" << 20 << stm.tm_year % 100
                      << "-" << (stm.tm_mon + 1) << "-" << stm.tm_mday
                      << " " << stm.tm_hour << ":" << stm.tm_min << ":" << stm.tm_sec
                      << std::endl;

            struct tm stm2;
            ASN1_STRING *af = X509_getm_notAfter(current_cert);
            ASN1_TIME_to_tm(af, &stm2);
            std::cout << "Not after:\t" << 20 << stm2.tm_year % 100
                      << "-" << (stm2.tm_mon + 1) << "-" << stm2.tm_mday
                      << " " << stm2.tm_hour << ":" << stm2.tm_min << ":" << stm2.tm_sec
                      << std::endl;

            int day, sec;
            ASN1_TIME_diff(&day, &sec, nullptr, X509_get0_notAfter(current_cert));

            std::cout << "Expires in " << day << "d " << sec << "s" << std::endl;

            if (day < 1) {
                std::cout << "STOP WHAT YOU ARE DOING AND RENEW THIS CERT" << std::endl;
            } else if (day < 10) {
                std::cout << "Renew VERY SOON" << std::endl;
            } else if (day < 30) {
                std::cout << "Renew SOON" << std::endl;
            } else if (day < 60) {
                std::cout << "Renew soon" << std::endl;
            }

            std::cout << std::endl;
        }
    } else {
        std::cout << "No Certificate Chain" << std::endl;
    }

    X509 *peer_cert = SSL_get_peer_certificate(ssl);
    if (peer_cert != nullptr) {
        std::cout << "PEER CERT" << std::endl;
        std::cout << "-----------------" << std::endl;

        std::cout << "ISSUER: \t" << X509_NAME_oneline(X509_get_issuer_name(peer_cert), nullptr, 0) << std::endl;
        std::cout << "SUBJECT: \t" << X509_NAME_oneline(X509_get_subject_name(peer_cert), nullptr, 0) << std::endl;

        // TODO lots of cleanup
        ASN1_INTEGER *serialNumber = X509_get_serialNumber(peer_cert);
        std::cout << "SERIAL: \t" << BN_bn2hex(ASN1_INTEGER_to_BN(serialNumber, nullptr)) << std::endl;
        std::cout << "Not before\t" << X509_get0_notBefore(peer_cert)->data << std::endl;
        std::cout << "Not after\t" << X509_get0_notAfter(peer_cert)->data << std::endl;

        int count = X509_get_ext_count(peer_cert);
        std::cout << "Extension Count: " << count << std::endl;

        GENERAL_NAMES *gs;
        gs = static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(peer_cert, NID_subject_alt_name, nullptr, nullptr));

        int general_name_count = sk_GENERAL_NAME_num(gs);

        if (general_name_count > 0) {

            if (opts.show_san) {
                std::cout << std::endl;
                std::cout << "Subject Alternative Names" << std::endl;
                std::cout << "-----------------" << std::endl;
                for (int i = 0; i < sk_GENERAL_NAME_num(gs); i++) {
                    std::cout << (sk_GENERAL_NAME_value(gs, i)->d.dNSName)->data << std::endl;
                }
            } else {
                std::cout << "Subject Alternative Name Count: " << general_name_count << std::endl;
            }

        } else {
            std::cout << "No Subject Alternative Names" << std::endl;
        }
    } else {
        std::cout << "No Peer Certificate" << std::endl;
    }

    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    return 0;
}
