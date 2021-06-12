#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <boost/program_options.hpp>

#include <iostream>
#include <vector>
#include <sstream>

namespace po = boost::program_options;

class WhatTheCertOptions {
public:
    std::string target;
    std::string s_port;
    std::string sni;
    bool show_san = false;
    bool no_sni = false;
    bool peer_only = false;

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
                ("show-sans", po::bool_switch(&show_san), "Whether to show sans in the output")
                ("peer-only", po::bool_switch(&peer_only)->default_value(false), "If only the peer certificate should be printed")
                ;

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            return false;
        }

        if (!vm.count("sni") && !no_sni) {
            sni = target;
        }

        return true;
    }
};

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

class Handshake {
public:
    std::vector<x509> chain;
    x509 peer;
    std::string host;
    std::string s_port;
    std::string sni;
    std::string tls;
    std::string cipher;

    void parse(SSL* ssl) {
        parse_peer_cert_chain(ssl);
        parse_peer_cert(ssl);
    }

    x509 parse_cert(X509 *cert) {
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

        expires_in_ss << "Expires in " << day << "d " << sec << "s" << std::endl;

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
    void parse_peer_cert_chain(SSL* ssl) {
        STACK_OF(X509) *chain_certs = SSL_get_peer_cert_chain(ssl);

        if(chain_certs != nullptr) {

            for (int i = sk_X509_num(chain_certs) - 1; i >= 0; i--) {

                X509 *current_cert = sk_X509_value(chain_certs, i);
                x509 cert_data = parse_cert(current_cert);

                chain.push_back(cert_data);
            }
        }
    }

    void parse_peer_cert(SSL *ssl) {
        X509 *peer_cert = SSL_get_peer_certificate(ssl);

        peer = parse_cert(peer_cert);
    }
};






class TLSConnection {
public:
    std::string host;
    std::string port;
    std::string sni;

    Handshake connect() {

        init_ssl();
        SSL_CTX *ctx = SSL_CTX_new(TLS_method());

        SSL *ssl = nullptr;

        BIO *bio = BIO_new_ssl_connect(ctx);

        BIO_get_ssl(bio, &ssl);

        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

        BIO_set_conn_hostname(bio, (host + ":" + port).c_str());

        if (sni.length() > 0) {
            SSL_set_tlsext_host_name(ssl, sni.c_str());
        } else {
            SSL_set_tlsext_host_name(ssl, nullptr);
        }

        if (BIO_do_connect(bio) <= 0) {
            std::cout << "WARNING: Unable to connect to " << (host + ":" + port) << std::endl;
            // TODO dump error message to stderr
        }

        Handshake handshake;
        handshake.parse(ssl);

        BIO_free_all(bio);
        SSL_CTX_free(ctx);

        return handshake;

    }
private:

    void init_ssl() {
        SSL_load_error_strings();
        ERR_load_BIO_strings();
        OpenSSL_add_all_algorithms();
    }

};

void dump_cert(const x509 &cert) {
    std::cout << "Issuer: \t" << cert.issuer << std::endl;
    std::cout << "Subject: \t" << cert.subject << std::endl;
    std::cout << "Serial: \t" << cert.serial << std::endl;
    std::cout << "Not Before: \t" << cert.before << std::endl;
    std::cout << "Not After: \t" << cert.after << std::endl;

    std::cout << "Expires in: \t" << cert.expires_in << std::endl;
    if(!cert.expires_message.empty()) {
        std::cout << "************************************" << std::endl;
        std::cout << cert.expires_message << std::endl;
        std::cout << "************************************" << std::endl;
    }
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

    TLSConnection connection;
    connection.host = opts.target;
    connection.port = opts.s_port;
    connection.sni = opts.sni;

    Handshake handshake = connection.connect();

    if (!opts.peer_only) {
        std::cout << std::endl << "Chained Certificates" << std::endl;
        std::cout << "-----------------------" << std::endl;
        for (const auto &current : handshake.chain) {

            dump_cert(current);
            std::cout << std::endl;
        }
        std::cout << std::endl;
    }

    std::cout << "Peer Certificate" <<std::endl;
    std::cout << "-----------------------" << std::endl;

    dump_cert(handshake.peer);

    if(handshake.peer.sans.empty()) {
        std::cout << "No Subject Alternative Names" <<std::endl;
    } else {
        std::cout << "Subject Alternative Names: [" <<handshake.peer.sans.size() << "]"<< std::endl;
        if (opts.show_san) {
            for (const auto& it : handshake.peer.sans) {
                std::cout << it << std::endl;
            }
        }
    }

    std::cout << std::endl;

    return 0;
}
