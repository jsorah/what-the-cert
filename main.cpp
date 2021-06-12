#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <boost/program_options.hpp>

#include <iostream>

namespace po = boost::program_options;

int main(int argc, char ** argv) {

    std::string target;
    std::string sni;

    po::options_description desc("Allowed options");
    desc.add_options()
        ("help", "produce help message")
        ("target", po::value<std::string>(&target),"target host")
            ("sni", po::value<std::string>(&sni),"sni value")
        ;


    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc << std::endl;
        return -1;
    }

    if (!vm.count("target")) {
        std::cout << desc << std::endl;
        return -1;
    }

    if (!vm.count("sni")) {
        sni = target;
    }

    std::string s = target;

    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    BIO * bio;

    std::cout << "Connecting to " << s << std::endl;

    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    SSL* ssl;

    bio = BIO_new_ssl_connect(ctx);

    BIO_get_ssl(bio, &ssl);

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    BIO_set_conn_hostname(bio, target.c_str());

    SSL_set_tlsext_host_name(ssl, sni.c_str());

    if (BIO_do_connect(bio) <= 0) {
        std::cout << "Unable to connect to " << s << std::endl;
        return -1;
    }

    STACK_OF(X509) * chain_certs = SSL_get_peer_cert_chain(ssl);


    for (int i = sk_X509_num(chain_certs) - 1; i >= 0; i--) {

        X509 * current_cert = NULL;
        current_cert = sk_X509_value(chain_certs, i);
        std::cout << "CHAIN " << i << std::endl;
        std::cout << "----------------" << std::endl;
        std::cout << "ISSUER: \t" << X509_NAME_oneline(X509_get_issuer_name(current_cert), NULL, 0) << std::endl;
        std::cout << "Subject: \t" << X509_NAME_oneline(X509_get_subject_name(current_cert), NULL, 0) << std::endl;
        std::cout << "SERIAL: \t" << X509_get_serialNumber(current_cert) << std::endl;
        std::cout << std::endl;
    }

    std::cout << std::endl;
    std::cout << "PEER CERT" << std::endl;
    std::cout << "-----------------" << std::endl;
    X509 *peer_cert = SSL_get_peer_certificate(ssl);
    if (peer_cert == NULL) {
        std::cout << "No peer_cert?" << std::endl;
    }

    std::cout << "ISSUER: \t" << X509_NAME_oneline(X509_get_issuer_name(peer_cert), NULL, 0) << std::endl;
    std::cout << "SUBJECT: \t" << X509_NAME_oneline(X509_get_subject_name(peer_cert), NULL, 0) << std::endl;
    std::cout << "SERIAL: \t" << X509_get_serialNumber(peer_cert) << std::endl;

    int count = X509_get_ext_count(peer_cert);
    std::cout << "Extension Count: " << count << std::endl;


    GENERAL_NAMES *gs;
    gs = static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(peer_cert, NID_subject_alt_name, NULL, NULL));

    int general_name_count = sk_GENERAL_NAME_num(gs);

    if (general_name_count > 0) {

        std::cout << std::endl;
        std::cout << "Subject Alternative Names" << std::endl;
        std::cout << "-----------------" << std::endl;

        for (int i = 0; i < sk_GENERAL_NAME_num(gs); i++) {
            std::cout << (sk_GENERAL_NAME_value(gs, i)->d.dNSName)->data << std::endl;
        }
    } else {
        std::cout << "No Subject Alternative Names" << std::endl;
    }


    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    return 0;
}
