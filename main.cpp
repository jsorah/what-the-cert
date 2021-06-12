#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <boost/program_options.hpp>

#include <iostream>

namespace po = boost::program_options;

int main(int argc, char ** argv) {

    std::string target;

    po::options_description desc("Allowed options");
    desc.add_options()
        ("help", "produce help message")
        ("target", po::value<std::string>(&target),"target host")
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

    std::string s = target;

    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    BIO * bio;

    std::cout << "Connecting to " << s << std::endl;

    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    SSL* ssl;

    bio = BIO_new_ssl_connect(ctx);
    std::cout << "After BIO_new_ssl_connect" << std::endl;
    BIO_get_ssl(bio, &ssl);
    std::cout << "After BIO_get_ssl" << std::endl;

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    BIO_set_conn_hostname(bio, s.c_str());

    SSL_set_tlsext_host_name(ssl, s.c_str());

    std::cout << "Here I am?" << std::endl;

    if (BIO_do_connect(bio) <= 0) {
        std::cout << "Unable to connect to " << s << std::endl;
        return -1;
    }

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL) {
        std::cout << "No cert?" << std::endl;
    }
    std::cout << (cert == NULL) << std::endl;

    std::cout << "ISSUER: \t" << X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0) << std::endl;
    std::cout << "SUBJECT: \t" << X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0) << std::endl;

    int count = X509_get_ext_count(cert);
    std::cout << "Extension Count: " << count << std::endl;

    STACK_OF(GENERAL_NAME) *san_names = NULL;

//    san_names = static_cast<struct stack_st_GENERAL_NAME *>(X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL));

//    int san_names_nb = san_names;

//    for (i =0; i<san_names_nb; i++)
    //std::cout << "Extension 1: \t" << X509_EXTENSION_get_data(X509v3_get_ext(X509_get0_extensions(cert),0)) << std::endl;

    for (int i = 0; i < count; i++) {
        X509_EXTENSION *ext = X509_get_ext(cert, i);
        int nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
//        X509
//        std::cout << nid << std::endl;

    }
    std::cout << "SERIAL: \t" << X509_get_serialNumber(cert) << std::endl;

    BIO_free_all(bio);
    SSL_CTX_free(ctx);




    return 0;
}
