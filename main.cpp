

#include <boost/program_options.hpp>

#include <iostream>
#include <iomanip>
#include "X509.h"
#include "TLSConnection.h"

namespace po = boost::program_options;

class WhatTheCertOptions {
public:
    std::string target;
    std::string s_port;
    std::string sni_value;
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
                ("host", po::value<std::string>(&target)->required(), "target host (IP or DNS)")
                ("port", po::value<std::string>(&s_port)->default_value("443"), "port (default 443)")
                ("sni-value", po::value<std::string>(&sni_value), "Value to use for SNI (default is the host provided)")
                ("no-sni", po::bool_switch(&no_sni), "whether to use SNI at all")
                ("show-sans", po::bool_switch(&show_san)->default_value(false), "Whether to show SANs in the output")
                ("peer-only", po::bool_switch(&peer_only)->default_value(false), "If only the peer certificate should be printed")
                ;

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            return false;
        }

        po::notify(vm);

        if (!vm.count("sni-value") && !no_sni) {
            sni_value = target;
        }

        return true;
    }
};

void print_field(const std::string & label, const std::string & value) {
    std::cout << std::left << std::setw(20) << label << value << std::endl;
}

void dump_cert(const x509 &cert) {

    print_field("Issuer:", cert.issuer);
    print_field("Subject:", cert.subject);
    print_field("Serial:", cert.serial);
    print_field("Not Before:", cert.before);
    print_field("Not After:", cert.after);

    print_field("Expires in:", cert.expires_in);
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
        std::cout << " with SNI value of " << opts.sni_value;
    }

    std::cout << std::endl;

    TLSConnection connection;
    connection.host = opts.target;
    connection.port = opts.s_port;
    connection.sni_value = opts.sni_value;
    connection.sni_enabled = !opts.no_sni;

    Handshake handshake = connection.connect();

    if (handshake.cipher.empty()) {
        std::cout << "No cipher negotiated!" << std::endl;
    } else {
        std::cout << "Negotiated Cipher: " << handshake.cipher << std::endl;
    }

    std::cout << std::endl << "Chained Certificates [" << handshake.chain.size() << "]" << std::endl;
    if (!opts.peer_only) {
        std::cout << "-----------------------" << std::endl;
        for (const auto &current : handshake.chain) {

            dump_cert(current);
            std::cout << std::endl;
        }
    }
    std::cout << std::endl;

    std::cout << "Peer Certificate" <<std::endl;
    std::cout << "-----------------------" << std::endl;

    dump_cert(handshake.peer);

    if(handshake.peer.sans.empty()) {
        std::cout << "No Subject Alternative Names" <<std::endl;
    } else {
        std::cout << "Subject Alternative Names [" <<handshake.peer.sans.size() << "]"<< std::endl;
        if (opts.show_san) {
            std::cout << "-------------------" << std::endl;
            for (const auto& it : handshake.peer.sans) {
                std::cout << it << std::endl;
            }
        }
    }

    std::cout << std::endl;
    return 0;
}
