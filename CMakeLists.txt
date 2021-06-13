cmake_minimum_required(VERSION 3.18)
project(what_the_cert)

set(CMAKE_CXX_STANDARD 14)

add_executable(what_the_cert main.cpp TLSConnection.cpp TLSConnection.h Handshake.cpp Handshake.h X509.h)

find_package(OpenSSL REQUIRED)
find_package(Boost COMPONENTS program_options REQUIRED)
target_link_libraries(what_the_cert OpenSSL::SSL Boost::program_options)