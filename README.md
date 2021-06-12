# What the Cert?!?

## What is this?
A utility to look at certificates presented during TLS handshakes.

## Why?
I wanted to see how OpenSSL worked, and I have things I'd like to do without a bunch of CLI magic.

## Usage

```
./what_the_cert --target 173.194.219.139 --sni www.youtube.com
Connecting to 173.194.219.139:443 with SNI value of www.youtube.com
CHAIN 1
----------------
ISSUER:         /OU=GlobalSign Root CA - R2/O=GlobalSign/CN=GlobalSign
Subject:        /C=US/O=Google Trust Services/CN=GTS CA 1O1
SERIAL:         01E3B49AA18D8AA981256950B8
Not before      170615000042Z
Not after       211215000042Z
Not before:     2017-6-15 0:0:42
Not after:      2021-12-15 0:0:42
Expires in 185d 33702s

CHAIN 0
----------------
ISSUER:         /C=US/O=Google Trust Services/CN=GTS CA 1O1
Subject:        /C=US/ST=California/L=Mountain View/O=Google LLC/CN=*.google.com
SERIAL:         20137C2BA844EF8B0300000000CC239F
Not before      210517013650Z
Not after       210809013649Z
Not before:     2021-5-17 1:36:50
Not after:      2021-8-9 1:36:49
Expires in 57d 39469s
Renew soon

PEER CERT
-----------------
ISSUER:         /C=US/O=Google Trust Services/CN=GTS CA 1O1
SUBJECT:        /C=US/ST=California/L=Mountain View/O=Google LLC/CN=*.google.com
SERIAL:         20137C2BA844EF8B0300000000CC239F
Not before      210517013650Z
Not after       210809013649Z
Extension Count: 10
Subject Alternative Name Count: 118

```
