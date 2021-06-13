# What the Cert?!?

## What is this?
A utility to look at certificates presented during TLS handshakes.

## Why?
I wanted to see how OpenSSL worked, and I have things I'd like to do without a bunch of CLI magic.

## Usage

```
./what_the_cert --host 173.194.219.139 --sni www.youtube.com
Connecting to 173.194.219.139:443 with SNI value of www.youtube.com
Negotiated Cipher: TLS_AES_256_GCM_SHA384  TLSv1.3 Kx=any      Au=any  Enc=AESGCM(256) Mac=AEAD

Chained Certificates
-----------------------
Issuer:             /OU=GlobalSign Root CA - R2/O=GlobalSign/CN=GlobalSign
Subject:            /C=US/O=Google Trust Services/CN=GTS CA 1O1
Serial:             01E3B49AA18D8AA981256950B8
Not Before:         170615000042Z
Not After:          211215000042Z
Expires in:         184d 21h 1m 49s


Issuer:             /C=US/O=Google Trust Services/CN=GTS CA 1O1
Subject:            /C=US/ST=California/L=Mountain View/O=Google LLC/CN=*.google.com
Serial:             17056F6E05310454050000000087DE9D
Not Before:         210524013600Z
Not After:          210816013559Z
Expires in:         63d 22h 37m 6s



Peer Certificate
-----------------------
Issuer:             /C=US/O=Google Trust Services/CN=GTS CA 1O1
Subject:            /C=US/ST=California/L=Mountain View/O=Google LLC/CN=*.google.com
Serial:             17056F6E05310454050000000087DE9D
Not Before:         210524013600Z
Not After:          210816013559Z
Expires in:         63d 22h 37m 6s


```
