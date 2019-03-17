# Crypto Prototype

Simple crypto prototype, generates X.509 certificate an private key with ECC, stores data in key store and loads data from persistent key store (if available). Also a small 'HTTP Server' is listening on port 8640.

## Key Store

We use a PKCS12 standard key store to save key material.

Useful commands to extract certificate and or private key from a .p12 file:

Show content of .p12 file: `openssl pkcs12 -in keystore.p12 -nodes -passin pass:"foobar"`

Extract private key from .p12 file: `openssl pkcs12 -in keystore.p12 -nodes -passin pass:"foobar" -nocerts -out privatekey.pem`

Extract certificate from .p12 file`openssl pkcs12 -in keystore.p12 -nodes -passin pass:"foobar" -clcerts -nokeys -out publiccert.pem`

### Running a local www server

`openssl s_server -key privatekey.pem -cert publiccert.pem -accept 1337 -www`