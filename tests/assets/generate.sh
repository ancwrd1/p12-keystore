#!/usr/bin/env bash

for edx in 25519 448
do
  SUBJECT="/CN=example.com"

  openssl genpkey -out key-ed${edx}.pem -algorithm ed${edx}
  openssl pkey -in key-ed${edx}.pem -pubout -out pub-ed${edx}.pem
  openssl req -new -sha256 -subj ${SUBJECT} \
                              -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
                              -addext "extendedKeyUsage=serverAuth" \
                              -addext "keyUsage=digitalSignature,keyAgreement" \
                              -key key-ed${edx}.pem -out csr-ed${edx}.pem
  openssl x509 -req -extensions v3_leaf -extfile "./ssl-extensions.cnf" -days 700 -in csr-ed${edx}.pem -signkey key-ed${edx}.pem -out cert-ed${edx}.pem
  openssl pkcs12 -export -out pfx-ed${edx}.pfx -inkey key-ed${edx}.pem -in cert-ed${edx}.pem -password pass:changeit
  openssl x509 -in cert-ed${edx}.pem -text -out cert-ed${edx}.txt

  rm cert-ed${edx}.pem
  rm cert-ed${edx}.txt
  rm csr-ed${edx}.pem
  rm key-ed${edx}.pem
  rm pub-ed${edx}.pem
done
