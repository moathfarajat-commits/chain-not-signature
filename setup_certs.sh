#!/usr/bin/env bash
# Test credentials for the classical baseline. c2pa-rs rejects self-signed
# certificates and requires PKCS#8 keys, so each algorithm gets a two-certificate
# chain issued by a local test CA, with the extensions the C2PA specification
# expects of a signer.
set -e
cd "$(dirname "$0")"
mkdir -p certs && cd certs

cat > ca.cnf <<'CFG'
[req]
distinguished_name=dn
x509_extensions=ca_ext
prompt=no
[dn]
CN=Line A Test Root CA
O=University of Jordan
[ca_ext]
basicConstraints=critical,CA:TRUE,pathlen:1
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
CFG

cat > leaf.cnf <<'CFG'
[req]
distinguished_name=dn
prompt=no
[dn]
CN=Line A Test Signer
O=University of Jordan
[leaf_ext]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
extendedKeyUsage=critical,emailProtection
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
CFG

openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null \
  | openssl pkcs8 -topk8 -nocrypt -out ca.key 2>/dev/null
openssl req -new -x509 -key ca.key -out ca.crt -days 3650 -sha256 -config ca.cnf 2>/dev/null

gen_leaf () {
  eval "$2" > /dev/null 2>&1
  openssl req -new -key "$1.key" -out "$1.csr" -config leaf.cnf 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$1-leaf.crt" -days 1825 -"$3" -extfile leaf.cnf -extensions leaf_ext 2>/dev/null
  cat "$1-leaf.crt" ca.crt > "$1-chain.pem"
  echo "  $1"
}

gen_leaf es256   "openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out es256.key"  sha256
gen_leaf es384   "openssl ecparam -name secp384r1  -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out es384.key"  sha384
gen_leaf es512   "openssl ecparam -name secp521r1  -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out es512.key"  sha512
gen_leaf ps256   "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ps256.key" sha256
gen_leaf ps384   "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out ps384.key" sha384
gen_leaf ps512   "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out ps512.key" sha512
gen_leaf ed25519 "openssl genpkey -algorithm ED25519 -out ed25519.key" sha256

rm -f ./*.csr
echo "credentials in certs/"
