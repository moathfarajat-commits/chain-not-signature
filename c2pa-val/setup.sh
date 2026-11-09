#!/bin/bash
# Clone c2pa-rs main, fetch c2pa_raw_crypto 0.2.0, apply the RFC 9964 patches.
set -u
V=$HOME/line-a-experiments/c2pa-val; cd $V
log(){ echo "[$(date +%H:%M:%S)] $*"; }
[ -d c2pa-rs ] || git clone -q https://github.com/contentauth/c2pa-rs c2pa-rs
cd c2pa-rs && git fetch -q origin main && git checkout -q e2ad88ecb46948118a25796615132b7cdec735f1 && git log -1 --format='c2pa-rs %H %cd' ; cd $V
if [ ! -d c2pa_raw_crypto ]; then
  curl -fsSL -o rc.crate https://static.crates.io/crates/c2pa_raw_crypto/c2pa_raw_crypto-0.2.0.crate && tar xzf rc.crate && mv c2pa_raw_crypto-0.2.0 c2pa_raw_crypto
  (cd c2pa_raw_crypto && patch -p0 < $V/c2pa_raw_crypto-signing_alg.patch)
  cp $V/mldsa_signer.rs c2pa_raw_crypto/src/rust_native/signers/
  cp $V/mldsa_validator.rs c2pa_raw_crypto/src/rust_native/validators/
fi
cd c2pa-rs && git checkout -q -- . && sed "s#/tmp/patched/c2pa_raw_crypto#$V/c2pa_raw_crypto#" $V/c2pa-rs-rfc9964.patch > /tmp/c2pa-p.patch && git apply /tmp/c2pa-p.patch && git diff --stat
log SETUP_DONE
