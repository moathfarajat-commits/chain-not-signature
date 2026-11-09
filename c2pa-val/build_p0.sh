#!/bin/bash
# p0: the harness against c2pa-rs e2ad88e exactly as published (crates.io
# c2pa_raw_crypto, no Line A patch), for the classical algorithms only. It
# answers whether the two departures from C2PA 2.5 are in the unmodified
# library rather than introduced by the ML-DSA patch.
set -u
V=$HOME/line-a-experiments/c2pa-val; cd $V
export PATH="$HOME/.cargo/bin:$PATH"
log(){ echo "[$(date +%H:%M:%S)] $*"; }
if [ ! -d c2pa-rs-p0 ]; then
  git -C c2pa-rs worktree add -f ../c2pa-rs-p0 e2ad88ecb46948118a25796615132b7cdec735f1 > /dev/null 2>&1 \
    || git clone -q c2pa-rs c2pa-rs-p0
fi
git -C c2pa-rs-p0 checkout -q -f e2ad88ecb46948118a25796615132b7cdec735f1
git -C c2pa-rs-p0 status --short | head -3
git -C c2pa-rs-p0 log -1 --format='p0 c2pa-rs %H %cd'
rm -rf harness-p0 && mkdir harness-p0 && cp -r harness/src harness-p0/
grep -v "MlDsa" harness/src/main.rs > harness-p0/src/main.rs
sed -e 's#\.\./c2pa-rs/sdk#../c2pa-rs-p0/sdk#' -e '/^\[patch.crates-io\]/,/^$/d' \
    harness/Cargo.toml > harness-p0/Cargo.toml
(cd harness-p0 && cargo build --release -j 6 > ../build-p0.log 2>&1) \
  || { log "p0 build FAILED"; grep -E "^error" -A12 build-p0.log | head -60; exit 1; }
mkdir -p bin && cp harness-p0/target/release/lineaval bin/lineaval-p0
log P0_BUILT
