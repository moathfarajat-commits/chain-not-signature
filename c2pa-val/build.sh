#!/bin/bash
# Build the harness twice: p1 (the paper's patch) and p2 (plus ML-DSA path validation).
set -u
V=$HOME/line-a-experiments/c2pa-val; cd $V
export PATH="$HOME/.cargo/bin:$PATH"
log(){ echo "[$(date +%H:%M:%S)] $*"; }
mkdir -p bin
rm -rf c2pa_raw_crypto && bash setup.sh > setup.log 2>&1 || exit 1
python3 port.py p1 || exit 1
(cd harness && cargo build --release -j 6 > ../build-p1.log 2>&1) || { log "p1 build FAILED"; grep -E "^(error|warning: unused)" -A12 build-p1.log | head -80; exit 1; }
cp harness/target/release/lineaval bin/lineaval-p1; log "p1 built"
python3 port.py p2 || exit 1
(cd harness && cargo build --release -j 6 > ../build-p2.log 2>&1) || { log "p2 build FAILED"; grep -E "^error" -A12 build-p2.log | head -80; exit 1; }
cp harness/target/release/lineaval bin/lineaval-p2; log "p2 built"
log BUILD_DONE
