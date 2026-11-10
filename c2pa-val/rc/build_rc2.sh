#!/bin/bash
set -u
V=$HOME/line-a-experiments/c2pa-val; cd $V
export PATH="$HOME/.cargo/bin:$PATH"
log(){ echo "[$(date +%T)] $*"; }
# 0.92 adds a context parameter to Signer::send_timestamp_request; only verification is used here.
sed -i '' 's/fn send_timestamp_request(&self, message: &\[u8\]) -> Option<c2pa::Result<Vec<u8>>>/fn send_timestamp_request(\&self, message: \&[u8], _context: \&c2pa::Context) -> Option<c2pa::Result<Vec<u8>>>/' harness-rc/src/main.rs
grep -n "fn send_timestamp_request" harness-rc/src/main.rs
(cd harness-rc && cargo build --release -j 6 > ../build-rc.log 2>&1) \
  || { log "build FAILED"; grep -E "^error" -A12 build-rc.log | head -80; exit 1; }
mkdir -p bin; cp harness-rc/target/release/lineaval bin/lineaval-rc; log BUILD_DONE
python3 run_rc_cases.py $V/bin/lineaval-rc c2pa-rc-v0.92.0-rc.1 $V/results/e1_findings_rc.json
log CASES_DONE
