#!/bin/bash
# Re-run the three findings against the c2pa-rs 0.92.0 release candidate,
# unpatched, with the vectors in work/ from the matrix run.
set -u
V=$HOME/line-a-experiments/c2pa-val; cd $V
export PATH="$HOME/.cargo/bin:$PATH"
TAG=${1:-c2pa-rc-v0.92.0-rc.1}
log(){ echo "[$(date +%T)] $*"; }
if [ ! -d c2pa-rs-rc ]; then
  git clone -q --depth 1 --branch $TAG https://github.com/contentauth/c2pa-rs c2pa-rs-rc || { log "clone failed"; exit 1; }
fi
git -C c2pa-rs-rc log -1 --format="tag $TAG %H %cd"
rm -rf harness-rc && mkdir harness-rc && cp -r harness-tag/src harness-rc/
sed -e 's#\.\./c2pa-rs-tag/sdk#../c2pa-rs-rc/sdk#' harness-tag/Cargo.toml > harness-rc/Cargo.toml
(cd harness-rc && cargo build --release -j 6 > ../build-rc.log 2>&1) \
  || { log "build FAILED"; grep -E "^error" -A12 build-rc.log | head -80; exit 1; }
mkdir -p bin; cp harness-rc/target/release/lineaval bin/lineaval-rc; log "built"
log BUILD_DONE
