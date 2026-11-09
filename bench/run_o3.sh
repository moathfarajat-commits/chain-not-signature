#!/bin/bash
# The paper's primary run: every experiment through cryptography built from
# source against -O3 OpenSSL 4.0.2, with certificates that carry the key
# identifiers the C2PA profile requires.
set -u
ROOT="$HOME/line-a-experiments"
cd "$ROOT/src"
for f in pq_cose e1_mixedchain e1_timestamp e1_algsweep; do
  [ -f "${f}_v2.py" ] && mv -f "${f}_v2.py" "$f.py"
done
rm -rf __pycache__
grep -q AuthorityKeyIdentifier pq_cose.py && echo "pq_cose: key identifiers present"
cd "$ROOT"
source .venv-o3/bin/activate
export DYLD_LIBRARY_PATH="$HOME/_oqs/lib"
export LINEA_OUT=out-o3
mkdir -p out-o3 logs
log() { echo "[$(date +%H:%M:%S)] $*"; }
for e in src/e1_pq.py src/e1_certref.py src/e1_carriage.py src/e1_verify.py \
         src/e1_algsweep.py src/e1_cache.py src/e1_hash.py src/e1_timestamp.py \
         src/e4_wrap.py src/e1_mixedchain.py compare_backends.py src/e1_archive.py; do
  name=$(basename "$e" .py)
  if python "$e" > "logs/o3-$name.log" 2>&1; then log "ok   $name"
  else log "FAIL $name"; tail -5 "logs/o3-$name.log"; fi
done
log "O3_RUN_DONE"
