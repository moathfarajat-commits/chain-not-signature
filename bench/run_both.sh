#!/bin/bash
# Every timing experiment, twice: once through cryptography built from source
# against -O3 OpenSSL 4.0.2 (out-o3/), once through the PyPI wheel whose
# OpenSSL 4.0.2 carries no optimisation flag (out-o0/). Same code, same
# machine, same session; only the build differs.
set -u
ROOT="$HOME/line-a-experiments"
cd "$ROOT"
export DYLD_LIBRARY_PATH="$HOME/_oqs/lib"
log() { echo "[$(date +%H:%M:%S)] $*"; }

EXPS="src/e1_pq.py src/e1_certref.py src/e1_carriage.py src/e1_verify.py
      src/e1_algsweep.py src/e1_cache.py src/e1_hash.py src/e1_timestamp.py
      src/e4_wrap.py src/e1_mixedchain.py compare_backends.py src/e1_archive.py"

for build in o3 o0; do
  venv=".venv-o3"; [ "$build" = o0 ] && venv=".venv"
  source "$venv/bin/activate"
  export LINEA_OUT="out-$build"
  mkdir -p "$LINEA_OUT" logs
  log "== $build: $(python -c 'import sys;sys.path.insert(0,"src");import common;print(common.openssl_build().get("openssl_compiler"))')"
  for e in $EXPS; do
    name=$(basename "$e" .py)
    if python "$e" > "logs/$build-$name.log" 2>&1; then
      log "ok   $build $name"
    else
      log "FAIL $build $name"; tail -5 "logs/$build-$name.log"
    fi
  done
  deactivate
done
log "BOTH_DONE"
