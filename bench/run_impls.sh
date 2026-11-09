#!/bin/bash
# Implementation study for Section 6: why is OpenSSL's ML-DSA 48.9 times
# slower than liboqs on this Mac and only 8.3 times slower on x86?
#
# Builds, from source and in this order:
#   OpenSSL 4.0.2 with assembly, and without
#   liboqs 0.16.0 with native aarch64 code, and with a generic target
#   PQClean's portable reference ML-DSA-65
# then times ML-DSA-65 through each with one harness, and re-runs the Python
# comparison (the wheel's OpenSSL against the installed liboqs) at 1,000
# iterations. Every build finishes before any timing starts, so no benchmark
# shares the machine with a compiler.
set -u
ROOT="$HOME/line-a-experiments"
B="$ROOT/build"
BENCH="$ROOT/bench"
OUT="$B/results.jsonl"
META="$B/meta.txt"
JOBS=8
mkdir -p "$B"
cd "$B"
log() { echo "[$(date +%H:%M:%S)] $*"; }
: > "$OUT"
: > "$META"

# ---------------------------------------------------------------- OpenSSL --
OSSL=4.0.2
if [ ! -d "openssl-$OSSL" ]; then
  log "fetching OpenSSL $OSSL"
  curl -fsSL -o "openssl-$OSSL.tar.gz" \
    "https://github.com/openssl/openssl/releases/download/openssl-$OSSL/openssl-$OSSL.tar.gz" \
    && tar xzf "openssl-$OSSL.tar.gz" \
    || git clone -q --depth 1 --branch "openssl-$OSSL" https://github.com/openssl/openssl "openssl-$OSSL"
fi

for v in asm noasm; do
  prefix="$B/ossl-$v"
  if [ ! -f "$prefix/lib/libcrypto.a" ]; then
    log "building OpenSSL $OSSL ($v)"
    rm -rf "ossl-src-$v"; cp -R "openssl-$OSSL" "ossl-src-$v"
    flag=""; [ "$v" = noasm ] && flag="no-asm"
    ( cd "ossl-src-$v" \
      && ./Configure darwin64-arm64-cc --prefix="$prefix" --libdir=lib \
           no-shared no-tests no-docs $flag > "../cfg-$v.log" 2>&1 \
      && make -j"$JOBS" build_libs > "../make-$v.log" 2>&1 \
      && make install_dev > "../inst-$v.log" 2>&1 ) \
      || { log "OpenSSL $v build FAILED"; tail -15 "make-$v.log" "cfg-$v.log" 2>/dev/null; }
  fi
  cc -O2 -o "bench_ossl_$v" "$BENCH/bench_openssl.c" -I"$prefix/include" \
     "$prefix/lib/libcrypto.a" 2> "cc-ossl-$v.log" \
     || { log "harness against OpenSSL $v failed"; cat "cc-ossl-$v.log"; }
done

# Homebrew's OpenSSL, if present, as one more independently built copy.
BREW_OSSL="$(brew --prefix openssl@3 2>/dev/null)"
if [ -n "$BREW_OSSL" ] && [ -f "$BREW_OSSL/lib/libcrypto.a" ]; then
  cc -O2 -o bench_ossl_brew "$BENCH/bench_openssl.c" -I"$BREW_OSSL/include" \
     "$BREW_OSSL/lib/libcrypto.a" 2> cc-ossl-brew.log || rm -f bench_ossl_brew
fi

# ----------------------------------------------------------------- liboqs --
OQS=0.16.0
if [ ! -d "liboqs-$OQS" ]; then
  log "fetching liboqs $OQS"
  curl -fsSL -o "liboqs-$OQS.tar.gz" \
    "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$OQS.tar.gz" \
    && tar xzf "liboqs-$OQS.tar.gz"
fi

for v in native generic; do
  prefix="$B/oqs-$v"
  if [ ! -f "$prefix/lib/liboqs.a" ]; then
    log "building liboqs $OQS ($v)"
    extra="-DOQS_OPT_TARGET=auto"
    [ "$v" = generic ] && extra="-DOQS_OPT_TARGET=generic -DOQS_USE_ARM_NEON_INSTRUCTIONS=OFF"
    # OQS_USE_OPENSSL=OFF keeps liboqs's own Keccak in the loop, so this
    # comparison never routes SHAKE through OpenSSL by the back door.
    cmake -S "liboqs-$OQS" -B "oqs-build-$v" -DCMAKE_BUILD_TYPE=Release \
      -DOQS_DIST_BUILD=OFF -DOQS_USE_OPENSSL=OFF -DBUILD_SHARED_LIBS=OFF \
      -DOQS_BUILD_ONLY_LIB=ON -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65" \
      -DCMAKE_INSTALL_PREFIX="$prefix" $extra > "oqs-cfg-$v.log" 2>&1 \
      && cmake --build "oqs-build-$v" -j"$JOBS" > "oqs-make-$v.log" 2>&1 \
      && cmake --install "oqs-build-$v" > /dev/null 2>&1 \
      || { log "liboqs $v build FAILED"; tail -15 "oqs-cfg-$v.log" "oqs-make-$v.log"; }
    grep -iE "ml_dsa|NEON|ARM_|OPT_TARGET|USE_OPENSSL" "oqs-build-$v/CMakeCache.txt" \
      > "oqs-flags-$v.txt" 2>/dev/null
    grep -iE "ml_dsa|NEON|ARM" "$prefix/include/oqs/oqsconfig.h" \
      >> "oqs-flags-$v.txt" 2>/dev/null
  fi
  cc -O2 -o "bench_oqs_$v" "$BENCH/bench_liboqs.c" -I"$prefix/include" \
     "$prefix/lib/liboqs.a" 2> "cc-oqs-$v.log" \
     || { log "harness against liboqs $v failed"; cat "cc-oqs-$v.log"; }
done

# The liboqs the Python measurements use, for continuity with the paper.
if [ -f "$HOME/_oqs/lib/liboqs.dylib" ]; then
  cc -O2 -o bench_oqs_installed "$BENCH/bench_liboqs.c" -I"$HOME/_oqs/include" \
     -L"$HOME/_oqs/lib" -loqs 2> cc-oqs-installed.log || rm -f bench_oqs_installed
fi

# ---------------------------------------------------------------- PQClean --
if [ ! -d pqclean ]; then
  log "fetching PQClean"
  git clone -q --depth 1 https://github.com/PQClean/PQClean pqclean
fi
D="pqclean/crypto_sign/ml-dsa-65/clean"
if [ -d "$D" ]; then
  cc -O3 -o bench_pqclean_clean "$BENCH/bench_pqclean.c" "$D"/*.c \
     pqclean/common/fips202.c pqclean/common/randombytes.c \
     -I"$D" -Ipqclean/common 2> cc-pqclean.log \
     || { log "PQClean harness failed"; head -30 cc-pqclean.log; }
else
  log "PQClean has no ml-dsa-65/clean in this checkout"; ls pqclean/crypto_sign | head
fi

# --------------------------------------------------------------- timings --
log "all builds done; timing starts"
run() { local bin=$1 name=$2; shift 2
  [ -x "./$bin" ] || { log "skip $name (not built)"; return; }
  log "timing $name"
  "$@" "./$bin" "$name" >> "$OUT" 2>> "$META" || log "$name FAILED"
}
run bench_ossl_asm      "openssl-4.0.2-source-asm"
run bench_ossl_noasm    "openssl-4.0.2-source-noasm"
run bench_ossl_brew     "openssl-homebrew"
run bench_oqs_native    "liboqs-0.16.0-native"
run bench_oqs_generic   "liboqs-0.16.0-generic"
run bench_oqs_installed "liboqs-installed" env DYLD_LIBRARY_PATH="$HOME/_oqs/lib"
run bench_pqclean_clean "pqclean-ml-dsa-65-clean"

# The Python comparison last, on a quiet machine, at 1,000 iterations.
log "re-running the Python backend comparison"
cd "$ROOT"
source .venv/bin/activate
export DYLD_LIBRARY_PATH="$HOME/_oqs/lib"
python compare_backends.py > "$B/compare_backends.log" 2>&1 || log "compare_backends FAILED"
tail -3 "$B/compare_backends.log"

log "IMPLS_DONE"
