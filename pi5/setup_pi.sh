#!/usr/bin/env bash
# One-time setup for the Line A experiments on a Raspberry Pi 5.
#
# Everything goes under ~/line-a-pi (override with LINEA_PI_HOME): its own
# liboqs, its own Python environment. Nothing here touches system OpenSSL or
# any other project's builds on the same card, including the HQC paper's H6
# toolchain.
#
# Software matches the M1 reference data: cryptography 50.0.1, whose Linux
# aarch64 wheel bundles OpenSSL 4.0.2 compiled at -O3, and liboqs 0.16.0
# built for this CPU. About fifteen minutes on a Pi 5.

set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$(pwd)
BASE=${LINEA_PI_HOME:-$HOME/line-a-pi}
OQS_TAG=0.16.0
JOBS=$(nproc)

echo "== Line A Pi setup into $BASE"
[ "$(uname -m)" = aarch64 ] || echo "   note: not aarch64 ($(uname -m)); continuing for a rehearsal"
MODEL="not a Raspberry Pi"
[ -r /proc/device-tree/model ] && MODEL=$(tr -d '\0' < /proc/device-tree/model)
echo "   board: $MODEL"
mkdir -p "$BASE/src" "$BASE/opt"

# --- system packages ---------------------------------------------------------
need=()
for p in cmake ninja-build build-essential git python3-venv python3-dev util-linux; do
    dpkg -s "$p" >/dev/null 2>&1 || need+=("$p")
done
if [ ${#need[@]} -gt 0 ]; then
    if sudo -n true 2>/dev/null || [ "$(id -u)" = 0 ]; then
        echo "== apt: ${need[*]}"
        sudo apt-get update -qq && sudo apt-get install -y -qq "${need[@]}"
    else
        echo "   missing packages (${need[*]}) and no sudo: trying pip's cmake/ninja instead"
    fi
fi

# --- Python environment ------------------------------------------------------
if [ ! -x "$BASE/.venv/bin/python" ]; then
    python3 -m venv "$BASE/.venv"
fi
PY="$BASE/.venv/bin/python"
"$PY" -m pip install -q --upgrade pip
command -v cmake >/dev/null 2>&1 || "$PY" -m pip install -q cmake ninja
export PATH="$BASE/.venv/bin:$PATH"
"$PY" -m pip install -q "cryptography==50.0.1" "cbor2==6.1.4"

# --- liboqs, native build ----------------------------------------------------
if [ ! -f "$BASE/opt/liboqs/lib/liboqs.so" ] && [ ! -f "$BASE/opt/liboqs/lib64/liboqs.so" ]; then
    echo "== liboqs $OQS_TAG (native, shared)"
    rm -rf "$BASE/src/liboqs"
    git clone -q --depth 1 --branch "$OQS_TAG" https://github.com/open-quantum-safe/liboqs "$BASE/src/liboqs"
    gen=(); command -v ninja >/dev/null 2>&1 && gen=(-G Ninja)
    cmake -S "$BASE/src/liboqs" -B "$BASE/src/liboqs/build" "${gen[@]}" \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
        -DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=auto -DOQS_USE_OPENSSL=OFF \
        -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX="$BASE/opt/liboqs" >/dev/null
    cmake --build "$BASE/src/liboqs/build" -j "$JOBS" >/dev/null
    cmake --install "$BASE/src/liboqs/build" >/dev/null
fi
export OQS_INSTALL_PATH="$BASE/opt/liboqs"
"$PY" -m pip install -q "liboqs-python==0.16.0"

# --- record what was built ---------------------------------------------------
cat > "$BASE/env.sh" <<EOF
# source this before running anything by hand
export LINEA_PI_HOME="$BASE"
export OQS_INSTALL_PATH="$BASE/opt/liboqs"
export LD_LIBRARY_PATH="$BASE/opt/liboqs/lib:$BASE/opt/liboqs/lib64:\${LD_LIBRARY_PATH:-}"
export PATH="$BASE/.venv/bin:\$PATH"
EOF
# shellcheck disable=SC1091
. "$BASE/env.sh"

echo "== check"
python - <<'EOF'
import cryptography, glob, os, oqs
so = glob.glob(os.path.join(os.path.dirname(cryptography.__file__), "hazmat", "bindings", "_rust*.so"))[0]
b = open(so, "rb").read()
i = b.find(b"compiler: ")
line = b[i:b.index(b"\0", i)].decode()
print("   cryptography", cryptography.__version__)
print("  ", line)
assert "-O3" in line, "OpenSSL in this cryptography is not built with -O3"
print("   liboqs", oqs.oqs_version(), "| ML-DSA-65 enabled:", "ML-DSA-65" in oqs.get_enabled_sig_mechanisms())
EOF
echo "== done. Next: bash $REPO/pi5/run_pi.sh --quick"
