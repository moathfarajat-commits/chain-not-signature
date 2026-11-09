#!/bin/bash
# A second Python environment whose `cryptography` is built from source against
# the -O3 OpenSSL 4.0.2 in build/ossl-asm. Same cryptography version as the
# wheel (50.0.1), same OpenSSL version (4.0.2); the only difference is that
# this OpenSSL was compiled with optimisation and the wheel's was not.
set -u
ROOT="$HOME/line-a-experiments"
B="$ROOT/build"
log() { echo "[$(date +%H:%M:%S)] $*"; }

# Rust, installed into the user's home only, if it is not already there.
if ! command -v cargo >/dev/null && [ ! -x "$HOME/.cargo/bin/cargo" ]; then
  log "installing a minimal Rust toolchain into ~/.cargo"
  curl -fsSL https://sh.rustup.rs -o "$B/rustup-init.sh" \
    && sh "$B/rustup-init.sh" -y --profile minimal --no-modify-path > "$B/rustup.log" 2>&1 \
    || { log "Rust install FAILED"; tail -20 "$B/rustup.log"; exit 1; }
fi
export PATH="$HOME/.cargo/bin:$PATH"
log "$(rustc --version)"

cd "$ROOT"
PY=$(command -v python3.12 || echo /opt/homebrew/bin/python3.12)
rm -rf .venv-o3
"$PY" -m venv .venv-o3
source .venv-o3/bin/activate
python -m pip install --quiet --upgrade pip

log "building cryptography 50.0.1 against the -O3 OpenSSL"
export OPENSSL_DIR="$B/ossl-asm"
export OPENSSL_STATIC=1
pip install --no-binary cryptography "cryptography==50.0.1" > "$B/cryptography-build.log" 2>&1 \
  || { log "cryptography build FAILED"; tail -30 "$B/cryptography-build.log"; exit 1; }

pip install --quiet "cbor2>=6.1.4" "pillow>=11.0" "matplotlib>=3.10"
export OQS_INSTALL_PATH="$HOME/_oqs"
export DYLD_LIBRARY_PATH="$HOME/_oqs/lib"
pip install --quiet liboqs-python

SO=$(python -c "import cryptography,os,glob;print(glob.glob(os.path.join(os.path.dirname(cryptography.__file__),'hazmat','bindings','_rust*.so'))[0])")
log "rebuilt wheel: $(strings "$SO" | grep -E '^compiler: ' | head -1)"
log "out-of-line helper copies: $(nm "$SO" | grep -cE ' _(constant_time_lt_32|constant_time_select_32|reduce_once|value_barrier_32)$')"
python -c "
from cryptography.hazmat.backends.openssl.backend import backend
import cryptography; print('cryptography', cryptography.__version__, backend.openssl_version_text())"
log "O3_ENV_DONE"
