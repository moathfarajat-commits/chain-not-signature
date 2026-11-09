#!/bin/bash
# Where does the wheel spend 4.6 ms on one ML-DSA-65 signature when the same
# OpenSSL version, built from source, needs 0.48? Sample both while they sign
# and compare the hottest frames.
set -u
ROOT="$HOME/line-a-experiments"
B="$ROOT/build"
cd "$ROOT"
source .venv/bin/activate

cat > "$B/wheel_loop.py" <<'PY'
import time
from cryptography.hazmat.primitives.asymmetric import mldsa
k = mldsa.MLDSA65PrivateKey.generate()
end = time.time() + 12
n = 0
while time.time() < end:
    k.sign(b"line-a benchmark message"); n += 1
print("wheel signatures", n)
PY

python "$B/wheel_loop.py" > "$B/wheel_loop.out" 2>&1 &
PY_PID=$!
sleep 2
sample "$PY_PID" 6 -file "$B/sample_wheel.txt" > /dev/null 2>&1
wait "$PY_PID"

"$B/bench_ossl_asm" source loop 12 2> "$B/source_loop.out" &
C_PID=$!
sleep 2
sample "$C_PID" 6 -file "$B/sample_source.txt" > /dev/null 2>&1
wait "$C_PID"

# Where the wheel's native code lives, and what it links.
python - <<'PY' > "$B/wheel_info.txt" 2>&1
import cryptography, os, glob
d = os.path.dirname(cryptography.__file__)
for so in glob.glob(os.path.join(d, "hazmat", "bindings", "*.so")):
    print(so, os.path.getsize(so))
PY
for so in $(awk '{print $1}' "$B/wheel_info.txt"); do
  otool -L "$so" >> "$B/wheel_info.txt" 2>&1
  nm -gU "$so" 2>/dev/null | grep -ciE "ml_dsa|mldsa" | sed 's/^/ml-dsa symbols exported: /' >> "$B/wheel_info.txt"
  nm "$so" 2>/dev/null | grep -iE "ossl_ml_dsa|ml_dsa_sign|mldsa" | head -20 >> "$B/wheel_info.txt"
done
echo PROFILE_DONE
