#!/usr/bin/env python3
"""Same algorithms, two implementations, one machine.

The M1 Pro runs standalone SHA-3 faster than an x86_64 Xeon yet signs ML-DSA-65
five times slower, on the same OpenSSL version. That points at OpenSSL's aarch64
lattice path rather than at the hardware. This script separates the two claims by
running the same operations through liboqs, which ships hand-written AVX2 and
NEON backends.

Read it this way:

  liboqs fast, OpenSSL slow   -> the finding is about OpenSSL's aarch64 build
  both slow                   -> the finding is broader than one library
  both fast                   -> the earlier measurement was wrong somewhere

Setup:
    brew install cmake          # macOS
    pip install liboqs-python   # first import builds liboqs, a few minutes

Run:
    python3 compare_backends.py
"""

import json
import os
import platform
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
try:
    from common import write_json
except Exception:
    write_json = None


# LINEA_SIGN_ONLY=1 drops the ML-KEM rows. The Raspberry Pi run sets it: KEM
# timings on that board belong to a separate study, and Line A reports
# signatures only from it.
SIGN_ONLY = os.environ.get("LINEA_SIGN_ONLY") == "1"


def med(fn, n=1000, warm=50):
    for _ in range(warm):
        fn()
    v = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        v.append((time.perf_counter() - t) * 1000)
    v.sort()
    return {"median_ms": round(statistics.median(v), 4),
            "mean_ms": round(statistics.fmean(v), 4),
            "iqr_ms": round(v[3 * len(v) // 4] - v[len(v) // 4], 4),
            "p95_ms": round(v[min(int(0.95 * len(v)), len(v) - 1)], 4),
            "min_ms": round(v[0], 4), "n": n}


def openssl_arms():
    from cryptography.hazmat.backends.openssl.backend import backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

    msg = b"line-a benchmark message"
    blob = b"x" * 65536
    out = {"library": f"OpenSSL via cryptography ({backend.openssl_version_text()})"}

    def sha3():
        h = hashes.Hash(hashes.SHA3_256())
        h.update(blob)
        h.finalize()
    out["SHA3-256 64KiB"] = med(sha3)

    d = mldsa.MLDSA65PrivateKey.generate()
    sig = d.sign(msg)
    pub = d.public_key()
    out["ML-DSA-65 sign"] = med(lambda: d.sign(msg))
    out["ML-DSA-65 verify"] = med(lambda: pub.verify(sig, msg))
    out["ML-DSA-65 sig bytes"] = len(sig)

    if SIGN_ONLY:
        return out
    k = mlkem.MLKEM768PrivateKey.generate()
    kp = k.public_key()
    _, ct = kp.encapsulate()
    out["ML-KEM-768 encap"] = med(lambda: kp.encapsulate())
    out["ML-KEM-768 decap"] = med(lambda: k.decapsulate(ct))
    out["ML-KEM-768 ct bytes"] = len(ct)
    return out


def liboqs_arms():
    import oqs

    msg = b"line-a benchmark message"
    out = {"library": f"liboqs {oqs.oqs_version()}"}

    with oqs.Signature("ML-DSA-65") as signer:
        pk = signer.generate_keypair()
        sig = signer.sign(msg)
        out["ML-DSA-65 sign"] = med(lambda: signer.sign(msg))
        out["ML-DSA-65 sig bytes"] = len(sig)
    with oqs.Signature("ML-DSA-65") as verifier:
        out["ML-DSA-65 verify"] = med(lambda: verifier.verify(msg, sig, pk))

    if SIGN_ONLY:
        return out
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        kpk = kem.generate_keypair()
        ct, _ = kem.encap_secret(kpk)
        out["ML-KEM-768 encap"] = med(lambda: kem.encap_secret(kpk))
        out["ML-KEM-768 decap"] = med(lambda: kem.decap_secret(ct))
        out["ML-KEM-768 ct bytes"] = len(ct)
    return out


def main():
    print(f"{platform.machine()}  python {sys.version.split()[0]}\n")

    arms = [openssl_arms()]
    try:
        arms.append(liboqs_arms())
    except Exception as e:
        print(f"liboqs unavailable ({e.__class__.__name__}: {e})")
        print("install it with: brew install cmake && pip install liboqs-python\n")

    ops = ["ML-DSA-65 sign", "ML-DSA-65 verify"]
    if not SIGN_ONLY:
        ops += ["ML-KEM-768 encap", "ML-KEM-768 decap"]
    width = max(len(a["library"]) for a in arms)
    print(f"{'operation':20s} " + " ".join(f"{a['library'][:28]:>28s}" for a in arms))
    for op in ops:
        row = f"{op:20s} "
        row += " ".join(f"{a[op]['median_ms']:28.4f}" for a in arms if op in a)
        print(row)

    if len(arms) == 2:
        print()
        for op in ops:
            r = arms[0][op]["median_ms"] / arms[1][op]["median_ms"]
            verdict = "OpenSSL slower" if r > 1.2 else ("liboqs slower" if r < 0.83 else "comparable")
            print(f"  {op:20s} OpenSSL/liboqs = {r:5.2f}x   {verdict}")

    if write_json:
        write_json("backend_comparison.json", arms, notes=[
            "same machine, same algorithms, two implementations",
            "separates an OpenSSL aarch64 build effect from a hardware effect",
        ])


if __name__ == "__main__":
    main()
