#!/usr/bin/env python3
"""E1 end to end: the pixel hash against the signature.

Signing a content credential is not only a signature. The claim contains a
hard binding, a hash over the image data, and that hash has to be computed
before anything is signed. Papers that report post-quantum signing cost in
isolation leave it out, and on a real photograph it is the larger term.

This measures SHA-256 over images of increasing size against the signature
cost from the same machine, so signing can be reported end to end. It answers
the "post-quantum is slow" question from a second direction: if the hash over
a 4 MB JPEG exceeds ML-DSA signing, then migrating the signature changes the
total by a fraction, whatever the algorithm.

Image sizes are synthesised by concatenation rather than by re-encoding, since
SHA-256 cost depends on length alone. The Kodak measurements use the real
files.
"""

import hashlib
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import time_it, write_json, run_order  # noqa: E402
from pq_cose import CLAIM, build_chain, cose_sig_input, liboqs_signer  # noqa: E402

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# Sizes that matter, from Section 4.1 of the paper.
SIZES = [
    ("thumbnail", 20_000),
    ("Kodak q90 (median)", 107_672),
    ("social re-encode", 350_000),
    ("1080p JPEG", 900_000),
    ("phone original", 4_000_000),
    ("high-res / raw-ish", 12_000_000),
]

ALGS = ["Ed25519", "ES256", "PS256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGES = os.path.join(ROOT, "images")


def sign_cost(alg):
    """Median signing time in ms, through the best available implementation."""
    key, chain = build_chain(alg, 3)
    msg = cose_sig_input(alg, chain, CLAIM)
    oq = liboqs_signer(alg)
    if oq:
        sign_fn = oq[0]
        return "liboqs", time_it(lambda: sign_fn(msg))
    from pq_cose import raw_sign
    return "openssl", time_it(lambda: raw_sign(alg, key, msg))


def main():
    signing = {}
    for alg in run_order(ALGS):
        backend, t = sign_cost(alg)
        signing[alg] = {"backend": backend, "median_ms": t["median_ms"],
                        "p99_ms": t["p99_ms"]}
        print(f"  sign {alg}: {t['median_ms']:.3f} ms ({backend})")

    results = []
    for label, n in SIZES:
        blob = os.urandom(min(n, 1 << 20))
        blob = (blob * (n // len(blob) + 1))[:n]

        def h():
            d = hashlib.sha256()
            d.update(blob)
            d.digest()

        t = time_it(h, trials=200, warmup=20)
        row = {"case": label, "image_bytes": n, "hash_ms": t,
               "throughput_MBps": round(n / 1e6 / (t["median_ms"] / 1000), 1)}
        for alg in ALGS:
            s = signing[alg]["median_ms"]
            row[f"sign_{alg}_ms"] = s
            row[f"hash_share_{alg}_pct"] = round(
                100 * t["median_ms"] / (t["median_ms"] + s), 1)
        results.append(row)
        print(f"  hash {label} ({n:,} B): {t['median_ms']:.3f} ms")

    write_json("e1_hash.json", results, extra_env={"signing": signing}, notes=[
        "SHA-256 over the image, which the C2PA hard binding requires before "
        "any signature is computed",
        "hash_share is the hash as a percentage of hash plus signature, so it "
        "is the fraction of end-to-end signing cost that migration cannot change",
        "sizes above Kodak are synthesised by length, since SHA-256 cost "
        "depends on length alone",
        "a hardware-accelerated SHA-256 path will change these figures; the "
        "platform's crypto_features field records whether one is present",
    ])


if __name__ == "__main__":
    main()
