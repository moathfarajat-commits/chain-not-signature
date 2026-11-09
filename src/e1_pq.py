#!/usr/bin/env python3
"""E1 post-quantum: manifest cost with ML-DSA, per image.

c2pa-rs cannot sign with a post-quantum algorithm; its SigningAlg enum is closed
over seven classical algorithms. This script builds the COSE_Sign1 directly to
RFC 9964 (see pq_cose.py) and adds the JUMBF and claim overhead measured
empirically by e1_baseline.py.

    manifest_bytes = COSE_Sign1 bytes + JUMBF/claim overhead

The overhead term is the median of manifest_minus_reserve from the baseline run,
so it is measured rather than assumed. The library's fixed reservation is
excluded, because it is a policy constant of the current implementation and not
a property of the cryptography.
"""

import json
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import time_it, write_json, OUT_DIR, run_order  # noqa: E402
from pq_cose import (COSE_ALG, build_chain, sign_cose, CLAIM,  # noqa: E402
                     cose_sig_input, liboqs_signer, liboqs_available,
                     raw_sign, x5chain_for, DEFAULT_FORM)

ALGS = ["Ed25519", "ES256", "PS256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
DEPTHS = [2, 3]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGES = os.path.join(ROOT, "images")
FALLBACK_OVERHEAD = 1072   # measured on c2pa-rs 0.90.19


def jumbf_overhead():
    p = os.path.join(OUT_DIR, "e1_baseline.json")
    if not os.path.exists(p):
        print(f"  e1_baseline.json not found, using {FALLBACK_OVERHEAD} B")
        return FALLBACK_OVERHEAD, "fallback"
    rows = json.load(open(p))["results"]
    return int(statistics.median(r["manifest_minus_reserve"] for r in rows)), "measured"


def _raw_sign(alg, key, msg):
    return raw_sign(alg, key, msg)


def main():
    overhead, source = jumbf_overhead()
    images = sorted((f, os.path.getsize(os.path.join(IMAGES, f)))
                    for f in os.listdir(IMAGES) if f.endswith(".jpg"))
    if not images:
        sys.exit(f"no .jpg files in {IMAGES}; run ./fetch_images.sh first")

    print(f"  JUMBF and claim overhead: {overhead} B ({source})")
    print(f"  {len(images)} images, {len(ALGS)} algorithms, depths {DEPTHS}")
    print(f"  liboqs backend: {'available' if liboqs_available() else 'not installed'}")

    results = []
    for alg in run_order(ALGS):
        for depth in DEPTHS:
            key, chain = build_chain(alg, depth)
            carried = x5chain_for(DEFAULT_FORM, chain)
            cose, siglen = sign_cose(alg, key, chain, CLAIM)
            manifest = len(cose) + overhead

            # Timing is taken on the raw signature over the COSE Sig_structure,
            # not on the whole COSE build, so the two backends are comparable.
            sig_input = cose_sig_input(alg, chain, CLAIM)
            timing = {"openssl": time_it(
                lambda: _raw_sign(alg, key, sig_input))}

            oq = liboqs_signer(alg)
            if oq:
                sign_fn = oq[0]
                timing["liboqs"] = time_it(
                    lambda: sign_fn(sig_input))

            for name, img_bytes in images:
                results.append({
                    "image": name,
                    "image_bytes": img_bytes,
                    "alg": alg,
                    "cose_alg_id": COSE_ALG[alg],
                    "chain_depth": depth,
                    "sig_bytes": siglen,
                    "leaf_cert_der_bytes": len(chain[0]),
                    # What travels: signer and intermediates, root omitted.
                    "carriage": DEFAULT_FORM,
                    "certs_carried": len(carried),
                    "chain_der_bytes": sum(len(c) for c in carried),
                    "root_der_bytes": len(chain[-1]),
                    "chain_share_of_cose_pct": round(
                        100 * sum(len(c) for c in carried) / len(cose), 2),
                    "cose_bytes": len(cose),
                    "jumbf_overhead_bytes": overhead,
                    "manifest_bytes": manifest,
                    "manifest_pct_of_image": round(100 * manifest / img_bytes, 3),
                    "sign_ms": timing,
                })
        print(f"  {alg} done")

    write_json("e1_postquantum.json", results, notes=[
        f"JUMBF and claim overhead {overhead} B, {source} from e1_baseline.json",
        "c2pa-rs 0.90.19 rejects all post-quantum algorithms; COSE_Sign1 built per RFC 9964",
        "sizes exclude the c2pa-rs fixed reservation",
        "x5chain carries the signer and its intermediates; the root is "
        "omitted, as C2PA 2.5 Section 13.5 requires (depth 2: leaf only)",
        "signing time is the raw signature over the COSE Sig_structure, so backends are comparable",
        "OpenSSL's lattice code is far slower than liboqs on both x86_64 and aarch64; report liboqs, name both",
    ])


if __name__ == "__main__":
    main()
