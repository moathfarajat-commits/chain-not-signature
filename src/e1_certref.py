#!/usr/bin/env python3
"""E1 mitigation: certificate reference instead of an embedded chain.

The baseline result is that certificates, not signatures, dominate a
post-quantum manifest: in a three-certificate chain they are over 80% of the
COSE structure. The obvious response is not to embed them.

RFC 9360 header 34 (x5t) carries a certificate thumbprint. The verifier resolves
the signer through a trust list, which C2PA already operates, so this is a
deployment change rather than a new mechanism.

This script measures what that saves, per algorithm and per chain depth, and
what it costs in verification terms (an extra trust-list lookup, which is a
network or cache operation rather than cryptography).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import time_it, write_json  # noqa: E402
from pq_cose import (COSE_ALG, CLAIM, build_chain, sign_cose,  # noqa: E402
                     sign_cose_certref)

ALGS = ["Ed25519", "ES256", "PS256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
DEPTHS = [2, 3]


def main():
    print(f"  {len(ALGS)} algorithms, depths {DEPTHS}")
    results = []
    for alg in ALGS:
        for depth in DEPTHS:
            key, chain = build_chain(alg, depth)

            embedded, siglen = sign_cose(alg, key, chain, CLAIM)
            referenced, _ = sign_cose_certref(alg, key, chain, CLAIM)

            results.append({
                "alg": alg,
                "cose_alg_id": COSE_ALG[alg],
                "chain_depth": depth,
                "sig_bytes": siglen,
                "chain_der_bytes": sum(len(c) for c in chain[:-1]),
                "cose_embedded_bytes": len(embedded),
                "cose_referenced_bytes": len(referenced),
                "saving_bytes": len(embedded) - len(referenced),
                "saving_pct": round(
                    100 * (len(embedded) - len(referenced)) / len(embedded), 2),
                "sign_embedded": time_it(
                    lambda: sign_cose(alg, key, chain, CLAIM)),
                "sign_referenced": time_it(
                    lambda: sign_cose_certref(alg, key, chain, CLAIM)),
            })
        print(f"  {alg} done")

    write_json("e1_certref.json", results, notes=[
        "x5t is RFC 9360 header 34, a SHA-256 thumbprint of the leaf certificate",
        "the verifier resolves the signer through a trust list, not the manifest",
        "signing cost is unchanged; the saving is entirely in bytes",
        "trade-off: verification needs trust-list access, so offline verification of an unknown signer is lost",
    ])


if __name__ == "__main__":
    main()
