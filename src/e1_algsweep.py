#!/usr/bin/env python3
"""E1 extended: every standardised post-quantum signature, every chain depth.

The core experiment covers ML-DSA because that is what a C2PA deployment would
reach for first. This one widens it in two directions the paper's limitations
section currently apologises for.

Algorithms. SLH-DSA has signatures an order of magnitude larger than ML-DSA and
Falcon has signatures an order of magnitude smaller, so together they test
whether the certificate-dominance finding is a property of ML-DSA or of the
manifest structure. It should not survive at SLH-DSA sizes, and confirming
where it breaks is worth more than assuming it holds everywhere.

Chain depth. The discussion claims chain length is a lever nobody has pulled.
Depths 1 to 5 turn that claim into a measurement.

Certificate sizes. Every chain here is real. ML-DSA certificates come from
`cryptography` through pq_cose.py. `cryptography` cannot issue Falcon or
SLH-DSA certificates, so pq_certs.py encodes the TBSCertificate itself, with
the same fields and extensions, and signs it with liboqs; its encoder is
byte-identical to `cryptography` on ML-DSA, and every chain it builds is
verified before it is measured. The earlier model,

    certificate = public key + signature + overhead,

with the overhead measured from real ML-DSA certificates, is kept beside each
row (cert_der_bytes_model) so that the paper can say how far off it was.
"""

import os
import statistics
import sys

import cbor2

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import time_it, write_json, run_order  # noqa: E402
from pq_cose import CLAIM, HDR_ALG, HDR_X5CHAIN, HDR_X5T, build_chain  # noqa: E402
import pq_certs  # noqa: E402

def _measured_overhead():
    """Mean bytes a real ML-DSA certificate carries beyond key and signature.

    Measured rather than written down, so that it follows whatever the
    certificate profile in pq_cose.py actually emits. It was a constant, 296,
    until the Subject and Authority Key Identifiers the C2PA profile requires
    were added; with them it is about 353, identical across the three
    parameter sets and varying only by position in the chain.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization as ser
    _, chain = build_chain("ML-DSA-65", 3)
    extra = []
    for d in chain:
        c = x509.load_der_x509_certificate(d)
        pk = c.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        extra.append(len(d) - len(pk) - len(c.signature))
    return round(sum(extra) / len(extra))


X509_OVERHEAD = _measured_overhead()
# Hierarchy depth counts every certificate from leaf to root. The manifest
# carries all but the root (C2PA 2.5, Section 13.5), so a depth-h hierarchy
# puts h - 1 certificates in x5chain.
DEPTHS = [2, 3, 4, 5]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGES = os.path.join(ROOT, "images")

# (label, liboqs mechanism, COSE alg id)
# COSE ids: ML-DSA from RFC 9964. Falcon and SLH-DSA have no COSE assignment
# yet, so they are marked None and the structure uses a placeholder. That gap
# is itself worth a sentence in the paper.
PQ = [
    ("ML-DSA-44", "ML-DSA-44", -48),
    ("ML-DSA-65", "ML-DSA-65", -49),
    ("ML-DSA-87", "ML-DSA-87", -50),
    ("Falcon-512", "Falcon-512", None),
    ("Falcon-1024", "Falcon-1024", None),
    ("SLH-DSA-SHA2-128s", "SLH_DSA_PURE_SHA2_128S", None),
    ("SLH-DSA-SHA2-128f", "SLH_DSA_PURE_SHA2_128F", None),
    ("SLH-DSA-SHA2-192s", "SLH_DSA_PURE_SHA2_192S", None),
    ("SLH-DSA-SHA2-256s", "SLH_DSA_PURE_SHA2_256S", None),
]

CLASSICAL = [("Ed25519", -8, 64), ("ES256", -7, 64), ("PS256", -37, 256)]


def cose_bytes(alg_id, chain_ders, sig_len, referenced=False):
    """Exact COSE_Sign1 size for a given chain and signature length.

    CBOR encoding depends on lengths rather than contents, so filler of the
    right size gives the same byte count as the real certificates would.
    """
    import hashlib

    if referenced:
        protected = {HDR_ALG: alg_id,
                     HDR_X5T: [-16, hashlib.sha256(b"x" * 64).digest()]}
    else:
        certs = [b"\x00" * n for n in chain_ders]
        protected = {HDR_ALG: alg_id,
                     HDR_X5CHAIN: certs[0] if len(certs) == 1 else certs}
    protected_bstr = cbor2.dumps(protected)
    return len(cbor2.dumps(
        cbor2.CBORTag(18, [protected_bstr, {}, None, b"\x00" * sig_len])))


def median_image():
    if not os.path.isdir(IMAGES):
        return None
    s = [os.path.getsize(os.path.join(IMAGES, f))
         for f in os.listdir(IMAGES) if f.endswith(".jpg")]
    return statistics.median(s) if s else None


def jumbf_overhead():
    import json
    p = os.path.join(ROOT, "out", "e1_baseline.json")
    if not os.path.exists(p):
        return 1072
    rows = json.load(open(p))["results"]
    return int(statistics.median(r["manifest_minus_reserve"] for r in rows))


def main():
    import oqs

    overhead = jumbf_overhead()
    img = median_image()
    print(f"  JUMBF overhead {overhead} B; "
          f"median image {img:.0f} B" if img else f"  JUMBF overhead {overhead} B")

    results = []

    # Classical control, real certificates.
    for label, alg_id, sig_len in run_order(CLASSICAL):
        for depth in DEPTHS:
            key, chain = build_chain(label, depth)
            ders = [len(c) for c in chain[:-1]]   # root omitted
            emb = cose_bytes(alg_id, ders, sig_len)
            ref = cose_bytes(alg_id, ders, sig_len, referenced=True)
            results.append(row(label, "classical", alg_id, depth, sig_len,
                               None, ders, emb, ref, overhead, img,
                               "measured", None, None))

    # Post-quantum, modelled certificates, measured signing and verification.
    for label, mech, alg_id in run_order(PQ):
        try:
            signer = oqs.Signature(mech)
        except Exception:
            print(f"  {label}: not in this liboqs build, skipped")
            continue
        pk = signer.generate_keypair()
        msg = CLAIM
        sig = signer.sign(msg)
        verifier = oqs.Signature(mech)

        # SLH-DSA signs in hundreds of milliseconds, so a thousand iterations
        # would take hours. Scale the count to the operation.
        quick = "SLH-DSA" not in label
        n = 1000 if quick else 20
        w = 50 if quick else 3
        t_sign = time_it(lambda: signer.sign(msg), trials=n, warmup=w)
        t_verify = time_it(lambda: verifier.verify(msg, sig, pk),
                           trials=1000 if quick else 100, warmup=w)

        model = len(pk) + len(sig) + X509_OVERHEAD
        for depth in DEPTHS:
            if label.startswith("ML-DSA"):
                _, chain = build_chain(label, depth)
                source = "measured (cryptography)"
            else:
                kp, sg = pq_certs.oqs_backend(mech)
                _, chain = pq_certs.build_chain(label, depth, kp, sg)
                if not pq_certs.verify_chain_oqs(mech, chain):
                    raise RuntimeError(f"{label}: chain does not verify")
                source = "measured (pq_certs, verified with liboqs)"
            ders = [len(c) for c in chain[:-1]]   # root omitted
            emb = cose_bytes(alg_id if alg_id else -49, ders, len(sig))
            ref = cose_bytes(alg_id if alg_id else -49, ders, len(sig),
                             referenced=True)
            r = row(label, "post-quantum", alg_id, depth, len(sig),
                    len(pk), ders, emb, ref, overhead, img,
                    source, t_sign, t_verify)
            r["cert_der_bytes_each"] = ders
            r["root_der_bytes"] = len(chain[-1])
            r["cert_der_bytes_model"] = model
            r["chain_der_bytes_model"] = model * len(ders)
            r["placeholder_oid"] = label in pq_certs.PLACEHOLDER_OID
            results.append(r)
        print(f"  {label} done")

    write_json("e1_algsweep.json", results, notes=[
        "every certificate is real: ML-DSA from cryptography, Falcon and SLH-DSA "
        "from pq_certs.py (same profile, signed with liboqs, chain verified)",
        "FN-DSA has no object identifier; Falcon uses a same-length placeholder "
        "in NIST's signature arc",
        f"cert_der_bytes_model is the earlier model, public key + signature + "
        f"{X509_OVERHEAD} B, kept for comparison",
        "Falcon and SLH-DSA have no COSE algorithm identifier assigned; the "
        "structure uses a placeholder and the size is unaffected",
        "classical rows use real certificates and carry no timing",
        "chain_depth is the hierarchy from leaf to root; x5chain carries "
        "certs_carried = depth - 1 certificates, the root omitted",
    ])


def row(label, family, alg_id, depth, sig_len, pk_len, ders, emb, ref,
        overhead, img, cert_source, t_sign, t_verify):
    chain = sum(ders)
    d = {
        "alg": label,
        "family": family,
        "cose_alg_id": alg_id,
        "cose_alg_assigned": alg_id is not None,
        "chain_depth": depth,
        "certs_carried": len(ders),
        "sig_bytes": sig_len,
        "public_key_bytes": pk_len,
        "cert_der_bytes": ders[0],
        "cert_source": cert_source,
        "chain_der_bytes": chain,
        "chain_share_of_cose_pct": round(100 * chain / emb, 2),
        "cose_embedded_bytes": emb,
        "cose_referenced_bytes": ref,
        "saving_pct": round(100 * (emb - ref) / emb, 2),
        "manifest_embedded_bytes": emb + overhead,
        "manifest_referenced_bytes": ref + overhead,
    }
    if img:
        d["manifest_pct_of_median_image"] = round(100 * (emb + overhead) / img, 2)
        d["manifest_ref_pct_of_median_image"] = round(
            100 * (ref + overhead) / img, 2)
    if t_sign:
        d["sign_ms"] = t_sign
        d["verify_ms"] = t_verify
    return d


if __name__ == "__main__":
    main()
