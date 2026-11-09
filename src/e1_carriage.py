#!/usr/bin/env python3
"""E1 carriage: what travels in x5chain, and what the verifier must hold.

build_chain makes leaf <- intermediate <- root. Four carriage forms:

    root    leaf, intermediate and root. What the Adobe chains in the public
            test corpus carry. C2PA 2.5 (Section 13.5) says the trust
            anchor's certificate should not be included.

    chain   leaf and intermediate, root omitted. What C2PA 2.5 requires:
            the signer's certificate and every intermediate CA. This is the
            conformant baseline the other forms are compared with.

    leaf    the leaf alone. Conformant when the leaf's issuer is itself a
            trust anchor, which the C2PA trust list allows (it lists issuing
            CAs as well as roots). Otherwise the verifier must already hold
            the intermediate, which no specification provides for.

    thumb   RFC 9360 x5t and no certificate. Not conformant, and nothing
            specification-defined resolves the thumbprint to a leaf.

Path validation cost depends on where the trust anchor sits, not on what
travels. With the root as anchor a three-certificate hierarchy costs two
signature verifications (leaf by intermediate, intermediate by root). With
the issuing CA as anchor it costs one, because an anchor's own signature is
never checked. Both hierarchies are measured.
"""

import hashlib
import os
import statistics
import sys
import tempfile

import cbor2

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import time_it, write_json, run_order  # noqa: E402
from pq_cose import (CLAIM, build_chain, cose_sig_input,  # noqa: E402
                     liboqs_signer, protected_header, raw_sign, raw_verify,
                     x5chain_for)

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

ALGS = ["Ed25519", "ES256", "PS256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
DEPTH = 3
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGES = os.path.join(ROOT, "images")


def build_cose(alg, form, chain, signature):
    """COSE_Sign1 for one carriage form. Sizes are exact."""
    protected_bstr = cbor2.dumps(protected_header(alg, chain, form))
    return cbor2.dumps(cbor2.CBORTag(18, [protected_bstr, {}, None, signature]))


def verify_path(der_chain):
    certs = [x509.load_der_x509_certificate(d) for d in der_chain]
    for child, parent in zip(certs, certs[1:]):
        pub = parent.public_key()
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       padding.PKCS1v15(), child.signature_hash_algorithm)
        else:
            pub.verify(child.signature, child.tbs_certificate_bytes)
    return certs


def jumbf_overhead():
    import json
    p = os.path.join(ROOT, "out", "e1_baseline.json")
    if not os.path.exists(p):
        return 1072
    rows = json.load(open(p))["results"]
    return int(statistics.median(r["manifest_minus_reserve"] for r in rows))


def median_image():
    if not os.path.isdir(IMAGES):
        return None
    s = [os.path.getsize(os.path.join(IMAGES, f))
         for f in os.listdir(IMAGES) if f.endswith(".jpg")]
    return statistics.median(s) if s else None


def main():
    overhead = jumbf_overhead()
    img = median_image()
    store = tempfile.mkdtemp(prefix="trust-store-")
    print(f"  JUMBF overhead {overhead} B, trust store {store}")

    results = []
    for alg in run_order(ALGS):
        key, chain = build_chain(alg, DEPTH)
        msg = cose_sig_input(alg, chain, CLAIM)

        oq = liboqs_signer(alg)
        if oq:
            backend, sign_fn, verify_fn = "liboqs", oq[0], oq[1]
            sig = sign_fn(msg)
            verify_manifest = lambda: verify_fn(msg, sig)          # noqa: E731
        else:
            backend = "openssl"
            pub = key.public_key()
            sig = raw_sign(alg, key, msg)
            verify_manifest = lambda: raw_verify(alg, pub, sig, msg)  # noqa: E731

        for i, der in enumerate(chain[1:], start=1):
            with open(os.path.join(store, f"{alg}-{i}.der"), "wb") as f:
                f.write(der)

        t_verify_sig = time_it(verify_manifest)
        # Anchor at the root: leaf by intermediate, intermediate by root.
        t_path_root = time_it(lambda: verify_path(chain), trials=200, warmup=20)
        # Anchor at the issuing CA: leaf by intermediate only.
        t_path_ica = time_it(lambda: verify_path(chain[:2]), trials=200,
                             warmup=20)

        cases = [
            # form, anchor, conformance, path verifications
            ("root", "root", "allowed; root should not be included", 2),
            ("chain", "root", "required form", 2),
            ("leaf", "issuing CA", "conformant", 1),
            ("leaf", "root", "not conformant; intermediate must be "
                             "provisioned", 2),
            ("thumb", "root", "not conformant; leaf must be provisioned", 2),
        ]
        for form, anchor, conformance, npath in cases:
            cose = build_cose(alg, form, chain, sig)
            manifest = len(cose) + overhead
            carried = x5chain_for(form, chain)
            t_path = t_path_ica if npath == 1 else t_path_root
            row = {
                "alg": alg,
                "carriage": form,
                "anchor": anchor,
                "chain_depth": DEPTH,
                "sig_backend": backend,
                "sig_bytes": len(sig),
                "certs_carried": len(carried),
                "cert_bytes_carried": sum(len(c) for c in carried),
                "cose_bytes": len(cose),
                "manifest_bytes": manifest,
                "path_verifications": npath,
                "verify_path_ms": t_path,
                "verify_signature_ms": t_verify_sig,
                "verify_total_ms": round(
                    t_path["median_ms"] + t_verify_sig["median_ms"], 4),
                "conformance_c2pa_2_5": conformance,
                "verifier_must_hold": {
                    ("root", "root"): "root",
                    ("chain", "root"): "root",
                    ("leaf", "issuing CA"): "issuing CA",
                    ("leaf", "root"): "root and intermediate",
                    ("thumb", "root"): "root, intermediate and leaf",
                }[(form, anchor)],
            }
            if img:
                row["manifest_pct_of_median_image"] = round(
                    100 * manifest / img, 2)
            results.append(row)

        base = [r for r in results
                if r["alg"] == alg and r["carriage"] == "chain"][0]
        for r in results:
            if r["alg"] == alg:
                r["saving_vs_chain_pct"] = round(
                    100 * (base["manifest_bytes"] - r["manifest_bytes"])
                    / base["manifest_bytes"], 2)
        print(f"  {alg} done ({backend})")

    write_json("e1_carriage.json", results, notes=[
        "four carriage forms; build_chain makes leaf, intermediate and root",
        "baseline is 'chain': signer and every intermediate, root omitted, "
        "as C2PA 2.5 Section 13.5 requires",
        "an anchor's own signature is never checked, so path validation costs "
        "two verifications with the root as anchor and one with the issuing "
        "CA as anchor",
        "leaf-only carriage conforms only when the issuing CA is a trust "
        "anchor; the C2PA trust list lists issuing CAs as well as roots",
        "thumbprint carriage has no specification-defined resolver",
        "path timings are the cryptography/OpenSSL certificate checks; the "
        "manifest signature uses liboqs where available",
    ])


if __name__ == "__main__":
    main()
