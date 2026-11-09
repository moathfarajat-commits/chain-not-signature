#!/usr/bin/env python3
"""E1 verification side: what the certificate reference costs, not just saves.

The mitigation measured in e1_certref.py removes the certificate chain from the
manifest and leaves a thumbprint. That saves 83% of the COSE structure. This
script measures the other side of the trade, which is what a reviewer will ask
for first.

A verifier holding an embedded chain does everything locally:

    decode COSE -> read x5chain -> validate chain -> verify signature

A verifier holding a thumbprint must resolve the signer before it can do
anything:

    decode COSE -> read x5t -> look up trust list -> validate chain -> verify signature

Three lookup conditions are measured, because the answer depends entirely on
which one a deployment is in:

  warm    the certificate is already in memory, a dictionary hit
  cold    it is on disk, one open and parse
  remote  it is not held at all and must be fetched

The remote case is not measured here. It is a network round trip whose cost
belongs to the deployment, not to the cryptography, so it is reported as a
parameter the reader supplies. What the script does give is everything else, so
the remote cost can be added to a measured local baseline rather than guessed
at wholesale.
"""

import hashlib
import json
import os
import sys
import tempfile

import cbor2

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import time_it, write_json, run_order  # noqa: E402
from pq_cose import (CLAIM, COSE_ALG, build_chain, cose_sig_input,  # noqa: E402
                     liboqs_signer, liboqs_available, sign_cose,
                     sign_cose_certref)

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

ALGS = ["Ed25519", "ES256", "PS256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGES = os.path.join(ROOT, "images")
PHONE_BYTES = 4 * 1024 * 1024      # a 12-megapixel phone JPEG
DEPTH = 3


def decode_cose(blob):
    """Unwrap COSE_Sign1 and return (protected map, signature)."""
    tagged = cbor2.loads(blob)
    protected_bstr, _unprotected, _payload, signature = tagged.value
    return cbor2.loads(protected_bstr), signature


def validate_chain(der_chain):
    """Check each certificate's signature against its issuer.

    Same work whether the chain came from the manifest or from a trust store,
    which is the point: moving the chain does not remove this cost, it moves
    where the certificates are found.
    """
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


def verifier_for(alg, key, chain):
    """A callable that verifies one signature, through liboqs where available."""
    oq = liboqs_signer(alg)
    if oq:
        # liboqs generated its own keypair, so sign and verify with that pair
        sign_fn, verify_fn, _ = oq
        msg = cose_sig_input(alg, chain, CLAIM)
        sig = sign_fn(msg)
        return ("liboqs", lambda: verify_fn(msg, sig))

    from pq_cose import raw_sign, raw_verify
    msg = cose_sig_input(alg, chain, CLAIM)
    pub = key.public_key()
    sig = raw_sign(alg, key, msg)
    return ("openssl", lambda: raw_verify(alg, pub, sig, msg))


def timestamp_check(alg):
    """Callables for the two cryptographic checks a timestamp adds: the TSA's
    signature over its signed attributes, and the TSA's certificate path."""
    import pq_tst
    from cryptography.hazmat.primitives import serialization as ser
    chain, key = pq_tst.tsa_chain(alg)
    attrs = os.urandom(160)            # signed attributes are about this size
    sig = pq_tst._sign(alg, key, attrs)
    pub = chain[0].public_key()
    ders = [c.public_bytes(ser.Encoding.DER) for c in chain]
    return (lambda: pq_tst._verify(alg, pub, sig, attrs),
            lambda: validate_chain(ders))


def content_hashers():
    """SHA-256 over a median test image and over a phone-sized JPEG, the hard
    binding a validator recomputes before it trusts anything else."""
    sizes = sorted(os.path.getsize(os.path.join(IMAGES, f))
                   for f in os.listdir(IMAGES) if f.endswith(".jpg")) \
        if os.path.isdir(IMAGES) else [100_000]
    median = os.urandom(sizes[len(sizes) // 2])
    phone = os.urandom(PHONE_BYTES)
    return ({"median_image": (len(median), lambda: hashlib.sha256(median).digest()),
             "phone_jpeg": (len(phone), lambda: hashlib.sha256(phone).digest())})


def main():
    store_dir = tempfile.mkdtemp(prefix="trust-store-")
    print(f"  trust store: {store_dir}")
    print(f"  liboqs backend: {'available' if liboqs_available() else 'not installed'}")

    results = []
    for alg in run_order(ALGS):
        key, chain = build_chain(alg, DEPTH)
        embedded, _ = sign_cose(alg, key, chain, CLAIM)
        referenced, _ = sign_cose_certref(alg, key, chain, CLAIM)

        # Populate a trust store keyed by leaf thumbprint, which is how a
        # verifier resolves an x5t reference.
        thumb = hashlib.sha256(chain[0]).hexdigest()
        path = os.path.join(store_dir, f"{thumb}.chain")
        with open(path, "wb") as f:
            f.write(cbor2.dumps(chain))
        warm_store = {thumb: chain}

        def decode_embedded():
            p, _ = decode_cose(embedded)
            c = p[33]
            return c if isinstance(c, list) else [c]

        def decode_referenced():
            p, _ = decode_cose(referenced)
            return p[34][1].hex()

        def lookup_warm():
            return warm_store[decode_referenced()]

        def lookup_cold():
            t = decode_referenced()
            with open(os.path.join(store_dir, f"{t}.chain"), "rb") as f:
                return cbor2.loads(f.read())

        backend, verify_sig = verifier_for(alg, key, chain)

        t_decode_emb = time_it(decode_embedded)
        t_decode_ref = time_it(decode_referenced)
        t_lookup_warm = time_it(lookup_warm)
        t_lookup_cold = time_it(lookup_cold)
        t_chain = time_it(lambda: validate_chain(chain))
        t_sig = time_it(verify_sig)
        tst_sig, tsa_path = timestamp_check(alg)
        t_tst_sig = time_it(tst_sig)
        t_tsa_path = time_it(tsa_path)
        hashers = content_hashers()
        t_hash = {k: dict(time_it(fn, trials=200, warmup=10), bytes=n)
                  for k, (n, fn) in hashers.items()}

        emb_total = (t_decode_emb["median_ms"] + t_chain["median_ms"]
                     + t_sig["median_ms"])
        warm_total = (t_lookup_warm["median_ms"] + t_chain["median_ms"]
                      + t_sig["median_ms"])
        cold_total = (t_lookup_cold["median_ms"] + t_chain["median_ms"]
                      + t_sig["median_ms"])

        results.append({
            "alg": alg,
            "cose_alg_id": COSE_ALG[alg],
            "chain_depth": DEPTH,
            "sig_backend": backend,
            "cose_embedded_bytes": len(embedded),
            "cose_referenced_bytes": len(referenced),
            "decode_embedded_ms": t_decode_emb,
            "decode_referenced_ms": t_decode_ref,
            "lookup_warm_ms": t_lookup_warm,
            "lookup_cold_ms": t_lookup_cold,
            "validate_chain_ms": t_chain,
            "verify_signature_ms": t_sig,
            "total_embedded_ms": round(emb_total, 4),
            "total_referenced_warm_ms": round(warm_total, 4),
            "total_referenced_cold_ms": round(cold_total, 4),
            "verify_timestamp_signature_ms": t_tst_sig,
            "validate_tsa_path_ms": t_tsa_path,
            "hash_content_ms": t_hash,
            # Everything cryptographic a validator does for one timestamped
            # image, with assertion hashing (a few hundred bytes) left out.
            "complete_median_image_ms": round(
                emb_total + t_tst_sig["median_ms"] + t_tsa_path["median_ms"]
                + t_hash["median_image"]["median_ms"], 4),
            "complete_phone_jpeg_ms": round(
                emb_total + t_tst_sig["median_ms"] + t_tsa_path["median_ms"]
                + t_hash["phone_jpeg"]["median_ms"], 4),
            "chain_share_of_complete_median_pct": round(
                100 * t_chain["median_ms"] / (
                    emb_total + t_tst_sig["median_ms"] + t_tsa_path["median_ms"]
                    + t_hash["median_image"]["median_ms"]), 1),
            "warm_overhead_ms": round(warm_total - emb_total, 4),
            "cold_overhead_ms": round(cold_total - emb_total, 4),
        })
        print(f"  {alg} done ({backend})")

    write_json("e1_verify.json", results, notes=[
        "embedded: decode COSE, read x5chain (leaf and intermediate), validate "
        "the path to the root anchor (two verifications), verify signature",
        "complete_* adds the cryptographic work of a full validation of one "
        "timestamped image: TSA signature, TSA path, SHA-256 of the content; "
        "assertion hashing, ingredient manifests, revocation and policy checks "
        "are not included",
        "referenced: decode COSE, read x5t, resolve trust store, validate chain, verify signature",
        "warm = certificate already in memory; cold = read from local trust store on disk",
        "remote resolution is a network round trip and is deliberately not measured; "
        "add the deployment's own latency to the warm figure",
        "the reference does not remove chain validation, it moves where the certificates come from",
        "trade-off to state in the paper: offline verification of a signer the verifier has never "
        "seen is no longer possible",
    ])


if __name__ == "__main__":
    main()
