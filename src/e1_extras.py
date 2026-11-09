#!/usr/bin/env python3
"""E1 extras: two checks on the size results.

1. Compression. Would a general-purpose compressor remove the post-quantum
   overhead? ML-DSA keys and signatures are close to uniformly random, so the
   expectation is no, but it is measured: zlib, zstd and brotli at their
   highest settings over the COSE signature in every carriage form, and over
   signature plus timestamp token.

2. Composite signatures. draft-ietf-lamps-pq-composite-sigs pairs ML-DSA with
   a classical scheme; both component signatures must verify, so forging
   one takes breaking both. The
   composite public key is the concatenation of the two keys and the
   composite signature the concatenation of the two signatures, so sizes are
   additive. They are measured here with real certificates built by
   pq_certs.py and signed by both component keys, under placeholder object
   identifiers of the draft's length (the draft's identifiers are not yet
   final) and a placeholder COSE algorithm identifier (none is assigned).
   Signing and verification time are those of the two component operations
   in sequence, which is what a composite implementation does apart from
   prefixing the message.
"""

import hashlib
import os
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import time_it, write_json, run_order  # noqa: E402
import cbor2  # noqa: E402
import pq_certs  # noqa: E402
import pq_tst  # noqa: E402
from pq_cose import (CLAIM, FORMS, HDR_ALG, HDR_X5CHAIN, build_chain,  # noqa: E402
                     sign_cose)

from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa

ALGS = ["Ed25519", "ES256", "PS256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]

# Composite pairs from the draft, with the ML-DSA level and classical partner.
COMPOSITES = [
    ("ML-DSA-44+Ed25519", mldsa.MLDSA44PrivateKey, "Ed25519"),
    ("ML-DSA-65+ES256", mldsa.MLDSA65PrivateKey, "ES256"),
    ("ML-DSA-65+Ed25519", mldsa.MLDSA65PrivateKey, "Ed25519"),
    ("ML-DSA-87+ES384", mldsa.MLDSA87PrivateKey, "ES384"),
]
# Placeholders in the id-pkix algorithms arc, same encoded length as the
# draft's identifiers (1.3.6.1.5.5.7.6.n).
for i, (label, _, _) in enumerate(COMPOSITES):
    pq_certs.OIDS[label] = f"1.3.6.1.5.5.7.6.{90 + i}"
    pq_certs.PLACEHOLDER_OID.add(label)
COMPOSITE_COSE_PLACEHOLDER = -60


def compressors():
    out = {"zlib-9": lambda b: zlib.compress(b, 9)}
    try:
        import zstandard
        c = zstandard.ZstdCompressor(level=19)
        out["zstd-19"] = c.compress
    except Exception:
        pass
    try:
        import brotli
        out["brotli-11"] = lambda b: brotli.compress(b, quality=11)
    except Exception:
        pass
    return out


def compression_rows():
    comp = compressors()
    rows = []
    for alg in ALGS:
        key, chain = build_chain(alg, 3)
        tok, _ = pq_tst.token(alg, hashlib.sha256(b"claim signature").digest())
        for form in FORMS:
            cose, _ = sign_cose(alg, key, chain, CLAIM, form)
            for what, blob in (("signature", cose), ("signature+timestamp",
                                                      cose + tok)):
                r = {"alg": alg, "carriage": form, "object": what,
                     "bytes": len(blob)}
                for name, fn in comp.items():
                    n = len(fn(blob))
                    r[name] = n
                    r[name + "_saving_pct"] = round(100 * (len(blob) - n)
                                                    / len(blob), 2)
                rows.append(r)
        print(f"  compression {alg} done")
    return rows, sorted(comp)


def classical_key(kind):
    if kind == "Ed25519":
        k = ed25519.Ed25519PrivateKey.generate()
        pub = k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        return k, pub, (lambda m: k.sign(m)), (lambda s, m: k.public_key().verify(s, m))
    curve, h = ((ec.SECP256R1(), hashes.SHA256()) if kind == "ES256"
                else (ec.SECP384R1(), hashes.SHA384()))
    k = ec.generate_private_key(curve)
    pub = k.public_key().public_bytes(ser.Encoding.X962,
                                      ser.PublicFormat.UncompressedPoint)
    return (k, pub, (lambda m: k.sign(m, ec.ECDSA(h))),
            (lambda s, m: k.public_key().verify(s, m, ec.ECDSA(h))))


def composite_backend(pq_cls, classical):
    """keypair()/sign() callables for pq_certs, plus raw sign/verify."""
    def keypair():
        pk_pq = pq_cls.generate()
        ck, cpub, csign, cverify = classical_key(classical)
        pub = pk_pq.public_key().public_bytes(ser.Encoding.Raw,
                                              ser.PublicFormat.Raw) + cpub
        return pub, (pk_pq, csign, cverify)

    def sign(handle, msg):
        pk_pq, csign, _ = handle
        return pk_pq.sign(msg) + csign(msg)

    return keypair, sign


def composite_rows():
    rows = []
    for label, pq_cls, classical in run_order(COMPOSITES):
        keypair, sign = composite_backend(pq_cls, classical)
        (pk_bytes, handle), chain = build_composite_chain(label, keypair, sign)
        pk_pq, csign, cverify = handle
        msg = cbor2.dumps(["Signature1", b"\xa0", b"", CLAIM])
        sig = sign(handle, msg)
        pq_len = len(pk_pq.sign(msg))
        pub_pq = pk_pq.public_key()

        def verify():
            pub_pq.verify(sig[:pq_len], msg)
            cverify(sig[pq_len:], msg)

        carried = chain[:-1]
        protected = cbor2.dumps({HDR_ALG: COMPOSITE_COSE_PLACEHOLDER,
                                 HDR_X5CHAIN: carried})
        cose = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, None, sig]))
        leaf_only = cbor2.dumps(cbor2.CBORTag(18, [cbor2.dumps(
            {HDR_ALG: COMPOSITE_COSE_PLACEHOLDER, HDR_X5CHAIN: carried[0]}),
            {}, None, sig]))
        rows.append({
            "alg": label,
            "public_key_bytes": len(pk_bytes),
            "sig_bytes": len(sig),
            "cert_der_bytes_each": [len(c) for c in chain],
            "chain_der_bytes": sum(len(c) for c in carried),
            "cose_bytes": len(cose),
            "cose_leaf_only_bytes": len(leaf_only),
            "sign_ms": time_it(lambda: sign(handle, msg)),
            "verify_ms": time_it(verify),
            "placeholder_oid": True,
            "cose_alg_id": None,
        })
        print(f"  composite {label}: {len(cose)} B")
    return rows


def build_composite_chain(label, keypair, sign):
    keys = []
    orig = keypair

    def kp():
        k = orig()
        keys.append(k)
        return k
    _, chain = pq_certs.build_chain(label, 3, kp, sign)
    # pq_certs builds the root first, then the intermediate, then the leaf.
    return keys[-1], chain


def composite_and_tests():
    """Both components must verify: a composite signature with either half
    corrupted is rejected. This checks the AND rule on the component-cost
    construction measured here; it is not the draft's full combiner (domain
    separator, prehash and context), which changes what is signed but not
    the length of keys or signatures."""
    rows = []
    for label, pq_cls, classical in COMPOSITES:
        keypair, sign = composite_backend(pq_cls, classical)
        pub, handle = keypair()
        pk_pq, csign, cverify = handle
        msg = cbor2.dumps(["Signature1", b"\xa0", b"", CLAIM])
        sig = sign(handle, msg)
        n = len(pk_pq.sign(msg))

        def accepts(s):
            try:
                pk_pq.public_key().verify(s[:n], msg)
                cverify(s[n:], msg)
                return True
            except Exception:  # noqa: BLE001
                return False

        flip = lambda s, i: s[:i] + bytes([s[i] ^ 1]) + s[i + 1:]
        rows.append({"alg": label, "intact_accepted": accepts(sig),
                     "pq_component_corrupted_rejected": not accepts(flip(sig, n // 2)),
                     "classical_component_corrupted_rejected": not accepts(flip(sig, n + 8)),
                     "classical_component_missing_rejected": not accepts(sig[:n])})
    return rows


def main():
    if "--and-only" in sys.argv:
        rows = composite_and_tests()
        write_json("e1_composite_and.json", rows, notes=[
            "composite verification is AND: each component signature must verify",
            "corruption is one flipped bit in the middle of a component; 'missing' "
            "strips the classical half"])
        return
    comp, names = compression_rows()
    comps = composite_rows()
    results = [dict(r, experiment="compression") for r in comp] + \
              [dict(r, experiment="composite") for r in comps]
    write_json("e1_extras.json", results, notes=[
        f"compressors: {', '.join(names)} at their highest settings",
        "compression is applied to the COSE signature in each carriage form, "
        "and to signature plus RFC 3161 token",
        "composite pairs follow draft-ietf-lamps-pq-composite-sigs: public key "
        "and signature are the concatenations of the two components",
        "composite certificates are real and signed by both component keys; "
        "object identifiers are placeholders of the draft's length, and no "
        "COSE algorithm identifier is assigned",
        "composite timings are the two component operations in sequence",
    ])


if __name__ == "__main__":
    main()
