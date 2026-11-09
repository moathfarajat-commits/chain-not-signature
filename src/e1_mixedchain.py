#!/usr/bin/env python3
"""
Chains whose levels do not share one algorithm.

Every chain measured so far uses a single algorithm from leaf to root. No real
PKI transition looks like that. A certificate carries two algorithms, not one:
the subject public key it holds, and the signature its issuer put on it. During
a migration those come apart, and they come apart in a particular order,
because the three levels move at different speeds. Leaf certificates are
reissued in days. Intermediates live for years. Roots are pinned in trust
stores and shipped with software, so they move last.

Three consequences follow, and this experiment measures all three.

Bytes. A chain's size is set by whichever levels have migrated, not by the
algorithm named in the COSE header. A post-quantum leaf under a classical
intermediate and a classical root is a post-quantum manifest by the header, and
costs a fraction of a uniform post-quantum chain.

Security. The chain is only as post-quantum as its weakest link. If the
intermediate signed the leaf certificate with ECDSA, an adversary who can break
ECDSA forges a leaf and signs whatever it likes, and the ML-DSA signature on
the manifest buys nothing. Partial migration gives partial protection, and the
paper should say which part.

Assurance mixing. The other reading of a mixed chain is deliberate: a category-2
leaf under a category-3 intermediate under a category-5 root, so that the
long-lived keys carry the higher margin. That ladder is measured here too,
along with its inversion, which is what an operator gets wrong by accident.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as ser

from common import time_it, write_json, run_order
from pq_cose import (CLAIM, COSE_ALG, HDR_ALG, HDR_X5CHAIN, KEYGEN, _cert,
                     _name)

# Which algorithms are post-quantum, for the weakest-link verdict below.
PQ = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}

# NIST category by parameter set. ML-DSA-44 is category 2, not category 1.
CATEGORY = {"ES256": 0, "Ed25519": 0,
            "ML-DSA-44": 2, "ML-DSA-65": 3, "ML-DSA-87": 5}


def build_mixed_chain(algs):
    """Build a chain whose levels use different algorithms.

    `algs` runs leaf first, root last. Each level's key is generated under its
    own algorithm; each certificate is signed by its issuer's key, so the
    signature on a certificate is in the issuer's algorithm, not the subject's.
    Returns (leaf_key, [DER certs, leaf first], [per-certificate byte counts]).
    """
    depth = len(algs)
    keys = [KEYGEN[a]() for a in algs]

    def h(alg):
        # ECDSA needs a digest named explicitly; ML-DSA and Ed25519 reject one.
        return hashes.SHA256() if alg == "ES256" else None

    root_alg = algs[-1]
    root_key = keys[-1]
    root_cert = _cert(root_key.public_key(), _name(f"{root_alg} Root"),
                      root_key, f"{root_alg} Root", True, h(root_alg))

    chain, issuer_key, issuer_cert, issuer_alg = [], root_key, root_cert, root_alg
    for i in range(depth - 2, -1, -1):
        is_ca = i > 0
        cn = f"{algs[i]} Signer" if i == 0 else f"{algs[i]} Intermediate {i}"
        c = _cert(keys[i].public_key(), issuer_cert.subject, issuer_key,
                  cn, is_ca, h(issuer_alg),
                  issuer_pub=issuer_key.public_key())
        chain.insert(0, c)
        issuer_key, issuer_cert, issuer_alg = keys[i], c, algs[i]

    chain.append(root_cert)
    der = [c.public_bytes(ser.Encoding.DER) for c in chain]
    return keys[0], der, [len(d) for d in der]


def sign_mixed(leaf_alg, key, der_chain, claim_bytes):
    """COSE_Sign1 signed by the leaf key, carrying leaf and intermediates.

    The root is the verifier's trust anchor and is not carried (C2PA 2.5,
    Section 13.5). Its algorithm still matters, because it signs the
    intermediate's certificate, but its size does not reach the manifest."""
    carried = der_chain[:-1]
    protected = {HDR_ALG: COSE_ALG[leaf_alg],
                 HDR_X5CHAIN: carried[0] if len(carried) == 1 else carried}
    protected_bstr = cbor2.dumps(protected)
    sig_structure = cbor2.dumps(
        ["Signature1", protected_bstr, b"", claim_bytes])

    if leaf_alg == "ES256":
        from pq_cose import es256_sign
        signature = es256_sign(key, sig_structure)
    else:
        signature = key.sign(sig_structure)

    return cbor2.dumps(
        cbor2.CBORTag(18, [protected_bstr, {}, None, signature]))


def validate_chain(der_chain):
    """Verify each certificate against its issuer's public key."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    certs = [x509.load_der_x509_certificate(d) for d in der_chain]
    for child, parent in zip(certs, certs[1:]):
        pub = parent.public_key()
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       ec.ECDSA(child.signature_hash_algorithm))
        else:
            pub.verify(child.signature, child.tbs_certificate_bytes)
    return certs


def weakest_link(algs):
    """What an adversary with a quantum computer has to break.

    A chain authenticates the leaf key only if every signature above it holds.
    The leaf signs the manifest, the intermediate signs the leaf certificate,
    the root signs the intermediate: every level therefore carries one
    load-bearing signature. The root's self-signature is the exception and is
    not load-bearing, because a root is trusted by being in the trust store,
    not by having signed itself. So forging any one of these breaks the chain,
    and the weakest of them sets what the manifest is worth.
    """
    load_bearing = list(algs)
    classical = [a for a in load_bearing if a not in PQ]
    if not classical:
        cats = [CATEGORY[a] for a in load_bearing]
        return {"quantum_resistant": True,
                "broken_by": None,
                "effective_category": min(cats)}
    return {"quantum_resistant": False,
            "broken_by": sorted(set(classical)),
            "effective_category": 0}


# Leaf first, root last. The comment on each says what it represents.
SCENARIOS = [
    (["ES256", "ES256", "ES256"], "Classical",
     "classical throughout, the deployed state today"),

    (["ML-DSA-65", "ES256", "ES256"], "Leaf only",
     "first step: a post-quantum leaf issued by the existing classical PKI"),

    (["ML-DSA-65", "ML-DSA-65", "ES256"], "Leaf and intermediate",
     "second step: the root still classical and still in the trust store"),

    (["ES256", "ML-DSA-65", "ML-DSA-65"], "PKI first, leaves last",
     "a migrated PKI still issuing classical leaves for compatibility"),

    (["ML-DSA-65", "ML-DSA-65", "ML-DSA-65"], "Fully migrated",
     "every level post-quantum"),

    (["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"], "Assurance ladder",
     "the longer a key lives, the higher its category"),

    (["ML-DSA-87", "ML-DSA-65", "ML-DSA-44"], "Ladder inverted",
     "the error an operator makes by accident"),

    (["ML-DSA-44", "ML-DSA-44", "ML-DSA-87"], "Cheap leaves, strong root",
     "category 2 issuance under a category 5 anchor"),
]


def main():
    results = []
    for algs, stage, description in run_order(SCENARIOS):
        key, chain, per_cert = build_mixed_chain(algs)
        cose = sign_mixed(algs[0], key, chain, CLAIM)

        row = {
            "chain": algs,
            "label": "/".join(a.replace("ML-DSA-", "D") for a in algs),
            "stage": stage,
            "description": description,
            "leaf_alg": algs[0],
            "cose_alg_id": COSE_ALG[algs[0]],
            "cose_bytes": len(cose),
            "chain_der_bytes": sum(per_cert[:-1]),
            "per_cert_der_bytes": per_cert,
            "root_der_bytes_not_carried": per_cert[-1],
            "leaf_der_bytes": per_cert[0],
            "cert_share_pct": round(100 * sum(per_cert[:-1]) / len(cose), 2),
            "validate_chain_ms": time_it(lambda c=chain: validate_chain(c),
                                         trials=200, warmup=20),
            "sign_ms": time_it(
                lambda a=algs, k=key, c=chain: sign_mixed(a[0], k, c, CLAIM),
                trials=200, warmup=20),
        }
        row.update(weakest_link(algs))
        results.append(row)
        print(f"  {row['label']:<18} {row['cose_bytes']:>7} B  "
              f"chain {row['chain_der_bytes']:>7} B  "
              f"{'PQ' if row['quantum_resistant'] else 'classical'}")

    # Every row against the fully migrated chain and against the classical one.
    classical = next(r for r in results if r["chain"] == ["ES256"] * 3)
    uniform_pq = next(r for r in results
                      if r["chain"] == ["ML-DSA-65"] * 3)
    for r in results:
        r["bytes_vs_classical"] = round(
            r["cose_bytes"] / classical["cose_bytes"], 2)
        r["bytes_vs_uniform_pq"] = round(
            r["cose_bytes"] / uniform_pq["cose_bytes"], 2)

    # The whole manifest: the signer's chain and the timestamp's. A manifest
    # signed under ML-DSA but timestamped by a classical TSA can be backdated
    # by an adversary who breaks the TSA's algorithm, which undoes the
    # "signed before the certificate was revoked" argument a timestamp exists
    # to make. So the time evidence has its own weakest link.
    import hashlib
    import pq_tst
    whole = []
    for algs, stage, _ in SCENARIOS:
        if stage not in ("Classical", "Leaf only", "Leaf and intermediate",
                         "Fully migrated"):
            continue
        base = next(r for r in results if r["stage"] == stage)
        for tsa_alg in ("ES256", "ML-DSA-65"):
            tok, tinfo = pq_tst.token(tsa_alg, hashlib.sha256(b"x").digest())
            signer_pq = base["quantum_resistant"]
            tsa_pq = tsa_alg in PQ
            whole.append({
                "stage": stage,
                "chain": algs,
                "tsa_alg": tsa_alg,
                "tsa_chain": [tsa_alg] * 3,
                "signature_cose_bytes": base["cose_bytes"],
                "timestamp_token_bytes": len(tok),
                "manifest_crypto_bytes": base["cose_bytes"] + len(tok),
                "signature_quantum_resistant": signer_pq,
                "timestamp_quantum_resistant": tsa_pq,
                "provenance_quantum_resistant": signer_pq and tsa_pq,
                "what_a_quantum_adversary_can_do": (
                    "nothing in the signature or time evidence"
                    if signer_pq and tsa_pq else
                    "forge the signer's chain" if not signer_pq and tsa_pq else
                    "backdate the manifest by forging the timestamp"
                    if signer_pq else
                    "forge the signer's chain and the timestamp"),
            })
    for r in results:
        r["whole_manifest"] = [w for w in whole if w["stage"] == r["stage"]]

    write_json("e1_mixedchain.json", results, notes=[
        "x5chain carries leaf and intermediates; the root is the trust anchor "
        "and is not carried, though its algorithm signs the intermediate",
        "whole_manifest adds an RFC 3161 timestamp from a classical or a "
        "post-quantum TSA; a classical TSA leaves the time evidence forgeable",
        "chains run leaf first, root last",
        "a certificate's signature is made in the issuer's algorithm, not the subject's",
        "the COSE header names the leaf's algorithm, which is what signs the manifest",
        "quantum_resistant is false when any load-bearing signature in the path is classical",
        "the root's self-signature is not load-bearing: a root is trusted by being in the trust store",
        "the assurance ladder puts the higher category on the longer-lived key",
    ])


if __name__ == "__main__":
    main()
