#!/usr/bin/env python3
"""E8: verification at platform scale, across CPU cores.

A platform that checks content credentials on upload verifies manifests from
many publishers, continuously. The question an operator asks is how many cores
that takes. This experiment answers it on the machines we have, and replaces
the GPU measurement the paper once planned.

The workload is a stream of manifests from --publishers signers, each with a
depth-3 chain, drawn with a Zipf distribution so that a few publishers produce
most of the traffic, as on a real platform. Three ways to verify each one:

  uncached          parse the embedded chain, validate it, verify the
                    signature: what every manifest costs when the chain
                    travels inside it
  cached            a worker that has already validated a publisher's chain
                    keeps the leaf key and only verifies the signature; the
                    first manifest from each publisher pays for validation
  cached, liboqs    as cached, with the ML-DSA signature checked by liboqs
                    rather than OpenSSL

Chains are always validated through `cryptography` (OpenSSL), because liboqs
has no X.509. Signatures are made with the certificate's own key, so every
verification is real.

Each worker count runs three times on a warm pool; the median throughput is
reported. Every verification must succeed, or the run stops.
"""

import argparse
import hashlib
import multiprocessing as mp
import os
import random
import statistics
import sys
import time

import cbor2

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import write_json, run_order  # noqa: E402
from pq_cose import (COSE_ALG, HDR_ALG, HDR_X5CHAIN, build_chain,  # noqa: E402
                     raw_sign, raw_verify)

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: E402

DEPTH = 3


# --- workload ---------------------------------------------------------------

def make_workload(alg, publishers, manifests, seed):
    """Per-publisher protected headers, and per-manifest (publisher, claim, sig)."""
    rng = random.Random(seed)
    heads, keys = [], []
    for _ in range(publishers):
        key, chain = build_chain(alg, DEPTH)
        # x5chain carries leaf and intermediate; the root is the verifier's
        # trust anchor and is appended from its store at validation time.
        heads.append(cbor2.dumps({HDR_ALG: COSE_ALG[alg],
                                  HDR_X5CHAIN: chain[:-1]}))
        ANCHORS.append(chain[-1])
        keys.append(key)
    # Zipf(1) over publishers: publisher k is chosen with weight 1/(k+1).
    weights = [1.0 / (k + 1) for k in range(publishers)]
    who = rng.choices(range(publishers), weights=weights, k=manifests)
    items = []
    for i, p in enumerate(who):
        claim = cbor2.dumps({"claim_generator_info": [{"name": "line-a-e8"}],
                             "seq": i, "hash": rng.randbytes(32)})
        tbs = cbor2.dumps(["Signature1", heads[p], b"", claim])
        sig = raw_sign(alg, keys[p], tbs)
        items.append((p, claim, sig))
    return heads, items


# --- worker side ------------------------------------------------------------

W = {}
ANCHORS = []      # per publisher, the root that x5chain leaves out


def _init(alg, heads, items, mode, n, anchors):
    W.update(alg=alg, heads=heads, items=items, mode=mode, n=n, cache={}, run=None,
             anchors=anchors)
    if mode == "cached-liboqs":
        import oqs
        W["oqs"] = oqs.Signature(alg)


def _validate(der, anchor):
    certs = [x509.load_der_x509_certificate(d) for d in list(der) + [anchor]]
    for child, parent in zip(certs, certs[1:]):
        pub = parent.public_key()
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       padding.PKCS1v15(), child.signature_hash_algorithm)
        else:
            pub.verify(child.signature, child.tbs_certificate_bytes)
    return certs[0].public_key()


def _verify_with(pub, sig, tbs):
    raw_verify(W["alg"], pub, sig, tbs)


def _work(idx):
    # Work items are numbered run * n + i, so a worker sees a new run number
    # on its first item of each timed run and starts that run with an empty
    # cache, whichever items the pool happens to hand it.
    run = idx // W["n"]
    if run != W["run"]:
        W["run"], W["cache"] = run, {}
    p, claim, sig = W["items"][idx % len(W["items"])]
    head = W["heads"][p]
    tbs = cbor2.dumps(["Signature1", head, b"", claim])
    mode = W["mode"]
    if mode == "uncached":
        prot = cbor2.loads(head)
        _verify_with(_validate(prot[HDR_X5CHAIN], W["anchors"][p]), sig, tbs)
        return 1
    hit = W["cache"].get(p)
    miss = hit is None
    if miss:
        prot = cbor2.loads(head)
        pub = _validate(prot[HDR_X5CHAIN], W["anchors"][p])
        if mode == "cached-liboqs":
            from cryptography.hazmat.primitives import serialization as ser
            raw = pub.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
            hit = raw
        else:
            hit = pub
        W["cache"][p] = hit
    if mode == "cached-liboqs":
        if not W["oqs"].verify(tbs, sig, hit):
            raise ValueError("liboqs rejected a valid signature")
    else:
        _verify_with(hit, sig, tbs)
    return 2 if miss else 1   # 2 marks a cache miss


# --- driver -----------------------------------------------------------------

def run(alg, heads, items, mode, workers, n, reps):
    ctx = mp.get_context("spawn")
    chunk = max(1, n // (workers * 16))
    with ctx.Pool(workers, initializer=_init,
                  initargs=(alg, heads, items, mode, n, list(ANCHORS))) as pool:
        warm = reps * n                                      # its own run number
        pool.map(_work, range(warm, warm + workers * 8), chunksize=1)
        rates, misses = [], []
        for r in range(reps):
            t0 = time.perf_counter()
            out = pool.map(_work, range(r * n, (r + 1) * n), chunksize=chunk)
            dt = time.perf_counter() - t0
            if len(out) != n:
                raise RuntimeError("lost work items")
            rates.append(n / dt)
            misses.append(sum(1 for x in out if x == 2))
    return statistics.median(rates), rates, statistics.median(misses)


def default_workers():
    c = os.cpu_count() or 1
    ws = [w for w in (1, 2, 4, 6, 8, 12, 16) if w < c] + [c]
    return sorted(set(ws))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--algs", default="Ed25519,ES256,PS256,ML-DSA-44,ML-DSA-65,ML-DSA-87")
    ap.add_argument("--publishers", type=int, default=500)
    ap.add_argument("--manifests", type=int, default=2000,
                    help="distinct signed manifests per algorithm")
    ap.add_argument("--verifications", type=int, default=20000,
                    help="verifications per timed run (manifests are reused)")
    ap.add_argument("--workers", default=",".join(map(str, default_workers())))
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--seed", type=int, default=20261022)
    a = ap.parse_args()
    if a.quick:
        a.algs, a.publishers, a.manifests, a.verifications, a.reps = \
            "Ed25519,ML-DSA-65", 20, 200, 2000, 1
        a.workers = "1,2"

    try:
        import oqs  # noqa: F401
        have_oqs = True
    except Exception:
        have_oqs = False

    workers = [int(x) for x in a.workers.split(",")]
    rows = []
    for alg in run_order(a.algs.split(",")):
        print(f"  {alg}: {a.publishers} publishers, {a.manifests} manifests", flush=True)
        ANCHORS.clear()
        heads, items = make_workload(alg, a.publishers, a.manifests, a.seed)
        modes = ["uncached", "cached"]
        if alg.startswith("ML-DSA") and have_oqs:
            modes.append("cached-liboqs")
        for mode in modes:
            base = None
            for w in workers:
                med, all_rates, miss = run(alg, heads, items, mode, w,
                                           a.verifications, a.reps)
                base = base or med
                rows.append({
                    "alg": alg, "mode": mode, "workers": w,
                    "publishers": a.publishers, "verifications": a.verifications,
                    "per_s": round(med, 1),
                    "per_s_runs": [round(r, 1) for r in all_rates],
                    "speedup": round(med / base, 3),
                    "efficiency": round(med / base / w, 3),
                    "cache_misses": miss if mode != "uncached" else None,
                })
                print(f"    {mode:14s} workers={w:<3d} {med:10.0f}/s  "
                      f"x{med / base:5.2f}", flush=True)

    write_json("e8_scale.json", rows, extra_env={
        "workers_tested": workers, "quick": a.quick}, notes=[
        "publishers drawn Zipf(1); hierarchy depth 3, x5chain carries leaf and "
        "intermediate, root from the verifier's store; every signature verified",
        "uncached: chain parsed and validated for every manifest",
        "cached: chain validated once per publisher per worker, then signature only",
        "cached-liboqs: as cached, ML-DSA signature checked by liboqs",
        "per_s is the median over reps of verifications / wall time on a warm pool",
    ])


if __name__ == "__main__":
    main()
