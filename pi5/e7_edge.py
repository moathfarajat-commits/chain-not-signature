#!/usr/bin/env python3
"""E7: an edge verifier with its trust store on an SD card.

A verifier that receives a thumbprint instead of a certificate chain must find
the chain itself. On the M1 the trust store sat on NVMe and the "cold" lookup
in e1_verify.py was in fact served from the page cache. Here the store lives
on the Pi's microSD card, and the cold pass is cold: every store file is
evicted from the page cache before it is read.

For each algorithm the script writes a store of --signers chains (depth 3),
one file per leaf thumbprint, and one referenced manifest per signer. It then
verifies every manifest end to end, in a shuffled order:

    decode COSE -> look up the chain by thumbprint (open, read, CBOR)
    -> parse the certificates -> validate the chain -> verify the signature

once cold and once warm, and once more from embedded manifests that carry
their own chain, which needs no lookup at all.

All verification goes through `cryptography` (OpenSSL 4.0.2, -O3), because
chain validation can only go there and a signature must verify against the
key in the certificate it came with.

Eviction: posix_fadvise(DONTNEED) on every store file, which needs no root;
with root (or passwordless sudo) the script also drops the whole page cache.
"""

import argparse
import hashlib
import json
import os
import random
import shutil
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "src"))
sys.path.insert(0, HERE)

import cbor2  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import pi_telemetry as tel  # noqa: E402
from common import write_json  # noqa: E402
from pq_cose import (CLAIM, build_chain, sign_cose,  # noqa: E402
                     sign_cose_certref)

DEPTH = 3


def storage_info(path):
    """Which device the store is on, so the paper can name the card."""
    info = {"path": os.path.abspath(path)}
    try:
        src = subprocess.run(["findmnt", "-no", "SOURCE", "--target", path],
                             capture_output=True, text=True).stdout.strip()
        info["mount_source"] = src
        dev = os.path.basename(src)
        parent = subprocess.run(["lsblk", "-no", "PKNAME", src],
                                capture_output=True, text=True).stdout.strip() or dev
        info["block_device"] = parent
        base = f"/sys/block/{parent}/device"
        for k in ("name", "manfid", "oemid", "date", "model", "type"):
            try:
                with open(os.path.join(base, k)) as f:
                    info[k] = f.read().strip()
            except Exception:
                pass
        info["fs"] = subprocess.run(["findmnt", "-no", "FSTYPE", "--target", path],
                                    capture_output=True, text=True).stdout.strip()
    except Exception as e:
        info["error"] = str(e)
    return info


def drop_all_caches():
    """Drop the whole page cache if we may. Returns how, or None."""
    cmd = "sync; echo 3 > /proc/sys/vm/drop_caches"
    if os.geteuid() == 0:
        r = subprocess.run(["sh", "-c", cmd])
        return "root" if r.returncode == 0 else None
    if shutil.which("sudo"):
        r = subprocess.run(["sudo", "-n", "sh", "-c", cmd],
                           capture_output=True)
        if r.returncode == 0:
            return "sudo"
    return None


def evict(paths):
    for p in paths:
        fd = os.open(p, os.O_RDONLY)
        try:
            os.fsync(fd)
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        finally:
            os.close(fd)
    return drop_all_caches() or "fadvise"


def resident_fraction(paths):
    """Share of store pages still in memory, via util-linux fincore, or None."""
    if not shutil.which("fincore"):
        return None
    try:
        out = subprocess.run(["fincore", "-nbo", "RES,SIZE", *paths[:200]],
                             capture_output=True, text=True).stdout.split()
        nums = list(map(int, out))
        res, size = sum(nums[0::2]), sum(nums[1::2])
        return round(res / size, 4) if size else None
    except Exception:
        return None


def verify_sig(pub, alg, sig, msg):
    from pq_cose import raw_verify
    raw_verify(alg, pub, sig, msg)


def validate(certs):
    for child, parent in zip(certs, certs[1:]):
        pub = parent.public_key()
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       ec.ECDSA(child.signature_hash_algorithm))
        elif hasattr(pub, "key_size"):      # RSA
            from cryptography.hazmat.primitives.asymmetric import padding
            pub.verify(child.signature, child.tbs_certificate_bytes,
                       padding.PKCS1v15(), child.signature_hash_algorithm)
        else:
            pub.verify(child.signature, child.tbs_certificate_bytes)


ANCHOR = {}      # the root, held in memory as a trust anchor, by thumbprint


def verify_one(alg, blob, store_dir, embedded):
    """Verify one manifest end to end. Returns per-step seconds.

    x5chain and the store both hold leaf and intermediate; the root is the
    verifier's trust anchor, loaded once and kept in memory."""
    t0 = time.perf_counter()
    tagged = cbor2.loads(blob)
    prot_bstr, _u, _p, sig = tagged.value
    prot = cbor2.loads(prot_bstr)
    t1 = time.perf_counter()
    if embedded:
        der = prot[33] if isinstance(prot[33], list) else [prot[33]]
    else:
        thumb = prot[34][1].hex()
        with open(os.path.join(store_dir, thumb + ".chain"), "rb") as f:
            der = cbor2.loads(f.read())
    t2 = time.perf_counter()
    certs = [x509.load_der_x509_certificate(d) for d in der]
    t3 = time.perf_counter()
    validate(certs + [ANCHOR[hashlib.sha256(der[0]).hexdigest()]])
    t4 = time.perf_counter()
    tbs = cbor2.dumps(["Signature1", prot_bstr, b"", CLAIM])
    verify_sig(certs[0].public_key(), alg, sig, tbs)
    t5 = time.perf_counter()
    return {"decode": t1 - t0, "lookup": t2 - t1, "parse": t3 - t2,
            "validate": t4 - t3, "verify": t5 - t4, "total": t5 - t0}


def stats(rows):
    out = {}
    for k in rows[0]:
        v = sorted(r[k] * 1000 for r in rows)
        out[k] = {"median_ms": round(statistics.median(v), 4),
                  "mean_ms": round(statistics.fmean(v), 4),
                  "p95_ms": round(v[min(int(0.95 * len(v)), len(v) - 1)], 4)}
    return out


def run_alg(alg, n, store_root, seed):
    store = os.path.join(store_root, alg)
    shutil.rmtree(store, ignore_errors=True)
    os.makedirs(store)
    print(f"  {alg}: building {n} signers", flush=True)
    refs, embs, paths = [], [], []
    for _ in range(n):
        key, chain = build_chain(alg, DEPTH)
        thumb = hashlib.sha256(chain[0]).hexdigest()
        p = os.path.join(store, thumb + ".chain")
        with open(p, "wb") as f:
            f.write(cbor2.dumps(chain[:-1]))
        ANCHOR[thumb] = x509.load_der_x509_certificate(chain[-1])
        paths.append(p)
        refs.append(sign_cose_certref(alg, key, chain, CLAIM)[0])
        embs.append(sign_cose(alg, key, chain, CLAIM)[0])
    os.sync()

    order = list(range(n))
    random.Random(seed).shuffle(order)

    how = evict(paths)
    resident = resident_fraction(paths)
    cold = [verify_one(alg, refs[i], store, False) for i in order]
    warm = [verify_one(alg, refs[i], store, False) for i in order]
    emb = [verify_one(alg, embs[i], store, True) for i in order]

    row = {
        "alg": alg, "signers": n, "chain_depth": DEPTH,
        "eviction": how, "resident_before_cold": resident,
        "store_bytes": sum(os.path.getsize(p) for p in paths),
        "cold": stats(cold), "warm": stats(warm), "embedded": stats(emb),
    }
    shutil.rmtree(store, ignore_errors=True)
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--signers", type=int, default=500)
    ap.add_argument("--algs", default="Ed25519,ES256,PS256,ML-DSA-44,ML-DSA-65,ML-DSA-87")
    ap.add_argument("--store", default=os.path.join(os.path.expanduser("~"),
                                                    "line-a-pi", "trust-store"),
                    help="directory on the medium under test (SD card by default)")
    ap.add_argument("--seed", type=int, default=20261014)
    a = ap.parse_args()
    if a.quick:
        a.signers, a.algs = 20, "Ed25519,ML-DSA-65"

    os.makedirs(a.store, exist_ok=True)
    core = tel.pin_to_core()
    sinfo = storage_info(a.store)
    print(f"  store on {sinfo.get('mount_source')} ({sinfo.get('name') or sinfo.get('model') or '?'})")
    rows = [run_alg(alg, a.signers, a.store, a.seed) for alg in a.algs.split(",")]
    for r in rows:
        print(f"  {r['alg']:10s} cold {r['cold']['total']['median_ms']:.3f} ms, "
              f"warm {r['warm']['total']['median_ms']:.3f} ms, "
              f"embedded {r['embedded']['total']['median_ms']:.3f} ms "
              f"(eviction: {r['eviction']})")
    write_json("e7_edge.json", rows, extra_env={
        "pi": tel.static_env(), "storage": sinfo, "pinned_core": core,
        "quick": a.quick}, notes=[
        "end-to-end verification through cryptography/OpenSSL; liboqs is not used here",
        "x5chain and the store hold leaf and intermediate; the root is a trust "
        "anchor held in memory",
        "cold: store files evicted (fadvise DONTNEED, plus drop_caches when permitted)",
        "resident_before_cold is from fincore when available; 0 means fully evicted",
        "manifests verified in a fixed shuffled order, the same for every pass",
    ])


if __name__ == "__main__":
    main()
