#!/usr/bin/env python3
"""E1 caching a validated signer, under signer lifecycles that deployments have.

An earlier version of this experiment composed per-operation costs for one
publisher with one long-lived leaf, which is the case most favourable to a
cache. This one runs a verifier over a stream of manifests and times the
whole stream, with the things that limit a cache in practice:

  publishers   P publishers sharing one root, each with its own issuing CA;
               which publisher signed each manifest is drawn from a Zipf
               distribution, so a few are frequent and most are rare.

  leaves       three lifecycles: one leaf per publisher for the whole stream
               ("long-lived"), a new leaf every ROTATE manifests ("rotating"),
               and a new leaf for every manifest ("per-image"), the pattern of
               signers that issue a fresh certificate per capture.

  cache        a bounded LRU of validated certificates, keyed on the
               certificate's SHA-256. A cached leaf skips both path
               verifications; a cached issuing CA skips the second. Entries
               carry the certificate's notAfter and the trust-list snapshot
               they were validated under.

  trust list   half-way through the stream one publisher's issuing CA is
               removed from trust. A verifier that tags cache entries with the
               trust-list snapshot (C2PA 2.5 adds snapshot identifiers) drops
               them; a naive cache keeps accepting that publisher. Both are
               run, and wrongly accepted manifests are counted.

Every row is the measured wall time of the whole stream through the real
verification code; nothing is composed.
"""

import collections
import hashlib
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import write_json, run_order  # noqa: E402
from pq_cose import (CLAIM, KEYGEN, _cert, _name, cose_sig_input,  # noqa: E402
                     raw_sign, raw_verify)

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

ALGS = ["Ed25519", "ES256", "PS256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
STREAM = int(os.environ.get("LINEA_CACHE_STREAM", "2000"))
PUBLISHERS = 50
ZIPF_S = 1.1
ROTATE = 100
CACHE_SIZES = [0, 16, 256, 4096]
LIFECYCLES = ["long-lived", "rotating", "per-image"]
KEY_POOL = 32


def verify_cert(child, parent_pub):
    if isinstance(parent_pub, ed25519.Ed25519PublicKey):
        parent_pub.verify(child.signature, child.tbs_certificate_bytes)
    elif isinstance(parent_pub, ec.EllipticCurvePublicKey):
        parent_pub.verify(child.signature, child.tbs_certificate_bytes,
                          ec.ECDSA(child.signature_hash_algorithm))
    elif isinstance(parent_pub, rsa.RSAPublicKey):
        parent_pub.verify(child.signature, child.tbs_certificate_bytes,
                          padding.PKCS1v15(), child.signature_hash_algorithm)
    else:
        parent_pub.verify(child.signature, child.tbs_certificate_bytes)


class Verifier:
    """Path validation with an optional LRU cache of validated certificates."""

    def __init__(self, root_cert, capacity, tag_snapshot):
        self.root = root_cert
        self.capacity = capacity
        self.tag = tag_snapshot
        self.cache = collections.OrderedDict()   # key -> (snapshot, not_after)
        self.cache_bytes = 0
        self.sizes = {}
        self.snapshot = 1
        self.distrusted = set()                  # issuing-CA keys removed
        self.hits = collections.Counter()
        self.path_verifications = 0

    def trust_list_update(self, ica_der):
        self.snapshot += 1
        self.distrusted.add(hashlib.sha256(ica_der).digest())

    def _cached(self, key, now):
        e = self.cache.get(key)
        if e is None:
            return False
        snap, not_after = e
        if (self.tag and snap != self.snapshot) or not_after < now:
            self._evict(key)
            return False
        self.cache.move_to_end(key)
        return True

    def _evict(self, key):
        self.cache.pop(key, None)
        self.cache_bytes -= self.sizes.pop(key, 0)

    def _put(self, key, der_len, not_after):
        if self.capacity == 0:
            return
        self.cache[key] = (self.snapshot, not_after)
        self.sizes[key] = der_len
        self.cache_bytes += der_len
        while len(self.cache) > self.capacity:
            old, _ = self.cache.popitem(last=False)
            self.cache_bytes -= self.sizes.pop(old, 0)

    def validate(self, leaf_der, ica_der, now):
        """True if the leaf chains to the root under the current trust list."""
        lk = hashlib.sha256(leaf_der).digest()
        ik = hashlib.sha256(ica_der).digest()
        if self._cached(lk, now):
            self.hits["leaf"] += 1
            return True
        # Distrust is checked on the uncached path, as a trust-list lookup.
        if ik in self.distrusted:
            return False
        leaf = x509.load_der_x509_certificate(leaf_der)
        ica = x509.load_der_x509_certificate(ica_der)
        if self._cached(ik, now):
            self.hits["ica"] += 1
        else:
            verify_cert(ica, self.root.public_key())
            self.path_verifications += 1
            self._put(ik, len(ica_der), ica.not_valid_after_utc)
        verify_cert(leaf, ica.public_key())
        self.path_verifications += 1
        self._put(lk, len(leaf_der), leaf.not_valid_after_utc)
        return True


def build_world(alg, lifecycle, rng):
    h = hashes.SHA256() if alg in ("ES256", "PS256") else None
    rkey = KEYGEN[alg]()
    root = _cert(rkey.public_key(), _name(f"{alg} Root"), rkey,
                 f"{alg} Root", True, h)
    icas = []
    for p in range(PUBLISHERS):
        k = KEYGEN[alg]()
        c = _cert(k.public_key(), root.subject, rkey, f"{alg} Publisher {p} CA",
                  True, h, issuer_pub=rkey.public_key())
        icas.append((k, c, c.public_bytes(ser.Encoding.DER)))

    weights = [1 / (i + 1) ** ZIPF_S for i in range(PUBLISHERS)]
    who = rng.choices(range(PUBLISHERS), weights, k=STREAM)
    seen = collections.Counter()
    leaves = {}
    pool = []
    stream = []
    for i, p in enumerate(who):
        n = seen[p]
        seen[p] += 1
        if lifecycle == "long-lived":
            gen = 0
        elif lifecycle == "rotating":
            gen = n // ROTATE
        else:
            gen = n
        if (p, gen) not in leaves:
            ik, ic, _ = icas[p]
            # Every leaf certificate is distinct (its own name and serial),
            # which is all a cache sees; the keys come from a small pool so
            # that building a per-image stream does not take an hour of RSA
            # key generation. Nothing timed depends on key reuse.
            if len(pool) < KEY_POOL:
                pool.append(KEYGEN[alg]())
            lk = pool[len(leaves) % len(pool)]
            lc = _cert(lk.public_key(), ic.subject, ik,
                       f"{alg} Publisher {p} Signer {gen}", False, h,
                       issuer_pub=ik.public_key())
            leaves[(p, gen)] = (lk, lc.public_bytes(ser.Encoding.DER), lc)
        lk, ld, lc = leaves[(p, gen)]
        msg = cose_sig_input(alg, [ld, icas[p][2], b""], CLAIM + str(i).encode())
        sig = raw_sign(alg, lk, msg)
        stream.append((p, ld, icas[p][2], msg, sig, lc.public_key()))
    return root, icas, stream, len(leaves)


def run(alg, lifecycle, capacity, tag, world):
    root, icas, stream, n_leaves = world
    v = Verifier(root, capacity, tag)
    removed = 0                      # the most frequent publisher
    wrong = rejected = 0
    now = time.time()
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.perf_counter()
    for i, (p, ld, idr, msg, sig, pub) in enumerate(stream):
        if i == len(stream) // 2:
            v.trust_list_update(icas[removed][2])
        ok = v.validate(ld, idr, now)
        if ok:
            raw_verify(alg, pub, sig, msg)
        if i >= len(stream) // 2 and p == removed:
            if ok:
                wrong += 1
            else:
                rejected += 1
    elapsed = (time.perf_counter() - t0) * 1000
    return {
        "alg": alg,
        "lifecycle": lifecycle,
        "cache_entries": capacity,
        "snapshot_tagged": tag,
        "stream": len(stream),
        "publishers": PUBLISHERS,
        "distinct_leaves": n_leaves,
        "total_ms": round(elapsed, 2),
        "per_manifest_ms": round(elapsed / len(stream), 4),
        "path_verifications": v.path_verifications,
        "leaf_hits": v.hits["leaf"],
        "ica_hits": v.hits["ica"],
        "cache_bytes_at_end": v.cache_bytes,
        "accepted_after_distrust": wrong,
        "rejected_after_distrust": rejected,
    }


def main():
    rng = random.Random(int(os.environ.get("LINEA_SEED", "1")))
    results = []
    for alg in run_order(ALGS):
        for lifecycle in LIFECYCLES:
            world = build_world(alg, lifecycle, rng)
            for capacity in CACHE_SIZES:
                for tag in ((True, False) if capacity else (True,)):
                    r = run(alg, lifecycle, capacity, tag, world)
                    results.append(r)
            base = next(r for r in results if r["alg"] == alg and
                        r["lifecycle"] == lifecycle and r["cache_entries"] == 0)
            for r in results:
                if r["alg"] == alg and r["lifecycle"] == lifecycle:
                    r["speedup_vs_no_cache"] = round(
                        base["total_ms"] / r["total_ms"], 2)
            print(f"  {alg} {lifecycle} done")

    write_json("e1_cache.json", results, notes=[
        f"stream of {STREAM} manifests from {PUBLISHERS} publishers (Zipf "
        f"s = {ZIPF_S}) under one root, each publisher with its own issuing CA",
        f"leaf lifecycles: one per publisher, a new one every {ROTATE} "
        "manifests, and a new one per manifest",
        "LRU cache of validated certificates keyed on SHA-256; a cached leaf "
        "skips both path verifications, a cached issuing CA skips one",
        "half-way through, the most frequent publisher's issuing CA is "
        "distrusted; snapshot-tagged caches drop entries validated under the "
        "old trust list, naive ones do not",
        "total_ms is measured over the whole stream, including the manifest "
        "signature verification of every accepted manifest",
    ])


if __name__ == "__main__":
    main()
