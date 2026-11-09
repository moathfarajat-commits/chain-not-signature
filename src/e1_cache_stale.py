#!/usr/bin/env python3
"""E1 stale trust in a verifier's cache when the trust list does not change.

e1_cache.py shows that a cache must be tied to the trust-list snapshot its
entries were validated under. A snapshot tag does not cover the other ways a
cached validation goes stale while the trust list stays the same. This runs a
verifier over a 30-day stream of manifests on a simulated clock, with the
trust list unchanged throughout, and two events on the most frequent
publisher, separately:

  expiry       its signing certificate's notAfter falls on day 15;
  revocation   its signing certificate is revoked on day 15, and the
               revocation is visible in OCSP responses issued from then on,
               each valid for OCSP_VALID_DAYS (thisUpdate to nextUpdate).

Three cache designs:

  naive        key: the certificate's SHA-256; an entry lives until evicted.
  expiry       as naive, and an entry is dropped once the clock passes the
               notAfter of any certificate on its path.
  bounded      key: (certificate SHA-256, trust-list snapshot, validation
               policy); an entry is valid only while the clock is inside
               every path certificate's validity AND before the nextUpdate
               of the revocation status it was validated with; a stale entry
               is revalidated, fetching current status.

Signatures and certificate paths are verified for real (ES256 and ML-DSA-65);
what is counted is how many of the publisher's manifests are accepted after
the event, and how long after it the last one was accepted. An uncached
verifier that relies on stapled or fetched OCSP has the same revocation
window as the bounded cache, since it too trusts a response until nextUpdate.
"""

import collections
import datetime
import hashlib
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import write_json  # noqa: E402
from pq_cose import CLAIM, KEYGEN, _cert, _name, cose_sig_input, raw_sign, raw_verify  # noqa: E402
from e1_cache import verify_cert  # noqa: E402

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as ser

ALGS = ["ES256", "ML-DSA-65"]
STREAM = 2000
PUBLISHERS = 50
ZIPF_S = 1.1
DAYS = 30
EVENT_DAY = 15
OCSP_VALID_DAYS = [1, 7]
DESIGNS = ["naive", "expiry", "bounded"]
POLICY = "c2pa-claimSigning"


class Cache:
    def __init__(self, design, root, ocsp_valid):
        self.design = design
        self.root = root
        self.ocsp_valid = ocsp_valid
        self.entries = {}
        self.snapshot = 1
        self.path_verifications = 0
        self.status_fetches = 0

    def key(self, der):
        h = hashlib.sha256(der).digest()
        return (h, self.snapshot, POLICY) if self.design == "bounded" else h

    def status(self, revoked, now, revoke_at):
        """An OCSP response fetched now: (good?, nextUpdate)."""
        self.status_fetches += 1
        good = not (revoked and now >= revoke_at)
        return good, now + datetime.timedelta(days=self.ocsp_valid)

    def validate(self, leaf, ica, leaf_der, now, revoked, revoke_at):
        k = self.key(leaf_der)
        e = self.entries.get(k)
        if e is not None:
            not_after, next_update = e
            fresh = True
            if self.design in ("expiry", "bounded") and now > not_after:
                fresh = False
            if self.design == "bounded" and now >= next_update:
                fresh = False
            if fresh:
                return True
            del self.entries[k]
        # Uncached: check validity period, path and current status.
        if not (leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc):
            return False
        verify_cert(ica, self.root.public_key())
        verify_cert(leaf, ica.public_key())
        self.path_verifications += 2
        good, next_update = self.status(revoked, now, revoke_at)
        if not good:
            return False
        not_after = min(leaf.not_valid_after_utc, ica.not_valid_after_utc)
        self.entries[k] = (not_after, next_update)
        return True


def world(alg, event, rng):
    h = hashes.SHA256() if alg == "ES256" else None
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    rk = KEYGEN[alg]()
    root = _cert(rk.public_key(), _name(f"{alg} Root"), rk, f"{alg} Root", True, h,
                 now=start - datetime.timedelta(days=365))
    pubs = []
    for p in range(PUBLISHERS):
        ik = KEYGEN[alg]()
        ic = _cert(ik.public_key(), root.subject, rk, f"{alg} Publisher {p} CA", True, h,
                   issuer_pub=rk.public_key(), now=start - datetime.timedelta(days=365))
        lk = KEYGEN[alg]()
        # The event publisher's leaf, under "expiry", lapses on EVENT_DAY:
        # issued 1825 days before that (the profile's lifetime).
        if p == 0 and event == "expiry":
            nb = start + datetime.timedelta(days=EVENT_DAY) - datetime.timedelta(days=1825)
        else:
            nb = start - datetime.timedelta(days=30)
        lc = _cert(lk.public_key(), ic.subject, ik, f"{alg} Publisher {p} Signer", False, h,
                   issuer_pub=ik.public_key(), now=nb)
        pubs.append((lk, lc, lc.public_bytes(ser.Encoding.DER), ic,
                     ic.public_bytes(ser.Encoding.DER)))
    weights = [1 / (i + 1) ** ZIPF_S for i in range(PUBLISHERS)]
    who = rng.choices(range(PUBLISHERS), weights, k=STREAM)
    step = datetime.timedelta(days=DAYS) / STREAM
    stream = []
    for i, p in enumerate(who):
        lk, lc, ld, ic, idr = pubs[p]
        msg = cose_sig_input(alg, [ld, idr, b""], CLAIM + str(i).encode())
        stream.append((start + i * step, p, msg, raw_sign(alg, lk, msg)))
    return root, pubs, stream, start


def run(alg, event, design, ocsp_valid, w):
    root, pubs, stream, start = w
    event_at = start + datetime.timedelta(days=EVENT_DAY)
    c = Cache(design, root, ocsp_valid)
    after_ok = after_bad = 0
    last_ok = None
    for now, p, msg, sig in stream:
        lk, lc, ld, ic, idr = pubs[p]
        ok = c.validate(lc, ic, ld, now, revoked=(event == "revocation" and p == 0),
                        revoke_at=event_at)
        if ok:
            raw_verify(alg, lc.public_key(), sig, msg)
        if p == 0 and now >= event_at:
            if ok:
                after_ok += 1
                last_ok = now
            else:
                after_bad += 1
    return {
        "alg": alg, "event": event, "design": design,
        "ocsp_valid_days": ocsp_valid if design == "bounded" or event == "revocation" else None,
        "stream": STREAM, "days": DAYS, "event_day": EVENT_DAY,
        "accepted_after_event": after_ok, "rejected_after_event": after_bad,
        "last_accept_hours_after_event": (round((last_ok - event_at).total_seconds() / 3600, 1)
                                          if last_ok else None),
        "path_verifications": c.path_verifications, "status_fetches": c.status_fetches,
    }


def main():
    rng = random.Random(int(os.environ.get("LINEA_SEED", "1")))
    rows = []
    for alg in ALGS:
        for event in ("expiry", "revocation"):
            w = world(alg, event, rng)
            for design in DESIGNS:
                for ov in (OCSP_VALID_DAYS if design == "bounded" else [OCSP_VALID_DAYS[-1]]):
                    rows.append(run(alg, event, design, ov, w))
            print(f"  {alg} {event} done", flush=True)
    write_json("e1_cache_stale.json", rows, notes=[
        f"{STREAM} manifests over {DAYS} simulated days from {PUBLISHERS} publishers "
        f"(Zipf s = {ZIPF_S}); the trust list never changes",
        f"event on the most frequent publisher on day {EVENT_DAY}: its leaf expires, or "
        "is revoked (visible in OCSP responses issued from then on)",
        "naive: key = certificate hash, no expiry; expiry: drops an entry past any path "
        "certificate's notAfter; bounded: key = (certificate hash, trust-list snapshot, "
        "policy), valid only inside the path's validity and before the nextUpdate of the "
        "revocation status it was validated with",
        "signatures and paths verified for real; accepted_after_event counts the event "
        "publisher's manifests accepted after the event",
    ])


if __name__ == "__main__":
    main()
