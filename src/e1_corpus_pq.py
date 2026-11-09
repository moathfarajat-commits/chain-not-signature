#!/usr/bin/env python3
"""E1 what ML-DSA-65 would add to the production files of the corpus.

The corpus experiment (corpus_inventory.py, e1_corpus.json) records, for every
production-signed file, its size, the size of its manifest store and, for every
signature in it, the signature, each certificate carried in x5chain with its
role, and each RFC 3161 token with the certificates it carries.

This substitutes post-quantum components for the classical ones, signature by
signature, keeping everything else the file carries (claims, assertions,
ingredients, thumbnails, the number of certificates each signer sends):

  manifest signature      sig_bytes            -> ML-DSA-65 signature
  each x5chain certificate actual DER size     -> our ML-DSA-65 certificate of
                                                  the same role (leaf,
                                                  intermediate, root)
  each RFC 3161 token     actual token size    -> our ML-DSA-65 token
                                                  structure plus ML-DSA-65 TSA
                                                  certificates, as many as the
                                                  original token carried

The ML-DSA-65 component sizes are the measured ones of e1_timestamp.json and
e1_carriage.json. Stapled OCSP responses are left as they are, because the
corpus does not record their size, so the figures are a lower bound for the
signatures that carry one.

The output is per file: bytes added, the new manifest store as a multiple of
the old, and the bytes added as a share of the file, which is the denominator
a reader of the paper actually has.
"""

import json
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import write_json  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(rel):
    return json.load(open(os.path.join(ROOT, rel)))


def pq_components():
    ts = [x for x in load("out-o3new/e1_timestamp.json")["results"]
          if x["alg"] == "ML-DSA-65"][0]
    car = load("out-o3new/e1_carriage.json")["results"]
    by = {x["carriage"]: x for x in car if x["alg"] == "ML-DSA-65"}
    root = by["root"]["cert_bytes_carried"] - by["chain"]["cert_bytes_carried"]
    td = ts["timestamp_details"]
    return {
        "sig": ts["sig_bytes"],
        "leaf": ts["breakdown_signature"]["leaf"],
        "intermediate": ts["breakdown_signature"]["intermediate"],
        "root": root or td["tsa_root_bytes_not_carried"],
        "tst_structure": td["structure_bytes"] + td["signature_bytes"],
        "tsa_certs": td["tsa_cert_bytes"] + [td["tsa_root_bytes_not_carried"]],
    }


def pq_token(pq, ncerts):
    certs = pq["tsa_certs"]
    extra = sum(certs[min(i, len(certs) - 1)] for i in range(ncerts))
    return pq["tst_structure"] + extra


def substitute(asset, pq):
    added = 0
    for s in asset["sig"]:
        if s.get("carriage") != "x5chain":
            continue
        added += pq["sig"] - s["sig_bytes"]
        for role, b in zip(s.get("roles", []), s.get("cert_bytes", [])):
            added += pq.get(role, pq["intermediate"]) - b
        for t in s.get("timestamps", []):
            added += pq_token(pq, t.get("tsa_certs", 0)) - t["token_bytes"]
    return added


def q(v, p):
    v = sorted(v)
    k = (len(v) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(v) - 1)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def main():
    pq = pq_components()
    corpus = load("out-reference/e1_corpus.json")["results"]["assets"]
    rows = []
    for a in corpus:
        if a["corpus"] != "production" or not a.get("sig"):
            continue
        add = substitute(a, pq)
        rows.append({
            "file": os.path.basename(a["file"]),
            "generator": a["generator"],
            "format": a["format"],
            "file_bytes": a["file_bytes"],
            "store_bytes": a["store_bytes"],
            "signatures": a["signatures"],
            "added_bytes": add,
            "store_growth": round((a["store_bytes"] + add) / a["store_bytes"], 3),
            "added_pct_of_file": round(100 * add / a["file_bytes"], 3),
        })
    pct = [r["added_pct_of_file"] for r in rows]
    add = [r["added_bytes"] for r in rows]
    fb = [r["file_bytes"] for r in rows]
    gr = [r["store_growth"] for r in rows]
    single = [r for r in rows if r["signatures"] == 1]
    summary = {
        "files": len(rows),
        "signatures": sum(r["signatures"] for r in rows),
        "file_bytes_median": statistics.median(fb),
        "file_bytes_p10": q(fb, 0.10),
        "file_bytes_p90": q(fb, 0.90),
        "added_bytes_median": statistics.median(add),
        "added_bytes_p90": q(add, 0.90),
        "added_bytes_max": max(add),
        "added_pct_median": statistics.median(pct),
        "added_pct_p90": q(pct, 0.90),
        "added_pct_max": max(pct),
        "files_over_1pct": sum(1 for p in pct if p > 1),
        "files_over_10pct": sum(1 for p in pct if p > 10),
        "store_growth_median": statistics.median(gr),
        "single_signature_files": len(single),
        "single_added_bytes_median": statistics.median(r["added_bytes"] for r in single)
        if single else None,
        "pq_components": pq,
    }
    write_json("e1_corpus_pq.json", {"summary": summary, "files": rows}, notes=[
        "ML-DSA-65 components substituted for classical ones in every production "
        "file of the corpus, signature by signature; everything else in the file kept",
        "certificate counts per signer and per timestamp token kept as shipped",
        "stapled OCSP responses not substituted (size not recorded): a lower bound "
        "for the signatures that carry one",
    ])
    print(json.dumps({k: v for k, v in summary.items() if k != "pq_components"}, indent=1))


if __name__ == "__main__":
    main()
