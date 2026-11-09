#!/usr/bin/env python3
"""Machine-readable inventory of the production corpus, one row per signature.

Joins out-reference/e1_corpus.json with the harvest's sources.csv (source and
page URL, licence, download date) and a SHA-256 of every file, and writes
data/corpus/inventory.csv and data/corpus/chains.csv.

    python3 src/corpus_inventory.py SOURCES.csv HASHES.csv

Identity rules, as the paper states them:
  * A chain is identified by chain_fingerprint: SHA-256 over the leaf's issuer
    name and the DER of every certificate after the leaf. Leaves issued per
    image under one issuing CA are therefore one chain.
  * Every signature in a file's manifest store counts, the active manifest's
    and its ingredients', and is attributed to the file's generator group.
    A chain carried in the files of several groups is listed under each, and
    counted once in the distinct totals.
E-mail addresses in certificate names are replaced by "[e-mail address]".
"""
import csv
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from make_tables_v2 import _group  # noqa: E402

EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def scrub(s):
    return EMAIL.sub("[e-mail address]", s or "")


def main(sources, hashes):
    d = json.load(open(os.path.join(ROOT, "out-reference", "e1_corpus.json")))
    src = {r["file"]: r for r in csv.DictReader(open(sources))}
    hsh = {r["file"]: r for r in csv.DictReader(open(hashes))}
    out = os.path.join(ROOT, "data", "corpus")
    os.makedirs(out, exist_ok=True)
    rows, chains = [], {}
    for a in d["results"]["assets"]:
        if a["corpus"] != "production":
            continue
        f = a["file"]
        s, h = src.get(f, {}), hsh.get(f, {})
        g = _group(a["corpus"], a["generator"])
        for i, x in enumerate(a["sig"]):
            fp = x.get("chain_fingerprint") or ""
            rows.append({
                "file": f, "sha256": h.get("sha256", ""), "bytes": a["file_bytes"],
                "group": g, "generator": a["generator"],
                "source_url": s.get("source_url", ""), "page_url": s.get("page_url", ""),
                "license_or_terms": s.get("license_or_terms", ""),
                "download_date": s.get("download_date", ""),
                "claim_version": a["claim_version"], "signature_index": i,
                "signatures_in_store": a["signatures"], "alg": x["alg"],
                "carriage": x.get("carriage"), "certs_transmitted": x.get("certs_transmitted"),
                "root_transmitted": x.get("root_transmitted"),
                "chain_fingerprint": fp, "chain_bytes": x.get("chain_bytes"),
                "anchor_on_c2pa_list": x.get("anchor_on_c2pa_list"),
                "anchor_is_leaf_issuer": x.get("anchor_is_leaf_issuer"),
                "timestamped": bool(x.get("timestamps")), "has_ocsp": x.get("has_ocsp"),
                "x5chain_label": x.get("x5chain_label"), "x5chain_bucket": x.get("x5chain_bucket"),
            })
            if fp:
                c = chains.setdefault(fp, {
                    "chain_fingerprint": fp, "alg": x["alg"],
                    "certificates_cn": " | ".join(scrub(n) for n in x.get("subject_cns", [])),
                    "certs_transmitted": x.get("certs_transmitted"),
                    "root_transmitted": x.get("root_transmitted"),
                    "anchor_on_c2pa_list": x.get("anchor_on_c2pa_list"),
                    "anchor_is_leaf_issuer": x.get("anchor_is_leaf_issuer"),
                    "groups": set(), "files": set(), "signatures": 0})
                c["groups"].add(g)
                c["files"].add(f)
                c["signatures"] += 1
    with open(os.path.join(out, "inventory.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(out, "chains.csv"), "w", newline="") as fh:
        cols = ["chain_fingerprint", "alg", "certificates_cn", "certs_transmitted",
                "root_transmitted", "anchor_on_c2pa_list", "anchor_is_leaf_issuer",
                "groups", "files", "signatures"]
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for c in sorted(chains.values(), key=lambda c: (-c["signatures"], c["chain_fingerprint"])):
            c = dict(c, groups="; ".join(sorted(c["groups"])), files=len(c["files"]))
            w.writerow(c)
    print(f"  {len(rows)} signatures, {len(chains)} distinct chains -> data/corpus/")


if __name__ == "__main__":
    main(*sys.argv[1:3])
