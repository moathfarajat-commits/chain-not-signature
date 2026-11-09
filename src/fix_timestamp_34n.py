#!/usr/bin/env python3
"""One-off correction of e1_timestamp.json files measured before 34n.

Two changes, both made in src/e1_timestamp.py for future runs:
  1. The signature-only manifest used a fixed 120 B for COSE wrapping; the
     real figure, from e1_postquantum.json in the same folder (cose_bytes -
     sig_bytes - chain_der_bytes at depth 3), is about 21-23 B. Every size
     derived from it is shifted by the difference.
  2. manifest_full_bytes now staples the delegated responder's OCSP
     response, the form C2PA 2.5 and c2pa-rs accept; the CA-signed form is
     kept as manifest_full_ca_signed_bytes.

    python3 src/fix_timestamp_34n.py out-o3new out-x86
"""
import json
import os
import sys


def fix(folder):
    p = os.path.join(folder, "e1_timestamp.json")
    q = os.path.join(folder, "e1_postquantum.json")
    d, pq = json.load(open(p)), json.load(open(q))
    if any("cose_wrap_corrected" in n for n in d.get("notes", [])):
        print(f"  {p}: already corrected")
        return
    for r in d["results"]:
        o = next(x for x in pq["results"] if x["alg"] == r["alg"]
                 and x.get("chain_depth") == 3)
        wrap = o["cose_bytes"] - o["sig_bytes"] - o["chain_der_bytes"]
        old_wrap = r["breakdown_signature"]["cose_and_jumbf"] - o["jumbf_overhead_bytes"]
        delta = old_wrap - wrap
        r["breakdown_signature"]["cose_and_jumbf"] -= delta
        for k in ("manifest_signature_only_bytes", "manifest_signed_and_timestamped_bytes",
                  "manifest_full_bytes", "manifest_full_delegated_bytes"):
            if k in r:
                r[k] -= delta
        if "manifest_full_bytes" in r:
            r["manifest_full_ca_signed_bytes"] = r["manifest_full_bytes"]
        if "manifest_full_delegated_bytes" in r:
            r["manifest_full_bytes"] = r["manifest_full_delegated_bytes"]
        sig = r["manifest_signature_only_bytes"]
        if "manifest_full_bytes" in r:
            r["growth_vs_signature_only"] = round(r["manifest_full_bytes"] / sig, 2)
        if "pct_signature_only" in r:
            img = 100 * (sig + delta) / r["pct_signature_only"]
            r["pct_signature_only"] = round(100 * sig / img, 2)
            r["pct_timestamped"] = round(100 * r["manifest_signed_and_timestamped_bytes"] / img, 2)
            if "manifest_full_bytes" in r:
                r["pct_full"] = round(100 * r["manifest_full_bytes"] / img, 2)
    d.setdefault("notes", []).append(
        "cose_wrap_corrected (34n): COSE wrapping taken from e1_postquantum instead of "
        "a fixed 120 B; manifest_full_bytes now uses the delegated OCSP response "
        "(src/fix_timestamp_34n.py)")
    json.dump(d, open(p, "w"), indent=2)
    print(f"  {p}: corrected")


if __name__ == "__main__":
    for f in sys.argv[1:]:
        fix(f)
