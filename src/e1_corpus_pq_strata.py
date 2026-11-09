#!/usr/bin/env python3
"""E1 the ML-DSA-65 substitution of e1_corpus_pq.py, broken down and bounded.

Reads e1_corpus.json (per-signature OCSP flags, generators) and
e1_corpus_pq.json (bytes added per file) and reports:

  * an upper bound with post-quantum revocation evidence: every signature that
    staples OCSP gains a full ML-DSA-65 delegated response (the form the
    reference implementation honours), with nothing subtracted for the
    classical response it replaces, whose size the corpus does not record;
  * the growth by signer group (the groups of the corpus table), by file size
    and by number of signatures in the file;
  * the per-file values behind the distribution figure in the supplement.

Percentages are bytes added over the original file size.
"""

import json
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import write_json  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GROUPS = [
    ("Google", ("google_",)),
    ("OpenAI", ("openai",)),
    ("Microsoft", ("microsoft",)),
    ("Adobe", ("adobe",)),
    ("News publishers", ("news_",)),
    ("Other", ("cloudflare", "leica", "vivo", "trustmycontent")),
]
SIZE_BANDS = [("under 500 kB", 0, 500_000), ("500 kB to 5 MB", 500_000, 5_000_000),
              ("over 5 MB", 5_000_000, float("inf"))]
SIG_BANDS = [("1", 1, 1), ("2", 2, 2), ("3 or more", 3, 10**9)]


def load(rel):
    return json.load(open(os.path.join(ROOT, rel)))


def group(gen):
    for name, prefixes in GROUPS:
        if gen.startswith(prefixes):
            return name
    return "Other"


def q(v, p):
    v = sorted(v)
    k = (len(v) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(v) - 1)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def stats(rows, key_add, key_pct):
    add = [r[key_add] for r in rows]
    pct = [r[key_pct] for r in rows]
    return {
        "files": len(rows),
        "file_bytes_median": statistics.median(r["file_bytes"] for r in rows),
        "added_bytes_median": statistics.median(add),
        "added_pct_median": statistics.median(pct),
        "added_pct_p90": q(pct, 0.90),
        "files_over_10pct": sum(1 for p in pct if p > 10),
    }


def main():
    pq = load("out-reference/e1_corpus_pq.json")["results"]["files"]
    corpus = [a for a in load("out-reference/e1_corpus.json")["results"]["assets"]
              if a["corpus"] == "production" and a.get("sig")]
    ts = [x for x in load("out-o3new/e1_timestamp.json")["results"]
          if x["alg"] == "ML-DSA-65"][0]
    ocsp_pq = ts["ocsp"]["delegated"]["bytes"]
    by_file = {}
    for a in corpus:
        by_file.setdefault(os.path.basename(a["file"]), []).append(a)
    rows = []
    for r in pq:
        a = by_file[r["file"]].pop(0)
        n_ocsp = sum(1 for s in a["sig"]
                     if s.get("carriage") == "x5chain" and s.get("has_ocsp"))
        hi = r["added_bytes"] + n_ocsp * ocsp_pq
        rows.append({**r, "group": group(r["generator"]), "ocsp_signatures": n_ocsp,
                     "added_bytes_ocsp_bound": hi,
                     "added_pct_ocsp_bound": round(100 * hi / r["file_bytes"], 3)})
    with_ocsp = [r for r in rows if r["ocsp_signatures"]]
    out = {
        "ocsp_delegated_bytes": ocsp_pq,
        "files_with_ocsp": len(with_ocsp),
        "signatures_with_ocsp": sum(r["ocsp_signatures"] for r in rows),
        "all": {"substituted": stats(rows, "added_bytes", "added_pct_of_file"),
                "ocsp_bound": stats(rows, "added_bytes_ocsp_bound", "added_pct_ocsp_bound")},
        "ocsp_files": {"substituted": stats(with_ocsp, "added_bytes", "added_pct_of_file"),
                       "ocsp_bound": stats(with_ocsp, "added_bytes_ocsp_bound",
                                           "added_pct_ocsp_bound")},
        "by_group": {}, "by_size": {}, "by_signatures": {},
    }
    for name, _ in GROUPS:
        sel = [r for r in rows if r["group"] == name]
        if sel:
            out["by_group"][name] = stats(sel, "added_bytes", "added_pct_of_file")
    for name, lo, hi in SIZE_BANDS:
        sel = [r for r in rows if lo <= r["file_bytes"] < hi]
        if sel:
            out["by_size"][name] = stats(sel, "added_bytes", "added_pct_of_file")
    for name, lo, hi in SIG_BANDS:
        sel = [r for r in rows if lo <= r["signatures"] <= hi]
        if sel:
            out["by_signatures"][name] = stats(sel, "added_bytes", "added_pct_of_file")
    out["files"] = [{k: r[k] for k in ("file", "group", "file_bytes", "signatures",
                                       "ocsp_signatures", "added_bytes",
                                       "added_pct_of_file", "added_bytes_ocsp_bound",
                                       "added_pct_ocsp_bound")} for r in rows]
    write_json("e1_corpus_pq_strata.json", out, notes=[
        "percentages are bytes added over the original file size",
        "ocsp_bound adds a full ML-DSA-65 delegated OCSP response for every stapled "
        "response and subtracts nothing for the classical one it replaces: an upper "
        "bound on the revocation evidence's contribution",
    ])
    print(json.dumps({k: v for k, v in out.items() if k != "files"}, indent=1))


if __name__ == "__main__":
    main()
