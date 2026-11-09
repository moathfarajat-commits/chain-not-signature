#!/usr/bin/env python3
"""Merge independent runs into one result file per experiment.

run_reps.sh runs the whole suite R times, each run a fresh set of processes
with fresh keys and its own random order of experiments and configurations,
into out-runs/run<k>/. Within a run every timing is a distribution over many
repetitions (time_it); across runs the unit of replication is the run.

For every timing dict (one carrying "median_ms") this writes, into the merged
row:

    median_ms        median of the R per-run medians
    ci95_ms          95% bootstrap interval of that median over runs
    run_medians_ms   the R per-run medians
    p99_ms           median of the per-run p99s
    runs             R

and keeps the first run's other fields (sizes vary by a byte or two with
random serial numbers and DER-encoded ECDSA signatures, and are reported from
one run). Rows are matched across runs by the key fields named below, since
configuration order differs between runs.

usage: aggregate_runs.py out-runs out
"""

import glob
import json
import os
import random
import statistics
import sys

KEYS = {
    "e1_postquantum": ("image", "alg", "chain_depth"),
    "e1_carriage": ("alg", "carriage", "anchor"),
    "e1_verify": ("alg",),
    "e1_timestamp": ("alg",),
    "e1_algsweep": ("alg", "chain_depth"),
    "e1_mixedchain": ("label",),
    "e1_cache": ("alg", "lifecycle", "cache_entries", "snapshot_tagged"),
    "e8_scale": ("alg", "mode", "workers"),
    "e1_extras": ("experiment", "alg", "carriage", "object"),
    "e1_certref": ("alg", "chain_depth"),
    "e1_hash": ("case",),
}
B = 10000


def boot_ci(xs, rng):
    if len(xs) < 2:
        return [xs[0], xs[0]] if xs else None
    meds = sorted(statistics.median(rng.choices(xs, k=len(xs))) for _ in range(B))
    return [round(meds[int(0.025 * B)], 4), round(meds[int(0.975 * B) - 1], 4)]


def key_of(row, fields):
    return json.dumps([row.get(f) for f in fields], sort_keys=True, default=str)


def merge_timing(dicts, rng):
    meds = [d["median_ms"] for d in dicts if isinstance(d, dict) and "median_ms" in d]
    out = dict(dicts[0])
    out["median_ms"] = round(statistics.median(meds), 4)
    out["ci95_ms"] = boot_ci(meds, rng)
    out["run_medians_ms"] = [round(m, 4) for m in meds]
    p99 = [d["p99_ms"] for d in dicts if isinstance(d, dict) and "p99_ms" in d]
    if p99:
        out["p99_ms"] = round(statistics.median(p99), 4)
    if all("mean_ms" in d for d in dicts):
        out["mean_ms"] = round(statistics.median(d["mean_ms"] for d in dicts), 4)
    out["runs"] = len(meds)
    return out


def merge_value(vals, rng):
    """Recursively merge the same field from R runs."""
    first = vals[0]
    if isinstance(first, dict):
        if "median_ms" in first:
            return merge_timing(vals, rng)
        return {k: merge_value([v.get(k) for v in vals if isinstance(v, dict)], rng)
                if all(isinstance(v, dict) and k in v for v in vals) else first[k]
                for k in first}
    return first


def merge_scalar_timings(row, rows, rng):
    """Fields such as per_s, total_ms or *_ms floats that are themselves
    measurements: report the median over runs and a CI beside them."""
    for k, v in list(row.items()):
        if isinstance(v, float) and (k.endswith("_ms") or k in ("per_s",)):
            xs = [r[k] for r in rows if isinstance(r.get(k), (int, float))]
            if len(xs) == len(rows) and len(xs) > 1:
                row[k] = round(statistics.median(xs), 4)
                row[k + "_ci95"] = boot_ci(xs, rng)
                row[k + "_runs"] = [round(x, 4) for x in xs]


def main(src, dst):
    rng = random.Random(1)
    runs = sorted(glob.glob(os.path.join(src, "run*")))
    if not runs:
        sys.exit(f"no runs under {src}")
    names = sorted({os.path.basename(p) for r in runs
                    for p in glob.glob(os.path.join(r, "*.json"))})
    os.makedirs(dst, exist_ok=True)
    for name in names:
        docs = [json.load(open(os.path.join(r, name)))
                for r in runs if os.path.exists(os.path.join(r, name))]
        exp = name[:-5]
        fields = KEYS.get(exp)
        base = docs[0]
        if fields:
            index = [{key_of(row, fields): row for row in d["results"]} for d in docs]
            merged = []
            for row in base["results"]:
                k = key_of(row, fields)
                rows = [ix[k] for ix in index if k in ix]
                m = {f: merge_value([r.get(f) for r in rows], rng)
                     if all(f in r for r in rows) else row[f] for f in row}
                merge_scalar_timings(m, rows, rng)
                merged.append(m)
        else:
            merged = base["results"]
        doc = dict(base)
        doc["results"] = merged
        doc["env"] = dict(base["env"], runs=len(docs),
                          run_timestamps=[d["env"].get("timestamp_utc") for d in docs])
        doc["notes"] = list(base.get("notes", [])) + [
            f"merged from {len(docs)} independent runs (fresh processes and "
            "keys, random experiment and configuration order); median_ms is "
            "the median of per-run medians, ci95_ms a 95% bootstrap interval "
            "over runs" if fields else
            f"{len(docs)} runs available; first run reported (no timing merge)"]
        with open(os.path.join(dst, name), "w") as f:
            json.dump(doc, f, indent=2)
        print(f"  {name}: {len(docs)} runs, {len(merged)} rows")


if __name__ == "__main__":
    main(*sys.argv[1:3])
