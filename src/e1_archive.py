#!/usr/bin/env python3
"""
What it costs to re-sign an archive, and a model that predicts it.

Every other experiment here measures one object. An operator does not migrate
one object. A hospital's imaging store, a broadcaster's tape library, a
ministry's surveillance retention: these hold millions of assets signed under
ECDSA, and a migration means re-signing all of them before those signatures
stop being worth anything. The question asked in that room is not how many
bytes a manifest grows by. It is how many machines, for how long.

The model has two terms and no free parameters.

Per asset, the work splits into a part that scales with the file and a part
that does not. Hashing the bytes for the hard binding scales. Building the
claim, signing it and assembling the manifest does not. So

    t(s) = a + s / h

with s the file size, h the hash throughput and a the fixed cost.

Both a and h are measured directly and separately: h by timing the hash alone
across the corpus, a by timing a signature over a digest that is already in
hand. Neither is fitted to the data the model is then tested on. That matters,
because an earlier version of this experiment fitted a and h jointly by least
squares and the fit failed: signature timing through OpenSSL varies by more
than the whole size-dependent term at a hundred kilobytes, so the regression
absorbed signing noise into the slope and reported a hash running eight times
slower for ML-DSA-87 than for ECDSA, which is impossible, since it is the same
hash. Measuring the terms apart and then testing whether they add is a real
test. Fitting both and reporting the residual was not.

The held-out check therefore asks the only question worth asking of this model:
do the two costs add, or does something else happen when they run together.
"""

import glob
import hashlib
import json
import multiprocessing as mp
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cbor2

from common import time_it, write_json
from pq_cose import (COSE_ALG, HDR_ALG, HDR_X5CHAIN, build_chain,
                     liboqs_signer, sign_cose)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGES = sorted(glob.glob(os.path.join(ROOT, "images", "*.jpg")))

ALGS = ["ES256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
CHAIN_DEPTH = 3
TRIALS = 200

# Sizes used for the projection, in bytes, with what each stands for.
PROFILES = [
    ("thumbnail", 8 * 1024),
    ("web image", 100 * 1024),
    ("camera JPEG", 4 * 1024 * 1024),
    ("raw capture", 25 * 1024 * 1024),
    ("radiology series", 150 * 1024 * 1024),
]

DUMMY_DIGEST = bytes(32)


def claim_for(digest):
    return json.dumps({
        "claim_generator_info": [{"name": "line-a-archive", "version": "0.1"}],
        "assertions": [
            {"url": "self#jumbf=c2pa.assertions/c2pa.hash.data",
             "hash": digest.hex()},
        ],
        "signature": "self#jumbf=c2pa.signature",
        "alg": "sha256",
    }).encode()


def sign_prehashed(digest, alg, key, chain):
    """Everything a claim generator does once the asset digest is in hand."""
    cose, _ = sign_cose(alg, key, chain, claim_for(digest))
    return len(cose)


def sign_one(payload, alg, key, chain):
    """The whole per-asset job: hash the asset, then sign a manifest over it."""
    return sign_prehashed(hashlib.sha256(payload).digest(), alg, key, chain)


def sign_prehashed_oqs(digest, alg, chain, signer):
    """The same work with the signature taken from liboqs instead of OpenSSL."""
    protected = {HDR_ALG: COSE_ALG[alg], HDR_X5CHAIN: chain[:-1]}
    protected_bstr = cbor2.dumps(protected)
    sig = signer(cbor2.dumps(
        ["Signature1", protected_bstr, b"", claim_for(digest)]))
    return len(cbor2.dumps(
        cbor2.CBORTag(18, [protected_bstr, {}, None, sig])))


# --- batch, across worker processes ----------------------------------------

_W = {}


def _init_worker(alg, payloads):
    key, chain = build_chain(alg, CHAIN_DEPTH)
    _W["alg"], _W["key"], _W["chain"] = alg, key, chain
    _W["payloads"] = payloads


def _work(index):
    p = _W["payloads"][index % len(_W["payloads"])]
    return sign_one(p, _W["alg"], _W["key"], _W["chain"])


def batch_wall_time(alg, payloads, n_assets, workers):
    """Wall-clock seconds to sign `n_assets` across `workers` processes.

    What crosses the process boundary is an index, not an asset. An earlier
    version mapped the image bytes themselves and measured pickling: a 51~MB
    batch came back 35 to 85 per cent slower than the model with no CPU
    contention to explain it, and the gap grew with the worker count, which is
    the signature of a serialisation bottleneck rather than of scaling. The
    corpus is handed to each worker once, in the initializer, along with its
    credential. The timed region is then exactly what the model describes:
    hash and sign, nothing else.

    Storage is therefore outside both the model and this measurement. A real
    archive reads each asset from disk once, and that cost adds to what is
    reported here.
    """
    ctx = mp.get_context("fork" if hasattr(os, "fork") else "spawn")
    with ctx.Pool(workers, initializer=_init_worker,
                  initargs=(alg, payloads)) as pool:
        pool.map(_work, range(max(8, workers)))            # warm the workers
        t0 = time.perf_counter()
        pool.map(_work, range(n_assets),
                 chunksize=max(1, n_assets // (workers * 8)))
        return time.perf_counter() - t0


def main():
    if not IMAGES:
        print("no images found; run ./fetch_images.sh first")
        return

    payloads = [open(p, "rb").read() for p in IMAGES]
    sizes = [len(p) for p in payloads]
    names = [os.path.basename(p) for p in IMAGES]

    # --- h: the hash, measured on its own -----------------------------------
    per_image_mb_s, per_image_mb_s_mean = [], []
    for p in payloads:
        t = time_it(lambda p=p: hashlib.sha256(p).digest(),
                    trials=TRIALS, warmup=20)
        per_image_mb_s.append(len(p) / 1e6 / (t["median_ms"] / 1e3))
        per_image_mb_s_mean.append(len(p) / 1e6 / (t["mean_ms"] / 1e3))
    hash_mb_s = statistics.median(per_image_mb_s)
    hash_mb_s_mean = statistics.median(per_image_mb_s_mean)
    hash_ms_per_byte = 1e3 / (hash_mb_s * 1e6)
    hash_ms_per_byte_mean = 1e3 / (hash_mb_s_mean * 1e6)
    print(f"  SHA-256 {hash_mb_s:.0f} MB/s "
          f"(spread {min(per_image_mb_s):.0f}-{max(per_image_mb_s):.0f})")

    # Calibration and held-out halves, split by index parity so both span the
    # same size range. Splitting by size would hand the model an easy job.
    held = [i for i in range(len(payloads)) if i % 2 == 1]

    results = []
    for alg in ALGS:
        key, chain = build_chain(alg, CHAIN_DEPTH)

        # --- a: the fixed cost, measured on its own -------------------------
        t_fixed = time_it(
            lambda: sign_prehashed(DUMMY_DIGEST, alg, key, chain),
            trials=TRIALS, warmup=20)
        a = t_fixed["median_ms"]
        a_mean = t_fixed["mean_ms"]

        oqs = liboqs_signer(alg)
        a_oqs = None
        if oqs is not None:
            sign_fn = oqs[0]
            t_oqs = time_it(
                lambda: sign_prehashed_oqs(DUMMY_DIGEST, alg, chain, sign_fn),
                trials=TRIALS, warmup=20)
            a_oqs = t_oqs["median_ms"]

        # --- the model, tested on assets it was not built from --------------
        detail, errs = [], []
        for i in held:
            t = time_it(lambda p=payloads[i]: sign_one(p, alg, key, chain),
                        trials=TRIALS, warmup=20)
            predicted = a + hash_ms_per_byte * sizes[i]
            e = 100 * (predicted - t["median_ms"]) / t["median_ms"]
            errs.append(abs(e))
            detail.append({"image": names[i], "bytes": sizes[i],
                           "measured_ms": round(t["median_ms"], 4),
                           "predicted_ms": round(predicted, 4),
                           "error_pct": round(e, 2)})

        errs.sort()
        row = {
            "alg": alg,
            "chain_depth": CHAIN_DEPTH,
            "fixed_cost_ms": round(a, 4),
            "fixed_cost_mean_ms": round(a_mean, 4),
            "tail_ratio_mean_over_median": round(a_mean / a, 3),
            "fixed_cost_iqr_ms": round(t_fixed["iqr_ms"], 4),
            "fixed_cost_p95_ms": round(t_fixed["p95_ms"], 4),
            "fixed_cost_liboqs_ms": round(a_oqs, 4) if a_oqs else None,
            "hash_MB_s": round(hash_mb_s, 1),
            "heldout_n": len(held),
            "heldout_abs_error_median_pct": round(statistics.median(errs), 2),
            "heldout_abs_error_max_pct": round(errs[-1], 2),
            "heldout_detail": detail,
            # The file size at which hashing costs as much as everything else.
            "crossover_bytes": int(a / hash_ms_per_byte),
            "profiles": [
                {"profile": nm, "bytes": sz,
                 "predicted_ms": round(a + hash_ms_per_byte * sz, 3),
                 "fixed_share_pct": round(
                     100 * a / (a + hash_ms_per_byte * sz), 2)}
                for nm, sz in PROFILES
            ],
        }
        results.append(row)
        oqs_note = (f"  liboqs {a_oqs:6.3f} ms" if a_oqs else "")
        print(f"  {alg:<10} fixed {a:7.3f} ms{oqs_note}  "
              f"held-out error {row['heldout_abs_error_median_pct']:.2f}% "
              f"(worst {row['heldout_abs_error_max_pct']:.2f}%)  "
              f"crossover {row['crossover_bytes']:,} B")

    # --- the model against a real batch ------------------------------------
    cores = os.cpu_count() or 1
    worker_counts = sorted({1, 2, 4, min(8, cores), cores})
    n_assets = 4800                      # the corpus, 200 times over
    archive_bytes = sum(sizes) * (n_assets // len(sizes))

    batch = []
    for alg in ("ES256", "ML-DSA-65"):
        row = next(r for r in results if r["alg"] == alg)
        a, a_mean = row["fixed_cost_ms"], row["fixed_cost_mean_ms"]
        sz = [sizes[i % len(sizes)] for i in range(n_assets)]
        serial_med = sum(a + hash_ms_per_byte * x for x in sz)
        serial_avg = sum(a_mean + hash_ms_per_byte_mean * x for x in sz)
        for w in worker_counts:
            wall = batch_wall_time(alg, payloads, n_assets, w)
            pred_med = serial_med / 1000.0 / w
            pred_avg = serial_avg / 1000.0 / w
            batch.append({
                "alg": alg, "workers": w, "assets": n_assets,
                "archive_bytes": archive_bytes,
                "predicted_median_s": round(pred_med, 3),
                "predicted_mean_s": round(pred_avg, 3),
                "measured_s": round(wall, 3),
                "error_median_pct": round(100 * (pred_med - wall) / wall, 2),
                "error_mean_pct": round(100 * (pred_avg - wall) / wall, 2),
                "parallel_efficiency": round(
                    (serial_avg / 1000.0) / (wall * w), 3),
                "assets_per_s": round(n_assets / wall, 1),
            })
            b = batch[-1]
            print(f"  batch {alg:<10} {w:>2}w  measured {wall:7.2f} s  "
                  f"median model {b['error_median_pct']:+6.1f}%  "
                  f"mean model {b['error_mean_pct']:+6.1f}%  "
                  f"efficiency {b['parallel_efficiency']:.2f}")

    # --- projection ---------------------------------------------------------
    full = max(worker_counts)
    eff = statistics.median([x["parallel_efficiency"] for x in batch
                             if x["workers"] == full]) or 1.0
    projection = []
    for alg in ALGS:
        a = next(r for r in results if r["alg"] == alg)["fixed_cost_mean_ms"]
        for nm, sz in PROFILES:
            per_s = (a + hash_ms_per_byte_mean * sz) / 1000.0
            for n_assets in (10_000, 1_000_000):
                for c in (1, 8, 64):
                    projection.append({
                        "alg": alg, "profile": nm, "asset_bytes": sz,
                        "assets": n_assets, "cores": c,
                        "hours": round(per_s * n_assets / (c * eff) / 3600, 3),
                        "assumed_efficiency": round(eff, 3),
                    })

    write_json("e1_archive.json",
               {"hash_MB_s": round(hash_mb_s, 1),
                "hash_MB_s_mean": round(hash_mb_s_mean, 1),
                "per_asset": results, "batch": batch, "projection": projection},
               notes=[
                   "t(s) = a + s/h, with a and h measured separately and neither fitted",
                   "h is SHA-256 throughput, measured on the corpus with no signing in the loop",
                   "a is claim assembly plus signature over a digest already in hand",
                   "the held-out images test whether the two costs add, which is the model's only claim",
                   "the per-asset test uses medians, which is the right statistic for one asset's latency",
                   "the batch is reported against both statistics: a batch pays the mean, not the median",
                   "tail_ratio_mean_over_median is how far rejection sampling separates the two",
                   "the projection uses the mean, because a schedule is a throughput question",
                   "fixed_cost_liboqs_ms is the same work with the signature from liboqs rather than OpenSSL",
                   "the batch check signs 4800 assets, the corpus 200 times over, across worker processes",
                   "only an index crosses the process boundary; each worker holds the corpus and its credential",
                   "storage is outside both the model and the batch: a real archive adds one disk read per asset",
                   "key generation happens once per worker, outside the timed region",
                   "crossover_bytes is the file size at which hashing costs as much as everything else",
                   "the projection uses parallel efficiency measured at full core count, not perfect scaling",
                   "projection beyond the measured range is a model result, not a measurement",
               ])


if __name__ == "__main__":
    main()
