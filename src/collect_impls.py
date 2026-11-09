#!/usr/bin/env python3
"""Gather the implementation study into out/e5_implementations.json.

Reads the per-harness JSON lines written by bench/run_impls.sh, the build
metadata each harness printed on stderr, and the Python comparison's own
output, so that the wheel's OpenSSL, the source-built OpenSSL and every liboqs
build sit in one file measured on one machine in one session.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import write_json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "build")


def main():
    rows = []
    with open(os.path.join(BUILD, "results.jsonl")) as f:
        for line in f:
            line = line.strip()
            if line.startswith("{"):
                rows.append(json.loads(line))

    meta = open(os.path.join(BUILD, "meta.txt")).read().splitlines()

    # The wheel, as measured through Python in the same session.
    wheel = None
    p = os.path.join(ROOT, "out", "backend_comparison.json")
    if os.path.exists(p):
        wheel = json.load(open(p))
        for r in wheel["results"]:
            lib = r["library"]
            impl = ("openssl-wheel" if lib.startswith("OpenSSL")
                    else "liboqs-installed-via-python")
            for op in ("ML-DSA-65 sign", "ML-DSA-65 verify"):
                if op in r:
                    x = dict(r[op])
                    x.update({"impl": impl, "op": op, "via": "python"})
                    rows.append(x)

    flags = {}
    for v in ("native", "generic"):
        fp = os.path.join(BUILD, f"oqs-flags-{v}.txt")
        if os.path.exists(fp):
            flags[f"liboqs-{v}"] = open(fp).read().splitlines()

    write_json("e5_implementations.json",
               {"timings": rows, "build_meta": meta, "liboqs_flags": flags},
               notes=[
                   "every C harness times 1,000 calls after 50 discarded, against CLOCK_MONOTONIC_RAW",
                   "the OpenSSL harness mirrors the call sequence of the Python cryptography package: fresh context, no digest, one-shot sign",
                   "all builds finished before any timing began",
                   "liboqs is built with OQS_USE_OPENSSL=OFF so its own Keccak is measured",
                   "'deterministic' signing removes the random number generator from the loop",
                   "the openssl-wheel rows come from compare_backends.py in the same session",
               ])


if __name__ == "__main__":
    main()
