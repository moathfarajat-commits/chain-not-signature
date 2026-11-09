#!/usr/bin/env python3
"""The size ladder: manifest cost as a percentage of file size.

Every percentage elsewhere in this study is taken against the Kodak set, whose
images are 768x512 and cluster near 108 kB. A phone photograph is closer to
4 MB, so the same manifest reads 19.6% there and 0.5% here. Reporting one
number invites a division the reader will do anyway, and losing the argument
to it.

The figure answers that directly. Once thumbnails are disabled a manifest's
size does not depend on the pixels at all: it is fixed by the algorithm and
the carriage format. So the percentage is an exact curve, manifest bytes over
file bytes, and a corpus contributes only the question of where real files sit
along it.

Manifest sizes come from out/e1_carriage.json and out/e1_timestamp.json. The
Kodak band is the measured range of that corpus. The other markers are the
sizes named in Section 4.1 and are labelled as reference points rather than
measurements.

    python3 src/fig_sizeladder.py     # writes manuscript/figures/sizeladder.pdf
"""

import json
import os
import statistics
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.environ.get("LINEA_TABLE_IN", os.path.join(ROOT, "out"))
FIGS = os.environ.get("LINEA_FIG_OUT", os.path.join(ROOT, "manuscript", "figures"))

# Reference file sizes from Section 4.1. Labelled as reference points, not
# measurements, except the Kodak band which is measured.
MARKERS = [
    (20_000, "thumbnail"),
    (350_000, "social\nre-encode"),
    (900_000, "1080p JPEG"),
    (4_000_000, "phone\noriginal"),
]


def load(name):
    p = os.path.join(OUT, name)
    if not os.path.exists(p):
        sys.exit(f"{p} missing; run the experiments first")
    return json.load(open(p))


def main():
    carriage = load("e1_carriage.json")
    ts = load("e1_timestamp.json")
    base = load("e1_baseline.json")

    def manifest(alg, how, anchor="root"):
        for r in carriage["results"]:
            if r["alg"] == alg and r["carriage"] == how and r.get("anchor", anchor) == anchor:
                return r["manifest_bytes"]
        raise KeyError((alg, how))

    def ts_row(alg):
        return next(r for r in ts["results"] if r["alg"] == alg)

    # One row per image per algorithm, so deduplicate by filename before
    # taking any statistic over the corpus.
    kodak = sorted({r["image"]: r["image_bytes"] for r in base["results"]}.values())
    kodak_lo, kodak_hi = kodak[0], kodak[-1]

    # Validated categorical palette (dataviz skill), fixed order.
    c = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#6250d6"]
    series = [
        (ts_row("ML-DSA-65")["manifest_full_bytes"],
         "ML-DSA-65, timestamp + OCSP", "-", c[0], 2.0),
        (ts_row("ML-DSA-65")["manifest_signed_and_timestamped_bytes"],
         "ML-DSA-65, timestamped", "-", c[1], 2.0),
        (manifest("ML-DSA-65", "chain"),
         "ML-DSA-65, leaf + intermediate", "-", c[2], 2.0),
        (manifest("ML-DSA-65", "leaf", "issuing CA"),
         "ML-DSA-65, leaf only", "--", c[3], 2.0),
        (manifest("ML-DSA-65", "thumb"),
         "ML-DSA-65, thumbprint", ":", c[4], 2.0),
        (ts_row("PS256")["manifest_signed_and_timestamped_bytes"],
         "PS256, timestamped (deployed today)", "-", c[5], 2.0),
    ]

    x = np.logspace(np.log10(10_000), np.log10(20_000_000), 400)
    fig, ax = plt.subplots(figsize=(6.2, 3.9))

    ax.axvspan(kodak_lo, kodak_hi, color="#f0c419", alpha=0.18, zorder=0)
    ax.text(np.sqrt(kodak_lo * kodak_hi), 0.026,
            "Kodak-24 (measured)", ha="center", va="bottom", rotation=90,
            fontsize=9, color="#8a6d00")

    for size, label in MARKERS:
        ax.axvline(size, color="#bbbbbb", lw=0.7, ls="-", zorder=0)
        ax.text(size * 1.08, 0.025, label, rotation=90, va="bottom", ha="left",
                fontsize=8.5, color="#5f5e5a")

    for bytes_, label, ls, colour, lw in series:
        ax.plot(x, 100.0 * bytes_ / x, ls, color=colour, lw=lw, label=label)

    ax.axhline(10, color="#999999", lw=0.6, ls="-.")
    ax.text(1.1e4, 10.8, "10% of the file", fontsize=8.5, color="#5f5e5a")
    ax.axhline(1, color="#999999", lw=0.6, ls="-.")
    ax.text(1.1e4, 1.08, "1% of the file", fontsize=8.5, color="#5f5e5a")

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlim(1e4, 2e7)
    ax.set_ylim(0.02, 100)
    ax.set_xlabel("File size (bytes)", fontsize=10)
    ax.set_ylabel("Manifest as % of file size", fontsize=10)
    ax.tick_params(labelsize=9)
    ax.grid(True, which="major", lw=0.4, color="#dddddd")
    ax.grid(True, which="minor", lw=0.25, color="#eeeeee")
    ax.legend(fontsize=8.5, loc="upper right", framealpha=0.95)

    for side in ("top", "right"):
        ax.spines[side].set_visible(False)

    os.makedirs(FIGS, exist_ok=True)
    out = os.path.join(FIGS, "sizeladder.pdf")
    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    print(f"  wrote {os.path.relpath(out, ROOT)}")

    print("\n  manifest sizes used (bytes):")
    for bytes_, label, *_ in series:
        print(f"    {label:45s} {bytes_:7,d}")
    print(f"\n  Kodak measured range: {kodak_lo:,}--{kodak_hi:,} B")
    print("\n  percentage at each reference size:")
    hdr = f"    {'file':>12s}" + "".join(f"{l.split(',')[1].strip()[:14]:>16s}"
                                         for _, l, *_ in series)
    print(hdr)
    kodak_median = int(statistics.median(kodak))
    for size, label in [(kodak_median, "Kodak median")] + MARKERS:
        row = f"    {size:12,d}"
        for bytes_, *_ in series:
            row += f"{100.0 * bytes_ / size:15.2f}%"
        print(row)


if __name__ == "__main__":
    main()
