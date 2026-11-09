#!/usr/bin/env python3
"""Supplementary figure: distribution of what ML-DSA-65 adds to the production files.

Left: bytes added per file (empirical CDF), as substituted and with the upper
bound for post-quantum OCSP. Right: bytes added as a share of the original file
size, by file-size band. Reads out-reference/e1_corpus_pq_strata.json.
"""

import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERIES = ["#2a78d6", "#eb6834", "#1baf7a"]
INK = "#5f5e5a"


def ecdf(values):
    v = sorted(values)
    n = len(v)
    return v, [(i + 1) / n for i in range(n)]


def main():
    d = json.load(open(os.path.join(ROOT, "out-reference/e1_corpus_pq_strata.json")))
    files = d["results"]["files"]
    plt.rcParams.update({"font.size": 8.5, "axes.edgecolor": "#999999",
                         "axes.labelcolor": INK, "xtick.color": INK, "ytick.color": INK})
    fig, (a, b) = plt.subplots(1, 2, figsize=(7.0, 2.6), constrained_layout=True)

    for key, label, col, ls in (("added_bytes", "substituted", SERIES[0], "-"),
                                ("added_bytes_ocsp_bound", "with PQ OCSP (upper bound)",
                                 SERIES[1], "--")):
        x, y = ecdf([f[key] / 1000 for f in files])
        a.step(x, y, where="post", color=col, lw=1.6, ls=ls, label=label)
    a.set_xscale("log")
    a.set_xlabel("Bytes added per file (kB, log scale)")
    a.set_ylabel("Share of the 317 files")
    a.legend(frameon=False, loc="lower right", fontsize=7.5)
    a.grid(True, which="major", color="#e6e5e0", lw=0.6)

    bands = [("<0.5 MB", lambda s: s < 500_000),
             ("0.5–5 MB", lambda s: 500_000 <= s < 5_000_000),
             (">5 MB", lambda s: s >= 5_000_000)]
    for (label, test), col in zip(bands, SERIES):
        sel = [f["added_pct_of_file"] for f in files if test(f["file_bytes"])]
        x, y = ecdf(sel)
        b.step(x, y, where="post", color=col, lw=1.6, label=f"{label} ({len(sel)})")
    b.set_xscale("log")
    b.axvline(10, color="#999999", lw=0.7, ls="-.")
    b.text(10.5, 0.03, "10%", color=INK)
    b.set_xlabel("Bytes added, % of original file size (log scale)")
    b.set_xlim(0.03, 600)
    b.legend(frameon=False, loc="center right", bbox_to_anchor=(1.04, 0.38), fontsize=7.5, handlelength=1.2, title="file size", title_fontsize=7.5)
    b.grid(True, which="major", color="#e6e5e0", lw=0.6)
    from matplotlib.ticker import FuncFormatter
    fmt = FuncFormatter(lambda v, _: f"{v:g}")
    for ax in (a, b):
        ax.xaxis.set_major_formatter(fmt)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.set_ylim(0, 1.0)
    out = os.path.join(ROOT, "manuscript", "figures", "corpusgrowth.pdf")
    fig.savefig(out)
    fig.savefig(out.replace(".pdf", ".png"), dpi=150)
    print("wrote", out)


if __name__ == "__main__":
    main()
