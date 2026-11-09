#!/usr/bin/env python3
"""Figures for the paper, drawn from the same JSON as the tables.

  compose.pdf   what a timestamped manifest is made of, by role, per algorithm
  latency.pdf   where the cryptographic work of validating one image goes
  mcu.pdf       RAM and radio energy against carriage form on the
                microcontrollers
  scale.pdf     verification throughput against cores on three platforms

Colours are the categorical palette validated with the dataviz skill's
validator (light surface; every adjacent pair passes the CVD check), assigned
in fixed order; every figure carries a legend, and stacked segments are
separated by a 1 pt white gap so identity never rests on colour alone.

    python3 src/make_figures.py     # reads $LINEA_TABLE_IN or out/
"""

import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.environ.get("LINEA_TABLE_IN", os.path.join(ROOT, "out"))
FIG = os.environ.get("LINEA_FIG_OUT", os.path.join(ROOT, "manuscript", "figures"))
SLOTS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300",
         "#6250d6", "#e34948"]
INK, MUTED, GRID = "#1f1f1e", "#5f5e5a", "#e6e5e1"
ALGS = ["Ed25519", "ES256", "PS256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]

plt.rcParams.update({
    "font.size": 8, "font.family": "sans-serif", "axes.edgecolor": MUTED,
    "axes.labelcolor": INK, "xtick.color": MUTED, "ytick.color": MUTED,
    "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
    "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "legend.frameon": False, "pdf.fonttype": 42,
})


def load(name, base=None):
    p = os.path.join(base or OUT, name)
    return json.load(open(p)) if os.path.exists(p) else None


def save(fig, name):
    os.makedirs(FIG, exist_ok=True)
    fig.savefig(os.path.join(FIG, name), bbox_inches="tight")
    plt.close(fig)
    print(f"  {name}")


def stacked_h(ax, labels, parts, names, scale=1.0):
    left = [0.0] * len(labels)
    for i, (nm, vals) in enumerate(zip(names, parts)):
        v = [x * scale for x in vals]
        ax.barh(labels, v, left=left, color=SLOTS[i], edgecolor="white",
                linewidth=1.0, height=0.62, label=nm)
        left = [a + b for a, b in zip(left, v)]
    return left


def fig_compose():
    d = load("e1_timestamp.json")
    if not d:
        return
    r = {x["alg"]: x for x in d["results"]}
    algs = [a for a in ALGS if a in r][::-1]
    names = ["Manifest signature", "Signer leaf", "Signer intermediate",
             "TSA signature", "TSA certificates", "Structure and wrapping"]
    parts = [[] for _ in names]
    for a in algs:
        s, t = r[a]["breakdown_signature"], r[a]["breakdown_timestamp"]
        total = r[a]["manifest_signed_and_timestamped_bytes"]
        vals = [s["signature"], s["leaf"], s["intermediate"], t["signature"],
                t["tsa_signer_cert"] + t["tsa_intermediate_cert"]]
        vals.append(total - sum(vals))
        for i, v in enumerate(vals):
            parts[i].append(v)
    fig, ax = plt.subplots(figsize=(5.4, 2.5))
    ends = stacked_h(ax, algs, parts, names, scale=1 / 1000)
    for y, e in enumerate(ends):
        ax.text(e + 0.4, y, f"{e:.1f} kB", va="center", color=INK, fontsize=7.5)
    ax.set_xlabel("Bytes in a timestamped manifest (kB)")
    ax.grid(axis="y", visible=False)
    ax.set_xlim(0, max(ends) * 1.13)
    ax.legend(loc="upper center", bbox_to_anchor=(0.45, 1.32), ncol=3,
              fontsize=7, handlelength=1.2, columnspacing=1.0)
    save(fig, "compose.pdf")


def fig_latency():
    d = load("e1_verify.json")
    if not d:
        return
    r = {x["alg"]: x for x in d["results"]}
    algs = [a for a in ALGS if a in r][::-1]
    names = ["Decode", "Signer's path", "Manifest signature",
             "Timestamp signature", "TSA path", "Content hash (median image)"]
    keys = ["decode_embedded_ms", "validate_chain_ms", "verify_signature_ms",
            "verify_timestamp_signature_ms", "validate_tsa_path_ms", None]
    parts = [[] for _ in names]
    for a in algs:
        for i, k in enumerate(keys):
            v = (r[a]["hash_content_ms"]["median_image"]["median_ms"] if k is None
                 else r[a][k]["median_ms"])
            parts[i].append(v)
    fig, ax = plt.subplots(figsize=(5.4, 2.5))
    ends = stacked_h(ax, algs, parts, names)
    for y, e in enumerate(ends):
        ax.text(e + 0.02, y, f"{e:.2f} ms", va="center", color=INK, fontsize=7.5)
    ax.set_xlabel("Validation time for one timestamped image (ms, "
                  + d["env"]["cpu"].split(" @")[0] + ")")
    ax.grid(axis="y", visible=False)
    ax.set_xlim(0, max(ends) * 1.18)
    ax.legend(loc="upper center", bbox_to_anchor=(0.45, 1.32), ncol=3,
              fontsize=7, handlelength=1.2, columnspacing=1.0)
    save(fig, "latency.pdf")


def fig_mcu():
    v2 = os.environ.get("LINEA_MCU_IN", os.path.join(ROOT, "out-mcu-v2"))
    nuc = load("e10_nucleo_80mhz.json", v2)
    model = load("e12_ble_model.json", v2)
    rxm = load("e12_ble_rx_energy.json", os.path.join(ROOT, "out-mcu-v3"))
    if not nuc:
        return
    forms = [("full", "Leaf, intermediate, root"), ("chain", "Leaf, intermediate"),
             ("leaf", "Leaf only"), ("thumb", "Thumbprint")]
    algs = ["Ed25519", "ES256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
    rows = nuc["results"]
    sizes = {}
    for x in rows:
        if x.get("op") == "sizes" and not x.get("hw"):
            for f, _ in forms:
                sizes[(x["alg"], f)] = x[f"{f}_bytes"]

    def ram(alg, form):
        for x in rows:
            if x.get("alg") == alg and x.get("op") == f"manifest_{form}" and not x.get("hw"):
                return (x.get("stack_bytes", 0) + x.get("buffers_bytes", 0)) / 1024
        return None

    fig, axes = plt.subplots(1, 2, figsize=(5.4, 2.3))
    w = 0.19
    for k, ax in enumerate(axes):
        for i, (f, nm) in enumerate(forms):
            xs, ys = [], []
            for j, a in enumerate(algs):
                if k == 0:
                    v = ram(a, f)
                elif rxm:
                    v = next((x["gross_uj_median"] / 1000 for x in rxm["summary"]
                              if x["alg"] == a and x["op"] == f), None)
                else:
                    m = model["model"] if model else None
                    v = (m["a_uj"] + m["b_nj_per_byte"] / 1000 * sizes[(a, f)]) / 1000 \
                        if (m and (a, f) in sizes) else None
                if v is not None:
                    xs.append(j + (i - 1.5) * w)
                    ys.append(v)
            ax.bar(xs, ys, width=w, color=SLOTS[i], edgecolor="white",
                   linewidth=0.8, label=nm)
        ax.set_xticks(range(len(algs)), [a.replace("ML-DSA-", "ML-DSA\n") for a in algs],
                      fontsize=7)
        ax.grid(axis="x", visible=False)
    axes[0].set_ylabel("RAM to verify (KiB)")
    axes[0].set_title("NUCLEO-L4R5ZI, 80 MHz", fontsize=8, color=INK)
    axes[1].set_ylabel("Energy to receive over BLE (mJ)" if rxm else "Energy to send over BLE (mJ)")
    axes[1].set_title("nRF52840 receiver, measured" if rxm else "nRF52840 transmitter", fontsize=8, color=INK)
    fig.legend(*axes[0].get_legend_handles_labels(), loc="upper center",
               bbox_to_anchor=(0.5, 1.1), ncol=4, fontsize=7)
    fig.tight_layout()
    save(fig, "mcu.pdf")


def fig_scale():
    sets = [("M1 Pro", load("e8_scale.json")),
            ("Xeon VM", load("e8_scale.json", os.path.join(ROOT, "out-x86"))),
            ("Raspberry Pi 5", load("e8_scale.json", os.path.join(ROOT, "out-pi-v2")))]
    sets = [(n, d) for n, d in sets if d]
    if not sets:
        return
    fig, axes = plt.subplots(1, 2, figsize=(5.4, 2.2), sharey=False)
    for k, mode in enumerate(("uncached", "cached")):
        ax = axes[k]
        for i, (name, d) in enumerate(sets):
            pts = sorted((x["workers"], x["per_s"]) for x in d["results"]
                         if x["alg"] == "ML-DSA-65" and x["mode"] == mode)
            if pts:
                ax.plot([p[0] for p in pts], [p[1] / 1000 for p in pts],
                        color=SLOTS[i], lw=2, marker="o", ms=4, label=name)
        ax.set_xlabel("Worker processes")
        ax.set_title(f"ML-DSA-65, {mode}", fontsize=8, color=INK)
        ax.set_ylim(bottom=0)
    axes[0].set_ylabel("Verifications per second (thousands)")
    axes[1].legend(fontsize=7, loc="upper left")
    fig.tight_layout()
    save(fig, "scale.pdf")


def main():
    fig_compose()
    fig_latency()
    fig_mcu()
    fig_scale()


if __name__ == "__main__":
    main()
