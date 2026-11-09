#!/usr/bin/env python3
"""Table generators for the experiments added after the external review.

Imported by make_tables.py so that every number in the new sections comes from
out/*.json on the same terms as the rest of the paper: nothing typed by hand.
"""

import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from make_tables import emit, load


def tab_prodchains():
    d = load("e1_prodchains.json")
    if not d:
        return
    s = d["results"]["summary"]
    depth = s["chain_depth_distribution"]
    total_chains = sum(depth.values())
    suppliers = ", ".join(f"{k.capitalize()} ({v})" for k, v in s["suppliers"].items())
    algs = ", ".join(f"{k} ({v})" for k, v in s["algorithms"].items())

    body = [
        r"\begin{table}[t]",
        r"\caption{Certificate chains read out of assets signed by other "
        r"people's software: the `good' files of the C2PA public test file "
        r"repository, produced by Conforming Generator Products under the "
        r"C2PA Conformance Program. Signature counts exceed asset counts "
        r"because an asset carries its ingredients' manifests whole, "
        r"certificates included.}",
        r"\label{tab:prodchains}",
        r"\begin{tabular}{lr}",
        r"\toprule",
        r"Observation & Value\\",
        r"\midrule",
        rf"Assets with an embedded manifest & {s['assets']}\\",
        rf"Signatures found & {s['signatures']}\\",
        rf"Suppliers & \multicolumn{{1}}{{r}}{{{suppliers}}}\\",
        rf"Signature algorithms & \multicolumn{{1}}{{r}}{{{algs}}}\\",
        r"\midrule",
    ]
    for k in sorted(depth, key=int):
        body.append(rf"Chains of {k} certificates & {depth[k]} of "
                    rf"{total_chains}\\")
    body += [
        rf"Leaf certificate, median bytes & "
        rf"{int(s['leaf_cert_bytes_median']):,}\\",
        rf"Leaf certificate, range & "
        rf"{s['leaf_cert_bytes_range'][0]:,}--"
        rf"{s['leaf_cert_bytes_range'][1]:,}\\",
        rf"Whole chain, median bytes & "
        rf"{int(s['chain_bytes_median']):,}\\",
        rf"Whole chain, range & {s['chain_bytes_range'][0]:,}--"
        rf"{s['chain_bytes_range'][1]:,}\\",
        r"\midrule",
        rf"Carrying no certificate chain & "
        rf"{s['carriage'].get('none', 0)} of {s['signatures']}\\",
        rf"Carrying an RFC~3161 timestamp & {s['with_timestamp']} of "
        rf"{s['signatures']}\\",
        rf"Carrying a stapled OCSP response & {s['with_ocsp']} of "
        rf"{s['signatures']}\\",
        rf"Chain in the protected header & "
        rf"{s['chain_in_protected_header']} of {s['signatures']}\\",
        rf"Post-quantum signatures & {s['post_quantum']} of "
        rf"{s['signatures']}\\",
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    emit("prodchains.tex", "\n".join(body) + "\n")


def tab_mixedchain():
    d = load("e1_mixedchain.json")
    if not d:
        return
    rows = d["results"]
    body = [
        r"\begin{table}[t]",
        r"\caption{Chains whose levels do not share one algorithm, which is "
        r"what a migration in progress looks like. \emph{PQ} is whether every "
        r"load-bearing signature in the path is post-quantum: the manifest "
        r"signature, the signature on the leaf certificate and the signature "
        r"on the intermediate. A root's self-signature is excluded, because a "
        r"root is trusted by being in the trust store. Chains run leaf first. "
        r"\emph{COSE} is the signed structure and \emph{Certs.} the chain "
        r"inside it, both in bytes; the ratio is to the classical structure.}",
        r"\label{tab:mixedchain}",
        r"\small",
        r"\begin{tabular}{llrrrc}",
        r"\toprule",
        r"Chain & Configuration & COSE (B) & Certs. (B) & $\times$ classical "
        r"& PQ\\",
        r"\midrule",
    ]
    for r in rows:
        stage = r.get("stage", r["description"][:28])
        # "Leaf only" here means only the leaf has migrated; keep the name
        # apart from the leaf-only carriage form of Section 5.
        stage = {"Leaf only": "Leaf migrated"}.get(stage, stage)
        body.append(
            rf"{r['label']} & {stage} & {r['cose_bytes']:,} & "
            rf"{r['chain_der_bytes']:,} & {r['bytes_vs_classical']:.1f} & "
            + (r"\checkmark" if r["quantum_resistant"] else "--") + r"\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("mixedchain.tex", "\n".join(body) + "\n")


def tab_archive_model():
    d = load("e1_archive.json")
    if not d:
        return
    res = d["results"]
    body = [
        r"\begin{table}[t]",
        r"\caption{The per-asset model and its test. $a$ is the fixed cost, "
        r"measured over a digest already in hand; the hash term is "
        f"{res['hash_MB_s']:,.0f}~MB/s measured with no signing in the loop. "
        r"Neither is fitted. The error column is the model's median error "
        r"against held-out images it was not built from. \emph{Crossover} is "
        r"the file size at which hashing costs as much as everything else, "
        r"which is where the algorithm stops mattering.}",
        r"\label{tab:archivemodel}",
        r"\begin{tabular}{lrrrrr}",
        r"\toprule",
        r"Algorithm & $a$ (ms) & mean/median & $a$ liboqs (ms) & "
        r"Held-out error & Crossover\\",
        r"\midrule",
    ]
    for r in res["per_asset"]:
        oqs = (f"{r['fixed_cost_liboqs_ms']:.3f}"
               if r.get("fixed_cost_liboqs_ms") else "--")
        body.append(
            rf"{r['alg']} & {r['fixed_cost_ms']:.3f} & "
            rf"{r.get('tail_ratio_mean_over_median', 1):.2f} & {oqs} & "
            rf"{r['heldout_abs_error_median_pct']:.2f}\% & "
            rf"{r['crossover_bytes']/1024:,.0f}~KiB\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("archivemodel.tex", "\n".join(body) + "\n")


def tab_archive_batch():
    d = load("e1_archive.json")
    if not d:
        return
    batch = d["results"]["batch"]
    n = batch[0]["assets"]
    mb = batch[0]["archive_bytes"] / 1e6
    body = [
        r"\begin{table}[t]",
        r"\caption{The model against a real batch: " + f"{n:,}" + r" assets, "
        + f"{mb:,.0f}" + r"~MB, signed across worker processes, predicted "
        r"from the median fixed cost and from the mean. Only an index crosses "
        r"the process boundary; each worker holds the corpus and its "
        r"credential, so the timed region is hash and signature alone. The "
        r"error columns show the effect: ECDSA barely distinguishes "
        r"the statistics and ML-DSA does, at one worker, where no contention "
        r"can explain it.}",
        r"\label{tab:archivebatch}",
        r"\begin{tabular}{lrrrrr}",
        r"\toprule",
        r"Algorithm & Workers & Measured (s) & Median model & Mean model "
        r"& Efficiency\\",
        r"\midrule",
    ]
    for b in batch:
        body.append(
            f"{b['alg']} & {b['workers']} & {b['measured_s']:.2f} & "
            f"{b['error_median_pct']:+.1f}" + r"\% & "
            + f"{b['error_mean_pct']:+.1f}" + r"\% & "
            + f"{b['parallel_efficiency']:.2f}" + r"\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("archivebatch.tex", "\n".join(body) + "\n")


def tab_archive_projection():
    d = load("e1_archive.json")
    if not d:
        return
    proj = d["results"]["projection"]
    profiles = list(dict.fromkeys(p["profile"] for p in proj))
    algs = list(dict.fromkeys(p["alg"] for p in proj))
    eff = proj[0]["assumed_efficiency"]

    body = [
        r"\begin{table}[t]",
        rf"\caption{{Modelled minutes to re-sign one million assets on eight "
        rf"cores, at a parallel efficiency of {eff:.2f}, the mean of the two "
        rf"eight-worker values in Table~\ref{{tab:archivebatch}}, rather than "
        rf"assuming perfect "
        rf"scaling. These are computation-only model results outside the "
        rf"measured range, not measurements: the efficiency was measured on "
        rf"small images and is not established for large objects, and reading "
        rf"from storage and memory bandwidth are not modelled. The column "
        rf"spread shows it: at "
        rf"photographic sizes the algorithm barely moves the schedule, and "
        rf"below the crossover it decides it.}}",
        r"\label{tab:archiveproj}",
        r"\begin{tabular}{lr" + "r" * len(algs) + r"}",
        r"\toprule",
        r"Asset profile & Bytes & " + " & ".join(algs) + r"\\",
        r"\midrule",
    ]
    for pr in profiles:
        cells, size = [], None
        for a in algs:
            m = [p for p in proj if p["profile"] == pr and p["alg"] == a
                 and p["assets"] == 1_000_000 and p["cores"] == 8]
            if m:
                cells.append(f"{m[0]['hours'] * 60:,.1f}")
                size = m[0]["asset_bytes"]
        label = pr[0].upper() + pr[1:]
        body.append(rf"{label} & {size/1024:,.0f}~KiB & "
                    + " & ".join(cells) + r"\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("archiveproj.tex", "\n".join(body) + "\n")


def tab_scale():
    """Verifications per second against cores, uncached and cached, for each
    machine that ran E8: the M1 Pro from out/, the Pi 5 from out-pi/."""
    runs = []
    for doc in (load("e8_scale.json"), _load_from("out-x86", "e8_scale.json"),
                _load_from("out-pi-v2", "e8_scale.json")):
        if doc:
            runs.append(doc)
    if not runs:
        return

    def k(v):
        return "--" if v is None else f"{v / 1000:.1f}"

    def name(doc):
        cpu = doc["env"].get("cpu", "")
        if cpu.startswith("Raspberry Pi") or "Cortex-A76" in cpu or doc["env"].get("pi"):
            return "Raspberry Pi 5"
        if "Xeon" in cpu:
            return "Intel Xeon VM"
        return cpu

    body = [
        r"\begin{table}[t]",
        r"\caption{Manifests verified per second, in thousands, on one core "
        r"and on every core of each machine. A stream from 500 publishers, "
        r"drawn Zipf(1), each with a three-certificate chain. "
        r"\emph{Uncached} validates the embedded chain for every manifest; "
        r"\emph{cached} validates each publisher's chain once per worker and "
        r"then checks only the signature, through OpenSSL or, for ML-DSA, "
        r"liboqs. x5chain carries leaf and intermediate; the root comes from "
        r"the verifier's store. Medians of three independent runs of 20,000 "
        r"verifications each.}",
        r"\label{tab:scale}",
        r"\begin{tabular}{lrrrrrr}",
        r"\toprule",
        r" & \multicolumn{2}{c}{Uncached} & \multicolumn{2}{c}{Cached} "
        r"& \multicolumn{2}{c}{Cached, liboqs}\\",
        r"\cmidrule(lr){2-3}\cmidrule(lr){4-5}\cmidrule(lr){6-7}",
        r"Algorithm & " + " & ".join(["1 core", "all"] * 3) + r"\\",
    ]
    for doc in runs:
        rows = doc["results"]
        ws = sorted({r["workers"] for r in rows})
        lo, hi = ws[0], ws[-1]
        algs = []
        for r in rows:
            if r["alg"] not in algs:
                algs.append(r["alg"])
        # Runs shuffle their order; print in the paper's order.
        order = ["Ed25519", "ES256", "PS256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
        algs.sort(key=lambda a: order.index(a) if a in order else len(order))
        get = {(r["alg"], r["mode"], r["workers"]): r["per_s"] for r in rows}
        body += [r"\midrule",
                 r"\multicolumn{7}{l}{\emph{" + name(doc).replace("_", r"\_")
                 + f", all = {hi} cores" + r"}}\\"]
        for a in algs:
            cells = []
            for m in ("uncached", "cached", "cached-liboqs"):
                cells += [k(get.get((a, m, lo))), k(get.get((a, m, hi)))]
            body.append(f"{a} & " + " & ".join(cells) + r"\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("scale.tex", "\n".join(body) + "\n")


def tab_video():
    """E6 on the Pi 5: a per-frame and a per-second signer at 30 fps."""
    d = _load_from("out-pi", "e6_video.json")
    if not d:
        return
    rows = d["results"]
    get = {(r["alg"], r["resolution"], r["segment_frames"]): r for r in rows}
    algs = []
    for r in rows:
        if r["alg"] not in algs:
            algs.append(r["alg"])
    body = [
        r"\begin{table}[t]",
        r"\caption{The earlier raw-frame video signer on one core of the "
        r"Raspberry Pi 5, kept as a computational upper bound; it predates the "
        r"paper's baseline, so its manifests carry leaf, intermediate and root, "
        r"and its bandwidth figures are those of that configuration. Every "
        r"frame is hashed (SHA-256 over raw YUV 4:2:0) and either signed on "
        r"its own or, in the last column, gathered into a one-second segment "
        r"that is signed once. \emph{fps} is the sustained rate running flat "
        r"out; at 30\,fps every configuration finished every frame within its "
        r"period. \emph{mJ} is energy per frame running flat out, PMIC rail "
        r"power above idle divided by frame rate. \emph{Mbps} is the "
        r"provenance stream at 30\,fps with the chain embedded "
        r"(\texttt{x5chain}) or referenced by thumbprint (\texttt{x5t}). "
        r"ML-DSA signs through liboqs, Ed25519 and ES256 through OpenSSL.}",
        r"\label{tab:video}",
        r"\small",
        r"\begin{tabular}{lrrrrrrr}",
        r"\toprule",
        r" & \multicolumn{4}{c}{Signed every frame} & \multicolumn{3}{c}{Mbps at 30\,fps}\\",
        r"\cmidrule(lr){2-5}\cmidrule(lr){6-8}",
        r" & \multicolumn{2}{c}{1080p} & \multicolumn{2}{c}{4K} & "
        r"\multicolumn{2}{c}{every frame} & per second\\",
        r"\cmidrule(lr){2-3}\cmidrule(lr){4-5}\cmidrule(lr){6-7}\cmidrule(lr){8-8}",
        r"Algorithm & fps & mJ & fps & mJ & \texttt{x5chain} & \texttt{x5t} & \texttt{x5chain}\\",
        r"\midrule",
    ]
    for a in algs:
        hd, uk, seg = get.get((a, "1080p", 1)), get.get((a, "4K", 1)), get.get((a, "1080p", 30))
        if not (hd and uk and seg):
            continue
        body.append(
            f"{a} & {hd['burst_fps']:.0f} & {hd['mj_per_frame_burst']:.1f} & "
            f"{uk['burst_fps']:.0f} & {uk['mj_per_frame_burst']:.1f} & "
            f"{hd['mbps_embedded']:.2f} & {hd['mbps_thumbprint']:.2f} & "
            f"{seg['mbps_embedded']:.2f}\\\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("video.tex", "\n".join(body) + "\n")


def tab_edge():
    """E7 on the Pi 5: end-to-end verification with the trust store on SD."""
    d = (_load_from("out-pi-v2", "e7_edge.json") or _load_from("out-pi", "e7_edge.json"))
    if not d:
        return
    body = [
        r"\begin{table}[t]",
        r"\caption{Verifying a manifest's signature and the signer's path on one "
        r"core of the Raspberry Pi 5, every signature through OpenSSL; decoding, "
        r"timestamp, revocation and content hashing are outside the boundary. "
        r"\emph{Embedded} carries leaf and "
        r"intermediate in the manifest, with the root as an in-memory anchor. "
        r"\emph{Referenced} finds them by thumbprint in a "
        r"trust store of 500 signers on the board's SD card, either already in "
        r"memory (\emph{warm}) or after the store has been evicted from the "
        r"page cache (\emph{cold}). Milliseconds, medians.}",
        r"\label{tab:edge}",
        r"\begin{tabular}{lrrrrrr}",
        r"\toprule",
        r" & Store & & & \multicolumn{3}{c}{Total}\\",
        r"\cmidrule(lr){5-7}",
        r"Algorithm & MB & Chain & Signature & Embedded & Warm & Cold\\",
        r"\midrule",
    ]
    for r in d["results"]:
        w = r["warm"]
        body.append(
            f"{r['alg']} & {r['store_bytes'] / 1e6:.1f} & "
            f"{w['validate']['median_ms']:.3f} & {w['verify']['median_ms']:.3f} & "
            f"{r['embedded']['total']['median_ms']:.3f} & "
            f"{w['total']['median_ms']:.3f} & {r['cold']['total']['median_ms']:.3f}\\\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("edge.tex", "\n".join(body) + "\n")


def main():
    tab_impls()
    tab_buildeffect()
    tab_c2parust()
    tab_prodchains()
    tab_mixedchain()
    tab_archive_model()
    tab_archive_batch()
    tab_archive_projection()
    tab_scale()
    tab_video()
    tab_edge()
    tab_mcu()
    tab_mcu_cost()
    tab_rewrap_cold()




def tab_c2parust():
    d = load("e1_c2parust.json")
    if not d:
        return
    rows = d["results"]
    algs = list(dict.fromkeys(r["alg"] for r in rows))
    states = {r["validation_state"] for r in rows}
    n_img = len({r["image"] for r in rows})

    body = [
        r"\begin{table}[t]",
        rf"\caption{{Manifests produced by the C2PA reference implementation "
        rf"itself, patched to accept the RFC~9964 algorithm identifiers. "
        rf"Medians over the {n_img} images of the Kodak set. Every output was "
        rf"read back and validated; all {len(rows)} validated. \emph{{Median "
        rf"growth}} is the manifest as a percentage of the image; \emph{{Sign}} "
        rf"covers hashing the asset, building the manifest and rewriting the "
        rf"file on the x86-64 host.}}",
        r"\label{tab:c2parust}",
        r"\begin{tabular}{lrrrr}",
        r"\toprule",
        r"Algorithm & Manifest & Median growth & Sign & Validates\\",
        r"\midrule",
    ]
    for a in algs:
        s = [r for r in rows if r["alg"] == a]
        body.append(
            rf"{a} & {s[0]['manifest_bytes']:,} & "
            rf"{statistics.median(x['growth_pct'] for x in s):.2f}\% & "
            rf"{statistics.median(x['sign_ms'] for x in s):.2f}~ms & "
            + (r"\checkmark" if states == {"Valid"} else "--") + r"\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("c2parust.tex", "\n".join(body) + "\n")

# How each row of the implementation table is labelled. Keys are the `impl`
# names the harnesses and the collector write.
IMPL_LABELS = [
    ("liboqs-0.16.0-native", "liboqs 0.16.0", "native, arm64 path"),
    ("liboqs-0.16.0-generic", "liboqs 0.16.0", "generic, no NEON"),
    ("pqclean-ml-dsa-65-clean", "PQClean reference", r"portable C, \texttt{-O3}"),
    ("openssl-4.0.2-source-asm", "OpenSSL 4.0.2", r"source, \texttt{-O3}"),
    ("openssl-4.0.2-source-noasm", "OpenSSL 4.0.2", r"source, \texttt{-O3}, no asm"),
    ("openssl-homebrew", "OpenSSL 3.6.4", "Homebrew"),
    ("cryptography-source-O3", r"\texttt{cryptography} 50.0.1",
     r"OpenSSL 4.0.2 source, \texttt{-O3}"),
    ("openssl-wheel", r"\texttt{cryptography} 50.0.1",
     r"PyPI wheel, no \texttt{-O}"),
]


def tab_impls():
    d = load("e5_implementations.json")
    if not d:
        return
    rows = d["results"]["timings"]

    # The source-built cryptography, measured through Python in the paired
    # re-run, sits in the O3 backend comparison rather than in the C harness
    # file; fold it in under its own name.
    b = load("backend_comparison.json")
    if b:
        for r in b["results"]:
            if r["library"].startswith("OpenSSL") and "-O3" in (
                    b["env"].get("openssl_compiler") or ""):
                for op in ("ML-DSA-65 sign", "ML-DSA-65 verify"):
                    x = dict(r[op]); x.update({"impl": "cryptography-source-O3",
                                               "op": op})
                    rows.append(x)

    def get(impl, op):
        m = [r for r in rows if r["impl"] == impl and r["op"] == op]
        return m[0] if m else None

    shown = {k for k, _, _ in IMPL_LABELS}
    fastest = min(r["median_ms"] for r in rows
                  if r["op"] == "ML-DSA-65 sign" and r["impl"] in shown)
    body = [
        r"\begin{table}[t]",
        r"\caption{ML-DSA-65 on one Apple M1 Pro through every implementation "
        r"and build we could obtain, 1,000 timed calls each after 50 discarded. "
        r"The C harness uses one call sequence for every OpenSSL build, the same "
        r"one the Python \texttt{cryptography} package uses. The last two rows "
        r"are the same package version over the same OpenSSL version and differ "
        r"only in whether that OpenSSL was compiled with optimisation.}",
        r"\label{tab:impls}",
        r"\small",
        r"\setlength{\tabcolsep}{4.5pt}",
        r"\begin{tabular}{llrrrr}",
        r"\toprule",
        r"Implementation & Build & Sign, med. & Sign, mean & Verify & "
        r"$\times$ fastest\\",
        r"\midrule",
    ]
    for key, name, build in IMPL_LABELS:
        s, v = get(key, "ML-DSA-65 sign"), get(key, "ML-DSA-65 verify")
        if not s:
            continue
        mean = s.get("mean_ms")
        body.append(
            rf"{name} & {build} & {s['median_ms']:.3f} & "
            + (f"{mean:.3f}" if mean else "--") + " & "
            + (f"{v['median_ms']:.3f}" if v else "--") + " & "
            + f"{s['median_ms'] / fastest:.1f}" + r"\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("impls.tex", "\n".join(body) + "\n")

# --------------------------------------------------------------- E9-E12
# Microcontrollers: the same signed manifests verified on a Pico (RP2040),
# a NUCLEO-L4R5ZI and an nRF52840-DK, energy from a PPK2, and the radio cost
# of each carriage form between two nRF52840-DKs. Results in out-mcu/.

MCU_ALGS = ["Ed25519", "ES256", "ES256 hw", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]


def _mcu_row(doc, alg, op):
    """Median ms (and the row) for one op; 'ES256 hw' is ES256 on the
    nRF52840's CryptoCell-310."""
    hw = 1 if alg.endswith(" hw") else 0
    a = alg.replace(" hw", "")
    for r in doc["results"]:
        if r.get("op") == op and r.get("alg") == a and r.get("hw", 0) == hw:
            if not r.get("ok", True):
                raise SystemExit(f"{op} {alg}: run not ok")
            return r
    return None


def _ms(doc, alg, op):
    r = _mcu_row(doc, alg, op) if doc else None
    return f"{r['median_us'] / 1000:.1f}" if r else "--"


def _energy(doc, alg, op, scale=1e-3, fmt="{:.2f}"):
    """Gross energy per op from a PPK2 summary, in mJ by default."""
    if not doc:
        return "--"
    hw = 1 if alg.endswith(" hw") else 0
    a = alg.replace(" hw", "")
    for s in doc["summary"]:
        if s["alg"] == a and s["op"] == op and s.get("hw", 0) == hw:
            return fmt.format(s["gross_uj_median"] * scale)
    return "--"


def _kb(doc, alg, op):
    r = _mcu_row(doc, alg, op) if doc else None
    return f"{(r['buffers_bytes'] + r['stack_bytes']) / 1024:.1f}" if r else "--"


def _check_negatives(doc, name):
    for r in doc["results"]:
        if r.get("op") == "negative" and not (r["rejects_flipped_bit"] and r["accepts_original"]
                                              and r["rejects_tampered_manifest"]):
            raise SystemExit(f"{name}: negative test failed for {r['alg']}")


def tab_mcu():
    pico = _load_from("out-mcu", "e9_pico.json")
    n20 = _load_from("out-mcu", "e10_nucleo_20mhz.json")
    n80 = _load_from("out-mcu", "e10_nucleo_80mhz.json")
    nrf = _load_from("out-mcu", "e11_nrf52840.json")
    if not (pico and n20 and n80 and nrf):
        return
    for d, n in ((pico, "pico"), (n20, "nucleo20"), (n80, "nucleo80"), (nrf, "nrf")):
        _check_negatives(d, n)
    body = [
        r"\begin{table}[t]",
        r"\caption{Verifying one complete manifest on three microcontrollers: "
        r"decode it, check the two certificate signatures and the manifest "
        r"signature, with the chain carried in full or found by thumbprint in a "
        r"trust store in flash (\emph{Thumb}). Pico: RP2040 Cortex-M0+ at 125\,MHz, portable C "
        r"(PQClean). NUCLEO: STM32L4R5 Cortex-M4F, pqm4's assembly, at 20\,MHz "
        r"with no flash wait states and at 80\,MHz. nRF: nRF52840 Cortex-M4F at "
        r"64\,MHz, the same objects as the NUCLEO; \emph{ES256 (hw)} runs on its "
        r"CryptoCell-310. Milliseconds, medians.}",
        r"\label{tab:mcu}",
        r"\small",
        r"\begin{tabular}{lrrrrrrr}",
        r"\toprule",
        r" & \multicolumn{2}{c}{Pico} & \multicolumn{3}{c}{NUCLEO} & "
        r"\multicolumn{2}{c}{nRF52840}\\",
        r"\cmidrule(lr){2-3}\cmidrule(lr){4-6}\cmidrule(lr){7-8}",
        r" & Full & Thumb & 20\,MHz & \multicolumn{2}{c}{80\,MHz} & Full & Thumb\\",
        r"\cmidrule(lr){5-6}",
        r"Algorithm & & & Full & Full & Thumb & & \\",
        r"\midrule",
    ]
    for a in MCU_ALGS:
        body.append(
            f"{a.replace(' hw', ' (hw)')} & {_ms(pico, a, 'manifest_full')} & "
            f"{_ms(pico, a, 'manifest_thumb')} & {_ms(n20, a, 'manifest_full')} & "
            f"{_ms(n80, a, 'manifest_full')} & {_ms(n80, a, 'manifest_thumb')} & "
            f"{_ms(nrf, a, 'manifest_full')} & {_ms(nrf, a, 'manifest_thumb')}\\\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("mcu.tex", "\n".join(body) + "\n")


def tab_mcu_cost():
    pico = _load_from("out-mcu", "e9_pico.json")
    n80 = _load_from("out-mcu", "e10_nucleo_80mhz.json")
    nrf = _load_from("out-mcu", "e11_nrf52840.json")
    ep = _load_from("out-mcu", "e9_pico_energy.json")
    en = _load_from("out-mcu", "e10_nucleo_energy.json")
    er = _load_from("out-mcu", "e11_nrf52840_energy.json")
    eb = _load_from("out-mcu", "e12_ble_energy.json")
    rx = _load_from("out-mcu", "e12_ble_rx.json")
    if not (pico and n80 and nrf and ep and en and er and eb and rx):
        return
    rxw = [r for r in rx["results"] if r.get("op") == "rx"]
    if not rxw or any(r["ok"] != r["k"] for r in rxw):
        raise SystemExit("e12: a manifest arrived damaged")
    for e, n in ((ep, "pico"), (en, "nucleo"), (er, "nrf"), (eb, "ble")):
        if e["spans_found"] != e["spans_expected"]:
            raise SystemExit(f"{n} energy: {e['spans_found']} windows, {e['spans_expected']} expected")
    body = [
        r"\begin{table}[t]",
        r"\caption{What a manifest costs a microcontroller beyond time. "
        r"\emph{RAM}: the received manifest, the signed structure rebuilt from "
        r"it and the peak stack, all live at once, with the full chain or a "
        r"thumbprint; M0+ is the Pico's portable C, M4 the NUCLEO's pqm4 build "
        r"(the nRF52840 for ES256 (hw)). "
        r"\emph{Verify}: energy to verify one full-chain manifest, measured by a "
        r"PPK2 on the whole Pico at its 3.3\,V input, on the NUCLEO's MCU supply "
        r"at 80\,MHz and on the nRF52840's supply, so the three columns are not "
        r"comparable with one another. \emph{Send}: energy for one nRF52840 to "
        r"send the manifest to another over Bluetooth LE (2M PHY, 247-byte MTU), "
        r"every byte checked on arrival. Medians of three rounds.}",
        r"\label{tab:mcucost}",
        r"\small",
        r"\setlength{\tabcolsep}{4.5pt}",
        r"\begin{tabular}{lrrrrrrrr}",
        r"\toprule",
        r" & \multicolumn{3}{c}{RAM (KiB)} & \multicolumn{3}{c}{Verify (mJ)} & "
        r"\multicolumn{2}{c}{Send ($\mu$J)}\\",
        r"\cmidrule(lr){2-4}\cmidrule(lr){5-7}\cmidrule(lr){8-9}",
        r" & M0+ & \multicolumn{2}{c}{M4} & & & & & \\",
        r"\cmidrule(lr){3-4}",
        r"Algorithm & Full & Full & Thumb & Pico & NUCLEO & nRF & Full & Thumb\\",
        r"\midrule",
    ]
    for a in MCU_ALGS:
        hw = a.endswith(" hw")
        ram_m0 = "--" if hw else _kb(pico, a, "manifest_full")
        ram_m4f = _kb(nrf, a, "manifest_full") if hw else _kb(n80, a, "manifest_full")
        ram_m4t = _kb(nrf, a, "manifest_thumb") if hw else _kb(n80, a, "manifest_thumb")
        vp = "--" if hw else _energy(ep, a, "manifest_full", fmt="{:.1f}")
        vn = "--" if hw else _energy(en, a, "manifest_full")
        vr = _energy(er, a, "manifest_full")
        sf = "--" if hw else _energy(eb, a, "full", scale=1, fmt="{:,.0f}")
        st = "--" if hw else _energy(eb, a, "thumb", scale=1, fmt="{:,.0f}")
        body.append(f"{a.replace(' hw', ' (hw)')} & {ram_m0} & {ram_m4f} & {ram_m4t} & "
                    f"{vp} & {vn} & {vr} & {sf} & {st}\\\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("mcucost.tex", "\n".join(body) + "\n")


def tab_rewrap_cold():
    """E4 archive re-wrap with the page cache purged first and every write
    forced to the drive with F_FULLFSYNC (supplement)."""
    d = _load_from("out-reference", "e4_keywrap_cold.json")
    if not d:
        return
    body = [
        r"\begin{table}[t]",
        r"\caption{The re-wrap of Table~\ref{tab:rewrap} repeated with the page cache emptied "
        r"(\texttt{purge}) after the archive was written and every write forced "
        r"to the drive with \texttt{F\_FULLFSYNC}, on Apple M1 Pro. Per-object "
        r"medians in milliseconds. Every object was checked to decrypt under the "
        r"new key.}",
        r"\label{tab:rewrapcold}",
        r"\begin{tabular}{llrrrrrr}",
        r"\toprule",
        r"Object & Layout & Read & Unwrap & Wrap & Write & Objects/s & Count\\",
        r"\midrule",
    ]
    prev = None
    for r in d["results"]:
        if not r.get("verified"):
            raise SystemExit("e4 cold: an object failed to decrypt")
        size = r["median_object_bytes"]
        label = f"{size / 1024:.0f}\\,KiB" if size < 1 << 20 else f"{size / (1 << 20):.0f}\\,MiB"
        if prev is not None and prev != r["corpus"]:
            body.append(r"\midrule")
        prev = r["corpus"]
        body.append(f"{label} & {r['layout']} & {r['read']['median_ms']:.3f} & "
                    f"{r['unwrap']['median_ms']:.3f} & {r['wrap']['median_ms']:.3f} & "
                    f"{r['write']['median_ms']:.3f} & {r['objects_per_s']:,.0f} & "
                    f"{r['objects']:,}\\\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("rewrapcold.tex", "\n".join(body) + "\n")


def _load_from(dirname, name):
    import json
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = os.path.join(root, dirname, name)
    return json.load(open(p)) if os.path.exists(p) else None


def tab_buildeffect():
    """The same operations through the optimised and the unoptimised build."""
    o3b = load("backend_comparison.json")
    o3p = load("e1_postquantum.json")
    o0b = _load_from("out-o0", "backend_comparison.json") or \
        _load_from("out-reference-o0", "backend_comparison.json")
    o0p = _load_from("out-o0", "e1_postquantum.json") or \
        _load_from("out-reference-o0", "e1_postquantum.json")
    if not all((o3b, o3p, o0b, o0p)):
        return

    def ossl(doc):
        return next(r for r in doc["results"] if r["library"].startswith("OpenSSL"))

    def sign(doc, alg):
        r = next(x for x in doc["results"]
                 if x["alg"] == alg and x["chain_depth"] == 3)
        return r["sign_ms"]["openssl"]["median_ms"]

    rows = [
        ("SHA3-256, 64\\,KiB", "assembly",
         ossl(o3b)["SHA3-256 64KiB"]["median_ms"],
         ossl(o0b)["SHA3-256 64KiB"]["median_ms"]),
        ("ECDSA P-256 sign", "assembly", sign(o3p, "ES256"), sign(o0p, "ES256")),
        ("Ed25519 sign", "C and assembly", sign(o3p, "Ed25519"), sign(o0p, "Ed25519")),
        ("ML-DSA-44 sign", "C", sign(o3p, "ML-DSA-44"), sign(o0p, "ML-DSA-44")),
        ("ML-DSA-65 sign", "C", sign(o3p, "ML-DSA-65"), sign(o0p, "ML-DSA-65")),
        ("ML-DSA-87 sign", "C", sign(o3p, "ML-DSA-87"), sign(o0p, "ML-DSA-87")),
        ("ML-DSA-65 verify", "C", ossl(o3b)["ML-DSA-65 verify"]["median_ms"],
         ossl(o0b)["ML-DSA-65 verify"]["median_ms"]),
        ("ML-KEM-768 encapsulate", "C",
         ossl(o3b)["ML-KEM-768 encap"]["median_ms"],
         ossl(o0b)["ML-KEM-768 encap"]["median_ms"]),
        ("ML-KEM-768 decapsulate", "C",
         ossl(o3b)["ML-KEM-768 decap"]["median_ms"],
         ossl(o0b)["ML-KEM-768 decap"]["median_ms"]),
    ]
    body = [
        r"\begin{table}[t]",
        r"\caption{The same \texttt{cryptography} 50.0.1 over the same OpenSSL "
        r"4.0.2 on the same machine, built with optimisation and as the PyPI "
        r"wheel ships it, without. Medians in milliseconds over 1,000 calls. "
        r"\emph{Path} is how OpenSSL implements the operation on arm64. Only "
        r"the operations written in C move, and every post-quantum one is.}",
        r"\label{tab:buildeffect}",
        r"\begin{tabular}{llrrr}",
        r"\toprule",
        r"Operation & Path & \texttt{-O3} & wheel & Ratio\\",
        r"\midrule",
    ]
    for op, path, a, b in rows:
        body.append(rf"{op} & {path} & {a:.4f} & {b:.4f} & "
                    + f"{b / a:.1f}" + r"$\times$\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("buildeffect.tex", "\n".join(body) + "\n")


if __name__ == "__main__":
    main()
