#!/usr/bin/env python3
"""Generate the manuscript's LaTeX tables from out/*.json.

The point is that no number is ever typed into the paper by hand. Re-run the
experiments, re-run this, and every table updates. A figure in the text that
disagrees with the data becomes impossible rather than merely unlikely.

    python3 src/make_tables.py          # writes manuscript/tables/*.tex
"""

import json
import os
import statistics
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
TAB = os.path.join(ROOT, "manuscript", "tables")


def load(name):
    p = os.path.join(OUT, name)
    return json.load(open(p)) if os.path.exists(p) else None


def emit(name, body):
    os.makedirs(TAB, exist_ok=True)
    with open(os.path.join(TAB, name), "w") as f:
        f.write(body)
    print(f"  {name}")


def machine(d):
    e = d["env"]
    return f"{e['cpu']} ({e['machine']})"


def fmt(x, n=2):
    return f"{x:,.{n}f}"


def tab_baseline():
    d = load("e1_baseline.json")
    if not d:
        return
    r = d["results"]
    rows = []
    for alg in dict.fromkeys(x["alg"] for x in r):
        s = [x for x in r if x["alg"] == alg]
        rows.append(("Ed25519" if alg.lower() == "ed25519" else alg.upper(),
                     statistics.median(x["manifest_bytes"] for x in s),
                     statistics.median(x["manifest_pct_of_image"] for x in s),
                     s[0]["reserve_size"],
                     statistics.median(x["manifest_minus_reserve"] for x in s)))
    body = [
        r"\begin{table}[t]",
        r"\caption{Manifest cost of the seven signature algorithms the C2PA "
        r"specification permits, embedded by \texttt{c2pa-rs} "
        f"{d['env']['c2pa_rs']} into JPEG images at quality 90. Medians over "
        r"the 24 images of the Kodak set. \emph{Reserved} is the fixed block "
        r"the library sets aside for signature, certificate chain, timestamp "
        r"and revocation data; \emph{payload} is the manifest less that "
        r"reservation. Thumbnail generation is disabled.}",
        r"\label{tab:baseline}",
        r"\begin{tabular}{lrrrr}",
        r"\toprule",
        r"Algorithm & Manifest (B) & \% of image & Reserved (B) & Payload (B)\\",
        r"\midrule",
    ]
    for a, mb, pc, res, pay in rows:
        body.append(f"{a} & {mb:,.0f} & {pc:.2f} & {res:,} & {pay:,.0f}\\\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("baseline.tex", "\n".join(body) + "\n")


def tab_pq():
    d = load("e1_postquantum.json")
    if not d:
        return
    r = [x for x in d["results"] if x["chain_depth"] == 3]
    body = [
        r"\begin{table}[t]",
        r"\caption{Manifest cost with post-quantum signatures, three-certificate "
        r"chain, against the classical baseline. Sizes are exact; the percentage "
        r"is the median over the Kodak set with its range in brackets. Signing "
        r"time is the signature over the COSE \texttt{Sig\_structure}, measured "
        r"through both libraries on "
        + machine(d).replace("_", r"\_") +
        r". COSE algorithm identifiers follow RFC~9964.}",
        r"\label{tab:pq}",
        r"\small",
        r"\setlength{\tabcolsep}{4.5pt}",
        r"\begin{tabular}{lrrrrrrr}",
        r"\toprule",
        r" & COSE & Signature & Chain & Manifest & \% of image & "
        r"\multicolumn{2}{c}{Sign (ms)}\\",
        r"\cmidrule(lr){7-8}",
        r"Algorithm & id & (B) & (B) & (B) & median (range) & liboqs & OpenSSL\\",
        r"\midrule",
    ]
    for alg in dict.fromkeys(x["alg"] for x in r):
        s = [x for x in r if x["alg"] == alg]
        p = sorted(x["manifest_pct_of_image"] for x in s)
        t = s[0].get("sign_ms", {})
        oq = f"{t['liboqs']['median_ms']:.3f}" if "liboqs" in t else "--"
        ss = f"{t['openssl']['median_ms']:.3f}" if "openssl" in t else "--"
        body.append(
            f"{alg} & {s[0]['cose_alg_id']} & {s[0]['sig_bytes']:,} & "
            f"{s[0]['chain_der_bytes']:,} & {s[0]['manifest_bytes']:,} & "
            f"{statistics.median(p):.2f} ({p[0]:.2f}--{p[-1]:.2f}) & {oq} & {ss}\\\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("postquantum.tex", "\n".join(body) + "\n")


def tab_certref():
    d = load("e1_certref.json")
    if not d:
        return
    r = [x for x in d["results"] if x["chain_depth"] == 3]
    body = [
        r"\begin{table}[t]",
        r"\caption{Full chain against \texttt{x5t} thumbprint, three-certificate "
        r"chain. Signing cost is unchanged; the whole difference is in bytes. "
        r"The leaf-only configuration, which sits between these two and is the "
        r"one deployable today, is not yet measured "
        r"(Section~\ref{sec:carrying}).}",
        r"\label{tab:certref}",
        r"\begin{tabular}{lrrrr}",
        r"\toprule",
        r"Algorithm & Embedded (B) & Referenced (B) & Saving (B) & Saving (\%)\\",
        r"\midrule",
    ]
    for x in r:
        body.append(
            f"{x['alg']} & {x['cose_embedded_bytes']:,} & "
            f"{x['cose_referenced_bytes']:,} & {x['saving_bytes']:,} & "
            f"{x['saving_pct']:.1f}\\\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("certref.tex", "\n".join(body) + "\n")


def tab_verify():
    d = load("e1_verify.json")
    if not d:
        return
    body = [
        r"\begin{table}[t]",
        r"\caption{Verification cost, embedded chain against certificate "
        r"reference, on " + machine(d).replace("_", r"\_") + r". "
        r"\emph{Warm} resolves the signer from memory, \emph{cold} from a "
        r"local trust store on disk. Chain validation is paid in both cases: "
        r"the reference moves where certificates are found, it does not remove "
        r"the work. Remote resolution is a network round trip and is excluded "
        r"deliberately (Section~\ref{sec:limitations}). Milliseconds, medians.}",
        r"\label{tab:verify}",
        r"\begin{tabular}{llrrrrrr}",
        r"\toprule",
        r" & Signature & Decode & Chain & Verify & Embedded & \multicolumn{2}{c}{Referenced}\\",
        r"\cmidrule(lr){7-8}",
        r"Algorithm & backend & & & & total & warm & cold\\",
        r"\midrule",
    ]
    for x in d["results"]:
        body.append(
            f"{x['alg']} & {x['sig_backend']} & "
            f"{x['decode_embedded_ms']['median_ms']:.4f} & "
            f"{x['validate_chain_ms']['median_ms']:.4f} & "
            f"{x['verify_signature_ms']['median_ms']:.4f} & "
            f"{x['total_embedded_ms']:.4f} & "
            f"{x['total_referenced_warm_ms']:.4f} & "
            f"{x['total_referenced_cold_ms']:.4f}\\\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("verify.tex", "\n".join(body) + "\n")


def tab_keywrap():
    d = load("e4_keywrap.json")
    if not d:
        return
    rows = d["results"]
    prim = [x for x in rows if x.get("part", "primitive") == "primitive"]
    arch = [x for x in rows if x.get("part") == "archive"]
    m = machine(d).replace("_", r"\_")
    body = [
        r"\begin{table}[t]",
        r"\caption{Wrapping one 32-byte AES-256 data key on " + m + r". "
        r"The ML-KEM rows follow the shape of RFC~9629's KEMRecipientInfo "
        r"(the KEM, HKDF-SHA256 to a key-encryption key, AES-256 key wrap) with a "
        r"fixed info string, not the full CMS structure (Section~\ref{sec:archive}). "
        r"\emph{Stored} is what the archive keeps per object. Wrap and unwrap "
        r"cover every step of each construction; medians over 1,000 calls.}",
        r"\label{tab:keywrap}",
        r"\begin{tabular}{llrrrr}",
        r"\toprule",
        r"Scheme & Library & Stored (B) & $\times$RSA-2048 & Wrap (ms) & Unwrap (ms)\\",
        r"\midrule",
    ]
    for x in prim:
        body.append(
            f"{x['scheme']} & {x.get('library', 'OpenSSL')} & "
            f"{x['wrapped_bytes']:,} & {x['wrapped_bytes_vs_rsa2048']:.2f} & "
            f"{x['wrap']['median_ms']:.4f} & {x['unwrap']['median_ms']:.4f}\\\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("keywrap.tex", "\n".join(body) + "\n")
    if not arch:
        return

    def kib(n):
        return (f"{n / 1048576:.0f}\\,MiB" if n >= 1048576
                else f"{n / 1024:.0f}\\,KiB")

    a0 = arch[0]
    body = [
        r"\begin{table}[t]",
        r"\caption{Re-wrapping an archive on disk, " + a0["legacy"] + r" to "
        + a0["new"].split(" (")[0] + r", on " + m + r". \emph{Sidecar} keeps "
        r"the wrapped key in its own file; \emph{embedded} keeps it in the "
        r"object's header, so the object is rewritten when the key grows; "
        r"\emph{reserved} was written with room for the larger key and is "
        r"updated in place. Per-object medians in milliseconds; every write "
        r"is followed by \texttt{fsync}, and reads come from a warm cache. "
        r"Every object was checked to decrypt under the new key.}",
        r"\label{tab:rewrap}",
        r"\begin{tabular}{llrrrrrr}",
        r"\toprule",
        r"Object & Layout & Read & Unwrap & Wrap & Write & Objects/s & Count\\",
        r"\midrule",
    ]
    prev = None
    for x in arch:
        if prev is not None and x["corpus"] != prev:
            body.append(r"\midrule")
        prev = x["corpus"]
        size = kib(x["median_object_bytes"])
        body.append(
            f"{size} & {x['layout']} & {x['read']['median_ms']:.3f} & "
            f"{x['unwrap']['median_ms']:.3f} & {x['wrap']['median_ms']:.3f} & "
            f"{x['write']['median_ms']:.3f} & {x['objects_per_s']:,.0f} & "
            f"{x['objects']:,}\\\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("rewrap.tex", "\n".join(body) + "\n")


def tab_backends():
    d = load("backend_comparison.json")
    if not d:
        return
    pi_path = os.path.join(ROOT, "out-pi", "backend_comparison.json")
    pi = json.load(open(pi_path)) if os.path.exists(pi_path) else None
    ops = ["ML-DSA-65 sign", "ML-DSA-65 verify", "ML-KEM-768 encap", "ML-KEM-768 decap"]

    def cells(doc, op):
        if doc is None:
            return None
        vals = [a[op]["median_ms"] for a in doc["results"] if op in a]
        if len(vals) < 2:
            return ["--", "--", "--"]
        return [f"{vals[0]:.4f}", f"{vals[1]:.4f}", f"{vals[0]/vals[1]:.1f}$\\times$"]

    ncol = 3 + (3 if pi else 0)
    head = r" & \multicolumn{3}{c}{Apple M1 Pro}"
    rule = r"\cmidrule(lr){2-4}"
    if pi:
        head += r" & \multicolumn{3}{c}{Raspberry Pi 5}"
        rule += r"\cmidrule(lr){5-7}"
    body = [
        r"\begin{table}[t]",
        r"\caption{The same algorithms through two implementations, OpenSSL "
        r"through \texttt{cryptography} and liboqs 0.16.0, on two arm64 "
        r"machines. Milliseconds, medians; the ratio is OpenSSL's time over "
        r"liboqs's. The spread between libraries exceeds the spread between "
        r"parameter sets, so any timing reported without naming its "
        r"implementation is uninterpretable. Key encapsulation was not timed "
        r"on the Pi, which measures signatures only.}",
        r"\label{tab:backends}",
        r"\begin{tabular}{l" + "r" * ncol + "}",
        r"\toprule",
        head + r"\\",
        rule,
        r"Operation" + r" & OpenSSL & liboqs & Ratio" * (ncol // 3) + r"\\",
        r"\midrule",
    ]
    for op in ops:
        row = cells(d, op) + (cells(pi, op) if pi else [])
        body.append(f"{op} & " + " & ".join(row) + r"\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("backends.tex", "\n".join(body) + "\n")


def tab_algsweep():
    d = load("e1_algsweep.json")
    if not d:
        return
    r = [x for x in d["results"] if x["chain_depth"] == 3]
    body = [
        r"\begin{table}[t]",
        r"\caption{The three NIST post-quantum signature schemes at chain "
        r"depth three, against the classical baseline. \emph{Chain} is the "
        r"share of the signed structure occupied by certificates. "
        r"\emph{Embedded} and \emph{referenced} are the manifest as a "
        r"percentage of the median image. Every certificate is real; Falcon "
        r"certificates carry a placeholder object identifier of the same "
        r"length (Section~\ref{sec:method-decisions}). "
        r"A dash in the COSE column means no identifier is assigned in the "
        r"IANA registry. "
        r"Signing times are liboqs on " + machine(d).replace("_", r"\_") + r".}",
        r"\label{tab:algsweep}",
        r"\begin{tabular}{llrrrrrr}",
        r"\toprule",
        r" & COSE & Sig. & Chain & Chain & Embed. & Ref. & Sign\\",
        r"Algorithm & id & (B) & (B) & (\%) & (\% img) & (\% img) & (ms)\\",
        r"\midrule",
    ]
    fam = None
    for x in r:
        if fam is not None and x["family"] != fam:
            body.append(r"\midrule")
        fam = x["family"]
        cid = str(x["cose_alg_id"]) if x["cose_alg_assigned"] else "--"
        v = x["sign_ms"]["median_ms"] if "sign_ms" in x else None
        sg = "--" if v is None else (f"{v:.0f}" if v >= 10 else f"{v:.3f}")
        body.append(
            f"{x['alg']} & {cid} & {x['sig_bytes']:,} & "
            f"{x['chain_der_bytes']:,} & {x['chain_share_of_cose_pct']:.1f} & "
            f"{x.get('manifest_pct_of_median_image', 0):.1f} & "
            f"{x.get('manifest_ref_pct_of_median_image', 0):.1f} & {sg}\\\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("algsweep.tex", "\n".join(body) + "\n")


def tab_chaindepth():
    d = load("e1_algsweep.json")
    if not d:
        return
    r = d["results"]
    algs = ["Ed25519", "Falcon-512", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
            "SLH-DSA-SHA2-128s"]
    depths = sorted({x["chain_depth"] for x in r})
    body = [
        r"\begin{table}[t]",
        r"\caption{Manifest size as a percentage of the median image against "
        r"certificate chain depth, embedded form. Each additional certificate "
        r"costs the same again, so the relationship is linear and chain length "
        r"is a lever of the same order as parameter choice. Depth one is a "
        r"self-signed signer, a lower bound rather than a deployable "
        r"configuration.}",
        r"\label{tab:chaindepth}",
        r"\begin{tabular}{l" + "r" * len(depths) + r"}",
        r"\toprule",
        r"Algorithm & " + " & ".join(f"{d_} cert." for d_ in depths) + r"\\",
        r"\midrule",
    ]
    for a in algs:
        rows = [x for x in r if x["alg"] == a]
        if not rows:
            continue
        cells = []
        for d_ in depths:
            m = [y for y in rows if y["chain_depth"] == d_]
            cells.append(f"{m[0].get('manifest_pct_of_median_image', 0):.1f}" if m else "--")
        body.append(f"{a} & " + " & ".join(cells) + r"\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("chaindepth.tex", "\n".join(body) + "\n")


def tab_cache():
    d = load("e1_cache.json")
    if not d:
        return
    r = d["results"]
    batches = sorted({x["batch"] for x in r})
    body = [
        r"\begin{table}[t]",
        r"\caption{Verifying a batch of manifests from one publisher on "
        + machine(d).replace("_", r"\_") + r", with and without caching the "
        r"validated signer. Figures are the speed-up from caching. The benefit "
        r"is available under any of the three carriage options "
        r"(Section~\ref{sec:cache}); it is reported because it has not been "
        r"quantified for manifests, not because it distinguishes them.}",
        r"\label{tab:cache}",
        r"\begin{tabular}{lrr" + "r" * len(batches) + r"}",
        r"\toprule",
        r" & Chain & Signature & \multicolumn{" + str(len(batches)) +
        r"}{c}{Speed-up at batch size}\\",
        r"\cmidrule(lr){4-" + str(3 + len(batches)) + r"}",
        r"Algorithm & (ms) & (ms) & " +
        " & ".join(str(b) for b in batches) + r"\\",
        r"\midrule",
    ]
    for a in dict.fromkeys(x["alg"] for x in r):
        rows = [x for x in r if x["alg"] == a]
        cells = " & ".join(
            f"{[y for y in rows if y['batch'] == b][0]['speedup']:.2f}"
            for b in batches)
        body.append(f"{a} & {rows[0]['validate_chain_ms']:.4f} & "
                    f"{rows[0]['verify_signature_ms']:.4f} & {cells}\\\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("cache.tex", "\n".join(body) + "\n")


def tab_carriage():
    d = load("e1_carriage.json")
    if not d:
        return
    r = d["results"]
    body = [
        r"\begin{table}[t]",
        r"\caption{The three ways a manifest can carry its signer, "
        r"three-certificate chain, on " + machine(d).replace("_", r"\_") +
        r". Path validation costs two signature verifications in all three, "
        r"whichever way the certificates arrive, so verification time is "
        r"reported in Table~\ref{tab:verify} rather than here. "
        r"\emph{Conformant} is whether the C2PA specification permits "
        r"the form today; \emph{unknown signer} is whether a verifier that "
        r"has never seen the signer can still verify, given a trusted CA.}",
        r"\label{tab:carriage}",
        r"\small",
        r"\begin{tabular}{llrrrrll}",
        r"\toprule",
        r" & & Certs & Manifest & \% of & Saving & & Unknown\\",
        r"Algorithm & Carriage & carried & (B) & image & (\%) & Conf. & signer\\",
        r"\midrule",
    ]
    prev = None
    for x in r:
        if prev is not None and x["alg"] != prev:
            body.append(r"\midrule")
        prev = x["alg"]
        name = x["alg"] if x["carriage"] == "full" else ""
        body.append(
            f"{name} & {x['carriage']} & {x['certs_carried']} & "
            f"{x['manifest_bytes']:,} & "
            f"{x.get('manifest_pct_of_median_image', 0):.1f} & "
            f"{x['saving_vs_full_pct']:.1f} & "
            f"{'yes' if x['conformant_today'] else 'no'} & "
            f"{'yes' if x['verifies_unknown_signer_with_trusted_ca'] else 'no'}"
            r"\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("carriage.tex", "\n".join(body) + "\n")


def tab_hash():
    d = load("e1_hash.json")
    if not d:
        return
    r = d["results"]
    body = [
        r"\begin{table}[t]",
        r"\caption{The C2PA hard binding against the signature, on "
        + machine(d).replace("_", r"\_") + r". The hash over the image is "
        r"computed before anything is signed. \emph{Hash share} is the hash "
        r"as a fraction of hash plus signature, so it is the part of "
        r"end-to-end signing cost that no choice of algorithm can change. "
        r"Signing figures are ML-DSA-65 through liboqs.}",
        r"\label{tab:hash}",
        r"\small",
        r"\begin{tabular}{lrrrrr}",
        r"\toprule",
        r" & Image & SHA-256 & Throughput & ML-DSA-65 & Hash\\",
        r"Case & (B) & (ms) & (MB/s) & sign (ms) & share (\%)\\",
        r"\midrule",
    ]
    for x in r:
        body.append(
            f"{x['case']} & {x['image_bytes']:,} & "
            f"{x['hash_ms']['median_ms']:.3f} & {x['throughput_MBps']:.0f} & "
            f"{x['sign_ML-DSA-65_ms']:.3f} & "
            f"{x['hash_share_ML-DSA-65_pct']:.1f}" + r"\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("hash.tex", "\n".join(body) + "\n")


def tab_timestamp():
    d = load("e1_timestamp.json")
    if not d:
        return
    body = [
        r"\begin{table}[t]",
        r"\caption{A manifest as deployments actually ship it. A C2PA manifest "
        r"is normally timestamped, and an RFC~3161 token is a second signature "
        r"with a second certificate chain; a stapled OCSP response is a third. "
        r"Timestamp tokens and OCSP responses are real objects signed under "
        r"each algorithm (Section~\ref{sec:method-decisions}). "
        r"Three-certificate chains, "
        r"percentages against the median Kodak image.}",
        r"\label{tab:timestamp}",
        r"\small",
        r"\begin{tabular}{lrrrrrr}",
        r"\toprule",
        r" & Signature & \ + timestamp & \ + OCSP & & \multicolumn{2}{c}{\% of image}\\",
        r"\cmidrule(lr){6-7}",
        r"Algorithm & only (B) & (B) & (B) & Growth & sig. only & full\\",
        r"\midrule",
    ]
    for x in d["results"]:
        body.append(
            f"{x['alg']} & {x['manifest_signature_only_bytes']:,} & "
            f"{x['manifest_signed_and_timestamped_bytes']:,} & "
            f"{x['manifest_full_bytes']:,} & "
            f"{x['growth_vs_signature_only']:.2f}$\\times$ & "
            f"{x['pct_signature_only']:.1f} & {x['pct_full']:.1f}" + r"\\")
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("timestamp.tex", "\n".join(body) + "\n")


def tab_platforms():
    """One row per machine that produced results, for the method section."""
    seen = {}
    files = [(OUT, f) for f in (sorted(os.listdir(OUT)) if os.path.isdir(OUT) else [])]
    # The Raspberry Pi run keeps its results apart, in out-pi/.
    for extra in ("out-x86", "out-pi-v2"):
        pi_dir = os.path.join(ROOT, extra)
        if os.path.isdir(pi_dir):
            files += [(pi_dir, f) for f in sorted(os.listdir(pi_dir))]
    for d, f in files:
        # Superseded files (the 2.80 GHz Xeon of the first c2pa-rs run) and
        # files written on the analysis host carry machines the paper no
        # longer reports.
        if not f.endswith(".json") or f in ("e1_c2parust.json", "e1_prodchains.json",
                                             "e1_libsize.json", "e1_corpus.json",
                                             "e1_profile.json", "e1_validation.json",
                                             "e1_cache_stale.json", "e1_composite_and.json",
                                             "e1_corpus_pq.json", "e1_trustlist.json",
                                             "e1_validation_extra.json"):
            continue
        try:
            e = json.load(open(os.path.join(d, f)))["env"]
            if d.endswith("out-x86") and os.path.exists(os.path.join(d, "lscpu.txt")):
                flags = open(os.path.join(d, "lscpu.txt")).read().split()
                want = ("aes", "vaes", "pclmulqdq", "sha_ni", "avx2", "avx512f")
                e = dict(e, crypto_features=[x for x in want if x in flags])
        except Exception:
            continue
        if "cpu" not in e or "cryptography" not in e:
            continue
        # Prefer an env block that records the OpenSSL build, which older
        # result files do not.
        if e["cpu"] not in seen or ("openssl_compiler" in e
                                    and "openssl_compiler" not in seen[e["cpu"]]) \
                or ("pi" in e and "pi" not in seen[e["cpu"]]):
            seen[e["cpu"]] = e
    if not seen:
        return
    body = [
        r"\begin{table}[t]",
        r"\caption{Measurement platforms. \emph{Crypto features} lists the "
        r"hardware instructions the CPU advertises. \emph{OpenSSL} is the "
        r"optimisation level recorded in the OpenSSL that \texttt{cryptography} "
        r"links, read from the compiler line OpenSSL embeds in itself; "
        r"Section~\ref{sec:supp-impl} of the supplement explains why it is reported.}",
        r"\label{tab:platforms}",
        r"\small",
        r"\begin{tabular}{p{3.4cm}lp{2.6cm}p{3.2cm}l}",
        r"\toprule",
        r"CPU & Arch. & Crypto features & Software & OpenSSL\\",
        r"\midrule",
    ]
    for cpu, e in seen.items():
        if e.get("pi", {}).get("core"):
            cpu = f"Raspberry Pi 5 ({e['pi']['core']})"
        feats = ", ".join(e["crypto_features"]) or "none reported"
        sw = f"Python {e['python']}, cryptography {e['cryptography']}"
        comp = e.get("openssl_compiler") or ""
        import re as _re
        lvl = _re.search(r"-O\w", comp)
        ossl = (lvl.group(0) if lvl else "no -O flag") if comp else "--"
        arch = "arm64" if e["machine"] in ("arm64", "aarch64") else e["machine"]
        body.append((f"{cpu} & {arch} & {feats} & {sw} & ".replace("_", r"\_")
                     + r"\texttt{" + ossl + r"}\\"))
    body += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("platforms.tex", "\n".join(body) + "\n")


def main():
    if not os.path.isdir(OUT):
        sys.exit("no out/ directory; run the experiments first")
    print("writing manuscript/tables/")
    tab_platforms()
    tab_baseline()
    tab_pq()
    tab_certref()
    tab_verify()
    tab_keywrap()
    tab_backends()
    tab_algsweep()
    tab_chaindepth()
    tab_cache()
    tab_carriage()
    tab_hash()
    tab_timestamp()
    try:
        import make_tables_new
        make_tables_new.main()
    except Exception as e:                      # new data may not exist yet
        print(f"  (new tables skipped: {e})")


if __name__ == "__main__":
    main()
