#!/usr/bin/env python3
"""Tables and text figures for the revision (34n onwards).

Runs after make_tables.py and make_tables_new.py and overwrites the tables
whose experiments changed: carriage now has four forms and two anchor
placements, every chain omits the root, PS256 is the deployed classical
baseline, timings carry across-run intervals, and several experiments are new
(corpus, validation, stream, extras, cache lifecycles).

It also writes tables/numbers.tex: one macro per figure the prose cites, so a
number in the text is read from the same JSON as the tables.

    python3 src/make_tables_v2.py         # reads $LINEA_TABLE_IN or out/
"""

import json
import os
import statistics

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.environ.get("LINEA_TABLE_IN", os.path.join(ROOT, "out"))
TAB = os.path.join(ROOT, "manuscript", "tables")
SUPP = os.path.join(ROOT, "manuscript", "tables")
NUM = {}

ALG_ORDER = ["Ed25519", "ES256", "PS256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
SHORT = {"Ed25519": "Ed25519", "ES256": "ES256", "PS256": "PS256",
         "ML-DSA-44": "ML-DSA-44", "ML-DSA-65": "ML-DSA-65", "ML-DSA-87": "ML-DSA-87"}


TOKEN = {"Ed25519": "Ed", "ES256": "ES", "PS256": "PS",
         "ML-DSA-44": "DSAfortyfour", "ML-DSA-65": "DSAsixtyfive",
         "ML-DSA-87": "DSAeightyseven"}


def tok(alg):
    return TOKEN[alg]


def load(name, base=None):
    p = os.path.join(base or OUT, name)
    return json.load(open(p)) if os.path.exists(p) else None


def emit(name, lines):
    os.makedirs(TAB, exist_ok=True)
    with open(os.path.join(TAB, name), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  {name}")


def machine(d):
    e = d["env"]
    return f"{e['cpu']}".replace("_", r"\_")


def num(name, value):
    """Register a figure for numbers.tex. Names are letters only."""
    NUM[name] = value


def kb(b):
    return f"{b / 1000:.1f}"


def ms(t, n=3):
    return f"{t['median_ms']:.{n}f}" if isinstance(t, dict) else f"{t:.{n}f}"


def ci(t, n=3):
    c = t.get("ci95_ms") if isinstance(t, dict) else None
    if not c:
        return ""
    return f" [{c[0]:.{n}f}, {c[1]:.{n}f}]"


def runs_note(d):
    r = d["env"].get("runs")
    return (f" Times are medians over {r} independent runs, each the median of "
            r"its own repetitions; Table~\ref{tab:ci} in the supplement gives "
            r"their intervals across runs." if r else "")


# --- Table: post-quantum manifest cost -------------------------------------------

def tab_pq():
    d = load("e1_postquantum.json")
    if not d:
        return
    r = [x for x in d["results"] if x["chain_depth"] == 3]
    by = {}
    for x in r:
        by.setdefault(x["alg"], []).append(x)
    ps = by["PS256"][0]["manifest_bytes"]
    es = by["ES256"][0]["manifest_bytes"]
    lines = [
        r"\begin{table}[t]",
        r"\caption{Manifest cost by signature algorithm with the signer's "
        r"certificate and its intermediate in \texttt{x5chain}, the root "
        r"omitted as C2PA~2.5 says it should be. Sizes are exact; the percentage is the "
        r"median over the Kodak set with its range. \emph{vs ES256} and "
        r"\emph{vs PS256} compare with the two algorithms deployed signers use "
        r"(Section~\ref{sec:prodchains}). Signing time is the signature "
        r"over the COSE \texttt{Sig\_structure} on " + machine(d) + ", through "
        r"liboqs for ML-DSA and OpenSSL for the classical rows."
        + runs_note(d) + "}",
        r"\label{tab:pq}",
        r"\small", r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{lrrrrrrrr}", r"\toprule",
        r" & COSE & Sig. & Chain & Manifest & \% of image & vs & vs & Sign\\",
        r"Algorithm & id & (B) & (B) & (B) & median (range) & ES256 & PS256 & (ms)\\",
        r"\midrule",
    ]
    for alg in ALG_ORDER:
        if alg not in by:
            continue
        s = by[alg]
        p = sorted(x["manifest_pct_of_image"] for x in s)
        t = s[0].get("sign_ms", {})
        best = t.get("liboqs") or t.get("openssl")
        m = s[0]["manifest_bytes"]
        lines.append(
            f"{alg} & {s[0]['cose_alg_id']} & {s[0]['sig_bytes']:,} & "
            f"{s[0]['chain_der_bytes']:,} & {m:,} & "
            f"{statistics.median(p):.2f} ({p[0]:.2f}--{p[-1]:.2f}) & "
            f"{m / es:.1f}$\\times$ & {m / ps:.1f}$\\times$ & "
            f"{ms(best)}" + r"\\")
        key = tok(alg)
        num(f"manifest{key}", f"{m:,}")
        num(f"manifestkB{key}", kb(m))
        num(f"cose{key}", f"{s[0]['cose_bytes']:,}")
        num(f"chainShareMan{key}", f"{100 * s[0]['chain_der_bytes'] / m:.0f}")
        num(f"vsPS{key}", f"{m / ps:.1f}")
        num(f"vsES{key}", f"{m / es:.1f}")
        num(f"pctimg{key}", f"{statistics.median(p):.1f}")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("postquantum.tex", lines)


# --- Table: carriage --------------------------------------------------------------

def tab_carriage():
    d = load("e1_carriage.json")
    if not d:
        return
    r = d["results"]
    algs = [a for a in ALG_ORDER if any(x["alg"] == a for x in r)]
    cases = [("root", "root"), ("chain", "root"), ("leaf", "issuing CA"),
             ("leaf", "root"), ("thumb", "root")]
    label = {("root", "root"): "Leaf, int., root",
             ("chain", "root"): "Leaf, int.",
             ("leaf", "issuing CA"): "Leaf (issuer is anchor)",
             ("leaf", "root"): "Leaf (int.\\ provisioned)",
             ("thumb", "root"): "Thumbprint"}
    conf = {("root", "root"): "yes$^a$", ("chain", "root"): "yes",
            ("leaf", "issuing CA"): "yes", ("leaf", "root"): "no",
            ("thumb", "root"): "no"}
    lines = [
        r"\begin{table*}[t]",
        r"\caption{Carrying the signer. Manifest bytes by carriage form and "
        r"algorithm, three-certificate hierarchy. \emph{Path} is the number "
        r"of signatures path validation checks, set by where the trust anchor "
        r"sits; \emph{Holds} is what the verifier must already have; \emph{int.} is the intermediate. "
        r"$^a$C2PA~2.5 says the root should not be included. The leaf-only "
        r"form conforms only when the leaf's issuer is itself on the trust "
        r"list.}",
        r"\label{tab:carriage}",
        r"\small", r"\setlength{\tabcolsep}{3.5pt}",
        r"\begin{tabular}{llcl" + "r" * len(algs) + "}", r"\toprule",
        (r" & & & & " + " & " * (len(algs) - 3) + r"\multicolumn{3}{c}{ML-DSA}\\"
         + r"\cmidrule(l){%d-%d}" % (len(algs) + 2, len(algs) + 4)
         if [a for a in algs if a.startswith("ML-DSA")] == algs[-3:] else ""),
        r"\texttt{x5chain} & Holds & Path & Conf. & "
        + " & ".join(a[-2:] if a.startswith("ML-DSA") else SHORT[a] for a in algs) + r"\\",
        r"\midrule",
    ]
    hold = {("root", "root"): "root", ("chain", "root"): "root",
            ("leaf", "issuing CA"): "issuing CA",
            ("leaf", "root"): "root, int.",
            ("thumb", "root"): "root, int., leaf"}
    for c in cases:
        row = [next(x for x in r if x["alg"] == a and x["carriage"] == c[0]
                    and x["anchor"] == c[1]) for a in algs]
        lines.append(f"{label[c]} & {hold[c]} & {row[0]['path_verifications']} & "
                     f"{conf[c]} & " + " & ".join(f"{x['manifest_bytes']:,}" for x in row)
                     + r"\\")
    lines.append(r"\midrule")
    for c in [("leaf", "issuing CA"), ("thumb", "root"), ("root", "root")]:
        row = [next(x for x in r if x["alg"] == a and x["carriage"] == c[0]
                    and x["anchor"] == c[1]) for a in algs]
        nm = {"leaf": "Saving, leaf only", "thumb": "Saving, thumbprint",
              "root": "Cost of the root"}[c[0]]
        vals = [(-x["saving_vs_chain_pct"] if c[0] == "root" else x["saving_vs_chain_pct"])
                for x in row]
        lines.append(f"\\multicolumn{{4}}{{l}}{{{nm} (\\%)}} & "
                     + " & ".join(f"{v:.0f}" for v in vals) + r"\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
    emit("carriage.tex", lines)
    for a in algs:
        k = tok(a)
        g = {(x["carriage"], x["anchor"]): x for x in r if x["alg"] == a}
        num(f"carrChain{k}", f"{g[('chain', 'root')]['manifest_bytes']:,}")
        num(f"carrRoot{k}", f"{g[('root', 'root')]['manifest_bytes']:,}")
        num(f"carrLeaf{k}", f"{g[('leaf', 'issuing CA')]['manifest_bytes']:,}")
        num(f"carrThumb{k}", f"{g[('thumb', 'root')]['manifest_bytes']:,}")
        num(f"saveLeaf{k}", f"{g[('leaf', 'issuing CA')]['saving_vs_chain_pct']:.0f}")
        num(f"saveThumb{k}", f"{g[('thumb', 'root')]['saving_vs_chain_pct']:.0f}")
        num(f"costRoot{k}", f"{-g[('root', 'root')]['saving_vs_chain_pct']:.0f}")
        num(f"pathRoot{k}", ms(g[('chain', 'root')]['verify_path_ms']))
        num(f"pathICA{k}", ms(g[('leaf', 'issuing CA')]['verify_path_ms']))


# --- Table: the timestamped manifest and its composition ------------------------

def tab_timestamp():
    d = load("e1_timestamp.json")
    if not d:
        return
    r = {x["alg"]: x for x in d["results"]}
    ps = r["PS256"]["manifest_signed_and_timestamped_bytes"]
    es = r["ES256"]["manifest_signed_and_timestamped_bytes"]
    lines = [
        r"\begin{table}[t]",
        r"\caption{The manifest a deployment ships: signature, then RFC~3161 "
        r"timestamp, then stapled revocation evidence, as most production "
        r"signatures carry a timestamp and a quarter also carry revocation "
        r"evidence (Section~\ref{sec:prodchains}). Signer and time-stamping "
        r"authority each carry their certificate and intermediate, roots "
        r"omitted; the \emph{+ OCSP} column adds a response from a delegated "
        r"responder, with the responder's certificate inside it, the form the "
        r"reference implementation honours. Every object "
        r"is real and signed under the named algorithm. "
        r"Figure~\ref{fig:compose} breaks the bytes down by role.}",
        r"\label{tab:timestamp}",
        r"\small", r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{lrrrrrr}", r"\toprule",
        r" & Signature & + timestamp & + OCSP & \multicolumn{2}{c}{Timestamped vs} & \% of\\",
        r"\cmidrule(lr){5-6}",
        r"Algorithm & (B) & (B) & (B) & ES256 & PS256 & image\\",
        r"\midrule",
    ]
    for a in ALG_ORDER:
        if a not in r:
            continue
        x = r[a]
        t = x["manifest_signed_and_timestamped_bytes"]
        lines.append(f"{a} & {x['manifest_signature_only_bytes']:,} & {t:,} & "
                     f"{x.get('manifest_full_bytes', 0):,} & {t / es:.1f}$\\times$ & "
                     f"{t / ps:.1f}$\\times$ & "
                     f"{x.get('pct_timestamped', 0):.1f}" + r"\\")
        k = tok(a)
        num(f"tsSig{k}", f"{x['manifest_signature_only_bytes']:,}")
        num(f"tsTst{k}", f"{t:,}")
        num(f"tsTstkB{k}", kb(t))
        num(f"tsFull{k}", f"{x.get('manifest_full_bytes', 0):,}")
        num(f"tsVsPS{k}", f"{t / ps:.1f}")
        num(f"tsVsES{k}", f"{t / es:.1f}")
        num(f"tokenBytes{k}", f"{x['timestamp_token_bytes']:,}")
        oc = x.get("ocsp", {})
        if x.get("manifest_full_ca_signed_bytes"):
            num(f"tsFullCA{k}", f"{x['manifest_full_ca_signed_bytes']:,}")
        if "ca_signed" in oc:
            num(f"ocspCA{k}", f"{oc['ca_signed']['bytes']:,}")
            num(f"ocspDel{k}", f"{oc['delegated']['bytes']:,}")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("timestamp.tex", lines)


# --- Table: where verification time goes ----------------------------------------

def tab_verify():
    d = load("e1_verify.json")
    if not d:
        return
    r = {x["alg"]: x for x in d["results"]}
    hb = next(iter(r.values()))["hash_content_ms"]["median_image"]["bytes"]
    lines = [
        r"\begin{table*}[t]",
        r"\caption{Where the cryptographic work of validating one timestamped "
        r"image goes, in milliseconds on " + machine(d) + r". \emph{Path} "
        r"checks leaf and intermediate up to the root anchor; \emph{TST} and "
        r"\emph{TSA path} are the timestamp's signature and certificate path; "
        r"\emph{Hash} is SHA-256 over the content, for the 13th of the 24 Kodak images by size "
        rf"({hb:,}\,B) "
        r"and for a 4\,MiB phone JPEG. Assertion hashing, ingredients, "
        r"revocation and policy checks are outside the boundary. \emph{Total} "
        r"is the sum of the row for each image."
        + runs_note(d) + "}",
        r"\label{tab:verify}",
        r"\small", r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{lrrrrrrrrr}", r"\toprule",
        r" & Decode & Path & Manifest & TST & TSA & \multicolumn{2}{c}{Hash} & "
        r"\multicolumn{2}{c}{Total}\\",
        r"\cmidrule(lr){7-8}\cmidrule(lr){9-10}",
        r"Algorithm & & & signature & & path & median & 4\,MiB & median & 4\,MiB\\",
        r"\midrule",
    ]
    for a in ALG_ORDER:
        if a not in r:
            continue
        x = r[a]
        h = x["hash_content_ms"]
        lines.append(
            f"{a} & {ms(x['decode_embedded_ms'])} & {ms(x['validate_chain_ms'])} & "
            f"{ms(x['verify_signature_ms'])} & {ms(x['verify_timestamp_signature_ms'])} & "
            f"{ms(x['validate_tsa_path_ms'])} & {ms(h['median_image'])} & "
            f"{ms(h['phone_jpeg'], 2)} & {x['complete_median_image_ms']:.3f} & "
            f"{x['complete_phone_jpeg_ms']:.2f}" + r"\\")
        k = tok(a)
        num(f"vPath{k}", ms(x["validate_chain_ms"]))
        num(f"vSig{k}", ms(x["verify_signature_ms"]))
        num(f"vTotal{k}", f"{x['total_embedded_ms']:.3f}")
        num(f"vComplete{k}", f"{x['complete_median_image_ms']:.2f}")
        num(f"vCompleteFactor{k}", f"{x['complete_median_image_ms'] / x['total_embedded_ms']:.1f}")
        num(f"vCompletePhone{k}", f"{x['complete_phone_jpeg_ms']:.2f}")
        num(f"vPathShare{k}", f"{x['chain_share_of_complete_median_pct']:.0f}")
        sigpath = x["validate_chain_ms"]["median_ms"] / x["total_embedded_ms"] * 100
        num(f"vPathShareSig{k}", f"{sigpath:.0f}")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
    emit("verify.tex", lines)


# --- Table: caching under signer lifecycles (supplement) -------------------------

def tab_cache():
    d = load("e1_cache.json")
    if not d:
        return
    r = d["results"]
    algs = [a for a in ALG_ORDER if any(x["alg"] == a for x in r)]
    num("cachepublishers", f"{r[0]['publishers']}")
    num("cachestream", f"{r[0]['stream']:,}")
    lines = [
        r"\begin{table}[ht]",
        r"\caption{Caching validated certificates in a verifier, under three "
        r"leaf lifecycles. A stream of " + str(r[0]["stream"]) + r" manifests "
        r"from " + str(r[0]["publishers"]) + r" publishers (Zipf), each "
        r"publisher with its own issuing CA; LRU cache of the given number "
        r"of certificates, entries tagged with the trust-list snapshot. "
        r"Speed-up is whole-stream wall time against no cache. "
        r"\emph{Naive} is an untagged cache of 4,096: half-way through, one "
        r"publisher's CA is distrusted, and the column counts that "
        r"publisher's manifests it still accepts; tagged caches accept none.}",
        r"\label{tab:cache}",
        r"\small", r"\setlength{\tabcolsep}{3.5pt}",
        r"\begin{tabular}{llrrrr}", r"\toprule",
        r" & & \multicolumn{3}{c}{Speed-up, tagged cache of} & Naive\\",
        r"\cmidrule(lr){3-5}",
        r"Algorithm & Leaves & 16 & 256 & 4,096 & accepts\\", r"\midrule",
    ]
    for a in algs:
        for lc in ("long-lived", "rotating", "per-image"):
            g = {(x["cache_entries"], x["snapshot_tagged"]): x for x in r
                 if x["alg"] == a and x["lifecycle"] == lc}
            wrong = g[(4096, False)]["accepted_after_distrust"]
            tot = wrong + g[(4096, False)]["rejected_after_distrust"]
            lines.append(f"{a if lc == 'long-lived' else ''} & {lc} & "
                         f"{g[(16, True)]['speedup_vs_no_cache']:.2f} & "
                         f"{g[(256, True)]['speedup_vs_no_cache']:.2f} & "
                         f"{g[(4096, True)]['speedup_vs_no_cache']:.2f} & "
                         f"{wrong}/{tot}" + r"\\")
            k = tok(a)
            lck = {"long-lived": "Long", "rotating": "Rot", "per-image": "Per"}[lc]
            num(f"cache{lck}{k}", f"{g[(4096, True)]['speedup_vs_no_cache']:.1f}")
            num(f"naive{lck}{k}", f"{wrong}")
            num(f"naiveTot{lck}{k}", f"{tot}")
        if a != algs[-1]:
            lines.append(r"\midrule")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("cache.tex", lines)


# --- Table: mixed chains, with the timestamp ------------------------------------

def tab_mixedchain():
    d = load("e1_mixedchain.json")
    if not d:
        return
    rename = {"Leaf only": "Leaf migrated"}
    lines = [
        r"\begin{table}[t]",
        r"\caption{Chains whose levels migrate at different times, leaf first "
        r"and root last; the root signs the intermediate but is not carried. "
        r"\emph{Signer PQ} is whether every load-bearing signature in the "
        r"signer's path is post-quantum. The last two columns add an RFC~3161 "
        r"timestamp: with a classical TSA the time evidence stays forgeable, "
        r"so a quantum adversary can backdate the manifest even when the "
        r"signer's path is post-quantum.}",
        r"\label{tab:mixedchain}",
        r"\small", r"\setlength{\tabcolsep}{3.5pt}",
        r"\begin{tabular}{llrcrr}", r"\toprule",
        r" & Chain & COSE & Signer & \multicolumn{2}{c}{+ timestamp (B)}\\",
        r"\cmidrule(lr){5-6}",
        r"Stage & leaf/int./root & (B) & PQ & ES256 TSA & ML-DSA-65 TSA\\",
        r"\midrule",
    ]
    stages = ["Classical", "Leaf only", "Leaf and intermediate", "PKI first, leaves last",
              "Fully migrated", "Assurance ladder", "Ladder inverted", "Cheap leaves, strong root"]
    rows = sorted(d["results"], key=lambda x: stages.index(x["stage"])
                  if x["stage"] in stages else len(stages))
    for x in rows:
        w = {y["tsa_alg"]: y for y in x.get("whole_manifest", [])}
        es = f"{w['ES256']['manifest_crypto_bytes']:,}" if "ES256" in w else "--"
        pq = f"{w['ML-DSA-65']['manifest_crypto_bytes']:,}" if "ML-DSA-65" in w else "--"
        lines.append(f"{rename.get(x['stage'], x['stage'])} & {x['label']} & "
                     f"{x['cose_bytes']:,} & {'yes' if x['quantum_resistant'] else 'no'} & "
                     f"{es} & {pq}" + r"\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("mixedchain.tex", lines)


# --- Supplement: compression and composites --------------------------------------

def tab_extras():
    d = load("e1_extras.json")
    if not d:
        return
    comp = [x for x in d["results"] if x["experiment"] == "compression"]
    names = [k for k in ("zlib-9", "zstd-19", "brotli-11") if k in comp[0]]
    lines = [
        r"\begin{table}[ht]",
        r"\caption{General-purpose compression of the COSE signature "
        r"(leaf and intermediate carried) and of signature plus timestamp "
        r"token, saving in per cent at each compressor's highest setting. "
        r"What compresses is X.509 structure and names; ML-DSA keys and "
        r"signatures do not.}",
        r"\label{tab:compress}",
        r"\small", r"\begin{tabular}{llr" + "r" * len(names) + "}", r"\toprule",
        r"Algorithm & Object & Bytes & " + " & ".join(names) + r"\\", r"\midrule",
    ]
    for a in ALG_ORDER:
        for obj in ("signature", "signature+timestamp"):
            x = next((y for y in comp if y["alg"] == a and y["carriage"] == "chain"
                      and y["object"] == obj), None)
            if not x:
                continue
            lines.append(f"{a if obj == 'signature' else ''} & "
                         f"{'signature' if obj == 'signature' else '+ timestamp'} & "
                         f"{x['bytes']:,} & " + " & ".join(
                             f"{x[n + '_saving_pct']:.1f}" for n in names) + r"\\")
            k = tok(a)
            if obj == "signature":
                best = max(x[n + "_saving_pct"] for n in names)
                num(f"compress{k}", f"{best:.0f}")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("compress.tex", lines)

    andt = load("e1_composite_and.json", os.environ.get("LINEA_REF_IN", os.path.join(ROOT, "out-reference")))
    if andt and not all(all(v for k, v in x.items() if k != "alg") for x in andt["results"]):
        raise SystemExit("composite AND test failed")
    comps = sorted((x for x in d["results"] if x["experiment"] == "composite"),
                   key=lambda x: x["alg"])
    lines = [
        r"\begin{table}[ht]",
        r"\caption{Composite signatures (draft-ietf-lamps-pq-composite-sigs): "
        r"real certificates signed by both component keys, leaf and "
        r"intermediate carried. Object identifiers are placeholders of the "
        r"draft's length and no COSE identifier is assigned. This is a "
        r"component-cost construction, not an implementation of the draft's "
        r"combiner (domain separator, prehash and context), which changes what "
        r"is signed but not the length of any key or signature. Times are the "
        r"two component operations in sequence. Verification is AND: with "
        r"either component corrupted or the classical half removed, every "
        r"composite was rejected.}",
        r"\label{tab:composite}",
        r"\small", r"\begin{tabular}{lrrrrrr}", r"\toprule",
        r" & Public & Sig. & Leaf cert & COSE & Sign & Verify\\",
        r"Pair & key (B) & (B) & (B) & (B) & (ms) & (ms)\\", r"\midrule",
    ]
    for x in comps:
        lines.append(f"{x['alg']} & {x['public_key_bytes']:,} & {x['sig_bytes']:,} & "
                     f"{x['cert_der_bytes_each'][0]:,} & {x['cose_bytes']:,} & "
                     f"{ms(x['sign_ms'])} & {ms(x['verify_ms'])}" + r"\\")
        if x["alg"] == "ML-DSA-65+ES256":
            num("compositeCose", f"{x['cose_bytes']:,}")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("composite.tex", lines)


# --- Video stream ---------------------------------------------------------------

def tab_stream():
    d = load("e6_stream.json", os.environ.get("LINEA_PI_IN", OUT))
    if not d:
        return
    r = d["results"]
    pick = [a for a in ("Ed25519", "PS256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87")
            if any(x["alg"] == a for x in r)]
    lines = [
        r"\begin{table*}[t]",
        r"\caption{Signing an encoded stream on the Raspberry Pi 5, one core. "
        r"\emph{Frame} signs every encoded access unit with the chain attached "
        r"(an upper bound, not a C2PA method); \emph{manifest} is C2PA~2.5 "
        r"Section~15.4, a manifest per segment; \emph{VSI} is Section~15.5, "
        r"the chain once and a session-key signature per segment. Provenance "
        r"rate is the bitrate the signatures add; \emph{latency} is from "
        r"segment close to signature (last fragment's hash plus signing). "
        r"A player can authenticate a segment only once it holds all of it, "
        r"so verification lags by at least the segment length. The provenance "
        r"rate depends on the size of each signature and on how often one is "
        r"sent, not on the video, so it is the same for both streams; the "
        r"latency is not. Streams of " + str(min(d["env"].get("streams_seconds", {"": 48}).values()))
        + r"\,s; medians over every segment of three passes.}",
        r"\label{tab:stream}",
        r"\small", r"\setlength{\tabcolsep}{3.2pt}",
        r"\begin{tabular}{llr" + "rr" * len(pick) + "}", r"\toprule",
        r" & & Seg. & " + " & ".join(
            f"\\multicolumn{{2}}{{c}}{{{a}}}" for a in pick) + r"\\",
        "".join(f"\\cmidrule(lr){{{4 + 2 * i}-{5 + 2 * i}}}" for i in range(len(pick))),
        r"Stream & Method & (s) & " + " & ".join(
            ["kbit/s & ms"] * len(pick)) + r"\\", r"\midrule",
    ]
    for stream in ("1080p H.264", "4K HEVC"):
        for method, seg in [("frame", 1), ("manifest", 1), ("manifest", 2),
                            ("manifest", 4), ("vsi", 1), ("vsi", 2), ("vsi", 4),
                            ("vsi", 6)]:
            cells = []
            for a in pick:
                x = next((y for y in r if y["alg"] == a and y["stream"] == stream
                          and y["method"] == method and y["segment_s"] == seg), None)
                cells.append(f"{x['prov_kbps']:,.1f} & {x['latency_after_close_ms']:.2f}"
                             if x else "-- & --")
            mname = {"frame": "frame", "manifest": "manifest", "vsi": "VSI"}[method]
            lines.append(f"{stream if (method, seg) == ('frame', 1) else ''} & {mname} & "
                         f"{'--' if method == 'frame' else seg} & " + " & ".join(cells) + r"\\")
        if stream == "1080p H.264":
            lines.append(r"\midrule")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
    emit("stream.tex", lines)
    for x in r:
        if x["alg"] == "ML-DSA-65" and x["stream"] == "1080p H.264":
            tag = {"frame": "Frame", "manifest": "Man", "vsi": "Vsi"}[x["method"]]
            sname = {1: "One", 2: "Two", 4: "Four", 6: "Six"}[x["segment_s"]]
            num(f"stream{tag}{sname}Kbps", f"{x['prov_kbps']:,.1f}")
            num(f"stream{tag}{sname}Share", f"{x['prov_share_of_video_pct']:.2f}")
            if x.get("init_bytes"):
                num("streamVsiInit", f"{x['init_bytes']:,}")
    seg = [x for x in r if x["method"] != "frame"]
    num("streamPnnMax", f"{max(x['process_ms_p99'] for x in seg):.1f}")
    num("streamCpuMax", f"{100 * max(x['cpu_fraction'] for x in seg):.2f}")
    num("streamLatMax", f"{max(x['latency_after_close_ms'] for x in seg):.1f}")
    num("streamSeconds", f"{min(d['env'].get('streams_seconds', {'': 48}).values())}")
    six = [x["segments"] for x in seg if x["segment_s"] == 6]
    if six:
        num("streamSixSegs", f"{min(six)}")
    num("streamSamplesMin", f"{min(x.get('samples', 0) for x in seg):,}")
    frame = [x for x in r if x["method"] == "frame"]
    num("streamFrameCpuMax", f"{100 * max(x['cpu_fraction'] for x in frame):.0f}")
    # Detection: one table over every algorithm, stream and segment length.
    names = [("drop", "Segment dropped"), ("reorder", "Segments reordered"),
             ("truncate_within_segment", "Bytes truncated within a segment"),
             ("replay", "Segment replayed in the same stream"),
             ("substitute", "Segment content substituted"),
             ("cross_stream_replay", "Segment from another stream, same signer"),
             ("suffix_removed", "Last segments removed"),
             ("suffix_removed_with_end", "\\quad with an announced length"),
             ("missing_init", "Initial manifest missing"),
             ("session_key_expired", "Session key expired")]
    det = {}
    for x in seg:
        for k, v in (x.get("detected") or {}).items():
            det.setdefault((k, x["method"]), set()).add(", ".join(v))
    if det:
        lines = [r"\begin{table}[ht]",
                 r"\caption{What a verifier detects when a signed stream is manipulated, "
                 r"for every algorithm, stream and segment length of Table~\ref{tab:stream}. "
                 r"The verifier checks each signature, the segment's hash, that sequence "
                 r"numbers advance by one, that each segment names the stream it is "
                 r"playing, and for VSI the session key's validity. \emph{gap} and "
                 r"\emph{order}: a sequence number skips or goes back; \emph{hash}: the "
                 r"segment's bytes do not match; \emph{foreign}: the segment names another "
                 r"stream; \emph{short}: fewer segments than announced. A stream that "
                 r"stops early is indistinguishable from one whose tail was removed unless "
                 r"its length is announced in signed data or the player times out.}",
                 r"\label{tab:streamdetect}", r"\small",
                 r"\begin{tabular}{lll}", r"\toprule",
                 r"Manipulation & Manifest per segment & VSI\\", r"\midrule"]
        for k, lab in names:
            cells = []
            for m in ("manifest", "vsi"):
                v = det.get((k, m))
                txt = "n/a" if v is None else " / ".join(sorted(v))
                txt = txt.replace("foreign stream", "foreign").replace("no session key", "no key, unverifiable") \
                         .replace("session key expired", "rejected (expired)")
                cells.append(txt)
            lines.append(f"{lab} & {cells[0]} & {cells[1]}" + r"\\")
        lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
        emit("streamdetect.tex", lines)


# --- Validation through the patched reference implementation ---------------------

VAL_ROWS = [
    ("Leaf and intermediate", ["chain_noroot"]),
    ("\\quad timestamped", ["chain_noroot_tsa"]),
    ("Leaf, intermediate, root", ["chain_withroot_tsa"]),
    ("Leaf only, issuer is anchor", ["leafonly_anchor_int"]),
    ("Leaf only, intermediate missing", ["leafonly_anchor_root"]),
    ("Unknown anchor", ["unknown_anchor"]),
    ("Thumbprint (\\texttt{x5t})", ["x5t_thumbprint"]),
    ("Leaf EKU serverAuth", ["eku_serverauth", "eku_serverauth_direct"]),
    ("Leaf EKU timeStamping only$^\\dagger$", ["eku_timestamping_claimsigning_policy"]),
    ("COSE algorithm $\\neq$ key (ML-DSA-44 only)", ["alg_header_mismatch"]),
    ("Image changed after signing", ["image_modified"]),
    ("Signature bit flipped", ["sig_bitflip"]),
    ("Expired leaf, timestamp inside validity", ["expired_leaf_with_tst"]),
    ("Expired leaf, no timestamp", ["expired_leaf_no_tst"]),
    ("Expired leaf, timestamp over other data", ["expired_leaf_wrong_imprint_tst"]),
    ("Expired leaf, TSA not trusted", ["expired_leaf_untrusted_tst"]),
    ("Timestamp over other data", ["tst_wrong_imprint"]),
    ("TSA not trusted", ["tsa_anchor_absent"]),
    ("TSA certificate lacks timeStamping$^\\dagger$", ["tsa_no_timestamping_eku"]),
    ("ML-DSA-65 TSA", ["pqtsa_good"]),
    ("\\quad timestamp over other data", ["pqtsa_wrong_imprint"]),
    ("\\quad expired leaf, timestamp inside validity", ["expired_leaf_with_pqtst"]),
    ("OCSP, CA-signed, revoked", ["ocsp_revoked"]),
    ("OCSP, delegated responder, revoked", ["ocsp_deleg_revoked"]),
]

TST_CODE = (("timeStamp.trusted", "t"), ("timeStamp.mismatch", "m"),
            ("timeStamp.untrusted", "u"))


def _outcome(x):
    if (x.get("sign") or {}).get("sign_error"):
        return "SR"
    if x.get("reader_error"):
        return "E"
    return {"Trusted": "T", "Valid": "V", "Invalid": "I"}.get(x.get("validation_state"), "?")


def _tst(x):
    codes = x.get("timestamp_codes") or []
    for c, k in TST_CODE:
        if c in codes:
            return k
    return "--"


def tab_validation():
    d = load("e1_validation.json", os.environ.get("LINEA_REF_IN", os.path.join(ROOT, "out-reference")))
    if not d:
        return
    r = d["results"]
    expect_map = {"Trusted": "T", "not Trusted": "not T", "sign refused": "refused",
                  "Invalid": "I", "any": "any", "reject": "reject"}

    def cell(cases, algs, patch, f=_outcome):
        outs, ok = [], True
        for c in cases:
            xs = [x for x in r if x["case"] == c and x["alg"] in algs and x["patch"] == patch]
            if not xs:
                continue
            o = "/".join(sorted({f(x) for x in xs}))
            outs.append(o)
            ok = ok and all(x.get("meets_expected", True) for x in xs)
        if not outs:
            return "", True
        if len(outs) > 1 and cases[-1].endswith("_direct"):
            txt = f"{outs[0]} (direct {outs[1]})"
        else:
            txt = "/".join(sorted(set("/".join(outs).split("/"))))
        return (txt if ok or f is not _outcome else f"\\textbf{{{txt}}}"), ok

    PQ = ("mldsa44", "mldsa65", "mldsa87")
    lines = [
        r"\begin{table*}[t]",
        r"\caption{Validation through the reference implementation, \texttt{c2pa-rs} "
        r"at commit \texttt{" + d["env"]["c2pa_rs"][:7] + r"} with our RFC~9964 "
        r"patch: a selection of the " + str(len({x['case'] for x in r})) + r" cases; "
        r"Table~\ref{tab:valfull} in the supplement lists every case for every "
        r"algorithm. T, V and I are the library's Trusted, Valid and Invalid; E is a "
        r"reader error; SR means the library refused to sign, and \emph{direct} gives "
        r"the result for a COSE structure our harness built with the same "
        r"certificate. \emph{Expected} is what C2PA~2.5 prescribes. ML-DSA appears "
        r"twice: with the signing patch alone (p1), path validation has no ML-DSA "
        r"mapping and no chain becomes Trusted; p2 adds it. \emph{TST} is the "
        r"timestamp's own status under p2: t trusted, m imprint mismatch, u "
        r"untrusted; a mismatched or untrusted timestamp is ignored and the signer is "
        r"judged at the current time. Unless the row says otherwise the time-stamping "
        r"authority is ES256; the indented rows use an ML-DSA-65 authority and anchor. "
        r"Bold marks a departure from the specification ($^\dagger$; both also occur "
        r"in the unmodified library).}",
        r"\label{tab:validation}",
        r"\footnotesize", r"\setlength{\tabcolsep}{3pt}",
        r"\begin{tabular}{llcccc}", r"\toprule",
        r" & & ES256, & \multicolumn{2}{c}{ML-DSA-44/65/87} & \\", r"\cmidrule(lr){4-5}",
        r"Case & Expected & Ed25519 & p1 & p2 & TST\\", r"\midrule",
    ]
    for label, cases in VAL_ROWS:
        xs = [x for x in r if x["case"] in cases]
        if not xs:
            continue
        exp = expect_map.get(xs[0]["expected"], xs[0]["expected"])
        c_cl, _ = cell(cases, ("es256", "ed25519"), "p2")
        c_p1, _ = cell(cases, PQ, "p1")
        c_p2, _ = cell(cases, PQ, "p2")
        c_ts, _ = cell(cases, PQ + ("es256", "ed25519"), "p2", _tst)
        lines.append(f"{label} & {exp} & {c_cl} & {c_p1} & {c_p2} & {c_ts}" + r"\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
    emit("validation.tex", lines)

    # Every case, every algorithm (supplement).
    algs = ["es256", "ed25519", "mldsa44", "mldsa65", "mldsa87"]
    full = [
        r"{\footnotesize",
        r"\begin{longtable}{p{4.6cm}p{1.2cm}ccccccc}",
        r"\caption{Every case of the validation matrix: the library's outcome "
        r"under the extended patch (p2) for each algorithm, with the timestamp's own "
        r"status after a slash (t trusted, m mismatch, u untrusted). \emph{p1}: the "
        r"three ML-DSA sets with the signing patch alone. \emph{p0}: \texttt{c2pa-rs} "
        r"\texttt{" + d["env"]["c2pa_rs"][:7] + r"} unmodified, for the classical "
        r"cases that bear on the two departures. Codes as in "
        r"Table~\ref{tab:validation}; every status code the library reported is in "
        r"the released data.}\label{tab:valfull}\\",
        r"\toprule",
        r"Case & Expected & ES256 & Ed25519 & ML-44 & ML-65 & ML-87 & p1 & p0\\",
        r"\midrule", r"\endfirsthead", r"\toprule",
        r"Case & Expected & ES256 & Ed25519 & ML-44 & ML-65 & ML-87 & p1 & p0\\",
        r"\midrule", r"\endhead", r"\bottomrule", r"\endfoot",
    ]
    order = list(dict.fromkeys(x["case"] for x in r))
    for c in order:
        xs = [x for x in r if x["case"] == c]
        exp = expect_map.get(xs[0]["expected"], xs[0]["expected"])
        cells = []
        for a in algs:
            y = [x for x in xs if x["alg"] == a and x["patch"] == "p2"]
            cells.append(f"{_outcome(y[0])}/{_tst(y[0])}".replace("/--", "") if y else "")
        p1 = sorted({_outcome(x) for x in xs if x["patch"] == "p1" and x["alg"] in PQ})
        p0 = sorted({_outcome(x) for x in xs if x["patch"] == "p0"})
        name = c.replace("_", r"\_")
        full.append(f"\\texttt{{{name}}} & {exp} & " + " & ".join(cells)
                    + f" & {'/'.join(p1)} & {'/'.join(p0)}" + r"\\")
    full += [r"\end{longtable}", "}"]
    emit("valfull.tex", full)

    good = [x["verify_ms"] for x in r if x["case"] == "chain_noroot_tsa" and x["patch"] == "p2"
            and x.get("verify_ms")]
    if good:
        num("valVerifyLo", f"{min(good):.1f}")
        num("valVerifyHi", f"{max(good):.1f}")
    pqg = [x["verify_ms"] for x in r if x["case"] == "pqtsa_good" and x["patch"] == "p2"
           and x["alg"] == "mldsa65" and x.get("verify_ms")]
    if pqg:
        num("valPqTsaMs", f"{max(pqg):.1f}")
    big = [x for x in r if x["case"] == "oversized_cert_1MB" and x["patch"] == "p2"]
    if big:
        num("valBigCertMs", f"{max(x['verify_ms'] for x in big):.0f}")
        num("valBigCertMB", f"{max(x['max_rss_bytes'] for x in big) / 1e6:.0f}")
    num("valRows", f"{len(r)}")
    num("valcases", f"{len({x['case'] for x in r})}")
    num("valShown", f"{len(VAL_ROWS)}")
    per_case = {}
    for x in r:
        if x["patch"] == "p2":
            per_case.setdefault(x["case"], set()).add(x["alg"])
    num("valAllFive", f"{sum(1 for v in per_case.values() if len(v) == 5)}")
    num("valCommit", d["env"]["c2pa_rs"][:7])


# --- Algorithm sweep, chain depth, hash and mixed-chain figures for the text -----

FALCON_PAD = {"Falcon-512": 666, "Falcon-1024": 1280}


def _padded(x):
    """Falcon rows at the padded signature length a reservation must hold."""
    pad = FALCON_PAD.get(x["alg"])
    if not pad:
        return x
    y = dict(x)
    extra = pad - x["sig_bytes"]
    y["sig_bytes"] = pad
    for k in ("cose_embedded_bytes", "cose_referenced_bytes",
              "manifest_embedded_bytes", "manifest_referenced_bytes"):
        y[k] = x[k] + extra
    for k, base in (("manifest_pct_of_median_image", "manifest_embedded_bytes"),
                    ("manifest_ref_pct_of_median_image", "manifest_referenced_bytes")):
        if k in x and x[base]:
            y[k] = x[k] * y[base] / x[base]
    y["chain_share_of_cose_pct"] = 100 * x["chain_der_bytes"] / y["cose_embedded_bytes"]
    return y


def tab_algsweep():
    d = load("e1_algsweep.json")
    if not d:
        return
    order = ["Ed25519", "ES256", "PS256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
             "Falcon-512", "Falcon-1024", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s",
             "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-256s"]
    r = sorted((_padded(x) for x in d["results"] if x["chain_depth"] == 3),
               key=lambda x: order.index(x["alg"]) if x["alg"] in order else len(order))
    lines = [
        r"\begin{table}[t]",
        r"\caption{Signature schemes at hierarchy depth three, leaf and "
        r"intermediate carried. \emph{Chain} is the share of the signed "
        r"structure taken by certificates; \emph{Embed.} and \emph{Ref.} are "
        r"the manifest with the chain and with a thumbprint, as a percentage "
        r"of the median image. Every certificate is real; Falcon carries a "
        r"placeholder object identifier and its padded signature length. A "
        r"dash means no COSE identifier is assigned. Signing times through "
        r"liboqs on " + machine(d) + r", over the claim alone (Section~\ref{sec:timing}). "
        r"Times are medians over " + str(d["env"].get("runs")) + r" independent runs; their "
        r"intervals across runs are in the released data.}",
        r"\label{tab:algsweep}",
        r"\small", r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{llrrrrrr}", r"\toprule",
        r" & COSE & Sig. & Chain & Chain & Embed. & Ref. & Sign\\",
        r"Algorithm & id & (B) & (B) & (\%) & (\% img) & (\% img) & (ms)\\",
        r"\midrule",
    ]
    fam = None
    for x in r:
        if fam is not None and x["family"] != fam:
            lines.append(r"\midrule")
        fam = x["family"]
        cid = str(x["cose_alg_id"]) if x["cose_alg_assigned"] else "--"
        v = x["sign_ms"]["median_ms"] if "sign_ms" in x else None
        sg = "--" if v is None else (f"{v:.0f}" if v >= 10 else f"{v:.3f}")
        lines.append(
            f"{x['alg']} & {cid} & {x['sig_bytes']:,} & {x['chain_der_bytes']:,} & "
            f"{x['chain_share_of_cose_pct']:.1f} & "
            f"{x.get('manifest_pct_of_median_image', 0):.1f} & "
            f"{x.get('manifest_ref_pct_of_median_image', 0):.1f} & {sg}" + r"\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("algsweep.tex", lines)
    pq = [x for x in r if x["family"] == "post-quantum"]
    shares = [x["chain_share_of_cose_pct"] for x in pq]
    num("sweepShareLo", f"{min(shares):.0f}")
    num("sweepShareHi", f"{max(shares):.0f}")
    f = next((x for x in pq if x["alg"] == "Falcon-512"), None)
    if f:
        num("falconEmbPct", f"{f['manifest_pct_of_median_image']:.1f}")
        num("falconRefPct", f"{f['manifest_ref_pct_of_median_image']:.1f}")
    s = next((x for x in pq if x["alg"] == "SLH-DSA-SHA2-256s"), None)
    if s:
        num("slhBigPct", f"{s['manifest_pct_of_median_image']:.0f}")
    sigs = [x["sig_bytes"] for x in pq]
    num("sweepSigFactor", f"{max(sigs) / min(sigs):.0f}")

    # chain depth (supplement): hierarchy depth and certificates carried
    rr = [_padded(x) for x in d["results"]]
    algs = ["Ed25519", "PS256", "Falcon-512", "ML-DSA-44", "ML-DSA-65",
            "ML-DSA-87", "SLH-DSA-SHA2-128s"]
    depths = sorted({x["chain_depth"] for x in rr})
    lines = [
        r"\begin{table}[ht]",
        r"\caption{Manifest size as a percentage of the median image against "
        r"hierarchy depth. A hierarchy of $h$ certificates puts $h-1$ in "
        r"\texttt{x5chain}, the root omitted; each further level costs the "
        r"same again.}",
        r"\label{tab:chaindepth}",
        r"\small", r"\begin{tabular}{l" + "r" * len(depths) + "}", r"\toprule",
        r"Hierarchy depth & " + " & ".join(str(x) for x in depths) + r"\\",
        r"Certificates carried & " + " & ".join(str(x - 1) for x in depths) + r"\\",
        r"\midrule",
    ]
    for a in algs:
        rows = {x["chain_depth"]: x for x in rr if x["alg"] == a}
        if not rows:
            continue
        lines.append(f"{a} & " + " & ".join(
            f"{rows[k].get('manifest_pct_of_median_image', 0):.1f}" if k in rows else "--"
            for k in depths) + r"\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("chaindepth.tex", lines)
    m = {x["chain_depth"]: x for x in rr if x["alg"] == "ML-DSA-65"}
    if 2 in m and 4 in m:
        num("depthSpread", f"{m[4]['manifest_pct_of_median_image'] - m[2]['manifest_pct_of_median_image']:.0f}")


def text_numbers():
    d = load("e1_postquantum.json")
    if d:
        for x in d["results"]:
            if x["chain_depth"] != 3 or x["image"] != d["results"][0]["image"]:
                continue
            k = tok(x["alg"])
            num(f"chainShare{k}", f"{x['chain_share_of_cose_pct']:.0f}")
            num(f"chainBytes{k}", f"{x['chain_der_bytes']:,}")
            t = x.get("sign_ms", {})
            best = t.get("liboqs") or t.get("openssl")
            if best:
                num(f"signMs{k}", ms(best))
    d = load("e1_timestamp.json")
    if d:
        for x in d["results"]:
            k = tok(x["alg"])
            num(f"tsGrowth{k}", f"{x['manifest_signed_and_timestamped_bytes'] / x['manifest_signature_only_bytes']:.1f}")
            if x.get("manifest_full_bytes"):
                num(f"fullGrowth{k}", f"{x['manifest_full_bytes'] / x['manifest_signature_only_bytes']:.1f}")
    d = load("e1_hash.json")
    if d:
        short = {"thumbnail": "Thumb", "Kodak q90 (median)": "Kodak",
                 "social re-encode": "Social", "1080p JPEG": "Hd",
                 "phone original": "Phone", "high-res / raw-ish": "Raw"}
        for x in d["results"]:
            c = short.get(x["case"], "".join(ch for ch in x["case"].title() if ch.isalpha()))
            num(f"hash{c}", ms(x["hash_ms"]))
            num(f"hashShare{c}", f"{x['hash_share_ML-DSA-65_pct']:.0f}")
    d = load("e1_mixedchain.json")
    if d:
        names = {"Leaf only": "LeafMig", "Leaf and intermediate": "LeafInt",
                 "PKI first, leaves last": "PkiFirst", "Fully migrated": "Full",
                 "Assurance ladder": "Ladder", "Ladder inverted": "Inverted",
                 "Cheap leaves, strong root": "Cheap", "Classical": "Classical"}
        full = next(x for x in d["results"] if x["stage"] == "Fully migrated")
        for x in d["results"]:
            k = names.get(x["stage"])
            if not k:
                continue
            num(f"mix{k}", f"{x['bytes_vs_classical']:.1f}")
            num(f"mixPctFull{k}", f"{100 * x['cose_bytes'] / full['cose_bytes']:.0f}")
            for w in x.get("whole_manifest", []):
                t = "Es" if w["tsa_alg"] == "ES256" else "Pq"
                num(f"mixWhole{k}{t}", f"{w['manifest_crypto_bytes']:,}")
    d = load("e7_edge.json", os.path.join(ROOT, "out-pi-v2"))
    if d:
        diffs = []
        for x in d["results"]:
            e, w, c = (x["embedded"]["total"]["median_ms"], x["warm"]["total"]["median_ms"],
                       x["cold"]["total"]["median_ms"])
            diffs.append(abs(e - w))
            if x["alg"] in ("Ed25519", "ML-DSA-65"):
                num(f"edgeCold{tok(x['alg'])}", f"{c - w:.2f}")
        num("edgeWarmDiff", f"{max(diffs):.2f}")
    d = load("e8_scale.json")
    if d:
        for x in d["results"]:
            if x["alg"] in ("ML-DSA-65", "ES256", "Ed25519", "PS256") and x["workers"] == 1:
                k = tok(x["alg"]) + {"uncached": "Unc", "cached": "Cac",
                                     "cached-liboqs": "Oqs"}[x["mode"]]
                num(f"rate{k}", f"{x['per_s']:,.0f}")


def profile_numbers():
    d = load("e1_profile.json", os.environ.get("LINEA_REF_IN", os.path.join(ROOT, "out-reference")))
    if not d:
        return
    r = d["results"]
    ica = next(x for x in r if x.get("role") == "issuing CA")
    num("profilelistlo", f"{min(ica['overhead_bytes'])}")
    num("profilelisthi", f"{max(ica['overhead_bytes'])}")
    num("profilelistmed", f"{ica['median']:.0f}")
    g = next(x for x in r if x.get("alg") == "ML-DSA-65")
    num("profileica", f"{g['overhead_bytes'][1]}")
    roots = next(x for x in r if x.get("role") == "root")
    num("tlIssuing", f"{ica['n']}")
    num("tlAnchors", f"{ica['n'] + roots['n']}")


# --- Microcontrollers ------------------------------------------------------------

MCU_ALGS = ["Ed25519", "ES256", "ES256 hw", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
MCU_V2 = os.path.join(ROOT, "out-mcu-v2")
MCU_V1 = os.path.join(ROOT, "out-mcu")
MCU_V3 = os.path.join(ROOT, "out-mcu-v3")


def _row(doc, alg, op):
    hw = 1 if alg.endswith(" hw") else 0
    a = alg.replace(" hw", "")
    for r in doc["results"]:
        if r.get("op") == op and r.get("alg") == a and r.get("hw", 0) == hw:
            if r.get("ok") is False:
                raise SystemExit(f"{op} {alg}: not ok")
            return r
    return None


def _ms_(doc, alg, op, nd=1):
    r = _row(doc, alg, op) if doc else None
    return f"{r['median_us'] / 1000:.{nd}f}" if r else "--"


def _kib(doc, alg, op):
    r = _row(doc, alg, op) if doc else None
    return (r["buffers_bytes"] + r["stack_bytes"]) / 1024 if r else None


def ble_model():
    """Least-squares fit of send energy against manifest bytes, from E12."""
    eb = load("e12_ble_energy.json", MCU_V1)
    rx = load("e12_ble_rx.json", MCU_V1)
    if not (eb and rx):
        return None
    size = {(r["alg"], r["form"]): r["bytes"] for r in rx["results"] if r.get("op") == "rx"}
    pts = [(size[(x["alg"], x["op"])], x["gross_uj_median"]) for x in eb["summary"]
           if (x["alg"], x["op"]) in size]
    n = len(pts)
    mx = sum(p[0] for p in pts) / n
    my = sum(p[1] for p in pts) / n
    b = sum((p[0] - mx) * (p[1] - my) for p in pts) / sum((p[0] - mx) ** 2 for p in pts)
    a = my - b * mx
    ss = sum((p[1] - (a + b * p[0])) ** 2 for p in pts)
    st = sum((p[1] - my) ** 2 for p in pts)
    worst = max(abs(p[1] - (a + b * p[0])) / p[1] for p in pts)
    return {"a_uj": a, "b_nj_per_byte": b * 1000, "r2": 1 - ss / st, "n": n,
            "worst_rel_err": worst}


def tab_mcu():
    pico = load("e9_pico.json", MCU_V2)
    n20 = load("e10_nucleo_20mhz.json", MCU_V2)
    n80 = load("e10_nucleo_80mhz.json", MCU_V2)
    nrf = load("e11_nrf52840.json", MCU_V2)
    if not (pico and n80 and nrf):
        return
    for d in (pico, n20, n80, nrf):
        if not d:
            continue
        for r in d["results"]:
            if r.get("op") == "negative" and not all(
                    v for k, v in r.items() if k.startswith("rejects") or k == "accepts_original"):
                raise SystemExit(f"negative test failed: {r}")
    lines = [
        r"\begin{table}[t]",
        r"\caption{Signing and verifying on three microcontrollers, milliseconds, "
        r"medians. \emph{Verify} is a complete manifest: receive it, decode it, "
        r"check the leaf and intermediate up to the root anchor in the trust store, "
        r"and check the manifest signature, with leaf and intermediate carried "
        r"(\emph{L+I}) or only a thumbprint (\emph{Th.}). Pico: RP2040 Cortex-M0+ at "
        r"125\,MHz, portable C (PQClean). NUCLEO: STM32L4R5 Cortex-M4F at 80\,MHz, "
        r"pqm4 assembly. nRF: nRF52840 Cortex-M4F at 64\,MHz, the same objects; "
        r"\emph{ES256 (hw)} runs on its CryptoCell-310. Every board rejected a "
        r"flipped signature bit, a tampered manifest, a tampered intermediate and a "
        r"missing intermediate for every algorithm.}",
        r"\label{tab:mcu}",
        r"\small", r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{lrrrrrrrr}", r"\toprule",
        r" & \multicolumn{3}{c}{Pico} & \multicolumn{3}{c}{NUCLEO, 80\,MHz} & "
        r"\multicolumn{2}{c}{nRF52840}\\",
        r"\cmidrule(lr){2-4}\cmidrule(lr){5-7}\cmidrule(lr){8-9}",
        r"Algorithm & Sign & L+I & Th. & Sign & L+I & Th. & Sign & L+I\\",
        r"\midrule",
    ]
    for a in MCU_ALGS:
        hw = a.endswith(" hw")
        lines.append(
            f"{a.replace(' hw', ' (hw)')} & "
            f"{'--' if hw else _ms_(pico, a, 'sign')} & {'--' if hw else _ms_(pico, a, 'manifest_chain')} & "
            f"{'--' if hw else _ms_(pico, a, 'manifest_thumb')} & "
            f"{'--' if hw else _ms_(n80, a, 'sign')} & {'--' if hw else _ms_(n80, a, 'manifest_chain')} & "
            f"{'--' if hw else _ms_(n80, a, 'manifest_thumb')} & "
            f"{_ms_(nrf, a, 'sign')} & {_ms_(nrf, a, 'manifest_chain')}" + r"\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("mcu.tex", lines)

    def f(doc, a, op, nd=0):
        r = _row(doc, a, op)
        return f"{r['median_us'] / 1000:.{nd}f}" if r else "--"
    num("picoChainEd", f(pico, "Ed25519", "manifest_chain"))
    num("picoChainDSAfortyfour", f(pico, "ML-DSA-44", "manifest_chain"))
    num("picoChainDSAsixtyfive", f(pico, "ML-DSA-65", "manifest_chain"))
    num("picoChainDSAeightyseven", f(pico, "ML-DSA-87", "manifest_chain"))
    num("picoChainES", f(pico, "ES256", "manifest_chain"))
    num("nrfChainEShw", f(nrf, "ES256 hw", "manifest_chain"))
    num("nrfChainES", f(nrf, "ES256", "manifest_chain"))
    num("nucSignDSAsixtyfive", f(n80, "ML-DSA-65", "sign"))
    num("nrfSignDSAsixtyfive", f(nrf, "ML-DSA-65", "sign"))
    num("picoSignDSAsixtyfive", f(pico, "ML-DSA-65", "sign"))
    num("picoSignDSAeightyseven", f(pico, "ML-DSA-87", "sign"))
    hwr = _row(nrf, "ES256 hw", "manifest_chain")["median_us"]
    for a in ("ML-DSA-44", "ML-DSA-87"):
        num(f"hwRatio{tok(a)}", f"{_row(nrf, a, 'manifest_chain')['median_us'] / hwr:.1f}")
    num("hwSpeedup", f"{_row(nrf, 'ES256', 'manifest_chain')['median_us'] / hwr:.1f}")
    if n20:
        r = _row(n20, "ML-DSA-65", "sign")
        if r and "median_ticks" in r:
            num("nucTwentySignMcycles", f"{r['median_ticks'] / 1e6:.1f}")
    # signing stack
    for d_, nm in ((n80, "nuc"), (pico, "pico")):
        for a in ("ML-DSA-65", "ML-DSA-87"):
            r = _row(d_, a, "sign")
            if r:
                num(f"{nm}SignStack{tok(a)}", f"{r['stack_bytes'] / 1024:.0f}")

    # RAM, energy and radio
    model = ble_model()
    ep3, en3, er3 = (load("e9_pico_energy.json", MCU_V3), load("e10_nucleo_energy.json", MCU_V3),
                     load("e11_nrf52840_energy.json", MCU_V3))
    ep = ep3 or load("e9_pico_energy.json", MCU_V1)
    en = en3 or load("e10_nucleo_energy.json", MCU_V1)
    er = er3 or load("e11_nrf52840_energy.json", MCU_V1)
    vop = {id(d): ("manifest_chain" if d3 else "manifest_full")
           for d, d3 in ((ep, ep3), (en, en3), (er, er3)) if d}
    all_v3 = bool(ep3 and en3 and er3)

    def e_(doc, a, op, scale=1e-3, fmt="{:.2f}"):
        if not doc:
            return "--"
        hw = 1 if a.endswith(" hw") else 0
        aa = a.replace(" hw", "")
        for x in doc["summary"]:
            if x["alg"] == aa and x["op"] == op and x.get("hw", 0) == hw:
                return fmt.format(x["gross_uj_median"] * scale)
        return "--"

    sizes = {}
    for r in n80["results"]:
        if r.get("op", "").startswith("manifest_") and "bytes" in r:
            sizes[(r["alg"], r["op"][9:])] = r["bytes"]
    for r in n80["results"]:
        if r.get("op") == "sizes":
            for frm in ("full", "chain", "leaf", "thumb"):
                sizes[(r["alg"], frm)] = r[f"{frm}_bytes"]

    radio = load("e12_ble_tx_energy.json", MCU_V3)
    verify_note = (r"with leaf and intermediate carried, measured with the current vectors"
                   if all_v3 else
                   r"measured with an earlier vector set that carried the root where marked")
    lines = [
        r"\begin{table*}[t]",
        r"\caption{What a manifest costs a microcontroller beyond time. "
        r"\emph{RAM}: received manifest, rebuilt signed structure and peak stack, "
        r"all live at once, by carriage form (root, leaf and intermediate, leaf "
        r"only, thumbprint); M0+ is the Pico's portable C, M4 the NUCLEO's pqm4 "
        r"build. \emph{Verify}: energy for one complete verification, " + verify_note
        + r". The three boards are measured at different "
        r"points (the whole Pico, the NUCLEO's MCU rail, the nRF52840's supply) and "
        r"are not comparable with one another."
        + ("" if radio else
           r" \emph{Send}: estimated transmit energy for one nRF52840 to send the "
           r"manifest to another over Bluetooth LE, from a straight-line fit to "
           + (str(model["n"]) if model else "15") + r" measured transfers.")
        + (r" Radio energy, measured, is in Table~\ref{tab:radio}." if radio else "") + "}",
        r"\label{tab:mcucost}",
        r"\small", r"\setlength{\tabcolsep}{3.6pt}",
        r"\begin{tabular}{lrrrrrrrr" + ("" if radio else "rrr") + "}", r"\toprule",
        r" & \multicolumn{5}{c}{RAM (KiB)} & \multicolumn{3}{c}{Verify (mJ)}"
        + ("" if radio else r" & \multicolumn{3}{c}{Send ($\mu$J)}") + r"\\",
        r"\cmidrule(lr){2-6}\cmidrule(lr){7-9}" + ("" if radio else r"\cmidrule(lr){10-12}"),
        r" & M0+ & \multicolumn{4}{c}{M4} & & & " + ("" if radio else "& & & ") + r"\\",
        r"\cmidrule(lr){3-6}",
        r"Algorithm & L+I & Root & L+I & Leaf & Th. & Pico & NUCLEO & nRF"
        + ("" if radio else " & L+I & Leaf & Th.") + r"\\",
        r"\midrule",
    ]
    ble = {}
    for a in MCU_ALGS:
        hw = a.endswith(" hw")
        aa = a.replace(" hw", "")
        src = nrf if hw else n80
        ram = [_kib(src, a, f"manifest_{x}") for x in ("full", "chain", "leaf", "thumb")]
        m0 = None if hw else _kib(pico, a, "manifest_chain")
        send = []
        for frm in ("chain", "leaf", "thumb"):
            b = sizes.get((aa, frm))
            v = model["a_uj"] + model["b_nj_per_byte"] / 1000 * b if (model and b and not hw) else None
            send.append(v)
            if v is not None:
                ble[(aa, frm)] = v
        cells = [("--" if m0 is None else f"{m0:.1f}")] + [("--" if x is None else f"{x:.1f}") for x in ram]
        cells += ["--" if hw else e_(ep, a, vop.get(id(ep), "manifest_full"), fmt="{:.1f}"),
                  "--" if hw else e_(en, a, vop.get(id(en), "manifest_full")),
                  e_(er, a, vop.get(id(er), "manifest_full"))]
        if not radio:
            cells += [("--" if v is None else f"{v:,.0f}") for v in send]
        lines.append(f"{a.replace(' hw', ' (hw)')} & " + " & ".join(cells) + r"\\")
        k = tok(aa) + ("hw" if hw else "")
        if not hw:
            num(f"ramChain{k}", f"{ram[1]:.0f}")
            num(f"ramRoot{k}", f"{ram[0]:.0f}")
            num(f"ramLeaf{k}", f"{ram[2]:.0f}")
            num(f"ramThumb{k}", f"{ram[3]:.0f}")
            num(f"ramPico{k}", f"{m0:.0f}")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
    emit("mcucost.tex", lines)
    num("energyVthree", "yes" if all_v3 else "no")
    for d_, nm in ((ep, "Pico"), (en, "Nuc"), (er, "Nrf")):
        if d_:
            op = vop.get(id(d_), "manifest_full")
            for a in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Ed25519", "ES256"):
                v = e_(d_, a, op, scale=1e-3, fmt="{:.2f}")
                if v != "--":
                    num(f"verE{nm}{tok(a)}", v)
    if radio:
        rxd = load("e12_ble_rx_energy.json", MCU_V3)
        tab_radio(radio, rxd, sizes)
        if er3 and rxd:
            rv = next(x["gross_uj_median"] for x in rxd["summary"]
                      if x["alg"] == "ML-DSA-87" and x["op"] == "chain")
            vv = next(x["gross_uj_median"] for x in er3["summary"]
                      if x["alg"] == "ML-DSA-87" and x["op"] == "manifest_chain" and not x.get("hw"))
            num("recvShareVerify", f"{100 * rv / vv:.0f}")
    if model:
        num("bleNjPerByte", f"{model['b_nj_per_byte']:.0f}")
        num("bleRsq", f"{model['r2']:.4f}")
        num("bleWorst", f"{100 * model['worst_rel_err']:.1f}")
        for (aa, frm), v in ble.items():
            num(f"send{frm.title()}{tok(aa)}", f"{v / 1000:.2f}")
        with open(os.path.join(MCU_V2, "e12_ble_model.json"), "w") as fh:
            json.dump({"model": model, "send_uj": {f"{a}|{f}": v for (a, f), v in ble.items()}},
                      fh, indent=2)



def _fit(pts):
    """Least squares E = a + b x with the slope's 95% interval and residuals."""
    n = len(pts)
    mx = sum(p[0] for p in pts) / n
    my = sum(p[1] for p in pts) / n
    sxx = sum((p[0] - mx) ** 2 for p in pts)
    b = sum((p[0] - mx) * (p[1] - my) for p in pts) / sxx
    a = my - b * mx
    res = [p[1] - (a + b * p[0]) for p in pts]
    ss = sum(r * r for r in res)
    st = sum((p[1] - my) ** 2 for p in pts)
    se_b = (ss / (n - 2) / sxx) ** 0.5
    t = 2.11 if n == 19 else 2.10 if n == 20 else 2.0      # t_{0.975, n-2}
    return {"a_uj": a, "b_uj_per_byte": b, "b_ci95": [b - t * se_b, b + t * se_b],
            "r2": 1 - ss / st, "n": n, "x_min": min(p[0] for p in pts),
            "x_max": max(p[0] for p in pts),
            "max_abs_resid_uj": max(abs(r) for r in res),
            "max_rel_resid": max(abs(r) / p[1] for r, p in zip(res, pts))}


def tab_radio(tx, rx, sizes):
    """Measured Bluetooth LE energy per manifest, sender and receiver."""
    forms = ("full", "chain", "leaf", "thumb")
    get = lambda d, a, f: next((x["gross_uj_median"] for x in (d or {}).get("summary", [])
                                if x["alg"] == a and x["op"] == f), None)
    lines = [
        r"\begin{table}[t]",
        r"\caption{Measured Bluetooth LE energy for one manifest's COSE signature "
        r"structure, with the certificates of each carriage form, between two "
        r"nRF52840-DKs (2M PHY, 251-byte data length, 247-byte ATT MTU, 15\,ms "
        r"connection interval, boards about a metre apart), on the measured board's "
        r"supply, microjoules, medians of three rounds of ten transfers. "
        r"\emph{Send}: from the first notification queued to the last acknowledged. "
        r"\emph{Receive}: the same board as receiver, from the first notification "
        r"received to the last. Both include the connected link's idle current "
        r"and any link-layer retransmissions inside the window, not connection "
        r"set-up or advertising. The receiving board checked every transfer byte for "
        r"byte against its own copy; all arrived intact.}",
        r"\label{tab:radio}",
        r"\small", r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{lrrrrrrrr}", r"\toprule",
        r" & \multicolumn{4}{c}{Send} & \multicolumn{4}{c}{Receive}\\",
        r"\cmidrule(lr){2-5}\cmidrule(lr){6-9}",
        r"Algorithm & Root & L+I & Leaf & Th. & Root & L+I & Leaf & Th.\\", r"\midrule",
    ]
    pts_tx, pts_rx = [], []
    for a in ("Ed25519", "ES256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
        cells = []
        for d, pts in ((tx, pts_tx), (rx, pts_rx)):
            for f in forms:
                v = get(d, a, f)
                cells.append("--" if v is None else f"{v:,.0f}")
                b = sizes.get((a, f))
                if v is not None and b:
                    pts.append((b, v))
                    num(f"{'send' if d is tx else 'recv'}M{f.title()}{tok(a)}", f"{v / 1000:.2f}")
        lines.append(f"{a} & " + " & ".join(cells) + r"\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("radio.tex", lines)
    out = {}
    for nm, pts in (("Tx", pts_tx), ("Rx", pts_rx)):
        if len(pts) >= 4:
            m = _fit(pts)
            out[nm] = m
            num(f"ble{nm}Nj", f"{1000 * m['b_uj_per_byte']:.0f}")
            num(f"ble{nm}NjLo", f"{1000 * m['b_ci95'][0]:.0f}")
            num(f"ble{nm}NjHi", f"{1000 * m['b_ci95'][1]:.0f}")
            num(f"ble{nm}A", f"{m['a_uj']:.0f}")
            num(f"ble{nm}Rsq", f"{m['r2']:.4f}")
            num(f"ble{nm}N", f"{m['n']}")
            num(f"ble{nm}ResUj", f"{m['max_abs_resid_uj']:.0f}")
            num(f"ble{nm}ResPct", f"{100 * m['max_rel_resid']:.0f}")
            num(f"ble{nm}Xmin", f"{m['x_min']:,}")
            num(f"ble{nm}Xmax", f"{m['x_max']:,}")
    if out:
        os.makedirs(MCU_V3, exist_ok=True)
        with open(os.path.join(MCU_V3, "e12_ble_fit.json"), "w") as fh:
            json.dump(out, fh, indent=2)


# --- Implementations: the x86 block ----------------------------------------------

X86_IMPLS = [("liboqs-0.16.0-native-avx2", "liboqs 0.16.0", "AVX2"),
             ("liboqs-0.16.0-generic", "liboqs 0.16.0", "generic"),
             ("pqclean-ml-dsa-65-clean", "PQClean reference", "\\texttt{-O3}"),
             ("openssl-4.0.2-source-asm", "OpenSSL 4.0.2", "source, asm"),
             ("openssl-4.0.2-source-noasm", "OpenSSL 4.0.2", "source, no asm")]


def tab_impls_x86():
    """Append the Xeon VM's builds to the M1 implementation table."""
    path = os.path.join(TAB, "impls.tex")
    src = os.path.join(ROOT, "out-x86", "impls_x86.jsonl")
    if not (os.path.exists(path) and os.path.exists(src)):
        return
    rows = [json.loads(l) for l in open(src) if l.strip()]

    def get(impl, op):
        return next((r for r in rows if r["impl"] == impl and r["op"] == op), None)

    fastest = min(r["median_ms"] for r in rows if r["op"] == "ML-DSA-65 sign")
    block = [r"\midrule",
             r"\multicolumn{6}{l}{\emph{Intel Xeon VM, x86-64, GCC 13.3}}\\"]
    for key, name, build in X86_IMPLS:
        sg, v = get(key, "ML-DSA-65 sign"), get(key, "ML-DSA-65 verify")
        if not sg:
            continue
        block.append(f"{name} & {build} & {sg['median_ms']:.3f} & {sg['mean_ms']:.3f} & "
                     f"{v['median_ms']:.3f} & {sg['median_ms'] / fastest:.1f}" + r"\\")
    t = open(path).read()
    if "Xeon VM" in t:
        return
    t = t.replace(r"\midrule", r"\midrule" + "\n" + r"\multicolumn{6}{l}{\emph{Apple M1 Pro, arm64}}\\", 1)
    t = t.replace(r"\bottomrule", "\n".join(block) + "\n" + r"\bottomrule", 1)
    t = t.replace("ML-DSA-65 on one Apple M1 Pro through every implementation "
                  "and build we could obtain,",
                  "ML-DSA-65 through every implementation and build we could "
                  "obtain on the M1 Pro, and the corresponding builds on the "
                  "Xeon VM,")
    open(path, "w").write(t)
    print("  impls.tex (+x86)")
    nat, gen = get("liboqs-0.16.0-native-avx2", "ML-DSA-65 sign"), get("liboqs-0.16.0-generic", "ML-DSA-65 sign")
    natv, genv = get("liboqs-0.16.0-native-avx2", "ML-DSA-65 verify"), get("liboqs-0.16.0-generic", "ML-DSA-65 verify")
    ossl = get("openssl-4.0.2-source-asm", "ML-DSA-65 sign")
    num("avxSign", f"{gen['median_ms'] / nat['median_ms']:.1f}")
    num("avxVerify", f"{genv['median_ms'] / natv['median_ms']:.1f}")
    num("xOsslVsOqs", f"{ossl['median_ms'] / nat['median_ms']:.1f}")
    num("xSpread", f"{max(r['median_ms'] for r in rows if r['op'] == 'ML-DSA-65 sign') / fastest:.1f}")


# --- Literature audit (supplement) --------------------------------------------------

def tab_audit():
    import csv
    path = os.path.join(ROOT, "data", "litaudit", "audit.csv")
    if not os.path.exists(path):
        return
    rows = list(csv.DictReader(open(path)))
    yes = lambda r, k: r[k].strip().lower().startswith("y")
    mark = lambda b: r"\checkmark" if b else ""
    import re as _re
    # An explicit optimisation level is a -O flag in the coded build text;
    # build types (Release) and optimised-vs-portable backends count as
    # build information but not as an optimisation level.
    olevel = lambda r: bool(_re.search(r"-O[0-3sfz]", r["flags"]))

    def flmark(r):
        if not yes(r, "flags_reported"):
            return ""
        return r"\checkmark" if olevel(r) else r"($\checkmark$)"
    lines = [
        r"\begin{longtable}{p{3.1cm}p{2.0cm}cccccccc}",
        r"\caption{Forty applied post-quantum timing studies, 2022--2026, coded "
        r"for what they report about the implementation behind their numbers: "
        r"library (\emph{Lib.}), its version (\emph{Ver.}), the compiler "
        r"(\emph{Cc}), the build (\emph{Fl.}: \checkmark{} an explicit "
        r"optimisation level such as \texttt{-O3}; ($\checkmark$) a build type "
        r"or an optimised-versus-portable backend without one), CPU model "
        r"and clock (\emph{CPU}), repetitions (\emph{Rep.}), a measure of spread "
        r"(\emph{Spr.}) and released code or data (\emph{Code}). A mark means "
        r"the paper states it explicitly. Coding by one author, without a second "
        r"rater; the evidence for every mark, with the version of the text "
        r"coded, is quoted in the released data (Section~\ref{sec:auditprotocol}).}"
        r"\label{tab:audit}\\",
        r"\toprule",
        r"Study & Area & Lib. & Ver. & Cc & Fl. & CPU & Rep. & Spr. & Code\\",
        r"\midrule", r"\endfirsthead",
        r"\toprule",
        r"Study & Area & Lib. & Ver. & Cc & Fl. & CPU & Rep. & Spr. & Code\\",
        r"\midrule", r"\endhead",
        r"\bottomrule", r"\endfoot",
    ]
    for r in sorted(rows, key=lambda r: (r["year"], r["key"])):
        area = r["application_area"].replace("&", r"\&").replace("_", r"\_")
        lines.append(
            f"\\citet{{{r['key']}}} & {area} & {mark(yes(r, 'implementation_named'))} & "
            f"{mark(yes(r, 'version_reported'))} & {mark(yes(r, 'compiler_named'))} & "
            f"{flmark(r)} & {mark(yes(r, 'cpu_model_and_clock'))} & "
            f"{mark(yes(r, 'iterations_reported'))} & {mark(yes(r, 'dispersion_reported'))} & "
            f"{mark(yes(r, 'code_or_data_released'))}" + r"\\")
    lines.append(r"\end{longtable}")
    emit("audit.tex", lines)
    n = len(rows)
    c = lambda k: sum(yes(r, k) for r in rows)
    num("auditN", f"{n}")
    num("auditLib", f"{c('implementation_named')}")
    num("auditVer", f"{c('version_reported')}")
    num("auditCc", f"{c('compiler_named')}")
    num("auditFlags", f"{c('flags_reported')}")
    num("auditOlevel", f"{sum(olevel(r) for r in rows)}")
    num("auditBoth", f"{sum(yes(r, 'compiler_named') and olevel(r) for r in rows)}")
    num("auditSpread", f"{c('dispersion_reported')}")
    num("auditNoSpread", f"{n - c('dispersion_reported')}")
    mean_only = [r for r in rows if not yes(r, "dispersion_reported")
                 and _re.search(r"mean|average", r["statistic"], _re.I)
                 and "median" not in r["statistic"].lower()]
    num("auditMeanNoSpread", f"{len(mean_only)}")
    num("auditNoStat", f"{sum('none stated' in r['statistic'] for r in rows)}")
    oqs = [r for r in rows if "liboqs" in r["implementation"].lower()]
    num("auditOqs", f"{len(oqs)}")
    num("auditOqsBuild", f"{sum(yes(r, 'compiler_named') and olevel(r) for r in oqs)}")
    num("auditOqsAny", f"{sum(yes(r, 'compiler_named') or yes(r, 'flags_reported') for r in oqs)}")
    num("auditNWord", {39: "thirty-nine", 40: "forty", 41: "forty-one"}.get(n, str(n)))
    num("auditPreprints", f"{sum('arxiv' in r['venue'].lower() or 'preprint' in r['venue'].lower() for r in rows)}")
    words = {2: "two", 3: "three", 4: "four", 5: "five", 6: "six"}
    num("auditBothWord", words.get(sum(yes(r, 'compiler_named') and olevel(r) for r in rows), "?"))


# --- Corpus: what production signers ship ---------------------------------------------

GROUPS = [
    ("Google", ("google_",)),
    ("OpenAI", ("openai",)),
    ("Microsoft", ("microsoft",)),
    ("Adobe", ("adobe",)),
    ("News publishers", ("news_",)),
    ("Other", ("cloudflare", "leica", "vivo", "trustmycontent")),
]


def _group(corpus, gen):
    if corpus == "testfiles":
        return "C2PA test files"
    for name, prefixes in GROUPS:
        if gen.startswith(prefixes):
            return name
    return "Other"


def _summ(assets):
    import collections
    sigs = [x for a in assets for x in a["sig"]]
    x5 = [x for x in sigs if x.get("carriage") == "x5chain"]
    u = {}
    for x in x5:
        u.setdefault(x["chain_fingerprint"], x)
    u = list(u.values())
    tst = [t for x in sigs for t in x.get("timestamps", [])]
    algs = collections.Counter(x["alg"] for x in u)
    return {
        "assets": len(assets), "gens": len({a["generator"] for a in assets}),
        "sigs": len(sigs), "chains": len(u),
        "es": algs.get("ES256", 0), "ps": algs.get("PS256", 0),
        "sent": sorted({x["certs_transmitted"] for x in u}),
        "root": sum(x["root_transmitted"] for x in u),
        "twocert": sum(1 for x in u if x["certs_transmitted"] == 2 and not x["root_transmitted"]),
        "listed": sum(x["anchor_on_c2pa_list"] for x in u),
        "issuer": sum(bool(x["anchor_is_leaf_issuer"]) for x in u),
        "v2": sum(a["claim_version"] == "2.x" for a in assets),
        "p33": sum(x.get("x5chain_label") == "33" and x.get("x5chain_bucket") == "protected"
                   for x in x5),
        "nx5": len(x5),
        "ts": sum(1 for x in sigs if x.get("timestamps")),
        "tst_med": statistics.median(t["token_bytes"] for t in tst) if tst else None,
        "ocsp": sum(1 for x in sigs if x.get("has_ocsp")),
        "chain_med": statistics.median(x["chain_bytes"] for x in u) if u else None,
    }


def tab_corpus():
    d = load("e1_corpus.json", os.environ.get("LINEA_REF_IN", os.path.join(ROOT, "out-reference")))
    if not d:
        return
    assets = d["results"]["assets"]
    order = [g for g, _ in GROUPS] + ["C2PA test files"]
    groups = {g: [a for a in assets if _group(a["corpus"], a["generator"]) == g] for g in order}
    prod = [a for a in assets if a["corpus"] != "testfiles"]
    lines = [
        r"\begin{table*}[t]",
        r"\caption{Certificate chains in " + str(len(prod)) + r" production-signed "
        r"files from " + str(len({a['generator'] for a in prod})) + r" signing "
        r"applications, and in the C2PA public test files, read against the "
        r"C2PA trust list of 29~October 2026, a convenience sample of public "
        r"files (Section~\ref{sec:supp-corpus} of the supplement lists the chains and "
        r"sources, and the released inventory every file with its URL, licence and SHA-256). A chain is identified by its issuer: "
        r"the leaf's issuer name and every certificate after the leaf, so leaves "
        r"issued per image under one CA count once. Every signature in a file "
        r"counts, the active manifest's and its ingredients', under the group of "
        r"the application that wrote the file; a chain carried by files of several "
        r"groups (Google's camera chains in files that Microsoft's tools wrote, for example) is "
        r"counted in each, so the rows do not add up, and the \emph{Distinct} row "
        r"counts each chain once. \emph{Sent}: certificates in \texttt{x5chain}. "
        r"\emph{Root}: chains that carry a self-signed root. \emph{Listed}: "
        r"chains whose path ends at a trust-list anchor. \emph{Issuer}: chains "
        r"whose leaf was issued directly by an anchor, the condition for "
        r"conformant leaf-only carriage. \emph{2.x}: files with a version-2 "
        r"claim. \emph{33p}: signatures carrying \texttt{x5chain} under label~33 "
        r"in the protected bucket. \emph{TST}: signatures with an RFC~3161 token, "
        r"and its median size. \emph{OCSP}: signatures carrying revocation "
        r"evidence.}",
        r"\label{tab:corpus}",
        r"\small", r"\setlength{\tabcolsep}{3.3pt}",
        r"\begin{tabular}{lrrrrlrrrrrrrr}", r"\toprule",
        r" & & & \multicolumn{2}{c}{Chains} & & & & & & & \multicolumn{2}{c}{TST} & \\",
        r"\cmidrule(lr){4-5}\cmidrule(lr){12-13}",
        r"Signer & Files & Sigs & ES256 & PS256 & Sent & Root & Listed & Issuer & 2.x & "
        r"33p & n & B & OCSP\\", r"\midrule",
    ]
    for g in order:
        rows = groups[g]
        if not rows:
            continue
        v = _summ(rows)
        if g == "C2PA test files":
            lines.append(r"\midrule")
        lines.append(f"{g} & {v['assets']} & {v['sigs']} & {v['es']} & {v['ps']} & "
                     f"{', '.join(map(str, v['sent']))} & {v['root']} & {v['listed']} & "
                     f"{v['issuer']} & {v['v2']} & {v['p33']} & {v['ts']} & "
                     f"{v['tst_med']:,.0f} & {v['ocsp']}" + r"\\")
        if g == order[-2]:
            v = _summ(prod)
            lines.append(r"\midrule")
            lines.append(f"\\emph{{Distinct}} & {v['assets']} & {v['sigs']} & "
                         f"{v['es']} & {v['ps']} & {', '.join(map(str, v['sent']))} & "
                         f"{v['root']} & {v['listed']} & {v['issuer']} & {v['v2']} & "
                         f"{v['p33']} & {v['ts']} & {v['tst_med']:,.0f} & {v['ocsp']}" + r"\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
    emit("corpus.tex", lines)
    P = _summ(prod)
    T = _summ(groups["C2PA test files"])
    for t, v in (("Prod", P), ("Test", T)):
        num(f"corp{t}Assets", f"{v['assets']}")
        num(f"corp{t}Sigs", f"{v['sigs']}")
        num(f"corp{t}Chains", f"{v['chains']}")
        num(f"corp{t}Es", f"{v['es']}")
        num(f"corp{t}Ps", f"{v['ps']}")
        num(f"corp{t}Root", f"{v['root']}")
        num(f"corp{t}TwoCert", f"{v['twocert']}")
        num(f"corp{t}Listed", f"{v['listed']}")
        num(f"corp{t}Issuer", f"{v['issuer']}")
        num(f"corp{t}Ts", f"{v['ts']}")
        num(f"corp{t}Ocsp", f"{v['ocsp']}")
        num(f"corp{t}Vtwo", f"{v['v2']}")
        num(f"corp{t}Pthree", f"{v['p33']}")
        num(f"corp{t}Nxfive", f"{v['nx5']}")
        num(f"corp{t}Gens", f"{v['gens']}")
        if v["tst_med"]:
            num(f"corp{t}TstMed", f"{v['tst_med']:,.0f}")
        if v["chain_med"]:
            num(f"corp{t}ChainMed", f"{v['chain_med']:,.0f}")
    sig_es = sum(1 for a in prod for x in a["sig"] if x["alg"] == "ES256")
    sig_ps = sum(1 for a in prod for x in a["sig"] if x["alg"] == "PS256")
    num("corpProdSigEs", f"{sig_es}")
    num("corpProdSigPs", f"{sig_ps}")
    v2_string = sum(1 for a in prod if a["claim_version"] == "2.x" for x in a["sig"]
                    if x.get("x5chain_label") == "string")
    num("corpProdVtwoString", f"{v2_string}")
    tstsizes = sorted(t["token_bytes"] for a in prod for x in a["sig"] for t in x.get("timestamps", []))
    if tstsizes:
        num("corpProdTstLo", f"{tstsizes[0]:,}")
        num("corpProdTstHi", f"{tstsizes[-1]:,}")
    tsal = sum(t["tsa_on_c2pa_tsa_list"] for a in prod for x in a["sig"] for t in x.get("timestamps", []))
    num("corpProdTsaListed", f"{tsal}")
    num("corpProdTstN", f"{len(tstsizes)}")


# --- Timing intervals across runs (supplement) ----------------------------------------

def tab_ci():
    plats = [("M1 Pro", OUT), ("Xeon VM", os.path.join(ROOT, "out-x86")),
             ("Pi 5", os.path.join(ROOT, "out-pi-v2"))]

    def cell(t):
        if not isinstance(t, dict) or "median_ms" not in t:
            return "--"
        c = t.get("ci95_ms")
        return (f"{t['median_ms']:.3f} [{c[0]:.3f}, {c[1]:.3f}]" if c
                else f"{t['median_ms']:.3f}")

    lines = [
        r"\begin{table*}[ht]",
        r"\caption{Timings with their spread across independent runs: median of "
        r"per-run medians, milliseconds, with the 95\% bootstrap interval over "
        r"runs in brackets (ten runs on the M1 Pro and the Xeon VM, five on the "
        r"Pi~5). \emph{Sign}: the manifest signature, liboqs for ML-DSA and "
        r"OpenSSL otherwise; on the Pi, from the hashing experiment, which "
        r"times the same operation. \emph{Verify}: the "
        r"manifest signature. \emph{Path}: leaf and intermediate up to the root "
        r"anchor, through OpenSSL's X.509 stack.}",
        r"\label{tab:ci}",
        r"\footnotesize", r"\setlength{\tabcolsep}{3pt}",
        r"\begin{tabular}{ll" + "l" * len(plats) + "}", r"\toprule",
        r"Algorithm & Operation & " + " & ".join(n for n, _ in plats) + r"\\",
        r"\midrule",
    ]
    docs = {n: (load("e1_postquantum.json", d), load("e1_carriage.json", d)) for n, d in plats}
    hs = {n: load("e1_hash.json", d) for n, d in plats}
    for a in ALG_ORDER:
        for op in ("Sign", "Verify", "Path"):
            cells = []
            for n, _ in plats:
                pq, ca = docs[n]
                t = None
                if op == "Sign":
                    x = pq and next((y for y in pq["results"] if y["alg"] == a
                                     and y["chain_depth"] == 3), None)
                    if x:
                        t = x["sign_ms"].get("liboqs") or x["sign_ms"].get("openssl")
                    elif hs.get(n):
                        # The Pi ran no e1_pq; its signing times come from e1_hash.
                        h = hs[n]["results"][0]
                        if f"sign_{a}_ms" in h:
                            t = {"median_ms": h[f"sign_{a}_ms"],
                                 "ci95_ms": h.get(f"sign_{a}_ms_ci95")}
                elif ca:
                    x = next((y for y in ca["results"] if y["alg"] == a and y["carriage"] == "chain"), None)
                    if x:
                        t = x["verify_signature_ms"] if op == "Verify" else x["verify_path_ms"]
                cells.append(cell(t))
            lines.append(f"{a if op == 'Sign' else ''} & {op} & " + " & ".join(cells) + r"\\")
        if a != ALG_ORDER[-1]:
            lines.append(r"\addlinespace")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
    emit("ci.tex", lines)


def archive_numbers():
    for prefix, d in (("arch", load("e1_archive.json")),
                      ("archPi", load("e1_archive.json", os.path.join(ROOT, "out-pi-v2")))):
        if not d:
            continue
        r = d["results"]
        pa = {x["alg"]: x for x in r["per_asset"]}
        if "ES256" in pa:
            num(f"{prefix}CrossES", f"{pa['ES256']['crossover_bytes'] / 1024:.0f}")
        for a in pa:
            if a.startswith("ML-DSA"):
                k = tok(a)
                num(f"{prefix}Held{k}", f"{pa[a]['heldout_abs_error_median_pct']:.1f}")
                num(f"{prefix}TailOf{k}", f"{pa[a]['tail_ratio_mean_over_median']:.2f}")
                num(f"{prefix}IqrRel{k}", f"{pa[a]['fixed_cost_iqr_ms'] / pa[a]['fixed_cost_ms']:.2f}")
        ml = [pa[a]["crossover_bytes"] / 1048576 for a in pa if a.startswith("ML-DSA")]
        if ml:
            num(f"{prefix}CrossLo", f"{min(ml):.1f}")
            num(f"{prefix}CrossHi", f"{max(ml):.1f}")
        if "ML-DSA-65" in pa:
            x = pa["ML-DSA-65"]
            num(f"{prefix}FixMed", f"{x['fixed_cost_ms']:.2f}")
            num(f"{prefix}FixMean", f"{x['fixed_cost_mean_ms']:.2f}")
            num(f"{prefix}FixPnf", f"{x['fixed_cost_p95_ms']:.2f}")
            num(f"{prefix}Tail", f"{x['tail_ratio_mean_over_median']:.2f}")
        if "ES256" in pa:
            num(f"{prefix}TailES", f"{pa['ES256']['tail_ratio_mean_over_median']:.2f}")
        b = r["batch"]
        ws = sorted({x["workers"] for x in b})
        for x in b:
            w = "One" if x["workers"] == ws[0] else ("Max" if x["workers"] == ws[-1] else None)
            if not w:
                continue
            k = tok(x["alg"])
            num(f"{prefix}Err{w}{k}", f"{abs(x['error_median_pct']):.0f}")
            num(f"{prefix}ErrMean{w}{k}", f"{abs(x['error_mean_pct']):.0f}")
            num(f"{prefix}Eff{w}{k}", f"{x['parallel_efficiency']:.2f}")
        num(f"{prefix}MaxWorkers", f"{ws[-1]}")

    # The Pi's batch, repeated: run 1 in out-pi-v2, runs 2 and 3 in
    # out-pi-v3-runs. Median over runs and the range, per worker count.
    import glob
    runs = [load("e1_archive.json", os.path.join(ROOT, "out-pi-v2"))]
    runs += [load("e1_archive.json", p) for p in
             sorted(glob.glob(os.path.join(ROOT, "out-pi-v3-runs", "run*")))]
    runs = [x for x in runs if x]
    if len(runs) > 1:
        num("archPiRuns", f"{len(runs)}")
        b0 = runs[0]["results"]["batch"]
        ws = sorted({x["workers"] for x in b0})
        for a in ("ES256", "ML-DSA-65"):
            k = tok(a)
            for w, lab in ((ws[0], "One"), (ws[-1], "Max")):
                for fld, nm in (("error_median_pct", "Err"), ("error_mean_pct", "ErrMean"),
                                ("parallel_efficiency", "Eff")):
                    v = [next(x[fld] for x in rr["results"]["batch"]
                              if x["alg"] == a and x["workers"] == w) for rr in runs]
                    v = [abs(t) for t in v] if fld != "parallel_efficiency" else v
                    fmt = (lambda t: f"{t:.2f}") if nm == "Eff" else (lambda t: f"{t:.0f}")
                    num(f"archPi{nm}{lab}{k}", fmt(statistics.median(v)))
                    num(f"archPi{nm}{lab}{k}Lo", fmt(min(v)))
                    num(f"archPi{nm}{lab}{k}Hi", fmt(max(v)))
            allm = [abs(x["error_mean_pct"]) for rr in runs for x in rr["results"]["batch"]
                    if x["alg"] == a]
            num(f"archPiErrMeanAllMax{k}", f"{max(allm):.0f}")


def scale_numbers():
    import math
    plats = (("M", load("e8_scale.json")), ("X", load("e8_scale.json", os.path.join(ROOT, "out-x86"))),
             ("P", load("e8_scale.json", os.path.join(ROOT, "out-pi-v2"))))
    for t, d in plats:
        if not d:
            continue
        g = {(x["alg"], x["mode"], x["workers"]): x["per_s"] for x in d["results"]}
        ws = sorted({x["workers"] for x in d["results"]})
        hi = ws[-1]
        num(f"sc{t}Max", f"{hi}")
        for a in ("ML-DSA-65", "ES256", "PS256", "Ed25519", "ML-DSA-44"):
            k = tok(a)
            for m, mk in (("uncached", "Unc"), ("cached", "Cac"), ("cached-liboqs", "Oqs")):
                one = g.get((a, m, 1))
                top = g.get((a, m, hi))
                if one:
                    num(f"sc{t}{mk}{k}", f"{one:,.0f}")
                    # cores for ten thousand verifications a second, at one core's rate
                    num(f"sc{t}Cores{mk}{k}", f"{math.ceil(10000 / one)}")
                if one and top:
                    num(f"sc{t}Speed{mk}{k}", f"{top / one:.1f}")
        a, b = g.get(("ML-DSA-65", "uncached", 1)), g.get(("ES256", "uncached", 1))
        if a and b:
            num(f"sc{t}VsES", f"{100 * a / b:.0f}")
        a, b = g.get(("ML-DSA-65", "uncached", 1)), g.get(("PS256", "uncached", 1))
        if a and b:
            num(f"sc{t}VsPS", f"{100 * a / b:.0f}")



# --- the reference implementation's own manifests -----------------------------------

def tab_libsize():
    """Manifests c2pa-rs writes (leaf and intermediate, no timestamp) against
    our direct structures over the same image; replaces the earlier c2parust
    table, whose run carried the root."""
    ref = os.environ.get("LINEA_REF_IN", os.path.join(ROOT, "out-reference"))
    d, v, pq = load("e1_libsize.json", ref), load("e1_validation.json", ref), load("e1_postquantum.json")
    if not (d and v and pq):
        return
    key = {"ES256": "es256", "Ed25519": "ed25519", "ML-DSA-44": "mldsa44",
           "ML-DSA-65": "mldsa65", "ML-DSA-87": "mldsa87"}
    vrows = v["results"] if isinstance(v, dict) else v
    lines = [
        r"\begin{table}[t]",
        r"\caption{Manifests written by the C2PA reference implementation "
        r"(c2pa-rs \texttt{e2ad88e} with the RFC~9964 patch), carrying leaf and "
        r"intermediate, without a timestamp, over \texttt{kodim01}, against our "
        r"direct structure over the same image. \emph{Padding} is the space "
        r"c2pa-rs reserves in the unprotected header; \emph{outside} is the "
        r"claim, assertions and JUMBF framing around the signature. Validation "
        r"is by the same library with the path-validation patch "
        r"(Section~\ref{sec:patch}). \emph{Certificates} and \emph{outside} "
        r"are the library's; bytes except the last column.}",
        r"\label{tab:c2parust}",
        r"\small",
        r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{lrrrrrrr}",
        r"\toprule",
        r"Algorithm & Library & Ours & Difference & Padding & Certificates & Outside & Verify (ms)\\",
        r"\midrule",
    ]
    gaps = {}
    for a in ("Ed25519", "ES256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
        r = next((x for x in d["results"] if x["alg"] == a), None)
        o = next((x for x in pq["results"] if x["alg"] == a and x.get("chain_depth") == 3
                  and x["image"] == "kodim01.jpg"), None)
        if not (r and o):
            continue
        vs = [x for x in vrows if x["alg"] == key[a] and x["case"] == "chain_noroot"
              and x["patch"] == "p2"]
        if not vs or any(x["validation_state"] != "Trusted" for x in vs):
            raise SystemExit(f"libsize: {a} chain_noroot not Trusted under p2")
        vms = statistics.median(x["verify_ms"] for x in vs)
        gap = r["store_bytes"] - o["manifest_bytes"]
        gaps[a] = gap
        lines.append(f"{a} & {r['store_bytes']:,} & {o['manifest_bytes']:,} & {gap:,} & "
                     f"{r['pad_bytes']:,} & {r['chain_der_bytes']:,} & "
                     f"{r['outside_signature_bytes']:,} & {vms:.2f}\\\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("c2parust.tex", lines)
    pq_gaps = {g for a, g in gaps.items() if a.startswith("ML-DSA")}
    if len(pq_gaps) == 1:
        num("libgap", f"{pq_gaps.pop():,}")
    else:
        num("libgap", f"{min(pq_gaps):,} to {max(pq_gaps):,}")
    cl = [g for a, g in gaps.items() if not a.startswith("ML-DSA")]
    num("libgapClassLo", f"{min(cl):,}")
    num("libgapClassHi", f"{max(cl):,}")
    pads = [x["pad_bytes"] for x in d["results"]]
    num("libpadLo", f"{min(pads):,}")
    num("libpadHi", f"{max(pads):,}")
    outs = {x["outside_signature_bytes"] for x in d["results"]}
    num("liboutside", f"{max(outs):,}")
    ourj = {x["jumbf_overhead_bytes"] for x in pq["results"]}
    num("ouroutside", f"{max(ourj):,}")



def tab_corpus_supp():
    """Supplement: the 23 distinct production chains and where the files came from."""
    import csv
    base = os.path.join(ROOT, "data", "corpus")
    if not os.path.exists(os.path.join(base, "chains.csv")):
        return
    ch = list(csv.DictReader(open(os.path.join(base, "chains.csv"))))
    yn = lambda v: r"\checkmark" if v == "True" else ""
    lines = [
        r"{\footnotesize",
        r"\begin{longtable}{lllrrcccc}",
        r"\caption{The " + str(len(ch)) + r" distinct certificate chains in the "
        r"production corpus. \emph{Chain} is the first 16 hex digits of the "
        r"identifier (SHA-256 over the leaf's issuer name and every certificate "
        r"after the leaf). \emph{Groups} are the file groups whose files carry the "
        r"chain, in the active manifest or an ingredient. \emph{Sent}: "
        r"certificates in \texttt{x5chain}; \emph{Root}: a self-signed root is "
        r"among them; \emph{Listed}: the path ends at a trust-list anchor; "
        r"\emph{Issuer}: the leaf's issuer is that anchor. Certificate names and "
        r"the per-signature inventory, with every file's source URL, licence and "
        r"SHA-256, are in the released data (\texttt{data/corpus/}).}\label{tab:chains}\\",
        r"\toprule",
        r"Chain & Alg. & Groups & Files & Sigs & Sent & Root & Listed & Issuer\\",
        r"\midrule", r"\endfirsthead", r"\toprule",
        r"Chain & Alg. & Groups & Files & Sigs & Sent & Root & Listed & Issuer\\",
        r"\midrule", r"\endhead", r"\bottomrule", r"\endfoot",
    ]
    for c in ch:
        groups = c["groups"].replace("News publishers", "News").replace("; ", ", ")
        lines.append(f"\\texttt{{{c['chain_fingerprint']}}} & {c['alg']} & {groups} & "
                     f"{c['files']} & {c['signatures']} & {c['certs_transmitted']} & "
                     f"{yn(c['root_transmitted'])} & {yn(c['anchor_on_c2pa_list'])} & "
                     f"{yn(c['anchor_is_leaf_issuer'])}" + r"\\")
    lines += [r"\end{longtable}", "}"]
    emit("chains.tex", lines)
    num("corpMultiGroup", f"{sum(1 for c in ch if ',' in c['groups'] or ';' in c['groups'])}")
    used = {r["file"] for r in csv.DictReader(open(os.path.join(base, "inventory.csv")))}
    src = [r for r in csv.DictReader(open(os.path.join(base, "sources.csv"))) if r["file"] in used]
    import collections
    def site(r):
        u = r["page_url"] or r["source_url"]
        for k, v in (("wikimedia", "Wikimedia Commons"), ("huggingface", "Hugging Face"),
                     ("iptc", "IPTC"), ("cloudflare", "Cloudflare")):
            if k in u:
                return v
        return u.split("/")[2] if "//" in u else "other"
    cnt = collections.Counter((site(r), r["license_or_terms"].split(" (")[0]
                               .replace("Wikimedia Commons: ", "")[:60]) for r in src)
    lines = [
        r"\begin{table}[ht]",
        r"\caption{Where the " + str(len(src)) + r" production files came from, "
        r"with the licence or terms each source states. All were downloaded on "
        + ", ".join(sorted({r['download_date'] for r in src})) + r".}",
        r"\label{tab:corpussrc}",
        r"\small",
        r"\begin{tabular}{llr}", r"\toprule",
        r"Source & Licence or terms & Files\\", r"\midrule",
    ]
    for (si, lic), n in sorted(cnt.items(), key=lambda kv: -kv[1]):
        lic = lic.replace("&", r"\&").replace("_", r"\_")
        lines.append(f"{si} & {lic} & {n}" + r"\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("corpussrc.tex", lines)



def tab_cache_stale():
    """Supplement: stale trust with an unchanged trust list (e1_cache_stale)."""
    d = load("e1_cache_stale.json", os.environ.get("LINEA_REF_IN", os.path.join(ROOT, "out-reference")))
    if not d:
        return
    r = d["results"]
    lab = {"naive": "certificate hash", "expiry": "hash, path notAfter",
           "bounded": "hash, snapshot, policy; notAfter, nextUpdate"}
    lines = [
        r"\begin{table}[ht]",
        r"\caption{Stale trust with the trust list unchanged: " + f"{r[0]['stream']:,}"
        + r" manifests over " + str(r[0]["days"]) + r" simulated days from the "
        r"stream of Table~\ref{tab:cache}, with the most frequent publisher's "
        r"signing certificate expiring, or being revoked, on day "
        + str(r[0]["event_day"]) + r". \emph{Key and validity} is what a cache "
        r"entry is keyed on and what bounds its life; \emph{OCSP} is how long a "
        r"status response is valid. \emph{Accepted} counts that publisher's "
        r"manifests accepted after the event (of all it sent after the event), "
        r"and \emph{Last} how long after the event the last was accepted. "
        r"ML-DSA-65; ES256 behaves the same.}",
        r"\label{tab:cachestale}",
        r"\small", r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{llrrr}", r"\toprule",
        r"Event & Key and validity & OCSP & Accepted & Last (h)\\", r"\midrule",
    ]
    for ev in ("expiry", "revocation"):
        for x in [y for y in r if y["alg"] == "ML-DSA-65" and y["event"] == ev]:
            tot = x["accepted_after_event"] + x["rejected_after_event"]
            ov = f"{x['ocsp_valid_days']}\\,d" if x["design"] == "bounded" else "--"
            last = "--" if x["last_accept_hours_after_event"] is None else f"{x['last_accept_hours_after_event']:.0f}"
            lines.append(f"{ev.capitalize() if x['design'] == 'naive' else ''} & {lab[x['design']]} & "
                         f"{ov} & {x['accepted_after_event']} of {tot} & {last}" + r"\\")
        if ev == "expiry":
            lines.append(r"\midrule")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    emit("cachestale.tex", lines)
    g = {(x["alg"], x["event"], x["design"], x["ocsp_valid_days"]): x for x in r}
    a = "ML-DSA-65"
    n = g[(a, "expiry", "naive", None)]
    num("staleExpNaive", f"{n['accepted_after_event']}")
    num("staleExpTot", f"{n['accepted_after_event'] + n['rejected_after_event']}")
    n = g[(a, "revocation", "naive", 7)]
    num("staleRevNaive", f"{n['accepted_after_event']}")
    num("staleRevTot", f"{n['accepted_after_event'] + n['rejected_after_event']}")
    n = g[(a, "revocation", "expiry", 7)]
    num("staleRevExpiry", f"{n['accepted_after_event']}")
    for days, k in ((1, "One"), (7, "Seven")):
        n = g[(a, "revocation", "bounded", days)]
        num(f"staleRevBound{k}", f"{n['accepted_after_event']}")
        num(f"staleRevBound{k}H", f"{n['last_accept_hours_after_event']:.0f}")


# --- numbers.tex ------------------------------------------------------------------

def write_numbers():
    lines = ["%% generated by make_tables_v2.py; do not edit"]
    for k in sorted(NUM):
        assert k.isalpha(), k
        lines.append(f"\\newcommand{{\\N{k}}}{{{NUM[k]}}}")
    emit("numbers.tex", lines)


def main():
    print(f"  reading {OUT}")
    tab_pq()
    tab_carriage()
    tab_timestamp()
    tab_verify()
    tab_cache()
    tab_mixedchain()
    tab_extras()
    tab_stream()
    tab_validation()
    tab_libsize()
    tab_algsweep()
    text_numbers()
    profile_numbers()
    tab_mcu()
    tab_impls_x86()
    tab_audit()
    tab_corpus()
    tab_corpus_supp()
    tab_cache_stale()
    tab_ci()
    archive_numbers()
    scale_numbers()
    write_numbers()


if __name__ == "__main__":
    main()
