#!/usr/bin/env python3
"""Run the validation matrix: sign every case once, validate it with the
original-patch library (p1) and the extended-patch library (p2), and write
e1_validation.json.

    run_matrix.py            (from ~/line-a-experiments/c2pa-val)
"""
import datetime
import json
import os
import platform
import re
import subprocess
import sys
import time

V = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
CERTS = f"{V}/work/certs"
OUT = f"{V}/work/signed"
SPEC = f"{V}/work/spec"
IMG = os.path.expanduser("~/line-a-experiments/images/kodim01.jpg")
BIN = {"p1": f"{V}/bin/lineaval-p1", "p2": f"{V}/bin/lineaval-p2",
       "p0": f"{V}/bin/lineaval-p0"}
# The unmodified library validates the classical cases that bear on the two
# departures from C2PA 2.5, when bin/lineaval-p0 exists (build_p0.sh).
P0_CASES = {"eku_timestamping", "eku_timestamping_claimsigning_policy",
            "tsa_no_timestamping_eku", "chain_noroot_tsa", "tst_wrong_imprint",
            "expired_leaf_noeku_tst"}
P0_ALGS = {"es256", "ed25519"}


def builds(alg, name):
    have0 = os.path.exists(BIN["p0"])
    return ("p1", "p2") + (("p0",) if have0 and alg in P0_ALGS and name in P0_CASES else ())
SHORT = 300          # seconds the short-lived leaves stay valid
ALGS = ["es256", "ed25519", "mldsa44", "mldsa65", "mldsa87"]
for d in (OUT, SPEC):
    os.makedirs(d, exist_ok=True)


def run(cmd, timeout=600):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def sign(name, alg, x5chain, key, tsa=None, ocsp=None, mode="normal"):
    spec = {"alg": alg, "key": key, "x5chain": x5chain, "input": IMG,
            "output": f"{OUT}/{name}.jpg", "mode": mode, "python": PY,
            "tsa_script": f"{V}/tsa.py", "certdir": CERTS}
    if tsa:
        spec["tsa_variant"] = tsa
    if ocsp:
        spec["ocsp"] = ocsp
    p = f"{SPEC}/{name}.sign.json"
    json.dump(spec, open(p, "w"))
    rc, so, se = run([BIN["p2"], "sign", p])
    if rc != 0:
        return {"sign_error": (se or so).strip()[-600:]}
    return json.loads(so.strip().splitlines()[-1])


def verify(binary, path, anchors, tsa_anchors, ekus=None):
    spec = {"input": path, "anchors": anchors, "tsa_anchors": tsa_anchors}
    p = f"{SPEC}/v-{os.path.basename(path)}-{binary}.json"
    json.dump(spec, open(p, "w"))
    envv = dict(os.environ)
    if ekus:
        envv["LINEA_EKUS"] = ekus
    p2 = subprocess.run(["/usr/bin/time", "-l", BIN[binary], "verify", p],
                        capture_output=True, text=True, timeout=600, env=envv)
    rc, so, se = p2.returncode, p2.stdout, p2.stderr
    m = re.search(r"(\d+)\s+maximum resident set size", se)
    rss = int(m.group(1)) if m else None
    try:
        r = json.loads(so.strip().splitlines()[-1])
    except Exception:
        r = {"verify_error": (se or so).strip()[-600:]}
    r["max_rss_bytes"] = rss
    return r


# --- byte surgery on signed files -------------------------------------------

def segments(b):
    """(marker, start, end) of each JPEG segment before the scan."""
    i, out = 2, []
    while i < len(b) - 4:
        if b[i] != 0xFF:
            break
        m = b[i + 1]
        if m == 0xDA:
            out.append((m, i, len(b)))
            break
        ln = int.from_bytes(b[i + 2:i + 4], "big")
        out.append((m, i, i + 2 + ln))
        i += 2 + ln
    return out


def cose_span(b):
    """(start, end) of the active COSE_Sign1 inside the last c2pa APP11 run."""
    lab = b.rfind(b"c2pa.signature")
    s = b.find(b"\xd2\x84", lab)
    app11 = [(st, en) for m, st, en in segments(b) if m == 0xEB and st < s]
    end = [en for st, en in app11 if st <= s][-1]
    return s, end


def mutate(src, dst, how):
    b = bytearray(open(src, "rb").read())
    if how == "image":
        sos = [st for m, st, en in segments(b) if m == 0xDA][0]
        i = sos + 2000
        while b[i] in (0xFE, 0xFF) or b[i - 1] == 0xFF:
            i += 1
        b[i] ^= 0x01
    else:
        s, e = cose_span(b)
        if how == "sigflip":
            b[e - 20] ^= 0x01
        elif how == "cbor":
            b[s + 1] = 0x85               # array of four becomes array of five
        elif how == "truncate":
            mid = s + (e - s) // 2
            b[mid:e] = bytes(e - mid)
    open(dst, "wb").write(bytes(b))


# --- the matrix --------------------------------------------------------------

def cases(alg):
    C = f"{CERTS}/{alg}"
    root, inter = f"{C}/root.pem", f"{C}/int.pem"
    tsa_root = [f"{CERTS}/tsa/root.pem"]
    k = lambda s: f"{C}/{s}.key"
    L = lambda s: f"{C}/{s}.pem"
    out = [
        # (name, sign kwargs, anchors, tsa anchors, expected, group, post)
        ("chain_noroot_tsa", dict(x5chain=[L("leaf"), inter], key=k("leaf"), tsa="good"),
         [root], tsa_root, "Trusted", "positive", None),
        ("chain_noroot", dict(x5chain=[L("leaf"), inter], key=k("leaf")),
         [root], tsa_root, "Trusted", "positive", None),
        ("chain_withroot_tsa", dict(x5chain=[L("leaf"), inter, root], key=k("leaf"), tsa="good"),
         [root], tsa_root, "Trusted", "positive", None),
        ("leafonly_anchor_int", dict(x5chain=[L("leaf")], key=k("leaf"), tsa="good"),
         [inter], tsa_root, "Trusted", "positive", None),
        ("leafonly_anchor_root", dict(x5chain=[L("leaf")], key=k("leaf"), tsa="good"),
         [root], tsa_root, "not Trusted", "negative: missing intermediate", None),
        ("unknown_anchor", dict(x5chain=[L("leaf"), inter], key=k("leaf"), tsa="good"),
         [f"{C}/other/root.pem"], tsa_root, "not Trusted", "negative: unknown anchor", None),
        ("eku_serverauth", dict(x5chain=[L("badeku"), inter], key=k("badeku"), tsa="good"),
         [root], tsa_root, "sign refused", "negative: wrong EKU (generator)", None),
        ("eku_serverauth_direct", dict(x5chain=[L("badeku"), inter], key=k("badeku"),
                                       mode="direct"),
         [root], tsa_root, "not Trusted", "negative: wrong EKU", None),
        ("eku_timestamping", dict(x5chain=[L("tseku"), inter], key=k("tseku"), tsa="good"),
         [root], tsa_root, "not Trusted", "negative: wrong EKU (TSA purpose)", None),
        ("ku_no_digitalsignature", dict(x5chain=[L("badku"), inter], key=k("badku"), tsa="good"),
         [root], tsa_root, "sign refused", "negative: wrong key usage (generator)", None),
        ("ku_no_digitalsignature_direct", dict(x5chain=[L("badku"), inter], key=k("badku"),
                                               mode="direct"),
         [root], tsa_root, "not Trusted", "negative: wrong key usage", None),
        ("chain_noroot_direct", dict(x5chain=[L("leaf"), inter], key=k("leaf"), mode="direct"),
         [root], tsa_root, "Trusted", "control: harness-built COSE", None),
        ("image_modified", dict(x5chain=[L("leaf"), inter], key=k("leaf"), tsa="good"),
         [root], tsa_root, "Invalid", "negative: content changed", "image"),
        ("sig_bitflip", dict(x5chain=[L("leaf"), inter], key=k("leaf"), tsa="good"),
         [root], tsa_root, "Invalid", "negative: signature altered", "sigflip"),
        ("cose_cbor_corrupt", dict(x5chain=[L("leaf"), inter], key=k("leaf"), tsa="good"),
         [root], tsa_root, "Invalid", "negative: malformed COSE", "cbor"),
        ("cose_truncated", dict(x5chain=[L("leaf"), inter], key=k("leaf"), tsa="good"),
         [root], tsa_root, "Invalid", "negative: malformed COSE", "truncate"),
        ("tst_wrong_imprint", dict(x5chain=[L("leaf"), inter], key=k("leaf"), tsa="wrongimprint"),
         [root], tsa_root, "Trusted", "time stamp ignored (C2PA 2.5: timeStamp.mismatch is informational)", None),
        ("tsa_no_timestamping_eku", dict(x5chain=[L("leaf"), inter], key=k("leaf"), tsa="noeku"),
         [root], tsa_root, "Trusted", "time stamp ignored (C2PA 2.5: invalid TSA credential is informational)", None),
        ("tsa_anchor_absent", dict(x5chain=[L("leaf"), inter], key=k("leaf"), tsa="good"),
         [root], [], "Trusted", "time stamp ignored (C2PA 2.5: timeStamp.untrusted is informational)", None),
        ("ocsp_good", dict(x5chain=[L("leaf"), inter], key=k("leaf"), tsa="good",
                           ocsp=f"{C}/ocsp_good.der"),
         [root], tsa_root, "Trusted", "revocation: CA-signed response (not usable under C2PA 2.5 13.5.1.1)", None),
        ("ocsp_revoked", dict(x5chain=[L("leaf"), inter], key=k("leaf"), tsa="good",
                              ocsp=f"{C}/ocsp_revoked.der"),
         [root], tsa_root, "Trusted", "revocation: CA-signed response (not usable under C2PA 2.5 13.5.1.1)", None),
        ("ocsp_deleg_good", dict(x5chain=[L("leaf"), inter], key=k("leaf"), tsa="good",
                                 ocsp=f"{C}/ocsp_deleg_good.der"),
         [root], tsa_root, "Trusted", "revocation (delegated responder)", None),
        ("ocsp_deleg_revoked", dict(x5chain=[L("leaf"), inter], key=k("leaf"), tsa="good",
                                    ocsp=f"{C}/ocsp_deleg_revoked.der"),
         [root], tsa_root, "not Trusted", "negative: revoked (delegated responder)", None),
    ]
    # Fully post-quantum: ML-DSA-65 time-stamping authority and anchor.
    pq_root = [f"{CERTS}/tsa_mldsa65/root.pem"]
    out += [
        ("pqtsa_good", dict(x5chain=[L("leaf"), inter], key=k("leaf"), tsa="pq-good"),
         [root], pq_root, "Trusted", "positive: ML-DSA-65 time-stamping authority", None),
        ("pqtsa_wrong_imprint", dict(x5chain=[L("leaf"), inter], key=k("leaf"),
                                     tsa="pq-wrongimprint"),
         [root], pq_root, "Trusted", "time stamp ignored (ML-DSA-65 TSA, mismatched imprint)", None),
        ("pqtsa_no_timestamping_eku", dict(x5chain=[L("leaf"), inter], key=k("leaf"),
                                           tsa="pq-noeku"),
         [root], pq_root, "Trusted", "time stamp ignored (ML-DSA-65 TSA without timeStamping EKU)", None),
        ("pqtsa_anchor_absent", dict(x5chain=[L("leaf"), inter], key=k("leaf"), tsa="pq-good"),
         [root], [], "Trusted", "time stamp ignored (ML-DSA-65 TSA, anchor absent)", None),
        ("pqtsa_sig_bitflip", dict(x5chain=[L("leaf"), inter], key=k("leaf"), tsa="pq-good"),
         [root], pq_root, "Invalid", "negative: signature altered (ML-DSA-65 TSA)", "sigflip"),
    ]
    if True:
        # The harness builds these COSE structures itself (direct COSE handling).
        out += [
            ("x5t_thumbprint", dict(x5chain=[L("leaf"), inter], key=k("leaf"), mode="x5t"),
             [root, inter], tsa_root, "not Trusted", "thumbprint carriage", None),
            ("no_credential", dict(x5chain=[L("leaf"), inter], key=k("leaf"), mode="nochain"),
             [root], tsa_root, "Invalid", "negative: no credential", None),
        ]
    if alg == "mldsa44":
        out.append(("alg_header_mismatch", dict(x5chain=[L("leaf"), inter], key=k("leaf"),
                                                 mode="alg:-49"),
                    [root], tsa_root, "Invalid", "negative: algorithm/key mismatch", None))
    if alg == "es256":
        out.append(("alg_header_mismatch", dict(x5chain=[L("leaf"), inter], key=k("leaf"),
                                                 mode="alg:-8"),
                    [root], tsa_root, "Invalid", "negative: algorithm/key mismatch", None))
    if alg == "ed25519":
        out.append(("alg_header_mismatch", dict(x5chain=[L("leaf"), inter], key=k("leaf"),
                                                 mode="alg:-7"),
                    [root], tsa_root, "Invalid", "negative: algorithm/key mismatch", None))
    if alg in ("es256", "mldsa65"):
        out += [
            ("oversized_chain_50", dict(x5chain=[L("leaf")] + [inter] * 49, key=k("leaf")),
             [root], tsa_root, "not Trusted", "negative: oversized x5chain", None),
            ("oversized_cert_1MB", dict(x5chain=[L("bigcert"), inter], key=k("bigcert")),
             [root], tsa_root, "any", "negative: oversized certificate", None),
        ]
    return out


def short_cases(alg):
    C = f"{CERTS}/{alg}"
    root, inter = f"{C}/root.pem", f"{C}/int.pem"
    return [
        ("expired_leaf_with_tst", dict(x5chain=[f"{C}/short.pem", inter], key=f"{C}/short.key",
                                       tsa="good"),
         [root], [f"{CERTS}/tsa/root.pem"], "Trusted", "expiry: timestamp within validity", None),
        ("expired_leaf_no_tst", dict(x5chain=[f"{C}/short.pem", inter], key=f"{C}/short.key"),
         [root], [f"{CERTS}/tsa/root.pem"], "not Trusted", "negative: expired, no timestamp", None),
        # An expired signer must not gain historical validity from a timestamp
        # the validator rejects.
        ("expired_leaf_wrong_imprint_tst", dict(x5chain=[f"{C}/short.pem", inter],
                                                key=f"{C}/short.key", tsa="wrongimprint"),
         [root], [f"{CERTS}/tsa/root.pem"], "not Trusted",
         "negative: expired, timestamp over other data", None),
        ("expired_leaf_untrusted_tst", dict(x5chain=[f"{C}/short.pem", inter],
                                            key=f"{C}/short.key", tsa="good"),
         [root], [], "not Trusted", "negative: expired, timestamp from an untrusted TSA", None),
        ("expired_leaf_noeku_tst", dict(x5chain=[f"{C}/short.pem", inter],
                                        key=f"{C}/short.key", tsa="noeku"),
         [root], [f"{CERTS}/tsa/root.pem"], "not Trusted",
         "negative: expired, TSA without timeStamping EKU", None),
        ("expired_leaf_with_pqtst", dict(x5chain=[f"{C}/short.pem", inter], key=f"{C}/short.key",
                                         tsa="pq-good"),
         [root], [f"{CERTS}/tsa_mldsa65/root.pem"], "Trusted",
         "expiry: ML-DSA-65 timestamp within validity", None),
    ]


def classify(r):
    codes = r.get("codes", {})
    fail = [c["code"] for c in codes.get("failure", [])]
    succ = [c["code"] for c in codes.get("success", [])]
    info = [c["code"] for c in codes.get("informational", [])]
    state = r.get("validation_state")
    return {
        "crypto_valid": ("claimSignature.validated" in succ)
        and not any(c.startswith("claimSignature.") for c in fail),
        "profile_compliant": not any(c in ("signingCredential.invalid", "signingCredential.expired",
                                           "algorithm.unsupported") for c in fail),
        "trusted": state == "Trusted",
        "binding_ok": not any(c.startswith("assertion.") for c in fail),
        "timestamp_codes": [c for c in succ + info + fail if c.startswith("timeStamp")],
        # The signer's certificate is valid now (no expiry failure), and the
        # validator relied on a trusted timestamp for historical validity.
        "signer_valid_now": not any(c == "signingCredential.expired" for c in fail + info),
        "timestamp_trusted": "timeStamp.trusted" in succ,
        "credential_codes": [c for c in succ + info + fail if c.startswith("signingCredential")],
    }


def meets(expected, r, sgn=None):
    if expected == "sign refused":
        return bool(sgn and "sign_error" in sgn)
    s = r.get("validation_state")
    if expected == "any":
        return True
    if expected == "not Trusted":
        return s != "Trusted"
    if expected == "Invalid":
        return s in (None, "Invalid")
    return s == expected


def env():
    def sh(c):
        try:
            return subprocess.run(c, shell=True, capture_output=True, text=True).stdout.strip()
        except Exception:
            return None
    import cryptography
    return {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "hostname": platform.node(), "machine": platform.machine(),
        "cpu": sh("sysctl -n machdep.cpu.brand_string"), "os": platform.platform(),
        "c2pa_rs": sh(f"git -C {V}/c2pa-rs log -1 --format='%H %cd'"),
        "c2pa_rs_version": sh(f"grep -m1 '^version' {V}/c2pa-rs/Cargo.toml"),
        "c2pa_raw_crypto": "0.2.0 (crates.io), patched",
        "ml_dsa_crate": sh(f"grep -A1 'name = \"ml-dsa\"' {V}/harness/Cargo.lock | tail -1"),
        "rustc": sh("~/.cargo/bin/rustc --version"),
        "python_cryptography": cryptography.__version__,
        "paper_original_commit": "d589cf7 (0.92.0-dev, 24 September 2026)",
    }


def main():
    subprocess.run([PY, f"{V}/gen_certs.py", CERTS, str(SHORT)], check=True)
    subprocess.run([PY, f"{V}/ocsp.py", CERTS], check=True)
    t0 = time.time()
    rows = []
    pending = []
    # Short-lived leaves first, so they are signed while valid.
    for alg in ALGS:
        for name, kw, anchors, tsa_a, exp, group, post in short_cases(alg):
            fn = f"{alg}-{name}"
            s = sign(fn, alg, **kw)
            pending.append((alg, name, fn, s, anchors, tsa_a, exp, group, kw))
    for alg in ALGS:
        for name, kw, anchors, tsa_a, exp, group, post in cases(alg):
            fn = f"{alg}-{name}"
            s = sign(fn, alg, **kw)
            path = f"{OUT}/{fn}.jpg"
            if post and "sign_error" not in s:
                mutate(path, f"{OUT}/{fn}-m.jpg", post)
                path = f"{OUT}/{fn}-m.jpg"
            for b in builds(alg, name):
                r = verify(b, path, anchors, tsa_a) if "sign_error" not in s else {}
                rows.append(row(alg, name, group, kw, exp, b, s, r))
            print(alg, name, rows[-1]["validation_state"], rows[-1]["meets_expected"], flush=True)
            if name == "eku_timestamping":
                # the same file under a claimSigning-only policy, as the C2PA trust list uses
                for b in builds(alg, "eku_timestamping_claimsigning_policy"):
                    r = verify(b, path, anchors, tsa_a, ekus="1.3.6.1.4.1.62558.2.1")
                    rows.append(row(alg, "eku_timestamping_claimsigning_policy", group, kw,
                                    exp, b, s, r))
                print(alg, "eku_timestamping (claimSigning policy)",
                      rows[-1]["validation_state"], rows[-1]["meets_expected"], flush=True)
    wait = SHORT + 15 - (time.time() - t0)
    if wait > 0:
        print(f"waiting {wait:.0f} s for the short-lived leaves to expire", flush=True)
        time.sleep(wait)
    for alg, name, fn, s, anchors, tsa_a, exp, group, kw in pending:
        for b in builds(alg, name):
            r = verify(b, f"{OUT}/{fn}.jpg", anchors, tsa_a) if "sign_error" not in s else {}
            rows.append(row(alg, name, group, kw, exp, b, s, r))
        print(alg, name, rows[-1]["validation_state"], rows[-1]["meets_expected"], flush=True)
    doc = {
        "experiment": "e1_validation",
        "env": env(),
        "notes": [
            "every case is signed once through the patched c2pa-rs (extended patch build) and "
            "validated by p1, p2 and, for the classical cases bearing on the two departures, p0 = "
            "c2pa-rs e2ad88e unmodified (build_p0.sh); p1 = the patch as in the paper (ML-DSA signing and COSE "
            "verification only), p2 = p1 plus ML-DSA in certificate path validation "
            "(cert_signing_alg, signing_alg_to_sig_and_hash_oid, validator_for_sig_and_hash_algs)",
            "PKI: root -> intermediate -> leaf per algorithm, generated for the run; leaf EKU "
            "c2pa-kp-claimSigning; the root is not placed in x5chain unless the case says so",
            "time-stamping authority and its trust anchor are ES256 for every algorithm except "
            "the pqtsa_* and *_pqtst cases, which use an ML-DSA-65 authority and anchor; "
            "OCSP responses come in both RFC 6960 forms: signed by the issuing intermediate "
            "(CA-signed, no certificates in the response) and signed by a delegated responder "
            "(id-kp-OCSPSigning, issued by the same intermediate, certificate in the response)",
            "x5t, no-credential, algorithm-mismatch and the *_direct cases are built by the "
            "harness (direct COSE handling, no time stamp) because the library's signer never "
            "emits them: c2pa-rs refuses at signing time to sign with a leaf that fails its "
            "certificate profile (wrong EKU, no digitalSignature); chain_noroot_direct is the "
            "control showing a harness-built COSE of a good chain validates",
            "crypto_valid: claimSignature.validated reported and no claimSignature failure; "
            "profile_compliant: no signingCredential.invalid/expired or algorithm.unsupported; "
            "trusted: validation_state Trusted",
            "trust policy: the EKU list c2pa-rs ships as default (emailProtection, documentSigning, "
            "timeStamping, OCSPSigning, MS C2PA signing, c2pa-kp-claimSigning) on the manifest "
            "anchor set, timeStamping on the TSA anchor set; eku_timestamping is also validated "
            "under a claimSigning-only policy",
            "verify_ms is the Reader call inside the harness; max_rss_bytes is the whole process",
            f"short-lived leaves expire {SHORT} s after generation and are validated after expiry",
            "expected outcomes follow the C2PA 2.5 text; spec_basis gives the clause that "
            "decides a case where a reader might expect otherwise (spec_basis.json)",
        ],
        "results": rows,
    }
    basis = json.load(open(f"{V}/spec_basis.json"))
    for r in rows:
        if r["case"] in basis:
            r["spec_basis"] = basis[r["case"]]
    os.makedirs(f"{V}/results", exist_ok=True)
    json.dump(doc, open(f"{V}/results/e1_validation.json", "w"), indent=1)
    print("MATRIX_DONE", len(rows))


def row(alg, name, group, kw, exp, b, s, r):
    form = {1: "leaf", 2: "leaf+intermediate", 3: "leaf+intermediate+root"}.get(
        len(kw.get("x5chain", [])), f"{len(kw.get('x5chain', []))} certificates")
    if kw.get("mode") == "x5t":
        form = "x5t thumbprint"
    if kw.get("mode") == "nochain":
        form = "none"
    out = {"alg": alg, "case": name, "group": group, "patch": b, "x5chain_form": form,
           "tsa": kw.get("tsa"), "ocsp": bool(kw.get("ocsp")), "mode": kw.get("mode", "normal"),
           "expected": exp, "sign": s, "validation_state": r.get("validation_state"),
           "reader_error": r.get("reader_error") or r.get("verify_error"),
           "verify_ms": r.get("verify_ms"), "max_rss_bytes": r.get("max_rss_bytes"),
           "codes": r.get("codes")}
    out.update(classify(r))
    out["meets_expected"] = meets(exp, r, s) if (r or exp == "sign refused") else None
    return out


if __name__ == "__main__":
    main()
