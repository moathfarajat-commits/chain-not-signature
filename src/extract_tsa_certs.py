#!/usr/bin/env python3
"""Extract the time-stamping authority certificates from the production files.

For every production file with an RFC 3161 timestamp, pull the TSA certificates
out of the token (reusing e1_corpus_v4's parsing), group them by the certificate
chain, and write each distinct TSA chain to disk as PEM. Record, per chain, the
operator, the subject and issuer common names, the leaf's extended key usage and
CA flag, its validity window, whether the chain anchors to the C2PA TSA trust
list, and whether its issuer is an anchor on the C2PA claim-signing list.

    C2PA_CORPORA=production=<corpus root> C2PA_TRUST=<trust-list dir> \
        python extract_tsa_certs.py <out dir>

The output feeds the harness check that runs each production TSA certificate
through the library's certificate-profile and trust checks against the
claim-signing list, with no signature.
"""

import glob
import hashlib
import json
import os
import re
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtensionOID

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e1_prodchains import find_cose, manifest_store  # noqa: E402
from e1_corpus_v4 import TrustList, load_pem_list, store_of, unwrap_token  # noqa: E402

EXTS = (".jpg", ".jpeg", ".png", ".heic", ".heif", ".avif", ".webp", ".mp4",
        ".mov", ".m4a", ".dng", ".tif", ".tiff", ".gif", ".pdf", ".wav", ".mp3")


def cn(name):
    try:
        return name.rfc4514_string()
    except Exception:
        return ""


def common_name(name):
    a = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return a[0].value if a else cn(name)


def eku_oids(cert):
    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        return [o.dotted_string for o in eku]
    except x509.ExtensionNotFound:
        return []


def is_ca(cert):
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        return bool(bc.ca)
    except x509.ExtensionNotFound:
        return False


def operator(cns):
    s = " ".join(cns).lower()
    for name, needle in [("Google", "google"), ("DigiCert", "digicert"),
                         ("Microsoft", "microsoft"), ("Sectigo", "sectigo"),
                         ("Entrust", "entrust"), ("GlobalSign", "globalsign"),
                         ("Apple", "apple"), ("Truepic", "truepic")]:
        if needle in s:
            return name
    return cns[0] if cns else "unknown"


def tsa_tokens(store):
    out = []
    for protected, unprotected, _sig, _raw in find_cose(store):
        for key in ("sigTst2", "sigTst"):
            v = unprotected.get(key)
            if not hasattr(v, "get"):
                continue
            for t in v.get("tstTokens", []):
                if hasattr(t, "get") and isinstance(t.get("val"), (bytes, bytearray)):
                    tok, _form = unwrap_token(bytes(t["val"]))
                    try:
                        certs = pkcs7.load_der_pkcs7_certificates(tok)
                    except Exception:
                        certs = []
                    if certs:
                        out.append(certs)
    return out


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: extract_tsa_certs.py <out dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    spec = os.environ["C2PA_CORPORA"]
    tdir = os.environ.get("C2PA_TRUST", "/tmp/ctl/trust-list")
    claim_list = TrustList(load_pem_list(os.path.join(tdir, "C2PA-TRUST-LIST.pem")))
    tsa_list = TrustList(load_pem_list(os.path.join(tdir, "C2PA-TSA-TRUST-LIST.pem")))

    chains = {}
    nfiles = 0
    for part in spec.split(","):
        _corpus, root = part.split("=", 1)
        files = sorted(p for p in glob.glob(os.path.join(root, "**", "*"), recursive=True)
                       if p.lower().endswith(EXTS) and os.path.isfile(p))
        for path in files:
            blob = open(path, "rb").read()
            store = store_of(path, blob)
            if not store:
                continue
            nfiles += 1
            for certs in tsa_tokens(store):
                leaf = certs[0]
                der = leaf.public_bytes(ser.Encoding.DER)
                fp = hashlib.sha256(der).hexdigest()[:16]
                if fp in chains:
                    chains[fp]["files"] += 1
                    continue
                cns = [common_name(c.subject) for c in certs]
                anchored = any(tsa_list.is_anchor(c) or tsa_list.issuer_anchor(c)
                               for c in certs)
                issuer_on_claim = claim_list.is_anchor(certs[1]) if len(certs) > 1 else False
                issuer_issued_by_claim = (claim_list.issuer_anchor(certs[1])
                                          if len(certs) > 1 else None)
                chains[fp] = {
                    "fp": fp,
                    "operator": operator(cns),
                    "subject_cns": cns,
                    "leaf_subject_cn": cns[0],
                    "leaf_issuer_cn": common_name(leaf.issuer),
                    "leaf_eku": eku_oids(leaf),
                    "leaf_is_ca": is_ca(leaf),
                    "not_before": leaf.not_valid_before_utc.isoformat(),
                    "not_after": leaf.not_valid_after_utc.isoformat(),
                    "certs_in_token": len(certs),
                    "anchors_to_tsa_list": anchored,
                    "issuer_is_claim_anchor": bool(issuer_on_claim),
                    "issuer_issued_by_claim_anchor": bool(issuer_issued_by_claim),
                    "files": 1,
                }
                # Write the leaf alone and the full carried chain (leaf first).
                base = os.path.join(outdir, fp)
                with open(base + "-leaf.pem", "wb") as f:
                    f.write(leaf.public_bytes(ser.Encoding.PEM))
                with open(base + "-chain.pem", "wb") as f:
                    for c in certs:
                        f.write(c.public_bytes(ser.Encoding.PEM))

    rows = sorted(chains.values(), key=lambda r: (-r["files"], r["operator"]))
    json.dump({"files_scanned": nfiles, "distinct_tsa_chains": len(rows),
               "chains": rows}, open(os.path.join(outdir, "tsa_chains.json"), "w"),
              indent=2)
    print(f"scanned {nfiles} files, {len(rows)} distinct TSA chains")
    for r in rows:
        print(f"  {r['fp']}  {r['operator']:10s}  files={r['files']:3d}  "
              f"eku={','.join(r['leaf_eku']) or '-':22s}  ca={r['leaf_is_ca']}  "
              f"tsaAnchored={r['anchors_to_tsa_list']}  "
              f"issuerClaimAnchor={r['issuer_is_claim_anchor']}  "
              f"issuerUnderClaim={r['issuer_issued_by_claim_anchor']}")


if __name__ == "__main__":
    main()
