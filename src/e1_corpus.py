#!/usr/bin/env python3
"""E1 corpus: what production signers ship, read against the C2PA trust list.

e1_prodchains.py read the C2PA public test files. Those turned out to be
mostly Adobe test chains ("C2PA Signer / Intermediate CA / Root CA"), which
says what a conformance test looks like rather than what deployments emit.
This script reads any set of C2PA-bearing files, in any container format, and
for every signature reports:

  roles            each transmitted certificate as leaf, intermediate, or
                   self-signed root, and whether the root was transmitted
                   (C2PA 2.5, Section 13.5: it should not be)
  anchor           which certificate, carried or not, is on the C2PA trust
                   list (an issuing CA or a root), and therefore how many
                   signatures path validation checks: one per certificate
                   below the anchor
  leaf-only        whether the leaf's issuer is itself a trust anchor, the
                   condition under which carrying the leaf alone conforms
  header           x5chain label (integer 33 or the deprecated string) and
                   bucket (protected or unprotected), and the claim version
                   (c2pa.claim, 1.x; c2pa.claim.v2, 2.x)
  timestamp        size of the RFC 3161 token, the TSA certificates it carries,
                   and whether the TSA chains to the C2PA TSA trust list

Distinct chains, issuing CAs and anchors are counted after de-duplication,
so a generator that signs a thousand files with one chain counts once.

usage: C2PA_CORPORA="label=path[,label=path...]" C2PA_TRUST=dir e1_corpus.py
"""

import collections
import glob
import hashlib
import os
import re
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cbor2  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization as ser  # noqa: E402
from cryptography.hazmat.primitives.serialization import pkcs7  # noqa: E402

from common import write_json  # noqa: E402
from e1_prodchains import (COSE_ALG_NAME, HDR_ALG, HDR_X5CHAIN, HDR_X5T,  # noqa: E402
                           find_cose, manifest_store)

EXTS = (".jpg", ".jpeg", ".png", ".heic", ".heif", ".avif", ".webp", ".mp4",
        ".mov", ".m4a", ".dng", ".tif", ".tiff", ".gif", ".pdf", ".wav", ".mp3")


# --- trust lists ----------------------------------------------------------------

def load_pem_list(path):
    if not os.path.exists(path):
        return []
    pem = open(path).read()
    return [x509.load_pem_x509_certificate(m.encode()) for m in re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)]


def spki(c):
    return c.public_key().public_bytes(ser.Encoding.DER,
                                       ser.PublicFormat.SubjectPublicKeyInfo)


class TrustList:
    def __init__(self, certs):
        self.certs = certs
        self.by_key = {hashlib.sha256(spki(c)).digest(): c for c in certs}
        self.by_subject = collections.defaultdict(list)
        for c in certs:
            self.by_subject[c.subject.public_bytes()].append(c)

    def is_anchor(self, c):
        return hashlib.sha256(spki(c)).digest() in self.by_key

    def issuer_anchor(self, c):
        """The listed certificate that issued c, if any (name and signature)."""
        for a in self.by_subject.get(c.issuer.public_bytes(), []):
            try:
                c.verify_directly_issued_by(a)
                return a
            except Exception:  # noqa: BLE001
                continue
        return None


# --- container-independent manifest-store location ---------------------------

def store_of(path, blob):
    if blob[:2] == b"\xff\xd8":
        return manifest_store(blob)
    # Elsewhere the JUMBF manifest store is contiguous: a 'jumb' superbox
    # whose description box is labelled 'c2pa'.
    i = 0
    while True:
        k = blob.find(b"jumb", i)
        if k < 4:
            return b""
        size = int.from_bytes(blob[k - 4:k], "big")
        head = blob[k + 4:k + 64]
        if b"jumd" in head and b"c2pa\x00" in head and size > 64:
            return blob[k - 4:k - 4 + size]
        i = k + 4


def claim_version(store):
    if b"c2pa.claim.v2" in store:
        return "2.x"
    if b"c2pa.claim\x00" in store:
        return "1.x"
    return "unknown"


# --- per signature ------------------------------------------------------------------

def _tlv(b, i):
    """(tag, header length, content length) of the DER element at i."""
    tag, ln = b[i], b[i + 1]
    if ln < 0x80:
        return tag, 2, ln
    n = ln & 0x7F
    return tag, 2 + n, int.from_bytes(b[i + 2:i + 2 + n], "big")


def unwrap_token(b):
    """C2PA 1.x stores a whole TimeStampResp (status, then token); later
    versions the bare TimeStampToken. Return the token either way."""
    try:
        tag, hl, ln = _tlv(b, 0)
        i = hl
        t1, h1, l1 = _tlv(b, i)
        if t1 == 0x30 and b[i + h1] == 0x02:          # PKIStatusInfo first
            j = i + h1 + l1
            t2, h2, l2 = _tlv(b, j)
            return b[j:j + h2 + l2], "TimeStampResp"
    except Exception:  # noqa: BLE001
        pass
    return b, "TimeStampToken"


def tst_info(unp, tsa_list):
    tokens = []
    for key in ("sigTst2", "sigTst"):
        v = unp.get(key)
        if hasattr(v, "get"):
            for t in v.get("tstTokens", []):
                if hasattr(t, "get") and isinstance(t.get("val"), (bytes, bytearray)):
                    tokens.append((key, bytes(t["val"])))
    out = []
    for key, raw in tokens:
        tok, form = unwrap_token(raw)
        info = {"header": key, "stored_bytes": len(raw), "token_bytes": len(tok),
                "stored_as": form}
        try:
            certs = pkcs7.load_der_pkcs7_certificates(tok)
        except Exception:  # noqa: BLE001
            certs = []
        info["tsa_certs"] = len(certs)
        info["tsa_cert_bytes"] = [len(c.public_bytes(ser.Encoding.DER)) for c in certs]
        info["tsa_cn"] = [cn(c.subject) for c in certs]
        anchored = None
        for c in certs:
            if tsa_list.is_anchor(c) or tsa_list.issuer_anchor(c):
                anchored = True
        info["tsa_on_c2pa_tsa_list"] = bool(anchored)
        out.append(info)
    return out


def cn(name):
    try:
        return name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    except Exception:  # noqa: BLE001
        return None


def describe(protected, unprotected, signature, trust, tsa_list):
    unp = dict(unprotected) if hasattr(unprotected, "keys") else {}
    alg_id = protected.get(HDR_ALG, unp.get(HDR_ALG))
    row = {"alg": COSE_ALG_NAME.get(alg_id, f"unknown({alg_id})"),
           "sig_bytes": len(signature) if signature else 0}
    label, bucket, chain = None, None, None
    for lab in (HDR_X5CHAIN, "x5chain"):
        for name, m in (("protected", protected), ("unprotected", unp)):
            if lab in m and chain is None:
                chain, label, bucket = m[lab], lab, name
    row["x5chain_label"] = {HDR_X5CHAIN: "33", "x5chain": "string"}.get(label)
    row["x5chain_bucket"] = bucket
    row["timestamps"] = tst_info(unp, tsa_list)
    row["has_ocsp"] = any(k in unp for k in ("rVals", "ocspVals"))
    if chain is None:
        row["carriage"] = "x5t" if (HDR_X5T in protected or "x5t" in unp) else "none"
        return row
    if isinstance(chain, (bytes, bytearray)):
        chain = [chain]
    ders = [bytes(d) for d in chain]
    certs = []
    for d in ders:
        try:
            certs.append(x509.load_der_x509_certificate(d))
        except Exception:  # noqa: BLE001
            certs.append(None)
    row["carriage"] = "x5chain"
    row["certs_transmitted"] = len(ders)
    row["cert_bytes"] = [len(d) for d in ders]
    row["chain_bytes"] = sum(row["cert_bytes"])
    # A chain is identified by its issuers: the leaf's issuer name and every
    # issuing certificate carried. Leaves differ per device or per image, and
    # a leaf-only chain carries no issuer certificate at all.
    try:
        leaf_issuer = x509.load_der_x509_certificate(ders[0]).issuer.public_bytes()
    except Exception:  # noqa: BLE001
        leaf_issuer = b""
    row["chain_fingerprint"] = hashlib.sha256(
        leaf_issuer + b"".join(ders[1:])).hexdigest()[:16]
    roles = []
    for c in certs:
        if c is None:
            roles.append("unparsed")
            continue
        try:
            bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except Exception:  # noqa: BLE001
            bc = False
        if not bc:
            roles.append("leaf")
        elif c.subject == c.issuer:
            roles.append("root")
        else:
            roles.append("intermediate")
    row["roles"] = roles
    row["root_transmitted"] = "root" in roles
    row["intermediates_transmitted"] = roles.count("intermediate")
    row["subject_cns"] = [cn(c.subject) if c else None for c in certs]
    row["key_types"] = [type(c.public_key()).__name__.replace("PublicKey", "")
                        if c else None for c in certs]
    try:
        row["leaf_key_bits"] = certs[0].public_key().key_size
    except Exception:  # noqa: BLE001
        row["leaf_key_bits"] = None

    # Where is the trust anchor? A carried certificate on the list, or the
    # listed issuer of the topmost carried certificate.
    anchor_pos, anchor_cn, anchor_carried = None, None, False
    for i, c in enumerate(certs):
        if c is not None and trust.is_anchor(c):
            anchor_pos, anchor_cn, anchor_carried = i, cn(c.subject), True
            break
    if anchor_pos is None:
        for i, c in enumerate(certs):
            if c is None:
                continue
            a = trust.issuer_anchor(c)
            if a is not None:
                anchor_pos, anchor_cn = i + 1, cn(a.subject)
                break
    row["anchor_on_c2pa_list"] = anchor_pos is not None
    row["anchor_cn"] = anchor_cn
    row["anchor_carried"] = anchor_carried
    # Signatures checked on the path: one per certificate below the anchor.
    row["path_signatures_checked"] = anchor_pos
    row["anchor_is_leaf_issuer"] = anchor_pos == 1
    row["leaf_only_would_conform"] = anchor_pos == 1
    if anchor_pos is not None:
        needed = ders[:anchor_pos]
        row["bytes_needed_for_path"] = sum(len(d) for d in needed)
        row["bytes_transmitted_not_needed"] = row["chain_bytes"] - row["bytes_needed_for_path"]
    return row


def main():
    spec = os.environ.get("C2PA_CORPORA")
    if not spec:
        sys.exit("set C2PA_CORPORA=label=path[,label=path]")
    tdir = os.environ.get("C2PA_TRUST", "/tmp/ctl/trust-list")
    trust = TrustList(load_pem_list(os.path.join(tdir, "C2PA-TRUST-LIST.pem")))
    tsa_list = TrustList(load_pem_list(os.path.join(tdir, "C2PA-TSA-TRUST-LIST.pem")))
    print(f"  trust list: {len(trust.certs)} anchors, TSA list: {len(tsa_list.certs)}")

    assets = []
    for part in spec.split(","):
        corpus, root = part.split("=", 1)
        files = sorted(p for p in glob.glob(os.path.join(root, "**", "*"), recursive=True)
                       if p.lower().endswith(EXTS) and os.path.isfile(p)
                       and "/bad/" not in p)
        for path in files:
            blob = open(path, "rb").read()
            store = store_of(path, blob)
            if not store:
                continue
            sigs = [describe(p, u, s, trust, tsa_list)
                    for p, u, s, _ in find_cose(store)]
            if not sigs:
                continue
            rel = os.path.relpath(path, root)
            gen = rel.split(os.sep)[1] if rel.startswith("files" + os.sep) \
                else rel.split(os.sep)[0]
            assets.append({"corpus": corpus, "file": rel, "generator": gen,
                           "format": os.path.splitext(path)[1].lower(),
                           "file_bytes": len(blob), "store_bytes": len(store),
                           "claim_version": claim_version(store),
                           "signatures": len(sigs), "sig": sigs})

    # --- summary, per corpus and generator, de-duplicated by chain ---------------
    def summarise(rows):
        flat = [s for a in rows for s in a["sig"]]
        x5 = [s for s in flat if s.get("carriage") == "x5chain"]
        uniq = {}
        for s in x5:
            uniq.setdefault(s["chain_fingerprint"], s)
        u = list(uniq.values())
        tst = [t for s in flat for t in s.get("timestamps", [])]
        c = collections.Counter
        return {
            "assets": len(rows), "signatures": len(flat),
            "distinct_chains": len(u),
            "claim_versions": dict(c(a["claim_version"] for a in rows)),
            "algorithms": dict(c(s["alg"] for s in flat)),
            "algorithms_by_chain": dict(c(s["alg"] for s in u)),
            "leaf_key_types_by_chain": dict(c(f"{s['key_types'][0]}-{s.get('leaf_key_bits')}"
                                              for s in u)),
            "x5chain_label": dict(c(str(s.get("x5chain_label")) for s in x5)),
            "x5chain_bucket": dict(c(str(s.get("x5chain_bucket")) for s in x5)),
            "certs_transmitted": dict(c(s["certs_transmitted"] for s in u)),
            "root_transmitted": sum(s["root_transmitted"] for s in u),
            "anchor_on_c2pa_list": sum(s["anchor_on_c2pa_list"] for s in u),
            "anchor_is_leaf_issuer": sum(bool(s["anchor_is_leaf_issuer"]) for s in u),
            "anchor_carried": sum(s["anchor_carried"] for s in u),
            "path_signatures_checked": dict(c(str(s["path_signatures_checked"]) for s in u)),
            "anchors": sorted({s["anchor_cn"] for s in u if s["anchor_cn"]}),
            "leaf_bytes_median": statistics.median(s["cert_bytes"][0] for s in u) if u else None,
            "chain_bytes_median": statistics.median(s["chain_bytes"] for s in u) if u else None,
            "bytes_transmitted_not_needed_median": statistics.median(
                s["bytes_transmitted_not_needed"] for s in u
                if s.get("bytes_transmitted_not_needed") is not None)
            if any(s.get("bytes_transmitted_not_needed") is not None for s in u) else None,
            "timestamped_signatures": sum(1 for s in flat if s.get("timestamps")),
            "tst_bytes_median": statistics.median(t["token_bytes"] for t in tst) if tst else None,
            "tst_bytes_range": [min(t["token_bytes"] for t in tst),
                                max(t["token_bytes"] for t in tst)] if tst else None,
            "tst_certs": dict(c(t["tsa_certs"] for t in tst)),
            "tsa_on_c2pa_tsa_list": sum(t["tsa_on_c2pa_tsa_list"] for t in tst),
            "with_ocsp": sum(1 for s in flat if s.get("has_ocsp")),
        }

    summary = {"all": summarise(assets)}
    for corpus in sorted({a["corpus"] for a in assets}):
        rows = [a for a in assets if a["corpus"] == corpus]
        summary[corpus] = summarise(rows)
        for gen in sorted({a["generator"] for a in rows}):
            summary[f"{corpus}/{gen}"] = summarise(
                [a for a in rows if a["generator"] == gen])
    for k, v in summary.items():
        print(f"  {k:40s} assets {v['assets']:4d} chains {v['distinct_chains']:3d} "
              f"anchored {v['anchor_on_c2pa_list']:3d} leaf-issuer-anchor "
              f"{v['anchor_is_leaf_issuer']:3d} root-sent {v['root_transmitted']:3d} "
              f"{v['claim_versions']} {v['algorithms']}")
    write_json("e1_corpus.json", {"summary": summary, "assets": assets}, notes=[
        f"corpora: {spec}",
        f"trust lists from {tdir}: {len(trust.certs)} signer anchors, "
        f"{len(tsa_list.certs)} TSA anchors",
        "anchor: a transmitted certificate on the C2PA trust list, or the listed "
        "certificate that verifiably issued the topmost transmitted one",
        "path_signatures_checked counts certificates below the anchor",
        "leaf_only_would_conform: the leaf's issuer is itself a trust anchor",
        "summary counts are over distinct chains (de-duplicated), except "
        "assets, signatures and timestamps",
    ])


if __name__ == "__main__":
    main()
