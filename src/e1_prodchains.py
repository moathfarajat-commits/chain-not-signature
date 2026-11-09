#!/usr/bin/env python3
"""
The certificate chains that shipping claim generators actually embed.

Every chain in this paper so far was one we built. Depth two and depth three
were chosen because they are what a textbook PKI looks like, and a reader is
entitled to ask whether real deployments look like that at all. If production
chains are deeper, or carry certificates fatter than ours, then the
certificate-dominance result is understated. If they are shallower, it is
overstated. Either way the assumption should not be left standing on our own
say-so.

So this reads the chains out of assets signed by other people's software.

The corpus is the C2PA public test file repository, whose "good" files are
produced by Conforming Generator Products under the C2PA Conformance Program:
Adobe, Truepic, Nikon and others, across the 1.4 and 2.2 specification
versions. These are the same bytes a validator implementer tests against, so
they are as close to production output as a public corpus gets.

Extraction is deliberately structural rather than clever. A C2PA manifest store
rides in JPEG APP11 segments; the signature inside it is a COSE_Sign1, which in
CBOR begins with tag 18 followed by a four-element array. Scanning the file for
that opening and decoding what follows finds every signature in the asset,
including the ones belonging to ingredients, which is what we want: an
ingredient's manifest is carried whole, certificates and all, and is part of
what the asset pays for.

What comes out is the distribution of chain depth, certificate size and
signature algorithm across real signers, plus how many of them carry a
timestamp, and what share of each manifest store the certificates occupy before
any post-quantum algorithm is involved.
"""

import glob
import json
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cbor2
from cryptography import x509
from cryptography.x509.oid import NameOID

from common import write_json

# COSE algorithm identifiers likely to appear in deployed manifests.
COSE_ALG_NAME = {
    -7: "ES256", -35: "ES384", -36: "ES512",
    -37: "PS256", -38: "PS384", -39: "PS512",
    -8: "EdDSA",
    -48: "ML-DSA-44", -49: "ML-DSA-65", -50: "ML-DSA-87",
}

HDR_ALG = 1
HDR_X5CHAIN = 33
HDR_X5T = 34

APP11 = 0xEB

# Each APP11 segment carries 8 bytes of its own framing before the JUMBF data:
# the tag "JP", a two-byte box instance number and a four-byte packet sequence
# number. A manifest store larger than a JPEG segment is split across several
# of them, so the store has to be reassembled before anything in it can be
# parsed. Decoding straight out of the file works only when the structure
# happens to fall inside one segment, which is exactly the kind of accident
# that makes a measurement look fine on the first asset and wrong on the rest.
APP11_FRAMING = 8


def manifest_store(blob):
    """Reassemble the C2PA manifest store from this JPEG's APP11 segments."""
    parts, i, n = [], 2, len(blob)
    while i < n - 1:
        if blob[i] != 0xFF:
            i += 1
            continue
        if blob[i + 1] == 0xFF:          # fill byte
            i += 1
            continue
        marker = blob[i + 1]
        if marker == 0xD9:               # end of image
            break
        if marker == 0xDA:               # start of scan; no headers past here
            break
        if i + 4 > n:
            break
        seg_len = int.from_bytes(blob[i + 2:i + 4], "big")
        if marker == APP11 and seg_len > 2 + APP11_FRAMING:
            parts.append(blob[i + 4 + APP11_FRAMING:i + 2 + seg_len])
        i += 2 + seg_len
    return b"".join(parts)


SIG_LABEL = b"c2pa.signature\x00"


def find_cose(store):
    """Every COSE_Sign1 in a reassembled manifest store, decoded.

    C2PA puts the signature in a JUMBF box labelled c2pa.signature whose
    content box has type "cbor". Reading the label and then the box header is
    exact, where scanning for the CBOR opening bytes is not: an asset with
    several ingredients holds several signatures, and image data contains the
    same byte pair by chance.
    """
    found, start = [], 0
    while True:
        i = store.find(SIG_LABEL, start)
        if i < 0:
            return found
        start = i + 1
        p = i + len(SIG_LABEL)
        if p + 8 > len(store):
            continue
        lbox = int.from_bytes(store[p:p + 4], "big")
        tbox = store[p + 4:p + 8]
        if tbox != b"cbor" or lbox < 8:
            continue
        payload = store[p + 8:p + lbox]
        try:
            obj = cbor2.loads(payload)
        except Exception:
            continue
        value = obj.value if isinstance(obj, cbor2.CBORTag) else obj
        # cbor2 hands back a tuple for a tagged array and a list for a bare
        # one, so accept either rather than the one the first asset showed.
        if not isinstance(value, (list, tuple)) or len(value) != 4:
            continue
        try:
            protected = cbor2.loads(value[0])
        except Exception:
            continue
        if not isinstance(protected, dict) or HDR_ALG not in protected:
            continue
        found.append((protected, value[1], value[3], len(payload)))


def cn_of(name):
    try:
        return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return None


def describe(protected, unprotected, signature):
    # RFC 9360 allows x5chain in either header bucket, and deployed generators
    # use both: the algorithm is integrity-protected, the chain often is not.
    # Reading only the protected header finds the algorithm and no certificates
    # at all, which reads as a conformance finding when it is a parsing bug.
    unp = dict(unprotected) if hasattr(unprotected, "keys") else {}
    merged = dict(unp)
    merged.update(protected)

    # Deployed 1.x generators label the chain with the string "x5chain" in the
    # unprotected header rather than RFC 9360's integer 33 in the protected
    # one. Both spellings mean the same thing to a validator that knows to look;
    # normalising them here keeps the string form from reading as an absent
    # chain. That the chain sits outside the protected header is itself worth
    # recording, and the row below does.
    for text_key, int_key in (("x5chain", HDR_X5CHAIN), ("x5t", HDR_X5T)):
        if text_key in merged and int_key not in merged:
            merged[int_key] = merged[text_key]

    alg_id = protected.get(HDR_ALG, merged.get(HDR_ALG))
    row = {
        "cose_alg_id": alg_id,
        "alg": COSE_ALG_NAME.get(alg_id, f"unknown({alg_id})"),
        "sig_bytes": len(signature) if signature else 0,
        "post_quantum": alg_id in (-48, -49, -50),
    }

    # Timestamps and revocation evidence live in the unprotected header.
    keys = {k for k in unp.keys() if isinstance(k, str)}
    row["has_timestamp"] = bool(keys & {"sigTst", "sigTst2"})
    row["has_ocsp"] = "rVals" in keys or "ocspVals" in keys

    chain = merged.get(HDR_X5CHAIN)
    if chain is None:
        row["carriage"] = "x5t" if HDR_X5T in merged else "none"
        row["chain_depth"] = 0
        row["chain_bytes"] = 0
        row["per_cert_bytes"] = []
        return row

    if isinstance(chain, (bytes, bytearray)):
        chain = [chain]
    chain = list(chain)
    row["carriage"] = "x5chain"
    row["chain_in_protected_header"] = HDR_X5CHAIN in protected
    row["chain_header_spelling"] = (
        "rfc9360_int33" if HDR_X5CHAIN in protected or HDR_X5CHAIN in unp
        else "text_x5chain")
    row["chain_depth"] = len(chain)
    row["per_cert_bytes"] = [len(c) for c in chain]
    row["chain_bytes"] = sum(row["per_cert_bytes"])

    subjects, issuers, key_algs = [], [], []
    for der in chain:
        try:
            c = x509.load_der_x509_certificate(bytes(der))
        except Exception:
            subjects.append(None)
            continue
        subjects.append(cn_of(c.subject))
        issuers.append(cn_of(c.issuer))
        key_algs.append(type(c.public_key()).__name__
                        .replace("PublicKey", "").replace("_", ""))
    row["subject_cns"] = subjects
    row["issuer_cns"] = issuers
    row["key_types"] = key_algs
    row["self_signed_root_included"] = bool(
        subjects and issuers and subjects[-1] == issuers[-1])
    return row


def main():
    corpus = os.environ.get("C2PA_TESTFILES", "/tmp/ptf")
    files = sorted(
        p for pattern in ("*.jpg", "*.jpeg")
        for p in glob.glob(os.path.join(corpus, "**", pattern), recursive=True)
        if "/bad/" not in p and os.path.getsize(p) > 1024)
    if not files:
        print(f"no assets under {corpus}; clone c2pa-org/public-testfiles first")
        return


    results = []
    for path in files:
        blob = open(path, "rb").read()
        rel = os.path.relpath(path, corpus)
        supplier = os.path.basename(path).split("-")[0]
        spec = rel.split(os.sep)[0]
        store_bytes = manifest_store(blob)
        store = len(store_bytes)

        sigs = [describe(p, u, sg) for p, u, sg, _ in find_cose(store_bytes)]
        if not sigs:
            continue

        certs_total = sum(s["chain_bytes"] for s in sigs)
        results.append({
            "file": rel,
            "supplier": supplier,
            "spec_dir": spec,
            "file_bytes": len(blob),
            "manifest_store_bytes": store,
            "manifest_share_pct": round(100 * store / len(blob), 3)
            if len(blob) else None,
            "signatures": len(sigs),
            "certificate_bytes_total": certs_total,
            "certificate_share_of_store_pct": round(100 * certs_total / store, 2)
            if store else None,
            "sig": sigs,
        })

    # --- what the corpus says ----------------------------------------------
    flat = [s for r in results for s in r["sig"]]
    depths = [s["chain_depth"] for s in flat if s["carriage"] == "x5chain"]
    leafs = [s["per_cert_bytes"][0] for s in flat if s.get("per_cert_bytes")]
    chains = [s["chain_bytes"] for s in flat if s["chain_bytes"]]

    def dist(xs):
        c = {}
        for x in xs:
            c[x] = c.get(x, 0) + 1
        return {str(k): v for k, v in sorted(c.items())}

    shares = [r["manifest_share_pct"] for r in results
              if r["manifest_share_pct"]]
    summary = {
        "assets": len(results),
        "signatures": len(flat),
        "suppliers": dist([r["supplier"] for r in results]),
        "algorithms": dist([s["alg"] for s in flat]),
        "carriage": dist([s["carriage"] for s in flat]),
        "chain_header_spelling": dist(
            [s.get("chain_header_spelling", "n/a") for s in flat]),
        "chain_in_protected_header": sum(
            1 for s in flat if s.get("chain_in_protected_header")),
        "chain_depth_distribution": dist(depths),
        "chain_depth_median": statistics.median(depths) if depths else None,
        "leaf_cert_bytes_median": statistics.median(leafs) if leafs else None,
        "leaf_cert_bytes_range": [min(leafs), max(leafs)] if leafs else None,
        "chain_bytes_median": statistics.median(chains) if chains else None,
        "chain_bytes_range": [min(chains), max(chains)] if chains else None,
        "with_timestamp": sum(1 for s in flat if s["has_timestamp"]),
        "with_ocsp": sum(1 for s in flat if s["has_ocsp"]),
        "post_quantum": sum(1 for s in flat if s["post_quantum"]),
        "manifest_share_pct_median": round(statistics.median(
            shares), 3) if shares else None,
    }

    print(f"  {summary['assets']} assets, {summary['signatures']} signatures")
    print(f"  suppliers          {summary['suppliers']}")
    print(f"  algorithms         {summary['algorithms']}")
    print(f"  carriage           {summary['carriage']}")
    print(f"  chain depth        {summary['chain_depth_distribution']} "
          f"(median {summary['chain_depth_median']})")
    print(f"  leaf cert bytes    median {summary['leaf_cert_bytes_median']}, "
          f"range {summary['leaf_cert_bytes_range']}")
    print(f"  chain bytes        median {summary['chain_bytes_median']}, "
          f"range {summary['chain_bytes_range']}")
    print(f"  timestamped        {summary['with_timestamp']}/{summary['signatures']}")
    print(f"  post-quantum       {summary['post_quantum']}/{summary['signatures']}")

    write_json("e1_prodchains.json", {"summary": summary, "assets": results},
               notes=[
                   "corpus: c2pa-org/public-testfiles, the 'good' files only",
                   "those files are produced by Conforming Generator Products under the C2PA Conformance Program",
                   "signatures include those of embedded ingredients, which the asset carries and pays for",
                   "a COSE_Sign1 is located by its CBOR opening, tag 18 over a four-element array",
                   "a candidate is accepted only if its protected header decodes to a map carrying an algorithm id",
                   "manifest_store_bytes is the payload of the JPEG APP11 segments, excluding JUMBF framing per segment",
               ])


if __name__ == "__main__":
    main()
