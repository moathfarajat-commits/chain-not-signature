#!/usr/bin/env python3
"""Size of the manifests the C2PA reference implementation itself writes.

Reads the leaf-and-intermediate manifests (no timestamp) that the validation
matrix signed through c2pa-rs (c2pa-val/run_matrix.py, case chain_noroot,
kodim01.jpg) and splits each manifest store into the COSE signature, the
padding c2pa-rs reserves in its unprotected header, the certificates it
carries, and everything outside the signature (claim, assertions, JUMBF
framing).

    LINEA_OUT=out-reference python3 src/e1_libsize.py <signed-dir>
"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e1_corpus as ec                               # noqa: E402
from common import write_json                        # noqa: E402

ALG = {"es256": "ES256", "ed25519": "Ed25519", "mldsa44": "ML-DSA-44",
       "mldsa65": "ML-DSA-65", "mldsa87": "ML-DSA-87"}


def main(src):
    rows = []
    for path in sorted(glob.glob(os.path.join(src, "*-chain_noroot.jpg"))):
        key = os.path.basename(path).split("-", 1)[0]
        blob = open(path, "rb").read()
        store = ec.store_of(path, blob)
        sigs = list(ec.find_cose(store))
        if len(sigs) != 1:
            sys.exit(f"{path}: {len(sigs)} signatures")
        prot, unprot, sig, cose_len = sigs[0]
        x5 = prot.get(33) or unprot.get(33)
        rows.append({
            "alg": ALG[key], "file": os.path.basename(path),
            "file_bytes": len(blob), "store_bytes": len(store),
            "cose_bytes": cose_len, "signature_bytes": len(sig),
            "certs_carried": len(x5), "chain_der_bytes": sum(len(c) for c in x5),
            "pad_bytes": len(unprot.get("pad", b"")),
            "outside_signature_bytes": len(store) - cose_len,
            "x5chain_bucket": "protected" if prot.get(33) else "unprotected",
        })
    write_json("e1_libsize.json", rows,
               notes=["c2pa-rs e2ad88e with the RFC 9964 patch (c2pa-val), "
                      "case chain_noroot, kodim01.jpg, no timestamp"])


if __name__ == "__main__":
    main(sys.argv[1])
