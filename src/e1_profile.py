#!/usr/bin/env python3
"""E1 profile: is the generated certificate profile like production's?

Compares the bytes our certificates carry beyond public key and signature
(names, extensions, encoding) with those of the certificates on the C2PA
trust list, issuing CAs and roots separately. The trust list is vendored in
data/c2pa-trust-list with the commit it was taken from.
"""
import os
import re
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import write_json  # noqa: E402
import pq_cose  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization as ser  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TL = os.path.join(ROOT, "data", "c2pa-trust-list", "C2PA-TRUST-LIST.pem")


def overhead(c):
    der = c.public_bytes(ser.Encoding.DER)
    spki = c.public_key().public_bytes(ser.Encoding.DER,
                                       ser.PublicFormat.SubjectPublicKeyInfo)
    return len(der) - len(spki) - len(c.signature)


def main():
    pem = open(TL).read()
    cs = [x509.load_pem_x509_certificate(m.encode()) for m in re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)]
    ica = sorted(overhead(c) for c in cs if c.subject != c.issuer)
    roots = sorted(overhead(c) for c in cs if c.subject == c.issuer)
    rows = [{"source": "C2PA trust list", "role": "issuing CA", "n": len(ica),
             "overhead_bytes": ica, "median": statistics.median(ica)},
            {"source": "C2PA trust list", "role": "root", "n": len(roots),
             "overhead_bytes": roots, "median": statistics.median(roots)}]
    for alg in ("ES256", "PS256", "ML-DSA-65"):
        _, chain = pq_cose.build_chain(alg, 3)
        o = [overhead(x509.load_der_x509_certificate(d)) for d in chain]
        rows.append({"source": f"generated ({pq_cose.PROFILE})", "alg": alg,
                     "role": "leaf, issuing CA, root", "overhead_bytes": o})
    write_json("e1_profile.json", rows, notes=[
        "overhead: certificate DER length minus SubjectPublicKeyInfo and "
        "signature, i.e. names, validity, extensions and encoding",
        "trust list from c2pa-org/conformance-public, see data/c2pa-trust-list"])


if __name__ == "__main__":
    main()
