#!/usr/bin/env python3
"""E1 the anchors on the C2PA trust lists: role, lifetime and key usage.

Reads the snapshot in data/c2pa-trust-list/ (the claim-signing list and the
time-stamping list) and records, for every anchor, whether it is a root
(self-issued) or an issuing CA, its validity period, its key type and its
extended key usages. Section 5 uses it for two questions: how long the issuing
CAs that make leaf-only carriage conformant live, against the roots above them,
and whether the time-stamping list anchors issuing CAs too, which decides
whether a timestamp token can carry its signer's certificate alone.
"""

import hashlib
import os
import re
import sys

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import write_json  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LISTS = {"claim": "C2PA-TRUST-LIST.pem", "tsa": "C2PA-TSA-TRUST-LIST.pem"}
PEM = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def key_type(c):
    k = c.public_key()
    if isinstance(k, ec.EllipticCurvePublicKey):
        return f"EC {k.curve.name}"
    if isinstance(k, rsa.RSAPublicKey):
        return f"RSA {k.key_size}"
    return type(k).__name__


def ekus(c):
    try:
        return [e.dotted_string for e in
                c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value]
    except x509.ExtensionNotFound:
        return []


def main():
    base = os.path.join(ROOT, "data", "c2pa-trust-list")
    src = open(os.path.join(base, "SOURCE.txt")).read().strip()
    from cryptography.hazmat.primitives import serialization as _ser
    certs = {lst: [x509.load_pem_x509_certificate(m.encode())
                   for m in PEM.findall(open(os.path.join(base, fn)).read())]
             for lst, fn in LISTS.items()}
    fp = {lst: {hashlib.sha256(c.public_bytes(_ser.Encoding.DER)).hexdigest() for c in cs}
          for lst, cs in certs.items()}
    subj = {lst: {c.subject for c in cs} for lst, cs in certs.items()}
    rows = []
    for lst, fn in LISTS.items():
        other = "tsa" if lst == "claim" else "claim"
        for c in certs[lst]:
            h = hashlib.sha256(c.public_bytes(_ser.Encoding.DER)).hexdigest()
            nb, na = c.not_valid_before_utc, c.not_valid_after_utc
            rows.append({
                "list": lst,
                "role": "root" if c.issuer == c.subject else "issuing CA",
                "subject": c.subject.rfc4514_string(),
                "not_before": nb.date().isoformat(),
                "not_after": na.date().isoformat(),
                "validity_years": round((na - nb).days / 365.25, 1),
                "key": key_type(c),
                "eku": ekus(c),
                "der_bytes": len(c.public_bytes(_ser.Encoding.DER)),
                "sha256": h,
                "also_on_other_list": h in fp[other],
                "issuer_on_other_list": c.issuer != c.subject and c.issuer in subj[other],
            })
    write_json("e1_trustlist.json", rows, notes=[
        f"snapshot: {src}",
        "role: root if self-issued, otherwise issuing CA",
        "also_on_other_list: the same certificate is an anchor on both lists; "
        "issuer_on_other_list: the anchor's issuer is an anchor on the other list",
    ])


if __name__ == "__main__":
    main()
