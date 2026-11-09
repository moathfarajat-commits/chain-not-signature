#!/usr/bin/env python3
"""Certificates for the validation matrix.

For each algorithm: a root, an intermediate, and a set of leaves that differ
in exactly one property. Every certificate follows the C2PA 2.5 profile as
c2pa-rs checks it: v3, SKI and AKI, basicConstraints, critical keyUsage, and
on leaves the c2pa-kp-claimSigning EKU (1.3.6.1.4.1.62558.2.1).

    leaf        the good signer
    badeku      EKU id-kp-serverAuth instead of claimSigning
    badku       keyUsage keyEncipherment only (no digitalSignature)
    tseku       EKU id-kp-timeStamping only (a TSA certificate used as signer)
    ocspresp    delegated OCSP responder, EKU id-kp-OCSPSigning
    bigcert     a valid leaf with a 1 MB non-critical extension (es256, mldsa65)
    short       valid from yesterday until SHORT_SECONDS from now, for the
                expiry tests (sign now, validate after it lapses)
    other/*     an unrelated root, intermediate and leaf (unknown anchor)

The OCSP responders and the main time-stamping authority are ES256; a second,
ML-DSA-65 time-stamping authority (tsa_mldsa65/) serves the fully
post-quantum cases.
Usage: gen_certs.py OUTDIR [SHORT_SECONDS]
"""
import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

C2PA_CLAIM_SIGNING = x509.ObjectIdentifier("1.3.6.1.4.1.62558.2.1")
KEYGEN = {
    "es256": lambda: ec.generate_private_key(ec.SECP256R1()),
    "ed25519": ed25519.Ed25519PrivateKey.generate,
    "mldsa44": mldsa.MLDSA44PrivateKey.generate,
    "mldsa65": mldsa.MLDSA65PrivateKey.generate,
    "mldsa87": mldsa.MLDSA87PrivateKey.generate,
}
NOW = datetime.datetime.now(datetime.timezone.utc)
DAY = datetime.timedelta(days=1)


def h(alg):
    return hashes.SHA256() if alg == "es256" else None


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Line A test PKI")])


def cert(alg, pub, subj, issuer_name, issuer_key, issuer_pub, kind,
         nb=None, na=None, eku=C2PA_CLAIM_SIGNING, ku_sign=True, pathlen=0, big=0):
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(issuer_name)
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(nb or NOW - DAY).not_valid_after(na or NOW + 700 * DAY))
    b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), False)
    b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_pub), False)
    if kind == "ca":
        b = b.add_extension(x509.BasicConstraints(True, pathlen), True)
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False,
                                          True, True, False, False), True)
    else:
        b = b.add_extension(x509.BasicConstraints(False, None), True)
        b = b.add_extension(x509.KeyUsage(ku_sign, False, not ku_sign, False, False,
                                          False, False, False, False), True)
        if eku is not None:
            b = b.add_extension(x509.ExtendedKeyUsage([eku]), True)
        if big:
            # an unknown, non-critical extension carrying `big` bytes
            b = b.add_extension(x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.4.1.99999.7.1"),
                b"\x04\x83" + big.to_bytes(3, "big") + b"\x00" * big), False)
    return b.sign(issuer_key, h(alg))


def pem_cert(c):
    return c.public_bytes(ser.Encoding.PEM)


def pem_key(k):
    return k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def hierarchy(alg, d, tag):
    """root, intermediate and leaves for one algorithm; returns the CA pair."""
    rk, ik = KEYGEN[alg](), KEYGEN[alg]()
    rc = cert(alg, rk.public_key(), name(f"{tag} {alg} Root"), name(f"{tag} {alg} Root"),
              rk, rk.public_key(), "ca", na=NOW + 3650 * DAY, pathlen=1)
    ic = cert(alg, ik.public_key(), name(f"{tag} {alg} Intermediate"), rc.subject,
              rk, rk.public_key(), "ca", na=NOW + 3000 * DAY, pathlen=0)
    write(f"{d}/root.pem", pem_cert(rc)); write(f"{d}/root.key", pem_key(rk))
    write(f"{d}/int.pem", pem_cert(ic)); write(f"{d}/int.key", pem_key(ik))
    return rc, rk, ic, ik


def leaf(alg, d, stem, ic, ik, **kw):
    k = KEYGEN[alg]()
    c = cert(alg, k.public_key(), name(f"{alg} {stem} signer"), ic.subject, ik,
             ik.public_key(), "leaf", **kw)
    write(f"{d}/{stem}.pem", pem_cert(c)); write(f"{d}/{stem}.key", pem_key(k))
    return c, k


def main():
    out = sys.argv[1]
    short = int(sys.argv[2]) if len(sys.argv) > 2 else 150
    for alg in KEYGEN:
        d = f"{out}/{alg}"
        rc, rk, ic, ik = hierarchy(alg, d, "Line A")
        leaf(alg, d, "leaf", ic, ik)
        leaf(alg, d, "badeku", ic, ik, eku=ExtendedKeyUsageOID.SERVER_AUTH)
        leaf(alg, d, "badku", ic, ik, ku_sign=False)
        leaf(alg, d, "short", ic, ik, na=NOW + datetime.timedelta(seconds=short))
        leaf(alg, d, "tseku", ic, ik, eku=ExtendedKeyUsageOID.TIME_STAMPING)
        # delegated OCSP responder issued by the signer's CA (RFC 6960 4.2.2.2)
        leaf(alg, d, "ocspresp", ic, ik, eku=ExtendedKeyUsageOID.OCSP_SIGNING)
        leaf(alg, d, "emaileku", ic, ik, eku=ExtendedKeyUsageOID.EMAIL_PROTECTION)
        if alg in ("es256", "mldsa65"):
            leaf(alg, d, "bigcert", ic, ik, big=1_000_000)
        orc, ork, oic, oik = hierarchy(alg, f"{d}/other", "Unrelated")
        leaf(alg, f"{d}/other", "leaf", oic, oik)

    # ES256 time-stamping authority: root, intermediate, a good TSA leaf with
    # id-kp-timeStamping (critical, as RFC 3161 requires) and a TSA leaf with
    # no timeStamping EKU.
    d = f"{out}/tsa"
    rc, rk, ic, ik = hierarchy("es256", d, "TSA")
    leaf("es256", d, "tsa", ic, ik, eku=ExtendedKeyUsageOID.TIME_STAMPING)
    leaf("es256", d, "tsa_noeku", ic, ik, eku=ExtendedKeyUsageOID.SERVER_AUTH)
    # ML-DSA-65 time-stamping authority, for the fully post-quantum cases.
    d = f"{out}/tsa_mldsa65"
    rc, rk, ic, ik = hierarchy("mldsa65", d, "TSA")
    leaf("mldsa65", d, "tsa", ic, ik, eku=ExtendedKeyUsageOID.TIME_STAMPING)
    leaf("mldsa65", d, "tsa_noeku", ic, ik, eku=ExtendedKeyUsageOID.SERVER_AUTH)
    print("certificates written to", out, "short-lived leaves expire at",
          (NOW + datetime.timedelta(seconds=short)).isoformat())


if __name__ == "__main__":
    main()
