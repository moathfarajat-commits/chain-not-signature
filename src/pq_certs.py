"""Real X.509 certificates for signature schemes `cryptography` cannot issue.

`cryptography` builds certificates for ML-DSA, Ed25519 and ECDSA (pq_cose.py)
but not for SLH-DSA or Falcon. This module builds them anyway: it encodes the
TBSCertificate itself, with the same fields and extensions pq_cose.py emits
(the C2PA certificate profile: key identifiers, basic constraints, key usage,
and emailProtection on the leaf), and signs it with liboqs. The result is a
complete certificate whose signature verifies, so its size is measured rather
than modelled.

The encoder is checked against `cryptography` on ML-DSA, where both can build
the certificate: same keys, serial and times give byte-identical DER, and
`cryptography` verifies the chain (check_against_cryptography below).

Object identifiers. ML-DSA and SLH-DSA use the NIST identifiers of FIPS 204
and FIPS 205. FN-DSA has none yet, so Falcon is encoded under a placeholder of
the same length in the same NIST arc; an assigned identifier there would give
the same size. The placeholders are not real assignments.
"""

import datetime
import hashlib
import os

NIST_SIG = "2.16.840.1.101.3.4.3."
OIDS = {
    "ML-DSA-44": NIST_SIG + "17", "ML-DSA-65": NIST_SIG + "18",
    "ML-DSA-87": NIST_SIG + "19",
    "SLH-DSA-SHA2-128s": NIST_SIG + "20", "SLH-DSA-SHA2-128f": NIST_SIG + "21",
    "SLH-DSA-SHA2-192s": NIST_SIG + "22", "SLH-DSA-SHA2-192f": NIST_SIG + "23",
    "SLH-DSA-SHA2-256s": NIST_SIG + "24", "SLH-DSA-SHA2-256f": NIST_SIG + "25",
    # placeholders, see the module docstring
    "Falcon-512": NIST_SIG + "98", "Falcon-1024": NIST_SIG + "99",
}
PLACEHOLDER_OID = {"Falcon-512", "Falcon-1024"}

OID_CN = "2.5.4.3"
OID_O = "2.5.4.10"
OID_SKI = "2.5.29.14"
OID_AKI = "2.5.29.35"
OID_BC = "2.5.29.19"
OID_KU = "2.5.29.15"
OID_EKU = "2.5.29.37"
OID_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4"
OID_C = "2.5.4.6"
OID_AIA = "1.3.6.1.5.5.7.1.1"
OID_OCSP = "1.3.6.1.5.5.7.48.1"
OID_CA_ISSUERS = "1.3.6.1.5.5.7.48.2"
OID_CRLDP = "2.5.29.31"
OID_CP = "2.5.29.32"


# --- DER ----------------------------------------------------------------------

def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + _len(len(body)) + body


def seq(*items):
    return tlv(0x30, b"".join(items))


def oid(dotted):
    arcs = [int(a) for a in dotted.split(".")]
    out = bytearray([40 * arcs[0] + arcs[1]])
    for a in arcs[2:]:
        enc = [a & 0x7F]
        a >>= 7
        while a:
            enc.append(0x80 | (a & 0x7F))
            a >>= 7
        out += bytes(reversed(enc))
    return tlv(0x06, bytes(out))


def integer(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True)
    return tlv(0x02, b)


def bitstring(b, unused=0):
    return tlv(0x03, bytes([unused]) + b)


def octets(b):
    return tlv(0x04, b)


def boolean(v):
    return tlv(0x01, b"\xff" if v else b"\x00")


def utf8(s):
    return tlv(0x0C, s.encode())


def utctime(t):
    return tlv(0x17, t.strftime("%y%m%d%H%M%SZ").encode())


def explicit(n, body):
    return tlv(0xA0 | n, body)


def name(cn):
    import pq_cose

    def rdn(o, v):
        return tlv(0x31, seq(oid(o), utf8(v)))
    parts = [rdn(OID_CN, cn), rdn(OID_O, "University of Jordan")]
    if pq_cose.PROFILE == "production":
        # countryName is a PrintableString, as cryptography encodes it
        parts.append(tlv(0x31, seq(oid(OID_C), tlv(0x13, b"JO"))))
    return seq(*parts)


def _uri(u):
    return tlv(0x86, u.encode())


def algid(alg):
    # FIPS 204 and FIPS 205 identifiers carry no parameters.
    return seq(oid(OIDS[alg]))


def extension(o, critical, value):
    parts = [oid(o)]
    if critical:
        parts.append(boolean(True))
    parts.append(octets(value))
    return seq(*parts)


def key_usage(ca):
    # digitalSignature and nonRepudiation for a signer; keyCertSign and
    # cRLSign for a CA, as pq_cose.py sets them. Named bits, DER-trimmed.
    if ca:
        return bitstring(bytes([0x06]), unused=1)    # bits 5, 6
    return bitstring(bytes([0xC0]), unused=6)        # bits 0, 1


def ski(pk):
    # RFC 5280 method 1, as cryptography's SubjectKeyIdentifier.from_public_key
    return hashlib.sha1(pk).digest()


def tbs_certificate(alg, serial, issuer_cn, subject_cn, not_before, not_after,
                    subject_pk, issuer_pk, ca):
    import pq_cose
    production = pq_cose.PROFILE == "production"
    exts = [
        extension(OID_SKI, False, octets(ski(subject_pk))),
        extension(OID_AKI, False, seq(tlv(0x80, ski(issuer_pk)))),
    ]
    if production and issuer_cn != subject_cn:
        # Same order and contents as pq_cose._cert: AIA, CRL DP, policy.
        slug = subject_cn.replace(" ", "-")
        host = pq_cose.CA_HOST
        exts.append(extension(OID_AIA, False, seq(
            seq(oid(OID_OCSP), _uri(f"http://ocsp.{host}")),
            seq(oid(OID_CA_ISSUERS), _uri(f"http://crt.{host}/{slug}-issuer.crt")))))
        exts.append(extension(OID_CRLDP, False, seq(seq(
            tlv(0xA0, tlv(0xA0, _uri(f"http://crl.{host}/{slug}-issuer.crl")))))))
        exts.append(extension(OID_CP, False, seq(seq(oid(pq_cose.POLICY_OID)))))
    if ca:
        exts.append(extension(OID_BC, True, seq(boolean(True), integer(1))))
        exts.append(extension(OID_KU, True, key_usage(True)))
    else:
        exts.append(extension(OID_BC, True, seq()))
        exts.append(extension(OID_KU, True, key_usage(False)))
        exts.append(extension(OID_EKU, True, seq(oid(
            pq_cose.C2PA_CLAIM_SIGNING if production else OID_EMAIL_PROTECTION))))
    return seq(
        explicit(0, integer(2)),
        integer(serial),
        algid(alg),
        name(issuer_cn),
        seq(utctime(not_before), utctime(not_after)),
        name(subject_cn),
        seq(algid(alg), bitstring(subject_pk)),
        explicit(3, seq(*exts)),
    )


def certificate(alg, tbs, signature):
    return seq(tbs, algid(alg), bitstring(signature))


# --- chains -----------------------------------------------------------------

def random_serial():
    # As x509.random_serial_number(): a positive 159-bit integer.
    return int.from_bytes(os.urandom(20), "big") >> 1


def build_chain(alg, depth, keypair, sign, now=None, serials=None):
    """[DER certs, leaf first] of the given depth, issued under one algorithm.

    keypair() -> (public_key_bytes, signing_handle); sign(handle, msg) -> sig.
    Names follow pq_cose.build_chain exactly, so sizes are comparable.
    """
    now = now or datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    later = now + datetime.timedelta(days=1825)
    keys = [keypair() for _ in range(depth)]
    serials = list(serials) if serials else [random_serial() for _ in range(depth)]

    root_pk, root_h = keys[-1]
    root_cn = f"{alg} Root"
    tbs = tbs_certificate(alg, serials[-1], root_cn, root_cn, now, later,
                          root_pk, root_pk, True)
    chain = [certificate(alg, tbs, sign(root_h, tbs))]
    issuer_cn, issuer_pk, issuer_h = root_cn, root_pk, root_h
    for i in range(depth - 2, -1, -1):
        pk, h = keys[i]
        cn = f"{alg} Signer" if i == 0 else f"{alg} Intermediate {i}"
        tbs = tbs_certificate(alg, serials[i], issuer_cn, cn, now, later,
                              pk, issuer_pk, i > 0)
        chain.insert(0, certificate(alg, tbs, sign(issuer_h, tbs)))
        issuer_cn, issuer_pk, issuer_h = cn, pk, h
    return keys[0], chain


def oqs_backend(mech):
    import oqs

    def keypair():
        s = oqs.Signature(mech)
        return s.generate_keypair(), s

    def sign(handle, msg):
        return handle.sign(msg)

    return keypair, sign


def verify_chain_oqs(mech, chain):
    """Check every non-root certificate's signature under its issuer, and the
    root's self-signature, with liboqs. Returns True if all verify."""
    import oqs
    v = oqs.Signature(mech)
    parsed = [_split(c) for c in chain]
    for i, (tbs, sig, pk) in enumerate(parsed):
        issuer_pk = parsed[i + 1][2] if i + 1 < len(parsed) else pk
        if not v.verify(tbs, sig, issuer_pk):
            return False
    return True


def _read(b, i):
    tag = b[i]
    n = b[i + 1]
    j = i + 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[j:j + k], "big")
        j += k
    return tag, j, j + n          # tag, content start, content end


def _split(cert):
    """(tbs DER, signature, subject public key) of one certificate."""
    _, s, _ = _read(cert, 0)
    _, ts, te = _read(cert, s)
    tbs = cert[s:te]
    _, as_, ae = _read(cert, te)           # signatureAlgorithm
    _, bs, be = _read(cert, ae)            # signatureValue
    sig = cert[bs + 1:be]
    i = ts
    tag, cs, ce = _read(cert, i)
    if tag == 0xA0:
        i = ce
    for _ in range(6):                      # serial .. subject, then SPKI
        tag, cs, ce = _read(cert, i)
        if _ < 5:
            i = ce
    spki_s, spki_e = cs, ce
    _, a_s, a_e = _read(cert, spki_s)
    _, ks, ke = _read(cert, a_e)
    pk = cert[ks + 1:ke]
    return tbs, sig, pk


def check_against_cryptography(alg="ML-DSA-65"):
    """Build an ML-DSA chain twice, with this encoder and with `cryptography`'s
    own builder as pq_cose.py uses it, from the same keys, serials and times.
    Returns True when every TBSCertificate is byte-identical and
    `cryptography` verifies the encoder's chain."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import mldsa
    import pq_cose
    gen = {"ML-DSA-44": mldsa.MLDSA44PrivateKey, "ML-DSA-65": mldsa.MLDSA65PrivateKey,
           "ML-DSA-87": mldsa.MLDSA87PrivateKey}[alg].generate
    keys = [gen() for _ in range(3)]
    it = iter(keys)

    def keypair():
        k = next(it)
        return k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw), k

    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    serials = [random_serial() for _ in range(3)]
    _, mine = build_chain(alg, 3, keypair, lambda k, m: k.sign(m), now=now,
                          serials=serials)
    certs = [x509.load_der_x509_certificate(c) for c in mine]
    for child, parent in zip(certs, certs[1:]):
        child.verify_directly_issued_by(parent)
    certs[-1].verify_directly_issued_by(certs[-1])

    def theirs(subject_key, issuer_name, issuer_key, cn, is_ca, serial,
               root=False):
        # pq_cose._cert itself, with the serial and time fixed
        return pq_cose._cert(subject_key.public_key(), issuer_name, issuer_key,
                             cn, is_ca, None,
                             issuer_pub=None if root else issuer_key.public_key(),
                             serial=serial, now=now)

    root = theirs(keys[2], pq_cose._name(f"{alg} Root"), keys[2], f"{alg} Root", True,
                  serials[2], root=True)
    mid = theirs(keys[1], root.subject, keys[2], f"{alg} Intermediate 1", True, serials[1])
    leaf = theirs(keys[0], mid.subject, keys[1], f"{alg} Signer", False, serials[0])
    same = [a.tbs_certificate_bytes == b.tbs_certificate_bytes
            for a, b in zip(certs, [leaf, mid, root])]
    same_len = [len(a) == len(b.public_bytes(ser.Encoding.DER))
                for a, b in zip(mine, [leaf, mid, root])]
    return all(same) and all(same_len), same, same_len


if __name__ == "__main__":
    for a in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
        print(a, check_against_cryptography(a))
