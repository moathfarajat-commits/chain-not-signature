"""Real RFC 3161 timestamp tokens under post-quantum and classical keys.

No library we can use issues an RFC 3161 token signed with ML-DSA, so this
module builds one: a CMS SignedData (RFC 5652) whose content is a TSTInfo
(RFC 3161), with the signed attributes a time-stamping authority emits
(content type, message digest, and the ESS signing-certificate-v2 attribute of
RFC 5035), signed by a TSA whose three-certificate chain travels in the token.

Algorithms follow the CMS profiles: ML-DSA per RFC 9882 with SHA-512 as the
digest algorithm, Ed25519 per RFC 8419 with SHA-512, ES256 as
ecdsa-with-SHA256 with SHA-256. The TSA leaf carries the id-kp-timeStamping
extended key usage, critical, as RFC 3161 requires.

Fields that vary between real authorities are set to typical values and
named here so a reader can adjust them: a 10-byte policy identifier (a
placeholder under the private-enterprise arc, not a real assignment), a 16-byte
serial, GeneralizedTime with milliseconds, accuracy of one second, and an
8-byte nonce echoed from the request. No TSA name field.

The token's signature is verified before it is measured, and on a machine
with OpenSSL 3.5 or later run_extra.sh also has `openssl ts -verify` check it.
"""

import datetime
import hashlib
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, padding, rsa

import pq_certs as d
import pq_cose
from pq_cose import _name

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_ED25519 = "1.3.101.112"
OID_SHA256_RSA = "1.2.840.113549.1.1.11"
OID_TIMESTAMPING = "1.3.6.1.5.5.7.3.8"
TSA_POLICY = "1.3.6.1.4.1.99999.1.1"      # placeholder, see the docstring

SIG_OID = {"ML-DSA-44": d.OIDS["ML-DSA-44"], "ML-DSA-65": d.OIDS["ML-DSA-65"],
           "ML-DSA-87": d.OIDS["ML-DSA-87"], "ES256": OID_ECDSA_SHA256,
           "Ed25519": OID_ED25519, "PS256": OID_SHA256_RSA}
# A PS256 signer's TSA is an RSA TSA signing PKCS#1 v1.5 with SHA-256, which is
# what deployed time-stamping authorities use.
DIGEST = {"ES256": (OID_SHA256, hashlib.sha256),
          "PS256": (OID_SHA256, hashlib.sha256)}
KEYGEN = {"ML-DSA-44": mldsa.MLDSA44PrivateKey.generate,
          "ML-DSA-65": mldsa.MLDSA65PrivateKey.generate,
          "ML-DSA-87": mldsa.MLDSA87PrivateKey.generate,
          "Ed25519": ed25519.Ed25519PrivateKey.generate,
          "ES256": lambda: ec.generate_private_key(ec.SECP256R1()),
          "PS256": lambda: rsa.generate_private_key(65537, 2048)}


def _digest(alg):
    return DIGEST.get(alg, (OID_SHA512, hashlib.sha512))


def _sign(alg, key, msg):
    if alg == "ES256":
        return key.sign(msg, ec.ECDSA(hashes.SHA256()))   # DER, as CMS uses
    if alg == "PS256":
        return key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    return key.sign(msg)


def _verify(alg, pub, sig, msg):
    if alg == "ES256":
        pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    elif alg == "PS256":
        pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
    else:
        pub.verify(sig, msg)


def _cert(subject_pub, issuer_name, issuer_key, cn, is_ca, h, issuer_pub, eku):
    """pq_cose's certificate profile, with the TSA's extended key usage.

    issuer_pub equal to subject_pub marks the self-signed root, which carries
    no AIA, CRL or policy extensions, as in pq_cose."""
    root = issuer_pub is subject_pub or (
        issuer_pub is not None and issuer_pub == subject_pub)
    return pq_cose._cert(subject_pub, issuer_name, issuer_key, cn, is_ca, h,
                         issuer_pub=None if root else issuer_pub, eku=eku)


def tsa_chain(alg):
    """A TSA's three-certificate chain: [leaf, intermediate, root] and keys."""
    h = hashes.SHA256() if alg in ("ES256", "PS256") else None
    root, mid, leaf = KEYGEN[alg](), KEYGEN[alg](), KEYGEN[alg]()
    rc = _cert(root.public_key(), _name(f"{alg} TSA Root"), root, f"{alg} TSA Root",
               True, h, root.public_key(), None)
    mc = _cert(mid.public_key(), rc.subject, root, f"{alg} TSA Intermediate", True, h,
               root.public_key(), None)
    lc = _cert(leaf.public_key(), mc.subject, mid, f"{alg} Time Stamping", False, h,
               mid.public_key(), OID_TIMESTAMPING)
    return [lc, mc, rc], leaf


def tstinfo(message_imprint, digest_oid=OID_SHA256):
    now = datetime.datetime.now(datetime.timezone.utc)
    gen_time = now.strftime("%Y%m%d%H%M%S") + f".{now.microsecond // 1000:03d}Z"
    return d.seq(
        d.integer(1),
        d.oid(TSA_POLICY),
        d.seq(d.seq(d.oid(digest_oid)), d.octets(message_imprint)),
        d.integer(int.from_bytes(os.urandom(16), "big") >> 1),
        d.tlv(0x18, gen_time.encode()),
        d.seq(d.integer(1)),                          # accuracy: 1 s
        d.integer(int.from_bytes(os.urandom(8), "big") >> 1),   # nonce
    )


def _attr(oid_, value):
    return d.seq(d.oid(oid_), d.tlv(0x31, value))


def token(alg, message_imprint, chain=None, key=None, include_root=False):
    """(TimeStampToken DER, details). message_imprint is a SHA-256 digest of
    what is being timestamped (for C2PA, the claim signature).

    The token carries the TSA's certificate and its intermediate; the root is
    the TSA trust anchor the validator already holds (the C2PA TSA trust list),
    so it is left out unless include_root is set."""
    if chain is None:
        chain, key = tsa_chain(alg)
    carried = chain if include_root else chain[:-1]
    certs = [c.public_bytes(ser.Encoding.DER) for c in carried]
    info = tstinfo(message_imprint)
    dig_oid, dig = _digest(alg)
    leaf_der = certs[0]
    ess = d.seq(d.seq(d.seq(d.octets(hashlib.sha256(leaf_der).digest()))))
    attrs = [
        _attr(OID_CONTENT_TYPE, d.oid(OID_TSTINFO)),
        _attr(OID_MESSAGE_DIGEST, d.octets(dig(info).digest())),
        _attr(OID_SIGNING_CERT_V2, ess),
    ]
    attrs.sort()          # DER SET OF: elements in ascending encoded order
    signed_attrs_set = d.tlv(0x31, b"".join(attrs))
    sig = _sign(alg, key, signed_attrs_set)
    _verify(alg, chain[0].public_key(), sig, signed_attrs_set)

    leaf = chain[0]
    issuer_and_serial = d.seq(leaf.issuer.public_bytes(), d.integer(leaf.serial_number))
    signer_info = d.seq(
        d.integer(1),
        issuer_and_serial,
        d.seq(d.oid(dig_oid)),
        d.tlv(0xA0, b"".join(attrs)),                 # [0] IMPLICIT SET
        d.seq(d.oid(SIG_OID[alg])),
        d.octets(sig),
    )
    signed_data = d.seq(
        d.integer(3),
        d.tlv(0x31, d.seq(d.oid(dig_oid))),
        d.seq(d.oid(OID_TSTINFO), d.explicit(0, d.octets(info))),
        d.tlv(0xA0, b"".join(certs)),                 # certificates [0] IMPLICIT
        d.tlv(0x31, signer_info),
    )
    tok = d.seq(d.oid(OID_SIGNED_DATA), d.explicit(0, signed_data))
    return tok, {
        "token_bytes": len(tok),
        "tsa_chain_bytes": sum(len(c) for c in certs),
        "tsa_cert_bytes": [len(c) for c in certs],
        "tsa_cert_roles": ["TSA signer", "TSA intermediate", "TSA root"][:len(certs)],
        "tsa_root_bytes_not_carried": (0 if include_root else
                                       len(chain[-1].public_bytes(ser.Encoding.DER))),
        "signature_bytes": len(sig),
        "structure_bytes": len(tok) - sum(len(c) for c in certs) - len(sig),
        "tstinfo_bytes": len(info),
        "signed_attributes_bytes": len(signed_attrs_set),
        "other_encoding_bytes": (len(tok) - sum(len(c) for c in certs) - len(sig)
                                 - len(info) - len(signed_attrs_set)),
        "digest_algorithm": "SHA-256" if dig_oid == OID_SHA256 else "SHA-512",
    }
