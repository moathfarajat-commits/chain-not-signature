#!/usr/bin/env python3
"""
RFC 9964 COSE_Sign1 builder for post-quantum C2PA manifests.

c2pa-rs accepts seven signature algorithms, all classical: ES256/384/512,
PS256/384/512 and Ed25519. Its SigningAlg enum is closed, so no post-quantum
manifest can be produced through the library or through c2patool. This module
builds the COSE_Sign1 structure directly instead, following RFC 9964
("ML-DSA for JOSE and COSE", Standards Track, May 2026) so the bytes are
conformant even though the C2PA validator will not recognise the algorithm.

COSE algorithm identifiers, RFC 9964 section 5:
    ML-DSA-44  -48
    ML-DSA-65  -49
    ML-DSA-87  -50

C2PA signs a detached payload: the claim bytes live in their own JUMBF box and
the COSE_Sign1 payload field is null. The Sig_structure is therefore
    [ "Signature1", protected, external_aad, payload ]
with the claim bytes supplied as payload during signing only.

Tested with cryptography 50.0.1 and cbor2 6.1.4 on Python 3.12.
"""

import datetime

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import serialization as ser
import os

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, padding, rsa
from cryptography.x509.oid import NameOID


# --- ES256 in COSE ----------------------------------------------------------
#
# RFC 9053 section 2.1 carries an ECDSA signature as the fixed-length
# concatenation r || s, 64 bytes for P-256. `cryptography` returns DER
# (70 to 72 bytes), so every COSE ES256 signature goes through these two
# helpers. Certificates keep DER, which is what X.509 specifies.

def es256_sign(key, msg):
    """ES256 over msg in the COSE form: r || s, 32 bytes each."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import \
        decode_dss_signature
    r, s = decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def es256_verify(pub, sig, msg):
    """Verify a COSE-form ES256 signature; raises InvalidSignature."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import \
        encode_dss_signature
    if len(sig) != 64:
        raise ValueError("COSE ES256 signature must be 64 bytes")
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"),
                               int.from_bytes(sig[32:], "big"))
    return pub.verify(der, msg, ec.ECDSA(hashes.SHA256()))

# PS256 with RSA-2048 is what deployed signers ship: 34 of the 37 signatures in
# the C2PA public test corpus use it. It is the classical baseline a migration
# starts from, so it is measured alongside the two compact classical schemes.
def ps256_sign(key, msg):
    from cryptography.hazmat.primitives import hashes
    return key.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                     salt_length=32), hashes.SHA256())


def ps256_verify(pub, sig, msg):
    from cryptography.hazmat.primitives import hashes
    return pub.verify(sig, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                            salt_length=32), hashes.SHA256())


def raw_sign(alg, key, msg):
    """The manifest signature in its COSE form, for any algorithm here."""
    if alg == "ES256":
        return es256_sign(key, msg)
    if alg == "PS256":
        return ps256_sign(key, msg)
    return key.sign(msg)


def raw_verify(alg, pub, sig, msg):
    if alg == "ES256":
        return es256_verify(pub, sig, msg)
    if alg == "PS256":
        return ps256_verify(pub, sig, msg)
    return pub.verify(sig, msg)


COSE_ALG = {"ML-DSA-44": -48, "ML-DSA-65": -49, "ML-DSA-87": -50,
            "ES256": -7, "Ed25519": -8, "PS256": -37}

KEYGEN = {"ML-DSA-44": mldsa.MLDSA44PrivateKey.generate,
          "ML-DSA-65": mldsa.MLDSA65PrivateKey.generate,
          "ML-DSA-87": mldsa.MLDSA87PrivateKey.generate,
          "Ed25519": ed25519.Ed25519PrivateKey.generate,
          "ES256": lambda: ec.generate_private_key(ec.SECP256R1()),
          "PS256": lambda: rsa.generate_private_key(65537, 2048)}

HDR_ALG = 1
HDR_X5CHAIN = 33   # RFC 9360: the full certificate chain, embedded
HDR_X5T = 34       # RFC 9360: certificate thumbprint, a reference instead

# --- carriage ---------------------------------------------------------------
#
# build_chain returns leaf, intermediate(s) and root. What travels in x5chain
# is a separate decision. C2PA 2.5, Section 13.5, requires the signer's
# certificate and every intermediate CA certificate and says the trust
# anchor's certificate should not be included, so "chain" (root omitted) is
# the conformant baseline and the default everywhere. "root" adds the anchor,
# as the Adobe chains in the public test corpus do. "leaf" carries the leaf
# alone, which conforms when the leaf's issuer is itself a trust anchor (the
# C2PA trust list holds issuing CAs as well as roots) and otherwise needs the
# intermediate provisioned in the verifier. "thumb" is RFC 9360 x5t.
FORMS = ("root", "chain", "leaf", "thumb")
DEFAULT_FORM = "chain"


def x5chain_for(form, chain):
    """The DER certificates a manifest carries under one carriage form."""
    if form == "root":
        return list(chain)
    if form == "chain":
        return list(chain[:-1]) if len(chain) > 1 else list(chain)
    if form == "leaf":
        return [chain[0]]
    if form == "thumb":
        return []
    raise ValueError(form)


def protected_header(alg, chain, form=DEFAULT_FORM):
    import hashlib
    if form == "thumb":
        return {HDR_ALG: COSE_ALG[alg],
                HDR_X5T: [-16, hashlib.sha256(chain[0]).digest()]}
    carried = x5chain_for(form, chain)
    return {HDR_ALG: COSE_ALG[alg],
            HDR_X5CHAIN: carried[0] if len(carried) == 1 else carried}

# A claim of realistic size: the c2pa.actions assertion, a hard binding hash,
# the claim generator block and the assertion hash links.
CLAIM = __import__("json").dumps({
    "claim_generator_info": [{"name": "line-a-e1", "version": "0.1"}],
    "assertions": [
        {"url": "self#jumbf=c2pa.assertions/c2pa.actions", "hash": "0" * 44},
        {"url": "self#jumbf=c2pa.assertions/c2pa.hash.data", "hash": "0" * 44},
    ],
    "signature": "self#jumbf=c2pa.signature",
    "alg": "sha256",
    "instanceID": "xmp:iid:" + "0" * 36,
}).encode()


# Certificate profile. "production" (the default) follows what issuing CAs on
# the C2PA trust list put in their certificates: country and organisation in
# every name, the c2pa-kp-claimSigning EKU that C2PA 2.5 names for signers,
# authority information access (OCSP responder and issuer certificate),
# a CRL distribution point and a certificate policy. "minimal" is the profile
# of earlier drafts (common name and organisation, emailProtection EKU, key
# identifiers only), kept so old results can be reproduced.
PROFILE = os.environ.get("LINEA_PROFILE", "production")
C2PA_CLAIM_SIGNING = "1.3.6.1.4.1.62558.2.1"
EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4"
POLICY_OID = "1.3.6.1.4.1.62558.3.1.1"
CA_HOST = "c2pa-ca.ju.edu.jo"


def _name(cn):
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn),
             x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                                "University of Jordan")]
    if PROFILE == "production":
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, "JO"))
    return x509.Name(attrs)


def _cert(subject_pub, issuer_name, issuer_key, cn, is_ca, hash_alg,
          issuer_pub=None, serial=None, now=None, eku=None):
    """Build one certificate.

    `issuer_pub` is the issuer's public key, used to derive the Authority Key
    Identifier. The C2PA certificate profile requires both key identifiers, and
    a chain without them is rejected by c2pa-rs with a bare "certificate is
    invalid" that names neither extension. They were missing from an earlier
    version of this module, which cost a measurement: sizes taken then were
    roughly sixty bytes per certificate below a conformant one.
    """
    now = now or datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder()
         .subject_name(_name(cn)).issuer_name(issuer_name)
         .public_key(subject_pub)
         .serial_number(serial or x509.random_serial_number())
         .not_valid_before(now)
         .not_valid_after(now + datetime.timedelta(days=1825)))

    # Subject Key Identifier on every certificate; Authority Key Identifier
    # pointing at whoever signed it. A self-signed root points at itself.
    b = b.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(subject_pub), critical=False)
    b = b.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer_pub if issuer_pub is not None else subject_pub),
        critical=False)

    production = PROFILE == "production"
    is_root = issuer_pub is None
    if production and not is_root:
        slug = cn.replace(" ", "-")
        b = b.add_extension(x509.AuthorityInformationAccess([
            x509.AccessDescription(
                x509.oid.AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier(f"http://ocsp.{CA_HOST}")),
            x509.AccessDescription(
                x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(
                    f"http://crt.{CA_HOST}/{slug}-issuer.crt"))]),
            critical=False)
        b = b.add_extension(x509.CRLDistributionPoints([
            x509.DistributionPoint(
                [x509.UniformResourceIdentifier(
                    f"http://crl.{CA_HOST}/{slug}-issuer.crl")],
                None, None, None)]), critical=False)
        b = b.add_extension(x509.CertificatePolicies([
            x509.PolicyInformation(x509.ObjectIdentifier(POLICY_OID), None)]),
            critical=False)

    if is_ca:
        b = b.add_extension(x509.BasicConstraints(True, 1), critical=True)
        b = b.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True,
                          False, False), critical=True)
    else:
        b = b.add_extension(x509.BasicConstraints(False, None), critical=True)
        b = b.add_extension(
            x509.KeyUsage(True, True, False, False, False, False, False,
                          False, False), critical=True)
        # C2PA 2.5 names c2pa-kp-claimSigning for signers; earlier versions
        # required emailProtection or documentSigning.
        eku = eku or (C2PA_CLAIM_SIGNING if production else EMAIL_PROTECTION)
        b = b.add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier(eku)]),
            critical=True)
    return b.sign(issuer_key, hash_alg)


def build_chain(alg, depth):
    """Return (leaf_private_key, [DER certs, leaf first]) of the given depth."""
    from cryptography.hazmat.primitives import hashes
    h = hashes.SHA256() if alg in ("ES256", "PS256") else None

    keys = [KEYGEN[alg]() for _ in range(depth)]
    root = keys[-1]
    root_cert = _cert(root.public_key(), _name(f"{alg} Root"), root,
                      f"{alg} Root", True, h)

    chain, issuer_key, issuer_cert = [], root, root_cert
    for i in range(depth - 2, -1, -1):
        is_ca = i > 0
        cn = f"{alg} Signer" if i == 0 else f"{alg} Intermediate {i}"
        c = _cert(keys[i].public_key(), issuer_cert.subject, issuer_key,
                  cn, is_ca, h, issuer_pub=issuer_key.public_key())
        chain.insert(0, c)
        issuer_key, issuer_cert = keys[i], c
    chain.append(root_cert)
    return keys[0], [c.public_bytes(ser.Encoding.DER) for c in chain]


def sign_cose(alg, key, der_chain, claim_bytes, form=DEFAULT_FORM):
    """Detached-payload COSE_Sign1 over claim_bytes. Returns (bytes, sig_len).

    der_chain is the whole chain from build_chain, root included; `form`
    decides which of those certificates travel (see x5chain_for).
    """
    protected_bstr = cbor2.dumps(protected_header(alg, der_chain, form))

    sig_structure = cbor2.dumps(
        ["Signature1", protected_bstr, b"", claim_bytes])

    signature = raw_sign(alg, key, sig_structure)

    return cbor2.dumps(
        cbor2.CBORTag(18, [protected_bstr, {}, None, signature])), len(signature)


def cose_size(alg, depth, claim_bytes, form=DEFAULT_FORM):
    key, chain = build_chain(alg, depth)
    cose, siglen = sign_cose(alg, key, chain, claim_bytes, form)
    return {"alg": alg, "chain_depth": depth, "form": form,
            "cose_bytes": len(cose), "sig_bytes": siglen,
            "chain_der_bytes": sum(len(c) for c in x5chain_for(form, chain)),
            "leaf_der_bytes": len(chain[0])}


def sign_cose_certref(alg, key, der_chain, claim_bytes):
    """COSE_Sign1 carrying a certificate thumbprint instead of the chain.

    RFC 9360 header 34 (x5t) holds [hash_alg, hash_value]. The verifier resolves
    the signer through a trust list rather than reading certificates out of the
    manifest. C2PA already operates a trust list, so this is a deployment change
    rather than a new mechanism, and it removes the term that dominates manifest
    size once signatures go post-quantum.
    """
    import hashlib

    thumb = hashlib.sha256(der_chain[0]).digest()
    protected = {HDR_ALG: COSE_ALG[alg], HDR_X5T: [-16, thumb]}  # -16 = SHA-256
    protected_bstr = cbor2.dumps(protected)
    sig_structure = cbor2.dumps(["Signature1", protected_bstr, b"", claim_bytes])

    signature = raw_sign(alg, key, sig_structure)

    return cbor2.dumps(
        cbor2.CBORTag(18, [protected_bstr, {}, None, signature])), len(signature)


# --- signing backends -------------------------------------------------------
#
# X.509 certificates must come from `cryptography`, because liboqs has no ASN.1
# layer. But OpenSSL's lattice signing is slow enough to dominate any timing
# measured through it: on both x86_64 and aarch64, liboqs signs ML-DSA-65 in
# about 0.10 ms while OpenSSL takes 0.83 ms and 4.54 ms respectively. Reporting
# only OpenSSL would measure the library rather than the algorithm.
#
# So certificates stay on `cryptography` and timings are taken from both.

LIBOQS_NAME = {"ML-DSA-44": "ML-DSA-44", "ML-DSA-65": "ML-DSA-65",
               "ML-DSA-87": "ML-DSA-87"}


def liboqs_available():
    try:
        import oqs  # noqa: F401
        return True
    except Exception:
        return False


def liboqs_signer(alg):
    """Return (sign_fn, verify_fn, sig_bytes) for one algorithm, or None.

    The returned closures hold an open liboqs context, so call them while the
    caller is alive and let them fall out of scope together.
    """
    if alg not in LIBOQS_NAME or not liboqs_available():
        return None
    import oqs

    # A minimal liboqs build may not carry every parameter set, so a missing
    # mechanism is a skipped column rather than a failed run.
    try:
        signer = oqs.Signature(LIBOQS_NAME[alg])
        pk = signer.generate_keypair()
        verifier = oqs.Signature(LIBOQS_NAME[alg])
    except Exception:
        return None

    def sign(msg):
        return signer.sign(msg)

    def verify(msg, sig):
        return verifier.verify(msg, sig, pk)

    return sign, verify, len(sign(b"probe"))


def cose_sig_input(alg, der_chain, claim_bytes, referenced=False,
                   form=DEFAULT_FORM):
    """The exact bytes a signature is computed over, for backend-neutral timing."""
    if referenced:
        form = "thumb"
    protected_bstr = cbor2.dumps(protected_header(alg, der_chain, form))
    return cbor2.dumps(["Signature1", protected_bstr, b"", claim_bytes])
