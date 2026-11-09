#!/usr/bin/env python3
"""A local RFC 3161 time-stamping authority for the validation matrix.

    tsa.py VARIANT CERTDIR REQUEST.tsq RESPONSE.tsr

reads the TimeStampReq c2pa-rs builds, and writes a TimeStampResp
(status granted) whose token is a CMS SignedData over a TSTInfo, ES256,
signed by CERTDIR/tsa/<leaf>, with the TSA leaf and intermediate in the token.

    good          the imprint from the request, TSA leaf with timeStamping EKU
    noeku         same, signed by a TSA leaf without the timeStamping EKU
    wrongimprint  imprint of different bytes (the token does not bind the
                  claim signature)

A "pq-" prefix (pq-good, pq-noeku, pq-wrongimprint) uses the ML-DSA-65
authority in CERTDIR/tsa_mldsa65 instead: pure ML-DSA-65 over the DER of the
signed attributes, SHA-512 as the digest algorithm (RFC 9882).

The nonce in the request is echoed. genTime is the current time.
"""
import datetime
import hashlib
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec


def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + _len(len(body)) + body


def seq(*xs):
    return tlv(0x30, b"".join(xs))


def oid(dotted):
    p = [int(x) for x in dotted.split(".")]
    out = bytes([40 * p[0] + p[1]])
    for v in p[2:]:
        enc = [v & 0x7F]
        v >>= 7
        while v:
            enc.insert(0, 0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(enc)
    return tlv(0x06, out)


def integer(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True)
    return tlv(0x02, b)


def read(b, i):
    """(tag, value_start, value_end) of the TLV at offset i."""
    tag = b[i]
    l = b[i + 1]
    j = i + 2
    if l & 0x80:
        n = l & 0x7F
        l = int.from_bytes(b[j:j + n], "big")
        j += n
    return tag, j, j + l


def children(b, start, end):
    out, i = [], start
    while i < end:
        t, s, e = read(b, i)
        out.append((t, s, e, b[i:e]))
        i = e
    return out


OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"
OID_ML_DSA_65 = "2.16.840.1.101.3.4.3.18"
TSA_POLICY = "1.3.6.1.4.1.99999.1.1"


def main():
    variant, certdir, reqp, outp = sys.argv[1:5]
    pq = variant.startswith("pq-")
    variant = variant[3:] if pq else variant
    tsadir = f"{certdir}/tsa_mldsa65" if pq else f"{certdir}/tsa"
    dig_oid, dig = (OID_SHA512, hashlib.sha512) if pq else (OID_SHA256, hashlib.sha256)
    req = open(reqp, "rb").read()
    _, s, e = read(req, 0)
    parts = children(req, s, e)
    imprint_der = parts[1][3]                 # MessageImprint SEQUENCE, verbatim
    nonce = None
    for t, vs, ve, raw in parts[2:]:
        if t == 0x02:
            nonce = raw
    if variant == "wrongimprint":
        mi = children(req, parts[1][1], parts[1][2])
        imprint_der = seq(mi[0][3], tlv(0x04, hashlib.sha256(b"not the claim signature").digest()))

    leafname = "tsa_noeku" if variant == "noeku" else "tsa"
    lc = x509.load_pem_x509_certificate(open(f"{tsadir}/{leafname}.pem", "rb").read())
    lk = ser.load_pem_private_key(open(f"{tsadir}/{leafname}.key", "rb").read(), None)
    ic = x509.load_pem_x509_certificate(open(f"{tsadir}/int.pem", "rb").read())

    now = datetime.datetime.now(datetime.timezone.utc)
    gen_time = now.strftime("%Y%m%d%H%M%S") + "Z"
    fields = [integer(1), oid(TSA_POLICY), imprint_der,
              integer(int.from_bytes(os.urandom(15), "big")),
              tlv(0x18, gen_time.encode())]
    if nonce is not None:
        fields.append(nonce)
    info = seq(*fields)

    leaf_der = lc.public_bytes(ser.Encoding.DER)
    ess = seq(seq(seq(tlv(0x04, hashlib.sha256(leaf_der).digest()))))
    attrs = sorted([
        seq(oid(OID_CONTENT_TYPE), tlv(0x31, oid(OID_TSTINFO))),
        seq(oid(OID_MESSAGE_DIGEST), tlv(0x31, tlv(0x04, dig(info).digest()))),
        seq(oid(OID_SIGNING_CERT_V2), tlv(0x31, ess)),
    ])
    if pq:
        sig = lk.sign(tlv(0x31, b"".join(attrs)))
        sig_alg = seq(oid(OID_ML_DSA_65))            # parameters absent (RFC 9882)
    else:
        sig = lk.sign(tlv(0x31, b"".join(attrs)), ec.ECDSA(hashes.SHA256()))
        sig_alg = seq(oid(OID_ECDSA_SHA256))
    signer_info = seq(
        integer(1),
        seq(lc.issuer.public_bytes(), integer(lc.serial_number)),
        seq(oid(dig_oid)),
        tlv(0xA0, b"".join(attrs)),
        sig_alg,
        tlv(0x04, sig),
    )
    # "leafonly": the token carries the authority's own certificate alone, as
    # it may when its issuer is an anchor on the time-stamping trust list.
    certs = leaf_der if variant == "leafonly" else leaf_der + ic.public_bytes(ser.Encoding.DER)
    signed_data = seq(
        integer(3),
        tlv(0x31, seq(oid(dig_oid))),
        seq(oid(OID_TSTINFO), tlv(0xA0, tlv(0x04, info))),
        tlv(0xA0, certs),
        tlv(0x31, signer_info),
    )
    token = seq(oid(OID_SIGNED_DATA), tlv(0xA0, signed_data))
    resp = seq(seq(integer(0)), token)
    open(outp, "wb").write(resp)


if __name__ == "__main__":
    main()
