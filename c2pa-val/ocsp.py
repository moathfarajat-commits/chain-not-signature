#!/usr/bin/env python3
"""OCSP responses for the signing leaves, in the two forms RFC 6960 allows:

    ocsp_{good,revoked}.der        signed by the issuing CA itself, no certs
    ocsp_deleg_{good,revoked}.der  signed by a delegated responder that the
                                   CA issued with id-kp-OCSPSigning; the
                                   responder certificate travels in the response

    ocsp.py CERTDIR
"""
import datetime
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.x509 import ocsp

d = sys.argv[1]
now = datetime.datetime.now(datetime.timezone.utc)
for alg in ("es256", "ed25519", "mldsa44", "mldsa65", "mldsa87"):
    leaf = x509.load_pem_x509_certificate(open(f"{d}/{alg}/leaf.pem", "rb").read())
    ic = x509.load_pem_x509_certificate(open(f"{d}/{alg}/int.pem", "rb").read())
    ik = ser.load_pem_private_key(open(f"{d}/{alg}/int.key", "rb").read(), None)
    h = hashes.SHA256() if alg == "es256" else None
    rc = x509.load_pem_x509_certificate(open(f"{d}/{alg}/ocspresp.pem", "rb").read())
    rk = ser.load_pem_private_key(open(f"{d}/{alg}/ocspresp.key", "rb").read(), None)
    for form, signer_cert, signer_key, certs in (("", ic, ik, None),
                                                 ("deleg_", rc, rk, [rc])):
      for status in ("good", "revoked"):
          b = ocsp.OCSPResponseBuilder()
          if status == "good":
              b = b.add_response(leaf, ic, hashes.SHA256(), ocsp.OCSPCertStatus.GOOD,
                                 now, now + datetime.timedelta(days=7), None, None)
          else:
              b = b.add_response(leaf, ic, hashes.SHA256(), ocsp.OCSPCertStatus.REVOKED,
                                 now, now + datetime.timedelta(days=7),
                                 now - datetime.timedelta(hours=1),
                                 x509.ReasonFlags.key_compromise)
          b = b.responder_id(ocsp.OCSPResponderEncoding.HASH, signer_cert)
          if certs:
              b = b.certificates(certs)
          try:
              r = b.sign(signer_key, h)
              open(f"{d}/{alg}/ocsp_{form}{status}.der", "wb").write(r.public_bytes(ser.Encoding.DER))
              print(alg, form + status, len(r.public_bytes(ser.Encoding.DER)))
          except Exception as e:
              print(alg, status, "FAILED", e)
