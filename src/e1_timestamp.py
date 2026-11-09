#!/usr/bin/env python3
"""E1 complete manifest: timestamp and revocation.

Every figure elsewhere in this study is for a manifest carrying one signature.
Deployed manifests carry more. A C2PA manifest is normally timestamped, and an
RFC 3161 timestamp token is a second signature with a second certificate
chain. Where revocation status is stapled, an embedded OCSP response is a
third signature with a third chain.

Under a classical algorithm those additions are a kilobyte or two. Under
ML-DSA each one brings its own chain, so the certificate term the rest of this
paper is about is paid two or three times over. That makes this the strongest
evidence available for the paper's central claim, and it is the configuration
a deployment actually ships.

What is measured and what is modelled:

  OCSP        measured. `cryptography` builds and signs a real
              BasicOCSPResponse under ML-DSA, so the DER sizes here come from
              real objects, with and without the responder certificate
              embedded.

  timestamp   measured. No library available to us issues an RFC 3161 token
              under a post-quantum key, so pq_tst.py builds one: a CMS
              SignedData over a TSTInfo with the signed attributes a TSA
              emits, signed by a TSA whose three-certificate chain (leaf with
              the timeStamping EKU) travels in the token. Its signature is
              verified before it is measured; run_extra.sh also has OpenSSL
              check it where OpenSSL supports the algorithm. The earlier model,
              signature + chain + 500 B, is kept beside it for comparison.
"""

import datetime
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import write_json, run_order  # noqa: E402
from pq_cose import CLAIM, build_chain, cose_sig_input, liboqs_signer  # noqa: E402

from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, mldsa
from cryptography.x509 import load_der_x509_certificate, ocsp

ALGS = ["Ed25519", "ES256", "PS256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
DEPTH = 3
TST_STRUCTURE_BYTES = 500
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGES = os.path.join(ROOT, "images")

KEYGEN = {"ML-DSA-44": mldsa.MLDSA44PrivateKey.generate,
          "ML-DSA-65": mldsa.MLDSA65PrivateKey.generate,
          "ML-DSA-87": mldsa.MLDSA87PrivateKey.generate}


def real_ocsp(alg, chain, keys, hash_alg):
    """Signed BasicOCSPResponses for the signer's leaf, in the two shapes RFC
    6960 allows, as {variant: details}.

    ca_signed   the issuing CA signs the response itself. The verifier already
                has that CA's certificate (it travels in x5chain), so the
                response carries no certificate.
    delegated   a responder certificate issued by the CA, with the
                id-kp-OCSPSigning EKU, signs the response and travels inside it.
    """
    from pq_cose import KEYGEN as KG, _cert, _name
    leaf = load_der_x509_certificate(chain[0])
    issuer = load_der_x509_certificate(chain[1])
    now = datetime.datetime.now(datetime.timezone.utc)
    out = {}

    def build(responder_cert, responder_key, carried):
        b = ocsp.OCSPResponseBuilder()
        b = b.add_response(
            cert=leaf, issuer=issuer, algorithm=hashes.SHA256(),
            cert_status=ocsp.OCSPCertStatus.GOOD, this_update=now,
            next_update=now + datetime.timedelta(days=1),
            revocation_time=None, revocation_reason=None)
        b = b.responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert)
        if carried:
            b = b.certificates(carried)
        if alg == "PS256":
            from cryptography.hazmat.primitives.asymmetric import padding
            resp = b.sign(responder_key, hashes.SHA256())
        else:
            resp = b.sign(responder_key, hash_alg)
        der = resp.public_bytes(ser.Encoding.DER)
        cert_bytes = sum(len(c.public_bytes(ser.Encoding.DER)) for c in carried)
        sig_bytes = len(resp.signature)
        return {"bytes": len(der), "signature_bytes": sig_bytes,
                "certificate_bytes": cert_bytes,
                "certificates": len(carried),
                "structure_bytes": len(der) - sig_bytes - cert_bytes,
                "signed_by": ("issuing CA" if responder_cert is issuer
                              else "delegated responder")}

    try:
        out["ca_signed"] = build(issuer, keys[1], [])
        rkey = KG[alg]()
        rcert = _cert(rkey.public_key(), issuer.subject, keys[1],
                      f"{alg} OCSP Responder", False, hash_alg,
                      issuer_pub=keys[1].public_key(),
                      eku="1.3.6.1.5.5.7.3.9")
        out["delegated"] = build(rcert, rkey, [rcert])
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)[:160]
    return out


def chain_with_keys(alg):
    """build_chain returns only the leaf key; OCSP signing needs the issuer's."""
    from pq_cose import KEYGEN as KG, _cert, _name
    h = hashes.SHA256() if alg in ("ES256", "PS256") else None
    root, inter, leaf = KG[alg](), KG[alg](), KG[alg]()
    rc = _cert(root.public_key(), _name(f"{alg} Root"), root, f"{alg} Root", True, h)
    ic = _cert(inter.public_key(), rc.subject, root, f"{alg} Intermediate 1", True,
               h, issuer_pub=root.public_key())
    lc = _cert(leaf.public_key(), ic.subject, inter, f"{alg} Signer", False, h,
               issuer_pub=inter.public_key())
    ders = [c.public_bytes(ser.Encoding.DER) for c in (lc, ic, rc)]
    # ECDSA and RSA need an explicit digest when signing; Ed25519 and ML-DSA
    # carry their own and reject one.
    return ders, [leaf, inter, root], h


def median_image():
    if not os.path.isdir(IMAGES):
        return None
    s = [os.path.getsize(os.path.join(IMAGES, f))
         for f in os.listdir(IMAGES) if f.endswith(".jpg")]
    return statistics.median(s) if s else None


def jumbf_overhead():
    import json
    p = os.path.join(ROOT, "out", "e1_baseline.json")
    if not os.path.exists(p):
        return 1072
    rows = json.load(open(p))["results"]
    return int(statistics.median(r["manifest_minus_reserve"] for r in rows))


def main():
    overhead = jumbf_overhead()
    img = median_image()
    results = []

    for alg in run_order(ALGS):
        chain, keys, hash_alg = chain_with_keys(alg)
        msg = cose_sig_input(alg, chain, CLAIM)

        oq = liboqs_signer(alg)
        if oq:
            sig_len = len(oq[0](msg))
        else:
            from pq_cose import raw_sign
            sig_len = len(raw_sign(alg, keys[0], msg))

        # What travels in x5chain: leaf and intermediate, root omitted.
        carried = chain[:-1]
        chain_bytes = sum(len(c) for c in carried)
        # Signature plus its chain plus the COSE and JUMBF wrapping, taken
        # from the carriage measurement's full-chain figure.
        # COSE wrapping (headers, CBOR framing) measured on a real
        # COSE_Sign1 over the same chain; 33n and earlier used a fixed 120 B.
        from pq_cose import sign_cose
        cose_wrap = len(sign_cose(alg, keys[0], chain, CLAIM)[0]) - sig_len - chain_bytes
        manifest_sig_only = sig_len + chain_bytes + cose_wrap + overhead

        import hashlib
        import pq_tst
        # C2PA timestamps the claim signature; any 32-byte imprint has the
        # same encoded size.
        tok, tinfo = pq_tst.token(alg, hashlib.sha256(msg).digest())
        tst = len(tok)
        tst_model = sig_len + tinfo["tsa_chain_bytes"] + TST_STRUCTURE_BYTES
        tok_dir = os.path.join(ROOT, os.environ.get("LINEA_OUT", "out"), "tst")
        os.makedirs(tok_dir, exist_ok=True)
        with open(os.path.join(tok_dir, f"{alg}.tst"), "wb") as f:
            f.write(tok)
        oc = real_ocsp(alg, chain, keys, hash_alg)
        ocsp_with = oc.get("delegated", {}).get("bytes")
        ocsp_without = oc.get("ca_signed", {}).get("bytes")

        row = {
            "alg": alg,
            "chain_depth": DEPTH,
            "sig_bytes": sig_len,
            "chain_der_bytes": chain_bytes,
            "certs_carried": len(carried),
            "breakdown_signature": {
                "signature": sig_len,
                "leaf": len(chain[0]),
                "intermediate": len(chain[1]),
                "cose_and_jumbf": cose_wrap + overhead,
            },
            "breakdown_timestamp": {
                "signature": tinfo["signature_bytes"],
                "tsa_signer_cert": tinfo["tsa_cert_bytes"][0],
                "tsa_intermediate_cert": tinfo["tsa_cert_bytes"][1],
                "tstinfo": tinfo["tstinfo_bytes"],
                "signed_attributes": tinfo["signed_attributes_bytes"],
                "other_encoding": tinfo["other_encoding_bytes"],
            },
            "ocsp": oc,
            "manifest_signature_only_bytes": manifest_sig_only,
            "timestamp_token_bytes": tst,
            "timestamp_source": "measured (pq_tst, signature verified)",
            "timestamp_details": tinfo,
            "timestamp_token_bytes_model": tst_model,
            "timestamp_structure_bytes": tinfo["structure_bytes"],
            "ocsp_with_responder_cert_bytes": ocsp_with,
            "ocsp_without_responder_cert_bytes": ocsp_without,
            "ocsp_source": "measured" if ocsp_with else "unavailable",
        }
        row["manifest_signed_and_timestamped_bytes"] = manifest_sig_only + tst
        if ocsp_with:
            # The full configuration staples a delegated responder's OCSP
            # response: C2PA 2.5 requires id-kp-OCSPSigning on the certificate
            # that signs OCSP responses, and c2pa-rs skips a response signed
            # by the issuing CA (e1_validation, ocsp_revoked). The CA-signed
            # form is kept for comparison.
            row["manifest_full_bytes"] = manifest_sig_only + tst + ocsp_with
            row["manifest_full_delegated_bytes"] = row["manifest_full_bytes"]
            if ocsp_without:
                row["manifest_full_ca_signed_bytes"] = (
                    manifest_sig_only + tst + ocsp_without)
            row["growth_vs_signature_only"] = round(
                row["manifest_full_bytes"] / manifest_sig_only, 2)
        if img:
            row["pct_signature_only"] = round(100 * manifest_sig_only / img, 2)
            row["pct_timestamped"] = round(
                100 * row["manifest_signed_and_timestamped_bytes"] / img, 2)
            if ocsp_with:
                row["pct_full"] = round(100 * row["manifest_full_bytes"] / img, 2)
        results.append(row)
        print(f"  {alg}: signature only {manifest_sig_only:,} B, "
              f"full {row.get('manifest_full_bytes', 0):,} B")

    write_json("e1_timestamp.json", results, notes=[
        "a deployed manifest carries a signature, an RFC 3161 timestamp token "
        "and, where revocation is stapled, an OCSP response",
        "each of the three brings its own certificate chain, so the "
        "certificate term is paid two or three times",
        "x5chain and the timestamp token each carry signer and intermediate; "
        "roots are the validator's trust anchors and are not carried",
        "OCSP responses are real objects signed under the measured algorithm, "
        "in two shapes: signed by the issuing CA (no certificate inside) and by "
        "a delegated responder whose certificate travels in the response; "
        "manifest_full_bytes uses the delegated shape, which C2PA 2.5 and "
        "c2pa-rs accept, and manifest_full_ca_signed_bytes the CA-signed one",
        "COSE wrapping is measured on a real COSE_Sign1 over the same chain",
        "timestamp tokens are real RFC 3161 tokens built by pq_tst.py: CMS "
        "SignedData, TSTInfo, content-type, message-digest and "
        "signing-certificate-v2 attributes; TSA hierarchy of three with the "
        "timeStamping EKU, of which signer and intermediate travel; written "
        "to tst/<alg>.tst",
        f"timestamp_token_bytes_model is the earlier model, signature + chain + "
        f"{TST_STRUCTURE_BYTES} B",
        "the certificate term dominates in every configuration, so the "
        "structural estimate does not affect the conclusion",
    ])


if __name__ == "__main__":
    main()
