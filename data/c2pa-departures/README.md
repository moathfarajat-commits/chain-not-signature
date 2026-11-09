# Two departures from C2PA 2.5 in c2pa-rs

Minimal vectors for the two departures of Section 7.2 of the paper. Both occur in c2pa-rs at
commit e2ad88e with no patch (`p0` in `status_codes.json`), with ES256 and
Ed25519, as well as in the two ML-DSA-patched builds, and on the latest tagged
release, c2pa-v0.91.9 (e62b5c8; `status_codes_c2pa-v0.91.9.json`).

Reported: finding 2 as https://github.com/contentauth/c2pa-rs/issues/3005
(3 November 2026); finding 1 was reported privately, with its vectors, to
Adobe's product security team on 9 November 2026. The signed file and leaf
certificate for finding 1 are withheld from this repository until a fix ships
or until 7 February 2027 (90 days after the report), whichever comes first;
its status codes are included. Both also reproduce with c2patool 0.28.4;
see `c2patool-0.28.4/`.

All certificates are throwaway test certificates generated for the run
(`c2pa-val/gen_certs.py`); no private keys are included.

## 1. A time-stamping certificate accepted as a claim signer

* `es256-eku_timestamping.jpg`, signed by `certs/signer/tseku.pem`, whose only
  extended key usage is id-kp-timeStamping (1.3.6.1.5.5.7.3.8), issued by
  `certs/signer/int.pem` under `certs/signer/root.pem`.
* Trust configuration: manifest anchor `certs/signer/root.pem`; TSA anchor
  `certs/tsa/root.pem`. Validated twice: with c2pa-rs's default EKU list, and
  with a policy listing only c2pa-kp-claimSigning (1.3.6.1.4.1.62558.2.1).
* Observed: `Trusted` under both policies (`signingCredential.trusted`).
* C2PA 2.5 §13.5.1.1: a certificate valid for id-kp-timeStamping shall be
  valid for exactly that purpose, so it cannot sign a claim; under a
  claimSigning-only policy the signer should not be trusted.

## 2. A TSA without the time-stamping EKU invalidates the whole manifest

* `es256-tsa_no_timestamping_eku.jpg`, signed by a good claim signer
  (`certs/signer/leaf.pem`), with an RFC 3161 token from `certs/tsa/tsa_noeku.pem`
  (EKU serverAuth, no timeStamping) under `certs/tsa/root.pem`.
* Observed: `Invalid`, with `signingCredential.invalid` among the failures.
* C2PA 2.5: an invalid TSA credential is reported as `timeStamp.untrusted`
  (informational) and the time stamp is ignored; the claim signature is then
  judged on its own, and here it is valid and trusted.

`status_codes.json` holds every status code each build reported, and
`chain_noroot_tsa` as the control (a good signer and a good TSA: Trusted).
