# Two departures from C2PA 2.5 in c2pa-rs

Minimal vectors for the two findings of Section 3.4. Both occur in c2pa-rs at
commit e2ad88e with no patch (`p0` in `status_codes.json`), with ES256 and
Ed25519, as well as in the two ML-DSA-patched builds, and on the latest tagged
release, c2pa-v0.91.9 (e62b5c8; `status_codes_c2pa-v0.91.9.json`).

Finding 2 is reported as https://github.com/contentauth/c2pa-rs/issues/3005
(3 November 2026). Both also reproduce with c2patool 0.28.4; see
`c2patool-0.28.4/`.

Finding 1 lets a time-stamping certificate sign manifests that validate as
Trusted, so its signed file and its signing certificate are withheld from this
release until the library is fixed. Its status codes are included.

All certificates are throwaway test certificates generated for the run
(`c2pa-val/gen_certs.py`); no private keys are included.

## 1. A time-stamping certificate accepted as a claim signer

* A JPEG signed by a leaf whose only extended key usage is id-kp-timeStamping
  (1.3.6.1.5.5.7.3.8), issued by `certs/signer/int.pem` under
  `certs/signer/root.pem` (file and leaf withheld; see above).
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
