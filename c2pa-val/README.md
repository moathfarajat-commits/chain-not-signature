# Validation matrix through the reference implementation

What it answers: does a post-quantum manifest validate, and does it fail when
it should, inside c2pa-rs itself rather than in our own COSE code.

* `setup.sh` takes c2pa-rs at e2ad88e (main, 2 November 2026) and
  `c2pa_raw_crypto` 0.2.0, and applies the RFC 9964 patch from the paper.
* `port.py p1` adds the registrations the paper's patch needed at that crate
  version (ML-DSA signer and validator, `ml-dsa` dependency, which resolves to
  0.1.2). This is the library as the paper used it.
* `port.py p2` additionally teaches certificate path validation and the OCSP
  response check about ML-DSA (`../patches/c2pa-rs-mldsa-pathvalidation-ext.patch`).
* `build.sh` builds the harness against each: `bin/lineaval-p1`, `bin/lineaval-p2`.
* `run_matrix.py` generates a fresh test PKI (`gen_certs.py`), OCSP responses
  (`ocsp.py`), runs a local RFC 3161 TSA (`tsa.py`), signs every case once and
  validates it with both builds. Output: `results/e1_validation.json`
  (copied to `out-reference/e1_validation.json`).

The ported patch for c2pa-rs main is `../patches/c2pa-rs-rfc9964-main.patch`
(SDK diff followed by the `c2pa_raw_crypto` diff).
