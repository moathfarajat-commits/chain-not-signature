# Findings re-run on the c2pa-rs 0.92.0 release candidate

Re-runs the cases behind the three validation findings of Section 7.2 against
the unmodified release candidate c2pa-rc-v0.92.0-rc.1 (fb05f75, 9 November
2026), with the signed files and verify specs of the matrix in `c2pa-val/work`.

* `retest_rc.sh` clones the tag and builds `harness-rc` from the tagged-release
  harness (`harness-tag`, the matrix harness without the ML-DSA patch).
* `build_rc2.sh` adapts the harness to 0.92's `Signer::send_timestamp_request`,
  which takes a context argument, builds it and runs `run_rc_cases.py`.
* `build_rc3.sh` adds an opt-out of 0.92's built-in usage list
  (`trust.use_default_ekus = false`), the only way 0.92 expresses a
  claim-signing-only policy, and re-runs the key-usage case under it.
* The production time-stamping chains were re-checked with the same binary
  through `src/run_tsa_checkcert.py` (`LINEAVAL=bin/lineaval-rc`).

Results: `out-reference/e1_findings_rc.json`. The time-stamping leaf is still a
Trusted claim signer, with and without the built-in list (control: with the list
off and an e-mail-only list, the ordinary claim-signing leaf is rejected); the
8 production chains still pass; the timestamp case is now Trusted and the
CA-signed revoked OCSP case Invalid.
