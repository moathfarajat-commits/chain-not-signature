#!/usr/bin/env python3
"""Run the findings' cases through a given lineaval binary (unpatched library).
usage: run_rc_cases.py <lineaval> <library label> <out.json>"""
import json, os, subprocess, sys
V = os.path.expanduser("~/line-a-experiments/c2pa-val")
binary, label, out = sys.argv[1:4]
CASES = [("chain_noroot_tsa", "default"), ("eku_timestamping", "default"),
         ("eku_timestamping", "claimsigning"), ("tsa_no_timestamping_eku", "default"),
         ("ocsp_good", "default"), ("ocsp_revoked", "default"),
         ("ocsp_deleg_good", "default"), ("ocsp_deleg_revoked", "default")]
rows = []
for alg in ("es256", "ed25519"):
    for case, pol in CASES:
        spec = None
        for p in ("p0", "p2"):
            s = f"{V}/work/spec/v-{alg}-{case}.jpg-{p}.json"
            if os.path.exists(s):
                spec = s; break
        env = dict(os.environ)
        if pol == "claimsigning":
            env["LINEA_EKUS"] = "1.3.6.1.4.1.62558.2.1"
        r = subprocess.run([binary, "verify", spec], capture_output=True, text=True, env=env, timeout=120)
        try:
            j = json.loads(r.stdout.strip().splitlines()[-1])
        except Exception:
            j = {"error": (r.stderr or r.stdout)[-400:]}
        codes = j.get("status_codes") or j.get("codes") or []
        rows.append({"alg": alg, "case": case, "policy": pol, "spec": os.path.basename(spec),
                     "validation_state": j.get("validation_state"), "result": j})
        print(alg, case, pol, j.get("validation_state"), flush=True)
json.dump({"experiment": "e1_findings_rc", "library": label,
           "notes": ["Cases bearing on the three findings verified with the unmodified library, online OCSP fetching off; vectors and verify specs are those of the matrix (c2pa-val/work)."],
           "results": rows}, open(out, "w"), indent=1)
