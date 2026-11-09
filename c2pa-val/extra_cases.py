#!/usr/bin/env python3
"""Validation cases added after the main matrix (run_matrix.py).

  tsa_leafonly_anchor_int   the time-stamping authority's token carries only its
                            own certificate; the TSA's issuing CA is the
                            time-stamping anchor, as on the C2PA TSA list
  tsa_leafonly_anchor_root  the same token with only the TSA root as anchor
                            (control: the path cannot be built)
  eku_email                 signer leaf whose only EKU is id-kp-emailProtection
  eku_ocspsigning           signer leaf whose only EKU is id-kp-OCSPSigning

Each is validated under c2pa-rs's default EKU list and under a policy that lists
only c2pa-kp-claimSigning. Usage: extra_cases.py BINARY OUTDIR [ALG ...]
"""
import json
import os
import subprocess
import sys

V = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
CLAIM_ONLY = "1.3.6.1.4.1.62558.2.1"


def run(binary, cmd, spec, env=None):
    p = subprocess.run([binary, cmd, spec], capture_output=True, text=True,
                       timeout=600, env=env)
    try:
        return json.loads(p.stdout.strip().splitlines()[-1])
    except Exception:
        return {"error": (p.stderr or p.stdout).strip()[-600:]}


def main():
    binary, out = sys.argv[1], sys.argv[2]
    algs = sys.argv[3:] or ["es256", "ed25519"]
    img = os.environ.get("LINEA_IMG")
    certs = f"{out}/certs"
    os.makedirs(f"{out}/spec", exist_ok=True)
    subprocess.run([PY, f"{V}/gen_certs.py", certs, "300"], check=True,
                   stdout=subprocess.DEVNULL)
    pq = os.environ.get("LINEA_PQTSA") == "1"
    td = f"{certs}/tsa_mldsa65" if pq else f"{certs}/tsa"
    pre = "pq-" if pq else ""
    rows = []
    for alg in algs:
        d = f"{certs}/{alg}"
        L = lambda s: f"{d}/{s}.pem"  # noqa: E731
        K = lambda s: f"{d}/{s}.key"  # noqa: E731
        cases = [
            ("tsa_leafonly_anchor_int", "leaf", pre + "leafonly", [f"{td}/int.pem"]),
            ("tsa_leafonly_anchor_root", "leaf", pre + "leafonly", [f"{td}/root.pem"]),
            ("chain_noroot_tsa", "leaf", pre + "good", [f"{td}/root.pem"]),
            ("eku_email", "emaileku", None, [f"{td}/root.pem"]),
            ("eku_ocspsigning", "ocspresp", None, [f"{td}/root.pem"]),
        ]
        for name, stem, tsa, tsa_anchors in cases:
            sj = {"alg": alg, "key": K(stem), "x5chain": [L(stem), L("int")],
                  "input": img, "output": f"{out}/{alg}-{name}.jpg", "mode": "normal",
                  "python": PY, "tsa_script": f"{V}/tsa.py", "certdir": certs}
            if tsa:
                sj["tsa_variant"] = tsa
            sp = f"{out}/spec/{alg}-{name}.sign.json"
            json.dump(sj, open(sp, "w"))
            signed = run(binary, "sign", sp)
            for policy in ("default", "claimsigning_only"):
                vj = {"input": sj["output"], "anchors": [L("root")], "tsa_anchors": tsa_anchors}
                vp = f"{out}/spec/{alg}-{name}-{policy}.verify.json"
                json.dump(vj, open(vp, "w"))
                env = dict(os.environ)
                if policy == "claimsigning_only":
                    env["LINEA_EKUS"] = CLAIM_ONLY
                r = run(binary, "verify", vp, env)
                rows.append({"alg": alg, "case": name, "policy": policy, "tsa": "mldsa65" if pq else "es256",
                             "manifest_bytes": signed.get("manifest_bytes"),
                             "sign_error": signed.get("error"),
                             "validation_state": r.get("validation_state"),
                             "codes": r.get("codes"), "reader_error": r.get("reader_error")})
                print(alg, name, policy, r.get("validation_state"),
                      sorted({c for k in ("failure",) for c in
                              [x if isinstance(x, str) else x.get("code") for x in (r.get("codes") or {}).get(k, [])]}),
                      flush=True)
    json.dump({"binary": binary, "results": rows}, open(f"{out}/e1_validation_extra.json", "w"),
              indent=1)


if __name__ == "__main__":
    main()
