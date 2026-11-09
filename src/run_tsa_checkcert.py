#!/usr/bin/env python3
"""Run every production TSA certificate through the tagged library's
certificate-profile and trust checks against the C2PA claim-signing list.

No signature is involved: this is the admission test the claim-signer validator
applies, in isolation, using lineaval's `checkcert` command (c2pa-rs
c2pa-v0.91.9). For each distinct production TSA chain it reports whether the
profile check and the trust check pass under the default EKU policy and under a
policy whose usage list names only c2pa-kp-claimSigning.

    LINEAVAL=<binary> CERTS=<dir from extract_tsa_certs.py> \
        CLAIM_LIST=<C2PA-TRUST-LIST.pem> python run_tsa_checkcert.py <out.json>
"""

import json
import os
import subprocess
import sys
import tempfile


def check(binary, chain_pems, anchors, policy):
    spec = {"chain": chain_pems, "anchors": anchors, "eku_policy": policy}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(spec, f)
        path = f.name
    try:
        r = subprocess.run([binary, "checkcert", path], capture_output=True,
                           text=True, timeout=60)
        if r.returncode != 0:
            return {"error": (r.stderr or r.stdout).strip()[:300]}
        return json.loads(r.stdout.strip().splitlines()[-1])
    finally:
        os.unlink(path)


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "tsa_checkcert.json"
    binary = os.environ["LINEAVAL"]
    certs = os.environ["CERTS"]
    claim_list = os.environ["CLAIM_LIST"]
    meta = json.load(open(os.path.join(certs, "tsa_chains.json")))["chains"]

    rows = []
    for c in meta:
        fp = c["fp"]
        chain_pem = os.path.join(certs, fp + "-chain.pem")
        res = {"fp": fp, "operator": c["operator"], "files": c["files"],
               "leaf_eku": c["leaf_eku"], "leaf_is_ca": c["leaf_is_ca"],
               "anchors_to_tsa_list": c["anchors_to_tsa_list"],
               "issuer_issued_by_claim_anchor": c["issuer_issued_by_claim_anchor"]}
        for policy in ("default", "claimsigning_only"):
            res[policy] = check(binary, [chain_pem], [claim_list], policy)
        rows.append(res)

    json.dump({"claim_list": os.path.basename(claim_list), "chains": rows},
              open(out_path, "w"), indent=2)

    def acc(r, pol):
        v = r.get(pol, {})
        return v.get("accepts_as_claim_signer")

    print(f"{'fp':17s} {'operator':12s} {'tsaAnchor':9s} {'underClaim':10s} "
          f"{'default':8s} {'claimOnly':9s}  profile/trust(claimOnly)")
    for r in rows:
        co = r["claimsigning_only"]
        print(f"{r['fp']:17s} {r['operator']:12s} "
              f"{str(r['anchors_to_tsa_list']):9s} "
              f"{str(r['issuer_issued_by_claim_anchor']):10s} "
              f"{str(acc(r, 'default')):8s} {str(acc(r, 'claimsigning_only')):9s}  "
              f"profile={co.get('profile_ok')} trust={co.get('trust_ok')} "
              f"[{co.get('trust_anchor_type') or co.get('trust_detail', '')[:40]}]")

    strong = [r for r in rows if acc(r, "claimsigning_only")]
    print(f"\n{len(strong)} of {len(rows)} production TSA chains are accepted as "
          f"claim signers under the claim-signing-only policy "
          f"(profile and trust both pass; only the private key is absent).")
    ops = sorted({r["operator"] for r in strong})
    print("operators:", ", ".join(ops))


if __name__ == "__main__":
    main()
