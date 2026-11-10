#!/bin/bash
# Add an opt-out of the built-in EKU list (trust.use_default_ekus, new in 0.92) to the rc harness,
# so that a claimSigning-only policy can be expressed, then re-run the key-usage cases.
set -u
V=$HOME/line-a-experiments/c2pa-val; cd $V
export PATH="$HOME/.cargo/bin:$PATH"
log(){ echo "[$(date +%T)] $*"; }
python3 - <<'EOF'
p="harness-rc/src/main.rs"; s=open(p).read()
old='s += &format!("[trust]\\ntrust_config = \\"\\"\\"\\n{ekus}\\n\\"\\"\\"\\n");'
new=('let nodef = if std::env::var("LINEA_NODEFAULT_EKUS").is_ok() { "use_default_ekus = false\\n" } else { "" };\n'
     '    s += &format!("[trust]\\n{nodef}trust_config = \\"\\"\\"\\n{ekus}\\n\\"\\"\\"\\n");')
assert old in s, "pattern"
s=s.replace(old,new); open(p,"w").write(s)
EOF
grep -n "nodef" harness-rc/src/main.rs
(cd harness-rc && cargo build --release -j 6 > ../build-rc.log 2>&1) \
  || { log "build FAILED"; grep -E "^error" -A12 build-rc.log | head -60; exit 1; }
cp harness-rc/target/release/lineaval bin/lineaval-rc; log BUILD_DONE
for alg in es256 ed25519; do
  for c in eku_timestamping chain_noroot_tsa; do
    s=work/spec/v-$alg-$c.jpg-p0.json
    r=$(LINEA_NODEFAULT_EKUS=1 LINEA_EKUS=1.3.6.1.4.1.62558.2.1 bin/lineaval-rc verify $s | tail -1)
    echo "$alg|$c|claimsigning_nodefault $r" >> results/e1_findings_rc_nodefault.txt
    log "$alg $c nodefault: $(echo "$r" | python3 -c 'import json,sys; j=json.load(sys.stdin); print(j.get("validation_state"), [c["code"] for c in j["codes"]["failure"]])')"
  done
done
log NODEFAULT_DONE
