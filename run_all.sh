#!/usr/bin/env bash
# Run every experiment that does not need the Raspberry Pi.
# Results land in out/ as JSON, one file per experiment.
set -e
cd "$(dirname "$0")"

echo "== setup =="
[ -d certs ] || ./setup_certs.sh
[ -n "$(ls images/*.jpg 2>/dev/null)" ] || ./fetch_images.sh

echo
echo "== E1 baseline: classical manifests on real JPEGs =="
python3 src/e1_baseline.py

echo
echo "== E1 post-quantum: ML-DSA manifest cost =="
python3 src/e1_pq.py

echo
echo "== E1 mitigation: certificate reference instead of chain =="
python3 src/e1_certref.py

echo
echo "== E1 carriage: full chain, leaf only, thumbprint =="
python3 src/e1_carriage.py

echo
echo "== E1 verification =="
python3 src/e1_verify.py

echo
echo "== E1 algorithm and chain-depth sweep =="
python3 src/e1_algsweep.py

echo
echo "== E1 amortised verification =="
python3 src/e1_cache.py

echo
echo "== E1 hard-binding hash against signature =="
python3 src/e1_hash.py

echo
echo "== E1 timestamp and revocation =="
python3 src/e1_timestamp.py

echo
echo "== E8: verification at scale, across cores =="
python3 src/e8_scale.py
echo
echo "== E4: archive key wrapping =="
python3 src/e4_wrap.py

echo
echo "== backend comparison =="
python3 compare_backends.py

echo
echo "== summary =="
python3 src/summarize.py

echo
echo "== manuscript tables =="
python3 src/make_tables.py

echo
echo "== manuscript figures =="
python3 src/fig_sizeladder.py
