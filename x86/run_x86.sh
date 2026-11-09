#!/bin/bash
# x86-64 runs on the Xeon VM: implementation harness (Table 15 counterpart,
# with liboqs's AVX2 path), then R independent repetitions of the host suite.
set -u
X=~/x86; B=$X/build; REPO=.
BENCH=$REPO/bench
log(){ echo "[$(date +%H:%M:%S)] $*"; }
if [ -z "${SUITE_ONLY:-}" ]; then
cd $B
OUT=$B/results.jsonl; META=$B/meta.txt; : > $OUT; : > $META
for v in asm noasm; do
  cc -O2 -o bench_ossl_$v $BENCH/bench_openssl.c -I ossl-$v/include ossl-$v/lib/libcrypto.a -lpthread -ldl 2> cc-ossl-$v.log || cat cc-ossl-$v.log
done
for v in native generic; do
  cc -O2 -o bench_oqs_$v $BENCH/bench_liboqs.c -I oqs-$v/include oqs-$v/lib/liboqs.a 2> cc-oqs-$v.log || cat cc-oqs-$v.log
done
D=pqclean/crypto_sign/ml-dsa-65/clean
cc -O3 -o bench_pqclean_clean $BENCH/bench_pqclean.c $D/*.c pqclean/common/fips202.c pqclean/common/randombytes.c -I$D -Ipqclean/common 2> cc-pqclean.log || head cc-pqclean.log
log "builds done; timing"
for pair in "bench_ossl_asm openssl-4.0.2-source-asm" "bench_ossl_noasm openssl-4.0.2-source-noasm" \
            "bench_oqs_native liboqs-0.16.0-native-avx2" "bench_oqs_generic liboqs-0.16.0-generic" \
            "bench_pqclean_clean pqclean-ml-dsa-65-clean"; do
  set -- $pair
  [ -x ./$1 ] && { log "timing $2"; ./$1 $2 >> $OUT 2>> $META; }
done
lscpu > $B/lscpu.txt; gcc --version | head -1 >> $META
log "IMPLS_DONE"
fi
[ -n "${SKIP_SUITE:-}" ] && exit 0
[ -n "${SUITE_ONLY:-}" ] || true

# Host suite, R independent runs
. $X/venv/bin/activate
export LD_LIBRARY_PATH=$B/oqs-shared/lib OQS_INSTALL_PATH=$B/oqs-shared LINEA_PROFILE=production
python -m pip install --quiet zstandard brotli 2>/dev/null
cd $REPO
R=${R:-10}
mkdir -p out-x86-runs out logs-x86
cp out-reference/e1_baseline.json out/
EXPS="e1_pq e1_certref e1_carriage e1_verify e1_algsweep e1_cache e1_hash e1_timestamp e1_mixedchain e1_extras"
for r in $(seq 1 $R); do
  mkdir -p out-x86-runs/run$r; cp out-reference/e1_baseline.json out-x86-runs/run$r/
  order=$(python -c "import random,sys;l=sys.argv[1:];random.Random($r).shuffle(l);print(' '.join(l))" $EXPS)
  for e in $order; do
    LINEA_RUN=$r LINEA_OUT=out-x86-runs/run$r python src/$e.py > logs-x86/rep$r-$e.log 2>&1 \
      && log "run $r ok $e" || { log "run $r FAIL $e"; tail -3 logs-x86/rep$r-$e.log; }
  done
done
for r in 1 2 3; do
  LINEA_RUN=$r LINEA_OUT=out-x86-runs/run$r python src/e8_scale.py --workers 1,2 > logs-x86/rep$r-e8.log 2>&1 \
    && log "run $r ok e8" || { log "run $r FAIL e8"; tail -3 logs-x86/rep$r-e8.log; }
done
python src/aggregate_runs.py out-x86-runs out-x86
log "X86_DONE"
