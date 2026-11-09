#!/bin/bash
# Independent repetitions of the host suite for the statistics the paper
# reports. Each run is a fresh set of processes with fresh keys, its own random
# order of experiments (and, inside each experiment, of configurations), into
# out-runs/run<k>/. aggregate_runs.py then merges them into out-o3/.
#   R=10 bench/run_reps.sh            (about 25 minutes on the M1 Pro)
set -u
ROOT="$HOME/line-a-experiments"
cd "$ROOT"
source .venv-o3/bin/activate
export DYLD_LIBRARY_PATH="$HOME/_oqs/lib"
export LINEA_PROFILE=production
python -m pip install --quiet zstandard brotli
R=${R:-10}
log() { echo "[$(date +%H:%M:%S)] $*"; }
mkdir -p logs out-runs out
cp out-reference/e1_baseline.json out/ 2>/dev/null || true
EXPS="e1_pq e1_certref e1_carriage e1_verify e1_algsweep e1_cache e1_hash e1_timestamp e1_mixedchain e1_extras"
for r in $(seq 1 "$R"); do
  mkdir -p "out-runs/run$r"
  cp out-reference/e1_baseline.json "out-runs/run$r/" 2>/dev/null || true
  order=$(python -c "import random,sys;l=sys.argv[1:];random.Random($r).shuffle(l);print(' '.join(l))" $EXPS)
  for e in $order; do
    if LINEA_RUN=$r LINEA_OUT="out-runs/run$r" python "src/$e.py" > "logs/rep$r-$e.log" 2>&1
    then log "run $r ok   $e"; else log "run $r FAIL $e"; tail -5 "logs/rep$r-$e.log"; fi
  done
done
# Scaling: three independent runs, each with its own internal repetitions.
for r in 1 2 3; do
  LINEA_RUN=$r LINEA_OUT="out-runs/run$r" python src/e8_scale.py > "logs/rep$r-e8.log" 2>&1 \
    && log "run $r ok   e8_scale" || { log "run $r FAIL e8_scale"; tail -5 "logs/rep$r-e8.log"; }
done
# Archive model and key wrap are not repeated; one run each.
LINEA_OUT=out-runs/run1 python src/e1_archive.py > logs/rep1-archive.log 2>&1 && log "ok archive"
python src/aggregate_runs.py out-runs out-o3new
log "REPS_DONE"
