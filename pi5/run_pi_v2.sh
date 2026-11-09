#!/usr/bin/env bash
# Line A revision runs on the Raspberry Pi 5 (about 90 minutes):
#   e6_stream   encoded H.264/HEVC streams, three signing methods (new)
#   e7_edge     edge verifier, root as an in-memory anchor
#   e1_verify, e1_hash, e1_carriage   five independent runs each
#   e8_scale    three runs, 1-4 workers
#   e1_archive  batch model on four identical cores
# Streams must be in ~/line-a-pi/streams (made on the Mac by make_stream.sh).
set -uo pipefail
cd "$(dirname "$0")/.."
. "$HOME/line-a-pi/env.sh"
export LINEA_PROFILE=production LINEA_SIGN_ONLY=1
OUT=out-pi-v2; RUNS=out-pi-v2-runs
mkdir -p $OUT $RUNS
LOG="$OUT/run_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1
gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)
thr=$(vcgencmd get_throttled | cut -d= -f2)
echo "== $(tr -d '\0' < /proc/device-tree/model) $(date -Is) governor $gov throttled $thr $(vcgencmd measure_temp)"
[ "$gov" = performance ] || { echo "set the performance governor first"; exit 1; }
log(){ echo "[$(date +%H:%M:%S)] $*"; }
cp images -r $RUNS/ 2>/dev/null; true
LINEA_OUT=$OUT python pi5/e6_stream.py --streams "$HOME/line-a-pi/streams" --reps 5 && log "ok e6_stream" || log "FAIL e6_stream"
LINEA_OUT=$OUT python pi5/e7_edge.py && log "ok e7_edge" || log "FAIL e7_edge"
for r in 1 2 3 4 5; do
  mkdir -p $RUNS/run$r; cp out-pi/e1_baseline.json $RUNS/run$r/ 2>/dev/null
  for e in $(python -c "import random,sys;l=sys.argv[1:];random.Random($r).shuffle(l);print(' '.join(l))" e1_verify e1_hash e1_carriage); do
    LINEA_RUN=$r LINEA_OUT=$RUNS/run$r python src/$e.py > $RUNS/run$r/$e.log 2>&1 && log "run $r ok $e" || log "run $r FAIL $e"
  done
done
for r in 1 2 3; do
  LINEA_RUN=$r LINEA_OUT=$RUNS/run$r python src/e8_scale.py --workers 1,2,3,4 > $RUNS/run$r/e8.log 2>&1 && log "run $r ok e8" || log "run $r FAIL e8"
done
LINEA_OUT=$OUT python src/e1_archive.py > $OUT/e1_archive.log 2>&1 && log "ok e1_archive" || log "FAIL e1_archive"
python src/aggregate_runs.py $RUNS $OUT && log "aggregated"
echo "== done $(date -Is) throttled $(vcgencmd get_throttled) $(vcgencmd measure_temp)"
log PI_V2_DONE
