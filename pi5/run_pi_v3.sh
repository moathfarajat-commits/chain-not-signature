#!/usr/bin/env bash
# Pi 5, 35n: the longer stream experiment with the extended manipulation set
# (streams looped on the Mac by loop_streams.sh), and two more archive-batch
# runs so the batch result has three.
set -uo pipefail
cd "$(dirname "$0")/.."
. "$HOME/line-a-pi/env.sh"
export LINEA_PROFILE=production LINEA_SIGN_ONLY=1
OUT=out-pi-v3; RUNS=out-pi-v3-runs
mkdir -p $OUT $RUNS/run2 $RUNS/run3
exec > >(tee -a "$OUT/run_$(date +%Y%m%d_%H%M%S).log") 2>&1
gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)
echo "== $(date -Is) governor $gov throttled $(vcgencmd get_throttled) $(vcgencmd measure_temp)"
[ "$gov" = performance ] || { echo "set the performance governor first"; exit 1; }
log(){ echo "[$(date +%H:%M:%S)] $*"; }
LINEA_OUT=$OUT python pi5/e6_stream.py --streams "$HOME/line-a-pi/streams" --long --reps 3 \
  > $OUT/e6_stream.log 2>&1 && log "ok e6_stream" || log "FAIL e6_stream"
for r in 2 3; do
  LINEA_RUN=$r LINEA_OUT=$RUNS/run$r python src/e1_archive.py > $RUNS/run$r/e1_archive.log 2>&1 \
    && log "run $r ok e1_archive" || log "run $r FAIL e1_archive"
done
echo "== $(date -Is) throttled $(vcgencmd get_throttled) $(vcgencmd measure_temp)"
log PI_V3_DONE
