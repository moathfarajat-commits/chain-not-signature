#!/usr/bin/env bash
# Runs the Line A experiments on a Raspberry Pi 5.
#
#   bash pi5/run_pi.sh --quick   a few minutes; proves everything works
#   bash pi5/run_pi.sh           the full set, about three and a half hours
#
# Results go to out-pi/ (out-pi-quick/ for --quick), with a log beside them.
# Signatures only: the KEM experiment (e4_wrap) belongs to the M1 data and is
# deliberately not run here, so nothing on this board overlaps the HQC paper.
#
# Before a full run: power from the supply that came with the kit, the case
# fan on, nothing else running, and ideally a reboot. The script checks the
# governor and the throttle flags and stops if the board is already
# throttling.

set -uo pipefail
cd "$(dirname "$0")/.."
BASE=${LINEA_PI_HOME:-$HOME/line-a-pi}
[ -f "$BASE/env.sh" ] || { echo "run pi5/setup_pi.sh first"; exit 1; }
# shellcheck disable=SC1091
. "$BASE/env.sh"

QUICK=""
OUT=out-pi
if [ "${1:-}" = "--quick" ]; then QUICK="--quick"; OUT=out-pi-quick; fi
export LINEA_OUT=$OUT
export LINEA_SIGN_ONLY=1   # no KEM timings from this board; see the header
mkdir -p "$OUT"
LOG="$OUT/run_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

BOARD=$(uname -m); [ -r /proc/device-tree/model ] && BOARD=$(tr -d '\0' < /proc/device-tree/model)
echo "== Line A on $BOARD  ($(date -Is))"
gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "?")
echo "   governor: $gov"
if command -v vcgencmd >/dev/null 2>&1; then
    thr=$(vcgencmd get_throttled | cut -d= -f2)
    echo "   throttled: $thr   $(vcgencmd measure_temp)"
    if [ -z "$QUICK" ] && [ "$((thr & 0xF))" -ne 0 ]; then
        echo "   the board is throttling or under-voltage right now; fix power/cooling first"; exit 1
    fi
    if [ -z "$QUICK" ] && [ "$gov" != performance ]; then
        echo "   set the performance governor for the full run:"
        echo "     echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"
        exit 1
    fi
else
    echo "   vcgencmd not found: rehearsal mode, no power or thermal data"
fi

step() { echo; echo "== $1"; shift; "$@" || echo "!! $1 failed (exit $?), continuing"; }

if [ -n "$QUICK" ]; then
    export LINEA_TRIALS=50
fi

# The platform-ladder row: same scripts as the M1, same output names.
step "E1 post-quantum manifest cost" python src/e1_pq.py
step "E1 verification" python src/e1_verify.py
step "E1 hash against signature" python src/e1_hash.py
step "backend comparison" python compare_backends.py

# Verification at scale across the Pi's four cores, as on the M1.
if [ -n "$QUICK" ]; then
    step "E8 verification across cores" python src/e8_scale.py --quick
else
    step "E8 verification across cores" python src/e8_scale.py
fi

# The Pi-only experiments.
step "E7 edge verifier, trust store on SD" python pi5/e7_edge.py $QUICK
step "E6 video signer" python pi5/e6_video.py $QUICK

echo
echo "== done: $OUT/"
ls -1 "$OUT"
