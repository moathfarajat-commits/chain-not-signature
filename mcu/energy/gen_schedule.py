"""schedule.json -> schedule.h, so the firmware and the PPK2 runner agree on
which marker window is which."""
import json, sys, pathlib
src = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "schedule.json")
dst = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else src.with_suffix(".h"))
s = json.loads(src.read_text())
# entries: [alg, op, k] or [alg, op, k, hw]; hw = 1 runs it on the crypto engine
rows = ",\n".join(f'    {{"{e[0]}", "{e[1]}", {e[2]}, {e[3] if len(e) > 3 else 0}}}' for e in s["entries"])
dst.write_text(f"""/* Generated from {src.name} by gen_schedule.py. Do not edit. */
#ifndef SCHEDULE_H
#define SCHEDULE_H
typedef struct {{ const char *alg; const char *op; int k; int hw; }} sched_t;
static const sched_t SCHEDULE[] = {{
{rows}
}};
#define N_SCHEDULE {len(s["entries"])}
#define ROUNDS {s["rounds"]}
#define GAP_MS {s["gap_ms"]}
#define START_IDLE_MS {s["start_idle_ms"]}
#define SYNC_PULSES {s["sync_pulses"]}
#define SYNC_MS {s["sync_ms"]}
#endif
""")
print("wrote", dst)
