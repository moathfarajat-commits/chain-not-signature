#!/usr/bin/env python3
"""Energy per credential operation with a Nordic PPK2.

The firmware's energy build raises a marker pin around each window of k
back-to-back runs of one operation, in the order fixed by schedule.json, and
sleeps between windows. This script records the PPK2 stream (current plus
the eight logic inputs, 100 kS/s) to disk, then splits it at the marker edges
and integrates current x voltage over each window.

Two ways to connect:
  source  (Pico)    the PPK2 powers the board: VOUT -> VSYS, GND -> GND.
  ampere  (NUCLEO)  the board powers itself through the PPK2: JP5 (IDD) off,
                    VIN/VOUT across JP5's two pins.
  ampere  (nRF52840-DK)  SB40 cut; VIN to P22's VDD pin, VOUT to VDD_nRF.
In both, logic input D0 takes the marker, and the logic port's VCC and GND go
to the board's 3V3 and GND.

Per window it reports gross energy (everything the measured rail drew) and
net energy (gross minus the idle power of the gap that follows, times the
window length). Absolute values carry the PPK2's own uncertainty (Nordic
quotes about +/-20 % below 1 uA and better above); ratios between algorithms
measured in one run are much tighter.

Usage:
  python3 ppk2_energy.py --board pico   --mode source --mv 3300 --out out-energy-pico
  python3 ppk2_energy.py --board nucleo --mode ampere --mv 3300 --out out-energy-nucleo
  python3 ppk2_energy.py --board nrf52840 --mode ampere --mv 3000 \
          --schedule schedule_nrf.json --out out-energy-nrf
  python3 ppk2_energy.py --board nrf52840 --mode ampere --mv 3000 \
          --schedule schedule_ble.json --out out-energy-ble
  python3 ppk2_energy.py --analyse out-energy-pico      (redo the analysis only)
"""
import argparse, json, os, pathlib, statistics, sys, time

HERE = pathlib.Path(__file__).resolve().parent
RATE = 100_000                      # PPK2 samples per second


def load_schedule(path):
    return load_schedule_obj(json.loads(pathlib.Path(path).read_text()))


def load_schedule_obj(s):
    windows = []
    for r in range(s["rounds"]):
        for e in s["entries"]:
            windows.append({"round": r, "alg": e[0], "op": e[1], "k": e[2],
                            "hw": e[3] if len(e) > 3 else 0})
    return s, windows


# ------------------------------------------------------------------ record

def open_ppk2(port):
    from ppk2_api.ppk2_api import PPK2_API
    if port is None:
        devs = PPK2_API.list_devices()
        if not devs:
            sys.exit("No PPK2 found. Is it plugged in and powered (switch on)?")
        port = devs[0][0] if isinstance(devs[0], (list, tuple)) else devs[0]
    ppk = PPK2_API(port, timeout=1, write_timeout=1, exclusive=True)
    return ppk, port


DEFAULT_R = {"0": 1031.64, "1": 101.65, "2": 10.15, "3": 0.94, "4": 0.043}


def read_metadata(ppk, timeout=3.0):
    """Ask for the calibration block and read until END. ppk2-api 0.9.x reads
    it in one go and loses it when it arrives in two pieces."""
    ppk.ser.reset_input_buffer()
    ppk.ser.write(bytes([0x19]))                 # GET_META_DATA
    out, t0 = b"", time.time()
    while time.time() - t0 < timeout:
        out += ppk.ser.read(max(1, ppk.ser.in_waiting))
        if b"END" in out:
            return out.decode("utf-8", errors="replace")
    return None


CAL_CACHE = HERE / "ppk2_calibration_cache.json"


def load_calibration(ppk, tries=6, port=None):
    """Load the device's own calibration and refuse to measure without it.

    The calibration block is constant for a given PPK2. After a session that
    switched the PPK2's output, ppk2-api 0.9.x often fails to read it again
    until the PPK2 is replugged, so a block read successfully is cached by
    the PPK2's serial number and reused when the read fails ("cached")."""
    key = os.path.basename(port or "")[:-1]          # serial without the interface digit
    for i in range(tries):
        meta = read_metadata(ppk)
        if meta and ppk._parse_metadata(meta):
            m = ppk.modifiers
            if any(abs(float(m["R"][k]) - DEFAULT_R[k]) > 1e-9 for k in DEFAULT_R):
                try:
                    c = json.loads(CAL_CACHE.read_text()) if CAL_CACHE.exists() else {}
                    c[key] = m
                    CAL_CACHE.write_text(json.dumps(c, indent=1))
                except Exception:
                    pass
                return True, i + 1
        time.sleep(0.5)
    if CAL_CACHE.exists():
        c = json.loads(CAL_CACHE.read_text())
        if key in c:
            ppk.modifiers = c[key]
            return "cached", tries
    return False, tries


def record(args, sched, n_windows):
    ppk, port = open_ppk2(args.port)
    calibrated, tries = load_calibration(ppk, port=port)
    if not calibrated and not args.allow_uncalibrated:
        sys.exit("PPK2 calibration did not load after %d tries; unplug and replug the PPK2 "
                 "and run again (or pass --allow-uncalibrated to measure anyway)." % tries)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    meta = {"port": port, "board": args.board, "mode": args.mode, "mv": args.mv,
            "calibrated": calibrated, "calibration_tries": tries,
            "modifiers": ppk.modifiers, "rate_hz": RATE, "schedule": sched,
            "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")}

    if args.mode == "source":
        ppk.use_source_meter()
    else:
        ppk.use_ampere_meter()
    ppk.set_source_voltage(args.mv)        # ampere mode: tells the PPK2 the rail voltage
    if args.flash_cmd:
        # Power the board from this same session, load its firmware over the
        # J-Link, and switch it off again before recording starts.
        import subprocess
        ppk.toggle_DUT_power("ON")
        time.sleep(1.0)
        r = subprocess.run(args.flash_cmd, shell=True, capture_output=True, text=True)
        ok = "O.K." in r.stdout and "Error" not in r.stdout
        print("flash:", "ok" if ok else "FAILED")
        meta["flash_cmd"] = args.flash_cmd
        ppk.toggle_DUT_power("OFF")
        time.sleep(1.5)
        if not ok:
            sys.exit(r.stdout[-2000:])

    # In both modes the PPK2 only closes the DUT path when its output is on,
    # so switching it off and on again also restarts the board cleanly.
    ppk.toggle_DUT_power("OFF")
    time.sleep(1.5)
    import numpy as np
    import threading, queue
    raw = open(out / "ppk2_raw.bin", "wb")
    q = queue.Queue()
    stop = threading.Event()
    nbytes = [0]

    def reader():
        """Only reads the port. The PPK2 sends 400 kB/s; any other work in
        this loop makes the OS buffer overflow and samples vanish."""
        ser = ppk.ser
        ser.timeout = 0.05
        while not stop.is_set():
            chunk = ser.read(max(4096, ser.in_waiting))
            if chunk:
                raw.write(chunk)
                nbytes[0] += len(chunk)
                q.put(chunk)

    ppk.start_measuring()
    th = threading.Thread(target=reader, daemon=True)
    th.start()
    ppk.toggle_DUT_power("ON")
    print("Board powered through the PPK2; the run starts after its 2 s idle."
          + (" (BLE: DK2 must already be running.)" if args.board == "nrf52840" else ""))
    expected_falls = sched["sync_pulses"] + n_windows
    t0 = time.time()
    carry = b""
    last = 0
    falls = 0
    last_fall_t = None
    try:
        while True:
            try:
                chunk = q.get(timeout=0.2)
            except queue.Empty:
                chunk = b""
            if chunk:
                buf = carry + chunk
                n = len(buf) // 4
                carry = buf[4 * n:]
                if n:
                    d0 = (np.frombuffer(buf[:4 * n], "<u4") >> 24) & 1
                    edges = np.diff(np.concatenate(([last], d0)).astype(np.int8))
                    nf = int((edges == -1).sum())
                    if nf:
                        falls += nf
                        last_fall_t = time.time()
                        print(f"\r  windows closed: {max(0, falls - sched['sync_pulses'])}/{n_windows}   ",
                              end="", flush=True)
                    last = int(d0[-1])
            el = time.time() - t0
            if falls >= expected_falls and time.time() - last_fall_t > 1.5:
                break
            if el > args.max_seconds:
                print(f"\nStopped at the {args.max_seconds} s limit with {falls} marker falls "
                      f"(expected {expected_falls}).")
                break
    except KeyboardInterrupt:
        print("\nStopped by Ctrl-C.")
    finally:
        elapsed = time.time() - t0
        ppk.stop_measuring()
        ppk.toggle_DUT_power("OFF")
        time.sleep(0.3)
        stop.set()
        th.join(timeout=2)
        raw.close()
    print()
    meta["seconds"] = round(elapsed, 2)
    meta["marker_falls"] = falls
    meta["sample_rate_received"] = round(nbytes[0] / 4 / elapsed, 1)
    print(f"received {meta['sample_rate_received']:.0f} samples/s (the PPK2 sends {RATE})")
    (out / "ppk2_meta.json").write_text(json.dumps(meta, indent=1))
    return out


# ----------------------------------------------------------------- analyse

def decode(raw_path, meta):
    """Raw stream -> (current in uA, D0) using ppk2-api's own conversion, so
    the numbers match what the library and nRF Connect would show."""
    import numpy as np
    from ppk2_api.ppk2_api import PPK2_API
    dec = PPK2_API.__new__(PPK2_API)          # no serial port needed
    dec.ser = None
    dec.modifiers = meta["modifiers"]
    dec.vdd_low, dec.vdd_high = 800, 5000
    dec.current_vdd = meta["mv"]
    dec.adc_mult = 1.8 / 163840
    dec.MEAS_ADC = dec._generate_mask(14, 0)
    dec.MEAS_RANGE = dec._generate_mask(3, 14)
    dec.MEAS_LOGIC = dec._generate_mask(8, 24)
    dec.mode = None
    dec.rolling_avg = dec.rolling_avg4 = dec.prev_range = None
    dec.consecutive_range_samples = 0
    dec.spike_filter_alpha, dec.spike_filter_alpha5 = 0.18, 0.06
    dec.spike_filter_samples = 3
    dec.after_spike = 0
    dec.remainder = {"sequence": b"", "len": 0}
    cur, dig = [], []
    with open(raw_path, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            s, d = dec.get_samples(chunk)
            cur.extend(s)
            dig.extend(d)
    i = np.asarray(cur, dtype=np.float64)
    m = (np.asarray(dig, dtype=np.uint16) & 1).astype(np.int8)
    return i, m


def analyse(out):
    import numpy as np
    out = pathlib.Path(out)
    meta = json.loads((out / "ppk2_meta.json").read_text())
    sched = meta["schedule"]
    _, windows = load_schedule_obj(sched)
    got = meta.get("sample_rate_received")
    if got is not None and got < 0.97 * RATE:
        sys.exit(f"Recording lost samples ({got:.0f}/s received, {RATE}/s sent): "
                 "times and energies would be wrong. Run it again.")
    i_ua, d0 = decode(out / "ppk2_raw.bin", meta)
    v = meta["mv"] / 1000.0
    dt = 1.0 / RATE
    e = np.diff(np.concatenate(([0], d0, [0])))
    rises = np.flatnonzero(e == 1)
    falls = np.flatnonzero(e == -1)
    spans = list(zip(rises, falls))
    ns = sched["sync_pulses"]
    # Anchor on the sync pulses, found by their length, so that a glitch on
    # the marker at power-on (the pin floats before the firmware drives it)
    # cannot shift every window by one.
    sync_len = sched["sync_ms"] / 1000.0 * RATE
    def is_sync(k):
        return all(abs((spans[j][1] - spans[j][0]) - sync_len) < 0.3 * sync_len
                   for j in range(k, k + ns))
    first = next((k for k in range(0, max(0, len(spans) - ns + 1)) if is_sync(k)), None)
    if first is None:
        sys.exit("No sync pulses found on the marker; cannot align windows.")
    dropped = first
    spans = spans[first:]
    report = {"meta": {k: meta[k] for k in ("board", "mode", "mv", "calibrated", "seconds")},
              "samples": int(len(i_ua)), "spans_found": len(spans),
              "spans_dropped_before_sync": dropped,
              "spans_expected": ns + len(windows)}
    if len(spans) < ns + len(windows):
        report["warning"] = "fewer marker windows than the schedule; matched in order up to what was found"
    rows = []
    gap = sched["gap_ms"] / 1000.0
    for w, (a, b) in zip(windows, spans[ns:]):
        q = i_ua[a:b].sum() * dt * 1e-6                     # coulombs
        dur = (b - a) * dt
        # idle: the middle 80 % of the gap after the window
        ga = b + int(0.1 * gap * RATE)
        gb = b + int(0.9 * gap * RATE)
        if gb <= len(i_ua) and gb > ga:
            idle_ua = float(np.median(i_ua[ga:gb]))
        else:                                   # last window: use the gap before it
            idle_ua = float(np.median(i_ua[max(0, a - int(0.9 * gap * RATE)):max(1, a - int(0.1 * gap * RATE))]))
        gross_j = q * v
        net_j = gross_j - idle_ua * 1e-6 * v * dur
        rows.append(dict(w, window_s=round(dur, 6), mean_ma=round(i_ua[a:b].mean() / 1000, 4),
                         idle_ma=round(idle_ua / 1000, 4),
                         gross_uj_per_op=round(gross_j / w["k"] * 1e6, 3),
                         net_uj_per_op=round(net_j / w["k"] * 1e6, 3),
                         ms_per_op=round(dur / w["k"] * 1000, 4)))
    report["windows"] = rows
    summary = {}
    for r in rows:
        key = f'{r["alg"]}|{r["op"]}|{r["hw"]}'
        summary.setdefault(key, []).append(r)
    report["summary"] = []
    for key, rs in summary.items():
        alg, op, hw = key.split("|")
        g = [x["gross_uj_per_op"] for x in rs]
        n = [x["net_uj_per_op"] for x in rs]
        t = [x["ms_per_op"] for x in rs]
        report["summary"].append({
            "alg": alg, "op": op, "hw": int(hw), "rounds": len(rs),
            "gross_uj_median": round(statistics.median(g), 2),
            "gross_uj_spread_pct": round(100 * (max(g) - min(g)) / statistics.median(g), 2) if len(g) > 1 else 0,
            "net_uj_median": round(statistics.median(n), 2),
            "ms_per_op_median": round(statistics.median(t), 3),
            "mean_ma_median": round(statistics.median(x["mean_ma"] for x in rs), 3),
            "idle_ma_median": round(statistics.median(x["idle_ma"] for x in rs), 3)})
    (out / "energy.json").write_text(json.dumps(report, indent=1))
    print(f"{report['spans_found']} marker windows found from the sync pulses on "
          f"({dropped} stray pulse(s) before them ignored), {report['spans_expected']} expected")
    print(f"{'alg':10} {'op':15} {'ms/op':>10} {'gross uJ':>11} {'net uJ':>11} {'spread%':>8}")
    for s in report["summary"]:
        print(f"{s['alg'] + ('+hw' if s['hw'] else ''):10} {s['op']:15} {s['ms_per_op_median']:10.3f} {s['gross_uj_median']:11.1f} "
              f"{s['net_uj_median']:11.1f} {s['gross_uj_spread_pct']:8.2f}")
    print("wrote", out / "energy.json")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--board", choices=["pico", "nucleo", "nrf52840"])
    ap.add_argument("--mode", choices=["source", "ampere"])
    ap.add_argument("--mv", type=int, default=3300)
    ap.add_argument("--port")
    ap.add_argument("--schedule", default=str(HERE / "schedule.json"))
    ap.add_argument("--out")
    ap.add_argument("--max-seconds", type=float, default=1800)
    ap.add_argument("--allow-uncalibrated", action="store_true")
    ap.add_argument("--flash-cmd", help="shell command run with the board powered, before recording")
    ap.add_argument("--analyse", metavar="DIR")
    args = ap.parse_args()
    if args.analyse:
        analyse(args.analyse)
        return
    if not (args.board and args.mode and args.out):
        ap.error("--board, --mode and --out are needed to record")
    sched, windows = load_schedule(args.schedule)
    out = record(args, sched, len(windows))
    analyse(out)


if __name__ == "__main__":
    main()
