#!/usr/bin/env python3
"""Collect a board's timing results from serial into one JSON file.

    python3 mcu_capture.py pico   [port]     -> out-mcu/e9_pico.json
    python3 mcu_capture.py nucleo [port]     -> out-mcu/e10_nucleo_<MHz>mhz.json
    python3 mcu_capture.py nrf    [port]     -> out-mcu/e11_nrf52840.json
    python3 mcu_capture.py ble    [port]     -> out-mcu/e12_ble_rx.json (DK2's port)

Pico: plug it in running linea_pico.uf2; the firmware waits for this script
to open the port, then starts.
NUCLEO: flashed with linea_nucleo_20mhz.bin or _80mhz.bin; start this script,
then press the black RESET button. Output comes through the ST-LINK's virtual
COM port at 38400 baud.
nRF52840-DK (nrf, ble): the J-Link virtual COM port at 115200 baud; start this
script, then press the DK's RESET button (for ble: DK2's, before DK1's).
Each board prints one JSON object per line and finishes with {"op":"done"}.
"""
import glob, json, os, sys, time

try:
    import serial
except ImportError:
    sys.exit("pyserial is missing: python3 -m pip install pyserial")

if len(sys.argv) < 2 or sys.argv[1] not in ("pico", "nucleo", "nrf", "ble"):
    sys.exit(__doc__)
board = sys.argv[1]
port = sys.argv[2] if len(sys.argv) > 2 else None
if not port:
    ports = sorted(glob.glob("/dev/cu.usbmodem*") + glob.glob("/dev/ttyACM*"))
    if not ports:
        sys.exit("no board found on /dev/cu.usbmodem*: is it plugged in?")
    if len(ports) > 1:
        print("several ports:", ports, "- using", ports[0], "(pass the port to choose)")
    port = ports[0]
baud = 38400 if board == "nucleo" else 115200
print(f"reading {port} at {baud}", flush=True)
if board == "nucleo":
    print("press the NUCLEO's black RESET button now", flush=True)
elif board == "nrf":
    print("press the nRF52840-DK's RESET button now", flush=True)
elif board == "ble":
    print("press DK2's RESET button, then DK1's", flush=True)

env, rows, raw = None, [], []
t0 = time.time()
with serial.Serial(port, baud, timeout=5) as s:
    s.dtr = True
    while time.time() - t0 < 5400:
        line = s.readline().decode(errors="replace").strip()
        if not line:
            continue
        raw.append(line)
        try:
            d = json.loads(line)
        except ValueError:
            print("  (not JSON)", line)
            continue
        if d.get("op") == "env":
            env, rows, raw = d, [], [line]      # a reset mid-run starts over
        elif d.get("op") == "done":
            break
        else:
            rows.append(d)
        show = {k: d[k] for k in ("op", "alg", "median_us", "stack_bytes", "buffers_bytes",
                                  "ok", "MBps", "rejects_tampered_manifest") if k in d}
        print(" ", show, flush=True)

env = env or {}
if board == "pico":
    name = "e9_pico"
elif board == "nrf":
    name = "e11_nrf52840"
elif board == "ble":
    name = "e12_ble_rx"
else:
    name = f"e10_nucleo_{int(env.get('clk_sys_hz', 0)) // 1000000}mhz"
notes = [
    "messages are the Sig_structure of a real manifest built by pq_cose.py",
    "chain: decode COSE, parse three X.509 certificates, verify the leaf's and "
    "the intermediate's signatures (the anchor is trusted, not re-verified)",
    "manifest_full / _chain / _leaf / _thumb: copy the manifest into a receive buffer, "
    "then decode it, resolve the chain (from the manifest, or from the trust "
    "store for the parts not carried), verify chain and manifest signature",
    "buffers_bytes: receive buffer + rebuilt Sig_structure, both live at once; "
    "stack_bytes: peak stack of one call, by stack painting",
    "Ed25519: Monocypher 4; ES256: micro-ecc P-256 with PQClean SHA-256",
]
notes.append({
    "pico": "ML-DSA: PQClean portable C on the RP2040 (Cortex-M0+, XIP flash, 1 us timer)",
    "nucleo": "ML-DSA: pqm4 m4f (Cortex-M4 assembly); SysTick core-cycle counts",
    "nrf": "ML-DSA: pqm4 m4f; hw=1 rows: ES256, Ed25519 and SHA-256 on the CryptoCell-310 "
           "through PSA (CC3XX driver only), key import inside each timed call; DWT cycles at 64 MHz",
    "ble": "DK2's view of DK1's transfers: bytes per manifest, byte-for-byte check against the "
           "vectors, time from first to last notification; energy and per-manifest time "
           "come from the PPK2 run on DK1",
}[board])
out = os.environ.get("LINEA_OUT", "out-mcu")
os.makedirs(out, exist_ok=True)
path = os.path.join(out, name + ".json")
with open(path, "w") as f:
    json.dump({"experiment": name, "env": env, "notes": notes, "results": rows}, f, indent=2)
with open(os.path.join(out, name + "_raw.log"), "w") as f:
    f.write("\n".join(raw) + "\n")
print(f"wrote {path} ({len(rows)} rows) in {time.time() - t0:.0f} s")
