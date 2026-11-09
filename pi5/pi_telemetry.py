"""Raspberry Pi 5 telemetry for the Line A edge experiments.

Everything here reads the board through `vcgencmd` and sysfs. Off a Pi, or with
`vcgencmd` missing, every reading comes back as None and `available()` says
why, so the experiments still run (for a rehearsal) and the result files say
plainly that the power and thermal columns are empty rather than zero.

Power comes from the PMIC's own ADC (`vcgencmd pmic_read_adc`). It reports a
current and a voltage per rail; the sum of V*I over the rails is the board's
rail power. That excludes USB peripherals and losses in the external supply,
so it is not wall power, and the papers built on it say so.
"""

import os
import re
import shutil
import subprocess
import threading
import time

VCGENCMD = shutil.which("vcgencmd")
_ALL_CORES = (frozenset(os.sched_getaffinity(0))
              if hasattr(os, "sched_getaffinity") else frozenset())
_PINNED = None   # the core the measured work runs on, once pin_to_core is called


def _vc(*args):
    if not VCGENCMD:
        return None
    try:
        return subprocess.run([VCGENCMD, *args], capture_output=True, text=True,
                              timeout=5).stdout
    except Exception:
        return None


def available():
    """(True, '') on a Pi with vcgencmd working, else (False, reason)."""
    if not VCGENCMD:
        return False, "vcgencmd not found: not a Raspberry Pi, or not installed"
    out = _vc("measure_temp")
    if not out or "temp=" not in out:
        return False, "vcgencmd present but not answering (permissions?)"
    return True, ""


def board_model():
    for p in ("/proc/device-tree/model", "/sys/firmware/devicetree/base/model"):
        try:
            with open(p, "rb") as f:
                return f.read().rstrip(b"\0").decode()
        except Exception:
            pass
    return None


def cpu_core_name():
    """The Arm core part number, decoded for the cores Line A cares about."""
    parts = {"0xd0b": "Cortex-A76", "0xd08": "Cortex-A72", "0xd03": "Cortex-A53"}
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.lower().startswith("cpu part"):
                    p = line.split(":", 1)[1].strip().lower()
                    return parts.get(p, p)
    except Exception:
        pass
    return None


def governor():
    try:
        with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") as f:
            return f.read().strip()
    except Exception:
        return None


def temp_c():
    out = _vc("measure_temp")
    m = re.search(r"temp=([\d.]+)", out or "")
    if m:
        return float(m.group(1))
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            return int(f.read()) / 1000.0
    except Exception:
        return None


def arm_clock_hz():
    m = re.search(r"=(\d+)", _vc("measure_clock", "arm") or "")
    return int(m.group(1)) if m else None


def throttled():
    m = re.search(r"throttled=(0x[0-9a-fA-F]+)", _vc("get_throttled") or "")
    return int(m.group(1), 16) if m else None


_RAIL = re.compile(r"^\s*(\S+?)_([AV])\s+\w+\(\d+\)=([\d.]+)[AV]", re.M)


def rail_power_w():
    """Sum of V*I over the PMIC rails, in watts, or None."""
    out = _vc("pmic_read_adc")
    if not out:
        return None
    amps, volts = {}, {}
    for name, kind, val in _RAIL.findall(out):
        (amps if kind == "A" else volts)[name] = float(val)
    rails = set(amps) & set(volts)
    if not rails:
        return None
    return sum(amps[r] * volts[r] for r in rails)


def static_env():
    ok, why = available()
    return {
        "board": board_model(),
        "core": cpu_core_name(),
        "governor": governor(),
        "telemetry": "vcgencmd" if ok else f"unavailable: {why}",
    }


class Sampler:
    """Samples temperature, clock, throttle flags and rail power once a second.

    Runs in a background thread. The experiments pin their own work to one
    core. A thread inherits the affinity of the thread that starts it, so the
    sampler first moves itself, and with it every vcgencmd it launches, onto
    the other cores; otherwise its calls would steal time from the measured
    loop.
    """

    def __init__(self, period=1.0):
        self.period = period
        self.samples = []
        self._stop = threading.Event()
        self._t = None

    def _run(self):
        others = _ALL_CORES - {_PINNED}
        if _PINNED is not None and others:
            os.sched_setaffinity(0, others)   # 0 is this thread on Linux
        while not self._stop.is_set():
            t = time.monotonic()
            self.samples.append({"t": t, "temp_c": temp_c(),
                                 "arm_hz": arm_clock_hz(),
                                 "throttled": throttled(),
                                 "power_w": rail_power_w()})
            self._stop.wait(max(0.0, self.period - (time.monotonic() - t)))

    def __enter__(self):
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._t.join()

    def summary(self):
        def col(k):
            return [s[k] for s in self.samples if s[k] is not None]

        temp, clk, pw = col("temp_c"), col("arm_hz"), col("power_w")
        thr = col("throttled")
        flags = 0
        for x in thr:
            flags |= x
        return {
            "samples": len(self.samples),
            "temp_c_mean": round(sum(temp) / len(temp), 2) if temp else None,
            "temp_c_max": max(temp) if temp else None,
            "arm_hz_min": min(clk) if clk else None,
            "arm_hz_max": max(clk) if clk else None,
            # Bits 0-3 are "now", 16-19 "since boot"; OR over the run keeps both.
            "throttled_or": hex(flags) if thr else None,
            "power_w_mean": round(sum(pw) / len(pw), 4) if pw else None,
            "power_w_max": round(max(pw), 4) if pw else None,
        }


def idle_power(seconds=60):
    """Mean rail power with nothing running, the baseline energy is net of."""
    with Sampler() as s:
        time.sleep(seconds)
    return s.summary()


def pin_to_core(core=None):
    """Pin this process to one core, the last by default. Returns the core."""
    if not hasattr(os, "sched_setaffinity"):
        return None
    global _PINNED
    cores = sorted(os.sched_getaffinity(0))
    c = cores[-1] if core is None else core
    os.sched_setaffinity(0, {c})
    _PINNED = c
    return c
