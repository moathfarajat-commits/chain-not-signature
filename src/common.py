"""Shared helpers: environment capture, timing, JSON output.

Every experiment writes one JSON file into out/ containing an "env" block and a
"results" list. The env block is what makes a run citable months later.
"""

import json
import os
import platform
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone

# LINEA_OUT redirects results, so a second build of the same software can be
# measured without overwriting the first: out/ for the wheel, out-o3/ for the
# source-built cryptography.
OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       os.environ.get("LINEA_OUT", "out"))


def cpu_brand():
    if sys.platform == "darwin":
        try:
            return subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
        except Exception:
            return platform.processor() or "unknown"
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith(("model name", "Model")):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "unknown"


def crypto_features():
    """Which hardware crypto instructions the CPU advertises.

    SHA-3 matters: Keccak dominates ML-DSA and ML-KEM cost, so a machine with
    SHA-3 instructions and one without are not comparable on clock speed alone.
    """
    want = ["aes", "sha1", "sha2", "sha3", "sha512", "pmull"]
    if sys.platform == "darwin":
        found = []
        for feat, flag in [("sha3", "hw.optional.armv8_2_sha3"),
                           ("sha512", "hw.optional.armv8_2_sha512"),
                           ("aes", "hw.optional.arm.FEAT_AES"),
                           ("sha2", "hw.optional.arm.FEAT_SHA256")]:
            try:
                v = subprocess.check_output(["sysctl", "-n", flag], text=True).strip()
                if v == "1":
                    found.append(feat)
            except Exception:
                pass
        return sorted(set(found))
    try:
        with open("/proc/cpuinfo") as f:
            text = f.read().lower()
        return sorted({w for w in want if w in text})
    except Exception:
        return []


def openssl_build():
    """Name the OpenSSL build behind `cryptography`, not only its version.

    The macOS arm64 wheel of cryptography 50.0.1 statically links an OpenSSL
    compiled without any -O flag, which leaves every C-implemented primitive,
    every post-quantum one included, about ten times slower than the same
    OpenSSL version built normally. The version string is identical in both
    cases, so recording it alone would not have caught this. The compiler line
    OpenSSL embeds in itself does.
    """
    out = {}
    try:
        import glob
        import cryptography
        from cryptography.hazmat.backends.openssl.backend import backend
        out["openssl"] = backend.openssl_version_text()
        so = glob.glob(os.path.join(os.path.dirname(cryptography.__file__),
                                    "hazmat", "bindings", "_rust*.so"))
        if so:
            blob = open(so[0], "rb").read()
            i = blob.find(b"compiler: ")
            if i >= 0:
                out["openssl_compiler"] = blob[i:blob.index(b"\0", i)].decode(
                    errors="replace")
    except Exception as e:
        out["openssl_build_error"] = str(e)[:120]
    return out


def env_block(extra=None):
    import cbor2
    import cryptography
    env = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hostname": platform.node(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu": cpu_brand(),
        "cpu_count": os.cpu_count(),
        "crypto_features": crypto_features(),
        "python": sys.version.split()[0],
        "cryptography": cryptography.__version__,
        "cbor2": _ver("cbor2"),
    }
    env.update(openssl_build())
    try:
        import c2pa
        env["c2pa_rs"] = c2pa.sdk_version()
    except Exception:
        env["c2pa_rs"] = None
    if extra:
        env.update(extra)
    return env


def _ver(pkg):
    try:
        import importlib.metadata as md
        return md.version(pkg)
    except Exception:
        return None


# ML-DSA signing uses rejection sampling, so its cost has a long right tail.
# A hundred iterations does not characterise that tail, and two runs of the
# same operation can differ by twenty per cent. Default to a thousand and
# report p99 alongside the median.
DEFAULT_TRIALS = int(os.environ.get("LINEA_TRIALS", "1000"))
DEFAULT_WARMUP = 50


def run_order(items):
    """The configurations of one experiment, in this run's order.

    Each independent run (LINEA_RUN set by run_reps.sh) visits algorithms and
    configurations in its own random order, so that drift during a run (heat,
    frequency, background load) does not always fall on the same
    configuration. Results are matched across runs by key, not by position.
    """
    items = list(items)
    run = os.environ.get("LINEA_RUN")
    if run:
        import random
        random.Random(int(run) * 7919).shuffle(items)
    return items


def time_it(fn, trials=DEFAULT_TRIALS, warmup=DEFAULT_WARMUP):
    """Median, IQR, p95, p99 and min in milliseconds. Warm-up is discarded."""
    for _ in range(warmup):
        fn()
    t = []
    for _ in range(trials):
        t0 = time.perf_counter()
        fn()
        t.append((time.perf_counter() - t0) * 1000)
    t.sort()

    def pct(q):
        return t[min(int(q * len(t)), len(t) - 1)]

    return {
        "n": trials,
        "median_ms": round(statistics.median(t), 4),
        # The mean is kept because the median is the wrong statistic for a
        # throughput question. ML-DSA signing uses rejection sampling and has a
        # long right tail, so one signature costs about the median while a
        # batch of many costs about the mean. Reporting only the median makes
        # any capacity estimate built on it optimistic by roughly that gap.
        "mean_ms": round(statistics.fmean(t), 4),
        "iqr_ms": round(pct(0.75) - pct(0.25), 4),
        "p95_ms": round(pct(0.95), 4),
        "p99_ms": round(pct(0.99), 4),
        "min_ms": round(t[0], 4),
        "max_ms": round(t[-1], 4),
    }


def write_json(name, results, extra_env=None, notes=None):
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, name)
    env = env_block(extra_env)
    if os.environ.get("LINEA_RUN"):
        env["run"] = int(os.environ["LINEA_RUN"])
    doc = {"experiment": name.replace(".json", ""),
           "env": env,
           "notes": notes or [],
           "results": results}
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)
    print(f"  wrote {os.path.relpath(path)}  ({len(results)} rows)")
    return path
