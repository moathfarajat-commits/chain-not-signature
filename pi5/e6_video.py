#!/usr/bin/env python3
"""E6: a camera that signs its video, on a Raspberry Pi 5.

The paper's per-image results leave one question open: can a device sign a
video stream as it is captured? This experiment answers it for an
application-processor camera. It is not a secure element, and the paper says
so wherever the numbers appear.

Per frame the signer does what a C2PA camera would:

    hash the raw frame (SHA-256 over YUV 4:2:0 pixels, the hard binding)
    -> build the claim around that hash
    -> sign the claim as a detached-payload COSE_Sign1 (RFC 9964 for ML-DSA)

`--segment N` signs once per N frames instead, the way fragmented-MP4
provenance signs a segment: every frame is still hashed, but only the
segment's claim is signed. N=1 is the per-frame upper bound; N=30 is one
signature a second at 30 fps.

Three kinds of run, all on one pinned core:

  burst    unpaced, as fast as possible: the sustainable frame rate
  paced    real time at --fps: deadline misses and frame latency
  thermal  paced and long (30 minutes by default) with temperature, clock,
           throttle flags and PMIC rail power sampled each second

Energy per signed frame is the rail power above the idle baseline divided by
the frame rate. Signing goes through liboqs for ML-DSA, as a camera would use
the fastest implementation available, and through `cryptography` for the
classical baselines.
"""

import argparse
import hashlib
import os
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "src"))
sys.path.insert(0, HERE)

import cbor2  # noqa: E402

import pi_telemetry as tel  # noqa: E402
from common import write_json  # noqa: E402
from pq_cose import (COSE_ALG, HDR_ALG, HDR_X5CHAIN, HDR_X5T,  # noqa: E402
                     build_chain, liboqs_available)

RES = {"1080p": (1920, 1080), "4K": (3840, 2160)}
DEPTH = 3


def make_frames(res, k=4):
    """k distinct YUV 4:2:0 frames. Content is irrelevant to SHA-256's cost."""
    w, h = RES[res]
    n = w * h * 3 // 2
    base = bytearray(os.urandom(n))
    frames = []
    for i in range(k):
        f = bytearray(base)
        f[:8] = i.to_bytes(8, "little")
        frames.append(bytes(f))
    return frames


def make_signer(alg):
    """(sign(bytes)->sig, backend name, protected headers for both carriages)."""
    key, chain = build_chain(alg, DEPTH)
    prot_emb = cbor2.dumps({HDR_ALG: COSE_ALG[alg], HDR_X5CHAIN: chain})
    thumb = hashlib.sha256(chain[0]).digest()
    prot_ref = cbor2.dumps({HDR_ALG: COSE_ALG[alg], HDR_X5T: [-16, thumb]})

    if alg.startswith("ML-DSA") and liboqs_available():
        import oqs
        s = oqs.Signature(alg)
        s.generate_keypair()
        return s.sign, "liboqs", prot_emb, prot_ref
    if alg == "ES256":
        from pq_cose import es256_sign
        return (lambda m: es256_sign(key, m),
                "cryptography", prot_emb, prot_ref)
    return key.sign, "cryptography", prot_emb, prot_ref


def claim_for(seq, digests):
    """A claim binding one frame (or one segment's frames) by hash."""
    return cbor2.dumps({
        "claim_generator_info": [{"name": "line-a-e6", "version": "0.1"}],
        "segment": seq,
        "frames": len(digests),
        "hash_alg": "sha256",
        "hashes": digests,
    })


class Pipeline:
    def __init__(self, alg, res, segment):
        self.frames = make_frames(res)
        self.sign, self.backend, self.prot_emb, self.prot_ref = make_signer(alg)
        self.segment = segment
        self.pending = []
        self.seq = 0
        self.last_bytes = 0

    def step(self, i):
        """Process frame i. Returns True when this frame closed a signature."""
        self.pending.append(hashlib.sha256(self.frames[i % len(self.frames)]).digest())
        if len(self.pending) < self.segment:
            return False
        claim = claim_for(self.seq, self.pending)
        tbs = cbor2.dumps(["Signature1", self.prot_emb, b"", claim])
        sig = self.sign(tbs)
        cose = cbor2.dumps(cbor2.CBORTag(18, [self.prot_emb, {}, None, sig]))
        self.last_bytes = len(cose) + len(claim)
        self.pending = []
        self.seq += 1
        return True

    def sizes(self):
        """Manifest bytes per signature, embedded chain against thumbprint."""
        claim = claim_for(0, [b"\0" * 32] * self.segment)
        sig = self.sign(cbor2.dumps(["Signature1", self.prot_emb, b"", claim]))
        emb = cbor2.dumps(cbor2.CBORTag(18, [self.prot_emb, {}, None, sig]))
        ref = cbor2.dumps(cbor2.CBORTag(18, [self.prot_ref, {}, None, sig]))
        return len(emb) + len(claim), len(ref) + len(claim)


def run_burst(p, seconds):
    n, t0 = 0, time.perf_counter()
    while time.perf_counter() - t0 < seconds:
        p.step(n)
        n += 1
    return n / (time.perf_counter() - t0)


def run_paced(p, fps, seconds):
    """Real-time loop. Frame i is released at t0 + i/fps and is late if not
    finished before frame i+1 is released."""
    period = 1.0 / fps
    total = int(seconds * fps)
    lat, late, backlog_max = [], 0, 0.0
    t0 = time.perf_counter() + 0.05
    for i in range(total):
        release = t0 + i * period
        now = time.perf_counter()
        if now < release:
            time.sleep(release - now)
        start = time.perf_counter()
        p.step(i)
        end = time.perf_counter()
        lat.append((end - start) * 1000)
        if end > release + period:
            late += 1
            backlog_max = max(backlog_max, end - (release + period))
    lat.sort()
    return {
        "frames": total,
        "late_frames": late,
        "late_fraction": round(late / total, 5),
        "max_backlog_ms": round(backlog_max * 1000, 3),
        "frame_ms_median": round(statistics.median(lat), 4),
        "frame_ms_p99": round(lat[min(int(0.99 * len(lat)), len(lat) - 1)], 4),
        "frame_ms_max": round(lat[-1], 4),
    }


def one(alg, res, segment, fps, burst_s, paced_s, thermal_s, idle_w):
    p = Pipeline(alg, res, segment)
    emb, ref = p.sizes()
    row = {
        "alg": alg, "resolution": res, "segment_frames": segment, "fps": fps,
        "backend": p.backend,
        "manifest_bytes_embedded": emb, "manifest_bytes_thumbprint": ref,
        # bits per second of provenance alongside the video
        "mbps_embedded": round(emb * 8 * fps / segment / 1e6, 4),
        "mbps_thumbprint": round(ref * 8 * fps / segment / 1e6, 4),
    }

    with tel.Sampler() as s:
        row["burst_fps"] = round(run_burst(p, burst_s), 2)
    row["burst_telemetry"] = s.summary()

    with tel.Sampler() as s:
        row["paced"] = run_paced(p, fps, paced_s)
    row["paced_telemetry"] = s.summary()

    if thermal_s:
        with tel.Sampler() as s:
            row["thermal"] = run_paced(p, fps, thermal_s)
            row["thermal"]["seconds"] = thermal_s
        row["thermal_telemetry"] = s.summary()
        row["thermal_trace"] = [
            {k: v for k, v in x.items() if k != "t"} for x in s.samples[::10]]

    # Energy per signed frame, net of idle, where power was measured.
    def per_frame(tsum, rate):
        pw = (tsum or {}).get("power_w_mean")
        if pw is None or idle_w is None or not rate:
            return None
        return round((pw - idle_w) / rate * 1000, 4)   # millijoules

    row["mj_per_frame_paced"] = per_frame(row["paced_telemetry"], fps)
    row["mj_per_frame_burst"] = per_frame(row["burst_telemetry"], row["burst_fps"])
    if thermal_s:
        row["mj_per_frame_thermal"] = per_frame(row["thermal_telemetry"], fps)
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--quick", action="store_true",
                    help="seconds-long runs, two algorithms, 1080p: a rehearsal")
    ap.add_argument("--algs", default="Ed25519,ES256,ML-DSA-44,ML-DSA-65,ML-DSA-87")
    ap.add_argument("--res", default="1080p,4K")
    ap.add_argument("--segments", default="1,30")
    ap.add_argument("--fps", type=int, default=30)
    ap.add_argument("--burst", type=float, default=10)
    ap.add_argument("--paced", type=float, default=120)
    ap.add_argument("--thermal", type=float, default=1800,
                    help="seconds for the long runs; 0 to skip")
    ap.add_argument("--thermal-cases", default="ML-DSA-65@4K,ML-DSA-87@4K,Ed25519@4K",
                    help="alg@res pairs that get a long thermal run (per-frame signing)")
    ap.add_argument("--idle", type=float, default=60)
    a = ap.parse_args()

    if a.quick:
        a.algs, a.res, a.segments = "Ed25519,ML-DSA-65", "1080p", "1,30"
        a.burst, a.paced, a.thermal, a.idle = 2, 3, 5, 3
        a.thermal_cases = "ML-DSA-65@1080p"

    core = tel.pin_to_core()
    ok, why = tel.available()
    print(f"  pinned to core {core}; telemetry: {'on' if ok else why}")
    print(f"  liboqs: {'yes' if liboqs_available() else 'NO - ML-DSA falls back to cryptography'}")

    print(f"  idle baseline, {a.idle:.0f} s")
    idle = tel.idle_power(a.idle)
    idle_w = idle.get("power_w_mean")

    long_runs = {tuple(x.split("@")) for x in a.thermal_cases.split(",") if x}
    rows = []
    for res in a.res.split(","):
        for alg in a.algs.split(","):
            for seg in (int(x) for x in a.segments.split(",")):
                th = a.thermal if (seg == 1 and (alg, res) in long_runs) else 0
                print(f"  {alg:10s} {res:5s} segment={seg:<3d}"
                      f"{' + thermal %ds' % th if th else ''}", flush=True)
                r = one(alg, res, seg, a.fps, a.burst, a.paced, th, idle_w)
                print(f"      burst {r['burst_fps']:8.1f} fps, paced late "
                      f"{r['paced']['late_fraction']:.3%}, "
                      f"{r['mbps_embedded']:.3f} Mbps embedded")
                rows.append(r)

    extra = {"pi": tel.static_env(), "pinned_core": core, "idle": idle,
             "quick": a.quick, "liboqs": liboqs_available()}
    try:
        import oqs
        extra["liboqs_version"] = oqs.oqs_version()
    except Exception:
        pass
    write_json("e6_video.json", rows, extra_env=extra, notes=[
        "frame hash is SHA-256 over raw YUV 4:2:0 pixels",
        "segment_frames=1 signs every frame; 30 signs once per second at 30 fps",
        "a paced frame is late if it is not finished before the next is released",
        "power is the PMIC rail sum, V*I over rails; not wall power",
        "mJ per frame is rail power above the idle baseline divided by frame rate",
        "application-processor signer, not a secure element",
    ])


if __name__ == "__main__":
    main()
