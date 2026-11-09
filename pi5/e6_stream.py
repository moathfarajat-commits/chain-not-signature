#!/usr/bin/env python3
"""E6b: signing an encoded video stream the ways C2PA 2.5 provides.

The first video experiment (e6_video.py) hashed raw YUV frames and signed
every frame. That is a computational upper bound, not a workflow: cameras and
encoders bind the encoded bitstream, and C2PA binds video through BMFF segment
hashes. This experiment uses real H.264 and HEVC streams in fragmented MP4
(make_stream.sh; one fragment per second) and signs them three ways:

  frame     a COSE signature over every encoded frame (access unit), each
            carrying the signer's chain. Not a C2PA method; the upper bound.

  manifest  C2PA 2.5 Section 15.4: every segment carries its own C2PA
            manifest with a BMFF hash of the segment, a live-video segment
            assertion (sequence number, stream identifier), and a COSE
            signature with x5chain (signer and intermediate).

  vsi       C2PA 2.5 Section 15.5: the stream's first manifest carries the
            chain and a session key bound to the signer by a signerBinding
            signature; each segment then carries only a Verifiable Segment
            Info map (sequence number, BMFF hash, manifest id) signed by the
            session key, in an emsg box. The session key here uses the same
            algorithm as the signer, so the stream is post-quantum end to end.

A segment is 1, 2, 4 or 6 consecutive one-second fragments. For every
algorithm, stream and segment length it measures, on one pinned core: hashing
and signing time per segment, the latency from segment close to signature,
provenance bytes per segment and as a share of the video bitrate, and the
one-off cost of the stream's initial manifest. A verifier then replays each
stream with segments dropped, reordered, truncated within a segment, replayed,
substituted, taken from another stream by the same signer, and with the tail
removed (with and without an announced length), and for the session-key
method without the initial manifest and after the session key has expired;
it reports what each method detects.
"""

import argparse
import hashlib
import os
import statistics
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "src"))
sys.path.insert(0, HERE)

import cbor2  # noqa: E402

from common import write_json  # noqa: E402
from pq_cose import (COSE_ALG, build_chain, liboqs_available,  # noqa: E402
                     protected_header, raw_sign, raw_verify, KEYGEN)

try:
    import pi_telemetry as tel  # noqa: E402
except Exception:  # noqa: BLE001
    tel = None

ALGS = ["Ed25519", "ES256", "PS256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
SEGMENTS = [1, 2, 4, 6]
FPS = 30
JUMBF_OVERHEAD = 1072        # measured manifest-store framing, e1_baseline
EMSG_SCHEME = b"urn:c2pa:verifiable-segment-info"


# --- fragmented MP4 -------------------------------------------------------------

def boxes(buf, start=0, end=None):
    end = len(buf) if end is None else end
    i = start
    while i + 8 <= end:
        size, typ = struct.unpack(">I4s", buf[i:i + 8])
        hdr = 8
        if size == 1:
            size = struct.unpack(">Q", buf[i + 8:i + 16])[0]
            hdr = 16
        elif size == 0:
            size = end - i
        yield typ.decode("latin1"), i, i + hdr, i + size
        i += size


def trun_sizes(buf, s, e):
    """Sample sizes from a trun box body."""
    flags = int.from_bytes(buf[s + 1:s + 4], "big")
    count = struct.unpack(">I", buf[s + 4:s + 8])[0]
    p = s + 8
    if flags & 0x1:
        p += 4
    if flags & 0x4:
        p += 4
    sizes = []
    for _ in range(count):
        if flags & 0x100:
            p += 4
        if flags & 0x200:
            sizes.append(struct.unpack(">I", buf[p:p + 4])[0])
            p += 4
        if flags & 0x400:
            p += 4
        if flags & 0x800:
            p += 4
    return sizes


def fragments(path):
    """(init bytes, [(fragment bytes, [frame bytes, ...]), ...])."""
    buf = open(path, "rb").read()
    init_end, frags, moof = None, [], None
    for typ, s, b, e in boxes(buf):
        if typ == "moof":
            if init_end is None:
                init_end = s
            sizes = []
            for t2, s2, b2, e2 in boxes(buf, b, e):
                if t2 == "traf":
                    for t3, s3, b3, e3 in boxes(buf, b2, e2):
                        if t3 == "trun":
                            sizes += trun_sizes(buf, b3, e3)
            moof = (s, sizes)
        elif typ == "mdat" and moof:
            ms, sizes = moof
            data, frames, p = buf[b:e], [], 0
            for n in sizes:
                frames.append(data[p:p + n])
                p += n
            frags.append((buf[ms:e], frames))
            moof = None
    return buf[:init_end], frags


# --- signing ----------------------------------------------------------------------

class Signer:
    def __init__(self, alg):
        self.alg = alg
        self.key, self.chain = build_chain(alg, 3)
        self.backend = "cryptography"
        self.pub = self.key.public_key()
        if alg.startswith("ML-DSA") and liboqs_available():
            import oqs
            self.oqs = oqs.Signature(alg)
            self.oqs_pk = self.oqs.generate_keypair()
            self.oqs_v = oqs.Signature(alg)
            self.backend = "liboqs"

    def sign(self, msg):
        if self.backend == "liboqs":
            return self.oqs.sign(msg)
        return raw_sign(self.alg, self.key, msg)

    def verify(self, msg, sig):
        if self.backend == "liboqs":
            if not self.oqs_v.verify(msg, sig, self.oqs_pk):
                raise ValueError("bad signature")
            return
        raw_verify(self.alg, self.pub, sig, msg)


def cose_detached(signer, prot_map, payload):
    prot = cbor2.dumps(prot_map)
    sig = signer.sign(cbor2.dumps(["Signature1", prot, b"", payload]))
    return cbor2.dumps(cbor2.CBORTag(18, [prot, {}, None, sig]))


def cose_attached(signer, prot_map, unprot, payload):
    prot = cbor2.dumps(prot_map)
    sig = signer.sign(cbor2.dumps(["Signature1", prot, b"", payload]))
    return cbor2.dumps(cbor2.CBORTag(18, [prot, unprot, payload, sig]))


def emsg(message):
    body = (b"\x00\x00\x00\x00" + EMSG_SCHEME + b"\x00" + b"fseg\x00"
            + struct.pack(">IIII", 90000, 0, 90000, 1) + message)
    return struct.pack(">I4s", 8 + len(body), b"emsg") + body


def segment_claim(seq, h, stream_id="urn:uuid:line-a-e6b"):
    return cbor2.dumps({
        "claim_generator_info": [{"name": "line-a-e6b"}],
        "assertions": {
            "c2pa.hash.bmff.v3": {"alg": "sha256", "hash": h,
                                  "exclusions": [{"xpath": "/uuid"}]},
            "c2pa.livevideo.segment": {"sequenceNumber": seq,
                                       "streamId": stream_id,
                                       "continuityMethod": "c2pa.manifestId"},
        }})


class Stream:
    """One method applied to one stream; produces per-segment provenance."""

    def __init__(self, signer, method, stream_id="urn:uuid:line-a-e6b",
                 validity_s=86400):
        self.s = signer
        self.method = method
        self.stream_id = stream_id
        self.manifest_id = "urn:c2pa:" + stream_id.split(":")[-1]
        self.validity_s = validity_s
        self.prot_chain = protected_header(signer.alg, signer.chain, "chain")
        self.init_bytes = 0
        if method == "vsi":
            # Session key: same algorithm as the signer, bound by signing the
            # signer's end-entity certificate (signerBinding).
            self.session = Signer(signer.alg)
            binding = cose_detached(self.session,
                                    {1: COSE_ALG[signer.alg]}, signer.chain[0])
            from cryptography.hazmat.primitives import serialization as ser
            if self.session.backend == "liboqs":
                spk = self.session.oqs_pk
            else:
                pk = self.session.pub
                try:
                    spk = pk.public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
                except Exception:  # noqa: BLE001
                    spk = pk.public_bytes(ser.Encoding.DER,
                                          ser.PublicFormat.SubjectPublicKeyInfo)
            claim = cbor2.dumps({"assertions": {"c2pa.session-keys": [{
                "key": spk, "kid": b"session-1", "createdAt": 0,
                "validityPeriod": validity_s, "minSequenceNumber": 0,
                "signerBinding": binding}]}})
            first = cose_detached(signer, self.prot_chain, claim)
            self.init_bytes = len(first) + len(claim) + JUMBF_OVERHEAD
        self.seq = 0

    def segment(self, frag_bytes):
        """frag_bytes: list of fragment bytes in this segment."""
        h = hashlib.sha256()
        for f in frag_bytes:
            h.update(f)
        return self.sign_segment(h.digest())

    def sign_segment(self, digest):
        """Provenance for a segment whose BMFF hash is already computed."""
        if self.method == "manifest":
            claim = segment_claim(self.seq, digest, self.stream_id)
            cose = cose_detached(self.s, self.prot_chain, claim)
            out = {"seq": self.seq, "claim": claim, "cose": cose,
                   "bytes": len(cose) + len(claim) + JUMBF_OVERHEAD}
        else:
            info = cbor2.dumps({"sequenceNumber": self.seq,
                                "bmffHash": {"alg": "sha256", "hash": digest,
                                             "exclusions": [{"xpath": "/emsg"}]},
                                "manifestId": self.manifest_id})
            cose = cose_attached(self.session, {1: COSE_ALG[self.s.alg]},
                                 {4: b"session-1"}, info)
            out = {"seq": self.seq, "cose": cose, "bytes": len(emsg(cose))}
        self.seq += 1
        return out


# --- verification of a manipulated stream ----------------------------------------

def verify_stream(stream, signer, segs, provs, have_init=True, now_s=0,
                  expected_segments=None):
    """Replay (segment bytes, provenance) pairs; return the problems found.

    The verifier knows the stream it is playing (stream_id, and for VSI the
    initial manifest's id), checks every signature, the BMFF hash, that
    sequence numbers advance by one, that each segment belongs to this
    stream, and for VSI that the session key is inside its validity period
    at verification time now_s. It cannot verify a VSI segment without the
    initial manifest that carries the session key. expected_segments models
    an authenticated end or an announced duration; without it, a stream that
    simply stops is indistinguishable from one whose tail was removed.
    """
    expected = 0
    problems = []
    if stream.method == "vsi" and not have_init:
        return [(0, "no session key")]
    if stream.method == "vsi" and now_s > stream.validity_s:
        return [(0, "session key expired")]
    vkey = stream.session if stream.method == "vsi" else signer
    for i, (frags, prov) in enumerate(zip(segs, provs)):
        tag = cbor2.loads(prov["cose"])
        prot, _u, payload, sig = tag.value
        if stream.method == "manifest":
            payload = prov["claim"]
        try:
            vkey.verify(cbor2.dumps(["Signature1", prot, b"", payload]), sig)
        except Exception:  # noqa: BLE001
            problems.append((i, "signature"))
            continue
        m = cbor2.loads(payload)
        if stream.method == "manifest":
            seg = m["assertions"]["c2pa.livevideo.segment"]
            seq, sid = seg["sequenceNumber"], seg["streamId"]
            want = m["assertions"]["c2pa.hash.bmff.v3"]["hash"]
            if sid != stream.stream_id:
                problems.append((i, "foreign stream"))
        else:
            seq, want = m["sequenceNumber"], m["bmffHash"]["hash"]
            if m["manifestId"] != stream.manifest_id:
                problems.append((i, "foreign stream"))
        h = hashlib.sha256()
        for f in frags:
            h.update(f)
        if h.digest() != want:
            problems.append((i, "hash"))
        if seq != expected:
            problems.append((i, "gap" if seq > expected else "order"))
        expected = max(expected, seq + 1)
    if expected_segments is not None and expected < expected_segments:
        problems.append((len(segs), "short"))
    return problems


def manipulations(segs, provs, other_segs, other_provs):
    """Each entry: (segments, provenance, verifier options)."""
    n = len(segs)
    out = {}
    if n < 8:
        return out
    out["drop"] = (segs[:3] + segs[4:], provs[:3] + provs[4:], {})
    sw_s, sw_p = list(segs), list(provs)
    sw_s[4], sw_s[5] = sw_s[5], sw_s[4]
    sw_p[4], sw_p[5] = sw_p[5], sw_p[4]
    out["reorder"] = (sw_s, sw_p, {})
    tr_s = list(segs)
    last = tr_s[6][-1]
    tr_s[6] = tr_s[6][:-1] + [last[:len(last) // 2]]
    out["truncate_within_segment"] = (tr_s, list(provs), {})
    out["replay"] = (segs[:8] + [segs[6]] + segs[8:],
                     provs[:8] + [provs[6]] + provs[8:], {})
    sub_s = list(segs)
    sub_s[2] = segs[1]
    out["substitute"] = (sub_s, list(provs), {})
    # A segment, with its own valid provenance, taken from another stream by
    # the same signer at the same sequence number.
    cs_s, cs_p = list(segs), list(provs)
    cs_s[5], cs_p[5] = other_segs[5], other_provs[5]
    out["cross_stream_replay"] = (cs_s, cs_p, {})
    # Tail removed: the last three segments never arrive.
    out["suffix_removed"] = (segs[:-3], provs[:-3], {})
    out["suffix_removed_with_end"] = (segs[:-3], provs[:-3],
                                      {"expected_segments": n})
    out["missing_init"] = (segs, list(provs), {"have_init": False})
    out["session_key_expired"] = (segs, list(provs), {"now_s": 10 ** 9})
    return out


# --- measurement ----------------------------------------------------------------

def measure(alg, path, label, segment_s, method, reps):
    init, frags = fragments(path)
    fps_frags = [f for f, _ in frags]
    video_bytes = sum(len(f) for f in fps_frags)
    seconds = len(fps_frags)
    signer = Signer(alg)
    row = {"alg": alg, "stream": label, "method": method,
           "segment_s": segment_s, "backend": signer.backend,
           "video_mbps": round(video_bytes * 8 / seconds / 1e6, 3),
           "fragments": seconds}

    if method == "frame":
        frames = [fr for _, frs in frags for fr in frs]
        st = Stream(signer, "manifest")
        hash_t, sign_t, sizes = [], [], []
        for r in range(reps):
            for i, fr in enumerate(frames):
                t0 = time.perf_counter()
                d = hashlib.sha256(fr).digest()
                t1 = time.perf_counter()
                claim = segment_claim(i, d)
                cose = cose_detached(signer, st.prot_chain, claim)
                t2 = time.perf_counter()
                hash_t.append((t1 - t0) * 1000)
                sign_t.append((t2 - t1) * 1000)
                if r == 0:
                    sizes.append(len(cose) + len(claim))
        per_s = len(frames) / seconds
        proc = [a + b for a, b in zip(hash_t, sign_t)]
        row.update({
            "units_per_s": per_s,
            "hash_ms_median": round(statistics.median(hash_t), 4),
            "sign_ms_median": round(statistics.median(sign_t), 4),
            "process_ms_p99": round(sorted(proc)[int(0.99 * len(proc))], 4),
            "cpu_fraction": round(statistics.fmean(proc) * per_s / 1000, 4),
            "latency_after_close_ms": round(statistics.median(proc), 4),
            "prov_bytes_per_unit": round(statistics.median(sizes)),
            "prov_kbps": round(statistics.fmean(sizes) * 8 * per_s / 1000, 1),
        })
    else:
        segs = [fps_frags[i:i + segment_s]
                for i in range(0, seconds - segment_s + 1, segment_s)]
        hash_t, sign_t, last_t, sizes = [], [], [], []
        for r in range(reps):
            st = Stream(signer, method)
            provs = []
            for sg in segs:
                # Fragments are hashed as they arrive; only the last one and
                # the signature fall after the segment closes.
                t0 = time.perf_counter()
                h = hashlib.sha256()
                for f in sg[:-1]:
                    h.update(f)
                t1 = time.perf_counter()
                h.update(sg[-1])
                t2 = time.perf_counter()
                p = st.sign_segment(h.digest())
                t3 = time.perf_counter()
                hash_t.append((t2 - t0) * 1000)
                sign_t.append((t3 - t2) * 1000)
                last_t.append((t2 - t1) * 1000)
                provs.append(p)
            if r == 0:
                sizes = [p["bytes"] for p in provs]
                first_st, first_provs = st, provs
        per_s = 1.0 / segment_s
        proc = [a + b for a, b in zip(hash_t, sign_t)]
        row.update({
            "units_per_s": per_s,
            "segments": len(segs),
            "hash_ms_median": round(statistics.median(hash_t), 4),
            "sign_ms_median": round(statistics.median(sign_t), 4),
            "process_ms_p99": round(sorted(proc)[min(int(0.99 * len(proc)),
                                                     len(proc) - 1)], 4),
            # Every fragment's hash plus building and signing the segment's
            # provenance, as a share of one core in real time.
            "cpu_fraction": round(statistics.fmean(proc) * per_s / 1000, 5),
            "process_ms_median": round(statistics.median(proc), 4),
            "samples": len(proc),
            "latency_after_close_ms": round(statistics.median(
                [a + b for a, b in zip(last_t, sign_t)]), 4),
            # A player can authenticate a segment only once it has all of it.
            "verify_delay_floor_s": segment_s,
            "prov_bytes_per_unit": round(statistics.median(sizes)),
            "init_bytes": first_st.init_bytes,
            "prov_kbps": round(statistics.fmean(sizes) * 8 * per_s / 1000, 2),
        })
        # Robustness of each method against stream manipulation. A second
        # stream by the same signer supplies the cross-stream replay.
        other = Stream(signer, method, stream_id="urn:uuid:line-a-e6b-other")
        if method == "vsi":
            other.session = first_st.session      # same session key: worst case
        other_provs = [other.segment(sg) for sg in segs]
        det = {}
        for name, (ms, mp, opt) in manipulations(segs, first_provs, segs,
                                                 other_provs).items():
            if name == "session_key_expired" and method != "vsi":
                continue
            if name == "missing_init" and method != "vsi":
                continue
            prob = verify_stream(first_st, signer, ms, mp, **opt)
            det[name] = sorted({k for _, k in prob}) or ["undetected"]
        clean = verify_stream(first_st, signer, segs, first_provs,
                              expected_segments=len(segs))
        if clean:
            raise SystemExit(f"{alg} {label} {method}: clean stream fails: {clean}")
        row["detected"] = det
        row["clean_stream_verifies"] = True
    row["prov_share_of_video_pct"] = round(
        100 * row["prov_kbps"] / (row["video_mbps"] * 1000), 3)
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--streams", default=os.path.join(
        os.path.expanduser("~"), "line-a-pi", "streams"))
    ap.add_argument("--long", action="store_true",
                    help="use the *_long.mp4 streams (loop_streams.sh)")
    ap.add_argument("--algs", default=",".join(ALGS))
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    if a.quick:
        a.algs, a.reps = "Ed25519,ML-DSA-65", 1
    core = tel.pin_to_core() if tel else None
    sfx = "_long" if a.long else ""
    streams = [("1080p H.264", os.path.join(a.streams, f"1080p_h264{sfx}.mp4")),
               ("4K HEVC", os.path.join(a.streams, f"4K_hevc{sfx}.mp4"))]
    rows = []
    for alg in a.algs.split(","):
        for label, path in streams:
            rows.append(measure(alg, path, label, 1, "frame", a.reps))
            nfrag = len(fragments(path)[1])
            for seg in [x for x in SEGMENTS if x <= nfrag]:
                for method in ("manifest", "vsi"):
                    r = measure(alg, path, label, seg, method, a.reps)
                    rows.append(r)
            print(f"  {alg} {label} done", flush=True)
    extra = {"pinned_core": core, "liboqs": liboqs_available(),
             "streams": {l: os.path.getsize(p) for l, p in streams},
             "streams_seconds": {l: len(fragments(p)[1]) for l, p in streams}}
    if tel:
        try:
            extra["pi"] = tel.static_env()
        except Exception:  # noqa: BLE001
            pass
    write_json("e6_stream.json", rows, extra_env=extra, notes=[
        "streams from make_stream.sh: fragmented MP4, one fragment per second, "
        "1080p30 H.264 at 12 Mbit/s and 4K30 HEVC at 40 Mbit/s",
        "frame: a COSE signature with x5chain over every encoded access unit "
        "(upper bound, not a C2PA method)",
        "manifest: C2PA 2.5 Section 15.4, a manifest with BMFF hash, live-video "
        "segment assertion and x5chain in every segment",
        "vsi: C2PA 2.5 Section 15.5, chain and session key once, then a "
        "session-key-signed segment-info map in an emsg box per segment; the "
        "session key uses the signer's algorithm",
        "fragments are hashed as they arrive; latency_after_close is hashing "
        "the last fragment plus signing",
        "detected lists what the verifier reports for each manipulation of "
        "the stream; the verifier knows the stream id (and for VSI the initial "
        "manifest id) it is playing",
        "cpu_fraction counts hashing every fragment of a segment and building "
        "and signing its provenance, over one core in real time",
        "streams of make_stream.sh looped by stream copy to the length in "
        "env.streams_seconds",
    ])


if __name__ == "__main__":
    main()
