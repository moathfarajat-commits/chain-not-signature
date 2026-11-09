#!/usr/bin/env python3
"""E1 baseline: classical C2PA manifests on real JPEGs, through c2pa-rs.

Signs every image with each of the seven algorithms the C2PA specification
permits and measures the bytes the manifest adds to the file. These are the
control columns of E1.

Two method points this script encodes:

1. Thumbnails are disabled. The default manifest embeds a generated thumbnail
   of the image, 173 kB on kodim01, which buries the difference between
   signature algorithms entirely.
2. c2pa-rs reserves a fixed block for the signature, certificate chain,
   timestamp and OCSP response, then pads to fill it. An ECDSA P-256 signature
   is 72 bytes while the reservation is near 12 kB, so the measured manifest
   reflects reservation policy, not cryptography. Both are recorded:
   manifest_bytes and manifest_minus_reserve.
"""

import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import time_it, write_json  # noqa: E402

ALGS = ["es256", "es384", "es512", "ps256", "ps384", "ps512", "ed25519"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTS = os.path.join(ROOT, "certs")
IMAGES = os.path.join(ROOT, "images")
SIGNED = os.path.join(ROOT, "out", "signed")

MANIFEST = {
    "claim_generator_info": [{"name": "line-a-e1", "version": "0.1"}],
    "title": "e1-baseline",
    "assertions": [
        {"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created"}]}}
    ],
}


def app11_bytes(path):
    """Bytes of the JPEG APP11 segments, which carry the C2PA manifest store.

    Cross-check on the file-size delta; the two agree when nothing else is
    appended to the file.
    """
    d = open(path, "rb").read()
    i, total, segs = 2, 0, 0
    while i < len(d) - 1:
        if d[i] != 0xFF:
            i += 1
            continue
        m = d[i + 1]
        if m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        if m == 0xDA:
            break
        ln = struct.unpack(">H", d[i + 2:i + 4])[0]
        if m == 0xEB:
            total += ln + 2
            segs += 1
        i += 2 + ln
    return total, segs


def main():
    from c2pa import Builder, C2paSignerInfo, Signer, load_settings

    load_settings(json.dumps({"builder": {"thumbnail": {"enabled": False}}}), "json")
    os.makedirs(SIGNED, exist_ok=True)

    images = sorted(os.path.join(IMAGES, f) for f in os.listdir(IMAGES)
                    if f.endswith(".jpg"))
    if not images:
        sys.exit(f"no .jpg files in {IMAGES}; run ./fetch_images.sh first")

    algs = [a for a in ALGS
            if os.path.exists(os.path.join(CERTS, f"{a}.key"))
            and os.path.exists(os.path.join(CERTS, f"{a}-chain.pem"))]
    missing = set(ALGS) - set(algs)
    if missing:
        print(f"  skipping (no credentials): {', '.join(sorted(missing))}")

    def signer_for(alg):
        info = C2paSignerInfo(
            alg=alg.encode(),
            sign_cert=open(os.path.join(CERTS, f"{alg}-chain.pem"), "rb").read(),
            private_key=open(os.path.join(CERTS, f"{alg}.key"), "rb").read(),
            ta_url=None)
        return Signer.from_info(info)

    results = []
    for alg in algs:
        for src in images:
            name = os.path.basename(src)
            out = os.path.join(SIGNED, f"{alg}-{name}")

            def once():
                s = signer_for(alg)
                b = Builder(MANIFEST)
                if os.path.exists(out):
                    os.remove(out)
                with open(src, "rb") as f, open(out, "wb") as d:
                    b.sign(s, "image/jpeg", f, d)

            once()
            reserve = signer_for(alg).reserve_size()
            timing = time_it(once)

            base = os.path.getsize(src)
            manifest = os.path.getsize(out) - base
            app11, segs = app11_bytes(out)

            results.append({
                "image": name,
                "alg": alg,
                "image_bytes": base,
                "manifest_bytes": manifest,
                "manifest_pct_of_image": round(100 * manifest / base, 3),
                "reserve_size": reserve,
                "manifest_minus_reserve": manifest - reserve,
                "app11_bytes": app11,
                "app11_segments": segs,
                "app11_matches_delta": app11 == manifest,
                "sign": timing,
            })
        print(f"  {alg} done")

    write_json("e1_baseline.json", results, notes=[
        "thumbnails disabled; the default manifest embeds a generated thumbnail",
        "manifest_bytes includes c2pa-rs reserved padding; manifest_minus_reserve does not",
        "signing time covers the whole embed, not the signature alone",
    ])


if __name__ == "__main__":
    main()
