#!/usr/bin/env python3
"""Print the headline tables from whatever JSON files exist in out/."""

import json
import os
import statistics
import sys

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")


def load(name):
    p = os.path.join(OUT, name)
    return json.load(open(p)) if os.path.exists(p) else None


def med(rows, key):
    return statistics.median(r[key] for r in rows)


def baseline():
    d = load("e1_baseline.json")
    if not d:
        return
    r = d["results"]
    print("\nE1 baseline, classical, as embedded by c2pa-rs")
    print(f"{'alg':9s} {'manifest B':>11s} {'% image':>9s} {'reserve':>8s} "
          f"{'real content':>13s} {'sign ms':>8s}")
    for alg in dict.fromkeys(x["alg"] for x in r):
        s = [x for x in r if x["alg"] == alg]
        print(f"{alg:9s} {med(s,'manifest_bytes'):11.0f} "
              f"{med(s,'manifest_pct_of_image'):8.2f}% {s[0]['reserve_size']:8d} "
              f"{med(s,'manifest_minus_reserve'):13.0f} "
              f"{statistics.median(x['sign']['median_ms'] for x in s):8.2f}")
    print("  medians over images; 'real content' is manifest minus c2pa-rs padding")


def postquantum():
    d = load("e1_postquantum.json")
    if not d:
        return
    r = [x for x in d["results"] if x["chain_depth"] == 3]
    print("\nE1 post-quantum, three-certificate chain")
    print(f"{'alg':11s} {'cose':>5s} {'sig B':>7s} {'chain B':>8s} {'chain %':>8s} "
          f"{'manifest B':>11s} {'% image':>16s} {'liboqs ms':>10s} {'openssl ms':>11s}")
    for alg in dict.fromkeys(x["alg"] for x in r):
        s = [x for x in r if x["alg"] == alg]
        p = sorted(x["manifest_pct_of_image"] for x in s)
        t = s[0].get("sign_ms", {})
        oq = f"{t['liboqs']['median_ms']:10.3f}" if "liboqs" in t else f"{'-':>10s}"
        os_ = f"{t['openssl']['median_ms']:11.3f}" if "openssl" in t else f"{'-':>11s}"
        print(f"{alg:11s} {s[0]['cose_alg_id']:5d} {s[0]['sig_bytes']:7d} "
              f"{s[0]['chain_der_bytes']:8d} {s[0]['chain_share_of_cose_pct']:7.1f}% "
              f"{s[0]['manifest_bytes']:11d} "
              f"{statistics.median(p):6.2f}% ({p[0]:5.2f}-{p[-1]:5.2f}) {oq} {os_}")
    print("  % of image is median over the image set, range in brackets")
    print("  timing is the raw signature over the COSE Sig_structure; report liboqs, name both")


def certref():
    d = load("e1_certref.json")
    if not d:
        return
    r = [x for x in d["results"] if x["chain_depth"] == 3]
    print("\nE1 mitigation, certificate reference, three-certificate chain")
    print(f"{'alg':11s} {'embedded B':>11s} {'referenced B':>13s} {'saving':>8s} {'saving %':>9s}")
    for x in r:
        print(f"{x['alg']:11s} {x['cose_embedded_bytes']:11d} "
              f"{x['cose_referenced_bytes']:13d} {x['saving_bytes']:8d} "
              f"{x['saving_pct']:8.1f}%")


def verify():
    d = load("e1_verify.json")
    if not d:
        return
    print("\nE1 verification, embedded chain against certificate reference")
    print(f"{'alg':11s} {'backend':8s} {'decode':>7s} {'chain':>7s} {'verify':>7s} "
          f"{'embedded':>9s} {'ref warm':>9s} {'ref cold':>9s} {'overhead':>9s}")
    for x in d["results"]:
        print(f"{x['alg']:11s} {x['sig_backend']:8s} "
              f"{x['decode_embedded_ms']['median_ms']:7.4f} "
              f"{x['validate_chain_ms']['median_ms']:7.4f} "
              f"{x['verify_signature_ms']['median_ms']:7.4f} "
              f"{x['total_embedded_ms']:9.4f} {x['total_referenced_warm_ms']:9.4f} "
              f"{x['total_referenced_cold_ms']:9.4f} {x['warm_overhead_ms']:+9.4f}")
    print("  milliseconds; overhead is warm reference minus embedded")
    print("  remote resolution is a network round trip, not measured; add it to the warm column")


def keywrap():
    d = load("e4_keywrap.json")
    if not d:
        return
    print("\nE4, archive key wrapping")
    print(f"{'scheme':16s} {'library':9s} {'wrapped B':>10s} {'vs RSA-2048':>12s} "
          f"{'wrap ms':>9s} {'unwrap ms':>10s}")
    for x in d["results"]:
        print(f"{x['scheme']:16s} {x.get('library','OpenSSL'):9s} {x['wrapped_bytes']:10d} "
              f"{x['wrapped_bytes_vs_rsa2048']:11.2f}x "
              f"{x['wrap']['median_ms']:9.4f} {x['unwrap']['median_ms']:10.4f}")


def env():
    for n in ("e1_baseline.json", "e1_postquantum.json", "e4_keywrap.json"):
        d = load(n)
        if d:
            e = d["env"]
            print(f"\nmeasured on {e['cpu']} / {e['machine']}, "
                  f"crypto features: {', '.join(e['crypto_features']) or 'none reported'}")
            if "sha3" not in e["crypto_features"]:
                print("  no SHA-3 instructions reported; note that liboqs times "
                      "ML-DSA-65 the same on x86_64 and aarch64, so the")
                print("  instruction set has not been the deciding factor in "
                      "these measurements, the library has")
            return


def main():
    if not os.path.isdir(OUT) or not os.listdir(OUT):
        sys.exit("no results in out/; run ./run_all.sh")
    baseline()
    postquantum()
    certref()
    verify()
    keywrap()
    env()
    print()


if __name__ == "__main__":
    main()
