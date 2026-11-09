# Method notes

Post-quantum cost measurement for media pipelines. Everything here runs on a
laptop. Nothing needs the Raspberry Pi or the SESAME node; those add columns to
tables that already exist.

Results are written to `out/` as JSON, one file per experiment, each carrying an
`env` block that records the machine, the CPU, its crypto instructions, and every
library version. That block is what makes a run citable months later.

## Setup on the Mac

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

OpenSSL is needed for the classical certificate chains. macOS ships LibreSSL as
`openssl`, which lacks some of what `setup_certs.sh` uses, so install the real
thing and put it first on the path:

```bash
brew install openssl@3
export PATH="$(brew --prefix openssl@3)/bin:$PATH"
openssl version          # expect OpenSSL 3.x, not LibreSSL
```

## Run

```bash
./run_all.sh
```

First run downloads the Kodak-24 images and builds test certificates, which
takes a couple of minutes. Later runs skip both. Roughly ten minutes end to end.

To re-print the tables without re-measuring:

```bash
python3 src/summarize.py
```

## What each experiment does

| File | Output | Question |
|---|---|---|
| `src/e1_baseline.py` | `e1_baseline.json` | What does a content credential cost today, signed through the real C2PA library on real JPEGs? |
| `src/e1_pq.py` | `e1_postquantum.json` | What does it cost under ML-DSA, per image? |
| `src/e1_certref.py` | `e1_certref.json` | How much is saved by referencing the certificate instead of embedding the chain? |
| `src/e4_wrap.py` | `e4_keywrap.json` | What does post-quantum key wrapping cost an archive, in bytes and in migration time? |

## Three method points that are easy to get wrong

**Thumbnails are off.** The default C2PA manifest embeds a generated thumbnail of
the image: 173 kB on kodim01, larger than the photograph. Leave it on and the
difference between signature algorithms disappears inside it. `e1_baseline.py`
disables it, and the paper has to say so.

**c2pa-rs pads.** The library reserves roughly 12 kB for the signature,
certificate chain, timestamp and OCSP response, then pads the signature box to
fill it. An ECDSA P-256 signature is 72 bytes. So the manifest size you measure
from a file is the library's reservation policy, not the cryptography. Both
numbers are recorded: `manifest_bytes` includes the padding,
`manifest_minus_reserve` does not. Report both.

**The post-quantum manifests are built outside the library.** c2pa-rs 0.90.19
accepts seven signature algorithms, all classical, and the enum is closed. So
`src/pq_cose.py` builds the COSE_Sign1 directly, following RFC 9964 ("ML-DSA for
JOSE and COSE", Standards Track, May 2026): ML-DSA-44 is COSE algorithm -48,
ML-DSA-65 is -49, ML-DSA-87 is -50. The bytes are conformant; the C2PA validator
will not accept them. That gap is itself a finding, and it belongs in the paper
alongside the numbers.

## Install liboqs

Not optional if you care about timings.

```bash
brew install cmake
pip install liboqs-python
python3 -c "import oqs; print(oqs.oqs_version())"   # first import builds it
```

The scripts run without it and skip the liboqs columns, but the OpenSSL numbers
alone would misstate the algorithms. See below.

liboqs also carries SLH-DSA, Falcon and HQC, which `cryptography` does not.

## Why timings are reported through liboqs

OpenSSL's lattice implementations are slow, and slow by different amounts on
different architectures. Measured with `compare_backends.py`, ML-DSA-65 signing:

| | OpenSSL | liboqs |
|---|---|---|
| Xeon 2.10 GHz, x86_64 | 0.834 ms | 0.101 ms |
| Apple M1 Pro, arm64 | 4.539 ms | 0.106 ms |

Same OpenSSL version, 4.0.2, on both machines. Through liboqs the two are within
5%. Through OpenSSL the M1 looks five times slower than a modest server CPU,
which it is not.

So a timing taken through OpenSSL measures the library, not the algorithm, and
the architecture gap it appears to show is an artefact. The experiments record
both and the summary prints both; the paper should report liboqs and name the
comparison.

Second reading of the same table: implementation choice costs more than
algorithm choice. ML-DSA-65 through liboqs signs in 0.10 ms, while RSA-2048
through OpenSSL takes 1.44 ms on the same Mac. Post-quantum signing is not the
slow part.

## Not covered here

HQC needs a liboqs build with HQC enabled. Nothing in `run_all.sh` depends on it.

## Adding the Raspberry Pi

The same folder runs unchanged on the Pi. Copy it across, install the
requirements, run `./run_all.sh`, and the `env` block will distinguish the two
machines automatically.

Before trusting any timing from the Pi, check that it is not thermally throttling:

```bash
vcgencmd measure_temp
vcgencmd get_throttled     # 0x0 means clean
```

Run those during a long signing loop, not at idle.

Also check for SHA-3 instructions on first boot:

```bash
grep -o 'sha3\|sha512\|aes\|sha2' /proc/cpuinfo | sort -u
```

The Cortex-A76 has AES and SHA-2 but not SHA-3; the M1 Pro has SHA-3. That looked
like it would separate the two machines, since Keccak dominates ML-DSA cost. The
liboqs measurements above say otherwise: liboqs signs ML-DSA-65 at the same speed
on x86_64 and aarch64 regardless. Worth recording anyway, and the `env` block does
it for every run, but do not build an argument on it without checking.

## Data that may not be redistributed

`corpus-real/` (on the Mac, not in this archive) holds the 317 production
files the corpus experiment reads, collected from Wikimedia Commons, the
IPTC's media-provenance samples, Cloudflare's examples and public datasets,
under their own licences; several (IPTC, Cloudflare) do not allow
redistribution. The C2PA public test files are a separate corpus in
`public-testfiles/`. The archive ships `out-reference/e1_corpus.json`, which
records chains, algorithms and sizes but no image content, and the script that
produced it. `data/c2pa-trust-list/` is the public C2PA trust list at commit
f58b10a; `data/c2pa-val-signed/` holds the five manifests c2pa-rs wrote for
`e1_libsize`, over Kodak image kodim01.
