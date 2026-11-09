# The Chain, Not the Signature: code and data

Measurement code, firmware, raw results and table generators for

> Mua'ad Alfarajat. *The Chain, Not the Signature: Cost and Soundness of
> Post-Quantum Content Credentials.* Manuscript, 2026.

The paper measures what C2PA content credentials cost when they move to
post-quantum signatures (ML-DSA, SLH-DSA, Falcon and composites), and finds that
the certificate chain, not the manifest signature, sets the cost. Every number
in the paper is generated from the JSON files in this repository.

## Layout

| Path | What it holds |
|---|---|
| `src/` | The experiments (`e1_*.py`, `e4_wrap.py`, `e8_scale.py`), the RFC 9964 COSE builder (`pq_cose.py`), post-quantum certificates and RFC 3161 tokens (`pq_certs.py`, `pq_tst.py`), and the table and figure generators (`make_all_tables.py`, `make_figures.py`, `fig_sizeladder.py`) |
| `pi5/` | Raspberry Pi 5 experiments: video signing (`e6_video.py`, `e6_stream.py`), the edge verifier (`e7_edge.py`) and rail-power telemetry |
| `mcu/` | Firmware and energy harness for the Raspberry Pi Pico, the NUCLEO-L4R5ZI and the nRF52840 (Bluetooth LE send and receive), with the Nordic PPK2 capture script |
| `c2pa-val/` | The validation harness that signs and validates every case through `c2pa-rs` |
| `patches/` | The two patches that add ML-DSA signing (RFC 9964) and ML-DSA path validation to `c2pa-rs` |
| `bench/` | C benchmarks through liboqs, PQClean and OpenSSL, and `build_paper.sh` |
| `x86/` | Scripts for the Xeon VM runs |
| `out-*/` | Raw results, one JSON file per experiment, each with an `env` block recording the machine, CPU features and library versions. `out-runs-m1/` and `out-x86-runs/` hold every independent run; `out-o3new/`, `out-x86/`, `out-pi-v2/` and `out-mcu-v3/` the aggregates the paper reports |
| `data/` | The C2PA trust-list snapshot, the corpus inventory, manifests written by `c2pa-rs`, the vectors for the two specification departures, and the literature-audit coding |
| `manuscript/` | LaTeX source of the paper and supplement; `tables/` and `figures/` are generated |
| `docs/NOTES.md` | Method notes: thumbnails, padding, why timings go through liboqs, checks for the Pi |

## Reproducing the tables and figures

Everything the paper reports can be regenerated from the stored results
without re-measuring:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
bench/build_paper.sh          # tables, numbers.tex, figures, then the PDFs
```

`build_paper.sh` needs a TeX distribution; `BUILD.md` lists the packages. To
regenerate the tables alone, run `python3 src/make_all_tables.py`.

## Re-measuring

```bash
./run_all.sh                  # the laptop experiments, results in out/
```

The first run downloads the Kodak-24 images (`fetch_images.sh`) and creates
test certificates (`setup_certs.sh`). Timings need liboqs (`pip install
liboqs-python`); `docs/NOTES.md` explains why. The Pi, Xeon and
microcontroller experiments have their own scripts in `pi5/`, `x86/` and
`mcu/`, and `c2pa-val/README.md` explains how to build the patched library and
run the validation matrix.

The measurements in the paper were taken on an Apple M1 Pro (ten runs), a
two-vCPU Intel Xeon VM (ten runs), a Raspberry Pi 5 (five runs), and the three
microcontroller boards.

## What is not here

* The production-signed files read by the corpus experiment. Several of their
  sources do not allow redistribution. `data/corpus/inventory.csv` gives each
  file's source URL, licence and SHA-256, and `out-reference/e1_corpus.json`
  records the chains, algorithms and sizes read from them.
* The Kodak images, which `fetch_images.sh` downloads.
* For the first specification departure (a time-stamping certificate accepted
  as a claim signer), the signed file and its leaf certificate, until the
  library is fixed. Its status codes are included. See
  `data/c2pa-departures/README.md`. The second departure is
  [c2pa-rs issue #3005](https://github.com/contentauth/c2pa-rs/issues/3005).
* Private keys. Every certificate in the repository is a throwaway test
  certificate.

## Licence

Code (everything under `src/`, `pi5/`, `mcu/`, `c2pa-val/`, `patches/`,
`bench/`, `x86/` and the shell scripts) is released under the MIT licence
(`LICENSE`). Results, the corpus inventory and the audit coding are released
under CC BY 4.0 (`LICENSE-DATA`). The C2PA trust-list snapshot in
`data/c2pa-trust-list/` is redistributed as published by the C2PA. The ACM
class and bibliography style in `manuscript/` keep their own licences.

## Citation

See `CITATION.cff`. Please cite the paper and the archived release.
