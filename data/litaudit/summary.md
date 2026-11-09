# Reporting audit: applied post-quantum timing studies, 2022-2026

Audit date: 2 November 2026. Corpus: 40 papers (audit.csv, audit.bib).

## How the corpus was built
- Sources: arXiv API keyword searches by application area (TLS, QUIC, IoT, embedded, 5G, DNSSEC, VPN/IKEv2, SSH, blockchain, V2X/CAN, PKI, cloud); Europe PMC full-text search for open-access journal papers (Sensors, Entropy, Scientific Reports); web searches for venue papers with open PDFs (NDSS MADWeb, MDPI Cryptography).
- Inclusion: 2022-2026; the paper reports its own timing of a PQ KEM or signature (primitive, handshake or end-to-end) in an applied setting; full text readable.
- Exclusion: primary contribution is a new optimised or hardware implementation; no separable timing (pure simulation or analytic projection); not in English; arXiv-only preprints first posted within 60 days of the audit date (after 3 Sept 2026). Sixteen of 56 screened candidates were dropped (listed below).
- Coding rule: "yes" only when the text states the item explicitly. Evidence is in the notes column. Seven papers with a published version were coded from their arXiv text (coded_from column).
- Venues: 24 papers with a publisher DOI and 16 arXiv preprints (3 accepted at workshops/conferences). Years: 2022 (1), 2023 (3), 2024 (8), 2025 (12), 2026 (16).

## Counts (n = 40)
| Field | Yes | % |
|---|---:|---:|
| 1. Implementation named | 36 | 90.0 |
| 2. Version or commit of the PQ implementation | 17 | 42.5 |
| 3. Compiler/toolchain named | 5 | 12.5 |
| (C compiler for the PQ code) | 3 | 7.5 |
| 4. Flags / build type / optimised-vs-portable stated | 6 | 15.0 |
| (explicit -O level) | 2 | 5.0 |
| 5a. CPU model | 25 | 62.5 |
| 5b. CPU clock | 17 | 42.5 |
| 5. Model and clock both | 12 | 30.0 |
| 6. Iterations / repetitions | 30 | 75.0 |
| 7. Any dispersion (SD, CI, percentiles, IQR, histograms) | 20 | 50.0 |
| 8. Code or data released | 21 | 52.5 |

Statistic used: mean or average only 28 (70.0%); mean plus median or percentiles 8 (20.0%); median or percentiles only 1 (2.5%); none stated 3 (7.5%).

Implementation, version, compiler and flags all reported: 2/40 (Commey et al. 2026, liboqs 0.8.0, GCC 11.4 / Apple Clang 14.0.3, -O3; Liu et al. 2026, liboqs 0.15.0, GCC 11.4, -O2 -mavx2). liboqs was used in 22 papers; 13 gave its version and none gave its CMake build type or optimisation target. With a publisher DOI vs arXiv-only: version 11/24 vs 6/16, compiler 2/24 vs 3/16, flags 4/24 vs 2/16.

## Findings
Almost every paper names the library that produced its numbers, but fewer than half say which version, and only two of the forty give both the compiler and the optimisation level. Hardware is reported more often than the software build, yet only 12 papers give both the CPU model and its clock. Seventy per cent summarise timings with a mean alone, so a reader often cannot tell whether a gap between schemes exceeds the run-to-run spread. Two papers even attribute differences to "compiler level optimizations" (Kudaloor and Aijaz 2026) or call for comparison "under equivalent optimization levels" (Astrizi et al. 2024) without stating their own build, which leaves most applied PQ timing comparisons impossible to reproduce on the build dimension.

## Doubts and limits
- Single coder, no second rater; borderline calls are explained in notes.
- "Flags reported" counts AVX2 builds and optimised-vs-reference backends; the strict -O count is 2.
- The version field refers to the PQ implementation only.
- Purposive sample leaning to open-access and arXiv-visible work; no IEEE Access full texts could be retrieved.
- Seven papers were coded from arXiv text although a publisher version exists.

## Dropped candidates
2404.13544 (AVX-512 ML-KEM implementation); 2607.12504 (no algorithm timing); 2606.15744 (own FPGA accelerator); 2502.02851 (no measurement methodology in arXiv text); 2308.10696 (ns-3 simulation); 2608.05087 (PQ cost only inside simulated latency); 2501.07028 (Chinese-language); 2509.11695 (no timings); 2508.00832 and 2503.12952 (generic desktop benchmarks); 2604.04191 (analytic projection); 2309.03338 (ns-3 NB-IoT simulation); 2609.23902, 2609.27828, 2610.38632, 2610.32356 (recency rule). 2609.23902 (Puch et al.) reports that liboqs 0.12.0 on AArch64 builds an optimised backend for Kyber/Dilithium but only portable reference code for ML-KEM/ML-DSA, and is worth citing separately.
