#!/bin/bash
# Regenerate tables and figures from the measured data and build both PDFs.
#   bench/build_paper.sh            (from the repository root)
# M1 results: out-reference/ (corpus, profile, validation, libsize, archive,
# key wrap, implementations) overlaid with out-o3new/ (the ten-run suite).
# Xeon: out-x86/. Pi 5: out-pi-v2/. Microcontrollers: out-mcu-v2/, out-mcu/.
set -eu
cd "$(dirname "$0")/.."
find out -mindepth 1 ! -name README.md -exec rm -rf {} +
cp -r out-reference/* out/
cp out-o3new/*.json out/
LINEA_PI_IN="$PWD/out-pi-v2" python3 src/make_all_tables.py
python3 src/make_figures.py
python3 src/fig_sizeladder.py
python3 src/fig_corpus_growth.py
find out -mindepth 1 ! -name README.md -exec rm -rf {} +
cd manuscript
latexmk -pdf -interaction=nonstopmode main.tex
latexmk -pdf -interaction=nonstopmode supplement.tex
latexmk -g -pdf -interaction=nonstopmode main.tex      # xr: supplement labels
latexmk -g -pdf -interaction=nonstopmode supplement.tex
