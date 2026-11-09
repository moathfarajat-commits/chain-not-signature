# Building the manuscript

```bash
bench/build_paper.sh
```

That script copies the M1 results into `out/` (`out-reference/` overlaid with
the ten-run aggregate in `out-o3new/`), regenerates every table and
`manuscript/tables/numbers.tex` through `src/make_all_tables.py`, redraws the
figures (`src/make_figures.py`, `src/fig_sizeladder.py`), empties `out/` again
and builds `main.pdf` and `supplement.pdf`. The Xeon, Pi and microcontroller
results are read from `out-x86/`, `out-pi-v2/`, `out-mcu-v2/` and `out-mcu/`
directly.

The main text and the supplement refer to each other through `xr`, so each is
built twice; `latexmk -g` forces the second pass.

Requires a TeX distribution. On macOS, MacTeX or the smaller BasicTeX plus
`booktabs`, `array`, `libertine`, `inconsolata`, `newtxmath`, `totpages`, `xr`
and `placeins`. The ACM class, `acmart` v2.21, is included in `manuscript/`.

Never edit anything under `manuscript/tables/`. Those files are generated, and
every number in the prose that comes from a measurement is a macro from
`numbers.tex`. Change the experiment, re-run it, re-run the build, and the
paper follows the data.

`acmart.cls` and `ACM-Reference-Format.bst` are copied into `manuscript/` from
the ACM template so the folder builds on its own; the one here is v2.20, dated
16 August 2026.
