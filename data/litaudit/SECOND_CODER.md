# Second coder: instructions

Ten studies drawn at random (seed 35) from the forty in `audit.csv`. Please
code them without looking at `audit.csv`, in `second_coder_sheet.csv`.

For each column write `yes` only if the paper states the item explicitly;
otherwise `no`. Put the sentence or table you relied on in `notes`.

| column | `yes` when the paper states |
|---|---|
| implementation_named | the library or code base that produced its post-quantum timings (e.g. liboqs, PQClean, OpenSSL) |
| version_reported | the version or commit of that implementation |
| compiler_named | the compiler or toolchain (e.g. GCC 11.4, Clang, MSVC) |
| flags_reported | anything about the build: flags, build type (Release), an optimised or portable backend, AVX2 |
| explicit_O_level | an optimisation level such as -O2 or -O3 |
| cpu_model_and_clock | both the CPU model and its clock frequency |
| iterations_reported | how many repetitions each timing is over |
| dispersion_reported | any measure of spread: SD, CI, IQR, percentiles, min/max, histograms |
| code_or_data_released | a link to the code or the data |

Return the sheet; agreement (Cohen's kappa per column) is computed from it
and reported in the supplement.
