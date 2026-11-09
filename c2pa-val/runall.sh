#!/bin/bash
# Build the library variants and run the validation matrix (about 15 minutes on an M1 Pro).
cd $HOME/line-a-experiments/c2pa-val
./build.sh > build.log 2>&1 || { echo BUILD_FAILED; exit 1; }
./build_p0.sh > build-p0-run.log 2>&1 || echo "P0_BUILD_FAILED (p0 rows skipped)"
rm -rf work
~/line-a-experiments/.venv-o3/bin/python -W ignore run_matrix.py > matrix.log 2>&1
echo RUNALL_DONE >> matrix.log
