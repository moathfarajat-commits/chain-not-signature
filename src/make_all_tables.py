#!/usr/bin/env python3
"""Regenerate every table and numbers.tex from out/ and the platform folders.

    cp -r out-reference/* out/ && cp out-o3new/*.json out/
    LINEA_PI_IN=out-pi-v2 python3 src/make_all_tables.py

Three generators write manuscript/tables/, in this order: make_tables.py (the
base tables), make_tables_new.py (the algorithm, composite and mixed-chain
tables) and make_tables_v2.py (the four carriage forms, PS256, the corpus, the
stream, the validation matrix, the supplement intervals and numbers.tex).
Where two write the same file, the later one wins. Two functions of
make_tables.py read an older output layout and are skipped; make_tables_v2.py
writes their tables.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import make_tables as a            # noqa: E402
import make_tables_new as b        # noqa: E402
import make_tables_v2 as c         # noqa: E402

if os.environ.get("TABDIR"):
    a.TAB = b.TAB = c.TAB = os.environ["TABDIR"]

OLD = ["tab_platforms", "tab_baseline", "tab_pq", "tab_certref", "tab_verify",
       "tab_keywrap", "tab_backends", "tab_algsweep", "tab_chaindepth",
       "tab_hash", "tab_timestamp"]          # tab_cache, tab_carriage: superseded
NEW = ["tab_impls", "tab_buildeffect", "tab_prodchains", "tab_mixedchain",
       "tab_archive_model", "tab_archive_batch", "tab_archive_projection",
       "tab_scale", "tab_video", "tab_edge", "tab_mcu", "tab_mcu_cost",
       "tab_rewrap_cold"]                    # tab_c2parust: superseded by tab_libsize

failed = []
for mod, names in ((a, OLD), (b, NEW)):
    for n in names:
        try:
            getattr(mod, n)()
        except Exception as e:                # report, carry on, fail at the end
            failed.append(f"{mod.__name__}.{n}: {type(e).__name__}: {e}")
c.main()
if failed:
    sys.exit("failed:\n  " + "\n  ".join(failed))
