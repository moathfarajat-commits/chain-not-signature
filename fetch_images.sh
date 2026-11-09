#!/usr/bin/env bash
# Kodak-24, the standard image-processing test set, converted to JPEG quality 90.
set -e
cd "$(dirname "$0")"
mkdir -p images/png images
for i in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24; do
  if [ ! -f "images/png/kodim$i.png" ]; then
    curl -sS -o "images/png/kodim$i.png" "https://r0k.us/graphics/kodak/kodak/kodim$i.png"
    printf '.'
  fi
done
echo
python3 - <<'PY'
from PIL import Image
import glob, os
n = 0
for p in sorted(glob.glob("images/png/*.png")):
    out = "images/" + os.path.basename(p).replace(".png", ".jpg")
    if not os.path.exists(out):
        Image.open(p).save(out, quality=90)
    n += 1
sizes = [os.path.getsize("images/" + os.path.basename(p).replace(".png", ".jpg"))
         for p in sorted(glob.glob("images/png/*.png"))]
print(f"{n} JPEGs at quality 90, {min(sizes)}-{max(sizes)} bytes")
PY
