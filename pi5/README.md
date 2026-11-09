# Line A on the Raspberry Pi 5

Signatures only. The KEM work on this board belongs to the HQC hardware paper,
and nothing here measures a KEM (`run_pi.sh` sets `LINEA_SIGN_ONLY=1`).
Everything installs under `~/line-a-pi`, so the HQC paper's H6 builds on the
same card are left alone.

## What runs

| Script | Measures |
|---|---|
| `src/e1_pq.py`, `src/e1_verify.py`, `src/e1_hash.py`, `compare_backends.py` | the Pi row of the platform ladder, same scripts as the M1 |
| `src/e8_scale.py` | verification throughput across the four cores, cached and uncached, as on the M1 |
| `pi5/e7_edge.py` | end-to-end manifest verification with the trust store on the SD card: cold (page cache evicted), warm, and embedded chains |
| `pi5/e6_video.py` | signing a 30 fps stream at 1080p and 4K, per frame and per 1-second segment: sustainable frame rate, late frames, provenance bitrate, and on the long runs temperature, clock, throttle flags and PMIC rail power |

## Steps

From the Mac, copy the package to the Pi (replace the address):

    scp ~/line-a-experiments/line-a-pi5-harness.tar.gz <user>@<pi-address>:~

On the Pi:

    tar xzf line-a-pi5-harness.tar.gz
    bash line-a-pi5/pi5/setup_pi.sh          # about 15 minutes, once
    bash line-a-pi5/pi5/run_pi.sh --quick     # about 3 minutes

Send `line-a-pi5/out-pi-quick/` back before the full run, so the quick
results can be checked first.

For the full run (about three and a half hours), reboot, let the board sit idle for five
minutes, then:

    echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
    cd line-a-pi5
    nohup bash pi5/run_pi.sh > full.log 2>&1 &

`nohup` keeps it running if the SSH session drops. Leave the case closed and
the fan on, and do not use the Pi while it runs. Results land in
`line-a-pi5/out-pi/`.

The full run refuses to start if the board is already throttling or the
governor is not `performance`, and says why.
