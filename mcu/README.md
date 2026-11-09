# Line A: microcontroller experiments (E9 to E12)

Four experiments on the boards in the lab inventory. All of them use the
same signed manifests as the paper: one real C2PA-style COSE manifest per
algorithm (Ed25519, ES256, ML-DSA-44/65/87) with a three-certificate X.509
chain, in the paper's three carriage forms:

| form  | what travels in the manifest | what the verifier keeps |
|-------|------------------------------|-------------------------|
| full  | the whole chain (x5chain of three) | the root |
| leaf  | the leaf certificate only | intermediate and root |
| thumb | an x5t thumbprint of the leaf | leaf, intermediate and root |

Manifest sizes in bytes (`vec/vectors.h`):

| algorithm | full | leaf | thumb |
|-----------|-----:|-----:|------:|
| Ed25519   |  1,352 |    519 |   113 |
| ES256     |  1,533 |    578 |   113 |
| ML-DSA-44 | 14,702 |  6,541 | 2,471 |
| ML-DSA-65 | 20,178 |  8,959 | 3,360 |
| ML-DSA-87 | 27,370 | 12,235 | 4,678 |

| id  | board | what it measures | firmware |
|-----|-------|------------------|----------|
| E9  | Raspberry Pi Pico (RP2040, M0+) | time, stack and RAM per op; energy (PPK2 source mode) | `linea_pico.uf2`, `linea_pico_energy.uf2` |
| E10 | NUCLEO-L4R5ZI (M4F) | the same at 20 MHz (pqm4 benchmark clock) and 80 MHz; energy at 80 MHz (PPK2 ampere mode) | `linea_nucleo_20mhz.bin`, `linea_nucleo_80mhz.bin`, `linea_nucleo_energy_80mhz.bin` |
| E11 | nRF52840-DK (M4F + CryptoCell-310) | ES256, Ed25519 and SHA-256 in software against the CryptoCell, ML-DSA in software; energy | `nrf_cred.hex`, `nrf_cred_energy.hex` |
| E12 | two nRF52840-DKs over Bluetooth LE | energy and time for DK1 to send each carriage form to DK2 | `nrf_ble_tx.hex` (DK1), `nrf_ble_rx.hex` (DK2) |

Every row of every run reports `"ok"`, and every algorithm ends with a
negative test (one flipped bit in a signature, and one in a received
manifest, must both be rejected). A run with any `"ok": false` is not usable.

This work stays inside the paper's scope: signatures only, no KEM, and
Bluetooth LE rather than Thread, so it does not overlap the HQC hardware study.

## Before you start (Mac)

```
cd ~/line-a-experiments/hw-exp
python3 -m venv .venv-hw && source .venv-hw/bin/activate
pip install pyserial numpy ppk2-api==0.9.2
```

With several boards plugged in there are several `/dev/cu.usbmodem*` ports.
Plug one board at a time and run `ls /dev/cu.usbmodem*` to see which port is
which, then pass that port to the scripts.

Flashing needs no tools: every board shows up as a USB drive.

* Pico: hold BOOTSEL while plugging in, drop the `.uf2` on `RPI-RP2`.
* NUCLEO: drop the `.bin` on `NOD_L4R5ZI`.
* nRF52840-DK: drop the `.hex` on `JLINK`.

## E9: Pico, timing (about 10 minutes)

1. Flash `firmware/linea_pico.uf2`. Leave the Pico on USB.
2. `python3 mcu_capture.py pico /dev/cu.usbmodemXXXX`
3. The script stops at `{"op":"done"}` and writes `out-mcu/e9_pico.json`.

This replaces the Pico package in `extra-fix/pico/`: the new firmware adds the
three carriage forms and the RAM accounting.

## E10: NUCLEO-L4R5ZI, timing (two runs, about 10 minutes each)

1. Flash `firmware/linea_nucleo_20mhz.bin`.
2. `python3 mcu_capture.py nucleo /dev/cu.usbmodemXXXX`, then press the black
   RESET button. Output: `out-mcu/e10_nucleo_20mhz.json`.
3. Repeat with `linea_nucleo_80mhz.bin` (gives `e10_nucleo_80mhz.json`).

## E11: nRF52840-DK, timing (about 10 minutes)

Use the DK whose SB40 is intact (or put a jumper on P22), so it powers normally.

1. Flash `firmware/nrf_cred.hex`.
2. `python3 mcu_capture.py nrf /dev/cu.usbmodemXXXX`, then press RESET.
   Output: `out-mcu/e11_nrf52840.json`.

The env line says whether the CryptoCell took Ed25519 (`"hw_ed25519"`). If it
is false, only ES256 and SHA-256 get a hardware row, which is still the main
comparison.

## Energy runs with the PPK2

The energy images do the same operations as the timing images, but between
marker-pin pulses, with idle gaps, and with nothing on the serial port. The
PPK2 records current and the marker together, and `ppk2_energy.py` integrates
each window. It refuses to run if the PPK2's calibration does not load (a known
ppk2-api fault); unplug and replug the PPK2 and try again.

The logic port on the PPK2 has its own VCC and GND pins: connect them to the
board's 3V3 (or VDD) and GND in every set-up below, and the marker to **D0**.

### E9 energy: Pico (source mode, PPK2 powers the Pico)

Wiring, with the Pico **unplugged from USB**:

| PPK2 | Pico |
|------|------|
| VOUT | VSYS (pin 39) |
| GND (power) | GND (pin 38) |
| logic D0 | GP16 (pin 21) |
| logic VCC | 3V3(OUT) (pin 36) |
| logic GND | GND (pin 23) |

Flash `linea_pico_energy.uf2` first (over USB), unplug USB, wire, then:

```
python3 energy/ppk2_energy.py --board pico --mode source --mv 3300 --out out-energy-pico
```

### E10 energy: NUCLEO (ampere mode)

Flash `linea_nucleo_energy_80mhz.bin`. Remove jumper **JP5 (IDD)**. Connect
PPK2 VIN to the JP5 pin on the 3V3 side and VOUT to the pin on the MCU side
(if the PPK2 shows almost no current, swap them). Marker: D0 to **A0 (PA3)**
on CN9; logic VCC to a 3V3 pin, logic GND to GND. Keep the NUCLEO on USB.

```
python3 energy/ppk2_energy.py --board nucleo --mode ampere --mv 3300 --out out-energy-nucleo
```

Press RESET when the script asks. Put JP5 back afterwards.

### E11 energy: nRF52840-DK (ampere mode)

On the DK with SB40 cut: PPK2 VIN to P22's **VDD** pin, VOUT to **VDD_nRF**.
Marker: D0 to **P0.03**; logic VCC to VDD, logic GND to GND. Power switch on,
SW6 on DEFAULT. Flash `nrf_cred_energy.hex`, then:

```
python3 energy/ppk2_energy.py --board nrf52840 --mode ampere --mv 3000 \
        --schedule energy/schedule_nrf.json --out out-energy-nrf
```

### E12: Bluetooth LE transfer (two DKs)

* DK1 (measured, SB40 cut, wired to the PPK2 as for E11): flash `nrf_ble_tx.hex`.
* DK2 (normal power, USB to the Mac): flash `nrf_ble_rx.hex`.

Two terminals:

```
# terminal 1: DK2's report of what arrived
python3 mcu_capture.py ble /dev/cu.usbmodemDK2
# terminal 2: DK1's energy
python3 energy/ppk2_energy.py --board nrf52840 --mode ampere --mv 3000 \
        --schedule energy/schedule_ble.json --out out-energy-ble
```

Press DK2's RESET, then DK1's. DK2 sets the link to 2M PHY, 251-byte data
length, 247-byte ATT MTU and a 15 ms interval, then checks every manifest byte
for byte. Expect 450 manifests, all `ok`. Keep the two DKs about a metre apart
and away from Wi-Fi access points.

## Send back

`out-mcu/` and the four `out-energy-*` folders.

## What was checked here before release

* Host build of the shared core: all 35 rows ok, all 5 negative tests pass,
  clean under AddressSanitizer and UBSan.
* NUCLEO objects run under QEMU (mps2-an386, Cortex-M4F): all rows ok, all
  negative tests pass. This run caught a link-order fault (PQClean's
  `fips202.c` linked in place of pqm4's, which leaks heap in pqm4's ML-DSA and
  would have crashed the board); the Makefile now names every source
  explicitly and refuses an image with the wrong one.
* nRF52840 BLE pair in BabbleSim: 450 of 450 manifests arrived intact.
* nRF52840 credential app in BabbleSim with software PSA: the PSA path signs
  and verifies, and accepts certificates signed by micro-ecc (so the key
  formats agree). The CryptoCell itself cannot be simulated.
* The PPK2 analysis was checked on a synthetic stream with known current.

Not checkable without the boards: real timings, the CryptoCell, and the PPK2
calibration.

## Rebuilding

`src/` holds everything. `host/` (gcc), `pico/` (pico-sdk 2.1.1), `nucleo/`
(arm-none-eabi-gcc 13.2, pqm4 at 5e5cc76; `make` and `make qemu-test`),
`nrf/` (nRF Connect SDK 3.1.1, `west build -b nrf52840dk/nrf52840`).
`vec/gen_vectors.py` regenerates the manifests, `energy/gen_schedule.py` the
schedule headers.
