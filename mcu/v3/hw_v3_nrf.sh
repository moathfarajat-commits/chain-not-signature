#!/bin/bash
# v3 energy runs on the nRF52840-DK pair, PPK2 in source mode powering DK1.
#   A  DK1 verifies (nrf_cred_energy_v3, schedule_nrf_v3)
#   B  DK1 sends to DK2 (DK1 ble_tx, DK2 ble_rx; schedule_ble_v3)
#   C  DK1 receives from DK2 (DK1 ble_rx, DK2 ble_tx; schedule_ble_rx_v3)
# DK1 is flashed inside each PPK2 session (--flash-cmd).
cd ~/line-a-experiments/hw-exp
FW=$PWD/firmware; L=logs-v3; mkdir -p $L
DK1=001050276547; DK2=1050298038
DK1COM=/dev/cu.usbmodem0010502765471; DK2COM=/dev/cu.usbmodem0010502980381
log(){ echo "[$(date +%T)] $*"; }
jl(){ JLinkExe -USB $1 -device nRF52840_xxAA -if SWD -speed 4000 -autoconnect 1 -NoGui 1 -CommandFile $2; }
dk1cmd(){ printf "connect\nh\nloadfile $1\nh\nexit\n" > $L/dk1_$(basename $1).jlink; echo "JLinkExe -USB $DK1 -device nRF52840_xxAA -if SWD -speed 4000 -autoconnect 1 -NoGui 1 -CommandFile $L/dk1_$(basename $1).jlink"; }
dk2_load(){ printf "r\nh\nloadfile $1\n$2\nexit\n" > $L/dk2.jlink; jl $DK2 $L/dk2.jlink > $L/dk2_$(basename $1).log 2>&1; grep -E "^O.K.|Error" $L/dk2_$(basename $1).log | tail -1; }
dk2_go(){ printf "r\ng\nexit\n" > $L/dk2go.jlink; jl $DK2 $L/dk2go.jlink > /dev/null 2>&1; }
E(){ python3 energy/ppk2_energy.py --port /dev/cu.usbmodemFDE99AA19FBF2 --board nrf52840 --mode source --mv 3000 "$@"; }
cp -n out-mcu/e12_ble_rx.json out-mcu/e12_ble_rx_v1.json 2>/dev/null

log "A: DK1 verifies"
E --schedule energy/schedule_nrf_v3.json --out out-energy-nrf-v3 \
  --flash-cmd "$(dk1cmd $FW/nrf_cred_energy_v3.hex)" > $L/A_energy.log 2>&1 && log "A ok" || log "A FAILED"
grep -E "flash:|windows found|calib" $L/A_energy.log | head -3

log "B: DK1 sends, DK2 receives"
dk2_load $FW/nrf_ble_rx_v3.hex h
python3 mcu_capture.py ble $DK2COM > $L/B_capture.log 2>&1 & CP=$!
sleep 2; dk2_go; sleep 2
E --schedule energy/schedule_ble_v3.json --out out-energy-ble-v3 \
  --flash-cmd "$(dk1cmd $FW/nrf_ble_tx_v3.hex)" > $L/B_energy.log 2>&1 && log "B ok" || log "B FAILED"
grep -E "flash:|windows found" $L/B_energy.log | head -2
sleep 5; kill $CP 2>/dev/null; wait $CP 2>/dev/null
cp out-mcu/e12_ble_rx.json out-energy-ble-v3/receiver_check.json 2>/dev/null
tail -2 $L/B_capture.log

log "C: DK1 receives (measured), DK2 sends"
dk2_load $FW/nrf_ble_tx_v3.hex h
python3 mcu_capture.py ble $DK1COM > $L/C_capture.log 2>&1 & CP=$!
sleep 2
rm -f $L/C_energy.log; ( for i in $(seq 1 240); do grep -q "Board powered" $L/C_energy.log 2>/dev/null && break; sleep 0.5; done; sleep 1; dk2_go ) & GP=$!
E --schedule energy/schedule_ble_rx_v3.json --out out-energy-blerx-v3 \
  --flash-cmd "$(dk1cmd $FW/nrf_ble_rx_v3.hex)" > $L/C_energy.log 2>&1 && log "C ok" || log "C FAILED"
wait $GP
grep -E "flash:|windows found" $L/C_energy.log | head -2
sleep 5; kill $CP 2>/dev/null; wait $CP 2>/dev/null
cp out-mcu/e12_ble_rx.json out-energy-blerx-v3/receiver_check.json 2>/dev/null
cp out-mcu/e12_ble_rx_v1.json out-mcu/e12_ble_rx.json 2>/dev/null
tail -2 $L/C_capture.log
log NRF_V3_DONE
