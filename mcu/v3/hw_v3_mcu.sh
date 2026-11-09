#!/bin/zsh
# 35n energy runs on the Pico (source mode) and the NUCLEO (ampere mode).
#   hw_v3_mcu.sh pico_flash   Pico on USB: reboot to BOOTSEL, copy the energy image
#   hw_v3_mcu.sh pico_run     Pico USB unplugged, powered by the PPK2
#   hw_v3_mcu.sh nucleo_run   NUCLEO on USB, JP5 off, PPK2 across JP5; flashed in-session
cd ~/line-a-experiments/hw-exp
FW=$PWD/firmware; L=logs-v3; mkdir -p $L
PPK=/dev/cu.usbmodemFDE99AA19FBF2
log(){ echo "[$(date +%H:%M:%S)] $*"; }
case $1 in
pico_flash)
  P=$(ls /dev/cu.usbmodem2* 2>/dev/null | grep -v FDE | head -1)
  [ -n "$P" ] && python3 -c "import serial; s=serial.Serial('$P',1200); s.close()" 2>/dev/null
  for i in {1..30}; do [ -d /Volumes/RPI-RP2 ] && break; sleep 1; done
  [ -d /Volumes/RPI-RP2 ] || { log "pico: no BOOTSEL volume (hold BOOTSEL while plugging in)"; exit 1; }
  cp $FW/linea_pico_energy_v3.uf2 /Volumes/RPI-RP2/ && log "pico flashed" ;;
pico_run)
  PYTHONUNBUFFERED=1 python3 energy/ppk2_energy.py --port $PPK --board pico --mode source --mv 3300 \
    --schedule energy/schedule_v3.json --out out-energy-pico-v3 > $L/pico_energy.log 2>&1 \
    && log "pico energy ok" || log "pico energy FAILED"
  grep -E "windows found|manifest_chain" $L/pico_energy.log | head -8 ;;
nucleo_run)
  OCD="openocd -f interface/stlink.cfg -f target/stm32l4x.cfg -c 'reset_config srst_only srst_nogate connect_assert_srst' -c 'program $FW/linea_nucleo_energy_80mhz_v3.bin 0x08000000 verify exit' 2>&1 | sed 's/\\*\\* Programming Finished \\*\\*/O.K./'"
  PYTHONUNBUFFERED=1 python3 energy/ppk2_energy.py --port $PPK --board nucleo --mode ampere --mv 3300 \
    --schedule energy/schedule_v3.json --out out-energy-nucleo-v3 --flash-cmd "$OCD" \
    > $L/nucleo_energy.log 2>&1 && log "nucleo energy ok" || log "nucleo energy FAILED"
  grep -E "flash:|windows found|manifest_chain" $L/nucleo_energy.log | head -8 ;;
esac
