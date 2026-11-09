# DK2: connects to DK1, sets the link up (2M PHY, 251-byte data length,
# 247-byte MTU, 15 ms interval), subscribes, and checks every manifest that
# arrives byte for byte against the same vectors; one JSON line per manifest
# on the J-Link VCOM (115200 baud).
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(linea_ble_rx)
set(MCU ${CMAKE_CURRENT_SOURCE_DIR}/../..)
target_sources(app PRIVATE src/main.c)
target_include_directories(app PRIVATE ${MCU}/vec ${MCU}/energy ${MCU}/nrf/common)
