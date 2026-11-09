# DK1, the measured side: sends each carriage form of each manifest to DK2 as
# GATT notifications, inside marker windows timed by schedule_ble.json.
# No UART (it would add to the measured current); DK2 reports what arrived.
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(linea_ble_tx)
set(MCU ${CMAKE_CURRENT_SOURCE_DIR}/../..)
target_sources(app PRIVATE src/main.c)
target_include_directories(app PRIVATE ${MCU}/vec ${MCU}/energy ${MCU}/nrf/common)
