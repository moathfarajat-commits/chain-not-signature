cmake_minimum_required(VERSION 3.13)
include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)
project(linea_pico C CXX ASM)
set(CMAKE_C_STANDARD 11)
pico_sdk_init()

set(LIB $ENV{LINEA_LIBS})
set(PQ ${LIB}/PQClean)
set(MCU ${CMAKE_CURRENT_SOURCE_DIR}/..)
file(GLOB D44 ${PQ}/crypto_sign/ml-dsa-44/clean/*.c)
file(GLOB D65 ${PQ}/crypto_sign/ml-dsa-65/clean/*.c)
file(GLOB D87 ${PQ}/crypto_sign/ml-dsa-87/clean/*.c)
set(SRCS plat_pico.c ${MCU}/common/credential.c ${MCU}/common/crypto_backend.c
  ${D44} ${D65} ${D87} ${PQ}/common/fips202.c ${PQ}/common/sha2.c
  ${LIB}/Monocypher/src/monocypher.c ${LIB}/Monocypher/src/optional/monocypher-ed25519.c
  ${LIB}/micro-ecc/uECC.c)

foreach(T linea_pico linea_pico_energy)
  add_executable(${T} ${SRCS})
  target_include_directories(${T} PRIVATE ${MCU}/common ${MCU}/vec ${MCU}/energy
    ${PQ}/common ${LIB}/Monocypher/src ${LIB}/Monocypher/src/optional ${LIB}/micro-ecc)
  target_compile_options(${T} PRIVATE -O3)
  target_compile_definitions(${T} PRIVATE USE_PQCLEAN_NAMES uECC_SUPPORTS_secp160r1=0
    uECC_SUPPORTS_secp192r1=0 uECC_SUPPORTS_secp224r1=0 uECC_SUPPORTS_secp256k1=0
    PICO_STDIO_USB_CONNECT_WAIT_TIMEOUT_MS=0)
  target_link_libraries(${T} pico_stdlib pico_multicore pico_rand hardware_clocks)
  pico_enable_stdio_usb(${T} 1)
  pico_enable_stdio_uart(${T} 0)
  pico_add_extra_outputs(${T})
endforeach()
target_compile_definitions(linea_pico_energy PRIVATE ENERGY)
