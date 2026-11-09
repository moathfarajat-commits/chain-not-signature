# nRF52840-DK: the credential benchmark with ES256, Ed25519 and SHA-256 both
# in software (the same libraries as the Pico and the NUCLEO) and on the
# CryptoCell-310 through PSA; ML-DSA in software only (pqm4 m4f, the same
# objects as the NUCLEO image). -DLINEA_ENERGY=1 builds the marker-pin energy
# image instead of the serial timing image.
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(linea_nrf_cred)

set(MCU ${CMAKE_CURRENT_SOURCE_DIR}/../..)
set(LIBS $ENV{LINEA_LIBS})
set(PQM4 ${LIBS}/pqm4)

target_sources(app PRIVATE
  src/plat_nrf.c
  ${MCU}/common/credential.c
  ${MCU}/common/crypto_backend.c
  ${PQM4}/mupq/common/fips202.c
  ${PQM4}/common/keccakf1600.S
  ${LIBS}/PQClean/common/sha2.c
  ${LIBS}/Monocypher/src/monocypher.c
  ${LIBS}/Monocypher/src/optional/monocypher-ed25519.c
  ${LIBS}/micro-ecc/uECC.c)
target_include_directories(app PRIVATE ${MCU}/common ${MCU}/vec ${MCU}/energy
  ${PQM4}/mupq/common ${LIBS}/PQClean/common ${LIBS}/Monocypher/src
  ${LIBS}/Monocypher/src/optional ${LIBS}/micro-ecc)
target_compile_definitions(app PRIVATE HW_CRYPTO PQM4
  uECC_SUPPORTS_secp160r1=0 uECC_SUPPORTS_secp192r1=0 uECC_SUPPORTS_secp224r1=0
  uECC_SUPPORTS_secp256k1=0)
# Zephyr puts its own optimisation flag on the target; a per-source -O3
# comes after it, matching the -O3 used on the other boards.
get_target_property(APP_SRCS app SOURCES)
set_source_files_properties(${APP_SRCS} TARGET_DIRECTORY app PROPERTIES COMPILE_OPTIONS -O3)
if(LINEA_ENERGY)
  target_compile_definitions(app PRIVATE ENERGY LINEA_SCHEDULE="schedule_nrf.h")
endif()

if(CONFIG_BOARD_NRF52_BSIM)
  # Functional check in BabbleSim (x86 host build): PQClean's portable ML-DSA
  # and PSA on Oberon (bsim.conf), since neither pqm4's assembly nor the
  # CryptoCell exists there.
  foreach(N 44 65 87)
    file(GLOB D${N} ${LIBS}/PQClean/crypto_sign/ml-dsa-${N}/clean/*.c)
    target_sources(app PRIVATE ${D${N}})
  endforeach()
  target_sources(app PRIVATE ${LIBS}/PQClean/common/fips202.c)
  target_compile_definitions(app PRIVATE USE_PQCLEAN_NAMES)
  get_target_property(_s app SOURCES)
  list(REMOVE_ITEM _s ${PQM4}/mupq/common/fips202.c ${PQM4}/common/keccakf1600.S)
  set_property(TARGET app PROPERTY SOURCES ${_s})
else()
  target_compile_definitions(app PRIVATE uECC_PLATFORM=uECC_arm_thumb2)
  # pqm4's three ML-DSA m4f sets, partially linked with their API renamed
  # (built by ../../nucleo/Makefile; same Cortex-M4F hard-float ABI as this
  # image).
  foreach(N 44 65 87)
    target_link_libraries(app PRIVATE ${MCU}/nucleo/build/mldsa${N}.o)
  endforeach()
endif()
