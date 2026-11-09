L = ~/pico
PQ = $(L)/PQClean
SRC = plat_host.c ../common/credential.c ../common/crypto_backend.c \
  $(wildcard $(PQ)/crypto_sign/ml-dsa-44/clean/*.c) \
  $(wildcard $(PQ)/crypto_sign/ml-dsa-65/clean/*.c) \
  $(wildcard $(PQ)/crypto_sign/ml-dsa-87/clean/*.c) \
  $(PQ)/common/fips202.c $(PQ)/common/sha2.c \
  $(L)/Monocypher/src/monocypher.c $(L)/Monocypher/src/optional/monocypher-ed25519.c \
  $(L)/micro-ecc/uECC.c
CFLAGS = -O2 -Wall -Wno-unused-function -DUSE_PQCLEAN_NAMES -I../common -I../vec \
  -I$(PQ)/common -I$(L)/Monocypher/src -I$(L)/Monocypher/src/optional -I$(L)/micro-ecc
host_test: $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC)
