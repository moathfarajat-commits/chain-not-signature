# NUCLEO-L4R5ZI images: timing at 20 MHz and 80 MHz, energy at 80 MHz.
# pqm4's three ML-DSA m4f sets all export crypto_sign_* and share internal
# names (poly_*, ntt, ...), so each set is partially linked on its own, every
# symbol but its API is made local, and the API is renamed mldsaNN_*.
PQM4 ?= ~/pico/pqm4
LIBS ?= ~/pico
MCU := ..
CROSS := arm-none-eabi-
CC := $(CROSS)gcc
LD := $(CROSS)ld
OBJCOPY := $(CROSS)objcopy
OPENCM3 := $(PQM4)/libopencm3
PQM4_COMMIT := $(shell git -C $(PQM4) rev-parse --short HEAD 2>/dev/null || echo unknown)

ARCH := -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16
CPPFLAGS := -DSTM32L4 -DSTM32L4R5ZI -DPQM4 -I$(OPENCM3)/include -I$(PQM4)/mupq/common \
  -I$(MCU)/common -I$(MCU)/vec -I$(MCU)/energy -I$(LIBS)/PQClean/common \
  -I$(LIBS)/Monocypher/src -I$(LIBS)/Monocypher/src/optional -I$(LIBS)/micro-ecc \
  -DuECC_SUPPORTS_secp160r1=0 -DuECC_SUPPORTS_secp192r1=0 -DuECC_SUPPORTS_secp224r1=0 \
  -DuECC_SUPPORTS_secp256k1=0 -DuECC_PLATFORM=uECC_arm_thumb2 -DPQM4_COMMIT='"$(PQM4_COMMIT)"'
CFLAGS := $(ARCH) -O3 -g -std=gnu99 -Wall -Wno-unused-function -ffunction-sections -fdata-sections
LDFLAGS := $(ARCH) --specs=nosys.specs -nostartfiles -ffreestanding -Wl,--gc-sections \
  -Wl,--wrap=_sbrk -Wl,--wrap=_close -Wl,--wrap=_isatty -Wl,--wrap=_kill -Wl,--wrap=_lseek \
  -Wl,--wrap=_read -Wl,--wrap=_write -Wl,--wrap=_fstat -Wl,--wrap=_getpid \
  -T$(PQM4)/ldscripts/nucleo-l4r5zi.ld -L$(OPENCM3)/lib -Wl,-Map=$(basename $@).map


B := build
all: $(B)/linea_nucleo_20mhz.bin $(B)/linea_nucleo_80mhz.bin $(B)/linea_nucleo_energy_80mhz.bin

# --- the three ML-DSA sets
define MLDSA
$(B)/mldsa$(1)/%.o: $(PQM4)/crypto_sign/ml-dsa-$(1)/m4f/%.c
	@mkdir -p $$(@D)
	$(CC) $(CPPFLAGS) -I$(PQM4)/crypto_sign/ml-dsa-$(1)/m4f $(CFLAGS) -c $$< -o $$@
$(B)/mldsa$(1)/%.o: $(PQM4)/crypto_sign/ml-dsa-$(1)/m4f/%.S
	@mkdir -p $$(@D)
	$(CC) $(CPPFLAGS) -I$(PQM4)/crypto_sign/ml-dsa-$(1)/m4f $(ARCH) -c $$< -o $$@
$(B)/mldsa$(1)/%.o: $(PQM4)/crypto_sign/ml-dsa-$(1)/m4f/%.s
	@mkdir -p $$(@D)
	$(CC) $(CPPFLAGS) -I$(PQM4)/crypto_sign/ml-dsa-$(1)/m4f $(ARCH) -c $$< -o $$@
MLDSA$(1)_OBJS := $$(patsubst $(PQM4)/crypto_sign/ml-dsa-$(1)/m4f/%,$(B)/mldsa$(1)/%.o,$$(basename $$(wildcard $(PQM4)/crypto_sign/ml-dsa-$(1)/m4f/*.c $(PQM4)/crypto_sign/ml-dsa-$(1)/m4f/*.S $(PQM4)/crypto_sign/ml-dsa-$(1)/m4f/*.s)))
$(B)/mldsa$(1).o: $$(MLDSA$(1)_OBJS)
	$(LD) -r -o $(B)/mldsa$(1)_r.o $$^
	$(OBJCOPY) --redefine-sym crypto_sign_keypair=mldsa$(1)_keypair \
	  --redefine-sym crypto_sign_signature_ctx=mldsa$(1)_signature_ctx \
	  --redefine-sym crypto_sign_verify_ctx=mldsa$(1)_verify_ctx \
	  $(B)/mldsa$(1)_r.o $(B)/mldsa$(1)_n.o
	$(OBJCOPY) --keep-global-symbol=mldsa$(1)_keypair --keep-global-symbol=mldsa$(1)_signature_ctx \
	  --keep-global-symbol=mldsa$(1)_verify_ctx $(B)/mldsa$(1)_n.o $$@
endef
$(eval $(call MLDSA,44))
$(eval $(call MLDSA,65))
$(eval $(call MLDSA,87))

# --- shared code (one copy each). Explicit paths, no vpath: PQClean and
# pqm4 both ship a fips202.c, and PQClean's (heap-allocated contexts) must
# not stand in for pqm4's, whose ML-DSA code never releases a context.
define SHARED
$(B)/shared/$(1).o: $(2)
	@mkdir -p $$(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $$< -o $$@
SHARED_OBJS += $(B)/shared/$(1).o
endef
SHARED_OBJS :=
$(eval $(call SHARED,fips202,$(PQM4)/mupq/common/fips202.c))
$(eval $(call SHARED,hal-opencm3,$(PQM4)/common/hal-opencm3.c))
$(eval $(call SHARED,sha2,$(LIBS)/PQClean/common/sha2.c))
$(eval $(call SHARED,monocypher,$(LIBS)/Monocypher/src/monocypher.c))
$(eval $(call SHARED,monocypher-ed25519,$(LIBS)/Monocypher/src/optional/monocypher-ed25519.c))
$(eval $(call SHARED,uECC,$(LIBS)/micro-ecc/uECC.c))
$(eval $(call SHARED,crypto_backend,$(MCU)/common/crypto_backend.c))
SHARED_OBJS += $(B)/shared/keccakf1600.o
$(B)/shared/keccakf1600.o: $(PQM4)/common/keccakf1600.S
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ARCH) -c $< -o $@

# --- per image: the platform file and the credential core
$(B)/%/plat_nucleo.o $(B)/%/credential.o: CFG = $(if $(findstring energy,$*),-DENERGY) -DCLOCK_MHZ=$(if $(findstring 20mhz,$*),20,80)
$(B)/%/plat_nucleo.o: plat_nucleo.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFG) $(CFLAGS) -c $< -o $@
$(B)/%/credential.o: $(MCU)/common/credential.c $(MCU)/vec/vectors.h $(MCU)/energy/schedule.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFG) $(CFLAGS) -c $< -o $@

.SECONDEXPANSION:
$(B)/linea_nucleo_%.elf: $(B)/$$*/plat_nucleo.o $(B)/$$*/credential.o $(SHARED_OBJS) $(B)/mldsa44.o $(B)/mldsa65.o $(B)/mldsa87.o
	$(CC) $(LDFLAGS) -o $@ $^ -lopencm3_stm32l4 -lc -lgcc -lnosys
	@! $(CROSS)nm $@ | grep -q ' T shake128_inc_ctx_release$$' || \
	  ! $(CROSS)objdump -d $@ | grep -A4 '<shake128_inc_init>:' | grep -q malloc || \
	  (echo "ERROR: PQClean's fips202 was linked instead of pqm4's" && rm -f $@ && false)
$(B)/%.bin: $(B)/%.elf
	$(OBJCOPY) -O binary $< $@
	$(CROSS)size $<

clean:
	rm -rf $(B)
.SECONDARY:
.PRECIOUS: $(B)/%.elf $(B)/%/plat_nucleo.o $(B)/%/credential.o

# Functional check of the same M4 objects under QEMU (mps2-an386), before
# the image goes on the board: every row must say ok, every negative test
# must reject. Needs pqm4's MPS2 HAL: make -C $(PQM4) PLATFORM=mps2-an386 obj/libpqm4hal.a obj/ldscript.ld
QEMU_CPP := $(filter-out -DSTM32L4 -DSTM32L4R5ZI,$(CPPFLAGS)) -DMPS2_AN386
$(B)/qemu/plat_qemu.o: plat_qemu.c
	@mkdir -p $(@D)
	$(CC) $(QEMU_CPP) $(CFLAGS) -c $< -o $@
$(B)/qemu/credential.o: $(MCU)/common/credential.c
	@mkdir -p $(@D)
	$(CC) $(QEMU_CPP) $(CFLAGS) -c $< -o $@
$(B)/qemu/qemu.elf: $(B)/qemu/plat_qemu.o $(B)/qemu/credential.o $(filter-out $(B)/shared/hal-opencm3.o,$(SHARED_OBJS)) $(B)/mldsa44.o $(B)/mldsa65.o $(B)/mldsa87.o
	$(CC) $(ARCH) --specs=nosys.specs -Wl,--wrap=_sbrk -Wl,--wrap=_open -Wl,--wrap=_close \
	  -Wl,--wrap=_isatty -Wl,--wrap=_kill -Wl,--wrap=_lseek -Wl,--wrap=_read -Wl,--wrap=_write \
	  -Wl,--wrap=_fstat -Wl,--wrap=_getpid -Wl,--no-warn-rwx-segments -ffreestanding \
	  -T$(PQM4)/obj/ldscript.ld -o $@ $^ -L$(PQM4)/obj -lpqm4hal -lc -lgcc -lnosys
qemu-test: $(B)/qemu/qemu.elf
	timeout 900 qemu-system-arm -M mps2-an386 -nographic -semihosting -kernel $< > $(B)/qemu/qemu_out.txt
	@echo "rows ok: $$(grep -c '"ok":true' $(B)/qemu/qemu_out.txt), bad: $$(grep -c '"ok":false' $(B)/qemu/qemu_out.txt), negatives passed: $$(grep -c 'rejects_flipped_bit":true,"accepts_original":true,"rejects_tampered_manifest":true' $(B)/qemu/qemu_out.txt)"
.PHONY: all clean qemu-test
