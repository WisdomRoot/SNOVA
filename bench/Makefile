# SPDX-License-Identifier: Apache-2.0
#
# Bare-metal builds for the two measurement machines. Run inside `nix develop`,
# which puts both cross toolchains and both emulators on PATH.
#
#   make ISA=arm baseline          build build/arm/baseline.elf
#   make ISA=riscv run-baseline    build it and run it under QEMU
#   make ISA=arm KERNEL=mem SET=l3-b stack speed
#   make ISA=riscv SET=l1-k DEFS='-DAESCTR' run-stack run-speed
#
# KERNEL, SET and DEFS pick the SNOVA build; see "SNOVA" below.
#
# ISA picks the machine:
#
#   arm    mps2-an386 under qemu-system-arm, Cortex-M4. Startup, linker script
#          and device headers are copied out of mbed-os into mps2-an386/.
#   riscv  QEMU's virt machine, rv32imc, 512 MiB of flat RAM. A measurement
#          instrument with no counterpart in silicon; see riscv32-virt/.
#
# Both builds and their compiler and linker flags follow pqsca's mk/ for the
# same two platforms.

ISA ?= arm

BUILD := build/$(ISA)

CFLAGS := -O3 -std=gnu17 -Wall -Wextra -Wshadow -fno-common \
          -fdata-sections -ffunction-sections -I.

# The newlib syscalls the HAL replaces; each is defined as __wrap_<name>.
LDFLAGS := -ffreestanding -Wl,--gc-sections \
           $(foreach f,_sbrk _open _close _isatty _kill _lseek _read _write _fstat _getpid,-Wl,--wrap=$(f))

ifeq ($(ISA),arm)
CROSS := arm-none-eabi-
ARCH := -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16
CFLAGS += $(ARCH) -DMPS2 -DMPS2_AN386 -DQEMU -Imps2-an386 -Imps2-an386/cmsis
HAL_SRC := hal-mps2.c notrandombytes.c mps2-an386/startup_MPS2.S
LDSCRIPT := $(BUILD)/MPS2.ld
LDFLAGS += $(ARCH) --specs=nosys.specs -Wl,--no-warn-rwx-segments -T$(LDSCRIPT)
LDLIBS :=
else ifeq ($(ISA),riscv)
CROSS := riscv32-esp-elf-
# Same ISA string as pqsca's esp32-c3, so the toolchain picks the same
# multilib; virt's CPU is a superset. -fno-lto keeps the asm startup intact.
ARCH := -march=rv32imc_zicsr_zifencei
CFLAGS += $(ARCH) -fno-lto -DRISCV -DQEMU
HAL_SRC := hal-virt.c hal-riscv-common.c notrandombytes.c riscv32-virt/start.S
LDSCRIPT := riscv32-virt/memory.ld
# One flat RAM region puts code and data in one RWX segment; on a machine with
# no memory protection that is what every bare-metal image looks like.
LDFLAGS += $(ARCH) -nostdlib -nostartfiles -static -fno-lto \
           -Wl,--no-warn-rwx-segments -T$(LDSCRIPT)
LDLIBS := -lg_nano -lgcc
else
$(error ISA=$(ISA) is not one of: arm riscv)
endif

CC := $(CROSS)gcc
SIZE := $(CROSS)size

HAL_OBJ := $(addprefix $(BUILD)/hal/,$(addsuffix .o,$(HAL_SRC)))

# --- SNOVA --------------------------------------------------------------------
# KERNEL is one of upstream's four portable kernels, with the symmetric front
# end and SNOVA_OPT its src/Makefile pairs it with:
#
#   ref      snova_ref.c          symmetric_ref.c   SNOVA_OPT=0
#   opt      snova_opt_16.c       symmetric.c       SNOVA_OPT=10
#   mem      snova_memopt_16.c    symmetric.c       SNOVA_OPT=5
#   tinymem  snova_tinymem_16.c   symmetric_tiny.c  SNOVA_OPT=5
KERNEL ?= ref

KERNEL_SRC_ref     := snova_ref.c symmetric_ref.c
KERNEL_SRC_opt     := snova_opt_16.c symmetric.c
KERNEL_SRC_mem     := snova_memopt_16.c symmetric.c
KERNEL_SRC_tinymem := snova_tinymem_16.c symmetric_tiny.c

KERNEL_OPT_ref     := 0
KERNEL_OPT_opt     := 10
KERNEL_OPT_mem     := 5
KERNEL_OPT_tinymem := 5

ifeq ($(KERNEL_SRC_$(KERNEL)),)
$(error KERNEL=$(KERNEL) is not one of: ref opt mem tinymem)
endif

# SET is one of the nine recommended sets, as the 6-tuple v o q l r m1 and the
# name dist/makesnova.py gives them. Passing SNOVA_q keeps src/snova_params.h,
# and the set hard-coded there, out of the build.
SET ?= l1-k

SET_l1-k := 29 3 16 4 8 5 SNOVA_I_K
SET_l1-b := 27 4 16 4 6 5 SNOVA_I_B
SET_l1-s := 27 5 16 4 4 5 SNOVA_I_S
SET_l3-k := 38 4 16 4 8 7 SNOVA_III_K
SET_l3-b := 38 5 16 4 6 7 SNOVA_III_B
SET_l3-s := 38 6 16 4 5 7 SNOVA_III_S
SET_l5-k := 40 4 16 5 8 6 SNOVA_V_K
SET_l5-b := 40 5 16 5 6 6 SNOVA_V_B
SET_l5-s := 40 6 16 5 5 6 SNOVA_V_S

ifeq ($(SET_$(SET)),)
$(error SET=$(SET) is not one of: l1-k l1-b l1-s l3-k l3-b l3-s l5-k l5-b l5-s)
endif

SET_DEFS := $(join -DSNOVA_v= -DSNOVA_o= -DSNOVA_q= -DSNOVA_l= -DSNOVA_r= -DSNOVA_m1= -DSNOVA_NAME=,$(SET_$(SET)))

# DEFS is any further -D flags, e.g. DEFS='-DAESCTR'. Each distinct DEFS gets
# its own build directory, named after the flags: "stock" when there are none.
DEFS ?=
empty :=
space := $(empty) $(empty)
VARIANT := $(if $(strip $(DEFS)),$(subst $(space),_,$(subst =,-,$(subst -D,,$(strip $(DEFS))))),stock)

SNOVA_BUILD := $(BUILD)/snova/$(KERNEL)-$(SET)-$(VARIANT)

# Upstream's sign.c is the NIST API over every kernel. rng.c is not built: it is
# the NIST DRBG over OpenSSL, and notrandombytes.c stands in for its randombytes.
# aes.c is only reached under AESCTR, and --gc-sections drops it otherwise.
SNOVA_SRC := $(KERNEL_SRC_$(KERNEL)) sign.c aes.c
SNOVA_OBJ := $(addprefix $(SNOVA_BUILD)/,$(SNOVA_SRC:.c=.o))
SNOVA_HDR := $(wildcard ../src/*.h)

# Upstream's own warnings (src/Makefile), without -Werror, which upstream does
# not use either.
SNOVA_CFLAGS := -Wall -Wextra -Wpedantic -Wredundant-decls -Wshadow -Wvla -Wpointer-arith \
                -DSNOVA_OPT=$(KERNEL_OPT_$(KERNEL)) $(SET_DEFS) $(DEFS) -I../src

# How many times speed repeats each operation before reporting the median.
NTESTS ?= 1

.PHONY: baseline run-baseline stack speed run-stack run-speed print-snova-build clean
baseline: $(BUILD)/baseline.elf

run-baseline: $(BUILD)/baseline.elf
	./emulate $(ISA) $<

stack: $(SNOVA_BUILD)/stack.elf
speed: $(SNOVA_BUILD)/speed.elf

run-stack: $(SNOVA_BUILD)/stack.elf
	./emulate $(ISA) $<

run-speed: $(SNOVA_BUILD)/speed.elf
	./emulate $(ISA) $<

# Where stack.elf and speed.elf land for this KERNEL, SET and DEFS; measure
# asks rather than rebuilding the directory name itself.
print-snova-build:
	@echo $(SNOVA_BUILD)

clean:
	rm -rf build

$(SNOVA_BUILD)/%.o: ../src/%.c $(SNOVA_HDR)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(SNOVA_CFLAGS) -c -o $@ $<

$(SNOVA_BUILD)/stack.c.o: stack.c $(SNOVA_HDR)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(SNOVA_CFLAGS) -c -o $@ $<

$(SNOVA_BUILD)/speed.c.o: speed.c $(SNOVA_HDR)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(SNOVA_CFLAGS) -DNTESTS=$(NTESTS) -c -o $@ $<

$(SNOVA_BUILD)/%.elf: $(SNOVA_BUILD)/%.c.o $(SNOVA_OBJ) $(HAL_OBJ) $(LDSCRIPT)
	$(CC) $(LDFLAGS) -o $@ $(filter %.o,$^) -Wl,--start-group $(LDLIBS) -Wl,--end-group
	$(SIZE) $@

$(BUILD)/hal/%.c.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/hal/%.S.o: %.S
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/%.c.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

# MBED's script includes cmsis_nvic.h for the vector count, so it goes through
# the preprocessor first.
$(BUILD)/MPS2.ld: mps2-an386/MPS2.ld mps2-an386/cmsis_nvic.h
	@mkdir -p $(@D)
	$(CC) -x assembler-with-cpp -E -P -Imps2-an386 $< -o $@

# The platform baseline: HAL, startup and libc statics, and no cryptography.
$(BUILD)/baseline.elf: $(BUILD)/baseline.c.o $(HAL_OBJ) $(LDSCRIPT)
	$(CC) $(LDFLAGS) -o $@ $(filter %.o,$^) -Wl,--start-group $(LDLIBS) -Wl,--end-group
	$(SIZE) $@
