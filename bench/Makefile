# SPDX-License-Identifier: Apache-2.0
#
# Bare-metal builds for the two measurement machines. Run inside `nix develop`,
# which puts both cross toolchains and both emulators on PATH.
#
#   make ISA=arm baseline          build build/arm/baseline.elf
#   make ISA=riscv run-baseline    build it and run it under QEMU
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

.PHONY: baseline run-baseline clean
baseline: $(BUILD)/baseline.elf

run-baseline: $(BUILD)/baseline.elf
	./emulate $(ISA) $<

clean:
	rm -rf build

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
