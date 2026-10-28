// SPDX-License-Identifier: Apache-2.0
//
// The platform baseline: a linkable image carrying the HAL, the startup code
// and the libc statics that every test binary carries, and no cryptography at
// all.
//
// scripts/measure subtracts this image's data+bss from a scheme's, so the static
// part of a space figure is what the *scheme* needs rather than what the machine
// it was measured on happens to reserve. Without it the two ISA columns are not
// comparable: mps2-an386 reserves a 4 KiB .heap and copies a 256-byte vector
// table into RAM, and riscv32-virt reserves neither.
//
// It calls exactly the HAL surface test/crypto_sign/kat.c calls -- static is
// measured from the -kat binary, and --gc-sections would otherwise drop HAL
// code that a real test binary keeps, making the baseline too small and
// over-attributing the difference to the scheme.
#include "hal.h"

int main(void) {
  hal_setup(CLOCK_FAST);
  hal_send_str("baseline\n");
  return 0;
}
