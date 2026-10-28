// SPDX-License-Identifier: Apache-2.0
// HAL for the QEMU `virt` RISC-V machine -- a measurement instrument, not a
// board. See mk/platforms/riscv32-virt.mk for why it exists.
//
// Only the machine-specific parts live here; stack measurement and the newlib
// stubs are shared with the ESP32 parts in hal-riscv-common.c.
//
// There is no hardware counterpart, so none of the bring-up a real part needs
// applies: no watchdogs to disable, no clock tree to configure, no USB host to
// wait for. hal_setup() is genuinely empty.
#include <hal.h>
#include <stdint.h>

/* QEMU `virt` puts a 16550A UART at 0x10000000. With -nographic its output is
 * the emulator's stdio, which is what the harness reads. THR is at offset 0 and
 * LSR at 5, bit 5 (THRE) meaning the transmit register is free. QEMU's FIFO
 * never fills, so the poll always falls through immediately -- it is here so
 * the code is correct against a real 16550 as well. */
#define UART0_BASE 0x10000000UL
#define UART0_THR (*(volatile uint8_t *)(UART0_BASE + 0))
#define UART0_LSR (*(volatile uint8_t *)(UART0_BASE + 5))
#define UART_LSR_THRE (1u << 5)

static inline void putc_hw(uint8_t c) {
  while (!(UART0_LSR & UART_LSR_THRE)) {
  }
  UART0_THR = c;
}

void hal_setup(const enum clock_mode clock) {
  (void)clock;
}

void hal_send_str(const char *in) {
  if (!in) {
    return;
  }
  const char *p = in;
  while (*p) {
    putc_hw((uint8_t)*p++);
  }
  /* Unconditional, as in hal-mps2.c: the harness reads one message per line. */
  putc_hw('\n');
}

/* Unlike the ESP32 parts, this machine implements the standard `cycle` CSR, so
 * no vendor performance counter is involved. cycle/cycleh are two 32-bit reads
 * of one 64-bit counter: re-read the high half and retry if it moved between
 * them, which is the standard RV32 sequence and needs no static state. */
uint64_t hal_get_time(void) {
  uint32_t hi, lo, hi_again;
  do {
    __asm__ volatile("csrr %0, cycleh" : "=r"(hi));
    __asm__ volatile("csrr %0, cycle" : "=r"(lo));
    __asm__ volatile("csrr %0, cycleh" : "=r"(hi_again));
  } while (hi != hi_again);
  return ((uint64_t)hi << 32) | lo;
}
