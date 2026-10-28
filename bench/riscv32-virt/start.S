/* SPDX-License-Identifier: Apache-2.0 */
/*
 * QEMU `virt` RISC-V startup.
 *
 * QEMU loads the ELF with -kernel -bios none and starts the hart at the ELF
 * entry point in M-mode, with every PT_LOAD segment already written to its
 * address.  There is therefore no .data copy to do (LMA == VMA, unlike the
 * ESP32 direct-boot path in hal/esp32_start.S) -- only .bss to zero.
 */

    .section .text.entry, "ax"

    .global _start
    .type   _start, @function
_start:
    .option push
    .option norelax
    la      gp, __global_pointer$
    .option pop

    la      sp, _stack_top

    /* Zero .bss */
    la      a0, _bss_start
    la      a2, _bss_end
    sub     a2, a2, a0
    beqz    a2, .Lmain
    li      a1, 0
    call    memset

.Lmain:
    la      a0, _main_argc
    lw      a0, 0(a0)
    la      a1, _main_argv
    li      a2, 0
    call    main

    /* RISC-V semihosting SYS_EXIT (0x18) so QEMU terminates instead of
     * spinning.  a0 = operation, a1 = reason.  On RV32 the reason is passed in
     * a1 itself, not through a {reason, exit_code} block as on RV64: QEMU
     * reads a pointer there as an unknown reason and exits 1, which is what
     * pqsca's copy of this file does.  The slli/ebreak/srai
     * sandwich is the spec's magic sequence that distinguishes a semihosting
     * call from an ordinary breakpoint; .option norvc keeps all three as 32-bit
     * instructions, which the sequence requires. */
    li      a0, 0x18            /* SYS_EXIT */
    li      a1, 0x20026         /* ADP_Stopped_ApplicationExit */
    .option push
    .option norvc
    slli    zero, zero, 0x1f
    ebreak
    srai    zero, zero, 0x07
    .option pop
1:  j       1b                  /* unreachable unless QEMU ignores semihosting */

    .size  _start, .-_start

    .section .data
    .global _main_argc
    .weak   _main_argc
_main_argc:
    .word   1
_argv_0:
    .string ""
    .global _main_argv
    .weak   _main_argv
_main_argv:
    .word   _argv_0
