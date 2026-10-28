/* SPDX-License-Identifier: Apache-2.0 */
/*
 * QEMU `virt` RISC-V linker script -- a measurement instrument, not a board.
 *
 * QEMU loads the ELF with -kernel and jumps to its entry point in M-mode, so
 * unlike the ESP32 parts there is no flash-to-RAM copy: LMA == VMA and .data
 * arrives already in place.  Startup only has to zero .bss.
 *
 * The (rw) spelling on the region is load-bearing: scripts/mem-config parses
 * exactly that token to learn a platform's usable RAM.  Code also executes from
 * this region -- the attribute only steers orphan-section placement, which this
 * script does not rely on.
 *
 * The stack is given an explicit bound rather than "everything left over".
 * hal_spraystack() writes a pattern across the whole stack region before each
 * measured operation, so a 512 MiB stack would mean spraying 512 MiB three
 * times per run.  32 MiB is about four times the largest figure in the tree
 * (SNOVA l5-x sign, ~8.4 MiB of stack and static, measurements/snova3.tsv) and
 * cheap to spray; raise it if a scheme ever approaches it.
 */

MEMORY {
    ram (rw) : ORIGIN = 0x80000000, LENGTH = 0x20000000  /* 512 MiB */
}

ENTRY(_start)

_stack_size = 32M;

SECTIONS {
  .text 0x80000000 : {
    KEEP(*(.text.entry))    /* _start must be at the entry address */
    *(.text .stub .text.* .gnu.linkonce.t.*)
  } > ram

  .rodata : {
    . = ALIGN(4);
    *(.rodata .rodata* .gnu.linkonce.r.*)
    *(.srodata .srodata* .sdata2 .sdata2*)
  } > ram

  .init_array : {
    . = ALIGN(4);
    KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*)))
    KEEP(*(.init_array))
  } > ram

  .fini_array : {
    . = ALIGN(4);
    KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*)))
    KEEP(*(.fini_array))
  } > ram

  .data : {
    . = ALIGN(4);
    _sdata_start = .;
    *(.data .data* .gnu.linkonce.d.*)
    *(.sdata .sdata.* .gnu.linkonce.s.*)
    *(.got .got.*)
    . = ALIGN(4);
  } > ram

  /* gp addresses +/-2 KiB around itself; point it into the small-data area. */
  __global_pointer$ = _sdata_start + 0x800;

  .bss (NOLOAD) : {
    . = ALIGN(4);
    _bss_start = .;
    *(.bss .bss* .sbss .sbss* .gnu.linkonce.b.*)
    *(COMMON)
    . = ALIGN(4);
    _bss_end = .;
  } > ram

  /* The stack is reserved by advancing the location counter, not by an output
   * section. A `.stack (NOLOAD)` section would still be ALLOC, so `size` counts
   * it as bss -- and this stack is 32 MiB, which swamped the few KiB of real
   * bss and made the scheme's static footprint unreadable. Plain symbols
   * reserve the same address range and appear in no section at all. */
  . = ALIGN(16);
  _stack_bottom = .;
  . = . + _stack_size;
  _stack_top = .;

  /* End of the image; anything past here is unused RAM. */
  _end = .;

  /DISCARD/ : {
    *(.eh_frame .eh_frame.*)
    *(.comment)
  }
}
