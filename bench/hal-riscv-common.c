// SPDX-License-Identifier: Apache-2.0
// RISC-V HAL parts that do not depend on the machine.
//
// Stack measurement and the newlib syscall stubs are the same code on every
// RV32 target -- they touch sp, the linker-defined stack bounds, and errno, and
// nothing else. They live here so a machine's own HAL file (hal-esp32.c,
// hal-virt.c) is only the part that differs: its UART, its clock bring-up, its
// cycle counter.
//
// Requires the linker script to define _stack_bottom and _stack_top.
#include <hal.h>
#include <stdint.h>

extern char _stack_top;
static char *stack_top = &_stack_top;
extern char _stack_bottom[];
static char *stack_bottom = _stack_bottom;

size_t hal_get_stack_size(void) {
  register char *cur_stack;
  __asm__ volatile("mv %0, sp" : "=r"(cur_stack));
  return stack_top - cur_stack;
}

const uint32_t stackpattern = 0xDEADBEEFlu;
static void *last_sp = NULL;

void hal_spraystack(void) {
  char *_sb = stack_bottom;
  asm volatile(
      "mv %0, sp\n"
      ".L%=:\n\t"
      "sw %2, (%1)\n\t"
      "addi %1, %1, 4\n\t"
      "blt %1, %0, .L%=\n\t"
      : "+r"(last_sp), "+r"(_sb)
      : "r"(stackpattern)
      : "cc", "memory");
}

size_t hal_checkstack(void) {
  size_t result = 0;
  if (hal_stack_guard_hit(stack_bottom, stackpattern)) {
    return HAL_STACK_OVERFLOW;
  }
  asm volatile(
      "sub %0, %1, %2\n"
      ".L%=:\n\t"
      "lw t0, (%2)\n\t"
      "addi %2, %2, 4\n\t"
      "bne t0, %3, .LE%=\n\t"
      "addi %0, %0, -4\n\t"
      "blt %2, %1, .L%=\n\t"
      ".LE%=:\n"
      : "+r"(result)
      : "r"(last_sp), "r"(stack_bottom), "r"(stackpattern)
      : "t0", "cc");
  return result;
}

void _exit(int code) {
  (void)code;
  for (;;) {
    (void)0;
  }
}

void exit(int code) {
  _exit(code);
}

#include <errno.h>
#undef errno
extern int errno;

int __wrap__open(char *file, int flags, int mode) {
  (void)file;
  (void)flags;
  (void)mode;
  errno = ENOSYS;
  return -1;
}
int __wrap__close(int fd) {
  (void)fd;
  errno = ENOSYS;
  return -1;
}
#include <sys/stat.h>
int __wrap__fstat(int fd, struct stat *buf) {
  (void)fd;
  (void)buf;
  errno = ENOSYS;
  return -1;
}
int __wrap__getpid(void) {
  errno = ENOSYS;
  return -1;
}
int __wrap__isatty(int file) {
  (void)file;
  errno = ENOSYS;
  return 0;
}
int __wrap__kill(int pid, int sig) {
  (void)pid;
  (void)sig;
  errno = ENOSYS;
  return -1;
}
int __wrap__lseek(int fd, int ptr, int dir) {
  (void)fd;
  (void)ptr;
  (void)dir;
  errno = ENOSYS;
  return -1;
}
int __wrap__read(int fd, char *ptr, int len) {
  (void)fd;
  (void)ptr;
  (void)len;
  errno = ENOSYS;
  return -1;
}
int __wrap__write(int fd, const char *ptr, int len) {
  (void)fd;
  (void)ptr;
  (void)len;
  errno = ENOSYS;
  return -1;
}
void *__wrap__sbrk(int incr) {
  (void)incr;
  errno = ENOSYS;
  return NULL;
}

struct _reent *__getreent(void) {
  return _impure_ptr;
}
