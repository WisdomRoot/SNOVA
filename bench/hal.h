// SPDX-License-Identifier: Apache-2.0
#ifndef HAL_H
#define HAL_H

#include <stdint.h>
#include <stdlib.h>

#if defined(__GNUC__) || defined(__clang__)
#define UNUSED __attribute__((unused))
#define NOINLINE __attribute__((noinline))
#define NORETURN __attribute__((noreturn))
#define DESTRUCTOR __attribute__((destructor))
#else
#define UNUSED
#define NOINLINE
#define NORETURN
#define DESTRUCTOR
#endif

#if !defined(MPS2)
#define SERIAL_MARKER() \
  {                     \
    hal_send_str("$");  \
  }
#else
#define SERIAL_MARKER()
#endif

enum clock_mode { CLOCK_FAST, CLOCK_BENCHMARK };

void hal_setup(const enum clock_mode clock);
void hal_send_str(const char *in);
uint64_t hal_get_time(void);
size_t hal_get_stack_size(void);
void hal_spraystack(void);
size_t hal_checkstack(void);

/* hal_checkstack()'s result when the operation's stack came within
 * HAL_STACK_GUARD bytes of the bottom of the sprayed region, usually where the
 * linked layout's static data or heap begins: it may have overflowed into
 * them, so its depth is unknown. The guard is a margin because a frame can
 * reserve words it never writes. */
#define HAL_STACK_OVERFLOW UINT32_MAX
#define HAL_STACK_GUARD 1024u

static inline int hal_stack_guard_hit(const char *bottom, uint32_t pattern) {
  const volatile uint32_t *word = (const volatile uint32_t *)bottom;
  for (size_t i = 0; i < HAL_STACK_GUARD / 4; i++) {
    if (word[i] != pattern) {
      return 1;
    }
  }
  return 0;
}

#endif
