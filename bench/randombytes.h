// SPDX-License-Identifier: Apache-2.0
#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stdint.h>
#include <unistd.h>

/* The prototype upstream's src/rng.h declares, which src/sign.c calls through.
 * pqsca's (uint8_t *, size_t) differs in the length's width, and on a 32-bit
 * target the two do not pass it in the same registers. */
int randombytes(unsigned char *output, unsigned long long n);

#endif /* RANDOMBYTES_H */
