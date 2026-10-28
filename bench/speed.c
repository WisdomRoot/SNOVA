// SPDX-License-Identifier: Apache-2.0
//
// Median hal_get_time() of keypair, sign and verify over NTESTS runs, from
// pqsca's test/crypto_sign/speed.c. Lengths are unsigned long long, as
// upstream's api.h declares them.
#include "api.h"
#include "hal.h"
#include "randombytes.h"
#include "sendfn.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MLEN 32
#define printcycles(S, U) send_unsignedll((S), (U))

static int cmp_uint64_t(const void *a, const void *b) {
  uint64_t x = *(const uint64_t *)a;
  uint64_t y = *(const uint64_t *)b;
  return (x > y) - (x < y);
}

static unsigned char pk[CRYPTO_PUBLICKEYBYTES];
static unsigned char sk[CRYPTO_SECRETKEYBYTES];

int main(void) {
  unsigned char m[MLEN];
  unsigned char sm[MLEN + CRYPTO_BYTES];
  unsigned char m_out[MLEN + CRYPTO_BYTES];
  unsigned long long smlen = 0;
  unsigned long long mlen = 0;

  uint64_t cycles_kg[NTESTS], cycles_sign[NTESTS], cycles_verify[NTESTS];
  unsigned long long t0, t1;
  int i;
  int rc = 0;

  hal_setup(CLOCK_BENCHMARK);
  SERIAL_MARKER();

  // Pre-generate a keypair for sign/verify benchmarks so those loops do not
  // include keygen time.
  crypto_sign_keypair(pk, sk);

  for (i = 0; i < NTESTS; i++) {
    randombytes(m, MLEN);
    t0 = hal_get_time();
    crypto_sign(sm, &smlen, m, MLEN, sk);
    t1 = hal_get_time();
    cycles_sign[i] = t1 - t0;
  }

  for (i = 0; i < NTESTS; i++) {
    t0 = hal_get_time();
    rc = crypto_sign_open(m_out, &mlen, sm, smlen, pk);
    t1 = hal_get_time();
    cycles_verify[i] = t1 - t0;
    if (rc) {
      break;
    }
  }

  if (rc) {
    hal_send_str("ERROR signature verification\n");
  } else if (mlen != MLEN || memcmp(m, m_out, MLEN)) {
    hal_send_str("ERROR message mismatch\n");
  } else {
    hal_send_str("OK signature verification\n");
  }

  for (i = 0; i < NTESTS; i++) {
    t0 = hal_get_time();
    crypto_sign_keypair(pk, sk);
    t1 = hal_get_time();
    cycles_kg[i] = t1 - t0;
  }

  hal_send_str("+");

  qsort(cycles_kg, NTESTS, sizeof(uint64_t), cmp_uint64_t);
  qsort(cycles_sign, NTESTS, sizeof(uint64_t), cmp_uint64_t);
  qsort(cycles_verify, NTESTS, sizeof(uint64_t), cmp_uint64_t);

  printcycles("keypair cycles", cycles_kg[NTESTS >> 1]);
  printcycles("sign cycles", cycles_sign[NTESTS >> 1]);
  printcycles("verify cycles", cycles_verify[NTESTS >> 1]);

  SERIAL_MARKER();
  return 0;
}
