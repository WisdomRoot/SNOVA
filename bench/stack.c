// SPDX-License-Identifier: Apache-2.0
//
// Peak stack of keypair, sign and verify, from pqsca's test/crypto_sign/stack.c.
// Lengths are unsigned long long, as upstream's api.h declares them.
#include "api.h"
#include "hal.h"
#include "randombytes.h"
#include "sendfn.h"

#include <string.h>

#define MLEN 32
#define send_stack_usage(S, U) send_unsigned((S), (U))

static int test_sign(void) {
  // pk/sk are API objects, not implementation working memory: keep them out of
  // the measured stack frame (static .bss) so hal_checkstack() reflects only the
  // keypair/sign/verify implementation stack. sm/m/m_out are small and stay on
  // the stack.
  static unsigned char pk[CRYPTO_PUBLICKEYBYTES];
  static unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char sm[MLEN + CRYPTO_BYTES];
  unsigned char m[MLEN];
  unsigned char m_out[MLEN + CRYPTO_BYTES];
  unsigned long long smlen = 0;
  unsigned long long mlen = 0;
  unsigned int stack_key_gen, stack_sign, stack_verify;
  int rc;

  hal_spraystack();
  crypto_sign_keypair(pk, sk);
  stack_key_gen = hal_checkstack();

  randombytes(m, MLEN);
  hal_spraystack();
  crypto_sign(sm, &smlen, m, MLEN, sk);
  stack_sign = hal_checkstack();

  hal_spraystack();
  rc = crypto_sign_open(m_out, &mlen, sm, smlen, pk);
  stack_verify = hal_checkstack();

  if (rc) {
    hal_send_str("ERROR signature verification\n");
    return -1;
  }
  if (mlen != MLEN || memcmp(m, m_out, MLEN)) {
    hal_send_str("ERROR message mismatch\n");
    return -2;
  }
  if (stack_key_gen == HAL_STACK_OVERFLOW || stack_sign == HAL_STACK_OVERFLOW || stack_verify == HAL_STACK_OVERFLOW) {
    hal_send_str("ERROR stack overflow\n");
    return -3;
  }

  send_stack_usage("keypair stack usage:", stack_key_gen);
  send_stack_usage("sign stack usage:", stack_sign);
  send_stack_usage("verify stack usage:", stack_verify);
  hal_send_str("OK signature verification\n");
  return 0;
}

int main(void) {
  hal_setup(CLOCK_FAST);

  SERIAL_MARKER();
  test_sign();
  SERIAL_MARKER();

  return 0;
}
