# SNOVA

This directory contains the official constant-time, optimized implementation of the SNOVA signature scheme.

## Building

Building SNOVA requires a C compiler and `make`. No additional dependencies are required.

The SNOVA parameters are defined in `snova_params.h`. They can also be overridden from the command line when invoking `make`. For example:

```bash
make clean all P="-D SNOVA_v=38 -D SNOVA_o=5 -D SNOVA_q=16 -D SNOVA_l=4 -D SNOVA_r=6 -D SNOVA_m1=7"
```

To build a SNOVA using AES-CTR for public-key expansion:

```bash
make clean all P="-D SNOVA_v=27 -D SNOVA_o=4 -D SNOVA_q=16 -D SNOVA_l=4 -D SNOVA_r=6 -D SNOVA_m1=5 -D AESCTR"
```

### Optimization variants

The following optimization variants are available:

1. `make OPT=REF` builds the reference implementation in `snova_ref.c`.
2. `make OPT=OPT` builds the optimized implementation. This is the default configuration.
3. `make OPT=AVX2` builds a further optimized implementation, using explicit AVX2 and GFNI instructions where available.
4. `make OPT=MEM` builds a plain-C implementation with a substantially reduced memory footprint. On x86 platforms, this implementation is a few times slower than the `OPT` and `AVX2` implementations.
5. `make OPT=TINYMEM` builds a variant with a further reduced memory footprint at the cost of increased computational overhead. Further optimization may reduce both execution time and memory consumption.

## Symmetric Primitives

The distribution includes implementations of AES and SHAKE. AES can alternatively be provided by the OpenSSL library, which may offer better performance on platforms without AVX2 support.

To use the OpenSSL AES implementation, build with:

```bash
make clean all P="-D USE_OPENSSL" LIBS=-lcrypto
```

## Compatibility with Round 2 SNOVA

Although the SNOVA parameter space has been expanded and the recommended parameter sets have changed, the underlying algorithm is unchanged between Rounds 2 and 3. Consequently, the Round 2 Known Answer Test (KAT) files can still be reproduced using the corresponding Round 2 parameters and compatibility options.

For example:

```bash
make clean kat P="-D SNOVA_v=24 -D SNOVA_o=5 -D SNOVA_q=16 -D SNOVA_l=4 -D SNOVA_r=4 -D SNOVA_m1=5 -D SNOVA_alpha=20 -D FIXED_ABQ=0 -D HASH_PK=0 -D ROUND2_T12=1 -D SNOVA_NAME=SNOVA_24_5_4_SHAKE"
```

This generates the response file:

```text
PQCsignKAT_SNOVA_24_5_4_SHAKE.rsp
```

To verify that the generated KAT response matches the Round 2 implementation, run:

```bash
diff PQCsignKAT_SNOVA_24_5_4_SHAKE.rsp \
     $SNOVA_KAT/Round2/PQCsignKAT_SNOVA_24_5_4_SHAKE_SSK.rsp
```
