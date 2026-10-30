// SIGN_BITSLICE: tinymem's and mem's sign, on sliced lanes.
//
// GF(16) = GF(2)[t]/(t^4 + t + 1), nibble bit k is the coefficient of t^k. A run
// of elements is held as four plane words, plane k carrying bit k of every
// element. whipped_sig, sum_t0, sum_t1, whipped_F12 and whipped_F21 are runs of
// SNOVA_lr elements, one plane word each (bs_t). The Gauss matrix rows are runs
// of SNOVA_o * SNOVA_lr + 1 elements over GW 32-bit words per plane.
//
// The arithmetic is exact, so the sliced parts need no gf16_compress. Scalars
// enter through masks, so no index or branch depends on a secret.

// The element type snova_pk_expander_squeeze writes: uint16_t for symmetric_tiny, uint8_t for symmetric.
#ifndef BS_PK_T
#define BS_PK_T uint16_t
#endif

#if SNOVA_lr <= 16
typedef uint16_t bs_t;
#elif SNOVA_lr <= 32
typedef uint32_t bs_t;
#else
typedef uint64_t bs_t;
#endif

#if SNOVA_r == 8
#define BS_R_MASK 0xffu
#else
#define BS_R_MASK ((1u << SNOVA_r) - 1)
#endif

#define GN (SNOVA_o * SNOVA_lr)
#define GW ((GN + 1 + 31) / 32)

static inline uint8_t bs_get(const bs_t *x, int c) {
	return (uint8_t)(((x[0] >> c) & 1) | (((x[1] >> c) & 1) << 1) | (((x[2] >> c) & 1) << 2) | (((x[3] >> c) & 1) << 3));
}

// acc ^= c * x, lane by lane.
static inline void bs_mul_acc(bs_t *acc, const bs_t *x, uint8_t c) {
	bs_t a0 = x[0], a1 = x[1], a2 = x[2], a3 = x[3], t;
	bs_t m;

	m = (bs_t)0 - (bs_t)(c & 1);
	acc[0] ^= m & a0;
	acc[1] ^= m & a1;
	acc[2] ^= m & a2;
	acc[3] ^= m & a3;
	for (int k = 1; k < 4; k++) {
		t = a3;
		a3 = a2;
		a2 = a1;
		a1 = a0 ^ t;
		a0 = t;
		m = (bs_t)0 - (bs_t)((c >> k) & 1);
		acc[0] ^= m & a0;
		acc[1] ^= m & a1;
		acc[2] ^= m & a2;
		acc[3] ^= m & a3;
	}
}

// The r lanes of x starting at lane from, moved to start at lane to.
static inline void bs_window(bs_t *out, const bs_t *x, int from, int to) {
	for (int p = 0; p < 4; p++) {
		out[p] = (bs_t)(((x[p] >> from) & BS_R_MASK) << to);
	}
}

static inline uint8_t g_get(uint32_t g[4][GW], int c) {
	int w = c / 32, b = c % 32;
	return (uint8_t)(((g[0][w] >> b) & 1) | (((g[1][w] >> b) & 1) << 1) | (((g[2][w] >> b) & 1) << 2) |
	                 (((g[3][w] >> b) & 1) << 3));
}

static inline void g_xor(uint32_t g[4][GW], int c, uint8_t v) {
	int w = c / 32, b = c % 32;
	g[0][w] ^= (uint32_t)(v & 1) << b;
	g[1][w] ^= (uint32_t)((v >> 1) & 1) << b;
	g[2][w] ^= (uint32_t)((v >> 2) & 1) << b;
	g[3][w] ^= (uint32_t)((v >> 3) & 1) << b;
}

// acc ^= c * x over a whole Gauss row.
static inline void g_mul_acc(uint32_t acc[4][GW], uint32_t x[4][GW], uint8_t c) {
	for (int w = 0; w < GW; w++) {
		uint32_t a0 = x[0][w], a1 = x[1][w], a2 = x[2][w], a3 = x[3][w], t;
		uint32_t m = 0u - (uint32_t)(c & 1);
		acc[0][w] ^= m & a0;
		acc[1][w] ^= m & a1;
		acc[2][w] ^= m & a2;
		acc[3][w] ^= m & a3;
		for (int k = 1; k < 4; k++) {
			t = a3;
			a3 = a2;
			a2 = a1;
			a1 = a0 ^ t;
			a0 = t;
			m = 0u - (uint32_t)((c >> k) & 1);
			acc[0][w] ^= m & a0;
			acc[1][w] ^= m & a1;
			acc[2][w] ^= m & a2;
			acc[3][w] ^= m & a3;
		}
	}
}

int SNOVA_NAMESPACE(sign)(const expanded_SK *skx_arg, uint8_t *sig, const uint8_t *digest, const size_t len_digest,
                          const uint8_t *salt) {
	uint8_t *sk = (uint8_t *)skx_arg;
	uint8_t *s_pk_seed = sk;
	uint8_t *s_sk_seed = sk + SEED_LENGTH_PUBLIC;
#if HASH_PK
	uint8_t *s_pk_hash = sk + SEED_LENGTH_PUBLIC + SEED_LENGTH_PRIVATE;
#endif

	uint8_t T12[T12_BYTES];
	expand_T12(T12, s_sk_seed);

	uint8_t hash_in_GF16[GF16_HASH];

	{
		uint8_t sign_hashb[BYTES_HASH];
#if HASH_PK
		hash_combined(sign_hashb, digest, len_digest, s_pk_hash, salt);
#else
		hash_combined(sign_hashb, digest, len_digest, s_pk_seed, salt);
#endif
		convert_bytes_to_GF(hash_in_GF16, sign_hashb, GF16_HASH);
	}

	uint8_t signature_in_GF[SNOVA_n * SNOVA_lr] = {0};
	int flag_redo;
	uint8_t num_sign = 0;

	while (1) {
		num_sign++;
		if (num_sign == 255) {
			memset(sig, 0, BYTES_SIGNATURE);
			return -1;
		}
		flag_redo = 0;

		uint32_t gauss[GN][4][GW];
		// Row (k1 * SNOVA_v + ni) holds whipped_sig[(k1 * SNOVA_v + ni) * SNOVA_lr + 0 .. SNOVA_lr - 1].
		bs_t whipped_sig[SNOVA_l * SNOVA_v][4];

		{
			uint8_t vinegar_in_byte[NUM_GEN_SEC_BYTES];
			shake_t v_instance;

			shake256_init(&v_instance);
			shake_absorb(&v_instance, s_sk_seed, SEED_LENGTH_PRIVATE);
			shake_absorb(&v_instance, digest, BYTES_DIGEST);
			shake_absorb(&v_instance, salt, BYTES_SALT);
			shake_absorb(&v_instance, &num_sign, 1);
			shake_finalize(&v_instance);
			shake_squeeze(vinegar_in_byte, NUM_GEN_SEC_BYTES, &v_instance);

			convert_bytes_to_GF(signature_in_GF, vinegar_in_byte, SNOVA_v * SNOVA_lr);

			SNOVA_SECURE_CLEARI(v_instance);
			SNOVA_SECURE_CLEAR(vinegar_in_byte);
		}

		{
			uint16_t whipped_sig1[SNOVA_lr];

			memset(whipped_sig, 0, sizeof(whipped_sig));
			for (int ni = 0; ni < SNOVA_v; ++ni)
				for (int i1 = 0; i1 < SNOVA_l; i1++) {
					memset(whipped_sig1, 0, sizeof(whipped_sig1));
					for (int ab = 0; ab < SNOVA_l; ++ab)
						for (int j1 = 0; j1 < SNOVA_r; j1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++)
								whipped_sig1[ab * SNOVA_r + j1] ^=
								    gf_Sx[ab * SNOVA_l2 + i1 * SNOVA_l + k1] * signature_in_GF[ni * SNOVA_lr + k1 * SNOVA_r + j1];

					bs_t *row = whipped_sig[i1 * SNOVA_v + ni];
					for (int j1 = 0; j1 < SNOVA_lr; j1++) {
						uint8_t val = gf16_compress(whipped_sig1[j1]);
						row[0] |= (bs_t)((bs_t)(val & 1) << j1);
						row[1] |= (bs_t)((bs_t)((val >> 1) & 1) << j1);
						row[2] |= (bs_t)((bs_t)((val >> 2) & 1) << j1);
						row[3] |= (bs_t)((bs_t)((val >> 3) & 1) << j1);
					}
				}

			SNOVA_SECURE_CLEAR(whipped_sig1);
		}

		memset(gauss, 0, sizeof(gauss));

		for (int mi = 0; mi < SNOVA_o; ++mi)
			for (int i1 = 0; i1 < SNOVA_lr; i1++) {
				g_xor(gauss[mi * SNOVA_lr + i1], GN, hash_in_GF16[mi * SNOVA_lr + i1]);
			}

		{
			snova_pk_expander_t instance;
			snova_pk_expander_init(&instance, s_pk_seed, SEED_LENGTH_PUBLIC);

#if !PUB_REORDER
			snova_pk_expander_t p12_instance;
			snova_pk_expander_init(&p12_instance, s_pk_seed, SEED_LENGTH_PUBLIC);
			snova_pk_expander_goto(&p12_instance, SNOVA_m1 * SNOVA_v * SNOVA_v * SNOVA_l2);

			snova_pk_expander_t p21_instance;
			snova_pk_expander_init(&p21_instance, s_pk_seed, SEED_LENGTH_PUBLIC);
			snova_pk_expander_goto(&p21_instance, SNOVA_m1 * SNOVA_v * SNOVA_n * SNOVA_l2);
#endif

			// Row (a1 * SNOVA_r + i1) of sum_t1, row (i1 * SNOVA_o + nk) of whipped_F12,
			// row (b1 * SNOVA_o + nk) of whipped_F21: the same rows tinymem indexes.
			bs_t sum_t1[SNOVA_l * SNOVA_r][4];
			bs_t whipped_F12[SNOVA_l * SNOVA_o][4];
			bs_t whipped_F21[SNOVA_l * SNOVA_o][4];
			bs_t win[4];
			uint16_t sum;

			for (int mi_prime = 0; mi_prime < SNOVA_m1; ++mi_prime) {
				memset(sum_t1, 0, sizeof(sum_t1));
				memset(whipped_F12, 0, sizeof(whipped_F12));
				memset(whipped_F21, 0, sizeof(whipped_F21));

				{
					bs_t sum_t0[SNOVA_l][4];
					uint16_t F12[SNOVA_o * SNOVA_l2];

					for (int ni = 0; ni < SNOVA_v; ++ni) {
						memset(sum_t0, 0, sizeof(sum_t0));
						memset(F12, 0, sizeof(F12));

						for (int nj = 0; nj < SNOVA_v; ++nj) {
							BS_PK_T P11b[SNOVA_l2];
							uint16_t P11x[SNOVA_l2];
							snova_pk_expander_squeeze(P11b, SNOVA_l2, &instance);
							for (int i1 = 0; i1 < SNOVA_l2; i1++) {
								P11x[i1] = gf16_expand(P11b[i1]);
							}

							for (int k1 = 0; k1 < SNOVA_l; k1++)
								for (int i1 = 0; i1 < SNOVA_l; i1++)
									bs_mul_acc(sum_t0[i1], whipped_sig[k1 * SNOVA_v + nj], (uint8_t)P11b[i1 * SNOVA_l + k1]);

							for (int nk = 0; nk < SNOVA_o; nk++)
								for (int i1 = 0; i1 < SNOVA_l; i1++)
									for (int j1 = 0; j1 < SNOVA_l; j1++)
										for (int k1 = 0; k1 < SNOVA_l; k1++)
											F12[nk * SNOVA_l2 + i1 * SNOVA_l + j1] ^=
											    T12_GET((nj * SNOVA_o + nk) * SNOVA_l2 + k1 * SNOVA_l + j1) *
											    P11x[i1 * SNOVA_l + k1];
						}

						// Left, transposed whipped_sig
						for (int a1 = 0; a1 < SNOVA_l; ++a1)
							for (int k1 = 0; k1 < SNOVA_l; k1++)
								for (int i1 = 0; i1 < SNOVA_r; i1++)
									bs_mul_acc(sum_t1[a1 * SNOVA_r + i1], sum_t0[k1],
									           bs_get(whipped_sig[k1 * SNOVA_v + ni], a1 * SNOVA_r + i1));

						for (int i1 = 0; i1 < SNOVA_o * SNOVA_l2; i1++) {
							F12[i1] = gf16_compress(F12[i1]);
						}

						for (int nk = 0; nk < SNOVA_o; nk++)
							for (int i1 = 0; i1 < SNOVA_l; i1++)
								for (int k1 = 0; k1 < SNOVA_l; k1++)
									bs_mul_acc(whipped_F12[i1 * SNOVA_o + nk], whipped_sig[k1 * SNOVA_v + ni],
									           (uint8_t)F12[nk * SNOVA_l2 + k1 * SNOVA_l + i1]);

						for (int k1 = 0; k1 < SNOVA_l; k1++)
							for (int b1 = 0; b1 < SNOVA_l; ++b1)
								for (int nk = 0; nk < SNOVA_o; nk++)
									for (int i1 = 0; i1 < SNOVA_l; i1++) {
										bs_window(win, sum_t0[k1], b1 * SNOVA_r, i1 * SNOVA_r);
										bs_mul_acc(whipped_F21[b1 * SNOVA_o + nk], win,
										           (uint8_t)T12_GET((ni * SNOVA_o + nk) * SNOVA_l2 + i1 * SNOVA_l + k1));
									}
					}

					SNOVA_SECURE_CLEAR(sum_t0);
					SNOVA_SECURE_CLEAR(F12);
				}

				// Right
				for (int nj = 0; nj < SNOVA_v; ++nj)
					for (int idx = 0; idx < SNOVA_o; idx++) {
						BS_PK_T P12b[SNOVA_l2];
#if !PUB_REORDER
						snova_pk_expander_squeeze(P12b, SNOVA_l2, &p12_instance);
#else
						snova_pk_expander_squeeze(P12b, SNOVA_l2, &instance);
#endif
						for (int i1 = 0; i1 < SNOVA_l; i1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++)
								bs_mul_acc(whipped_F12[i1 * SNOVA_o + idx], whipped_sig[k1 * SNOVA_v + nj],
								           (uint8_t)P12b[k1 * SNOVA_l + i1]);
					}

				for (int idx = 0; idx < SNOVA_o; idx++)
					for (int nj = 0; nj < SNOVA_v; ++nj) {
						BS_PK_T P21b[SNOVA_l2];
#if !PUB_REORDER
						snova_pk_expander_squeeze(P21b, SNOVA_l2, &p21_instance);
#else
						snova_pk_expander_squeeze(P21b, SNOVA_l2, &instance);
#endif
						for (int b1 = 0; b1 < SNOVA_l; ++b1)
							for (int i1 = 0; i1 < SNOVA_l; i1++)
								for (int k1 = 0; k1 < SNOVA_l; k1++) {
									bs_window(win, whipped_sig[k1 * SNOVA_v + nj], b1 * SNOVA_r, i1 * SNOVA_r);
									bs_mul_acc(whipped_F21[b1 * SNOVA_o + idx], win, (uint8_t)P21b[i1 * SNOVA_l + k1]);
								}
					}

				/**
				 * Alpha loop: tinymem's, reading the sliced rows element by element.
				 */
				uint16_t gfm_temp0[SNOVA_o * SNOVA_lr + 1];
				uint16_t gfm_temp1[SNOVA_o * SNOVA_lr + 1];
				uint16_t gfm_temp2[SNOVA_o * SNOVA_lr + 1];
				uint16_t Q12[SNOVA_l2];

				for (int alpha = 0; alpha < SNOVA_alpha; ++alpha) {
					int mi = (mi_prime + SNOVA_m1 * SNOVA_alpha - alpha) % SNOVA_m1;

					if (mi >= SNOVA_o) {
						continue;
					}

					memset(gfm_temp0, 0, sizeof(gfm_temp0));
					memset(gfm_temp1, 0, sizeof(gfm_temp1));
					memset(gfm_temp2, 0, sizeof(gfm_temp2));

					for (int a1 = 0; a1 < SNOVA_l; ++a1) {
						memset(gfm_temp0, 0, sizeof(gfm_temp0));

						for (int b1 = 0; b1 < SNOVA_l; ++b1)
							for (int i1 = 0; i1 < SNOVA_r; i1++)
								for (int j1 = 0; j1 < SNOVA_r; j1++)
									gfm_temp0[i1 * SNOVA_r + j1] ^= bs_get(sum_t1[a1 * SNOVA_r + i1], b1 * SNOVA_r + j1) *
									                                fixedq2[(mi * SNOVA_alpha + alpha) * SNOVA_l + b1];

						for (int i1 = 0; i1 < SNOVA_r2; i1++) {
							gfm_temp0[i1] = gf16_compress(gfm_temp0[i1]);
						}

						for (int i1 = 0; i1 < SNOVA_r2; i1++) {
							gfm_temp1[i1] ^= gfm_temp0[i1] * fixedq1[(mi * SNOVA_alpha + alpha) * SNOVA_l + a1];
						}
					}

					for (int i1 = 0; i1 < SNOVA_r2; i1++) {
						gfm_temp1[i1] = gf16_compress(gfm_temp1[i1]);
					}

					for (int i1 = 0; i1 < SNOVA_r; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++)
							for (int k1 = 0; k1 < SNOVA_r; k1++) {
								gfm_temp2[i1 * SNOVA_l + j1] ^=
								    gfm_temp1[i1 * SNOVA_r + k1] * fixedBm[(mi * SNOVA_alpha + alpha) * SNOVA_lr + k1 * SNOVA_l + j1];
							}

					for (int i1 = 0; i1 < SNOVA_lr; i1++) {
						gfm_temp2[i1] = gf16_compress(gfm_temp2[i1]);
					}

					for (int i1 = 0; i1 < SNOVA_r; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++)
							for (int k1 = 0; k1 < SNOVA_r; k1++) {
								g_xor(gauss[mi * SNOVA_lr + i1 * SNOVA_l + j1], GN,
								      gf16_compress(fixedAm[(mi * SNOVA_alpha + alpha) * SNOVA_r2 + i1 * SNOVA_r + k1] *
								                    gfm_temp2[k1 * SNOVA_l + j1]));
							}
				}

				for (int alpha = 0; alpha < SNOVA_alpha; ++alpha) {
					int mi = (mi_prime + SNOVA_m1 * SNOVA_alpha - alpha) % SNOVA_m1;

					if (mi >= SNOVA_o) {
						continue;
					}

					memset(gfm_temp0, 0, sizeof(gfm_temp0));
					memset(gfm_temp1, 0, sizeof(gfm_temp1));
					memset(gfm_temp2, 0, sizeof(gfm_temp2));

					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int idx = 0; idx < SNOVA_o; idx++)
							for (int b1 = 0; b1 < SNOVA_l; ++b1)
								for (int j1 = 0; j1 < SNOVA_r; j1++)
									gfm_temp0[idx * SNOVA_lr + i1 * SNOVA_r + j1] ^=
									    bs_get(whipped_F12[i1 * SNOVA_o + idx], b1 * SNOVA_r + j1) *
									    fixedq1[(mi * SNOVA_alpha + alpha) * SNOVA_l + b1];

					for (int i1 = 0; i1 < SNOVA_o * SNOVA_lr; i1++) {
						gfm_temp0[i1] = gf16_compress(gfm_temp0[i1]);
					}

					for (int idx = 0; idx < SNOVA_o; idx++)
						for (int i1 = 0; i1 < SNOVA_r; i1++)
							for (int j1 = 0; j1 < SNOVA_l; j1++)
								for (int k1 = 0; k1 < SNOVA_r; k1++)
									gfm_temp1[idx * SNOVA_lr + i1 * SNOVA_l + j1] ^=
									    fixedAm[(mi * SNOVA_alpha + alpha) * SNOVA_r2 + i1 * SNOVA_r + k1] *
									    gfm_temp0[idx * SNOVA_lr + j1 * SNOVA_r + k1];

					for (int i1 = 0; i1 < SNOVA_o * SNOVA_lr; i1++) {
						gfm_temp1[i1] = gf16_compress(gfm_temp1[i1]);
					}

					for (int i1 = 0; i1 < SNOVA_l2; i1++) {
						sum = 0;
						for (int j1 = 0; j1 < SNOVA_l; j1++) {
							sum ^= fixedq2[(mi * SNOVA_alpha + alpha) * SNOVA_l + j1] * gf_S[j1 * SNOVA_l2 + i1];
						}
						Q12[i1] = gf16_expand(gf16_compress(sum));
					}

					for (int idx = 0; idx < SNOVA_o; idx++)
						for (int i1 = 0; i1 < SNOVA_r; i1++)
							for (int j1 = 0; j1 < SNOVA_l; j1++)
								for (int k1 = 0; k1 < SNOVA_l; k1++) {
									gfm_temp2[idx * SNOVA_lr + i1 * SNOVA_l + j1] ^=
									    gfm_temp1[idx * SNOVA_lr + i1 * SNOVA_l + k1] * Q12[k1 * SNOVA_l + j1];
								}

					for (int i1 = 0; i1 < SNOVA_o * SNOVA_lr; i1++) {
						gfm_temp2[i1] = gf16_compress(gfm_temp2[i1]);
					}

					for (int idx = 0; idx < SNOVA_o; idx++)
						for (int ti1 = 0; ti1 < SNOVA_r; ti1++)
							for (int ti2 = 0; ti2 < SNOVA_l; ti2++)
								for (int tj2 = 0; tj2 < SNOVA_r; tj2++)
									for (int tj1 = 0; tj1 < SNOVA_l; tj1++)
										g_xor(gauss[mi * SNOVA_lr + ti1 * SNOVA_l + ti2], idx * SNOVA_lr + tj1 * SNOVA_r + tj2,
										      gf16_compress(gfm_temp2[idx * SNOVA_lr + ti1 * SNOVA_l + tj1] *
										                    fixedBm[(mi * SNOVA_alpha + alpha) * SNOVA_lr + tj2 * SNOVA_l + ti2]));

					memset(gfm_temp0, 0, sizeof(gfm_temp0));
					memset(gfm_temp1, 0, sizeof(gfm_temp1));
					memset(gfm_temp2, 0, sizeof(gfm_temp2));

					for (int idx = 0; idx < SNOVA_o; idx++)
						for (int b1 = 0; b1 < SNOVA_l; ++b1)
							for (int i1 = 0; i1 < SNOVA_l; i1++)
								for (int j1 = 0; j1 < SNOVA_r; j1++)
									gfm_temp0[idx * SNOVA_lr + i1 * SNOVA_r + j1] ^=
									    bs_get(whipped_F21[b1 * SNOVA_o + idx], i1 * SNOVA_r + j1) *
									    fixedq2[(mi * SNOVA_alpha + alpha) * SNOVA_l + b1];

					for (int i1 = 0; i1 < SNOVA_o * SNOVA_lr; i1++) {
						gfm_temp0[i1] = gf16_compress(gfm_temp0[i1]);
					}

					for (int idx = 0; idx < SNOVA_o; idx++)
						for (int i1 = 0; i1 < SNOVA_l; i1++)
							for (int j1 = 0; j1 < SNOVA_l; j1++)
								for (int k1 = 0; k1 < SNOVA_r; k1++) {
									gfm_temp1[idx * SNOVA_l2 + i1 * SNOVA_l + j1] ^=
									    gfm_temp0[idx * SNOVA_lr + i1 * SNOVA_r + k1] *
									    fixedBm[(mi * SNOVA_alpha + alpha) * SNOVA_lr + k1 * SNOVA_l + j1];
								}

					for (int i1 = 0; i1 < SNOVA_o * SNOVA_l2; i1++) {
						gfm_temp1[i1] = gf16_compress(gfm_temp1[i1]);
					}

					for (int i1 = 0; i1 < SNOVA_l2; i1++) {
						sum = 0;
						for (int j1 = 0; j1 < SNOVA_l; j1++) {
							sum ^= fixedq1[(mi * SNOVA_alpha + alpha) * SNOVA_l + j1] * gf_S[j1 * SNOVA_l2 + i1];
						}
						Q12[i1] = gf16_expand(gf16_compress(sum));
					}

					for (int idx = 0; idx < SNOVA_o; idx++)
						for (int i1 = 0; i1 < SNOVA_l; i1++)
							for (int j1 = 0; j1 < SNOVA_l; j1++)
								for (int k1 = 0; k1 < SNOVA_l; k1++) {
									gfm_temp2[idx * SNOVA_l2 + i1 * SNOVA_l + j1] ^=
									    Q12[i1 * SNOVA_l + k1] * gfm_temp1[idx * SNOVA_l2 + k1 * SNOVA_l + j1];
								}

					for (int i1 = 0; i1 < SNOVA_o * SNOVA_l2; i1++) {
						gfm_temp2[i1] = gf16_compress(gfm_temp2[i1]);
					}

					for (int idx = 0; idx < SNOVA_o; idx++)
						for (int ti1 = 0; ti1 < SNOVA_r; ti1++)
							for (int ti2 = 0; ti2 < SNOVA_l; ti2++)
								for (int tj2 = 0; tj2 < SNOVA_r; tj2++)
									for (int tj1 = 0; tj1 < SNOVA_l; tj1++)
										g_xor(gauss[mi * SNOVA_lr + ti1 * SNOVA_l + ti2], idx * SNOVA_lr + tj1 * SNOVA_r + tj2,
										      gf16_compress(gfm_temp2[idx * SNOVA_l2 + tj1 * SNOVA_l + ti2] *
										                    fixedAm[(mi * SNOVA_alpha + alpha) * SNOVA_r2 + ti1 * SNOVA_r + tj2]));
				}

				SNOVA_SECURE_CLEAR(gfm_temp0);
				SNOVA_SECURE_CLEAR(gfm_temp1);
				SNOVA_SECURE_CLEAR(gfm_temp2);
				SNOVA_SECURE_CLEAR(Q12);
			}

			SNOVA_SECURE_CLEAR(sum_t1);
			SNOVA_SECURE_CLEAR(whipped_F12);
			SNOVA_SECURE_CLEAR(whipped_F21);
			SNOVA_SECURE_CLEAR(win);
			SNOVA_SECURE_CLEARI(sum);

			snova_pk_expander_free(&instance);
#if !PUB_REORDER
			snova_pk_expander_free(&p12_instance);
			snova_pk_expander_free(&p21_instance);
#endif
		}

		/**
		 * Gaussian elimination in constant time, on sliced rows.
		 */
		uint16_t t_GF16;
		uint16_t fact;

		for (int i = 0; i < GN; ++i) {
			for (int j = i + 1; j < GN; ++j) {
				uint32_t mask = (uint32_t)ct_is_not_zero(g_get(gauss[i], i)) - 1u;
				for (int p = 0; p < 4; p++)
					for (int w = 0; w < GW; w++) {
						gauss[i][p][w] ^= mask & gauss[j][p][w];
					}
			}

			uint8_t pivot = g_get(gauss[i], i);
			flag_redo |= 1 - ct_is_not_zero(pivot);

			fact = pivot * gf16_expand(pivot);
			fact = gf16_compress(fact);
			t_GF16 = fact;

			fact = fact * gf16_expand(fact);
			fact = gf16_compress(fact);
			t_GF16 = t_GF16 * gf16_expand(fact);
			t_GF16 = gf16_compress(t_GF16);

			fact = fact * gf16_expand(fact);
			fact = gf16_compress(fact);
			t_GF16 = t_GF16 * gf16_expand(fact);
			t_GF16 = gf16_compress(t_GF16);

			{
				uint32_t row[4][GW];
				memcpy(row, gauss[i], sizeof(row));
				memset(gauss[i], 0, sizeof(row));
				g_mul_acc(gauss[i], row, (uint8_t)t_GF16);
				SNOVA_SECURE_CLEAR(row);
			}

			for (int j = i + 1; j < GN; ++j) {
				g_mul_acc(gauss[j], gauss[i], g_get(gauss[j], i));
			}
		}

		SNOVA_SECURE_CLEARI(t_GF16);
		SNOVA_SECURE_CLEARI(fact);

		if (flag_redo) {
			continue;
		}

		uint8_t solution[GN + 1] = {0};
		uint16_t solution16[GN] = {0};
		uint16_t sum;

		for (int i = GN - 1; i >= 0; --i) {
			sum = 0;
			for (int k = i + 1; k < GN; ++k) {
				sum ^= g_get(gauss[i], k) * solution16[k];
			}
			solution16[i] = gf16_expand(gf16_compress(sum ^ g_get(gauss[i], GN)));
		}
		for (int i = 0; i < GN; i++) {
			solution[i] = gf16_compress(solution16[i]);
		}

		memcpy(signature_in_GF + SNOVA_v * SNOVA_lr, solution, GN);

		for (int index = 0; index < SNOVA_v; ++index)
			for (int mi = 0; mi < SNOVA_o; ++mi)
				for (int i1 = 0; i1 < SNOVA_l; i1++)
					for (int j1 = 0; j1 < SNOVA_r; j1++) {
						sum = 0;
						for (int k1 = 0; k1 < SNOVA_l; k1++) {
							sum ^= gf16_expand(T12_GET((index * SNOVA_o + mi) * SNOVA_l2 + i1 * SNOVA_l + k1)) *
							       solution[mi * SNOVA_lr + k1 * SNOVA_r + j1];
						}
						signature_in_GF[index * SNOVA_lr + i1 * SNOVA_r + j1] ^= gf16_compress(sum);
					}

		memcpy(signature_in_GF + SNOVA_v * SNOVA_lr, solution, GN);

		SNOVA_SECURE_CLEAR(gauss);
		SNOVA_SECURE_CLEAR(whipped_sig);
		SNOVA_SECURE_CLEAR(solution);
		SNOVA_SECURE_CLEAR(solution16);
		SNOVA_SECURE_CLEARI(sum);

		break;
	}

	SNOVA_SECURE_CLEAR(T12);

	compress_gf(sig, signature_in_GF, SNOVA_n * SNOVA_lr);
	memcpy(sig + BYTES_SIGNATURE - BYTES_SALT, salt, BYTES_SALT);

	return 0;
}
