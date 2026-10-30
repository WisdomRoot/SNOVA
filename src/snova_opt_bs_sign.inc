// SIGN_BITSLICE: opt's sign (its portable path), on sliced lanes.
//
// GF(16) = GF(2)[t]/(t^4 + t + 1), nibble bit k is the coefficient of t^k. A run
// of elements is four plane words, plane k carrying bit k of every element.
// whipped_sig, sum_t0, sum_t1, whipped_F12 and whipped_F21 are runs of SNOVA_lr
// elements (one bs_t per plane). gausstmp1, gausstmp2 and the Gauss matrix rows
// are runs of SNOVA_o * SNOVA_lr + 1 elements over GW 32-bit words per plane.
// sum_t1s and whipped_F12s, opt's transposed copies, are not kept: their reads
// go to the sliced rows directly.

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

int SNOVA_NAMESPACE(sign)(const expanded_SK *skx, uint8_t *sig, const uint8_t *digest, const size_t len_digest,
                          const uint8_t *salt) {
	SNOVA_INIT

#if FIXED_ABQ
#define Am fixedAm
#define Bm fixedBm
#define Q1 fixedQ1
#define Q2 fixedQ2
#define q1 fixedq1
#define q2 fixedq2
#else
#define Am skx->Am
#define Bm skx->Bm
#define Q1 skx->Q1
#define Q2 skx->Q2
#define q1 skx->q1
#define q2 skx->q2
#endif

	uint8_t hash_in_GF16[GF16_HASH];

	uint8_t sign_hashb[BYTES_HASH];
#if HASH_PK
	hash_combined(sign_hashb, digest, len_digest, skx->pk_hash, salt);
#else
	hash_combined(sign_hashb, digest, len_digest, skx->pk_seed, salt);
#endif
	convert_bytes_to_GF(hash_in_GF16, sign_hashb, GF16_HASH);

	uint8_t signature_in_GF[SNOVA_n * SNOVA_lr];
	uint8_t num_sign = 0;

	while (1) {
		num_sign++;
		if (num_sign == 255) {
			memset(sig, 0, BYTES_SIGNATURE);
			return -1;
		}

		int flag_redo = 0;

		uint8_t solution[GN + 1] = {0};
		uint32_t gauss[GN][4][GW];

		uint8_t vinegar_in_byte[NUM_GEN_SEC_BYTES];
		uint16_t Fvv_in_GF16Matrix[GN] = {0};

		// Row (i1 * SNOVA_v + ni), lane ab * SNOVA_r + j1: opt's whipped_sig layout.
		bs_t whipped_sig[SNOVA_l * SNOVA_v][4];
		bs_t sum_t0[SNOVA_l][4];
		// Row ((mi * SNOVA_l + a1) * SNOVA_r + i1), lane b1.
		bs_t sum_t1[SNOVA_m1 * SNOVA_l * SNOVA_r][4];
		// Row ((mi * SNOVA_r + ti1) * SNOVA_r + tj2), lane idx: opt's gausstmp rows, mi < SNOVA_o.
		uint32_t gausstmp1[SNOVA_o * SNOVA_r * SNOVA_r][4][GW];
		uint32_t gausstmp2[SNOVA_o * SNOVA_r * SNOVA_r][4][GW];

		uint16_t gfm_temp0[SNOVA_r2];
		uint16_t gfm_temp1[SNOVA_r2];
		uint16_t gfm_temp2[SNOVA_lr];

		// Row ((mi * SNOVA_l + b1) * SNOVA_o + idx) of whipped_F21, lane i1 * SNOVA_r + j1.
		// Row ((mi * SNOVA_l + i1) * SNOVA_o + idx) of whipped_F12, lane b1.
		bs_t whipped_F21[SNOVA_m1 * SNOVA_l * SNOVA_o][4];
		bs_t whipped_F12[SNOVA_m1 * SNOVA_l * SNOVA_o][4];
		bs_t win[4];

		uint16_t coef_temp0[GN];
		uint16_t coef_temp1[GN];
		uint16_t coef_temp2[GN];
		uint32_t crow[4][GW];

		uint16_t t_GF16;
		uint16_t fact;
		uint16_t solution16[GN] = {0};

		shake_t v_instance;

		memset(gauss, 0, sizeof(gauss));
		memset(whipped_sig, 0, sizeof(whipped_sig));
		memset(sum_t1, 0, sizeof(sum_t1));
		memset(gausstmp1, 0, sizeof(gausstmp1));
		memset(gausstmp2, 0, sizeof(gausstmp2));
		memset(whipped_F21, 0, sizeof(whipped_F21));
		memset(whipped_F12, 0, sizeof(whipped_F12));

		shake256_init(&v_instance);
		shake_absorb(&v_instance, skx->sk_seed, SEED_LENGTH_PRIVATE);
		shake_absorb(&v_instance, digest, BYTES_DIGEST);
		shake_absorb(&v_instance, salt, BYTES_SALT);
		shake_absorb(&v_instance, &num_sign, 1);
		shake_finalize(&v_instance);
		shake_squeeze(vinegar_in_byte, NUM_GEN_SEC_BYTES, &v_instance);

		convert_bytes_to_GF(signature_in_GF, vinegar_in_byte, SNOVA_v * SNOVA_lr);

		for (int ni = 0; ni < SNOVA_v; ++ni)
			for (int i1 = 0; i1 < SNOVA_l; i1++) {
				bs_t *row = whipped_sig[i1 * SNOVA_v + ni];
				for (int ab = 0; ab < SNOVA_l; ++ab)
					for (int j1 = 0; j1 < SNOVA_r; j1++) {
						uint16_t acc = 0;
						for (int k1 = 0; k1 < SNOVA_l; k1++)
							acc ^= gf_Sx[ab * SNOVA_l2 + i1 * SNOVA_l + k1] * signature_in_GF[ni * SNOVA_lr + k1 * SNOVA_r + j1];
						uint8_t val = gf16_compress(acc);
						int c = ab * SNOVA_r + j1;
						row[0] |= (bs_t)((bs_t)(val & 1) << c);
						row[1] |= (bs_t)((bs_t)((val >> 1) & 1) << c);
						row[2] |= (bs_t)((bs_t)((val >> 2) & 1) << c);
						row[3] |= (bs_t)((bs_t)((val >> 3) & 1) << c);
					}
			}

		/**
		 * Evaluate whipped central map
		 */
		for (int mi = 0; mi < SNOVA_m1; ++mi)
			for (int ni = 0; ni < SNOVA_v; ++ni) {
				memset(sum_t0, 0, sizeof(sum_t0));
				for (int nj = 0; nj < SNOVA_v; ++nj)
					for (int k1 = 0; k1 < SNOVA_l; k1++)
						for (int i1 = 0; i1 < SNOVA_l; i1++)
							bs_mul_acc(sum_t0[i1], whipped_sig[k1 * SNOVA_v + nj],
							           (uint8_t)skx->P11[((mi * SNOVA_v + ni) * SNOVA_v + nj) * SNOVA_l2 + i1 * SNOVA_l + k1]);

				for (int a1 = 0; a1 < SNOVA_l; ++a1)
					for (int k1 = 0; k1 < SNOVA_l; k1++)
						for (int i1 = 0; i1 < SNOVA_r; i1++)
							bs_mul_acc(sum_t1[(mi * SNOVA_l + a1) * SNOVA_r + i1], sum_t0[k1],
							           bs_get(whipped_sig[k1 * SNOVA_v + ni], a1 * SNOVA_r + i1));
			}

		/**
		 * Apply A, B, q1 and q2, aka E matrix
		 */
		for (int mi = 0; mi < SNOVA_o; ++mi)
			for (int alpha = 0; alpha < SNOVA_alpha; ++alpha) {
				int mi_prime = i_prime(mi, alpha);

				memset(gfm_temp1, 0, sizeof(gfm_temp1));
				memset(gfm_temp2, 0, sizeof(gfm_temp2));

				for (int a1 = 0; a1 < SNOVA_l; ++a1) {
					memset(gfm_temp0, 0, sizeof(gfm_temp0));

					for (int b1 = 0; b1 < SNOVA_l; ++b1)
						for (int i1 = 0; i1 < SNOVA_r; i1++)
							for (int j1 = 0; j1 < SNOVA_r; j1++)
								gfm_temp0[i1 * SNOVA_r + j1] ^=
								    bs_get(sum_t1[(mi_prime * SNOVA_l + a1) * SNOVA_r + i1], b1 * SNOVA_r + j1) *
								    q2[(mi * SNOVA_alpha + alpha) * SNOVA_l + b1];

					for (int i1 = 0; i1 < SNOVA_r2; i1++) {
						gfm_temp0[i1] = gf16_compress(gfm_temp0[i1]);
					}

					for (int i1 = 0; i1 < SNOVA_r2; i1++) {
						gfm_temp1[i1] ^= gfm_temp0[i1] * q1[(mi * SNOVA_alpha + alpha) * SNOVA_l + a1];
					}
				}

				for (int i1 = 0; i1 < SNOVA_r2; i1++) {
					gfm_temp1[i1] = gf16_compress(gfm_temp1[i1]);
				}

				for (int i1 = 0; i1 < SNOVA_r; i1++)
					for (int j1 = 0; j1 < SNOVA_l; j1++)
						for (int k1 = 0; k1 < SNOVA_r; k1++) {
							gfm_temp2[i1 * SNOVA_l + j1] ^=
							    gfm_temp1[i1 * SNOVA_r + k1] * Bm[(mi * SNOVA_alpha + alpha) * SNOVA_lr + k1 * SNOVA_l + j1];
						}

				for (int i1 = 0; i1 < SNOVA_lr; i1++) {
					gfm_temp2[i1] = gf16_compress(gfm_temp2[i1]);
				}

				for (int i1 = 0; i1 < SNOVA_r; i1++)
					for (int j1 = 0; j1 < SNOVA_l; j1++)
						for (int k1 = 0; k1 < SNOVA_r; k1++) {
							Fvv_in_GF16Matrix[mi * SNOVA_lr + i1 * SNOVA_l + j1] ^=
							    Am[(mi * SNOVA_alpha + alpha) * SNOVA_r2 + i1 * SNOVA_r + k1] * gfm_temp2[k1 * SNOVA_l + j1];
						}
			}

		// The last column of the Gauss matrix
		for (int i1 = 0; i1 < GN; i1++) {
			g_xor(gauss[i1], GN, (uint8_t)(hash_in_GF16[i1] ^ gf16_compress(Fvv_in_GF16Matrix[i1])));
		}

		// Whipped F21
		for (int mi = 0; mi < SNOVA_m1; mi++)
			for (int idx = 0; idx < SNOVA_o; idx++)
				for (int b1 = 0; b1 < SNOVA_l; ++b1)
					for (int nj = 0; nj < SNOVA_v; ++nj)
						for (int i1 = 0; i1 < SNOVA_l; i1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++) {
								bs_window(win, whipped_sig[k1 * SNOVA_v + nj], b1 * SNOVA_r, i1 * SNOVA_r);
								bs_mul_acc(whipped_F21[(mi * SNOVA_l + b1) * SNOVA_o + idx], win,
								           (uint8_t)skx->F21[((mi * SNOVA_o + idx) * SNOVA_v + nj) * SNOVA_l2 + i1 * SNOVA_l + k1]);
							}

		// Whipped F12
		for (int mi = 0; mi < SNOVA_m1; mi++)
			for (int nj = 0; nj < SNOVA_v; ++nj)
				for (int idx = 0; idx < SNOVA_o; idx++)
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int k1 = 0; k1 < SNOVA_l; k1++)
							bs_mul_acc(whipped_F12[(mi * SNOVA_l + i1) * SNOVA_o + idx], whipped_sig[k1 * SNOVA_v + nj],
							           (uint8_t)skx->F12[((mi * SNOVA_v + nj) * SNOVA_o + idx) * SNOVA_l2 + k1 * SNOVA_l + i1]);

		for (int mi = 0; mi < SNOVA_o; mi++)
			for (int alpha = 0; alpha < SNOVA_alpha; alpha++) {
				memset(coef_temp0, 0, sizeof(coef_temp0));
				memset(coef_temp1, 0, sizeof(coef_temp1));
				memset(coef_temp2, 0, sizeof(coef_temp2));

				int mi_prime = i_prime(mi, alpha);

				for (int idx = 0; idx < SNOVA_o; idx++)
					for (int b1 = 0; b1 < SNOVA_l; ++b1)
						for (int i1 = 0; i1 < SNOVA_l; i1++)
							for (int j1 = 0; j1 < SNOVA_r; j1++)
								coef_temp0[idx * SNOVA_lr + i1 * SNOVA_r + j1] ^=
								    bs_get(whipped_F21[(mi_prime * SNOVA_l + b1) * SNOVA_o + idx], i1 * SNOVA_r + j1) *
								    q2[(mi * SNOVA_alpha + alpha) * SNOVA_l + b1];

				for (int i1 = 0; i1 < GN; i1++) {
					coef_temp0[i1] = gf16_compress(coef_temp0[i1]);
				}

				for (int idx = 0; idx < SNOVA_o; idx++)
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++)
							for (int k1 = 0; k1 < SNOVA_r; k1++) {
								coef_temp1[idx * SNOVA_l2 + i1 * SNOVA_l + j1] ^=
								    coef_temp0[idx * SNOVA_lr + i1 * SNOVA_r + k1] *
								    Bm[(mi * SNOVA_alpha + alpha) * SNOVA_lr + k1 * SNOVA_l + j1];
							}

				for (int i1 = 0; i1 < SNOVA_o * SNOVA_l2; i1++) {
					coef_temp1[i1] = gf16_compress(coef_temp1[i1]);
				}

				for (int idx = 0; idx < SNOVA_o; idx++)
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++)
								coef_temp2[idx * SNOVA_l2 + i1 * SNOVA_l + j1] ^=
								    Q1[(mi * SNOVA_alpha + alpha) * SNOVA_l2 + i1 * SNOVA_l + k1] *
								    coef_temp1[idx * SNOVA_l2 + k1 * SNOVA_l + j1];

				memset(crow, 0, sizeof(crow));
				for (int i1 = 0; i1 < SNOVA_o * SNOVA_l2; i1++) {
					g_xor(crow, i1, (uint8_t)gf16_compress(coef_temp2[i1]));
				}

				for (int ti1 = 0; ti1 < SNOVA_r; ti1++)
					for (int tj2 = 0; tj2 < SNOVA_r; tj2++)
						g_mul_acc(gausstmp1[(mi * SNOVA_r + ti1) * SNOVA_r + tj2], crow,
						          (uint8_t)gf16_compress(Am[(mi * SNOVA_alpha + alpha) * SNOVA_r2 + ti1 * SNOVA_r + tj2]));
			}

		for (int mi = 0; mi < SNOVA_o; mi++)
			for (int idx = 0; idx < SNOVA_o; idx++)
				for (int ti1 = 0; ti1 < SNOVA_r; ti1++)
					for (int ti2 = 0; ti2 < SNOVA_l; ti2++)
						for (int tj1 = 0; tj1 < SNOVA_l; tj1++)
							for (int tj2 = 0; tj2 < SNOVA_r; tj2++)
								g_xor(gauss[mi * SNOVA_lr + ti1 * SNOVA_l + ti2], idx * SNOVA_lr + tj1 * SNOVA_r + tj2,
								      g_get(gausstmp1[(mi * SNOVA_r + ti1) * SNOVA_r + tj2], idx * SNOVA_l2 + tj1 * SNOVA_l + ti2));

		for (int mi = 0; mi < SNOVA_o; mi++) {
			for (int alpha = 0; alpha < SNOVA_alpha; alpha++) {
				memset(coef_temp0, 0, sizeof(coef_temp0));
				memset(coef_temp1, 0, sizeof(coef_temp1));
				memset(coef_temp2, 0, sizeof(coef_temp2));

				int mi_prime = i_prime(mi, alpha);

				// Transpose: opt's whipped_F12s[(mi' * l + b1) * olr + idx * lr + i1 * r + j1]
				for (int b1 = 0; b1 < SNOVA_l; ++b1)
					for (int idx = 0; idx < SNOVA_o; idx++)
						for (int i1 = 0; i1 < SNOVA_l; i1++)
							for (int j1 = 0; j1 < SNOVA_r; j1++)
								coef_temp0[idx * SNOVA_lr + i1 * SNOVA_r + j1] ^=
								    bs_get(whipped_F12[(mi_prime * SNOVA_l + i1) * SNOVA_o + idx], b1 * SNOVA_r + j1) *
								    q1[(mi * SNOVA_alpha + alpha) * SNOVA_l + b1];

				for (int i1 = 0; i1 < GN; i1++) {
					coef_temp0[i1] = gf16_compress(coef_temp0[i1]);
				}

				for (int idx = 0; idx < SNOVA_o; idx++)
					for (int i1 = 0; i1 < SNOVA_r; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++)
							for (int k1 = 0; k1 < SNOVA_r; k1++)
								coef_temp1[idx * SNOVA_lr + i1 * SNOVA_l + j1] ^=
								    Am[(mi * SNOVA_alpha + alpha) * SNOVA_r2 + i1 * SNOVA_r + k1] *
								    coef_temp0[idx * SNOVA_lr + j1 * SNOVA_r + k1];

				for (int i1 = 0; i1 < GN; i1++) {
					coef_temp1[i1] = gf16_compress(coef_temp1[i1]);
				}

				for (int idx = 0; idx < SNOVA_o; idx++)
					for (int i1 = 0; i1 < SNOVA_r; i1++)
						for (int j1 = 0; j1 < SNOVA_l; j1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++)
								coef_temp2[idx * SNOVA_lr + i1 * SNOVA_l + j1] ^=
								    coef_temp1[idx * SNOVA_lr + i1 * SNOVA_l + k1] *
								    Q2[(mi * SNOVA_alpha + alpha) * SNOVA_l2 + k1 * SNOVA_l + j1];

				memset(crow, 0, sizeof(crow));
				for (int i1 = 0; i1 < GN; i1++) {
					g_xor(crow, i1, (uint8_t)gf16_compress(coef_temp2[i1]));
				}

				for (int ti2 = 0; ti2 < SNOVA_l; ti2++)
					for (int tj2 = 0; tj2 < SNOVA_r; tj2++)
						g_mul_acc(gausstmp2[(mi * SNOVA_r + ti2) * SNOVA_r + tj2], crow,
						          (uint8_t)gf16_compress(Bm[(mi * SNOVA_alpha + alpha) * SNOVA_lr + tj2 * SNOVA_l + ti2]));
			}
		}

		for (int mi = 0; mi < SNOVA_o; mi++)
			for (int idx = 0; idx < SNOVA_o; idx++)
				for (int ti1 = 0; ti1 < SNOVA_r; ti1++)
					for (int ti2 = 0; ti2 < SNOVA_l; ti2++)
						for (int tj1 = 0; tj1 < SNOVA_l; tj1++)
							for (int tj2 = 0; tj2 < SNOVA_r; tj2++)
								g_xor(gauss[mi * SNOVA_lr + ti1 * SNOVA_l + ti2], idx * SNOVA_lr + tj1 * SNOVA_r + tj2,
								      g_get(gausstmp2[(mi * SNOVA_r + ti2) * SNOVA_r + tj2], idx * SNOVA_lr + ti1 * SNOVA_l + tj1));

		// Gaussian elimination in constant time, on sliced rows
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

			memcpy(crow, gauss[i], sizeof(crow));
			memset(gauss[i], 0, sizeof(crow));
			g_mul_acc(gauss[i], crow, (uint8_t)t_GF16);

			for (int j = i + 1; j < GN; ++j) {
				g_mul_acc(gauss[j], gauss[i], g_get(gauss[j], i));
			}
		}

		if (flag_redo) {
			continue;
		}

		for (int i = GN - 1; i >= 0; --i) {
			t_GF16 = 0;
			for (int k = i + 1; k < GN; ++k) {
				t_GF16 ^= g_get(gauss[i], k) * solution16[k];
			}
			t_GF16 ^= g_get(gauss[i], GN);
			t_GF16 = gf16_compress(t_GF16);
			solution16[i] = gf16_expand(t_GF16);
		}
		for (int i = 0; i < GN; i++) {
			solution[i] = gf16_compress(solution16[i]);
		}

		memcpy(signature_in_GF + SNOVA_v * SNOVA_lr, solution, GN);

		for (int index = 0; index < SNOVA_v; ++index)
			for (int mi = 0; mi < SNOVA_o; ++mi)
				for (int i1 = 0; i1 < SNOVA_l; i1++)
					for (int j1 = 0; j1 < SNOVA_r; j1++) {
						t_GF16 = 0;
						for (int k1 = 0; k1 < SNOVA_l; k1++) {
							t_GF16 ^= skx->T12[(index * SNOVA_o + mi) * SNOVA_l2 + i1 * SNOVA_l + k1] *
							          solution[mi * SNOVA_lr + k1 * SNOVA_r + j1];
						}
						signature_in_GF[index * SNOVA_lr + i1 * SNOVA_r + j1] ^= gf16_compress(t_GF16);
					}

		memcpy(signature_in_GF + SNOVA_v * SNOVA_lr, solution, GN);

		SNOVA_SECURE_CLEAR(solution);
		SNOVA_SECURE_CLEAR(gauss);
		SNOVA_SECURE_CLEAR(vinegar_in_byte);
		SNOVA_SECURE_CLEAR(Fvv_in_GF16Matrix);
		SNOVA_SECURE_CLEAR(whipped_sig);
		SNOVA_SECURE_CLEAR(sum_t0);
		SNOVA_SECURE_CLEAR(sum_t1);
		SNOVA_SECURE_CLEAR(gausstmp1);
		SNOVA_SECURE_CLEAR(gausstmp2);
		SNOVA_SECURE_CLEAR(gfm_temp0);
		SNOVA_SECURE_CLEAR(gfm_temp1);
		SNOVA_SECURE_CLEAR(gfm_temp2);
		SNOVA_SECURE_CLEAR(whipped_F21);
		SNOVA_SECURE_CLEAR(whipped_F12);
		SNOVA_SECURE_CLEAR(win);
		SNOVA_SECURE_CLEAR(coef_temp0);
		SNOVA_SECURE_CLEAR(coef_temp1);
		SNOVA_SECURE_CLEAR(coef_temp2);
		SNOVA_SECURE_CLEAR(crow);
		SNOVA_SECURE_CLEARI(t_GF16);
		SNOVA_SECURE_CLEARI(fact);
		SNOVA_SECURE_CLEAR(solution16);
		SNOVA_SECURE_CLEARI(v_instance);

		break;
	}

	compress_gf(sig, signature_in_GF, SNOVA_n * SNOVA_lr);
	memcpy(sig + BYTES_SIGNATURE - BYTES_SALT, salt, BYTES_SALT);

	return 0;
}
