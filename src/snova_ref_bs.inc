// EXPAND_BITSLICE and SIGN_BITSLICE: the reference kernel's genkeys, its F12 and
// F21 in sign, and its sign.
//
// GF(16) = GF(2)[t]/(t^4 + t + 1), nibble bit k is the coefficient of t^k. A run
// of elements is held as four plane words, plane k carrying bit k of every
// element. A scalar times a run is acc ^= mask(c_k) & (x * t^k), so no index or
// branch depends on the scalar. q = 16 only.

#if SNOVA_q != 16
#error "the bit-sliced reference paths are GF(16) only"
#endif

#if EXPAND_BITSLICE
/**
 * expand-bitslice. T12 is held sliced two ways over o * l lanes, as in
 * snova_opt_bs_expand.inc:
 *
 *   T12a[a * l + i1], lane b * l + j1 = T12[(a * o + b) * l2 + i1 * l + j1]
 *   T12b[a * l + j1], lane b * l + i1 = T12[(a * o + b) * l2 + i1 * l + j1]
 */
#define XL (SNOVA_o * SNOVA_l)
_Static_assert(XL <= 32, "expand-bitslice packs o * l lanes into one word");

static inline uint8_t xs_get(const uint32_t *x, int c) {
	return (uint8_t)(((x[0] >> c) & 1) | (((x[1] >> c) & 1) << 1) | (((x[2] >> c) & 1) << 2) | (((x[3] >> c) & 1) << 3));
}

static inline void xs_xor(uint32_t *x, int c, uint8_t v) {
	x[0] ^= (uint32_t)(v & 1) << c;
	x[1] ^= (uint32_t)((v >> 1) & 1) << c;
	x[2] ^= (uint32_t)((v >> 2) & 1) << c;
	x[3] ^= (uint32_t)((v >> 3) & 1) << c;
}

// acc ^= c * x, lane by lane.
static inline void xs_mul_acc(uint32_t *acc, const uint32_t *x, uint8_t c) {
	uint32_t a0 = x[0], a1 = x[1], a2 = x[2], a3 = x[3], t;
	uint32_t m = 0u - (uint32_t)(c & 1);
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
		m = 0u - (uint32_t)((c >> k) & 1);
		acc[0] ^= m & a0;
		acc[1] ^= m & a1;
		acc[2] ^= m & a2;
		acc[3] ^= m & a3;
	}
}

static void ref_pack_T12(uint32_t T12a[SNOVA_v * SNOVA_l][4], uint32_t T12b[SNOVA_v * SNOVA_l][4], const gf_t *T12) {
	memset(T12a, 0, sizeof(uint32_t) * SNOVA_v * SNOVA_l * 4);
	memset(T12b, 0, sizeof(uint32_t) * SNOVA_v * SNOVA_l * 4);
	for (int a = 0; a < SNOVA_v; a++)
		for (int b = 0; b < SNOVA_o; b++)
			for (int i1 = 0; i1 < SNOVA_l; i1++)
				for (int j1 = 0; j1 < SNOVA_l; j1++) {
					gf_t val = T12[(a * SNOVA_o + b) * SNOVA_l2 + i1 * SNOVA_l + j1];
					xs_xor(T12a[a * SNOVA_l + i1], b * SNOVA_l + j1, val);
					xs_xor(T12b[a * SNOVA_l + j1], b * SNOVA_l + i1, val);
				}
}

/**
 * Reference genkey with sliced F12 and P22.
 */
int SNOVA_NAMESPACE(genkeys)(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
	if (first_time) {
		snova_init();
	}

	uint32_t T12a[SNOVA_v * SNOVA_l][4];
	uint32_t T12b[SNOVA_v * SNOVA_l][4];
	{
		gf_t T12[SNOVA_o * SNOVA_v * SNOVA_l2];
		expand_T12(T12, seed + SEED_LENGTH_PUBLIC);
		ref_pack_T12(T12a, T12b, T12);
	}

	gf_t P_matrix[NUM_PUB_GF];

	expand_public(P_matrix, seed);

	gf_t* P11 = P_matrix;
	gf_t* P12 = P_matrix + SNOVA_m1 * SNOVA_v * SNOVA_v * SNOVA_l2;
	gf_t* P21 = P_matrix + SNOVA_m1 * SNOVA_v * SNOVA_n * SNOVA_l2;

	// P22 row (mi, nk, i1), lane (ni, j1)
	uint32_t P22s[SNOVA_m1 * SNOVA_o * SNOVA_l][4];
	memset(P22s, 0, sizeof(P22s));

	for (int mi = 0; mi < SNOVA_m1; mi++)
		for (int nj = 0; nj < SNOVA_v; nj++) {
			// F12 row (mi, nj, k1), lane (ni, j1), including P12
			uint32_t F12[SNOVA_l][4];
			memset(F12, 0, sizeof(F12));

			for (int k1 = 0; k1 < SNOVA_l; k1++) {
				for (int nk = 0; nk < SNOVA_v; nk++)
					for (int kk = 0; kk < SNOVA_l; kk++)
						xs_mul_acc(F12[k1], T12a[nk * SNOVA_l + kk], P11[((mi * SNOVA_v + nj) * SNOVA_v + nk) * SNOVA_l2 + k1 * SNOVA_l + kk]);
				for (int ni = 0; ni < SNOVA_o; ni++)
					for (int j1 = 0; j1 < SNOVA_l; j1++)
						xs_xor(F12[k1], ni * SNOVA_l + j1, P12[((mi * SNOVA_v + nj) * SNOVA_o + ni) * SNOVA_l2 + k1 * SNOVA_l + j1]);
			}

			// P22[mi, nk, ni, i1, j1] ^= T12[nj, nk, i1, k1] * F12[mi, nj, ni, k1, j1]
			for (int nk = 0; nk < SNOVA_o; nk++)
				for (int i1 = 0; i1 < SNOVA_l; i1++)
					for (int k1 = 0; k1 < SNOVA_l; k1++)
						xs_mul_acc(P22s[(mi * SNOVA_o + nk) * SNOVA_l + i1], F12[k1], xs_get(T12b[nj * SNOVA_l + k1], nk * SNOVA_l + i1));
		}

	// P22[mi, nk, ni, i1, j1] ^= P21[mi, nk, nj, i1, k1] * T12[nj, ni, k1, j1]
	for (int mi = 0; mi < SNOVA_m1; mi++)
		for (int nk = 0; nk < SNOVA_o; nk++)
			for (int nj = 0; nj < SNOVA_v; nj++)
				for (int i1 = 0; i1 < SNOVA_l; i1++)
					for (int k1 = 0; k1 < SNOVA_l; k1++)
						xs_mul_acc(P22s[(mi * SNOVA_o + nk) * SNOVA_l + i1], T12a[nj * SNOVA_l + k1],
						           P21[((mi * SNOVA_o + nk) * SNOVA_v + nj) * SNOVA_l2 + i1 * SNOVA_l + k1]);

	gf_t P22[SNOVA_m1 * SNOVA_o * SNOVA_o * SNOVA_l2];
	for (int mi = 0; mi < SNOVA_m1; mi++)
		for (int nk = 0; nk < SNOVA_o; nk++)
			for (int ni = 0; ni < SNOVA_o; ni++)
				for (int i1 = 0; i1 < SNOVA_l; i1++)
					for (int j1 = 0; j1 < SNOVA_l; j1++)
						P22[((mi * SNOVA_o + nk) * SNOVA_o + ni) * SNOVA_l2 + i1 * SNOVA_l + j1] =
						    xs_get(P22s[(mi * SNOVA_o + nk) * SNOVA_l + i1], ni * SNOVA_l + j1);

	memcpy(pk, seed, SEED_LENGTH_PUBLIC);
	compress_pk(pk + SEED_LENGTH_PUBLIC, P22);
	memcpy(sk, seed, SEED_LENGTH_PUBLIC + SEED_LENGTH_PRIVATE);

#if HASH_PK
	shake256(sk + SEED_LENGTH_PUBLIC + SEED_LENGTH_PRIVATE, BYTES_PK_HASH, pk, BYTES_PK);
#endif

	return 0;
}

/**
 * Sign's F21 = P21 + T12 * P11 and F12 = P12 + P11 * T12, sliced.
 */
static void ref_bs_F12F21(gf_t *F12, gf_t *F21, const gf_t *T12, const gf_t *P11, const gf_t *P12, const gf_t *P21) {
	uint32_t T12a[SNOVA_v * SNOVA_l][4];
	uint32_t T12b[SNOVA_v * SNOVA_l][4];
	uint32_t acc[4];

	ref_pack_T12(T12a, T12b, T12);

	// F21[mi, ni, nj, i1, j1] = P21 + sum T12[nk, ni, i1, k1] * P11[mi, nk, nj, k1, j1]
	// Row (mi, nj, j1), lane (ni, i1).
	for (int mi = 0; mi < SNOVA_m1; mi++)
		for (int nj = 0; nj < SNOVA_v; nj++)
			for (int j1 = 0; j1 < SNOVA_l; j1++) {
				memset(acc, 0, sizeof(acc));
				for (int nk = 0; nk < SNOVA_v; nk++)
					for (int k1 = 0; k1 < SNOVA_l; k1++)
						xs_mul_acc(acc, T12b[nk * SNOVA_l + k1], P11[((mi * SNOVA_v + nk) * SNOVA_v + nj) * SNOVA_l2 + k1 * SNOVA_l + j1]);
				for (int ni = 0; ni < SNOVA_o; ni++)
					for (int i1 = 0; i1 < SNOVA_l; i1++) {
						int idx = ((mi * SNOVA_o + ni) * SNOVA_v + nj) * SNOVA_l2 + i1 * SNOVA_l + j1;
						F21[idx] = xs_get(acc, ni * SNOVA_l + i1) ^ P21[idx];
					}
			}

	// F12[mi, nj, nk, i1, j1] = P12 + sum P11[mi, nj, ni, i1, k1] * T12[ni, nk, k1, j1]
	// Row (mi, nj, i1), lane (nk, j1).
	for (int mi = 0; mi < SNOVA_m1; mi++)
		for (int nj = 0; nj < SNOVA_v; nj++)
			for (int i1 = 0; i1 < SNOVA_l; i1++) {
				memset(acc, 0, sizeof(acc));
				for (int ni = 0; ni < SNOVA_v; ni++)
					for (int k1 = 0; k1 < SNOVA_l; k1++)
						xs_mul_acc(acc, T12a[ni * SNOVA_l + k1], P11[((mi * SNOVA_v + nj) * SNOVA_v + ni) * SNOVA_l2 + i1 * SNOVA_l + k1]);
				for (int nk = 0; nk < SNOVA_o; nk++)
					for (int j1 = 0; j1 < SNOVA_l; j1++) {
						int idx = ((mi * SNOVA_v + nj) * SNOVA_o + nk) * SNOVA_l2 + i1 * SNOVA_l + j1;
						F12[idx] = xs_get(acc, nk * SNOVA_l + j1) ^ P12[idx];
					}
			}
}
#endif

#if SIGN_BITSLICE
/**
 * sign-bitslice. whipped_sig, sum_t0, whipped_F21 and whipped_F12 are runs of
 * l * r elements and sum_t1 runs of r * r, one plane word each (rb_t). The
 * Gauss rows are runs of o * l * r + 1 elements over GW 32-bit words per plane.
 */
#define RB_LANES (SNOVA_lr > SNOVA_r2 ? SNOVA_lr : SNOVA_r2)
#if RB_LANES <= 32
typedef uint32_t rb_t;
#else
typedef uint64_t rb_t;
#endif
#define RB_R_MASK ((((rb_t)1) << SNOVA_r) - 1)

#define GN (SNOVA_o * SNOVA_lr)
#define GW ((GN + 1 + 31) / 32)

static inline uint8_t rb_get(const rb_t *x, int c) {
	return (uint8_t)(((x[0] >> c) & 1) | (((x[1] >> c) & 1) << 1) | (((x[2] >> c) & 1) << 2) | (((x[3] >> c) & 1) << 3));
}

static inline void rb_xor(rb_t *x, int c, uint8_t v) {
	x[0] ^= (rb_t)(v & 1) << c;
	x[1] ^= (rb_t)((v >> 1) & 1) << c;
	x[2] ^= (rb_t)((v >> 2) & 1) << c;
	x[3] ^= (rb_t)((v >> 3) & 1) << c;
}

// acc ^= c * x, lane by lane.
static inline void rb_mul_acc(rb_t *acc, const rb_t *x, uint8_t c) {
	rb_t a0 = x[0], a1 = x[1], a2 = x[2], a3 = x[3], t;
	rb_t m = (rb_t)0 - (rb_t)(c & 1);
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
		m = (rb_t)0 - (rb_t)((c >> k) & 1);
		acc[0] ^= m & a0;
		acc[1] ^= m & a1;
		acc[2] ^= m & a2;
		acc[3] ^= m & a3;
	}
}

// The r lanes of x starting at lane from, moved to start at lane to.
static inline void rb_window(rb_t *out, const rb_t *x, int from, int to) {
	for (int p = 0; p < 4; p++) {
		out[p] = ((x[p] >> from) & RB_R_MASK) << to;
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

/**
 * Reference Sign with the whipped central map and the Gauss matrix sliced.
 */
int SNOVA_NAMESPACE(sign)(const expanded_SK* skx, uint8_t *sig, const uint8_t *digest, const size_t len_digest,
                          const uint8_t *salt) {
	if (first_time) {
		snova_init();
	}

	const uint8_t *seed = (uint8_t *)skx;

	gf_t T12[SNOVA_o * SNOVA_v * SNOVA_l2];
	expand_T12(T12, seed + SEED_LENGTH_PUBLIC);

	gf_t P_matrix[NUM_PUB_GF];

	expand_public(P_matrix, seed);

	gf_t* P11 = P_matrix;
	gf_t* P12 = P_matrix + SNOVA_m1 * SNOVA_v * SNOVA_v * SNOVA_l2;
	gf_t* P21 = P_matrix + SNOVA_m1 * SNOVA_v * SNOVA_n * SNOVA_l2;

	gf_t F21[SNOVA_m1 * SNOVA_o * SNOVA_v * SNOVA_l2] = {0};

	for (int i1 = 0; i1 < SNOVA_m1; i1++) {
		for (int j1 = 0; j1 < SNOVA_v; j1++) {
			for (int j2 = 0; j2 < SNOVA_v; j2++) {
				for (int k1 = 0; k1 < SNOVA_o; k1++) {
					gf_mat_mul_add(&F21[((i1 * SNOVA_o + k1) * SNOVA_v + j1) * SNOVA_l2], &T12[(j2 * SNOVA_o + k1) * SNOVA_l2],
					               &P11[((i1 * SNOVA_v + j2) * SNOVA_v + j1) * SNOVA_l2]);
				}
			}
		}
	}

	gf_t F12[SNOVA_m1 * SNOVA_v * SNOVA_o * SNOVA_l2] = {0};

	for (int i1 = 0; i1 < SNOVA_m1; i1++) {
		for (int j1 = 0; j1 < SNOVA_v; j1++) {
			for (int j2 = 0; j2 < SNOVA_v; j2++) {
				for (int k1 = 0; k1 < SNOVA_o; k1++) {
					gf_mat_mul_add(&F12[((i1 * SNOVA_v + j1) * SNOVA_o + k1) * SNOVA_l2],
					               &P11[((i1 * SNOVA_v + j1) * SNOVA_v + j2) * SNOVA_l2], &T12[(j2 * SNOVA_o + k1) * SNOVA_l2]);
				}
			}
		}
	}

	for (int i1 = 0; i1 < SNOVA_m1 * SNOVA_v * SNOVA_o * SNOVA_l2; i1++) {
		gf_set_add(&F12[i1], P12[i1]);
	}

	for (int i1 = 0; i1 < SNOVA_m1 * SNOVA_v * SNOVA_o * SNOVA_l2; i1++) {
		gf_set_add(&F21[i1], P21[i1]);
	}

	// Generate ABQ
	gf_t Am[SNOVA_o * SNOVA_alpha * SNOVA_r2];
	gf_t Bm[SNOVA_o * SNOVA_alpha * SNOVA_lr];
	gf_t Q1[SNOVA_o * SNOVA_alpha * SNOVA_l2];
	gf_t Q2[SNOVA_o * SNOVA_alpha * SNOVA_l2];

	gf_t* aptr = P_matrix + SNOVA_m1 * (SNOVA_v * SNOVA_v + 2 * SNOVA_v * SNOVA_o) * SNOVA_l2;
	gf_t* q1 = aptr + SNOVA_o * SNOVA_alpha * (SNOVA_r2 + SNOVA_lr);
	gf_t* q2 = q1 + SNOVA_o * SNOVA_alpha * SNOVA_l;

#if FIXED_ABQ
	memcpy(aptr, fixed_abq, sizeof(fixed_abq));
#endif
	gen_ABQ(aptr, Am, Bm, Q1, Q2);

	gf_t hash_in_GF16[GF16_HASH];

	uint8_t sign_hashb[BYTES_HASH];
#if HASH_PK
	hash_combined(sign_hashb, digest, len_digest, seed + SEED_LENGTH_PUBLIC + SEED_LENGTH_PRIVATE, salt);
#else
	hash_combined(sign_hashb, digest, len_digest, seed, salt);
#endif
	expand_gf(hash_in_GF16, sign_hashb, GF16_HASH);

	uint32_t gauss[GN][4][GW];
	gf_t solution[GN] = {0};
	gf_t signature_in_GF[SNOVA_n * SNOVA_lr] = {0};
	int flag_redo = 1;
	uint8_t num_sign = 0;

	do {
		memset(gauss, 0, sizeof(gauss));
		num_sign++;
		if (num_sign == 255) {
			memset(sig, 0, BYTES_SIGNATURE);
			return -1;
		}
		flag_redo = 0;

		uint8_t vinegar_in_byte[NUM_GEN_SEC_BYTES];
		shake_t v_instance;

		shake256_init(&v_instance);
		shake_absorb(&v_instance, seed + SEED_LENGTH_PUBLIC, SEED_LENGTH_PRIVATE);
		shake_absorb(&v_instance, digest, BYTES_DIGEST);
		shake_absorb(&v_instance, salt, BYTES_SALT);
		shake_absorb(&v_instance, &num_sign, 1);
		shake_finalize(&v_instance);

		size_t b_idx = SK_BLOCK_SIZE;
		size_t t_idx = 0;

		while (t_idx < SNOVA_v * SNOVA_l * SNOVA_r) {
			if (b_idx >= SK_BLOCK_SIZE) {
				shake_squeeze(vinegar_in_byte, SK_BLOCK_SIZE, &v_instance);
				b_idx = 0;
			}
			signature_in_GF[t_idx] = vinegar_in_byte[b_idx] & 0xf;
			t_idx++;
			signature_in_GF[t_idx] = vinegar_in_byte[b_idx] >> 4;
			t_idx++;
			b_idx++;
		}

		gf_t Fvv_in_GF16Matrix[SNOVA_o * SNOVA_lr] = {0};

		// Row (mi, b1, ni) of sum_t0, row (mi, a1, b1) of sum_t1, row (ab, ni) of
		// whipped_sig: the same rows the stock sign indexes.
		rb_t sum_t0[SNOVA_m1 * SNOVA_l * SNOVA_v][4];
		rb_t sum_t1[SNOVA_m1 * SNOVA_l2][4];
		rb_t whipped_sig[SNOVA_l * SNOVA_v][4];
		rb_t win[4];

		memset(sum_t0, 0, sizeof(sum_t0));
		memset(sum_t1, 0, sizeof(sum_t1));
		memset(whipped_sig, 0, sizeof(whipped_sig));

		for (int ab = 0; ab < SNOVA_l; ++ab)
			for (int ni = 0; ni < SNOVA_v; ++ni)
				for (int i1 = 0; i1 < SNOVA_l; i1++)
					for (int j1 = 0; j1 < SNOVA_r; j1++) {
						gf_t val = 0;
						for (int k1 = 0; k1 < SNOVA_l; k1++)
							gf_set_add(&val, gf_mult(gf_S[ab * SNOVA_l2 + i1 * SNOVA_l + k1], signature_in_GF[ni * SNOVA_lr + k1 * SNOVA_r + j1]));
						rb_xor(whipped_sig[ab * SNOVA_v + ni], i1 * SNOVA_r + j1, val);
					}

		for (int mi = 0; mi < SNOVA_m1; ++mi) {
			// Right: sum_t0[i1, j1] += P11[i1, k1] * whipped_sig[k1, j1]
			for (int ni = 0; ni < SNOVA_v; ++ni)
				for (int b1 = 0; b1 < SNOVA_l; ++b1)
					for (int nj = 0; nj < SNOVA_v; ++nj)
						for (int i1 = 0; i1 < SNOVA_l; i1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++) {
								rb_window(win, whipped_sig[b1 * SNOVA_v + nj], k1 * SNOVA_r, i1 * SNOVA_r);
								rb_mul_acc(sum_t0[(mi * SNOVA_l + b1) * SNOVA_v + ni], win,
								           P11[((mi * SNOVA_v + ni) * SNOVA_v + nj) * SNOVA_l2 + i1 * SNOVA_l + k1]);
							}

			// Left, transposed whipped_sig: sum_t1[i1, j1] += whipped_sig[k1, i1] * sum_t0[k1, j1]
			for (int a1 = 0; a1 < SNOVA_l; ++a1)
				for (int b1 = 0; b1 < SNOVA_l; ++b1)
					for (int ni = 0; ni < SNOVA_v; ++ni)
						for (int i1 = 0; i1 < SNOVA_r; i1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++) {
								rb_window(win, sum_t0[(mi * SNOVA_l + b1) * SNOVA_v + ni], k1 * SNOVA_r, i1 * SNOVA_r);
								rb_mul_acc(sum_t1[mi * SNOVA_l2 + a1 * SNOVA_l + b1], win,
								           rb_get(whipped_sig[a1 * SNOVA_v + ni], k1 * SNOVA_r + i1));
							}
		}

		/**
		 * Apply A, B, q1 and q2, aka E matrix
		 */
		for (int mi = 0; mi < SNOVA_o; ++mi)
			for (int alpha = 0; alpha < SNOVA_alpha; ++alpha) {
				int mi_prime = i_prime(mi, alpha);

				rb_t t1s[4] = {0};
				gf_t gf16m_temp1[SNOVA_r2];
				gf_t gf16m_temp2[SNOVA_lr] = {0};

				for (int a1 = 0; a1 < SNOVA_l; ++a1) {
					rb_t sumb[4] = {0};

					for (int b1 = 0; b1 < SNOVA_l; ++b1)
						rb_mul_acc(sumb, sum_t1[mi_prime * SNOVA_l2 + a1 * SNOVA_l + b1], q2[(mi * SNOVA_alpha + alpha) * SNOVA_l + b1]);
					rb_mul_acc(t1s, sumb, q1[(mi * SNOVA_alpha + alpha) * SNOVA_l + a1]);
				}
				for (int i1 = 0; i1 < SNOVA_r2; i1++) {
					gf16m_temp1[i1] = rb_get(t1s, i1);
				}

				gf_mat_mul_add_lr(gf16m_temp2, gf16m_temp1, &Bm[(mi * SNOVA_alpha + alpha) * SNOVA_lr], SNOVA_r, SNOVA_r,
				                  SNOVA_l);
				gf_mat_mul_add_lr(&Fvv_in_GF16Matrix[mi * SNOVA_lr], &Am[(mi * SNOVA_alpha + alpha) * SNOVA_r2], gf16m_temp2,
				                  SNOVA_r, SNOVA_r, SNOVA_l);
			}

		for (int mi = 0; mi < SNOVA_o; ++mi)
			for (int i1 = 0; i1 < SNOVA_lr; i1++) {
				g_xor(gauss[mi * SNOVA_lr + i1], GN, gf_sub(hash_in_GF16[mi * SNOVA_lr + i1], Fvv_in_GF16Matrix[mi * SNOVA_lr + i1]));
			}

		// Row ((mi * l + b1) * o + idx) of whipped_F21 and whipped_F12
		rb_t whipped_F21[SNOVA_m1 * SNOVA_l * SNOVA_o][4];
		rb_t whipped_F12[SNOVA_m1 * SNOVA_l * SNOVA_o][4];

		memset(whipped_F21, 0, sizeof(whipped_F21));
		memset(whipped_F12, 0, sizeof(whipped_F12));

		for (int mi = 0; mi < SNOVA_m1; mi++) {
			// whipped_F21[i1, j1] += F21[i1, k1] * whipped_sig[k1, j1]
			for (int idx = 0; idx < SNOVA_o; idx++)
				for (int b1 = 0; b1 < SNOVA_l; ++b1)
					for (int nj = 0; nj < SNOVA_v; ++nj)
						for (int i1 = 0; i1 < SNOVA_l; i1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++) {
								rb_window(win, whipped_sig[b1 * SNOVA_v + nj], k1 * SNOVA_r, i1 * SNOVA_r);
								rb_mul_acc(whipped_F21[(mi * SNOVA_l + b1) * SNOVA_o + idx], win,
								           F21[((mi * SNOVA_o + idx) * SNOVA_v + nj) * SNOVA_l2 + i1 * SNOVA_l + k1]);
							}

			// whipped_F12[i1, j1] += F12[k1, i1] * whipped_sig[k1, j1]
			for (int idx = 0; idx < SNOVA_o; idx++)
				for (int b1 = 0; b1 < SNOVA_l; ++b1)
					for (int nj = 0; nj < SNOVA_v; ++nj)
						for (int i1 = 0; i1 < SNOVA_l; i1++)
							for (int k1 = 0; k1 < SNOVA_l; k1++) {
								rb_window(win, whipped_sig[b1 * SNOVA_v + nj], k1 * SNOVA_r, i1 * SNOVA_r);
								rb_mul_acc(whipped_F12[(mi * SNOVA_l + b1) * SNOVA_o + idx], win,
								           F12[((mi * SNOVA_v + nj) * SNOVA_o + idx) * SNOVA_l2 + k1 * SNOVA_l + i1]);
							}
		}

		for (int mi = 0; mi < SNOVA_o; mi++) {
			for (int idx = 0; idx < SNOVA_o; idx++) {
				for (int alpha = 0; alpha < SNOVA_alpha; alpha++) {
					gf_t gf16m_temp0[SNOVA_l2] = {0};
					gf_t gf16m_temp1[SNOVA_lr];
					rb_t t1s[4] = {0};

					gf_t X_tmp[SNOVA_l2] = {0};
					int mi_prime = i_prime(mi, alpha);

					for (int b1 = 0; b1 < SNOVA_l; ++b1)
						rb_mul_acc(t1s, whipped_F21[(mi_prime * SNOVA_l + b1) * SNOVA_o + idx], q2[(mi * SNOVA_alpha + alpha) * SNOVA_l + b1]);
					for (int i1 = 0; i1 < SNOVA_lr; i1++) {
						gf16m_temp1[i1] = rb_get(t1s, i1);
					}
					gf_mat_mul_add_lr(gf16m_temp0, gf16m_temp1, &Bm[(mi * SNOVA_alpha + alpha) * SNOVA_lr], SNOVA_l, SNOVA_r,
					                  SNOVA_l);
					gf_mat_mul_add(X_tmp, &Q1[(mi * SNOVA_alpha + alpha) * SNOVA_l2], gf16m_temp0);

					for (int ti1 = 0; ti1 < SNOVA_r; ti1++)
						for (int ti2 = 0; ti2 < SNOVA_l; ti2++)
							for (int tj1 = 0; tj1 < SNOVA_l; tj1++)
								for (int tj2 = 0; tj2 < SNOVA_r; tj2++) {
									int ti = ti1 * SNOVA_l + ti2;
									int tj = tj1 * SNOVA_r + tj2;
									g_xor(gauss[mi * SNOVA_lr + ti], idx * SNOVA_lr + tj,
									      gf_mult(X_tmp[tj1 * SNOVA_l + ti2], Am[(mi * SNOVA_alpha + alpha) * SNOVA_r2 + ti1 * SNOVA_r + tj2]));
								}
				}
			}
		}

		for (int mi = 0; mi < SNOVA_o; mi++) {
			for (int idx = 0; idx < SNOVA_o; idx++) {
				for (int alpha = 0; alpha < SNOVA_alpha; alpha++) {
					gf_t gf16m_temp0[SNOVA_lr] = {0};
					gf_t gf16m_temp1[SNOVA_lr];
					rb_t t1s[4] = {0};

					gf_t X_tmp[SNOVA_lr] = {0};
					int mi_prime = i_prime(mi, alpha);

					// Transpose
					for (int b1 = 0; b1 < SNOVA_l; ++b1)
						rb_mul_acc(t1s, whipped_F12[(mi_prime * SNOVA_l + b1) * SNOVA_o + idx], q1[(mi * SNOVA_alpha + alpha) * SNOVA_l + b1]);
					for (int i1 = 0; i1 < SNOVA_l; i1++)
						for (int j1 = 0; j1 < SNOVA_r; j1++) {
							gf16m_temp1[j1 * SNOVA_l + i1] = rb_get(t1s, i1 * SNOVA_r + j1);
						}

					gf_mat_mul_add_lr(gf16m_temp0, &Am[(mi * SNOVA_alpha + alpha) * SNOVA_r2], gf16m_temp1, SNOVA_r, SNOVA_r,
					                  SNOVA_l);
					gf_mat_mul_add_lr(X_tmp, gf16m_temp0, &Q2[(mi * SNOVA_alpha + alpha) * SNOVA_l2], SNOVA_r, SNOVA_l,
					                  SNOVA_l);

					for (int ti1 = 0; ti1 < SNOVA_r; ti1++)
						for (int ti2 = 0; ti2 < SNOVA_l; ti2++)
							for (int tj1 = 0; tj1 < SNOVA_l; tj1++)
								for (int tj2 = 0; tj2 < SNOVA_r; tj2++) {
									int ti = ti1 * SNOVA_l + ti2;
									int tj = tj1 * SNOVA_r + tj2;
									g_xor(gauss[mi * SNOVA_lr + ti], idx * SNOVA_lr + tj,
									      gf_mult(X_tmp[ti1 * SNOVA_l + tj1], Bm[(mi * SNOVA_alpha + alpha) * SNOVA_lr + tj2 * SNOVA_l + ti2]));
								}
				}
			}
		}

		// Gaussian elimination on sliced rows, with the stock pivot search.
		for (int i = 0; i < GN; ++i) {
			if (g_get(gauss[i], i) == 0) {
				for (int j = i + 1; j < GN; ++j) {
					if (g_get(gauss[j], i) != 0) {
						uint32_t row[4][GW];
						memcpy(row, gauss[i], sizeof(row));
						memcpy(gauss[i], gauss[j], sizeof(row));
						memcpy(gauss[j], row, sizeof(row));
						break;
					}
				}
			}
			if (g_get(gauss[i], i) == 0) {
				flag_redo = 1;
				break;
			}

			{
				uint32_t row[4][GW];
				memcpy(row, gauss[i], sizeof(row));
				memset(gauss[i], 0, sizeof(row));
				g_mul_acc(gauss[i], row, gf_inv(g_get(row, i)));
			}

			for (int j = i + 1; j < GN; ++j) {
				gf_t gji = g_get(gauss[j], i);
				if (gji != 0) {
					g_mul_acc(gauss[j], gauss[i], gji);
				}
			}
		}

		if (!flag_redo) {
			memset(solution, 0, sizeof(solution));

			for (int i = GN - 1; i >= 0; --i) {
				gf_t sum = 0;
				for (int k = i + 1; k < GN; ++k) {
					gf_set_add(&sum, gf_mult(g_get(gauss[i], k), solution[k]));
				}
				solution[i] = gf_sub(g_get(gauss[i], GN), sum);
			}
			memcpy(signature_in_GF + SNOVA_v * SNOVA_lr, solution, GN);

			for (int index = 0; index < SNOVA_v; ++index) {
				for (int mi = 0; mi < SNOVA_o; ++mi) {
					gf_mat_mul_add_lr(&signature_in_GF[index * SNOVA_lr], &T12[(index * SNOVA_o + mi) * SNOVA_l2],
					                  &solution[mi * SNOVA_lr], SNOVA_l, SNOVA_l, SNOVA_r);
				}
			}
		}
	} while (flag_redo);

	compress_gf(sig, signature_in_GF, SNOVA_n * SNOVA_lr);
	memcpy(sig + BYTES_SIGNATURE - BYTES_SALT, salt, BYTES_SALT);

	return 0;
}
#endif
