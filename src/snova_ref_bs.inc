// EXPAND_BITSLICE: the reference kernel's genkeys and F12, F21 in sign.
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

