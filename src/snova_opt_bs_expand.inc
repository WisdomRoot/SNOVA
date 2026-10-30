// EXPAND_BITSLICE: opt's genkeys and sk_expand, on sliced T12.
//
// GF(16) = GF(2)[t]/(t^4 + t + 1), nibble bit k is the coefficient of t^k. A run
// of SNOVA_o * SNOVA_l elements (at most 30) is four uint32_t plane words. T12 is
// held sliced two ways, so that every product in F12, F21 and P22 is a public or
// secret scalar times a sliced row of T12 or of F12:
//
//   T12a[ni * l + k1], lane nk * l + j1 = T12[(ni * o + nk) * l2 + k1 * l + j1]
//   T12b[nk * l + k1], lane ni * l + i1 = T12[(nk * o + ni) * l2 + i1 * l + k1]
//
// Each output row is accumulated in full before it is written, so no F12, F21
// or P22 accumulator array is held, only the rows in flight.

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

static inline void pack_T12(uint32_t T12a[SNOVA_v * SNOVA_l][4], uint32_t T12b[SNOVA_v * SNOVA_l][4], const uint8_t *T12) {
	memset(T12a, 0, sizeof(uint32_t) * SNOVA_v * SNOVA_l * 4);
	memset(T12b, 0, sizeof(uint32_t) * SNOVA_v * SNOVA_l * 4);
	for (int a = 0; a < SNOVA_v; a++)
		for (int b = 0; b < SNOVA_o; b++)
			for (int i1 = 0; i1 < SNOVA_l; i1++)
				for (int j1 = 0; j1 < SNOVA_l; j1++) {
					uint8_t val = T12[(a * SNOVA_o + b) * SNOVA_l2 + i1 * SNOVA_l + j1];
					// T12a: row (ni = a, k1 = i1), lane (nk = b, j1)
					xs_xor(T12a[a * SNOVA_l + i1], b * SNOVA_l + j1, val);
					// T12b: row (nk = a, k1 = j1), lane (ni = b, i1)
					xs_xor(T12b[a * SNOVA_l + j1], b * SNOVA_l + i1, val);
				}
}

/**
 * genkeys with sliced F12 and P22.
 */
int SNOVA_NAMESPACE(genkeys)(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
	SNOVA_INIT

	uint32_t T12a[SNOVA_v * SNOVA_l][4];
	uint32_t T12b[SNOVA_v * SNOVA_l][4];
	{
		uint8_t T12[SNOVA_o * SNOVA_v * SNOVA_l2];

		expand_T12(T12, seed + SEED_LENGTH_PUBLIC);
		pack_T12(T12a, T12b, T12);

		SNOVA_SECURE_CLEAR(T12);
	}

	uint8_t P_matrix[NUM_PUB_GF];

	expand_public(P_matrix, seed);

	uint8_t *P11 = P_matrix;
	uint8_t *P12 = P_matrix + SNOVA_m1 * SNOVA_v * SNOVA_v * SNOVA_l2;
	uint8_t *P21 = P_matrix + SNOVA_m1 * SNOVA_v * SNOVA_n * SNOVA_l2;

	// P22 row (mi, nk, i1), lane (ni, j1)
	uint32_t P22[SNOVA_m1 * SNOVA_o * SNOVA_l][4];
	memset(P22, 0, sizeof(P22));

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
						xs_mul_acc(P22[(mi * SNOVA_o + nk) * SNOVA_l + i1], F12[k1], xs_get(T12b[nj * SNOVA_l + k1], nk * SNOVA_l + i1));

			SNOVA_SECURE_CLEAR(F12);
		}

	// P22[mi, nk, ni, i1, j1] ^= P21[mi, nk, nj, i1, k1] * T12[nj, ni, k1, j1]
	for (int mi = 0; mi < SNOVA_m1; mi++)
		for (int nk = 0; nk < SNOVA_o; nk++)
			for (int nj = 0; nj < SNOVA_v; nj++)
				for (int i1 = 0; i1 < SNOVA_l; i1++)
					for (int k1 = 0; k1 < SNOVA_l; k1++)
						xs_mul_acc(P22[(mi * SNOVA_o + nk) * SNOVA_l + i1], T12a[nj * SNOVA_l + k1],
						           P21[((mi * SNOVA_o + nk) * SNOVA_v + nj) * SNOVA_l2 + i1 * SNOVA_l + k1]);

	/**
	 * Output public and secret keys
	 */
	memcpy(pk, seed, SEED_LENGTH_PUBLIC);
	memset(pk + SEED_LENGTH_PUBLIC, 0, BYTES_PK - SEED_LENGTH_PUBLIC);
	for (int mi = 0; mi < SNOVA_m1; mi++)
		for (int nk = 0; nk < SNOVA_o; nk++)
			for (int ni = 0; ni < SNOVA_o; ni++)
				for (int i1 = 0; i1 < SNOVA_l; i1++)
					for (int j1 = 0; j1 < SNOVA_l; j1++) {
						int idx = ((mi * SNOVA_o + nk) * SNOVA_o + ni) * SNOVA_l2 + i1 * SNOVA_l + j1;
						uint8_t val = xs_get(P22[(mi * SNOVA_o + nk) * SNOVA_l + i1], ni * SNOVA_l + j1);
						pk[SEED_LENGTH_PUBLIC + idx / 2] ^= (uint8_t)((idx & 1) ? val << 4 : val);
					}
	memcpy(sk, seed, SEED_LENGTH_PUBLIC + SEED_LENGTH_PRIVATE);

#if HASH_PK
	shake256(sk + SEED_LENGTH_PUBLIC + SEED_LENGTH_PRIVATE, BYTES_PK_HASH, pk, BYTES_PK);
#endif

	SNOVA_SECURE_CLEAR(T12a);
	SNOVA_SECURE_CLEAR(T12b);

	return 0;
}

/**
 * sk_expand with sliced F12 and F21.
 */
int SNOVA_NAMESPACE(sk_expand)(expanded_SK *skx, const uint8_t *sk) {
	SNOVA_INIT

	memcpy(skx->pk_seed, sk, SEED_LENGTH_PUBLIC);
	memcpy(skx->sk_seed, sk + SEED_LENGTH_PUBLIC, SEED_LENGTH_PRIVATE);
#if HASH_PK
	memcpy(skx->pk_hash, sk + SEED_LENGTH_PUBLIC + SEED_LENGTH_PRIVATE, BYTES_PK_HASH);
#endif

	uint32_t T12a[SNOVA_v * SNOVA_l][4];
	uint32_t T12b[SNOVA_v * SNOVA_l][4];
	{
		uint8_t T12[SNOVA_o * SNOVA_v * SNOVA_l2];

		expand_T12(T12, skx->sk_seed);
		for (int i1 = 0; i1 < SNOVA_o * SNOVA_v * SNOVA_l2; i1++) {
			skx->T12[i1] = gf16_expand(T12[i1]);
		}
		pack_T12(T12a, T12b, T12);

		SNOVA_SECURE_CLEAR(T12);
	}

	uint8_t P_matrix[NUM_PUB_GF];

	expand_public(P_matrix, skx->pk_seed);

	uint8_t *P11 = P_matrix;
	uint8_t *P12 = P_matrix + SNOVA_m1 * SNOVA_v * SNOVA_v * SNOVA_l2;
	uint8_t *P21 = P_matrix + SNOVA_m1 * SNOVA_v * SNOVA_n * SNOVA_l2;

	for (int i1 = 0; i1 < SNOVA_m1 * SNOVA_v * SNOVA_v * SNOVA_l2; i1++) {
		skx->P11[i1] = P11[i1];
	}

	uint32_t acc[4];

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
						skx->F21[idx] = xs_get(acc, ni * SNOVA_l + i1) ^ P21[idx];
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
						skx->F12[idx] = xs_get(acc, nk * SNOVA_l + j1) ^ P12[idx];
					}
			}

	SNOVA_SECURE_CLEAR(acc);
	SNOVA_SECURE_CLEAR(T12a);
	SNOVA_SECURE_CLEAR(T12b);

	return 0;
}
