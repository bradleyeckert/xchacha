/* https://github.com/bradleyeckert/ychacha
 *
 * A small cryptographic library that implements a version of the YChaCha
 * stream cipher modified to accept a 256-bit IV. The last 64 bits of IV
 * set the counter.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "ychacha.h"
#include "string.h"

static const uint8_t ind[32] = {
    0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
    0, 5, 10, 15, 1, 6, 11, 12, 2, 7, 8, 13, 3, 4, 9, 14
};

static void doRounds(uint32_t *x) {
    for (int i = 0; i < 10; i++){
        for (int j = 0; j < 8; j++) {
            const uint8_t * p = &ind[j*4];  // eliminate QUARTERROUND macro
            x[p[0]] += x[p[1]];  x[p[3]] = ROTL32(x[p[3]] ^ x[p[0]], 16);
            x[p[2]] += x[p[3]];  x[p[1]] = ROTL32(x[p[1]] ^ x[p[2]], 12);
            x[p[0]] += x[p[1]];  x[p[3]] = ROTL32(x[p[3]] ^ x[p[0]], 8);
            x[p[2]] += x[p[3]];  x[p[1]] = ROTL32(x[p[1]] ^ x[p[2]], 7);
        }
    }
}

static uint32_t u8tou32(const uint8_t *p) {
    return                              // This little gem handles alignment
  (((uint32_t)(p[0])      ) |           // even if the CPU doesn't.
   ((uint32_t)(p[1]) <<  8) |
   ((uint32_t)(p[2]) << 16) |
   ((uint32_t)(p[3]) << 24));
}

static void u32tou8(uint8_t *p, uint32_t v) {
    memcpy(p, &v, 4);                   // 8-bit --> 32-bit little-endian
}

void ychacha_hchacha20(uint8_t *out, const uint8_t *in, const uint8_t *k){
    int i;
    uint32_t x[16];

    x[0] = 0x61707865;                  // XChaCha Constant
    x[1] = 0x3320646e;
    x[2] = 0x79622d32;
    x[3] = 0x6b206574;

    for (i = 0; i < 4; i++){
        x[i+ 4] = u8tou32(&k[i*4]);
        x[i+ 8] = u8tou32(&k[i*4+16]);
        x[i+12] = u8tou32(&in[i*4]);
    }
    doRounds(x);
    for (i = 0; i < 4; i++){
        u32tou8(out + i*4, x[i]);
        u32tou8(out + i*4 + 16, x[i+12]);
    }
}

void ychacha_keysetup(YChaCha_ctx *ctx, const uint8_t *k, uint8_t *iv){
    /* The sub-key to use */
    uint8_t k2[32];
    int i;
    ychacha_hchacha20(k2, iv, k);
    ctx->input[0] = 0x61707865;
    ctx->input[1] = 0x3320646e;
    ctx->input[2] = 0x79622d32;
    ctx->input[3] = 0x6b206574;
    for (i = 0; i < 8; i++) {   // load the key
        ctx->input[i + 4] = u8tou32(&k2[i*4]);
    }
    for (i = 0; i < 4; i++) {   // load the key
        ctx->input[(i^2) + 12] = u8tou32(&iv[i*4 + 16]);
    }
    ctx->chaptr = 64;
}

void ychacha_set_counter(YChaCha_ctx *ctx, uint8_t *counter){
    ctx->input[12] = u8tou32(&counter[0]);
    ctx->input[13] = u8tou32(&counter[4]);
}

uint8_t ychacha_next(YChaCha_ctx *ctx){
    if (ctx->chaptr > 63) {
        ctx->chaptr = 0;
        uint32_t x[16], j[16];
        memcpy(j, &ctx->input, 64);
        memcpy(x, j, 64);
        doRounds(x);
        for (int i = 0; i < 16; i++) {
            x[i] += j[i];
        }
        memcpy(ctx->chabuf, x, 64);
        j[12]++;
        if (!j[12]) j[13]++;
        ctx->input[12] = j[12];
        ctx->input[13] = j[13];
    }
    return ctx->chabuf[ctx->chaptr++];
}

void ychacha_encrypt_bytes(YChaCha_ctx *ctx, const uint8_t *m, uint8_t *c, uint32_t bytes){
    while (bytes--) {
        *c++ = *m++ ^ ychacha_next(ctx);
    }
}

void ychacha_decrypt_bytes(YChaCha_ctx *ctx, const uint8_t *c, uint8_t *m, uint32_t bytes){
    ychacha_encrypt_bytes(ctx,c,m,bytes);
}

/* ------------------------------------------------------------------------- */

static void doubleround(uint64_t *v) {
	DOUBLE_ROUND(v[0],v[1],v[2],v[3]);
}

uint64_t siphash24(const uint8_t *src, unsigned long src_sz, const uint8_t key[16]) {
	const uint64_t *_key = (uint64_t *)key;
	uint64_t k0 = (uint64_t)(_key[0]);
	uint64_t k1 = (uint64_t)(_key[1]);
	uint64_t b = (uint64_t)src_sz << 56;
	uint64_t v[4];

	v[0] = k0 ^ 0x736f6d6570736575ULL;
	v[1] = k1 ^ 0x646f72616e646f6dULL;
	v[2] = k0 ^ 0x6c7967656e657261ULL;
	v[3] = k1 ^ 0x7465646279746573ULL;

	uint64_t mi;
	uint8_t *pt = (uint8_t *)&mi;
	while (src_sz) {
		mi = 0;
		for (int i = 0; i < 8; i++) {   // little-endian input stream
            if (i < src_sz)  pt[i] = *src++;
		}
		if (src_sz < 8) break;
		v[3] ^= mi;
		doubleround(v);
		v[0] ^= mi;
		src_sz -= 8;
	}

	uint64_t t = 0;
	pt = (uint8_t *)&t;
	uint8_t *m = (uint8_t *)&mi;
	switch (src_sz) {
	case 7: pt[6] = m[6];
	case 6: pt[5] = m[5];
	case 5: pt[4] = m[4];
	case 4: *((uint32_t*)&pt[0]) = *((uint32_t*)&m[0]); break;
	case 3: pt[2] = m[2];
	case 2: pt[1] = m[1];
	case 1: pt[0] = m[0];
	}
	b |= (uint64_t)(t);

	v[3] ^= b;
	doubleround(v);
	v[0] ^= b; v[2] ^= 0xff;
	doubleround(v);
	doubleround(v);
	return (v[0] ^ v[1]) ^ (v[2] ^ v[3]);
}

