/*
 * Header file for the xChaCha encryption and SipHash keyed hash algorithms
 * Evolution:
 * Daniel J. Bernstein's ChaCha reference: http://cr.yp.to/chacha.html
 * xChaCha version: https://github.com/spcnvdr/xChaCha
 * This version: https://github.com/bradleyeckert/ychacha
 */
#include <stdint.h>

#ifndef _YCHACHA_H_
#define _YCHACHA_H_

/** Key and IV sizes that are supported by xChaCha.
 *  All sizes are in bits.
 */
#define NAME "xChaCha"
#define KEYSIZE 256                 /* 256-bits, 32 bytes */
#define BLOCKSIZE 512               /* 512-bits, 64 bytes */
#define IVSIZE 256                  /* 256-bits, 32 bytes */
#define YCH_IV_BYTES 32
#define SIPHASH_OUTPUT_BYTES 8

/* The following macros are used to obtain exact-width results. */
#define U8V(v)  ((uint8_t)(v) & (0xFF))
#define U16V(v) ((uint16_t)(v) & (0xFFFF))
#define U32V(v) ((uint32_t)(v) & (0xFFFFFFFF))
#define U64V(v) ((uint64_t)(v) & (0xFFFFFFFFFFFFFFFF))

#define ROTL32(v, n) (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define ROTL64(x, b) (uint64_t)( ((x) << (b)) | ( (x) >> (64 - (b))) )

#define HALF_ROUND(a,b,c,d,s,t)		\
	a += b; c += d;					\
	b = ROTL64(b, s) ^ a;			\
	d = ROTL64(d, t) ^ c;			\
	a = ROTL64(a, 32);

#define DOUBLE_ROUND(v0,v1,v2,v3)	\
	HALF_ROUND(v0,v1,v2,v3,13,16);	\
	HALF_ROUND(v2,v1,v0,v3,17,21);	\
	HALF_ROUND(v0,v1,v2,v3,13,16);	\
	HALF_ROUND(v2,v1,v0,v3,17,21);


/** ChaCha_ctx is the structure containing the representation of the internal
 *  state of the xChaCha cipher. Typically 129 to 132 bytes.
 */

typedef struct
{   uint32_t input[16];		// state
    uint8_t chabuf[64];     // keystream buffer
    uint8_t chaptr;         // keystream pointer
} xChaCha_ctx;

typedef int (*rngFn)(uint8_t *dest, unsigned int size);

/* ------------------------------------------------------------------------- */

/** hchacha an intermediary step towards xChaCha based on the
 * construction and security proof used to create XSalsa20.
 * @param out Holds output of hchacha
 * @param in The input to process with hchacha
 * @param k The key to use with hchacha
 *
 */
void xchacha_hchacha20(uint8_t *out, const uint8_t *in, const uint8_t *k);


/** Set the encryption key and iv to be used with XChaCha
 * @param ctx The XChaCha context to use
 * @param k The 256-bit/32-byte key to use for encryption
 * @param iv The 192-bit/24-byte iv or nonce to use
 * @note It is the user's responsibility to ensure that the key
 * and the iv are of the correct lengths!
 */
void xchacha_keysetup(xChaCha_ctx *ctx, const uint8_t *k, uint8_t *iv);


/** Set the internal counter to a specific number. Depending
 * on the specification, sometimes the counter is started at 1.
 * @param ctx The XChaCha context to modify
 * @param counter The number to set the counter to
 */
void xchacha_set_counter(xChaCha_ctx *ctx, uint8_t *counter);


/** Get the next PRNG byte
 * @param x The xChaCha context with the cipher's state to use
 * @return next byte in the XOR stream
 */
uint8_t xchacha_next(xChaCha_ctx *ctx);


/** Encrypt a set of bytes with xChaCha
 * @param ctx The xChaCha context to use
 * @param plaintext The data to be encrypted
 * @param ciphertext A buffer to hold the encrypted data
 * @param msglen Message length in bytes
 */
void xchacha_encrypt_bytes(xChaCha_ctx* ctx, const uint8_t* plaintext,
		uint8_t* ciphertext,
		uint32_t msglen);


/** Decrypt a set of bytes with xChaCha
 * @param ctx The xChaCha context to use
 * @param ciphertext The encrypted data to decrypt
 * @param plaintext A buffer to hold the decrypted data
 * @param msglen Message length in bytes
 */
void xchacha_decrypt_bytes(xChaCha_ctx* ctx, const uint8_t* ciphertext,
    uint8_t* plaintext,
    uint32_t msglen);


/** Encryption/decryption initialization
 * @param ctx   Encryption/Decryption context
 * @param key   Key, 32 bytes
 * @param iv    Initialization vector, 16 bytes
 */
void xc_crypt_setkey(xChaCha_ctx *ctx, const uint8_t *key, const uint8_t *iv);

/** 16-byte block encryption/decryption
 * @param ctx   Encryption/Decryption context
 * @param mode  CRYPT_ENCRYPT or CRYPT_DECRYPT
 * @param in    16-byte buffer holding the input data
 * @param out   16-byte buffer holding the output data
 */
void xc_crypt_block(xChaCha_ctx *ctx, int mode, const uint8_t *in, uint8_t *out);


#endif // _YCHACHA_H_
