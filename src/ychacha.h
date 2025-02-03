/*
 * Header file for the YChaCha encryption and SipHash keyed hash algorithms
 * Evolution:
 * Daniel J. Bernstein's ChaCha reference: http://cr.yp.to/chacha.html
 * YChaCha version: https://github.com/spcnvdr/YChaCha
 * This version: https://github.com/bradleyeckert/ychacha
 */
#include <stdint.h>

#ifndef _YCHACHA_H_
#define _YCHACHA_H_

#define YCH_BUFSIZE 256			/* Power of 2, at least 128 */


/** Key and IV sizes that are supported by YChaCha.
 *  All sizes are in bits.
 */
#define NAME "YChaCha"
#define KEYSIZE 256                 /* 256-bits, 32 bytes */
#define BLOCKSIZE 512               /* 512-bits, 64 bytes */
#define IVSIZE 256                  /* 256-bits, 24 bytes */
#define YCHACHA_BLOCKLENGTH 64		/* YChaCha block size in bytes */


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

#if ((YCH_BUFSIZE-1) & YCH_BUFSIZE)
#error YCH_BUFSIZE must be an exact power of 2
#endif

/** ChaCha_ctx is the structure containing the representation of the internal
 *  state of the YChaCha cipher. It includes state for siphash and comms.
 */

typedef struct
{	uint32_t input[16];		// xchacha state
    uint64_t hkey[2];		// siphash key (increment after each message)
    uint8_t chabuf[64];     // xchacha keystream buffer
    uint8_t chaptr;         // xchacha keystream pointer
	uint16_t p;             // number of bytes in buf
	uint8_t buf[YCH_BUFSIZE];
} YChaCha_ctx;

/* ------------------------------------------------------------------------- */

/** hchacha an intermediary step towards YChaCha based on the
 * construction and security proof used to create XSalsa20.
 * @param out Holds output of hchacha
 * @param in The input to process with hchacha
 * @param k The key to use with hchacha
 *
 */
void ychacha_hchacha20(uint8_t *out, const uint8_t *in, const uint8_t *k);


/** Set the encryption key and iv to be used with XChaCha
 * @param ctx The XChaCha context to use
 * @param k The 256-bit/32-byte key to use for encryption
 * @param iv The 192-bit/24-byte iv or nonce to use
 * @note It is the user's responsibility to ensure that the key
 * and the iv are of the correct lengths!
 */
void ychacha_keysetup(YChaCha_ctx *ctx, const uint8_t *k, uint8_t *iv);


/** Set the internal counter to a specific number. Depending
 * on the specification, sometimes the counter is started at 1.
 * @param ctx The XChaCha context to modify
 * @param counter The number to set the counter to
 *
 */
void ychacha_set_counter(YChaCha_ctx *ctx, uint8_t *counter);


/** Get the next PRNG byte
 * @param x The YChaCha context with the cipher's state to use
 * @return next byte in the XOR stream
 */
uint8_t ychacha_next(YChaCha_ctx *ctx);


/** Encrypt a set of bytes with YChaCha
 * @param ctx The YChaCha context to use
 * @param plaintext The data to be encrypted
 * @param ciphertext A buffer to hold the encrypted data
 * @param msglen Message length in bytes
 *
 */
void ychacha_encrypt_bytes(YChaCha_ctx* ctx, const uint8_t* plaintext,
		uint8_t* ciphertext,
		uint32_t msglen);


/** Dencrypt a set of bytes with YChaCha
 * @param ctx The YChaCha context to use
 * @param ciphertext The encrypted data to decrypt
 * @param plaintext A buffer to hold the decrypted data
 * @param msglen Message length in bytes
 *
 */
void ychacha_decrypt_bytes(YChaCha_ctx* ctx, const uint8_t* ciphertext,
    uint8_t* plaintext,
    uint32_t msglen);


/** Calculate HMAC with SipHash 2.4
 * @param src Input byte array
 * @param src_sz Input length
 * @param key 16-byte key
 * @return 64-bit hash
 */
uint64_t siphash24(const uint8_t *src, unsigned long src_sz, const uint8_t key[16]);

/* ------------------------------------------------------------------------- */


#endif // _YCHACHA_H_
