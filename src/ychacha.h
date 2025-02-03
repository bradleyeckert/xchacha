/*
 * Header file for the XChaCha20 encryption and SipHash keyed hash algorithms
 * Evolution:
 * Daniel J. Bernstein's ChaCha reference: http://cr.yp.to/chacha.html
 * xchacha20 version: https://github.com/spcnvdr/xchacha20
 * This version: https://github.com/bradleyeckert/ychacha
 */
#include <stdint.h>

#ifndef XCHACHA20_H_
#define XCHACHA20_H_

#define XCHACHA_BUFSIZE 256			/* Power of 2, at least 128 */


/** Key and IV sizes that are supported by XChaCha20.
 *  All sizes are in bits.
 */
#define NAME "XChaCha20"
#define KEYSIZE 256                 /* 256-bits, 32 bytes */
#define BLOCKSIZE 512               /* 512-bits, 64 bytes */
#define IVSIZE 192                  /* 192-bits, 24 bytes */
#define XCHACHA_BLOCKLENGTH 64		/* XChaCha20 block size in bytes */


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

#if ((XCHACHA_BUFSIZE-1) & XCHACHA_BUFSIZE)
#error XCHACHA_BUFSIZE must be an exact power of 2
#endif

/** ChaCha_ctx is the structure containing the representation of the internal
 *  state of the XChaCha20 cipher. It includes state for siphash and comms.
 */

typedef struct
{	uint32_t input[16];		// xchacha state
    uint64_t hkey[2];		// siphash key (increment after each message)
    uint8_t sipbuf[8];      // siphash buffer
    uint8_t chabuf[64];     // xchacha keystream buffer
    uint8_t chaptr;         // xchacha keystream pointer
    uint8_t sipptr;         // siphash pointer
	uint8_t ready;          // buf is ready to process
	uint16_t tail;
	uint16_t head;
	uint8_t buf[XCHACHA_BUFSIZE];
} XChaCha_ctx;

/* ------------------------------------------------------------------------- */

/** Clear the communication buffer
 * @param ctx The XChaCha context to use
 */
void xcClearBuffer(XChaCha_ctx *ctx);

/** Send a byte to the communication buffer
 * @param ctx The XChaCha context to use
 * @param c Byte to append to the buffer
 */
void xcPutch(XChaCha_ctx *ctx, uint8_t c);

/** Get a byte from the communication buffer
 * @param ctx The XChaCha context to use
 * @return next byte
 */
uint8_t xcGetch(XChaCha_ctx *ctx);

/** Send a byte array to the communication buffer
 * @param ctx The XChaCha context to use
 * @param src Byte array to send
 * @param len Length in bytes
 */
void xcPutsm(XChaCha_ctx *ctx, uint8_t *src, uint8_t len);

/** Encrypt a byte array to the communication buffer
 * @param ctx The XChaCha context to use
 * @param src Byte array to send
 * @param len Length in bytes
 */
void xcPuts(XChaCha_ctx *ctx, uint8_t *src, uint8_t len);


/* ------------------------------------------------------------------------- */

/** hchacha an intermediary step towards XChaCha20 based on the
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
void xchacha_keysetup(XChaCha_ctx *ctx, const uint8_t *k, uint8_t *iv);


/** Set the internal counter to a specific number. Depending
 * on the specification, sometimes the counter is started at 1.
 * @param ctx The XChaCha context to modify
 * @param counter The number to set the counter to
 *
 */
void xchacha_set_counter(XChaCha_ctx *ctx, uint8_t *counter);


/** Get the next PRNG byte
 * @param x The XChaCha20 context with the cipher's state to use
 * @return next byte in the XOR stream
 */
uint8_t xchacha_next(XChaCha_ctx *ctx);


/** Encrypt a set of bytes with XChaCha20
 * @param ctx The XChaCha20 context to use
 * @param plaintext The data to be encrypted
 * @param ciphertext A buffer to hold the encrypted data
 * @param msglen Message length in bytes
 *
 */
void xchacha_encrypt_bytes(XChaCha_ctx* ctx, const uint8_t* plaintext,
		uint8_t* ciphertext,
		uint32_t msglen);


/** Dencrypt a set of bytes with XChaCha20
 * @param ctx The XChaCha20 context to use
 * @param ciphertext The encrypted data to decrypt
 * @param plaintext A buffer to hold the decrypted data
 * @param msglen Message length in bytes
 *
 */
void xchacha_decrypt_bytes(XChaCha_ctx* ctx, const uint8_t* ciphertext,
    uint8_t* plaintext,
    uint32_t msglen);


#endif // XCHACHA20_H_
