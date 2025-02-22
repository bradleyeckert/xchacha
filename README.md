# Tiny Version of XChaCha20

According to an [IETF draft](https://tools.ietf.org/html/draft-arciszewski-xchacha-02),

> The eXtended-nonce ChaCha cipher construction (XChaCha) allows for ChaCha-based ciphersuites to accept a 192-bit nonce with similar
> guarantees to the original construction, except with a much lower probability of nonce misuse occurring. This enables XChaCha
> constructions to be stateless, while retaining the same security assumptions as ChaCha.

The small [spcnvdr/XChaCha20](https://github.com/spcnvdr/xchacha20) library was not small enough, so I re-factored it for minimum footprint. The target processor is 32-bit such as RISC V or Arm Cortex. Giving the code a little-endian dependency simplified it.

The block dependency of [spcnvdr/XChaCha20](https://github.com/spcnvdr/xchacha20) prevented small chunks of keystream from being used without calling `xchacha_init` before each `xchacha_encrypt_bytes`.
This restriction is removed. The small abstraction layer in the form of `xc_crypt_setkey` and `xc_crypt_block` facilitate swappeing out encryption with AES or SM4.

**More Information**

- [IETF XChaCha20 Draft](https://tools.ietf.org/html/draft-arciszewski-xchacha-03)
- [Bernstein's ChaCha Web page](http://cr.yp.to/chacha.html)
- [Libsodium Documentation](https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xchacha20)
- [Crypto++ Documentation](https://www.cryptopp.com/wiki/XChaCha20)
- [Wikipedia Salsa20](https://en.wikipedia.org/wiki/Salsa20)

**WARNING**

I am not a cryptographer so use this library at your own risk.  

**Getting Started**

Import the library into your project

```C
    #include "xchacha.h"
```

Create a XChaCha context

```C
    xChaCha_ctx ctx;
```

Set up the 256-bit encryption key and the 256-bit nonce to be used.

```C
    xchacha_init(&ctx, key, nonce);
```

Then use xchacha_encrypt_bytes or xchacha_encrypt_blocks to encrypt data

```C
    xchacha_encrypt_bytes(&ctx, plaintext, ciphertext, sizeof(plaintext));
```

**Test Vectors**

In the src folder is a program named test.c It calculates and compares
XChaCha20 test vectors obtained from two different sources. The test vectors
were borrowed from the IETF draft regarding XChaCha20 and an example from
Crypto++ wikipedia. It will compare the output of this XChaCha20 library with
known good test vectors to ensure this library is working correctly.

To make the test program simply run make

    make

Then run the test program

    ./test

The program will produce the following output if successful:

    Cryptographic tests passed

If this library failed to generate the correct ciphertexts, then something
is wrong with the library and you will see this output:

    Cryptographic tests failed!

**Is it secure?**

NIST recommends cryptography such as (e.g., FIPS 140-3, NIST Suite B), or equivalent-strength cryptographic protection that are expected to be considered cryptographically strong throughout the service life of the device.

XChaCha20 is considered highly secure and may be less susceptible to certain side-channel [attacks](https://eprint.iacr.org/2014/899.pdf) compared to AES. Google, Cloudflare, and Nordstream use XChaCha20 encryption. In terms of achieving the goals of AES, XChaCha20 is lower-risk because it contains fewer hidden surprises.
