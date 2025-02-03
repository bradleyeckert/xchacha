# YChaCha - Tiny Extended Nonce Version of XChaCha20

YChaCha is a stream cipher based on XChaCha20. YChaCha uses a 256-bit key and a 256-bit nonce. According to an [IETF draft:](https://tools.ietf.org/html/draft-arciszewski-xchacha-02),

> The eXtended-nonce ChaCha cipher construction (XChaCha) allows for ChaCha-based ciphersuites to accept a 192-bit nonce with similar
> guarantees to the original construction, except with a much lower probability of nonce misuse occurring. This enables XChaCha
> constructions to be stateless, while retaining the same security assumptions as ChaCha.

The small [XChaCha20](https://github.com/spcnvdr/xchacha20) library was not small enough, so I re-factored it for minimum footprint. The target processor is 32-bit such as RISC V or Arm Cortex. Giving the code a little-endian dependency simplified it. The key and the IV are both 256-bit. It is backward-compatible with XChaCha20 if the last 64 bits of IV are 0. XChaCha20 is the same as YChaCha if the last 64 bits of the 256-bit IV are set using `xchacha_set_counter`.

YChaCha is immune to power analysis side-channel attacks, unlike AES. Since some industries mandate AES (FIPS-140), the 256-bit IV can be shared with AES-CBC (or AES-GCM) for a kind of belt-and-suspenders double-encryption scheme.

XChaCha20's block dependency prevented small chunks of keystream from being used without calling `xchacha_keysetup` before each `xchacha_encrypt_bytes`.
This restriction is removed with YChaCha.

A larger context structure is used to integrate SipHash keyed HMAC and communication FIFOs into the library.

**More Information**

[IETF XChaCha20 Draft](https://tools.ietf.org/html/draft-arciszewski-xchacha-03)

[Bernstein's ChaCha Web page](http://cr.yp.to/chacha.html)

[Libsodium Documentation](https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xchacha20)

[Crypto++ Documentation](https://www.cryptopp.com/wiki/XChaCha20)

[Wikipedia](https://en.wikipedia.org/wiki/Salsa20)

[XChaCha20 Github repo](https://github.com/spcnvdr/xchacha20)

**WARNING**

I am not a cryptographer so use this library at your own risk.  


**Getting Started**

Import the library into your project

```C
    #include "ychacha.h"
```

Create a XChaCha context

```C
    YChaCha_ctx ctx;
```

Set up the 256-bit encryption key and the 256-bit nonce to be used.

```C
    ychacha_keysetup(&ctx, key, nonce);
```

Then use xchacha_encrypt_bytes or xchacha_encrypt_blocks to encrypt data

```C
    ychacha_encrypt_bytes(&ctx, plaintext, ciphertext, sizeof(plaintext));
```


**Test Vectors**

In the src folder is a program named test.c It calculates and compares
XChaCha20 test vectors obtained from two different sources. The test vectors
were borrowed from the IETF draft regarding XChaCha20 and an example from
Crypto++ wikipedia. It will compare the output of this YChaCha library with
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


**To Do**

- [x] Add a program to calculate and compare test vectors
- [ ] Find and add more test vectors for XChaCha20
