#include "unsafe_decrypt.h"
#include <sodium.h>
#include <stddef.h>
#include <stdint.h>
#include <memory.h>

int
unsafe_secretbox_open_detached(unsigned char *m, const unsigned char *c,
                               const unsigned char *mac,
                               unsigned long long clen,
                               const unsigned char *n,
                               const unsigned char *k)
{
    unsigned char      block0[64U];
    unsigned char      subkey[crypto_stream_salsa20_KEYBYTES];
    unsigned long long i;
    unsigned long long mlen0;
    int result;

    crypto_core_hsalsa20(subkey, n, k, NULL);
    crypto_stream_salsa20(block0, crypto_stream_salsa20_KEYBYTES,
                          n + 16, subkey);
    result = crypto_onetimeauth_poly1305_verify(mac, c, clen, block0) != 0;
    (void)result;
    if (m == NULL) {
        return 0; /* result; */
    }
    if (((uintptr_t) c >= (uintptr_t) m &&
         (uintptr_t) c - (uintptr_t) m < clen) ||
        ((uintptr_t) m >= (uintptr_t) c &&
         (uintptr_t) m - (uintptr_t) c < clen)) { /* LCOV_EXCL_LINE */
        memmove(m, c, clen);
        c = m;
    }
    mlen0 = clen;
    if (mlen0 > 64U - crypto_secretbox_ZEROBYTES) {
        mlen0 = 64U - crypto_secretbox_ZEROBYTES;
    }
    for (i = 0U; i < mlen0; i++) {
        block0[crypto_secretbox_ZEROBYTES + i] = c[i];
    }
    crypto_stream_salsa20_xor(block0, block0,
                              crypto_secretbox_ZEROBYTES + mlen0,
                              n + 16, subkey);
    for (i = 0U; i < mlen0; i++) {
        m[i] = block0[i + crypto_secretbox_ZEROBYTES];
    }
    if (clen > mlen0) {
        crypto_stream_salsa20_xor_ic(m + mlen0, c + mlen0, clen - mlen0,
                                     n + 16, 1U, subkey);
    }
    sodium_memzero(subkey, sizeof subkey);

    return 0; /*result;*/
}

int
unsafe_secretbox_open_easy(unsigned char *m, const unsigned char *c,
                           unsigned long long clen, const unsigned char *n,
                           const unsigned char *k)
{
    if (clen < crypto_secretbox_MACBYTES) {
        return 1;
    }
    return unsafe_secretbox_open_detached(m, c + crypto_secretbox_MACBYTES, c,
                                          clen - crypto_secretbox_MACBYTES,
                                          n, k);
}
