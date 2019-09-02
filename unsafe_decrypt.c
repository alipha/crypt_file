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
    unsigned char ch[] = {0x65, 0x78, 0x70, 0x61, 
                          0x6e, 0x64, 0x20, 0x33, 
                          0x32, 0x2d, 0x62, 0x79,
                          0x74, 0x65, 0x20, 0x6b};

    crypto_core_hsalsa20(subkey, n, k, ch);;

    (void)mac;
    (void)result;
    if (m == NULL) {
        return 0;
    }
    if (((uintptr_t) c >= (uintptr_t) m &&
         (uintptr_t) c - (uintptr_t) m < clen) ||
        ((uintptr_t) m >= (uintptr_t) c &&
         (uintptr_t) m - (uintptr_t) c < clen)) { /* LCOV_EXCL_LINE */
        memmove(m, c, (size_t)clen);
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

    return 0;
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
