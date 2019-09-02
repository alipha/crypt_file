#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include "unsafe_decrypt.h"

int
unsafe_secretbox_detached(unsigned char *c, unsigned char *mac,
                          const unsigned char *m,
                          unsigned long long mlen, const unsigned char *n,
                          const unsigned char *k);
int
unsafe_secretbox_easy(unsigned char *c, const unsigned char *m,
                      unsigned long long mlen, const unsigned char *n,
                      const unsigned char *k);

int main() {
    if(sodium_init() == -1)
        return 1;
    char original[] = "this is a test";
    char ciphertext[sizeof original + crypto_secretbox_MACBYTES] = {0};
    char plaintext[sizeof original] = {0};
    char nonce[crypto_secretbox_NONCEBYTES] = {0};
    char key[crypto_secretbox_KEYBYTES] = {0};
    int i;

    printf("%u %u %u %u\n", crypto_secretbox_MACBYTES, crypto_secretbox_NONCEBYTES, crypto_secretbox_KEYBYTES, crypto_stream_salsa20_KEYBYTES);
    crypto_secretbox_easy(ciphertext, original, sizeof original, nonce, key);
    ciphertext[10] ^= 1;
    //crypto_stream_xor(plaintext, ciphertext, sizeof original, nonce, key);
    unsafe_secretbox_open_easy(plaintext, ciphertext, sizeof ciphertext, nonce, key);

    for(i = 0; i < sizeof ciphertext; i++)
        printf("%d ", ciphertext[i]);

    puts("");
    for(i = 0; i < sizeof plaintext; i++)
        putchar(plaintext[i]);

    puts("");
//    puts(plaintext);
    return 0;
}

