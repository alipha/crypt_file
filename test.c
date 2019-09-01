#include <sodium.h>
#include <stdio.h>
#include <stdint.h>

int main() {
    if(sodium_init() == -1)
        return 1;
    char original[] = "this is a test";
    char ciphertext[sizeof original + crypto_secretbox_MACBYTES] = {0};
    char plaintext[sizeof original] = {0};
    char nonce[crypto_secretbox_NONCEBYTES] = {0};
    char key[crypto_secretbox_KEYBYTES] = {0};
    int i;

    crypto_secretbox_easy(ciphertext, original, sizeof original, nonce, key);
    ciphertext[10] ^= 1;
    crypto_stream_xor(plaintext, ciphertext, sizeof original, nonce, key);
    //crypto_secretbox_open_easy(plaintext, ciphertext, sizeof ciphertext, nonce, key);

    for(i = 0; i < sizeof ciphertext; i++)
        printf("%d ", ciphertext[i]);

    puts("");
    puts(plaintext);
    return 0;
}

