#ifndef UNSAFE_DECRYPT_H
#define UNSAFE_DECRYPT_H

int
unsafe_secretbox_open_detached(unsigned char *m, const unsigned char *c,
                               const unsigned char *mac,
                               unsigned long long clen,
                               const unsigned char *n,
                               const unsigned char *k);

int
unsafe_secretbox_open_easy(unsigned char *m, const unsigned char *c,
                           unsigned long long clen, const unsigned char *n,
                           const unsigned char *k);

#endif

