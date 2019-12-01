#include "crypt_file.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>


int main(void) {
    unsigned char key[CRYPT_KEY_BYTES] = {56, 2, 23, 74, 123, 43, 63, 241, 54, 23, 85, 90, 100, 23, 72, 68, 29, 10, 58, 29, 216, 20, 48, 92, 55, 88, 21, 85, 219, 53, 29, 12};
    char buffer[1500];
    size_t amount_read;

    FILE *src, *dest;
    crypt_file *cf, *cf2;
    crypt_status status;

    if(sodium_init() == -1) {
        fprintf(stderr, "error initializing libsodium\n");
        return 1;
    }

    if((status = crypt_open("test3.cf", key, CRYPT_OVERWRITE, &cf))) {
        fprintf(stderr, "crypt_open error: %s\n", crypt_error(status));
        return 1;
    }

    if(!(src = fopen("crypt_file.c", "rb"))) {
        fprintf(stderr, "fopen read error\n");
        return 1;
    }

    while((amount_read = fread(buffer, 1, sizeof buffer, src))) {
        printf("read: %zu\n", amount_read);

        if((status = crypt_write(cf, buffer, amount_read))) {
            fprintf(stderr, "crypt_write error: %s\n", crypt_error(status));
            return 1;
        }
        if(amount_read != sizeof buffer)
            break; 
    }

    fclose(src);

    /* crypt_close flushes any unwritten changes, so this could indeed fail. */
    if((status = crypt_close(cf))) {
        fprintf(stderr, "crypt_close error: %s\n", crypt_error(status));
        return 1;
    } 
 

    if(!(dest = fopen("output.c", "wb"))) {
        fprintf(stderr, "fopen write error\n");
        return 1;
    }

    if((status = crypt_open("test3.cf", key, CRYPT_READ, &cf2))) {
        fprintf(stderr, "crypt_open 2 error: %s\n", crypt_error(status));
        return 1;
    }

    do {
        if((status = crypt_read(cf2, buffer, sizeof buffer, &amount_read))) {
            fprintf(stderr, "crypt_read error: %s\n", crypt_error(status));
            return 1;
        }

        printf("write: %zu\n", amount_read);

        if(fwrite(buffer, 1, amount_read, dest) != amount_read) {
            fprintf(stderr, "fwrite error\n");
            return 1;
        } 
    } while(amount_read == sizeof buffer);

    fclose(dest);

    /* crypt_close flushes any unwritten changes, so this could indeed fail. */
    if((status = crypt_close(cf2))) {
        fprintf(stderr, "crypt_close 2 error: %s\n", crypt_error(status));
        return 1;
    } 
 
    return 0;
}

