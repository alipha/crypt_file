#include "crypt_file.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>


int main(void) {
    unsigned char key[CRYPT_KEY_BYTES];
    char read_buffer[20];
    const char *sample_text = "hello world!";
    long file_pos;
    size_t amount_read;

    crypt_file *cf, *cf2;
    crypt_status status;

    if(sodium_init() == -1) {
        fprintf(stderr, "error initializing libsodium\n");
        return 1;
    }

    /* generate a random key */
    randombytes_buf(key, sizeof key);
    
    /* open "test.cf" for writing and overwrite it if it already exists. */
    if((status = crypt_open("test.cf", key, CRYPT_OVERWRITE, &cf))) {
        fprintf(stderr, "crypt_open error: %s\n", crypt_error(status));
        return 1;
    }

    /* write "hello world!" encrypted to the file */
    if((status = crypt_write(cf, sample_text, strlen(sample_text)))) {
        fprintf(stderr, "crypt_write error: %s\n", crypt_error(status));
        return 1;
    } 

    /* crypt_close flushes any unwritten changes, so this could indeed fail. */
    if((status = crypt_close(cf))) {
        fprintf(stderr, "crypt_close error: %s\n", crypt_error(status));
        return 1;
    } 
 

    if((status = crypt_open("test.cf", key, CRYPT_READ, &cf2))) {
        fprintf(stderr, "crypt_open error: %s\n", crypt_error(status));
        return 1;
    }

    /* read in the message we just wrote */
    if((status = crypt_read(cf2, read_buffer, sizeof read_buffer - 1, &amount_read))) {
        fprintf(stderr, "crypt_read error: %s\n", crypt_error(status));
        return 1;
    } 

    read_buffer[amount_read] = '\0';
    printf("Read `%s`\n", read_buffer);

    /* crypt_close flushes any unwritten changes, so this could indeed fail. */
    if((status = crypt_close(cf2))) {
        fprintf(stderr, "crypt_close error: %s\n", crypt_error(status));
        return 1;
    } 
 
    return 0;
}

