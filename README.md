# crypt_file
A C library for effortlessly reading/writing encrypted files in the crypt_file file format.

crypt_file provides a secure and simple API for random-access into an encrypted file, very similar to
fopen/fwrite/fread/fseek/ftell/fclose. You only need to provide a key to the library to perform the
encryption, and all the details of how the encryption is performed is handled automatically. This
library uses its own file format and does not conform to any other existing file format.

The library is built on top of libsodium, so you'll need libsodium installed. You'll also probably
will want to use libsodium for generating encryption keys.

Here's a simple example which generates a random key, writes a message to a file, and then reads back
in that message:
```c
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

    crypt_file *cf;
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

    file_pos = crypt_tell(cf);
    printf("Wrote `%s`. Now at file position %ld\n", sample_text, file_pos);
    /* output: Wrote `hello world!`. Now at file position 12
     * The actual file is larger, due to the encryption overhead. */

    /* return to the beginning of the file so we can read what we just wrote */
    if((status = crypt_seek(cf, 0, SEEK_SET))) {
        fprintf(stderr, "crypt_seek error: %s\n", crypt_error(status));
        return 1;
    }

    /* read in the message we just wrote */
    if((status = crypt_read(cf, read_buffer, sizeof read_buffer - 1, &amount_read))) {
        fprintf(stderr, "crypt_read error: %s\n", crypt_error(status));
        return 1;
    } 

    read_buffer[amount_read] = '\0';
    printf("Read `%s`\n", read_buffer);

    /* crypt_close flushes any unwritten changes, so this could indeed fail. */
    if((status = crypt_close(cf))) {
        fprintf(stderr, "crypt_close error: %s\n", crypt_error(status));
        return 1;
    } 
 
    return 0;
}
```

Note that writes are buffered, so crypt_write does not immediately write the data to the file. If
you want to force changes to be written, use crypt_flush:

```c
    /* write "hello world!" encrypted to the file */
    if((status = crypt_write(cf, sample_text, strlen(sample_text)))) {
        fprintf(stderr, "crypt_write error: %s\n", crypt_error(status));
        return 1;
    } 

    if((status = crypt_flush(cf))) {
        fprintf(stderr, "crypt_flush error: %s\n", crypt_error(status));
        return 1;
    } 
```

Also note that since writes are buffered, if any calls to any library functions fail, the safest
course of action would be to crypt_close the file and re-open it. Exactly which data has been
successfully written and the file position after an error may be difficult to determine.


See crypt_file.h for the exact definitions of the library's functions and additional information.
