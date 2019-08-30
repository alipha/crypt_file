#ifndef CRYPT_FILE_H
#define CRYPT_FILE_H

#include <stddef.h>
#include <stdio.h>


typedef enum crypt_status {
    CRYPT_OK = 0,
    CRYPT_SODIUM_ERROR,
    CRYPT_FILE_ERROR,
    CRYPT_MEMORY_ERROR,
    CRYPT_ENCRYPTION_ERROR,
    CRYPT_KEY_ERROR,
    CRYPT_VERSION_ERROR,
    CRYPT_FILE_FORMAT_ERROR,
    CRYPT_ARGUMENT_ERROR
} crypt_status;


typedef enum crypt_mode {
    CRYPT_READ = 0,
    CRYPT_RW = 1,
    CRYPT_OVERWRITE = 2,
    CRYPT_NEW = 3
} crypt_mode;


typedef struct crypt_file crypt_file;


/*
 * Opens the file named `file_name` using the specified file access `mode`. The mode corresponds to
 * the following fopen modes:
 * CRYPT_READ      = "rb"
 * CRYPT_RW        = "r+b"
 * CRYPT_OVERWRITE = "w+b"
 * CRYPT_NEW       = "w+bx"
 * The file cannot be opened "for text" and no newline translation is performed. The file also
 * cannot be opened "for append".
 *
 * The `key` is a unsigned char[32] from which a file-specific key is derived to encrypt/decrypt the
 * file. The key should be completely random bytes or derived from a password using libsodium's
 * crypto_pwhash.
 *
 * If the file is opened successfully and parsed sucessfully (if it already exists), then a
 * crypt_file* file handle is assigned to `*out_file_handle`. Else, NULL is assigned to the address
 * pointed to by `out_file_handle`.
 *
 * CRYPT_OK - returned upon successful opening and (if the file already exists) parsing of the file.
 * CRYPT_SODIUM_ERROR - this library depends upon the libsodium library and libsodium did not
 *      properly initialize.
 * CRYPT_FILE_ERROR - a file i/o error occurred while opening or reading the file. See ferror() for
 *      additional information.
 * CRYPT_MEMORY_ERROR - crypt_open failed to allocate memory for the crypt_file object.
 * CRYPT_FILE_FORMAT_ERROR - the file already exists and was not a file previously encrypted with
 *      this library.
 * CRYPT_VERSION_ERROR - the file already exists and was encrypted with a different version of this
 *      library.
 * CRYPT_KEY_ERROR - the file already exists but was encrypted with a different key than the key
 *      that was provided.
 * CRYPT_ENCRYPTION_ERROR - the file already exists and the header stated it was a file encrypted
 *      with this library version and the correct key, but decryption of the file failed, either
 *      due to corruption or malicious modification.
 */ 
crypt_status crypt_open(const char *file_name, const unsigned char *key, crypt_mode mode, crypt_file **out_file_handle);


crypt_status crypt_start(FILE *file, int writable, const unsigned char *key, size_t chunk_size, long file_offset, crypt_file **out_cf);

/*
 * Reads the whole file and validates the cryptographic integrity of the whole file. Normal usage
 * of this library only validates the sections of the file which are actually accessed.
 *
 * The current file position is restored to what it was previously after calling this function.
 *
 * `cf` must be NULL or by a valid crypt_file* obtained from crypt_open or crypt_start.
 *
 * Returns CRYPT_OK if the file has not been corrupted or maliciously modified, or `cf` is NULL.
 * Returns CRYPT_FILE_ERROR if a file i/o error occurred while reading the file (or writing cached
 *      changes.) See ferror() for additional information.
 * Returns CRYPT_ENCRYPTION_ERROR if the cryptographic integrity of the file has been compromised.
 */
crypt_status crypt_validate(crypt_file *cf);

/*
 * Reads and decrypts up to `max` bytes from the current file position into `buffer`. The number 
 * of bytes read may be less than `max` if the end of file is reached or a file i/o error occurred.
 *
 * `cf` must be a valid crypt_file* obtained from crypt_open or crypt_start.
 *
 * `*out_size` is assigned the number of bytes successfully read.
 *
 * Returns CRYPT_OK if no error occurred while reading or decrypting the bytes from the file.
 * Returns CRYPT_FILE_ERROR if a file i/o error occurred while reading the file (or writing cached
 *      changes.) See ferror() for additional information.
 * Returns CRYPT_ENCRYPTION_ERROR if the cryptographic integrity of the file has been compromised.
 */
crypt_status crypt_read(crypt_file *cf, void *buffer, size_t max, size_t *out_size);

/*
 * Encrypts and writes `size` bytes from `buffer` to the file, starting at the current file 
 * position. Writes are buffered and may not be actually written until crypt_flush or crypt_close 
 * is called.
 *
 * `cf` must be a valid crypt_file* obtained from crypt_open or crypt_start.
 *
 * Returns CRYPT_OK if no file i/o occurred and no decryption error occurred. Note that file i/o
 *      errors may be due to writing previously-cached changes or reading in new sections of the
 *      file to be cached, and not actually be related to the specific data being written. See
 *      ferror() for additional information on the exact file error.
 * Returns CRYPT_FILE_ERROR if a file i/o error occurred.
 * Returns CRYPT_ENCRYPTION_ERROR if the cryptographic integrity of the file has been compromised.
 */
crypt_status crypt_write(crypt_file *cf, const void *buffer, size_t size);


/*
 * Encrypts and writes the `ch` character `size` times to the file, starting at the current file 
 * position. Writes are buffered and may not be actually written until crypt_flush or crypt_close is
 * called.
 *
 * `cf` must be a valid crypt_file* obtained from crypt_open or crypt_start.
 *
 * Returns CRYPT_OK if no file i/o occurred and no decryption error occurred. Note that file i/o
 *      errors may be due to writing previously-cached changes or reading in new sections of the
 *      file to be cached, and not actually be related to the specific data being written. See
 *      ferror() for additional information on the exact file error.
 * Returns CRYPT_FILE_ERROR if a file i/o error occurred.
 * Returns CRYPT_ENCRYPTION_ERROR if the cryptographic integrity of the file has been compromised.
 */
crypt_status crypt_fill(crypt_file *cf, char ch, size_t size);

/*
 * Seeks to a specific location in the file, which is an `offset` from a specified `origin`. The
 * new file location cannot be negative. Seeking past the end of the file results in encrypted
 * nul characters being appended to the file up to the specified file location. Offsets refer to
 * the logical positions in the file and exclude any space overhead of the encryption.
 *
 * `cf` must be a valid crypt_file* obtained from crypt_open or crypt_start.
 *
 * `origin` can be SEEK_SET, SEEK_CUR, or SEEK_END, which have the same usage as in fseek.
 * 
 * Returns CRYPT_OK if the seek was successful.
 * Returns CRYPT_FILE_ERROR if a file i/o error occurred while writing cached data or reading
 *      the section of the file that was seeked to.
 * Returns CRYPT_ENCRYPTION_ERROR if new file section has been corrupted or maliciously modified.
 * Returns CRYPT_ARGUMENT_ERROR if `origin` is not SEEK_SET, SEEK_CUR, or SEEK_END, or if the
 *      new file position is negative.
 */
crypt_status crypt_seek(crypt_file *cf, long offset, int origin);

/*
 * Returns the logical zero-based position in the file, from which crypt_read will read or to which
 * crypt_write will write. This number excludes any overhead due to encryption. This function will
 * not fail (but will produce undefined behavior if `cf` is invalid.)
 *
 * `cf` must be a valid crypt_file* obtained from crypt_open or crypt_start. 
 */
long crypt_tell(crypt_file *cf);

/*
 * Flushes any cached data from previous crypt_write calls which are uncommitted.
 *
 * `cf` must be NULL or by a valid crypt_file* obtained from crypt_open or crypt_start.
 *
 * Returns CRYPT_OK if no file i/o errors occurred or if `cf` is NULL.
 * Returns CRYPT_FILE_ERROR if an error occurred while flushing the changes.
 */ 
crypt_status crypt_flush(crypt_file *cf);

/*
 * Flushes any cached data, closes the file, and frees the memory pointed to by the crypt_file*.
 * `cf` is invalid after crypt_close and cannot be used with any other crypt_* functions.
 *
 * `cf` must be NULL or by a valid crypt_file* obtained from crypt_open or crypt_start.
 *
 * Returns CRYPT_OK if no file i/o errors occurred or if `cf` is NULL.
 * Returns CRYPT_FILE_ERROR if an error occurred while flushing the changes or closing the file.
 */
crypt_status crypt_close(crypt_file *cf);

/*
 * Flushes any cached data and frees the memory pointed to by the crypt_file*. Does NOT close the file.
 *
 * `cf` is invalid after crypt_stop and cannot be used with any other crypt_* functions.
 *
 * `cf` must be NULL or by a valid crypt_file* obtained from crypt_start or crypt_open.
 *
 * Returns CRYPT_OK if no file i/o errors occurred or if `cf` is NULL.
 * Returns CRYPT_FILE_ERROR if an error occurred while flushing the changes to the file.
 */
crypt_status crypt_stop(crypt_file *cf);

#endif

