// first chunk is shorter because it's prepended with 128-bit (16-byte) file id and hash.
// NO: nonce is 196 bits: (file_id ^ zero-padded 64-bit chunk_index) || 64-bit chunk_version
// nonce is 64-bit chunk_version || 64-bit chunk_index || zeros
// file key is KDF from user key || file id. 
// store chunk version as: blowfish(version) ^ 
// SECRETBOX_NONCE_BYTES

#include "crypt_file.h"
#include "blowfish.h"
#include "unsafe_decrypt.h"

#include <sodium.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* crypto_generichash_BYTES = 32 */
/* crypto_secretbox_MACBYTES = 16 */
/* crypto_generichash_KEYBYTES = 32 */
/* crypto_secretbox_xsalsa20poly1305_NONCEBYTES = 24 */

#define FILE_FORMAT_NAME "liphEnc"
#define FILE_FORMAT_SIZE 7
#define KEY_BYTES 32U
#define FILE_ID_SIZE 32U
#define VERSION_SIZE 8U
#define FILE_ID_POS (FILE_FORMAT_SIZE + 1)
#define FILE_MAC_POS (FILE_ID_POS + FILE_ID_SIZE)
#define HEADER_SIZE (FILE_MAC_POS + crypto_generichash_BYTES)
#define DEFAULT_CHUNK_SIZE (4096U - HEADER_SIZE)
#define MIN_CHUNK_SIZE 64U
#define CHUNK_OVERHEAD (VERSION_SIZE - crypto_secretbox_MACBYTES)

#define CRYPT_TRY(x) do { crypt_status status = (x); if(status != CRYPT_OK) return status; } while(0)
/*#define UNSAFE_TRY(x) do { crypt_status status = (x); if(!status_ok(cf, status)) return status; } while(0)*/


struct crypt_file {
    unsigned char key[KEY_BYTES];
    BLOWFISH_KEY blowfish_key;
    unsigned char file_id[FILE_ID_SIZE];
    FILE *file;
    long file_offset;
    int unsafe_reads;
    /*int writable;*/
    int chunk_changed;  /* true/false */
    uint64_t chunk_index;
    uint64_t chunk_version;
    /*uint64_t file_size; // data size */
    uint64_t chunks;
    size_t chunk_size;
    size_t last_chunk_size;
    size_t data_pos;   /* within chunk */
    /*size_t data_size;*/  /* within chunk */
    /*unsigned char *data; */
    /*crypt_status status;*/
    unsigned char *encrypted_chunk;
    unsigned char data_chunk[1];
};


static const char* crypt_mode_strs[] = {"rb", "r+b", "w+b", "w+bx"};

static crypt_status init(crypt_file *cf, const unsigned char *master_key, int writable);
static void file_id_hash(crypt_file *cf, const unsigned char *master_key, unsigned char *dest);

static crypt_status read_chunk(crypt_file *cf);
static crypt_status write_chunk(crypt_file *cf);
static crypt_status switch_chunk(crypt_file *cf, uint64_t new_chunk_index);

static crypt_status read_version(crypt_file *cf);
static crypt_status perform_read(crypt_file *cf, unsigned char *nonce, size_t read_amount);
static crypt_status seek(crypt_file *cf);

static size_t data_size(crypt_file *cf);
static size_t last_data_size(crypt_file *cf);
static size_t max_data_size(crypt_file *cf);

/*static int status_ok(crypt_file *cf, crypt_status status);*/

static unsigned char *xor_bytes(unsigned char *dest, unsigned char *src, size_t size);

static unsigned char *uint64_to_bytes(unsigned char *bytes, uint64_t value);
static uint64_t bytes_to_uint64(const unsigned char *bytes);


   
crypt_status crypt_open(const char *file_name, const unsigned char *key, crypt_mode mode, crypt_file **out_cf) {
    crypt_status status;

    if(!file_name || !key || !out_cf)
        return CRYPT_ARGUMENT_ERROR;

    FILE *file = fopen(file_name, crypt_mode_strs[mode]);
    if(!file) {
        *out_cf = NULL;
        return CRYPT_FILE_ERROR;
    }

    status = crypt_start(file, mode != CRYPT_READ, key, 0, 0, 0, out_cf);
    if(status != CRYPT_OK)
        fclose(file);

    return status;
}


crypt_status crypt_start(FILE *file, int writable, const unsigned char *key, size_t chunk_size, long file_offset, int unsafe_reads, crypt_file **out_cf) {
    crypt_status status;
    crypt_file *cf;
    *out_cf = NULL;

    if(sodium_init() == -1)
        return CRYPT_SODIUM_ERROR;

    if(!chunk_size)
        chunk_size = DEFAULT_CHUNK_SIZE;
    
    if(!file || !key || chunk_size < MIN_CHUNK_SIZE || file_offset < 0 || !out_cf)
       return CRYPT_ARGUMENT_ERROR;

    if(chunk_size > SIZE_MAX - chunk_size || chunk_size + chunk_size - CHUNK_OVERHEAD - 1 > SIZE_MAX - sizeof(crypt_file))
        return CRYPT_ARGUMENT_ERROR;

    cf = malloc(sizeof(crypt_file) + chunk_size + chunk_size - CHUNK_OVERHEAD - 1);
    if(!cf) 
        return CRYPT_MEMORY_ERROR;

    cf->file = file;
    cf->file_offset = file_offset;
    cf->unsafe_reads = unsafe_reads;
    cf->chunk_size = chunk_size;
    cf->encrypted_chunk = cf->data_chunk + max_data_size(cf);
   
    status = init(cf, key, writable);
    if(status != CRYPT_OK) {
        free(cf);
        return status;
    }
    /*cf->writable = writable;*/
    
    *out_cf = cf;
    return CRYPT_OK;
}


crypt_status crypt_validate(crypt_file *cf) {
    uint64_t i;

    if(!cf)
        return CRYPT_OK;

    uint64_t prev_chunk_index = cf->chunk_index;
    size_t prev_data_pos = cf->data_pos;

    for(i = 0; i < cf->chunks; i++) {
        CRYPT_TRY(switch_chunk(cf, i));
    }

    CRYPT_TRY(switch_chunk(cf, prev_chunk_index));
    cf->data_pos = prev_data_pos;
    return CRYPT_OK;
}


crypt_status crypt_read(crypt_file *cf, void *buffer, size_t max, size_t *out_size) {
    crypt_status status;
    size_t read_amount;
    size_t total_read = 0;
    size_t data_left;
    unsigned char *ch_buffer = buffer;
    unsigned char *end_buffer;

    if(!cf || (!buffer && max) || !out_size)
        return CRYPT_ARGUMENT_ERROR;

    end_buffer = ch_buffer + max;
    (void)end_buffer;

    while(max) {
        assert(ch_buffer < end_buffer);
        assert(ch_buffer + max == end_buffer);
        assert(cf->data_pos <= data_size(cf));

        data_left = data_size(cf) - cf->data_pos;
        if(!data_left) {
            assert(cf->chunk_index < cf->chunks);

            if(cf->chunk_index >= cf->chunks - 1) {
                *out_size = total_read;
                return CRYPT_OK;
            }

            /*CRYPT_TRY(switch_chunk(cf, cf->chunk_index + 1));*/
            status = switch_chunk(cf, cf->chunk_index + 1);
            if(status != CRYPT_OK) {
                *out_size = total_read;
                return status;
            }

            assert(!cf->data_pos);
            data_left = data_size(cf);
        }

        read_amount = max >= data_left ? data_left : max;
        assert(read_amount);
        assert(ch_buffer + read_amount <= end_buffer);
        assert(max >= read_amount);
        assert(cf->data_pos + read_amount <= data_size(cf));

        memcpy(ch_buffer, cf->data_chunk + cf->data_pos, read_amount);
        ch_buffer += read_amount;
        max -= read_amount;
        cf->data_pos += read_amount;
        total_read += read_amount;
    }

    *out_size = total_read;
    return CRYPT_OK;
}


crypt_status crypt_write(crypt_file *cf, const void *buffer, size_t size) {
    size_t space_left;
    size_t write_amount;
    size_t max_data_len;
    const unsigned char *ch_buffer = buffer;
    const unsigned char *end_buffer;

    if(!cf || (!buffer && size))
        return CRYPT_ARGUMENT_ERROR;

    end_buffer = ch_buffer + size;
    max_data_len = max_data_size(cf);
    (void)end_buffer;

    while(size) {
        assert(ch_buffer < end_buffer);
        assert(ch_buffer + size == end_buffer);
        assert(max_data_len == max_data_size(cf));
        assert(cf->data_pos <= max_data_len);

        space_left = max_data_len - cf->data_pos;
        if(!space_left) {
            /*CRYPT_TRY(switch_chunk(cf, cf->chunk_index + 1));*/
            CRYPT_TRY(write_chunk(cf));
            cf->chunk_index++;

            /* TODO: what does read_chunk/read_version do if >= cf->chunks? */
            /* do we need to cf->chunks++ if CRYPT_TRY fails? */
            if(size < max_data_len) {
                CRYPT_TRY(read_chunk(cf));
            } else {
                CRYPT_TRY(read_version(cf));
                cf->data_pos = 0;
            }

            assert(!cf->data_pos);
            space_left = max_data_len;

            if(cf->chunk_index == cf->chunks)
                cf->chunks++;
        }

        write_amount = size >= space_left ? space_left : size;
        assert(write_amount);
        assert(ch_buffer + write_amount <= end_buffer);
        assert(size >= write_amount);
        assert(cf->data_pos + write_amount <= max_data_len);

        memcpy(cf->data_chunk + cf->data_pos, ch_buffer, write_amount);
        cf->chunk_changed = 1;
        ch_buffer += write_amount;
        size -= write_amount;
        cf->data_pos += write_amount;

        if(cf->chunk_index == cf->chunks - 1)
            cf->last_chunk_size = cf->data_pos + CHUNK_OVERHEAD;
    }

    return CRYPT_OK;
}


crypt_status crypt_fill(crypt_file *cf, char ch, size_t size) {
    size_t space_left;
    size_t write_amount;
    size_t max_data_len;
    int filled = 0;
    int will_fill;
   
    if(!cf)
        return CRYPT_ARGUMENT_ERROR;

    max_data_len = max_data_size(cf);
    will_fill = (!cf->data_pos && size >= max_data_len) || (size >= 2 * max_data_len - cf->data_pos);
    (void)will_fill;

    while(size) {
        assert(cf->data_pos <= max_data_size(cf));

        space_left = max_data_size(cf) - cf->data_pos;
        if(!space_left) {
            /*CRYPT_TRY(switch_chunk(cf, cf->chunk_index + 1));*/
            CRYPT_TRY(write_chunk(cf));
            cf->chunk_index++;

            /* TODO: what does read_chunk/read_version do if >= cf->chunks? */
            /* do we need to cf->chunks++ if CRYPT_TRY fails? */
            if(size < max_data_size(cf)) {
                CRYPT_TRY(read_chunk(cf));
            } else {
                CRYPT_TRY(read_version(cf));
                cf->data_pos = 0;
            }

            assert(!cf->data_pos);
            space_left = max_data_size(cf);

            if(cf->chunk_index == cf->chunks)
                cf->chunks++;
        }

        write_amount = size >= space_left ? space_left : size;
        assert(write_amount);
        assert(size >= write_amount);
        assert(cf->data_pos + write_amount <= max_data_size(cf));

        if(!filled)
            memset(cf->data_chunk + cf->data_pos, ch, write_amount);

        cf->chunk_changed = 1;
        size -= write_amount;
        cf->data_pos += write_amount;

        if(write_amount == max_data_size(cf))
            filled = 1;

        if(cf->chunk_index == cf->chunks - 1)
            cf->last_chunk_size = cf->data_pos + CHUNK_OVERHEAD;
    }

    assert(will_fill == filled);
    return CRYPT_OK;
}


crypt_status crypt_seek(crypt_file *cf, long offset, int origin) {
    uint64_t new_index;
    long new_file_pos;
    long file_size;
   
    if(!cf)
        return CRYPT_ARGUMENT_ERROR;

    file_size = (cf->chunks - 1) * max_data_size(cf) + last_data_size(cf);

    switch(origin) {
    case SEEK_SET:
        new_file_pos = offset;
        break;
    case SEEK_CUR:
        new_file_pos = crypt_tell(cf) + offset;
        break;
    case SEEK_END:
        new_file_pos = file_size + offset;
        break;
    default:
        return CRYPT_ARGUMENT_ERROR;
    }

    if(new_file_pos < 0)
        return CRYPT_ARGUMENT_ERROR;

    if(new_file_pos > file_size) {
        CRYPT_TRY(crypt_seek(cf, 0, SEEK_END));
        return crypt_fill(cf, '\0', new_file_pos - file_size);
    }

    new_index = new_file_pos / max_data_size(cf);

    CRYPT_TRY(switch_chunk(cf, new_index));

    cf->data_pos = new_file_pos % max_data_size(cf);
    return CRYPT_OK;
}


long crypt_tell(crypt_file *cf) {
    if(!cf)
        return -1;

    return (long)(cf->chunk_index * max_data_size(cf) + cf->data_pos);
}


crypt_status crypt_flush(crypt_file *cf) {
    crypt_status status;
    int file_status;

    if(!cf)
        return CRYPT_OK;

    status = write_chunk(cf);
    file_status = fflush(cf->file);

    if(status == CRYPT_OK)
        return file_status ? CRYPT_FILE_ERROR : CRYPT_OK;
    else
        return status;
}


crypt_status crypt_stop(crypt_file *cf) {
    if(!cf)
        return CRYPT_OK;

    crypt_status status = crypt_flush(cf);
    free(cf);
    return status;
}


crypt_status crypt_close(crypt_file *cf) {
    int file_status;
    FILE *file;

    if(!cf)
        return CRYPT_OK;

    file = cf->file;
    crypt_status status = crypt_stop(cf);
    file_status = fclose(file);

    if(status == CRYPT_OK)
        return file_status ? CRYPT_FILE_ERROR : CRYPT_OK;
    else
        return status;
}


crypt_status init(crypt_file *cf, const unsigned char *master_key, int writable) {
    unsigned char blowfish_key[KEY_BYTES];
    unsigned char mac[crypto_generichash_BYTES];
    unsigned char header[HEADER_SIZE];

    if(fseek(cf->file, 0, SEEK_END))
        return CRYPT_FILE_ERROR;

    long size = ftell(cf->file);
    if(size == -1 || size - cf->file_offset < 0)
        return CRYPT_FILE_ERROR;

    if(fseek(cf->file, cf->file_offset, SEEK_SET))
        return CRYPT_FILE_ERROR;

    size -= cf->file_offset;
    cf->chunk_index = 0;
    cf->chunk_version = 0;

    /* TODO: redundant with read_chunk? */
    cf->chunk_changed = 0;
    cf->data_pos = 0;
    /*cf->data_size = 0;*/

    if(size && size < (int)HEADER_SIZE)
        return CRYPT_DECRYPTION_ERROR;

    if(size == 0) {
        cf->chunks = 1;
        cf->last_chunk_size = 0;

        randombytes_buf(cf->file_id, sizeof cf->file_id);
        cf->file_id[0] = 1;   /* set crypt_file version */

        memcpy(header, FILE_FORMAT_NAME, FILE_FORMAT_SIZE);
        memcpy(header + FILE_FORMAT_SIZE, cf->file_id, sizeof cf->file_id);
        file_id_hash(cf, master_key, header + FILE_MAC_POS);

        if(writable && !fwrite(header, sizeof header, 1, cf->file))
            return CRYPT_FILE_ERROR;

    } else if(fread(header, sizeof header, 1, cf->file)) {
        if(!cf->unsafe_reads && sodium_memcmp(FILE_FORMAT_NAME, header, FILE_FORMAT_SIZE))
            return CRYPT_FILE_FORMAT_ERROR;

        if(!cf->unsafe_reads && header[FILE_FORMAT_SIZE] != 1)
            return CRYPT_VERSION_ERROR;

        memcpy(cf->file_id, header + FILE_ID_POS, sizeof cf->file_id);
        file_id_hash(cf, master_key, mac);
        if(!cf->unsafe_reads && sodium_memcmp(mac, header + FILE_MAC_POS, sizeof mac))
            return CRYPT_KEY_ERROR;

        cf->chunks = (size + cf->chunk_size - HEADER_SIZE - 1) / cf->chunk_size;
        if(cf->chunks == 0)
            cf->chunks = 1;

        cf->last_chunk_size = size - HEADER_SIZE - (cf->chunks - 1) * cf->chunk_size;

        assert(cf->chunks == 1 || cf->last_chunk_size > 0);
        assert(cf->last_chunk_size <= cf->chunk_size);

        if(cf->last_chunk_size > 0 && cf->last_chunk_size < CHUNK_OVERHEAD)
            return CRYPT_DECRYPTION_ERROR;
    } else {
        return CRYPT_FILE_ERROR;
    }

    crypto_generichash(cf->key, sizeof cf->key, header, sizeof header, master_key, KEY_BYTES);
    crypto_generichash(blowfish_key, sizeof blowfish_key, cf->key, sizeof cf->key, master_key, KEY_BYTES);
    blowfish_key_setup(blowfish_key, &cf->blowfish_key, sizeof blowfish_key);

    /*cf->data = data_chunk;
    cf->status = CRYPT_OK; */

    return read_chunk(cf);
}


void file_id_hash(crypt_file *cf, const unsigned char *master_key, unsigned char *dest) {
    crypto_generichash(dest, crypto_generichash_BYTES, cf->file_id, sizeof cf->file_id, 
            master_key, KEY_BYTES);
}


crypt_status read_chunk(crypt_file *cf) {
    unsigned char nonce[crypto_secretbox_NONCEBYTES] = {0};
    size_t read_amount = cf->chunk_index == cf->chunks - 1 ? cf->last_chunk_size : cf->chunk_size;
    cf->chunk_changed = 0;
    cf->data_pos = 0;

    if(read_amount != 0) {
        CRYPT_TRY(perform_read(cf, nonce, read_amount));

        if(!(cf->unsafe_reads ? unsafe_secretbox_open_easy : crypto_secretbox_open_easy)(cf->data_chunk, cf->encrypted_chunk + VERSION_SIZE, read_amount - VERSION_SIZE, nonce, cf->key))
            return CRYPT_DECRYPTION_ERROR;
    } else {
        cf->chunk_version = 0;
    }

    /*cf->data_size = read_amount - CHUNK_OVERHEAD;*/
    return CRYPT_OK;
}


crypt_status write_chunk(crypt_file *cf) {
    unsigned char encrypted_version[VERSION_SIZE];
    unsigned char nonce[crypto_secretbox_NONCEBYTES] = {0};
    size_t size = data_size(cf);

    if(!cf->chunk_changed || size == 0)
        return CRYPT_OK;

    cf->chunk_changed = 0;
    CRYPT_TRY(seek(cf));

    uint64_to_bytes(nonce, ++cf->chunk_version);
    /*memcpy(encrypted_chunk, nonce, VERSION_SIZE);*/
    uint64_to_bytes(nonce + VERSION_SIZE, cf->chunk_index);

    blowfish_encrypt(nonce, encrypted_version, &cf->blowfish_key);
    xor_bytes(encrypted_version, nonce + VERSION_SIZE, sizeof cf->chunk_index);
    blowfish_encrypt(encrypted_version, cf->encrypted_chunk, &cf->blowfish_key);

    crypto_secretbox_easy(cf->encrypted_chunk + VERSION_SIZE, cf->data_chunk, size, nonce, cf->key);

    if(!fwrite(cf->encrypted_chunk, size + CHUNK_OVERHEAD, 1, cf->file))
        return CRYPT_FILE_ERROR;

    return CRYPT_OK;
}


crypt_status switch_chunk(crypt_file *cf, uint64_t new_chunk_index) {
    if(new_chunk_index == cf->chunk_index)
        return CRYPT_OK;

    CRYPT_TRY(write_chunk(cf));

    if(new_chunk_index != cf->chunk_index + 1) {
        cf->chunk_index = new_chunk_index;
        CRYPT_TRY(seek(cf));
    } else {
        cf->chunk_index = new_chunk_index;
    }

    return read_chunk(cf);
}


crypt_status read_version(crypt_file *cf) {
    unsigned char nonce[crypto_secretbox_NONCEBYTES] = {0};
    size_t chunk_size = cf->chunk_index == cf->chunks - 1 ? cf->last_chunk_size : cf->chunk_size;

    if(chunk_size != 0) {
        CRYPT_TRY(perform_read(cf, nonce, VERSION_SIZE));
    } else {
        cf->chunk_version = 0;
    }

    return CRYPT_OK;
}


crypt_status perform_read(crypt_file *cf, unsigned char *nonce, size_t read_amount) {
    unsigned char encrypted_version[VERSION_SIZE];

    /* TODO: what if chunk_index is at the end of the file? */
    if(fread(cf->encrypted_chunk, 1, read_amount, cf->file) != read_amount)
        return CRYPT_FILE_ERROR;

    uint64_to_bytes(nonce + VERSION_SIZE, cf->chunk_index);
    /*memcpy(nonce, encrypted_chunk, VERSION_SIZE);*/
    blowfish_decrypt(cf->encrypted_chunk, encrypted_version, &cf->blowfish_key);
    xor_bytes(encrypted_version, nonce + VERSION_SIZE, sizeof cf->chunk_index);
    blowfish_decrypt(encrypted_version, nonce, &cf->blowfish_key); 
    cf->chunk_version = bytes_to_uint64(nonce);
    return CRYPT_OK;
}


crypt_status seek(crypt_file *cf) {
    if(fseek(cf->file, cf->file_offset + HEADER_SIZE + cf->chunk_index * cf->chunk_size, SEEK_SET))
        return CRYPT_FILE_ERROR;
    else
        return CRYPT_OK;
}


size_t data_size(crypt_file *cf) {
    if(cf->chunk_index >= cf->chunks - 1)
        return last_data_size(cf);
    else
        return max_data_size(cf);
}


size_t last_data_size(crypt_file *cf) {
    return cf->last_chunk_size - CHUNK_OVERHEAD;
}

size_t max_data_size(crypt_file *cf) {
    return cf->chunk_size - CHUNK_OVERHEAD;
}

/*
int status_ok(crypt_file *cf, crypt_status status) {
    return status == CRYPT_OK || (status == CRYPT_DECRYPTION_ERROR && cf->unsafe_reads);
}
*/

unsigned char *xor_bytes(unsigned char *dest, unsigned char *src, size_t size) {
    size_t i;
    for(i = 0; i < size; i++)
        dest[i] ^= src[i];
    return dest;
}


unsigned char *uint64_to_bytes(unsigned char *bytes, uint64_t value) {
    bytes[0] = value & 255;
    bytes[1] = (value >> 8) & 255;
    bytes[2] = (value >> 16) & 255;
    bytes[3] = (value >> 24) & 255;
    bytes[4] = (value >> 32) & 255;
    bytes[5] = (value >> 40) & 255;
    bytes[6] = (value >> 48) & 255;
    bytes[7] = (value >> 56) & 255;
    return bytes;
}


uint64_t bytes_to_uint64(const unsigned char *bytes) {
    return bytes[0] 
        | ((uint16_t)bytes[1] << 8)
        | ((uint32_t)bytes[2] << 16)
        | ((uint32_t)bytes[3] << 24)
        | ((uint64_t)bytes[4] << 32)
        | ((uint64_t)bytes[5] << 40)
        | ((uint64_t)bytes[6] << 48)
        | ((uint64_t)bytes[7] << 56);
}

