// first chunk is shorter because it's prepended with 128-bit (16-byte) file id and hash.
// NO: nonce is 196 bits: (file_id ^ zero-padded 64-bit chunk_index) || 64-bit chunk_version
// nonce is 64-bit chunk_version || 64-bit chunk_index || zeros
// file key is KDF from user key || file id. 
// store chunk version as: blowfish(version) ^ 
// SECRETBOX_NONCE_BYTES

#include "crypt_file.h"

#include <sodium.h>

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
#define FIRST_CHUNK_OFFSET (FILE_FORMAT_SIZE + FILE_ID_SIZE + crypto_generichash_BYTES)
#define CHUNK_SIZE 4032U
#define CHUNK_OVERHEAD (VERSION_SIZE - crypto_secretbox_MACBYTES)
#define CHUNK_DATA_SIZE (CHUNK_SIZE - CHUNK_OVERHEAD)

#define CRYPT_TRY(x) do { crypt_status status = (x); if(status != CRYPT_OK) return status; } while(false)


struct crypt_file {
    unsigned char data_chunk[CHUNK_DATA_SIZE];
    unsigned char key[KEY_BYTES];
    unsigned char file_id[FILE_ID_SIZE];
    FILE *file;
    /*int writable;*/
    int chunk_changed;  /* true/false */
    uint64_t chunk_index;
    uint64_t chunk_version;
    /*uint64_t file_size; // data size */
    uint64_t chunks;
    size_t last_chunk_size;
    size_t data_pos;   /* within chunk */
    size_t data_size;  /* within chunk */
    /*unsigned char *data; */
    /*crypt_status status;*/
};


static const char* crypt_mode_strs[] = {"rb", "r+b", "w+b", "w+bx"};

static crypt_status init(crypt_file *cf, const unsigned char *master_key, crypt_mode mode);
static void file_id_hash(crypt_file *cf, unsigned char *master_key, unsigned char *dest);

static crypt_status read_chunk(crypt_file *cf);
static crypt_status write_chunk(crypt_file *cf);
static crypt_status switch_chunk(crypt_file *cf, uint64_t new_chunk_index);

static unsigned char *uint64_to_bytes(unsigned char *bytes, uint64_t value);
static uint64_t bytes_to_uint64(unsigned char *bytes);



crypt_status crypt_open(const char *file_name, const unsigned char *key, crypt_mode mode, crypt_file **out_cf) {
    crypt_status status;
    crypt_file *cf = malloc(sizeof(crypt_file));
    *out_cf = NULL;

    if(!cf) 
        return CRYPT_MEMORY_ERROR;

    cf->file = fopen(file_name, crypt_mode_strs[mode]);
    if(!cf->file) {
        free(cf);
        return CRYPT_FILE_ERROR;
    }

    status = init(cf, key, mode);
    if(status != CRYPT_OK) {
        fclose(cf->file);
        free(cf);
        return status;
    }
    /*cf->writable = writable;*/
    
    *out_cf = cf;
    return CRYPT_OK;
}


crypt_status crypt_validate(crypt_file *cf) {
    if(!cf)
        return CRYPT_OK;

    uint64_t prev_chunk_index = cf->chunk_index;
    size_t prev_data_pos = cf->data_pos;

    for(uint64_t i = 0; i < cf->chunks; i++) {
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

    while(max) {
        data_left = cf->data_size - cf->data_pos;
        if(!data_left) {
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

            data_left = cf->data_size;
        }

        read_amount = max >= data_left ? data_left : max;
        memcpy(buffer, cf->data_chunk + cf->data_pos, read_amount);
        buffer += read_amount;
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

    /* TODO: get rid of reads when the whole chunk is being written to */
    while(size) {
        space_left = CHUNK_DATA_SIZE - cf->data_pos;
        if(!space_left) {
            CRYPT_TRY(switch_chunk(cf, cf->chunk_index + 1));
            space_left = CHUNK_DATA_SIZE;

            if(cf->chunk_index == cf->chunks)
                cf->chunks++;
        }

        write_amount = size >= space_left ? space_left : size;
        memcpy(cf->data_chunk, buffer, write_amount);
        cf->chunk_changed = 1;
        buffer += write_amount;
        size -= write_amount;
        cf->data_pos += write_amount;

        if(cf->chunk_index == cf->chunks - 1)
            cf->last_chunk_size = cf->data_pos;
    }

    return CRYPT_OK;
}


crypt_status crypt_seek(crypt_file *cf, long offset, int origin) {
    uint64_t new_index;
    size_t new_data_pos;
    long new_file_pos;
    long file_size = (cf->chunks - 1) * CHUNK_DATA_SIZE + cf->last_chunk_size;

    switch(origin) {
    case SEEK_SET:
        new_file_pos = 0;
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

    if(new_file_pos < 0 || new_file_pos > file_size)  /* TODO: allow seek past end of file */
        return CRYPT_ARGUMENT_ERROR;

    new_index = new_file_pos / CHUNK_DATA_SIZE;

    CRYPT_TRY(switch_chunk(cf, new_index));

    cf->data_pos = new_file_pos % CHUNK_DATA_SIZE;
    return CRYPT_OK;
}


long crypt_tell(crypt_file *cf) {
    return (long)(cf->chunk_index * CHUNK_DATA_SIZE + cf->data_pos);
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


crypt_status crypt_close(crypt_file *cf) {
    int file_status;

    if(!cf)
        return CRYPT_OK;

    crypt_status status = crypt_flush(cf);
    file_status = fclose(cf->file);
    free(cf);

    if(status == CRYPT_OK)
        return file_status ? CRYPT_FILE_ERROR : CRYPT_OK;
    else
        return status;
}


crypt_status init(crypt_file *cf, const unsigned char *master_key, crypt_mode mode) {
    unsigned char mac[crypto_generichash_BYTES];
    unsigned char header[FIRST_CHUNK_OFFSET];

    if(fseek(cf->file, 0, SEEK_END))
        return CRYPT_FILE_ERROR;

    long size = ftell(cf->file);
    if(size == -1)
        return CRYPT_FILE_ERROR;

    if(fseek(cf->file, 0, SEEK_SET))
        return CRYPT_FILE_ERROR;

    cf->chunk_index = 0;
    cf->chunk_version = 0;

    /* TODO: redundant with read_chunk? */
    cf->chunk_changed = 0;
    cf->data_pos = 0;
    cf->data_size = 0;

    if(size && size < FIRST_CHUNK_OFFSET)
        return CRYPT_ENCRYPTION_ERROR;

    if(size == 0) {
        cf->chunks = 1;
        cf->last_chunk_size = 0;

        randombytes_buf(cf->file_id, sizeof cf->file_id);
        cf->file_id[0] = 1;   /* set crypt_file version */

        strcpy(header, FILE_FORMAT_NAME);
        memcpy(header + FILE_FORMAT_SIZE, cf->file_id, sizeof cf->file_id);
        file_id_hash(cf, master_key, header + FILE_FORMAT_NAME + sizeof cf->file_id);

        if(mode != CRYPT_READ && !fwrite(header, sizeof header, 1, cf->file))
            return CRYPT_FILE_ERROR;

    } else if(fread(header, sizeof header, 1, cf->file)) {
        if(sodium_memcmp(FILE_FORMAT_NAME, header, sizeof FILE_FORMAT_SIZE))
            return CRYPT_FILE_FORMAT_ERROR;

        if(header[FILE_FORMAT_NAME] != 1)
            return CRYPT_VERSION_ERROR;

        memcpy(cf->file_id, header + FILE_FORMAT_NAME, sizeof cf->file_id);
        file_id_hash(cf, master_key, mac);
        if(sodium_memcmp(mac, header + FILE_FORMAT_NAME + sizeof cf->file_id, sizeof mac))
            return CRYPT_KEY_ERROR;

        cf->chunks = (size + CHUNK_SIZE - FIRST_CHUNK_OFFSET - 1) / CHUNK_SIZE;
        if(cf->chunks == 0)
            cf->chunks = 1;

        cf->last_chunk_size = size - FIRST_CHUNK_OFFSET - (cf->chunks - 1) * CHUNK_SIZE;

        assert(cf->chunks == 1 || cf->last_chunk_size > 0);
        assert(cf->last_chunk_size <= CHUNK_SIZE);

        if(cf->last_chunk_size > 0 && cf->last_chunk_size < CHUNK_OVERHEAD)
            return CRYPT_ENCRYPTION_ERROR;
    } else {
        return CRYPT_FILE_ERROR;
    }

    crypto_generichash(cf->key, KEY_BYTES, header, sizeof header, master_key, KEY_BYTES);

    /*cf->data = data_chunk;
    cf->status = CRYPT_OK; */

    read_chunk(cf);
    /* TODO: CRYPT_APPEND */

}


void file_id_hash(crypt_file *cf, unsigned char *master_key, unsigned char *dest) {
    crypto_generichash(dest, crypto_generichash_BYTES, cf->file_id, sizeof cf->file_id, 
            master_key, KEY_BYTES);
}


crypt_status read_chunk(crypt_file *cf) {
    unsigned char encrypted_chunk[CHUNK_SIZE];
    unsigned char nonce[crypto_secretbox_NONCEBYTES] = {0};
    size_t read_amount = cf->chunk_index == cf->chunks - 1 ? cf->last_chunk_size : CHUNK_SIZE;

    if(read_amount != 0) {
        /* TODO: what if chunk_index is at the end of the file? */
        if(fread(encrypted_chunk, 1, read_amount, cf->file) != read_amount)
            return CRYPT_FILE_ERROR;

        /* TODO: decrypt nonce */
        memcpy(nonce, encrypted_chunk, VERSION_SIZE);
        cf->chunk_version = bytes_to_uint64(nonce);
        uint64_to_bytes(nonce + VERSION_SIZE, cf->chunk_index);

        if(!crypto_secretbox_open_easy(cf->data_chunk, encrypted_chunk + VERSION_SIZE, read_amount - VERSION_SIZE, nonce, cf->key))
            return CRYPT_ENCRYPTION_ERROR;
    }

    cf->chunk_changed = 0;
    cf->data_pos = 0;
    cf->data_size = read_amount - CHUNK_OVERHEAD;
    return CRYPT_OK;
}


crypt_status write_chunk(crypt_file *cf) {
    unsigned char encrypted_chunk[CHUNK_SIZE];
    unsigned char nonce[crypto_secretbox_NONCEBYTES] = {0};

    if(!cf->chunk_changed || cf->data_size == 0)
        return CRYPT_OK;

    /* TODO: encrypt nonce */
    uint64_to_bytes(encrypted_chunk, ++cf->chunk_version);
    memcpy(nonce, encrypted_chunk, VERSION_SIZE);
    uint64_to_bytes(nonce + VERSION_SIZE, cf->chunk_index);

    crypto_secretbox_easy(encrypted_chunk + VERSION_SIZE, cf->data_chunk, cf->data_size, nonce, cf->key);

    if(!fwrite(encrypted_chunk, cf->data_size + CHUNK_OVERHEAD, 1, cf->file))
        return CRYPT_FILE_ERROR;

    cf->chunk_changed = 0;
    return CRYPT_OK;
}


crypt_status switch_chunk(crypt_file *cf, uint64_t new_chunk_index) {
    if(new_chunk_index == cf->chunk_index)
        return CRYPT_OK;

    CRYPT_TRY(write_chunk(cf));

    cf->chunk_index = new_chunk_index;
    return read_chunk(cf);
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


uint64_t bytes_to_uint64(unsigned char *bytes) {
    return bytes[0] 
        | ((uint16_t)bytes[1] << 8)
        | ((uint32_t)bytes[2] << 16)
        | ((uint32_t)bytes[3] << 24)
        | ((uint64_t)bytes[4] << 32)
        | ((uint64_t)bytes[5] << 40)
        | ((uint64_t)bytes[6] << 48)
        | ((uint64_t)bytes[7] << 56);
}

