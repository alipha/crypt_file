#include "crypt_file.h"
#include "unsafe_decrypt.h"

#include <sodium.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define FILE_FORMAT_NAME "liphEnc"
#define FILE_FORMAT_SIZE 7
#define KEY_BYTES 32U
#define FILE_ID_SIZE 32U
#define VERSION_SIZE 16U
#define FILE_ID_POS (FILE_FORMAT_SIZE + 1)
#define FILE_CHUNK_SIZE_POS (FILE_ID_POS + FILE_ID_SIZE)
#define FILE_MAC_POS (FILE_CHUNK_SIZE_POS + 8)
#define HEADER_SIZE (FILE_MAC_POS + crypto_generichash_BYTES)
#define DEFAULT_CHUNK_SIZE (4096U - HEADER_SIZE)
#define MIN_CHUNK_SIZE 64U
#define CHUNK_OVERHEAD (VERSION_SIZE + crypto_secretbox_MACBYTES)

#define CRYPT_TRY(x) do { crypt_status status = (x); if(status != CRYPT_OK) return status; } while(0)


struct crypt_file {
    unsigned char key[KEY_BYTES];
    unsigned char file_id[FILE_ID_SIZE];
    uint64_t chunk_index;
    uint64_t chunks;
    unsigned char *encrypted_chunk;
    FILE *file;
    long file_offset;
    int unsafe_reads;   /* true/false */
    int chunk_changed;  /* true/false */
    size_t chunk_size;
    size_t last_chunk_size;
    size_t data_pos;   /* within chunk */
    unsigned char data_chunk[1];
};


static const char* crypt_mode_strs[] = {"rb", "r+b", "w+b", "w+bx"};

static crypt_status init(crypt_file **out_cf, const unsigned char *master_key, int writable);
static void file_id_hash(crypt_file *cf, const unsigned char *master_key, unsigned char *dest);

static crypt_status read_chunk(crypt_file *cf);
static crypt_status write_chunk(crypt_file *cf);
static crypt_status switch_chunk(crypt_file *cf, uint64_t new_chunk_index);

static crypt_status seek(crypt_file *cf);

static size_t get_alloc_amount(size_t chunk_size);
static size_t data_size(crypt_file *cf);
static size_t last_data_size(crypt_file *cf);
static size_t max_data_size(crypt_file *cf);

static unsigned char *uint64_to_bytes(unsigned char *bytes, uint64_t value);
static uint64_t bytes_to_uint64(const unsigned char *bytes);

   
crypt_status crypt_open(const char *file_name, const unsigned char *key, crypt_mode mode, crypt_file **out_cf) {
    crypt_status status;
    FILE *file;

    if(!file_name || !key || !out_cf)
        return CRYPT_ARGUMENT_ERROR;

    file = fopen(file_name, crypt_mode_strs[mode]);
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
    
    if(!file || !key || file_offset < 0 || !out_cf)
       return CRYPT_ARGUMENT_ERROR;

    size_t malloc_size = get_alloc_amount(chunk_size);
    if(!malloc_size)
        return CRYPT_ARGUMENT_ERROR;

    cf = malloc(malloc_size);
    if(!cf) 
        return CRYPT_MEMORY_ERROR;

    cf->file = file;
    cf->file_offset = file_offset;
    cf->unsafe_reads = unsafe_reads;
    cf->chunk_size = chunk_size;
    cf->encrypted_chunk = cf->data_chunk + max_data_size(cf);
   
    status = init(&cf, key, writable);
    if(status != CRYPT_OK) {
        free(cf);
        return status;
    }
    
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
            CRYPT_TRY(write_chunk(cf));
            cf->chunk_index++;

            /* TODO: what does read_chunk do if >= cf->chunks? */
            /* do we need to cf->chunks++ if CRYPT_TRY fails? */
            if(size < max_data_len) {
                CRYPT_TRY(read_chunk(cf));
            } else {
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
            CRYPT_TRY(write_chunk(cf));
            cf->chunk_index++;

            /* TODO: what does read_chunk do if >= cf->chunks? */
            /* do we need to cf->chunks++ if CRYPT_TRY fails? */
            if(size < max_data_size(cf)) {
                CRYPT_TRY(read_chunk(cf));
            } else {
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

    assert(cf->chunks > 0);
    file_size = (long)((cf->chunks - 1) * max_data_size(cf) + last_data_size(cf));

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
        return crypt_fill(cf, '\0', (size_t)(new_file_pos - file_size));
    }

    new_index = (size_t)new_file_pos / max_data_size(cf);

    CRYPT_TRY(switch_chunk(cf, new_index));

    cf->data_pos = (size_t)new_file_pos % max_data_size(cf);
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


crypt_status init(crypt_file **out_cf, const unsigned char *master_key, int writable) {
    unsigned char mac[crypto_generichash_BYTES];
    unsigned char header[HEADER_SIZE];
    uint64_t file_chunk_size;
    size_t new_cf_size;
    long size;
    crypt_file *cf = *out_cf;

    if(fseek(cf->file, 0, SEEK_END))
        return CRYPT_FILE_ERROR;

    size = ftell(cf->file);
    if(size == -1 || size - cf->file_offset < 0)
        return CRYPT_FILE_ERROR;

    if(fseek(cf->file, cf->file_offset, SEEK_SET))
        return CRYPT_FILE_ERROR;

    size -= cf->file_offset;
    cf->chunk_index = 0;

    /* TODO: redundant with read_chunk? */
    cf->chunk_changed = 0;
    cf->data_pos = 0;

    if(size && size < (int)HEADER_SIZE)
        return CRYPT_DECRYPTION_ERROR;

    if(size == 0) {
        cf->chunks = 1;
        cf->last_chunk_size = 0;

        randombytes_buf(cf->file_id, sizeof cf->file_id);

        memcpy(header, FILE_FORMAT_NAME, FILE_FORMAT_SIZE);
        header[FILE_FORMAT_SIZE] = 1;  /* set crypt_file version */
        memcpy(header + FILE_ID_POS, cf->file_id, sizeof cf->file_id);
        uint64_to_bytes(header + FILE_CHUNK_SIZE_POS, cf->chunk_size);
        file_id_hash(cf, master_key, header + FILE_MAC_POS);

        /* TODO: should we do all the above if !writable? */
        if(writable && !fwrite(header, sizeof header, 1, cf->file))
            return CRYPT_FILE_ERROR;

    } else if(fread(header, sizeof header, 1, cf->file)) {
        if(!cf->unsafe_reads && sodium_memcmp(FILE_FORMAT_NAME, header, FILE_FORMAT_SIZE))
            return CRYPT_FILE_FORMAT_ERROR;

        if(!cf->unsafe_reads && header[FILE_FORMAT_SIZE] != 1)
            return CRYPT_VERSION_ERROR;

        memcpy(cf->file_id, header + FILE_ID_POS, sizeof cf->file_id);
        file_chunk_size = bytes_to_uint64(header + FILE_CHUNK_SIZE_POS);
        file_id_hash(cf, master_key, mac);
        if(!cf->unsafe_reads && sodium_memcmp(mac, header + FILE_MAC_POS, sizeof mac))
            return CRYPT_KEY_ERROR;

        if(file_chunk_size > SIZE_MAX)
            return CRYPT_FILE_FORMAT_ERROR;

        if(cf->chunk_size != file_chunk_size) {
            new_cf_size = get_alloc_amount((size_t)file_chunk_size);
            if(!new_cf_size)
                return CRYPT_FILE_FORMAT_ERROR;

            cf = realloc(cf, new_cf_size);
            if(!cf)
                return CRYPT_MEMORY_ERROR;

            *out_cf = cf;
        }

        cf->chunks = ((uint64_t)size + cf->chunk_size - HEADER_SIZE - 1) / cf->chunk_size;
        if(cf->chunks == 0)
            cf->chunks = 1;

        cf->last_chunk_size = (size_t)((uint64_t)size - HEADER_SIZE - (cf->chunks - 1) * cf->chunk_size);

        assert(cf->chunks == 1 || cf->last_chunk_size > 0);
        assert(cf->last_chunk_size <= cf->chunk_size);

        if(cf->last_chunk_size > 0 && cf->last_chunk_size < CHUNK_OVERHEAD)
            return CRYPT_DECRYPTION_ERROR;
    } else {
        return CRYPT_FILE_ERROR;
    }

    crypto_generichash(cf->key, sizeof cf->key, header, sizeof header, master_key, KEY_BYTES);
    return read_chunk(cf);
}


void file_id_hash(crypt_file *cf, const unsigned char *master_key, unsigned char *dest) {
    crypto_generichash(dest, crypto_generichash_BYTES, cf->file_id, sizeof cf->file_id, 
            master_key, KEY_BYTES);
}


crypt_status read_chunk(crypt_file *cf) {
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    size_t read_amount = cf->chunk_index == cf->chunks - 1 ? cf->last_chunk_size : cf->chunk_size;
    cf->chunk_changed = 0;
    cf->data_pos = 0;

    assert(sizeof nonce == VERSION_SIZE + sizeof cf->chunk_index);

    if(read_amount != 0) {
        /* TODO: what if chunk_index is at the end of the file? */
        if(fread(cf->encrypted_chunk, 1, read_amount, cf->file) != read_amount)
            return CRYPT_FILE_ERROR;

        uint64_to_bytes(nonce + VERSION_SIZE, cf->chunk_index);
        memcpy(nonce, cf->encrypted_chunk, VERSION_SIZE);

        if(!(cf->unsafe_reads ? unsafe_secretbox_open_easy : crypto_secretbox_open_easy)(cf->data_chunk, cf->encrypted_chunk + VERSION_SIZE, read_amount - VERSION_SIZE, nonce, cf->key))
            return CRYPT_DECRYPTION_ERROR;
    }

    return CRYPT_OK;
}


crypt_status write_chunk(crypt_file *cf) {
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    size_t size = data_size(cf);

    assert(sizeof nonce == VERSION_SIZE + sizeof cf->chunk_index);

    if(!cf->chunk_changed || size == 0)
        return CRYPT_OK;

    cf->chunk_changed = 0;
    CRYPT_TRY(seek(cf));

    randombytes_buf(nonce, VERSION_SIZE);
    uint64_to_bytes(nonce + VERSION_SIZE, cf->chunk_index);

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


crypt_status seek(crypt_file *cf) {
    if(fseek(cf->file, (long)((uint64_t)cf->file_offset + HEADER_SIZE + cf->chunk_index * cf->chunk_size), SEEK_SET))
        return CRYPT_FILE_ERROR;
    else
        return CRYPT_OK;
}


size_t get_alloc_amount(size_t chunk_size) {
    if(chunk_size < MIN_CHUNK_SIZE 
            || chunk_size > SIZE_MAX - chunk_size 
            || chunk_size + chunk_size - CHUNK_OVERHEAD - 1 > SIZE_MAX - sizeof(crypt_file))
        return 0;

    return sizeof(crypt_file) + chunk_size + chunk_size - CHUNK_OVERHEAD - 1;
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


unsigned char *uint64_to_bytes(unsigned char *bytes, uint64_t value) {
    bytes[0] = value & 255;
    bytes[1] = (value >> 8) & 255;
    bytes[2] = (value >> 16) & 255;
    bytes[3] = (value >> 24) & 255;
    bytes[4] = (value >> 32) & 255;
    bytes[5] = (value >> 40) & 255;
    bytes[6] = (value >> 48) & 255;
    bytes[7] = (unsigned char)((value >> 56) & 255);
    return bytes;
}


uint64_t bytes_to_uint64(const unsigned char *bytes) {
    return bytes[0] 
        | ((uint32_t)bytes[1] << 8)
        | ((uint32_t)bytes[2] << 16)
        | ((uint32_t)bytes[3] << 24)
        | ((uint64_t)bytes[4] << 32)
        | ((uint64_t)bytes[5] << 40)
        | ((uint64_t)bytes[6] << 48)
        | ((uint64_t)bytes[7] << 56);
}

