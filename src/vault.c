
/**
 * vault.c - Vault Manager Implementation
 *
 * Implements vault file I/O with atomic writes, binary format serialization/
 * deserialization, and the full encrypt/decrypt pipeline for the vault file.
 */

#include "vault.h"
#include "platform.h"
#include "encryption.h"

#include <stdlib.h>
#include <string.h>

/* ─── Internal Helpers: Little-Endian Read/Write ──────────────────────────── */

static void write_u16_le(uint8_t *buf, uint16_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
}

static void write_u32_le(uint8_t *buf, uint32_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
}

static void write_u64_le(uint8_t *buf, uint64_t val)
{
    for (int i = 0; i < 8; i++) {
        buf[i] = (uint8_t)((val >> (i * 8)) & 0xFF);
    }
}

static uint16_t read_u16_le(const uint8_t *buf)
{
    return (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
}

static uint32_t read_u32_le(const uint8_t *buf)
{
    return (uint32_t)buf[0] |
           ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) |
           ((uint32_t)buf[3] << 24);
}

static uint64_t read_u64_le(const uint8_t *buf)
{
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) {
        val |= ((uint64_t)buf[i] << (i * 8));
    }
    return val;
}

/* ─── File I/O Functions ──────────────────────────────────────────────────── */

StoreResult store_load(const char *path, uint8_t **data, size_t *len)
{
    if (path == NULL || data == NULL || len == NULL) {
        return STORE_ERR_FILE_NOT_FOUND;
    }

    *data = NULL;
    *len = 0;

    /* Check if file exists */
    if (!platform_file_exists(path)) {
        return STORE_ERR_FILE_NOT_FOUND;
    }

    /* Read file into memory */
    if (!platform_file_read(path, data, len)) {
        return STORE_ERR_PERMISSION;
    }

    /* Validate minimum size (must have at least the 64-byte header) */
    if (*len < VAULT_HEADER_SIZE) {
        free(*data);
        *data = NULL;
        *len = 0;
        return STORE_ERR_CORRUPT;
    }

    /* Validate magic bytes */
    if ((*data)[0] != VAULT_MAGIC_0 ||
        (*data)[1] != VAULT_MAGIC_1 ||
        (*data)[2] != VAULT_MAGIC_2 ||
        (*data)[3] != VAULT_MAGIC_3) {
        free(*data);
        *data = NULL;
        *len = 0;
        return STORE_ERR_CORRUPT;
    }

    return STORE_OK;
}

StoreResult store_save(const char *path, const uint8_t *data, size_t len)
{
    if (path == NULL || data == NULL) {
        return STORE_ERR_WRITE_FAILED;
    }

    if (!platform_file_write_atomic(path, data, len)) {
        return STORE_ERR_WRITE_FAILED;
    }

    return STORE_OK;
}

bool store_exists(const char *path)
{
    if (path == NULL) {
        return false;
    }
    return platform_file_exists(path);
}

/* ─── Internal: Credential Serialization ──────────────────────────────────── */

/**
 * Calculate the serialized size of a single credential.
 * Format: id(4) + url_len(2) + url + user_len(2) + username +
 *         pass_len(2) + password + created_at(8) + modified_at(8) + deleted(1)
 */
static size_t credential_serialized_size(const Credential *cred)
{
    size_t url_len = strlen(cred->url);
    size_t user_len = strlen(cred->username);
    size_t pass_len = strlen(cred->password);

    return 4                /* id */
         + 2 + url_len     /* url_len + url */
         + 2 + user_len    /* user_len + username */
         + 2 + pass_len    /* pass_len + password */
         + 8               /* created_at */
         + 8               /* modified_at */
         + 1;              /* deleted */
}

/**
 * Serialize all credentials in the vault to a plaintext buffer.
 * Caller must free *out_buf when done.
 * Returns STORE_OK on success, STORE_ERR_WRITE_FAILED on memory allocation failure.
 */
static StoreResult serialize_credentials(const Vault *vault,
                                         uint8_t **out_buf, size_t *out_len)
{
    size_t total_size = 0;
    uint8_t *buf;
    size_t offset = 0;

    /* Calculate total buffer size */
    for (uint32_t i = 0; i < vault->count; i++) {
        total_size += credential_serialized_size(&vault->entries[i]);
    }

    /* Handle empty vault */
    if (total_size == 0) {
        *out_buf = NULL;
        *out_len = 0;
        return STORE_OK;
    }

    /* Allocate buffer */
    buf = (uint8_t *)malloc(total_size);
    if (buf == NULL) {
        return STORE_ERR_WRITE_FAILED;
    }

    /* Serialize each credential */
    for (uint32_t i = 0; i < vault->count; i++) {
        const Credential *cred = &vault->entries[i];
        size_t url_len = strlen(cred->url);
        size_t user_len = strlen(cred->username);
        size_t pass_len = strlen(cred->password);

        /* id (4 bytes, LE) */
        write_u32_le(buf + offset, cred->id);
        offset += 4;

        /* url_len (2 bytes, LE) + url data */
        write_u16_le(buf + offset, (uint16_t)url_len);
        offset += 2;
        if (url_len > 0) {
            memcpy(buf + offset, cred->url, url_len);
            offset += url_len;
        }

        /* user_len (2 bytes, LE) + username data */
        write_u16_le(buf + offset, (uint16_t)user_len);
        offset += 2;
        if (user_len > 0) {
            memcpy(buf + offset, cred->username, user_len);
            offset += user_len;
        }

        /* pass_len (2 bytes, LE) + password data */
        write_u16_le(buf + offset, (uint16_t)pass_len);
        offset += 2;
        if (pass_len > 0) {
            memcpy(buf + offset, cred->password, pass_len);
            offset += pass_len;
        }

        /* created_at (8 bytes, LE) */
        write_u64_le(buf + offset, cred->created_at);
        offset += 8;

        /* modified_at (8 bytes, LE) */
        write_u64_le(buf + offset, cred->modified_at);
        offset += 8;

        /* deleted (1 byte) */
        buf[offset] = cred->deleted ? 1 : 0;
        offset += 1;
    }

    *out_buf = buf;
    *out_len = total_size;
    return STORE_OK;
}

/**
 * Deserialize credentials from a plaintext buffer into the vault.
 * Allocates vault->entries. Caller must free when done.
 * Returns STORE_OK on success, STORE_ERR_CORRUPT on malformed data.
 */
static StoreResult deserialize_credentials(const uint8_t *buf, size_t buf_len,
                                           uint32_t count, Vault *vault)
{
    size_t offset = 0;
    Credential *entries;

    /* Handle empty vault */
    if (count == 0) {
        vault->entries = NULL;
        vault->count = 0;
        vault->capacity = 0;
        vault->is_dirty = false;
        return STORE_OK;
    }

    /* Allocate entries array */
    entries = (Credential *)calloc(count, sizeof(Credential));
    if (entries == NULL) {
        return STORE_ERR_WRITE_FAILED;
    }

    for (uint32_t i = 0; i < count; i++) {
        Credential *cred = &entries[i];
        uint16_t url_len, user_len, pass_len;

        /* id (4 bytes) */
        if (offset + 4 > buf_len) goto corrupt;
        cred->id = read_u32_le(buf + offset);
        offset += 4;

        /* url_len (2 bytes) + url data */
        if (offset + 2 > buf_len) goto corrupt;
        url_len = read_u16_le(buf + offset);
        offset += 2;
        if (url_len > MAX_URL_LEN) goto corrupt;
        if (offset + url_len > buf_len) goto corrupt;
        if (url_len > 0) {
            memcpy(cred->url, buf + offset, url_len);
            offset += url_len;
        }
        cred->url[url_len] = '\0';

        /* user_len (2 bytes) + username data */
        if (offset + 2 > buf_len) goto corrupt;
        user_len = read_u16_le(buf + offset);
        offset += 2;
        if (user_len > MAX_USERNAME_LEN) goto corrupt;
        if (offset + user_len > buf_len) goto corrupt;
        if (user_len > 0) {
            memcpy(cred->username, buf + offset, user_len);
            offset += user_len;
        }
        cred->username[user_len] = '\0';

        /* pass_len (2 bytes) + password data */
        if (offset + 2 > buf_len) goto corrupt;
        pass_len = read_u16_le(buf + offset);
        offset += 2;
        if (pass_len > MAX_PASSWORD_LEN) goto corrupt;
        if (offset + pass_len > buf_len) goto corrupt;
        if (pass_len > 0) {
            memcpy(cred->password, buf + offset, pass_len);
            offset += pass_len;
        }
        cred->password[pass_len] = '\0';

        /* created_at (8 bytes) */
        if (offset + 8 > buf_len) goto corrupt;
        cred->created_at = read_u64_le(buf + offset);
        offset += 8;

        /* modified_at (8 bytes) */
        if (offset + 8 > buf_len) goto corrupt;
        cred->modified_at = read_u64_le(buf + offset);
        offset += 8;

        /* deleted (1 byte) */
        if (offset + 1 > buf_len) goto corrupt;
        cred->deleted = (buf[offset] != 0);
        offset += 1;
    }

    vault->entries = entries;
    vault->count = count;
    vault->capacity = count;
    vault->is_dirty = false;
    return STORE_OK;

corrupt:
    free(entries);
    return STORE_ERR_CORRUPT;
}

/* ─── Vault Serialization / Deserialization ───────────────────────────────── */

StoreResult vault_serialize(const Vault *vault, const DerivedKey *key,
                            uint8_t **out_data, size_t *out_len)
{
    uint8_t *plaintext = NULL;
    size_t pt_len = 0;
    uint8_t *ciphertext = NULL;
    size_t ct_len = 0;
    uint8_t nonce[ENC_NONCE_SIZE];
    uint8_t tag[ENC_TAG_SIZE];
    uint8_t *result_buf = NULL;
    size_t result_len;
    StoreResult res;
    EncResult enc_res;

    if (vault == NULL || key == NULL || out_data == NULL || out_len == NULL) {
        return STORE_ERR_WRITE_FAILED;
    }

    *out_data = NULL;
    *out_len = 0;

    /* Step 1: Serialize credentials to plaintext buffer */
    res = serialize_credentials(vault, &plaintext, &pt_len);
    if (res != STORE_OK) {
        return res;
    }

    /* Step 2: Encrypt the plaintext buffer */
    /* Allocate ciphertext buffer (same size as plaintext for GCM) */
    /* For empty vaults (pt_len == 0), we still need a valid buffer pointer
       for enc_encrypt since it validates ciphertext != NULL */
    {
        uint8_t empty_ct_buf[1]; /* Stack buffer for empty plaintext case */
        uint8_t *ct_ptr;

        if (pt_len > 0) {
            ciphertext = (uint8_t *)malloc(pt_len);
            if (ciphertext == NULL) {
                free(plaintext);
                return STORE_ERR_WRITE_FAILED;
            }
            ct_ptr = ciphertext;
        } else {
            ct_ptr = empty_ct_buf;
        }

        enc_res = enc_encrypt(key, plaintext, pt_len,
                              ct_ptr, &ct_len, nonce, tag);
    }

    /* Clear and free plaintext immediately after encryption */
    if (plaintext != NULL) {
        enc_secure_zero(plaintext, pt_len);
        free(plaintext);
        plaintext = NULL;
    }

    if (enc_res != ENC_OK) {
        free(ciphertext);
        return STORE_ERR_WRITE_FAILED;
    }

    /* Step 3: Build the complete vault file buffer */
    /* Total size = header (64) + ciphertext + GCM tag (16) */
    result_len = VAULT_HEADER_SIZE + ct_len + ENC_TAG_SIZE;
    result_buf = (uint8_t *)malloc(result_len);
    if (result_buf == NULL) {
        free(ciphertext);
        return STORE_ERR_WRITE_FAILED;
    }

    /* Zero the header area first (ensures reserved bytes are zero) */
    memset(result_buf, 0, VAULT_HEADER_SIZE);

    /* Write header fields */
    /* Bytes 0-3: Magic bytes */
    result_buf[0] = VAULT_MAGIC_0;
    result_buf[1] = VAULT_MAGIC_1;
    result_buf[2] = VAULT_MAGIC_2;
    result_buf[3] = VAULT_MAGIC_3;

    /* Bytes 4-5: Format version (uint16 LE) */
    write_u16_le(result_buf + 4, VAULT_FORMAT_VERSION);

    /* Byte 6: Algorithm ID */
    result_buf[6] = VAULT_ALGO_AES256GCM;

    /* Bytes 7-10: Argon2 iterations (uint32 LE) */
    write_u32_le(result_buf + 7, key->iterations);

    /* Bytes 11-14: Argon2 memory cost KB (uint32 LE) */
    write_u32_le(result_buf + 11, key->memory_kb);

    /* Byte 15: Argon2 parallelism */
    result_buf[15] = key->parallelism;

    /* Bytes 16-31: Salt (16 bytes) */
    memcpy(result_buf + 16, key->salt, ENC_SALT_SIZE);

    /* Bytes 32-43: Nonce (12 bytes) */
    memcpy(result_buf + 32, nonce, ENC_NONCE_SIZE);

    /* Bytes 44-47: Credential count (uint32 LE) */
    write_u32_le(result_buf + 44, vault->count);

    /* Bytes 48-63: Reserved (already zeroed by memset) */

    /* Copy ciphertext after header */
    if (ct_len > 0 && ciphertext != NULL) {
        memcpy(result_buf + VAULT_HEADER_SIZE, ciphertext, ct_len);
    }

    /* Append GCM tag at the end */
    memcpy(result_buf + VAULT_HEADER_SIZE + ct_len, tag, ENC_TAG_SIZE);

    /* Clean up */
    free(ciphertext);

    *out_data = result_buf;
    *out_len = result_len;
    return STORE_OK;
}

StoreResult vault_deserialize(const uint8_t *data, size_t len,
                              const DerivedKey *key, Vault *vault)
{
    uint8_t nonce[ENC_NONCE_SIZE];
    uint8_t tag[ENC_TAG_SIZE];
    uint32_t cred_count;
    size_t ct_len;
    uint8_t *plaintext = NULL;
    size_t pt_len = 0;
    EncResult enc_res;
    StoreResult res;

    if (data == NULL || key == NULL || vault == NULL) {
        return STORE_ERR_CORRUPT;
    }

    /* Validate minimum size: header (64) + GCM tag (16) */
    if (len < VAULT_HEADER_SIZE + ENC_TAG_SIZE) {
        return STORE_ERR_CORRUPT;
    }

    /* Validate magic bytes */
    if (data[0] != VAULT_MAGIC_0 ||
        data[1] != VAULT_MAGIC_1 ||
        data[2] != VAULT_MAGIC_2 ||
        data[3] != VAULT_MAGIC_3) {
        return STORE_ERR_CORRUPT;
    }

    /* Extract nonce from header (bytes 32-43) */
    memcpy(nonce, data + 32, ENC_NONCE_SIZE);

    /* Extract credential count from header (bytes 44-47) */
    cred_count = read_u32_le(data + 44);

    /* Calculate ciphertext length: total - header - tag */
    ct_len = len - VAULT_HEADER_SIZE - ENC_TAG_SIZE;

    /* Extract GCM tag from the end of the file */
    memcpy(tag, data + len - ENC_TAG_SIZE, ENC_TAG_SIZE);

    /* Decrypt the body */
    if (ct_len > 0) {
        plaintext = (uint8_t *)malloc(ct_len);
        if (plaintext == NULL) {
            return STORE_ERR_WRITE_FAILED;
        }

        enc_res = enc_decrypt(key,
                              data + VAULT_HEADER_SIZE, ct_len,
                              nonce, tag,
                              plaintext, &pt_len);

        if (enc_res == ENC_ERR_INTEGRITY_FAILED) {
            free(plaintext);
            return STORE_ERR_CORRUPT;
        }
        if (enc_res != ENC_OK) {
            free(plaintext);
            return STORE_ERR_CORRUPT;
        }
    } else {
        /* Empty body (no credentials) */
        pt_len = 0;
    }

    /* Deserialize credentials from plaintext */
    res = deserialize_credentials(plaintext, pt_len, cred_count, vault);

    /* Clear and free plaintext */
    if (plaintext != NULL) {
        enc_secure_zero(plaintext, pt_len);
        free(plaintext);
    }

    return res;
}