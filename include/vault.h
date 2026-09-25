/**
 * vault.h - Vault Manager
 *
 * Provides vault file I/O (atomic write), binary format serialization/
 * deserialization, and the full save/load pipeline integrating encryption.
 *
 * Vault File Format (64-byte header + encrypted body + 16-byte GCM tag):
 *   Header: magic "VLT1", version, algorithm ID, Argon2 params, salt, nonce, count, reserved
 *   Body:   AES-256-GCM encrypted credential data
 *   Footer: 16-byte GCM authentication tag
 */

#ifndef VAULT_H
#define VAULT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "credential.h"
#include "encryption.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Constants ───────────────────────────────────────────────────────────── */

#define VAULT_MAGIC_0       0x56  /* 'V' */
#define VAULT_MAGIC_1       0x4C  /* 'L' */
#define VAULT_MAGIC_2       0x54  /* 'T' */
#define VAULT_MAGIC_3       0x31  /* '1' */

#define VAULT_HEADER_SIZE   64
#define VAULT_FORMAT_VERSION 1
#define VAULT_ALGO_AES256GCM 0x01

/* ─── Result Codes ────────────────────────────────────────────────────────── */

typedef enum {
    STORE_OK = 0,
    STORE_ERR_FILE_NOT_FOUND,
    STORE_ERR_CORRUPT,
    STORE_ERR_WRITE_FAILED,
    STORE_ERR_DISK_FULL,
    STORE_ERR_PERMISSION
} StoreResult;

/* ─── File I/O Functions ──────────────────────────────────────────────────── */

/**
 * Load a vault file into a memory buffer.
 * Validates magic bytes and minimum header size (64 bytes).
 * Caller must free *data when done.
 *
 * @param path  Path to the vault file
 * @param data  Output pointer to allocated buffer
 * @param len   Output length of the buffer
 * @return STORE_OK on success, appropriate error code on failure
 */
StoreResult store_load(const char *path, uint8_t **data, size_t *len);

/**
 * Save data to a vault file using atomic write (temp + fsync + rename).
 *
 * @param path  Path to the vault file
 * @param data  Data buffer to write
 * @param len   Length of data buffer
 * @return STORE_OK on success, appropriate error code on failure
 */
StoreResult store_save(const char *path, const uint8_t *data, size_t len);

/**
 * Check if a vault file exists at the given path.
 *
 * @param path  Path to check
 * @return true if file exists, false otherwise
 */
bool store_exists(const char *path);

/* ─── Vault Serialization / Deserialization ───────────────────────────────── */

/**
 * Serialize a vault to the binary file format.
 * Pipeline: serialize credentials → encrypt → prepend header → append GCM tag.
 * Caller must free *out_data when done.
 *
 * @param vault     The vault containing credentials to serialize
 * @param key       The derived encryption key (includes salt, params)
 * @param out_data  Output pointer to the complete vault file data
 * @param out_len   Output length of the vault file data
 * @return STORE_OK on success, appropriate error code on failure
 */
StoreResult vault_serialize(const Vault *vault, const DerivedKey *key,
                            uint8_t **out_data, size_t *out_len);

/**
 * Deserialize a vault from the binary file format.
 * Pipeline: validate header → extract params → decrypt body → deserialize credentials.
 * The vault's entries array is allocated and must be freed by the caller.
 *
 * @param data   Raw vault file data
 * @param len    Length of the raw data
 * @param key    The derived encryption key
 * @param vault  Output vault structure (entries will be allocated)
 * @return STORE_OK on success, appropriate error code on failure
 */
StoreResult vault_deserialize(const uint8_t *data, size_t len,
                              const DerivedKey *key, Vault *vault);

#ifdef __cplusplus
}
#endif

#endif /* VAULT_H */
