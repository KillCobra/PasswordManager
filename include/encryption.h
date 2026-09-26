/**
 * encryption.h - Encryption Engine
 *
 * Provides key derivation (Argon2id), authenticated encryption (AES-256-GCM),
 * and secure memory clearing for the password manager vault.
 */

#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Constants ───────────────────────────────────────────────────────────── */

#define ENC_KEY_SIZE        32   /* 256-bit derived key */
#define ENC_SALT_SIZE       16   /* 128-bit random salt */
#define ENC_NONCE_SIZE      12   /* 96-bit GCM nonce */
#define ENC_TAG_SIZE        16   /* 128-bit GCM authentication tag */

#define ENC_MIN_ITERATIONS  3
#define ENC_MIN_MEMORY_KB   65536   /* 64 MB */
#define ENC_PARALLELISM     1

/* ─── Types ───────────────────────────────────────────────────────────────── */

/**
 * Holds the derived encryption key along with the KDF parameters
 * used to produce it.
 */
typedef struct {
    uint8_t key[ENC_KEY_SIZE];      /* 256-bit derived key */
    uint8_t salt[ENC_SALT_SIZE];    /* 128-bit random salt */
    uint32_t iterations;            /* Argon2id time cost (min 3) */
    uint32_t memory_kb;             /* Argon2id memory cost (min 65536 = 64MB) */
    uint8_t parallelism;            /* Argon2id parallelism (1) */
} DerivedKey;

/**
 * Result codes for encryption operations.
 */
typedef enum {
    ENC_OK = 0,
    ENC_ERR_INVALID_PASSWORD,
    ENC_ERR_INTEGRITY_FAILED,
    ENC_ERR_MEMORY,
    ENC_ERR_IO
} EncResult;

/* ─── Functions ───────────────────────────────────────────────────────────── */

/**
 * Derive a 256-bit encryption key from a master password using Argon2id.
 *
 * Uses configurable iterations (min 3), memory (min 64MB), parallelism (1),
 * and the provided 128-bit salt.
 *
 * @param password  Master password bytes
 * @param pw_len    Length of password in bytes
 * @param salt      128-bit (16-byte) salt
 * @param out       Output DerivedKey structure (key + params)
 * @return ENC_OK on success, ENC_ERR_INVALID_PASSWORD if password is NULL/empty,
 *         ENC_ERR_MEMORY on allocation failure
 */
EncResult enc_derive_key(const char *password, size_t pw_len,
                         const uint8_t salt[ENC_SALT_SIZE], DerivedKey *out);

/**
 * Derive a 256-bit key using explicit Argon2id parameters.
 *
 * Like enc_derive_key(), but uses the provided iterations / memory / parallelism
 * instead of the compile-time minimums. Each parameter is clamped UP to the
 * corresponding ENC_MIN_* floor (and parallelism to at least 1) so a vault can
 * never be opened with weaker-than-minimum settings. This lets the vault header
 * describe (and later increase) the KDF cost while staying backward compatible:
 * existing vaults already store the minimums, so they derive identically.
 *
 * @param password     Master password bytes
 * @param pw_len       Length of password in bytes
 * @param salt         128-bit (16-byte) salt
 * @param iterations   Argon2id time cost (clamped up to ENC_MIN_ITERATIONS)
 * @param memory_kb    Argon2id memory cost KB (clamped up to ENC_MIN_MEMORY_KB)
 * @param parallelism  Argon2id parallelism (clamped up to 1)
 * @param out          Output DerivedKey (key + the params actually used)
 * @return ENC_OK on success, ENC_ERR_INVALID_PASSWORD if inputs invalid,
 *         ENC_ERR_MEMORY on allocation failure
 */
EncResult enc_derive_key_params(const char *password, size_t pw_len,
                                const uint8_t salt[ENC_SALT_SIZE],
                                uint32_t iterations, uint32_t memory_kb,
                                uint8_t parallelism, DerivedKey *out);

/**
 * Encrypt plaintext using AES-256-GCM.
 *
 * Generates a random 12-byte nonce via platform_random_bytes() and produces
 * ciphertext of the same length as plaintext, plus a 16-byte authentication tag.
 *
 * @param key        Derived key to use for encryption
 * @param plaintext  Input data to encrypt
 * @param pt_len     Length of plaintext in bytes
 * @param ciphertext Output buffer (must be at least pt_len bytes)
 * @param ct_len     On output, set to the ciphertext length (== pt_len)
 * @param nonce      Output 12-byte nonce (randomly generated)
 * @param tag        Output 16-byte GCM authentication tag
 * @return ENC_OK on success, ENC_ERR_IO on encryption failure
 */
EncResult enc_encrypt(const DerivedKey *key,
                      const uint8_t *plaintext, size_t pt_len,
                      uint8_t *ciphertext, size_t *ct_len,
                      uint8_t nonce[ENC_NONCE_SIZE], uint8_t tag[ENC_TAG_SIZE]);

/**
 * Decrypt ciphertext using AES-256-GCM with tag verification.
 *
 * Verifies the GCM authentication tag before returning plaintext.
 * Returns ENC_ERR_INTEGRITY_FAILED on tag mismatch.
 *
 * @param key        Derived key to use for decryption
 * @param ciphertext Input encrypted data
 * @param ct_len     Length of ciphertext in bytes
 * @param nonce      12-byte nonce used during encryption
 * @param tag        16-byte GCM authentication tag to verify
 * @param plaintext  Output buffer (must be at least ct_len bytes)
 * @param pt_len     On output, set to the plaintext length (== ct_len)
 * @return ENC_OK on success, ENC_ERR_INTEGRITY_FAILED on tag mismatch,
 *         ENC_ERR_IO on decryption failure
 */
EncResult enc_decrypt(const DerivedKey *key,
                      const uint8_t *ciphertext, size_t ct_len,
                      const uint8_t nonce[ENC_NONCE_SIZE],
                      const uint8_t tag[ENC_TAG_SIZE],
                      uint8_t *plaintext, size_t *pt_len);

/**
 * Securely zero memory, preventing compiler optimizations from
 * removing the operation. Delegates to platform_secure_zero().
 *
 * @param ptr  Pointer to memory to zero
 * @param len  Number of bytes to zero
 */
void enc_secure_zero(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ENCRYPTION_H */
