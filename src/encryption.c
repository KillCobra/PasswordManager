/**
 * encryption.c - Encryption Engine Implementation
 *
 * Implements key derivation (Argon2id), authenticated encryption (AES-256-GCM),
 * and secure memory clearing for the password manager vault.
 */

#include "encryption.h"
#include "platform.h"
#include "argon2.h"
#include "gcm.h"

#include <string.h>

/* ─── Key Derivation ──────────────────────────────────────────────────────── */

EncResult enc_derive_key_params(const char *password, size_t pw_len,
                                const uint8_t salt[ENC_SALT_SIZE],
                                uint32_t iterations, uint32_t memory_kb,
                                uint8_t parallelism, DerivedKey *out)
{
    int result;

    /* Validate inputs */
    if (password == NULL || pw_len == 0) {
        return ENC_ERR_INVALID_PASSWORD;
    }
    if (salt == NULL || out == NULL) {
        return ENC_ERR_INVALID_PASSWORD;
    }

    /* Clamp each parameter UP to its minimum floor so a vault can never be
     * opened with weaker-than-minimum KDF settings. */
    if (iterations < ENC_MIN_ITERATIONS) iterations = ENC_MIN_ITERATIONS;
    if (memory_kb  < ENC_MIN_MEMORY_KB)  memory_kb  = ENC_MIN_MEMORY_KB;
    if (parallelism < ENC_PARALLELISM)   parallelism = ENC_PARALLELISM;

    out->iterations  = iterations;
    out->memory_kb   = memory_kb;
    out->parallelism = parallelism;

    /* Copy salt into output structure */
    memcpy(out->salt, salt, ENC_SALT_SIZE);

    /* Derive key using Argon2id */
    result = argon2id_hash_raw(
        out->iterations,
        out->memory_kb,
        (uint32_t)out->parallelism,
        password,
        pw_len,
        salt,
        ENC_SALT_SIZE,
        out->key,
        ENC_KEY_SIZE
    );

    if (result != ARGON2_OK) {
        /* Clear any partial key material */
        enc_secure_zero(out->key, ENC_KEY_SIZE);
        if (result == ARGON2_MEMORY_ALLOCATION_ERROR) {
            return ENC_ERR_MEMORY;
        }
        return ENC_ERR_IO;
    }

    return ENC_OK;
}

EncResult enc_derive_key(const char *password, size_t pw_len,
                         const uint8_t salt[ENC_SALT_SIZE], DerivedKey *out)
{
    /* Convenience wrapper: derive using the enforced minimum parameters.
     * Existing callers (new-vault creation) keep the same behavior. */
    return enc_derive_key_params(password, pw_len, salt,
                                 ENC_MIN_ITERATIONS, ENC_MIN_MEMORY_KB,
                                 ENC_PARALLELISM, out);
}

/* ─── Encryption ──────────────────────────────────────────────────────────── */

EncResult enc_encrypt(const DerivedKey *key,
                      const uint8_t *plaintext, size_t pt_len,
                      uint8_t *ciphertext, size_t *ct_len,
                      uint8_t nonce[ENC_NONCE_SIZE], uint8_t tag[ENC_TAG_SIZE])
{
    gcm_context ctx;
    int result;

    /* Validate inputs */
    if (key == NULL || ciphertext == NULL || ct_len == NULL ||
        nonce == NULL || tag == NULL) {
        return ENC_ERR_IO;
    }

    /* Allow empty plaintext (pt_len == 0) but plaintext pointer must be valid
       if pt_len > 0 */
    if (pt_len > 0 && plaintext == NULL) {
        return ENC_ERR_IO;
    }

    /* Generate random nonce using platform CSPRNG */
    if (!platform_random_bytes(nonce, ENC_NONCE_SIZE)) {
        return ENC_ERR_IO;
    }

    /* Initialize GCM context with the derived key */
    result = gcm_init(&ctx, key->key);
    if (result != 0) {
        enc_secure_zero(&ctx, sizeof(ctx));
        return ENC_ERR_IO;
    }

    /* Encrypt with AES-256-GCM (no additional authenticated data) */
    result = gcm_encrypt(&ctx, nonce, plaintext, pt_len,
                         NULL, 0, ciphertext, tag);

    /* Clear GCM context regardless of result */
    gcm_free(&ctx);

    if (result != 0) {
        return ENC_ERR_IO;
    }

    /* Ciphertext length equals plaintext length for GCM */
    *ct_len = pt_len;

    return ENC_OK;
}

/* ─── Decryption ──────────────────────────────────────────────────────────── */

EncResult enc_decrypt(const DerivedKey *key,
                      const uint8_t *ciphertext, size_t ct_len,
                      const uint8_t nonce[ENC_NONCE_SIZE],
                      const uint8_t tag[ENC_TAG_SIZE],
                      uint8_t *plaintext, size_t *pt_len)
{
    gcm_context ctx;
    int result;

    /* Validate inputs */
    if (key == NULL || plaintext == NULL || pt_len == NULL ||
        nonce == NULL || tag == NULL) {
        return ENC_ERR_IO;
    }

    /* Allow empty ciphertext (ct_len == 0) but ciphertext pointer must be valid
       if ct_len > 0 */
    if (ct_len > 0 && ciphertext == NULL) {
        return ENC_ERR_IO;
    }

    /* Initialize GCM context with the derived key */
    result = gcm_init(&ctx, key->key);
    if (result != 0) {
        enc_secure_zero(&ctx, sizeof(ctx));
        return ENC_ERR_IO;
    }

    /* Decrypt and verify GCM tag */
    result = gcm_decrypt(&ctx, nonce, ciphertext, ct_len,
                         NULL, 0, tag, plaintext);

    /* Clear GCM context regardless of result */
    gcm_free(&ctx);

    if (result != 0) {
        /* Tag verification failed - integrity violation */
        enc_secure_zero(plaintext, ct_len);
        return ENC_ERR_INTEGRITY_FAILED;
    }

    /* Plaintext length equals ciphertext length for GCM */
    *pt_len = ct_len;

    return ENC_OK;
}

/* ─── Secure Memory Clearing ──────────────────────────────────────────────── */

void enc_secure_zero(void *ptr, size_t len)
{
    if (ptr != NULL && len > 0) {
        platform_secure_zero(ptr, len);
    }
}
