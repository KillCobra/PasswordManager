/*
 * AES-GCM (Galois/Counter Mode) implementation header
 * Lightweight GCM implementation for embedded/portable use.
 * Supports AES-256-GCM authenticated encryption.
 */

#ifndef GCM_H
#define GCM_H

#include <stdint.h>
#include <stddef.h>
#include "aes.h"

/* GCM nonce size (96 bits recommended by NIST) */
#define GCM_NONCE_SIZE 12

/* GCM tag size (128 bits) */
#define GCM_TAG_SIZE 16

/* GCM context structure */
typedef struct {
    aes_context aes_ctx;    /* Underlying AES context */
    uint8_t H[16];          /* Hash subkey H = AES_K(0^128) */
} gcm_context;

/**
 * Initialize GCM context with a 256-bit key.
 * @param ctx    GCM context to initialize
 * @param key    256-bit (32-byte) encryption key
 * @return 0 on success, -1 on error
 */
int gcm_init(gcm_context *ctx, const uint8_t key[AES256_KEY_SIZE]);

/**
 * Encrypt and authenticate data using AES-256-GCM.
 * @param ctx        Initialized GCM context
 * @param nonce      96-bit (12-byte) nonce (must be unique per encryption)
 * @param plaintext  Input plaintext data
 * @param pt_len     Length of plaintext in bytes
 * @param aad        Additional authenticated data (can be NULL)
 * @param aad_len    Length of AAD in bytes
 * @param ciphertext Output ciphertext buffer (same size as plaintext)
 * @param tag        Output 128-bit (16-byte) authentication tag
 * @return 0 on success, -1 on error
 */
int gcm_encrypt(const gcm_context *ctx,
                const uint8_t nonce[GCM_NONCE_SIZE],
                const uint8_t *plaintext, size_t pt_len,
                const uint8_t *aad, size_t aad_len,
                uint8_t *ciphertext,
                uint8_t tag[GCM_TAG_SIZE]);

/**
 * Decrypt and verify data using AES-256-GCM.
 * @param ctx        Initialized GCM context
 * @param nonce      96-bit (12-byte) nonce used during encryption
 * @param ciphertext Input ciphertext data
 * @param ct_len     Length of ciphertext in bytes
 * @param aad        Additional authenticated data (can be NULL)
 * @param aad_len    Length of AAD in bytes
 * @param tag        Expected 128-bit (16-byte) authentication tag
 * @param plaintext  Output plaintext buffer (same size as ciphertext)
 * @return 0 on success (tag verified), -1 on authentication failure
 */
int gcm_decrypt(const gcm_context *ctx,
                const uint8_t nonce[GCM_NONCE_SIZE],
                const uint8_t *ciphertext, size_t ct_len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t tag[GCM_TAG_SIZE],
                uint8_t *plaintext);

/**
 * Clear GCM context (zero sensitive key material).
 * @param ctx    GCM context to clear
 */
void gcm_free(gcm_context *ctx);

#endif /* GCM_H */
