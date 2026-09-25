/*
 * AES-256 implementation header
 * Lightweight AES implementation for embedded/portable use.
 * Supports AES-256 encryption and decryption (single block).
 */

#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

/* AES-256 key size in bytes */
#define AES256_KEY_SIZE 32

/* AES block size in bytes */
#define AES_BLOCK_SIZE 16

/* Number of rounds for AES-256 */
#define AES256_ROUNDS 14

/* AES context structure */
typedef struct {
    uint32_t rk[60];       /* Round keys (max for AES-256: 4*(14+1) = 60) */
    uint32_t nr;           /* Number of rounds */
} aes_context;

/**
 * Initialize AES-256 context with encryption key.
 * @param ctx    AES context to initialize
 * @param key    256-bit (32-byte) encryption key
 * @return 0 on success, -1 on error
 */
int aes_init(aes_context *ctx, const uint8_t key[AES256_KEY_SIZE]);

/**
 * Encrypt a single 16-byte block.
 * @param ctx    Initialized AES context
 * @param input  16-byte plaintext block
 * @param output 16-byte ciphertext block
 */
void aes_encrypt_block(const aes_context *ctx,
                       const uint8_t input[AES_BLOCK_SIZE],
                       uint8_t output[AES_BLOCK_SIZE]);

/**
 * Decrypt a single 16-byte block.
 * @param ctx    Initialized AES context
 * @param input  16-byte ciphertext block
 * @param output 16-byte plaintext block
 */
void aes_decrypt_block(const aes_context *ctx,
                       const uint8_t input[AES_BLOCK_SIZE],
                       uint8_t output[AES_BLOCK_SIZE]);

/**
 * Clear AES context (zero sensitive key material).
 * @param ctx    AES context to clear
 */
void aes_free(aes_context *ctx);

#endif /* AES_H */
