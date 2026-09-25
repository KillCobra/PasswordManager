/*
 * AES-GCM (Galois/Counter Mode) implementation
 * Lightweight GCM implementation for embedded/portable use.
 * Based on NIST SP 800-38D specification.
 */

#include <string.h>
#include "gcm.h"

/* GF(2^128) multiplication (bit-by-bit, reference implementation) */
static void ghash_mult(const uint8_t X[16], const uint8_t Y[16], uint8_t result[16]) {
    uint8_t V[16];
    uint8_t Z[16] = {0};
    int i, j;

    memcpy(V, Y, 16);

    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            if ((X[i] >> j) & 1) {
                /* Z = Z XOR V */
                for (int k = 0; k < 16; k++) {
                    Z[k] ^= V[k];
                }
            }

            /* V = V * x (multiply by x in GF(2^128)) */
            uint8_t carry = V[15] & 1;
            for (int k = 15; k > 0; k--) {
                V[k] = (V[k] >> 1) | (V[k-1] << 7);
            }
            V[0] >>= 1;

            if (carry) {
                V[0] ^= 0xE1; /* Reduction polynomial: x^128 + x^7 + x^2 + x + 1 */
            }
        }
    }

    memcpy(result, Z, 16);
}

/* GHASH function: hash AAD and ciphertext */
static void ghash(const uint8_t H[16],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *ciphertext, size_t ct_len,
                  uint8_t output[16]) {
    uint8_t tmp[16] = {0};
    uint8_t block[16];
    size_t i, remaining;

    /* Process AAD */
    for (i = 0; i + 16 <= aad_len; i += 16) {
        for (int k = 0; k < 16; k++) {
            tmp[k] ^= aad[i + k];
        }
        ghash_mult(tmp, H, tmp);
    }
    /* Handle partial AAD block */
    remaining = aad_len - i;
    if (remaining > 0) {
        memset(block, 0, 16);
        memcpy(block, aad + i, remaining);
        for (int k = 0; k < 16; k++) {
            tmp[k] ^= block[k];
        }
        ghash_mult(tmp, H, tmp);
    }

    /* Process ciphertext */
    for (i = 0; i + 16 <= ct_len; i += 16) {
        for (int k = 0; k < 16; k++) {
            tmp[k] ^= ciphertext[i + k];
        }
        ghash_mult(tmp, H, tmp);
    }
    /* Handle partial ciphertext block */
    remaining = ct_len - i;
    if (remaining > 0) {
        memset(block, 0, 16);
        memcpy(block, ciphertext + i, remaining);
        for (int k = 0; k < 16; k++) {
            tmp[k] ^= block[k];
        }
        ghash_mult(tmp, H, tmp);
    }

    /* Final block: lengths of AAD and ciphertext in bits (big-endian 64-bit) */
    memset(block, 0, 16);
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)ct_len * 8;
    block[0] = (uint8_t)(aad_bits >> 56);
    block[1] = (uint8_t)(aad_bits >> 48);
    block[2] = (uint8_t)(aad_bits >> 40);
    block[3] = (uint8_t)(aad_bits >> 32);
    block[4] = (uint8_t)(aad_bits >> 24);
    block[5] = (uint8_t)(aad_bits >> 16);
    block[6] = (uint8_t)(aad_bits >> 8);
    block[7] = (uint8_t)(aad_bits);
    block[8] = (uint8_t)(ct_bits >> 56);
    block[9] = (uint8_t)(ct_bits >> 48);
    block[10] = (uint8_t)(ct_bits >> 40);
    block[11] = (uint8_t)(ct_bits >> 32);
    block[12] = (uint8_t)(ct_bits >> 24);
    block[13] = (uint8_t)(ct_bits >> 16);
    block[14] = (uint8_t)(ct_bits >> 8);
    block[15] = (uint8_t)(ct_bits);

    for (int k = 0; k < 16; k++) {
        tmp[k] ^= block[k];
    }
    ghash_mult(tmp, H, tmp);

    memcpy(output, tmp, 16);
}

/* Increment counter (last 32 bits, big-endian) */
static void inc32(uint8_t counter[16]) {
    uint32_t c = ((uint32_t)counter[12] << 24) |
                 ((uint32_t)counter[13] << 16) |
                 ((uint32_t)counter[14] << 8) |
                 ((uint32_t)counter[15]);
    c++;
    counter[12] = (uint8_t)(c >> 24);
    counter[13] = (uint8_t)(c >> 16);
    counter[14] = (uint8_t)(c >> 8);
    counter[15] = (uint8_t)(c);
}

int gcm_init(gcm_context *ctx, const uint8_t key[AES256_KEY_SIZE]) {
    uint8_t zero_block[16] = {0};

    if (ctx == NULL || key == NULL) {
        return -1;
    }

    /* Initialize AES context */
    if (aes_init(&ctx->aes_ctx, key) != 0) {
        return -1;
    }

    /* Compute hash subkey H = AES_K(0^128) */
    aes_encrypt_block(&ctx->aes_ctx, zero_block, ctx->H);

    return 0;
}

int gcm_encrypt(const gcm_context *ctx,
                const uint8_t nonce[GCM_NONCE_SIZE],
                const uint8_t *plaintext, size_t pt_len,
                const uint8_t *aad, size_t aad_len,
                uint8_t *ciphertext,
                uint8_t tag[GCM_TAG_SIZE]) {
    uint8_t counter[16] = {0};
    uint8_t J0[16] = {0};
    uint8_t S[16];
    uint8_t keystream[16];
    size_t i;

    if (ctx == NULL || nonce == NULL || tag == NULL) {
        return -1;
    }
    if (pt_len > 0 && (plaintext == NULL || ciphertext == NULL)) {
        return -1;
    }

    /* J0 = nonce || 0^31 || 1 (for 96-bit nonce) */
    memcpy(J0, nonce, GCM_NONCE_SIZE);
    J0[15] = 1;

    /* Initialize counter = J0 + 1 */
    memcpy(counter, J0, 16);
    inc32(counter);

    /* Encrypt plaintext using CTR mode */
    for (i = 0; i < pt_len; i += 16) {
        size_t block_len = (pt_len - i < 16) ? (pt_len - i) : 16;

        aes_encrypt_block(&ctx->aes_ctx, counter, keystream);

        for (size_t j = 0; j < block_len; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        }

        inc32(counter);
    }

    /* Compute GHASH over AAD and ciphertext */
    ghash(ctx->H, aad, aad_len, ciphertext, pt_len, S);

    /* Compute tag = GHASH XOR E_K(J0) */
    aes_encrypt_block(&ctx->aes_ctx, J0, keystream);
    for (i = 0; i < 16; i++) {
        tag[i] = S[i] ^ keystream[i];
    }

    return 0;
}

int gcm_decrypt(const gcm_context *ctx,
                const uint8_t nonce[GCM_NONCE_SIZE],
                const uint8_t *ciphertext, size_t ct_len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t tag[GCM_TAG_SIZE],
                uint8_t *plaintext) {
    uint8_t counter[16] = {0};
    uint8_t J0[16] = {0};
    uint8_t S[16];
    uint8_t computed_tag[16];
    uint8_t keystream[16];
    size_t i;
    int diff;

    if (ctx == NULL || nonce == NULL || tag == NULL) {
        return -1;
    }
    if (ct_len > 0 && (ciphertext == NULL || plaintext == NULL)) {
        return -1;
    }

    /* J0 = nonce || 0^31 || 1 (for 96-bit nonce) */
    memcpy(J0, nonce, GCM_NONCE_SIZE);
    J0[15] = 1;

    /* Compute GHASH over AAD and ciphertext first (before decryption) */
    ghash(ctx->H, aad, aad_len, ciphertext, ct_len, S);

    /* Compute expected tag = GHASH XOR E_K(J0) */
    aes_encrypt_block(&ctx->aes_ctx, J0, keystream);
    for (i = 0; i < 16; i++) {
        computed_tag[i] = S[i] ^ keystream[i];
    }

    /* Constant-time tag comparison */
    diff = 0;
    for (i = 0; i < 16; i++) {
        diff |= computed_tag[i] ^ tag[i];
    }

    if (diff != 0) {
        /* Authentication failed - do not produce plaintext */
        memset(plaintext, 0, ct_len);
        return -1;
    }

    /* Tag verified - decrypt ciphertext using CTR mode */
    memcpy(counter, J0, 16);
    inc32(counter);

    for (i = 0; i < ct_len; i += 16) {
        size_t block_len = (ct_len - i < 16) ? (ct_len - i) : 16;

        aes_encrypt_block(&ctx->aes_ctx, counter, keystream);

        for (size_t j = 0; j < block_len; j++) {
            plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
        }

        inc32(counter);
    }

    return 0;
}

void gcm_free(gcm_context *ctx) {
    if (ctx != NULL) {
        aes_free(&ctx->aes_ctx);
        /* Zero the hash subkey */
        volatile uint8_t *p = (volatile uint8_t *)ctx->H;
        for (size_t i = 0; i < 16; i++) {
            p[i] = 0;
        }
    }
}
