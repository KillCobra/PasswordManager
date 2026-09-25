
/*
 * AES-256 implementation
 * Lightweight AES implementation for embedded/portable use.
 * Based on FIPS 197 specification.
 */

#include <string.h>
#include "aes.h"

/* AES S-Box */
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Inverse S-Box */
static const uint8_t inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/* Round constants */
static const uint8_t rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static inline uint32_t get_uint32_le(const uint8_t *b) {
    return ((uint32_t)b[0]) | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static inline void put_uint32_le(uint8_t *b, uint32_t val) {
    b[0] = (uint8_t)(val);
    b[1] = (uint8_t)(val >> 8);
    b[2] = (uint8_t)(val >> 16);
    b[3] = (uint8_t)(val >> 24);
}

/* Multiply by 2 in GF(2^8) */
static inline uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

int aes_init(aes_context *ctx, const uint8_t key[AES256_KEY_SIZE]) {
    uint32_t *rk;
    int i;

    if (ctx == NULL || key == NULL) {
        return -1;
    }

    ctx->nr = AES256_ROUNDS;
    rk = ctx->rk;

    /* Copy key into first 8 round key words */
    for (i = 0; i < 8; i++) {
        rk[i] = get_uint32_le(key + 4 * i);
    }

    /* Key expansion for AES-256 */
    for (i = 8; i < 4 * (AES256_ROUNDS + 1); i++) {
        uint32_t temp = rk[i - 1];

        if (i % 8 == 0) {
            /* RotWord + SubWord + Rcon */
            temp = ((uint32_t)sbox[(temp >> 8) & 0xFF]) |
                   ((uint32_t)sbox[(temp >> 16) & 0xFF] << 8) |
                   ((uint32_t)sbox[(temp >> 24) & 0xFF] << 16) |
                   ((uint32_t)sbox[temp & 0xFF] << 24);
            temp ^= (uint32_t)rcon[i / 8 - 1];
        } else if (i % 8 == 4) {
            /* SubWord only */
            temp = ((uint32_t)sbox[temp & 0xFF]) |
                   ((uint32_t)sbox[(temp >> 8) & 0xFF] << 8) |
                   ((uint32_t)sbox[(temp >> 16) & 0xFF] << 16) |
                   ((uint32_t)sbox[(temp >> 24) & 0xFF] << 24);
        }

        rk[i] = rk[i - 8] ^ temp;
    }

    return 0;
}

void aes_encrypt_block(const aes_context *ctx,
                       const uint8_t input[AES_BLOCK_SIZE],
                       uint8_t output[AES_BLOCK_SIZE]) {
    uint8_t state[4][4];
    const uint32_t *rk = ctx->rk;
    int round, i, j;

    /* Copy input to state (column-major) */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[j][i] = input[i * 4 + j];
        }
    }

    /* Initial round key addition */
    for (i = 0; i < 4; i++) {
        uint32_t k = rk[i];
        state[0][i] ^= (uint8_t)(k);
        state[1][i] ^= (uint8_t)(k >> 8);
        state[2][i] ^= (uint8_t)(k >> 16);
        state[3][i] ^= (uint8_t)(k >> 24);
    }

    /* Main rounds */
    for (round = 1; round < (int)ctx->nr; round++) {
        uint8_t tmp[4][4];

        /* SubBytes */
        for (i = 0; i < 4; i++)
            for (j = 0; j < 4; j++)
                state[i][j] = sbox[state[i][j]];

        /* ShiftRows */
        /* Row 0: no shift */
        /* Row 1: shift left 1 */
        uint8_t t = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = t;
        /* Row 2: shift left 2 */
        t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t;
        t = state[2][1]; state[2][1] = state[2][3]; state[2][3] = t;
        /* Row 3: shift left 3 */
        t = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = t;

        /* MixColumns */
        for (i = 0; i < 4; i++) {
            uint8_t a0 = state[0][i], a1 = state[1][i];
            uint8_t a2 = state[2][i], a3 = state[3][i];
            tmp[0][i] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
            tmp[1][i] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
            tmp[2][i] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
            tmp[3][i] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
        }
        memcpy(state, tmp, 16);

        /* AddRoundKey */
        for (i = 0; i < 4; i++) {
            uint32_t k = rk[round * 4 + i];
            state[0][i] ^= (uint8_t)(k);
            state[1][i] ^= (uint8_t)(k >> 8);
            state[2][i] ^= (uint8_t)(k >> 16);
            state[3][i] ^= (uint8_t)(k >> 24);
        }
    }

    /* Final round (no MixColumns) */
    /* SubBytes */
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] = sbox[state[i][j]];

    /* ShiftRows */
    {
        uint8_t t = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = t;

        t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t;
        t = state[2][1]; state[2][1] = state[2][3]; state[2][3] = t;

        t = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = t;
    }

    /* AddRoundKey */
    for (i = 0; i < 4; i++) {
        uint32_t k = rk[ctx->nr * 4 + i];
        state[0][i] ^= (uint8_t)(k);
        state[1][i] ^= (uint8_t)(k >> 8);
        state[2][i] ^= (uint8_t)(k >> 16);
        state[3][i] ^= (uint8_t)(k >> 24);
    }

    /* Copy state to output (column-major) */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            output[i * 4 + j] = state[j][i];
        }
    }
}

void aes_decrypt_block(const aes_context *ctx,
                       const uint8_t input[AES_BLOCK_SIZE],
                       uint8_t output[AES_BLOCK_SIZE]) {
    uint8_t state[4][4];
    const uint32_t *rk = ctx->rk;
    int round, i, j;

    /* Copy input to state (column-major) */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[j][i] = input[i * 4 + j];
        }
    }

    /* Initial round key addition (last round key) */
    for (i = 0; i < 4; i++) {
        uint32_t k = rk[ctx->nr * 4 + i];
        state[0][i] ^= (uint8_t)(k);
        state[1][i] ^= (uint8_t)(k >> 8);
        state[2][i] ^= (uint8_t)(k >> 16);
        state[3][i] ^= (uint8_t)(k >> 24);
    }

    /* Main rounds (reverse) */
    for (round = (int)ctx->nr - 1; round >= 1; round--) {
        uint8_t t;

        /* InvShiftRows */
        t = state[1][3];
        state[1][3] = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = state[1][0];
        state[1][0] = t;

        t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t;
        t = state[2][1]; state[2][1] = state[2][3]; state[2][3] = t;

        t = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = t;

        /* InvSubBytes */
        for (i = 0; i < 4; i++)
            for (j = 0; j < 4; j++)
                state[i][j] = inv_sbox[state[i][j]];

        /* AddRoundKey */
        for (i = 0; i < 4; i++) {
            uint32_t k = rk[round * 4 + i];
            state[0][i] ^= (uint8_t)(k);
            state[1][i] ^= (uint8_t)(k >> 8);
            state[2][i] ^= (uint8_t)(k >> 16);
            state[3][i] ^= (uint8_t)(k >> 24);
        }

        /* InvMixColumns */
        uint8_t tmp[4][4];
        for (i = 0; i < 4; i++) {
            uint8_t a0 = state[0][i], a1 = state[1][i];
            uint8_t a2 = state[2][i], a3 = state[3][i];
            /* Multiply by inverse MixColumns matrix */
            uint8_t x0 = xtime(xtime(a0 ^ a2));
            uint8_t x1 = xtime(xtime(a1 ^ a3));
            a0 ^= x0; a1 ^= x1; a2 ^= x0; a3 ^= x1;
            tmp[0][i] = xtime(a0 ^ a1) ^ a1 ^ a2 ^ a3;
            tmp[1][i] = a0 ^ xtime(a1 ^ a2) ^ a2 ^ a3;
            tmp[2][i] = a0 ^ a1 ^ xtime(a2 ^ a3) ^ a3;
            tmp[3][i] = xtime(a0 ^ a3) ^ a0 ^ a1 ^ a2;
        }
        memcpy(state, tmp, 16);
    }

    /* Final round (no InvMixColumns) */
    {
        uint8_t t;

        /* InvShiftRows */
        t = state[1][3];
        state[1][3] = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = state[1][0];
        state[1][0] = t;

        t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t;
        t = state[2][1]; state[2][1] = state[2][3]; state[2][3] = t;

        t = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = t;

        /* InvSubBytes */
        for (i = 0; i < 4; i++)
            for (j = 0; j < 4; j++)
                state[i][j] = inv_sbox[state[i][j]];

        /* AddRoundKey (first round key) */
        for (i = 0; i < 4; i++) {
            uint32_t k = rk[i];
            state[0][i] ^= (uint8_t)(k);
            state[1][i] ^= (uint8_t)(k >> 8);
            state[2][i] ^= (uint8_t)(k >> 16);
            state[3][i] ^= (uint8_t)(k >> 24);
        }
    }

    /* Copy state to output (column-major) */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            output[i * 4 + j] = state[j][i];
        }
    }
}

void aes_free(aes_context *ctx) {
    if (ctx != NULL) {
        /* Securely zero the round keys */
        volatile uint8_t *p = (volatile uint8_t *)ctx;
        size_t n = sizeof(aes_context);
        while (n--) {
            *p++ = 0;
        }
    }
}