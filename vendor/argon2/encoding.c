/*
 * Argon2 reference implementation - Encoding utilities
 * Based on the reference C implementation by the Argon2 authors.
 * https://github.com/P-H-C/phc-winner-argon2
 * License: CC0 1.0 Universal / Apache 2.0
 *
 * This file provides encoding/decoding utilities for Argon2 hash strings.
 * For this password manager, we use raw hash output directly, so encoding
 * is minimal. This file is included for completeness of the vendored library.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "argon2.h"

/*
 * Encode an Argon2 hash to a string (PHC format).
 * Not used in this project (we use raw bytes), but included for library completeness.
 */

static const char *b64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Base64 encode without padding */
static size_t b64_encode(char *dst, size_t dst_len,
                         const uint8_t *src, size_t src_len) {
    size_t i, j;
    uint32_t acc;
    int bits;

    if (dst_len == 0) {
        return 0;
    }

    j = 0;
    acc = 0;
    bits = 0;

    for (i = 0; i < src_len; i++) {
        acc = (acc << 8) | src[i];
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            if (j >= dst_len - 1) {
                break;
            }
            dst[j++] = b64_chars[(acc >> bits) & 0x3F];
        }
    }

    if (bits > 0) {
        if (j < dst_len - 1) {
            dst[j++] = b64_chars[(acc << (6 - bits)) & 0x3F];
        }
    }

    dst[j] = '\0';
    return j;
}

/* Placeholder: full encoding not needed for raw hash usage */
int argon2_encode_string(char *dst, size_t dst_len,
                         const argon2_context *ctx, argon2_type type) {
    (void)dst;
    (void)dst_len;
    (void)ctx;
    (void)type;
    /* Not implemented - we use raw hash output */
    return ARGON2_ENCODING_FAIL;
}
