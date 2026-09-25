/*
 * BLAKE2b reference implementation header
 * Based on RFC 7693 and the BLAKE2 reference implementation.
 * License: CC0 1.0 Universal / Apache 2.0
 */

#ifndef BLAKE2B_H
#define BLAKE2B_H

#include <stdint.h>
#include <stddef.h>

#define BLAKE2B_BLOCKBYTES 128
#define BLAKE2B_OUTBYTES 64
#define BLAKE2B_KEYBYTES 64
#define BLAKE2B_SALTBYTES 16
#define BLAKE2B_PERSONALBYTES 16

typedef struct {
    uint64_t h[8];                   /* chained state */
    uint64_t t[2];                   /* total bytes count */
    uint64_t f[2];                   /* finalization flags */
    uint8_t buf[BLAKE2B_BLOCKBYTES]; /* input buffer */
    size_t buflen;                   /* buffer length */
    size_t outlen;                   /* digest length */
} blake2b_state;

/* Initialize BLAKE2b state with digest length */
int blake2b_init(blake2b_state *S, size_t outlen);

/* Update BLAKE2b state with input data */
int blake2b_update(blake2b_state *S, const void *in, size_t inlen);

/* Finalize BLAKE2b and produce digest */
int blake2b_final(blake2b_state *S, void *out, size_t outlen);

/* One-shot BLAKE2b hash */
int blake2b(void *out, size_t outlen, const void *in, size_t inlen,
            const void *key, size_t keylen);

#endif /* BLAKE2B_H */
