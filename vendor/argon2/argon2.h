/*
 * Argon2 reference implementation - Header
 * Based on the reference C implementation by the Argon2 authors.
 * https://github.com/P-H-C/phc-winner-argon2
 * License: CC0 1.0 Universal / Apache 2.0
 */

#ifndef ARGON2_H
#define ARGON2_H

#include <stdint.h>
#include <stddef.h>

/* Argon2 algorithm variants */
typedef enum {
    Argon2_d = 0,
    Argon2_i = 1,
    Argon2_id = 2
} argon2_type;

/* Argon2 version */
typedef enum {
    ARGON2_VERSION_10 = 0x10,
    ARGON2_VERSION_13 = 0x13,
    ARGON2_VERSION_NUMBER = ARGON2_VERSION_13
} argon2_version;

/* Error codes */
typedef enum {
    ARGON2_OK = 0,
    ARGON2_OUTPUT_PTR_NULL = -1,
    ARGON2_OUTPUT_TOO_SHORT = -2,
    ARGON2_OUTPUT_TOO_LONG = -3,
    ARGON2_PWD_TOO_SHORT = -4,
    ARGON2_PWD_TOO_LONG = -5,
    ARGON2_SALT_TOO_SHORT = -6,
    ARGON2_SALT_TOO_LONG = -7,
    ARGON2_AD_TOO_SHORT = -8,
    ARGON2_AD_TOO_LONG = -9,
    ARGON2_SECRET_TOO_SHORT = -10,
    ARGON2_SECRET_TOO_LONG = -11,
    ARGON2_TIME_TOO_SMALL = -12,
    ARGON2_TIME_TOO_LARGE = -13,
    ARGON2_MEMORY_TOO_LITTLE = -14,
    ARGON2_MEMORY_TOO_MUCH = -15,
    ARGON2_LANES_TOO_FEW = -16,
    ARGON2_LANES_TOO_MANY = -17,
    ARGON2_PWD_PTR_MISMATCH = -18,
    ARGON2_SALT_PTR_MISMATCH = -19,
    ARGON2_SECRET_PTR_MISMATCH = -20,
    ARGON2_AD_PTR_MISMATCH = -21,
    ARGON2_MEMORY_ALLOCATION_ERROR = -22,
    ARGON2_FREE_MEMORY_CBK_NULL = -23,
    ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24,
    ARGON2_INCORRECT_PARAMETER = -25,
    ARGON2_INCORRECT_TYPE = -26,
    ARGON2_OUT_PTR_MISMATCH = -27,
    ARGON2_THREADS_TOO_FEW = -28,
    ARGON2_THREADS_TOO_MANY = -29,
    ARGON2_MISSING_ARGS = -30,
    ARGON2_ENCODING_FAIL = -31,
    ARGON2_DECODING_FAIL = -32,
    ARGON2_THREAD_FAIL = -33,
    ARGON2_DECODING_LENGTH_FAIL = -34,
    ARGON2_VERIFY_MISMATCH = -35
} argon2_error_codes;

/* Argon2 context structure */
typedef struct {
    uint8_t *out;       /* output array */
    uint32_t outlen;    /* digest length */
    uint8_t *pwd;       /* password array */
    uint32_t pwdlen;    /* password length */
    uint8_t *salt;      /* salt array */
    uint32_t saltlen;   /* salt length */
    uint8_t *secret;    /* key array (optional) */
    uint32_t secretlen; /* key length */
    uint8_t *ad;        /* associated data array (optional) */
    uint32_t adlen;     /* associated data length */
    uint32_t t_cost;    /* number of passes (iterations) */
    uint32_t m_cost;    /* amount of memory requested (KB) */
    uint32_t lanes;     /* number of lanes (parallelism) */
    uint32_t threads;   /* maximum number of threads */
    argon2_version version; /* version number */
    void *(*allocate_cbk)(uint8_t *, size_t); /* memory allocator */
    void (*free_cbk)(uint8_t *, size_t);      /* memory deallocator */
    uint32_t flags;     /* array of bool options */
} argon2_context;

/* Minimum and maximum values */
#define ARGON2_MIN_LANES 1
#define ARGON2_MAX_LANES 0xFFFFFF
#define ARGON2_MIN_THREADS 1
#define ARGON2_MAX_THREADS 0xFFFFFF
#define ARGON2_SYNC_POINTS 4
#define ARGON2_MIN_OUTLEN 4
#define ARGON2_MAX_OUTLEN 0xFFFFFFFF
#define ARGON2_MIN_MEMORY (2 * ARGON2_SYNC_POINTS)
#define ARGON2_MIN(a, b) ((a) < (b) ? (a) : (b))
#define ARGON2_MAX_MEMORY 0xFFFFFFFF
#define ARGON2_MIN_TIME 1
#define ARGON2_MAX_TIME 0xFFFFFFFF
#define ARGON2_MIN_PWD_LENGTH 0
#define ARGON2_MAX_PWD_LENGTH 0xFFFFFFFF
#define ARGON2_MIN_AD_LENGTH 0
#define ARGON2_MAX_AD_LENGTH 0xFFFFFFFF
#define ARGON2_MIN_SALT_LENGTH 8
#define ARGON2_MAX_SALT_LENGTH 0xFFFFFFFF
#define ARGON2_MIN_SECRET 0
#define ARGON2_MAX_SECRET 0xFFFFFFFF
#define ARGON2_BLOCK_SIZE 1024
#define ARGON2_QWORDS_IN_BLOCK (ARGON2_BLOCK_SIZE / 8)
#define ARGON2_OWORDS_IN_BLOCK (ARGON2_BLOCK_SIZE / 16)
#define ARGON2_HWORDS_IN_BLOCK (ARGON2_BLOCK_SIZE / 32)
#define ARGON2_512BIT_WORDS_IN_BLOCK (ARGON2_BLOCK_SIZE / 64)
#define ARGON2_PREHASH_DIGEST_LENGTH 64
#define ARGON2_PREHASH_SEED_LENGTH 72

/**
 * High-level Argon2id hash function.
 * @param t_cost   Number of iterations
 * @param m_cost   Memory usage in kibibytes
 * @param parallelism Number of threads and lanes
 * @param pwd      Password data
 * @param pwdlen   Password length in bytes
 * @param salt     Salt data
 * @param saltlen  Salt length in bytes
 * @param hash     Output buffer for the hash
 * @param hashlen  Desired hash length in bytes
 * @return ARGON2_OK on success, error code otherwise
 */
int argon2id_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                      const uint32_t parallelism, const void *pwd,
                      const size_t pwdlen, const void *salt,
                      const size_t saltlen, void *hash,
                      const size_t hashlen);

/**
 * Low-level Argon2 function with full context.
 * @param context  Pointer to Argon2 context
 * @param type     Argon2 variant (d, i, or id)
 * @return ARGON2_OK on success, error code otherwise
 */
int argon2_ctx(argon2_context *context, argon2_type type);

/**
 * Get error message string for an error code.
 * @param error_code  The error code
 * @return Pointer to error message string
 */
const char *argon2_error_message(int error_code);

#endif /* ARGON2_H */
