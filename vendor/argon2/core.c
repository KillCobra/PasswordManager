/*
 * Argon2 reference implementation - Core functions
 * Based on the reference C implementation by the Argon2 authors.
 * https://github.com/P-H-C/phc-winner-argon2
 * License: CC0 1.0 Universal / Apache 2.0
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "argon2.h"
#include "core.h"
#include "blake2b.h"

/* Clear a block of memory */
static void clear_block(block *b) {
    memset(b->v, 0, sizeof(b->v));
}

/* XOR two blocks: dst = a XOR b */
static void xor_block(block *dst, const block *src) {
    for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
        dst->v[i] ^= src->v[i];
    }
}

/* Copy block */
static void copy_block(block *dst, const block *src) {
    memcpy(dst->v, src->v, sizeof(src->v));
}

int argon2_validate_inputs(const argon2_context *context) {
    if (NULL == context) {
        return ARGON2_INCORRECT_PARAMETER;
    }

    if (NULL == context->out) {
        return ARGON2_OUTPUT_PTR_NULL;
    }

    if (context->outlen < ARGON2_MIN_OUTLEN) {
        return ARGON2_OUTPUT_TOO_SHORT;
    }

    if (context->pwdlen > 0 && NULL == context->pwd) {
        return ARGON2_PWD_PTR_MISMATCH;
    }

    if (context->saltlen < ARGON2_MIN_SALT_LENGTH) {
        return ARGON2_SALT_TOO_SHORT;
    }

    if (context->saltlen > 0 && NULL == context->salt) {
        return ARGON2_SALT_PTR_MISMATCH;
    }

    if (context->t_cost < ARGON2_MIN_TIME) {
        return ARGON2_TIME_TOO_SMALL;
    }

    if (context->m_cost < ARGON2_MIN_MEMORY) {
        return ARGON2_MEMORY_TOO_LITTLE;
    }

    if (context->lanes < ARGON2_MIN_LANES) {
        return ARGON2_LANES_TOO_FEW;
    }

    return ARGON2_OK;
}

/* Hash variable-length input to produce a fixed or variable-length digest */
static void argon2_hash_long(uint8_t *out, uint32_t outlen,
                             const uint8_t *in, uint32_t inlen) {
    uint8_t outlen_bytes[4];
    blake2b_state blake_state;

    if (outlen <= 64) {
        /* Short output: single BLAKE2b call */
        outlen_bytes[0] = (uint8_t)(outlen);
        outlen_bytes[1] = (uint8_t)(outlen >> 8);
        outlen_bytes[2] = (uint8_t)(outlen >> 16);
        outlen_bytes[3] = (uint8_t)(outlen >> 24);

        blake2b_init(&blake_state, outlen);
        blake2b_update(&blake_state, outlen_bytes, 4);
        blake2b_update(&blake_state, in, inlen);
        blake2b_final(&blake_state, out, outlen);
    } else {
        /* Long output: repeated BLAKE2b */
        uint32_t toproduce = outlen;
        uint8_t out_buffer[64];
        uint8_t in_buffer[64];

        outlen_bytes[0] = (uint8_t)(outlen);
        outlen_bytes[1] = (uint8_t)(outlen >> 8);
        outlen_bytes[2] = (uint8_t)(outlen >> 16);
        outlen_bytes[3] = (uint8_t)(outlen >> 24);

        blake2b_init(&blake_state, 64);
        blake2b_update(&blake_state, outlen_bytes, 4);
        blake2b_update(&blake_state, in, inlen);
        blake2b_final(&blake_state, out_buffer, 64);

        memcpy(out, out_buffer, 32);
        out += 32;
        toproduce -= 32;

        while (toproduce > 64) {
            memcpy(in_buffer, out_buffer, 64);
            blake2b_init(&blake_state, 64);
            blake2b_update(&blake_state, in_buffer, 64);
            blake2b_final(&blake_state, out_buffer, 64);
            memcpy(out, out_buffer, 32);
            out += 32;
            toproduce -= 32;
        }

        memcpy(in_buffer, out_buffer, 64);
        blake2b_init(&blake_state, toproduce);
        blake2b_update(&blake_state, in_buffer, 64);
        blake2b_final(&blake_state, out_buffer, toproduce);
        memcpy(out, out_buffer, toproduce);
    }
}

/* Initial hash computation (H0) */
static void argon2_initial_hash(uint8_t *blockhash, argon2_context *context,
                                argon2_type type) {
    blake2b_state blake_state;
    uint8_t value[4];

    blake2b_init(&blake_state, ARGON2_PREHASH_DIGEST_LENGTH);

    /* lanes */
    value[0] = (uint8_t)(context->lanes);
    value[1] = (uint8_t)(context->lanes >> 8);
    value[2] = (uint8_t)(context->lanes >> 16);
    value[3] = (uint8_t)(context->lanes >> 24);
    blake2b_update(&blake_state, value, 4);

    /* outlen */
    value[0] = (uint8_t)(context->outlen);
    value[1] = (uint8_t)(context->outlen >> 8);
    value[2] = (uint8_t)(context->outlen >> 16);
    value[3] = (uint8_t)(context->outlen >> 24);
    blake2b_update(&blake_state, value, 4);

    /* m_cost */
    value[0] = (uint8_t)(context->m_cost);
    value[1] = (uint8_t)(context->m_cost >> 8);
    value[2] = (uint8_t)(context->m_cost >> 16);
    value[3] = (uint8_t)(context->m_cost >> 24);
    blake2b_update(&blake_state, value, 4);

    /* t_cost */
    value[0] = (uint8_t)(context->t_cost);
    value[1] = (uint8_t)(context->t_cost >> 8);
    value[2] = (uint8_t)(context->t_cost >> 16);
    value[3] = (uint8_t)(context->t_cost >> 24);
    blake2b_update(&blake_state, value, 4);

    /* version */
    value[0] = (uint8_t)(context->version);
    value[1] = (uint8_t)(context->version >> 8);
    value[2] = (uint8_t)(context->version >> 16);
    value[3] = (uint8_t)(context->version >> 24);
    blake2b_update(&blake_state, value, 4);

    /* type */
    value[0] = (uint8_t)(type);
    value[1] = (uint8_t)((uint32_t)type >> 8);
    value[2] = (uint8_t)((uint32_t)type >> 16);
    value[3] = (uint8_t)((uint32_t)type >> 24);
    blake2b_update(&blake_state, value, 4);

    /* pwdlen + pwd */
    value[0] = (uint8_t)(context->pwdlen);
    value[1] = (uint8_t)(context->pwdlen >> 8);
    value[2] = (uint8_t)(context->pwdlen >> 16);
    value[3] = (uint8_t)(context->pwdlen >> 24);
    blake2b_update(&blake_state, value, 4);
    if (context->pwd != NULL && context->pwdlen > 0) {
        blake2b_update(&blake_state, context->pwd, context->pwdlen);
    }

    /* saltlen + salt */
    value[0] = (uint8_t)(context->saltlen);
    value[1] = (uint8_t)(context->saltlen >> 8);
    value[2] = (uint8_t)(context->saltlen >> 16);
    value[3] = (uint8_t)(context->saltlen >> 24);
    blake2b_update(&blake_state, value, 4);
    if (context->salt != NULL && context->saltlen > 0) {
        blake2b_update(&blake_state, context->salt, context->saltlen);
    }

    /* secretlen + secret */
    value[0] = (uint8_t)(context->secretlen);
    value[1] = (uint8_t)(context->secretlen >> 8);
    value[2] = (uint8_t)(context->secretlen >> 16);
    value[3] = (uint8_t)(context->secretlen >> 24);
    blake2b_update(&blake_state, value, 4);
    if (context->secret != NULL && context->secretlen > 0) {
        blake2b_update(&blake_state, context->secret, context->secretlen);
    }

    /* adlen + ad */
    value[0] = (uint8_t)(context->adlen);
    value[1] = (uint8_t)(context->adlen >> 8);
    value[2] = (uint8_t)(context->adlen >> 16);
    value[3] = (uint8_t)(context->adlen >> 24);
    blake2b_update(&blake_state, value, 4);
    if (context->ad != NULL && context->adlen > 0) {
        blake2b_update(&blake_state, context->ad, context->adlen);
    }

    blake2b_final(&blake_state, blockhash, ARGON2_PREHASH_DIGEST_LENGTH);
}

int argon2_initialize(argon2_instance_t *instance, argon2_context *context) {
    uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH];
    uint32_t l;

    if (instance == NULL || context == NULL) {
        return ARGON2_INCORRECT_PARAMETER;
    }

    /* Compute H0 */
    argon2_initial_hash(blockhash, context, instance->type);

    /* Fill first two blocks for each lane */
    for (l = 0; l < instance->lanes; l++) {
        /* Block[l][0] = H'(H0 || 0 || l) */
        blockhash[ARGON2_PREHASH_DIGEST_LENGTH] = 0;
        blockhash[ARGON2_PREHASH_DIGEST_LENGTH + 1] = 0;
        blockhash[ARGON2_PREHASH_DIGEST_LENGTH + 2] = 0;
        blockhash[ARGON2_PREHASH_DIGEST_LENGTH + 3] = 0;
        blockhash[ARGON2_PREHASH_DIGEST_LENGTH + 4] = (uint8_t)l;
        blockhash[ARGON2_PREHASH_DIGEST_LENGTH + 5] = (uint8_t)(l >> 8);
        blockhash[ARGON2_PREHASH_DIGEST_LENGTH + 6] = (uint8_t)(l >> 16);
        blockhash[ARGON2_PREHASH_DIGEST_LENGTH + 7] = (uint8_t)(l >> 24);

        argon2_hash_long((uint8_t *)instance->memory[l * instance->lane_length].v,
                         ARGON2_BLOCK_SIZE, blockhash, ARGON2_PREHASH_SEED_LENGTH);

        /* Block[l][1] = H'(H0 || 1 || l) */
        blockhash[ARGON2_PREHASH_DIGEST_LENGTH] = 1;

        argon2_hash_long((uint8_t *)instance->memory[l * instance->lane_length + 1].v,
                         ARGON2_BLOCK_SIZE, blockhash, ARGON2_PREHASH_SEED_LENGTH);
    }

    memset(blockhash, 0, sizeof(blockhash));
    return ARGON2_OK;
}

void argon2_finalize(const argon2_context *context,
                     argon2_instance_t *instance) {
    block blockhash;
    uint32_t l;

    copy_block(&blockhash, &instance->memory[instance->lane_length - 1]);

    /* XOR last blocks of all lanes */
    for (l = 1; l < instance->lanes; l++) {
        uint32_t last_block_in_lane = l * instance->lane_length + (instance->lane_length - 1);
        xor_block(&blockhash, &instance->memory[last_block_in_lane]);
    }

    /* Hash the final block to produce the output */
    argon2_hash_long(context->out, context->outlen,
                     (uint8_t *)blockhash.v, ARGON2_BLOCK_SIZE);

    clear_block(&blockhash);

    /* Free memory */
    if (instance->memory != NULL) {
        /* Clear sensitive memory before freeing */
        for (l = 0; l < instance->memory_blocks; l++) {
            clear_block(&instance->memory[l]);
        }
        free(instance->memory);
        instance->memory = NULL;
    }
}
int argon2_ctx(argon2_context *context, argon2_type type) {
    int result;
    uint32_t memory_blocks, segment_length;
    argon2_instance_t instance;

    /* Validate inputs */
    result = argon2_validate_inputs(context);
    if (result != ARGON2_OK) {
        return result;
    }

    /* Calculate memory block count */
    memory_blocks = context->m_cost;
    if (memory_blocks < 2 * ARGON2_SYNC_POINTS * context->lanes) {
        memory_blocks = 2 * ARGON2_SYNC_POINTS * context->lanes;
    }

    segment_length = memory_blocks / (context->lanes * ARGON2_SYNC_POINTS);
    memory_blocks = segment_length * context->lanes * ARGON2_SYNC_POINTS;

    /* Initialize instance */
    memset(&instance, 0, sizeof(argon2_instance_t));
    instance.version = context->version;
    instance.memory = NULL;
    instance.passes = context->t_cost;
    instance.memory_blocks = memory_blocks;
    instance.segment_length = segment_length;
    instance.lane_length = segment_length * ARGON2_SYNC_POINTS;
    instance.lanes = context->lanes;
    instance.threads = context->threads;
    instance.type = type;
    instance.context_ptr = context;

    /* Allocate memory */
    instance.memory = (block *)calloc(memory_blocks, sizeof(block));
    if (instance.memory == NULL) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    /* Initialize first blocks */
    result = argon2_initialize(&instance, context);
    if (result != ARGON2_OK) {
        free(instance.memory);
        return result;
    }

    /* Fill memory - multiple passes */
    for (uint32_t pass = 0; pass < instance.passes; pass++) {
        for (uint32_t slice = 0; slice < ARGON2_SYNC_POINTS; slice++) {
            for (uint32_t lane = 0; lane < instance.lanes; lane++) {
                argon2_position_t position;
                position.pass = pass;
                position.lane = lane;
                position.slice = slice;
                position.index = 0;
                argon2_fill_segment(&instance, position);
            }
        }
    }

    /* Finalize - produce output */
    argon2_finalize(context, &instance);

    return ARGON2_OK;
}



