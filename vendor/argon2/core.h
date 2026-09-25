/*
 * Argon2 reference implementation - Core functions header
 * Based on the reference C implementation by the Argon2 authors.
 * https://github.com/P-H-C/phc-winner-argon2
 * License: CC0 1.0 Universal / Apache 2.0
 */

#ifndef ARGON2_CORE_H
#define ARGON2_CORE_H

#include "argon2.h"

/* Memory block structure */
typedef struct block_ {
    uint64_t v[ARGON2_QWORDS_IN_BLOCK];
} block;

/* Argon2 instance structure */
typedef struct {
    block *memory;          /* Memory blocks */
    uint32_t version;
    uint32_t passes;        /* Number of passes (iterations) */
    uint32_t memory_blocks; /* Number of blocks in memory */
    uint32_t segment_length;
    uint32_t lane_length;
    uint32_t lanes;
    uint32_t threads;
    argon2_type type;
    int print_internals;    /* Debug flag */
    argon2_context *context_ptr;
} argon2_instance_t;

/* Position structure for fill operations */
typedef struct {
    uint32_t pass;
    uint32_t lane;
    uint32_t slice;
    uint32_t index;
} argon2_position_t;

/*
 * Core Argon2 function - processes the context and fills memory.
 */
int argon2_ctx(argon2_context *context, argon2_type type);

/*
 * Initialize memory blocks.
 */
int argon2_initialize(argon2_instance_t *instance, argon2_context *context);

/*
 * Fill a memory segment.
 */
void argon2_fill_segment(const argon2_instance_t *instance,
                         argon2_position_t position);

/*
 * Validate inputs.
 */
int argon2_validate_inputs(const argon2_context *context);

/*
 * Finalize - produce the output hash.
 */
void argon2_finalize(const argon2_context *context,
                     argon2_instance_t *instance);

#endif /* ARGON2_CORE_H */
