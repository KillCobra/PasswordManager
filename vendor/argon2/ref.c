/*
 * Argon2 reference implementation - Fill segment (reference, non-optimized)
 * Based on the reference C implementation by the Argon2 authors.
 * https://github.com/P-H-C/phc-winner-argon2
 * License: CC0 1.0 Universal / Apache 2.0
 */

#include <string.h>
#include <stdlib.h>

#include "argon2.h"
#include "core.h"
#include "blake2b.h"

/* Generate pseudo-random index for reference block */
static uint64_t fBlaMka(uint64_t x, uint64_t y) {
    const uint64_t m = 0xFFFFFFFFULL;
    const uint64_t xy = (x & m) * (y & m);
    return x + y + 2 * xy;
}

static inline uint64_t rotr64_ref(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

#define G_REF(a, b, c, d)                          \
    do {                                            \
        a = fBlaMka(a, b);                         \
        d = rotr64_ref(d ^ a, 32);                \
        c = fBlaMka(c, d);                         \
        b = rotr64_ref(b ^ c, 24);                \
        a = fBlaMka(a, b);                         \
        d = rotr64_ref(d ^ a, 16);                \
        c = fBlaMka(c, d);                         \
        b = rotr64_ref(b ^ c, 63);                \
    } while (0)

#define BLAKE2_ROUND_NOMSG(v0, v1, v2, v3, v4, v5, v6, v7, \
                           v8, v9, v10, v11, v12, v13, v14, v15) \
    do {                                                          \
        G_REF(v0, v4, v8, v12);                                  \
        G_REF(v1, v5, v9, v13);                                  \
        G_REF(v2, v6, v10, v14);                                 \
        G_REF(v3, v7, v11, v15);                                 \
        G_REF(v0, v5, v10, v15);                                 \
        G_REF(v1, v6, v11, v12);                                 \
        G_REF(v2, v7, v8, v13);                                  \
        G_REF(v3, v4, v9, v14);                                  \
    } while (0)

static void fill_block(const block *prev_block, const block *ref_block,
                       block *next_block, int with_xor) {
    block blockR, tmp;
    unsigned i;

    /* R = prev XOR ref */
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
        blockR.v[i] = prev_block->v[i] ^ ref_block->v[i];
    }

    /* Save R for XOR at the end */
    memcpy(tmp.v, blockR.v, sizeof(blockR.v));

    /* Apply Blake2 on columns of 64-bit words */
    for (i = 0; i < 8; i++) {
        BLAKE2_ROUND_NOMSG(
            blockR.v[16 * i + 0], blockR.v[16 * i + 1],
            blockR.v[16 * i + 2], blockR.v[16 * i + 3],
            blockR.v[16 * i + 4], blockR.v[16 * i + 5],
            blockR.v[16 * i + 6], blockR.v[16 * i + 7],
            blockR.v[16 * i + 8], blockR.v[16 * i + 9],
            blockR.v[16 * i + 10], blockR.v[16 * i + 11],
            blockR.v[16 * i + 12], blockR.v[16 * i + 13],
            blockR.v[16 * i + 14], blockR.v[16 * i + 15]);
    }

    /* Apply Blake2 on rows of 64-bit words */
    for (i = 0; i < 8; i++) {
        BLAKE2_ROUND_NOMSG(
            blockR.v[2 * i + 0], blockR.v[2 * i + 1],
            blockR.v[2 * i + 16], blockR.v[2 * i + 17],
            blockR.v[2 * i + 32], blockR.v[2 * i + 33],
            blockR.v[2 * i + 48], blockR.v[2 * i + 49],
            blockR.v[2 * i + 64], blockR.v[2 * i + 65],
            blockR.v[2 * i + 80], blockR.v[2 * i + 81],
            blockR.v[2 * i + 96], blockR.v[2 * i + 97],
            blockR.v[2 * i + 112], blockR.v[2 * i + 113]);
    }

    /* XOR with tmp (original R) */
    if (with_xor) {
        for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
            next_block->v[i] = blockR.v[i] ^ tmp.v[i] ^ next_block->v[i];
        }
    } else {
        for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
            next_block->v[i] = blockR.v[i] ^ tmp.v[i];
        }
    }
}

static uint32_t index_alpha(const argon2_instance_t *instance,
                            const argon2_position_t *position,
                            uint32_t pseudo_rand, int same_lane) {
    uint32_t reference_area_size;
    uint64_t relative_position;
    uint32_t start_position;

    if (position->pass == 0) {
        /* First pass */
        if (position->slice == 0) {
            /* First slice: can only reference current lane */
            reference_area_size = position->index - 1;
        } else {
            if (same_lane) {
                reference_area_size = position->slice * instance->segment_length +
                                      position->index - 1;
            } else {
                reference_area_size = position->slice * instance->segment_length +
                                      ((position->index == 0) ? -1 : 0);
            }
        }
    } else {
        /* Subsequent passes */
        if (same_lane) {
            reference_area_size = instance->lane_length -
                                  instance->segment_length + position->index - 1;
        } else {
            reference_area_size = instance->lane_length -
                                  instance->segment_length +
                                  ((position->index == 0) ? -1 : 0);
        }
    }

    /* Map pseudo_rand to reference area */
    relative_position = pseudo_rand;
    relative_position = relative_position * relative_position >> 32;
    relative_position = reference_area_size - 1 -
                        (reference_area_size * relative_position >> 32);

    /* Compute start position */
    start_position = 0;
    if (position->pass != 0) {
        start_position = (position->slice == ARGON2_SYNC_POINTS - 1)
                             ? 0
                             : (position->slice + 1) * instance->segment_length;
    }

    return (uint32_t)((start_position + relative_position) % instance->lane_length);
}

void argon2_fill_segment(const argon2_instance_t *instance,
                         argon2_position_t position) {
    block *ref_block, *curr_block, *prev_block;
    uint64_t pseudo_rand, ref_index, ref_lane;
    uint32_t prev_offset, curr_offset;
    uint32_t starting_index;
    uint32_t i;
    int data_independent_addressing;

    if (instance == NULL) {
        return;
    }

    data_independent_addressing = (instance->type == Argon2_i) ||
                                  (instance->type == Argon2_id && position.pass == 0 &&
                                   position.slice < ARGON2_SYNC_POINTS / 2);

    starting_index = 0;
    if (position.pass == 0 && position.slice == 0) {
        starting_index = 2; /* First two blocks already filled */
    }

    /* Current offset in memory */
    curr_offset = position.lane * instance->lane_length +
                  position.slice * instance->segment_length + starting_index;

    if (curr_offset % instance->lane_length == 0) {
        prev_offset = curr_offset + instance->lane_length - 1;
    } else {
        prev_offset = curr_offset - 1;
    }

    for (i = starting_index; i < instance->segment_length; i++, curr_offset++, prev_offset++) {
        if (curr_offset % instance->lane_length == 1) {
            prev_offset = curr_offset - 1;
        }

        /* Determine pseudo-random for reference block selection */
        if (data_independent_addressing) {
            /* For simplicity in reference implementation, use previous block */
            pseudo_rand = instance->memory[prev_offset].v[0];
        } else {
            pseudo_rand = instance->memory[prev_offset].v[0];
        }

        /* Determine reference lane */
        ref_lane = ((pseudo_rand >> 32)) % instance->lanes;
        if (position.pass == 0 && position.slice == 0) {
            ref_lane = position.lane;
        }

        /* Determine reference index */
        position.index = i;
        ref_index = index_alpha(instance, &position, (uint32_t)pseudo_rand,
                                ref_lane == position.lane);

        /* Get reference block */
        ref_block = &instance->memory[(uint32_t)(instance->lane_length * ref_lane + ref_index)];
        prev_block = &instance->memory[prev_offset];
        curr_block = &instance->memory[curr_offset];

        /* Fill block */
        int with_xor = (position.pass != 0);
        fill_block(prev_block, ref_block, curr_block, with_xor);
    }
}
