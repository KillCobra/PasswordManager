/*
 * theft - property-based testing library for C
 * Based on https://github.com/silentbicycle/theft
 * License: ISC
 *
 * This is a minimal vendored version providing the core API
 * for property-based testing.
 */

#ifndef THEFT_H
#define THEFT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

/* Version */
#define THEFT_VERSION_MAJOR 0
#define THEFT_VERSION_MINOR 4
#define THEFT_VERSION_PATCH 5

/* Forward declarations */
typedef struct theft theft;
typedef struct theft_seed theft_seed;

/* Trial result - what the property function returns */
typedef enum {
    THEFT_TRIAL_PASS = 0,   /* Property held */
    THEFT_TRIAL_FAIL = 1,   /* Property violated (counterexample found) */
    THEFT_TRIAL_SKIP = 2,   /* Input not applicable, skip */
    THEFT_TRIAL_ERROR = 3   /* Error during test execution */
} theft_trial_res;

/* Overall run result */
typedef enum {
    THEFT_RUN_PASS = 0,         /* All trials passed */
    THEFT_RUN_FAIL = 1,         /* Found a counterexample */
    THEFT_RUN_ERROR = 2,        /* Error during run */
    THEFT_RUN_ERROR_MEMORY = 3  /* Memory allocation failure */
} theft_run_res;

/* Bloom filter for deduplication (opaque) */
typedef enum {
    THEFT_BLOOM_NONE = 0,
    THEFT_BLOOM_SMALL = 1,
    THEFT_BLOOM_MEDIUM = 2,
    THEFT_BLOOM_LARGE = 3
} theft_bloom_filter;

/* Type info - describes how to generate, shrink, print, and free a type */
typedef struct {
    /* Allocate/generate a random instance.
     * seed: random seed for generation
     * env: user environment pointer
     * output: pointer to store generated value
     * Returns: THEFT_TRIAL_PASS on success, THEFT_TRIAL_SKIP to skip */
    theft_trial_res (*alloc)(theft *t, void *env, void **output);

    /* Free a generated instance */
    void (*free)(void *instance, void *env);

    /* Print an instance (for counterexample reporting) */
    void (*print)(FILE *f, const void *instance, void *env);

    /* Hash an instance (for bloom filter deduplication, optional) */
    uint64_t (*hash)(const void *instance, void *env);

    /* Shrink an instance to find minimal counterexample (optional).
     * instance: current instance
     * tactic: shrink attempt number (0, 1, 2, ...)
     * env: user environment pointer
     * output: pointer to store shrunk value
     * Returns: THEFT_TRIAL_PASS if shrunk, THEFT_TRIAL_SKIP if no more shrinks */
    theft_trial_res (*shrink)(theft *t, const void *instance,
                              uint32_t tactic, void *env, void **output);
} theft_type_info;

/* Configuration for a property test run */
typedef struct {
    /* Property function pointer - set via theft_run macros */
    void *fun;

    /* Type info array (one per argument to property function) */
    theft_type_info *type_info[7]; /* Max 7 arguments */

    /* Number of trials to run (default: 100) */
    size_t trials;

    /* Random seed (0 = use time-based seed) */
    uint64_t seed;

    /* User environment pointer passed to alloc/free/print/shrink */
    void *env;

    /* Bloom filter size for deduplication */
    theft_bloom_filter bloom_bits;

    /* Name of the property (for reporting) */
    const char *name;
} theft_cfg;

/* Random number generation */

/**
 * Get a random uint64 from the theft PRNG.
 */
uint64_t theft_random(theft *t);

/**
 * Get a random uint64 in range [0, ceil).
 */
uint64_t theft_random_choice(theft *t, uint64_t ceil);

/**
 * Get random bits (0 to 64 bits).
 */
uint64_t theft_random_bits(theft *t, uint8_t bit_count);

/**
 * Fill buffer with random bytes.
 */
void theft_random_bytes(theft *t, uint8_t *buf, size_t len);

/**
 * Get a random double in [0.0, 1.0).
 */
double theft_random_double(theft *t);

/* Running property tests */

/**
 * Run a property test with the given configuration.
 * @param cfg  Test configuration
 * @return THEFT_RUN_PASS if all trials pass, THEFT_RUN_FAIL if counterexample found
 */
theft_run_res theft_run(const theft_cfg *cfg);

/* Convenience macros for running property tests with typed function pointers */

/* 1-argument property */
#define THEFT_RUN_1(cfg_ptr, fn_ptr) \
    do { (cfg_ptr)->fun = (void *)(fn_ptr); } while(0), \
    theft_run(cfg_ptr)

/* 2-argument property */
#define THEFT_RUN_2(cfg_ptr, fn_ptr) \
    do { (cfg_ptr)->fun = (void *)(fn_ptr); } while(0), \
    theft_run(cfg_ptr)

/* Macro to run a property test (generic) */
#define THEFT_RUN(cfg_ptr) theft_run(cfg_ptr)

#endif /* THEFT_H */
