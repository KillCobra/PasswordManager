/*
 * theft - property-based testing library for C
 * Based on https://github.com/silentbicycle/theft
 * License: ISC
 *
 * Core implementation: PRNG, trial execution, shrinking.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include "theft.h"

/* Internal theft state */
struct theft {
    uint64_t seed;
    uint64_t state[2]; /* xorshift128+ state */
    size_t trial;
    void *env;
};

/* xorshift128+ PRNG */
static uint64_t xorshift128plus(uint64_t state[2]) {
    uint64_t s1 = state[0];
    const uint64_t s0 = state[1];
    state[0] = s0;
    s1 ^= s1 << 23;
    state[1] = s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26);
    return state[1] + s0;
}

/* Seed the PRNG */
static void theft_seed_prng(theft *t, uint64_t seed) {
    t->seed = seed;
    /* SplitMix64 to initialize xorshift state from seed */
    uint64_t z = seed;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z = z ^ (z >> 31);
    t->state[0] = z;
    z = (seed + 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z = z ^ (z >> 31);
    t->state[1] = z;
}

uint64_t theft_random(theft *t) {
    return xorshift128plus(t->state);
}

uint64_t theft_random_choice(theft *t, uint64_t ceil) {
    if (ceil <= 1) return 0;
    return theft_random(t) % ceil;
}

uint64_t theft_random_bits(theft *t, uint8_t bit_count) {
    if (bit_count == 0) return 0;
    if (bit_count >= 64) return theft_random(t);
    return theft_random(t) & ((1ULL << bit_count) - 1);
}

void theft_random_bytes(theft *t, uint8_t *buf, size_t len) {
    size_t i;
    for (i = 0; i + 8 <= len; i += 8) {
        uint64_t r = theft_random(t);
        memcpy(buf + i, &r, 8);
    }
    if (i < len) {
        uint64_t r = theft_random(t);
        memcpy(buf + i, &r, len - i);
    }
}

double theft_random_double(theft *t) {
    uint64_t r = theft_random(t);
    return (double)(r >> 11) * (1.0 / 9007199254740992.0);
}

/* Run a single trial */
static theft_trial_res run_trial(theft *t, const theft_cfg *cfg,
                                 void **args, int arg_count) {
    /* Generate arguments */
    for (int i = 0; i < arg_count; i++) {
        if (cfg->type_info[i] == NULL) break;
        theft_trial_res res = cfg->type_info[i]->alloc(t, cfg->env, &args[i]);
        if (res == THEFT_TRIAL_SKIP) {
            /* Free already allocated args */
            for (int j = 0; j < i; j++) {
                if (cfg->type_info[j]->free) {
                    cfg->type_info[j]->free(args[j], cfg->env);
                }
            }
            return THEFT_TRIAL_SKIP;
        }
        if (res != THEFT_TRIAL_PASS) {
            for (int j = 0; j < i; j++) {
                if (cfg->type_info[j]->free) {
                    cfg->type_info[j]->free(args[j], cfg->env);
                }
            }
            return THEFT_TRIAL_ERROR;
        }
    }

    /* Call property function based on argument count */
    theft_trial_res result;
    typedef theft_trial_res (*prop1_fn)(theft *, void *);
    typedef theft_trial_res (*prop2_fn)(theft *, void *, void *);
    typedef theft_trial_res (*prop3_fn)(theft *, void *, void *, void *);

    if (arg_count == 1) {
        result = ((prop1_fn)cfg->fun)(t, args[0]);
    } else if (arg_count == 2) {
        result = ((prop2_fn)cfg->fun)(t, args[0], args[1]);
    } else if (arg_count == 3) {
        result = ((prop3_fn)cfg->fun)(t, args[0], args[1], args[2]);
    } else {
        result = THEFT_TRIAL_ERROR;
    }

    return result;
}

/* Attempt to shrink a failing case */
static void try_shrink(theft *t, const theft_cfg *cfg,
                       void **args, int arg_count) {
    const uint32_t MAX_SHRINK_TACTICS = 100;

    for (int i = 0; i < arg_count; i++) {
        if (cfg->type_info[i] == NULL || cfg->type_info[i]->shrink == NULL) {
            continue;
        }

        for (uint32_t tactic = 0; tactic < MAX_SHRINK_TACTICS; tactic++) {
            void *shrunk = NULL;
            theft_trial_res sres = cfg->type_info[i]->shrink(
                t, args[i], tactic, cfg->env, &shrunk);

            if (sres == THEFT_TRIAL_SKIP) {
                break; /* No more shrink tactics */
            }
            if (sres != THEFT_TRIAL_PASS || shrunk == NULL) {
                continue;
            }

            /* Test with shrunk value */
            void *old = args[i];
            args[i] = shrunk;

            theft_trial_res result;
            typedef theft_trial_res (*prop1_fn)(theft *, void *);
            typedef theft_trial_res (*prop2_fn)(theft *, void *, void *);
            typedef theft_trial_res (*prop3_fn)(theft *, void *, void *, void *);

            if (arg_count == 1) {
                result = ((prop1_fn)cfg->fun)(t, args[0]);
            } else if (arg_count == 2) {
                result = ((prop2_fn)cfg->fun)(t, args[0], args[1]);
            } else if (arg_count == 3) {
                result = ((prop3_fn)cfg->fun)(t, args[0], args[1], args[2]);
            } else {
                result = THEFT_TRIAL_ERROR;
            }

            if (result == THEFT_TRIAL_FAIL) {
                /* Shrunk version still fails - keep it */
                if (cfg->type_info[i]->free) {
                    cfg->type_info[i]->free(old, cfg->env);
                }
                /* Reset tactic to try shrinking further */
                tactic = 0;
            } else {
                /* Shrunk version passes - revert */
                args[i] = old;
                if (cfg->type_info[i]->free) {
                    cfg->type_info[i]->free(shrunk, cfg->env);
                }
            }
        }
    }
}

theft_run_res theft_run(const theft_cfg *cfg) {
    theft t;
    void *args[7] = {NULL};
    int arg_count = 0;
    size_t trials;
    size_t passes = 0, failures = 0, skips = 0;
    theft_run_res run_result = THEFT_RUN_PASS;

    if (cfg == NULL || cfg->fun == NULL) {
        return THEFT_RUN_ERROR;
    }

    /* Count arguments */
    for (int i = 0; i < 7; i++) {
        if (cfg->type_info[i] == NULL) break;
        arg_count++;
    }

    if (arg_count == 0) {
        return THEFT_RUN_ERROR;
    }

    /* Set up PRNG */
    uint64_t seed = cfg->seed;
    if (seed == 0) {
        seed = (uint64_t)time(NULL) ^ ((uint64_t)clock() << 32);
    }
    theft_seed_prng(&t, seed);
    t.env = cfg->env;

    trials = cfg->trials > 0 ? cfg->trials : 100;

    if (cfg->name) {
        printf("  Property: %s (seed: %llu, trials: %zu)\n",
               cfg->name, (unsigned long long)seed, trials);
    }

    /* Run trials */
    for (size_t trial = 0; trial < trials; trial++) {
        t.trial = trial;

        /* Re-seed for each trial for reproducibility */
        theft_seed_prng(&t, seed + trial);

        memset(args, 0, sizeof(args));
        theft_trial_res res = run_trial(&t, cfg, args, arg_count);

        switch (res) {
        case THEFT_TRIAL_PASS:
            passes++;
            /* Free args */
            for (int i = 0; i < arg_count; i++) {
                if (cfg->type_info[i]->free && args[i]) {
                    cfg->type_info[i]->free(args[i], cfg->env);
                }
            }
            break;

        case THEFT_TRIAL_FAIL:
            failures++;
            /* Try to shrink */
            try_shrink(&t, cfg, args, arg_count);

            /* Print counterexample */
            printf("    FAIL (trial %zu", trial);
            printf(")\n");
            for (int i = 0; i < arg_count; i++) {
                if (cfg->type_info[i]->print && args[i]) {
                    printf("      Arg %d: ", i);
                    cfg->type_info[i]->print(stdout, args[i], cfg->env);
                    printf("\n");
                }
            }

            /* Free args */
            for (int i = 0; i < arg_count; i++) {
                if (cfg->type_info[i]->free && args[i]) {
                    cfg->type_info[i]->free(args[i], cfg->env);
                }
            }

            run_result = THEFT_RUN_FAIL;
            goto done;

        case THEFT_TRIAL_SKIP:
            skips++;
            break;

        case THEFT_TRIAL_ERROR:
            /* Free any allocated args */
            for (int i = 0; i < arg_count; i++) {
                if (cfg->type_info[i]->free && args[i]) {
                    cfg->type_info[i]->free(args[i], cfg->env);
                }
            }
            run_result = THEFT_RUN_ERROR;
            goto done;
        }
    }

done:
    if (cfg->name) {
        printf("    Result: %zu passed, %zu failed, %zu skipped\n",
               passes, failures, skips);
    }

    return run_result;
}
