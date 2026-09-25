/**
 * test_validation.c - Property-based tests for master password validation
 *
 * Properties tested:
 *   5: Master Password Length Validation
 *
 * Uses the vendored theft library for property-based testing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "credential.h"
#include "theft.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Property 5: Master Password Length Validation
 * Feature: cross-platform-password-manager, Property 5: Master Password Length Validation
 *
 * For any random string of length 0-100:
 *   - Length < 8: master_password_validate returns false
 *   - Length >= 8: master_password_validate returns true
 *
 * Validates: Requirements 1.7
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    char password[101];
    size_t len;
} PasswordInput;

static theft_trial_res password_alloc(theft *t, void *env, void **output)
{
    (void)env;
    PasswordInput *input = (PasswordInput *)calloc(1, sizeof(PasswordInput));
    if (!input) return THEFT_TRIAL_ERROR;

    /* Generate random length 0-100 */
    input->len = (size_t)theft_random_choice(t, 101);

    /* Fill with random printable ASCII characters */
    for (size_t i = 0; i < input->len; i++) {
        input->password[i] = (char)(33 + (int)theft_random_choice(t, 94));
    }
    input->password[input->len] = '\0';

    *output = input;
    return THEFT_TRIAL_PASS;
}

static void password_free(void *instance, void *env)
{
    (void)env;
    free(instance);
}

static void password_print(FILE *f, const void *instance, void *env)
{
    (void)env;
    const PasswordInput *input = (const PasswordInput *)instance;
    fprintf(f, "password_len=%zu", input->len);
}

/* Feature: cross-platform-password-manager, Property 5: Master Password Length Validation */
static theft_trial_res prop_master_password_length(theft *t, void *arg1)
{
    (void)t;
    PasswordInput *input = (PasswordInput *)arg1;

    bool result = master_password_validate(input->password, input->len);

    if (input->len < MASTER_PASSWORD_MIN_LEN) {
        /* Should be rejected */
        if (result != false) {
            return THEFT_TRIAL_FAIL;
        }
    } else {
        /* Should be accepted */
        if (result != true) {
            return THEFT_TRIAL_FAIL;
        }
    }

    return THEFT_TRIAL_PASS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test Runner
 * ═══════════════════════════════════════════════════════════════════════════ */

static theft_type_info password_type = {
    .alloc = password_alloc,
    .free  = password_free,
    .print = password_print,
    .hash  = NULL,
    .shrink = NULL
};

int run_validation_tests(void)
{
    int failures = 0;
    theft_run_res res;

    printf("=== Validation Property Tests ===\n\n");

    /* Property 5: Master Password Length Validation */
    {
        theft_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.name = "Master Password Length Validation";
        cfg.fun = (void *)prop_master_password_length;
        cfg.type_info[0] = &password_type;
        cfg.trials = 100;
        cfg.seed = 50001;

        res = theft_run(&cfg);
        if (res != THEFT_RUN_PASS) {
            printf("  FAILED: Property 5 - Master Password Length Validation\n");
            failures++;
        } else {
            printf("  PASSED: Property 5 - Master Password Length Validation\n");
        }
    }

    printf("\n=== Validation Tests: %d failures ===\n", failures);
    return failures;
}

/* Stand-alone main for running just validation tests */
#ifndef TEST_NO_MAIN
int main(void)
{
    return run_validation_tests() == 0 ? 0 : 1;
}
#endif
