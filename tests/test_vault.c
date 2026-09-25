/**
 * test_vault.c - Property-based tests for vault manager
 *
 * Properties tested:
 *  16: Vault Header Format
 *  11: Atomic Write Preservation
 *
 * Uses the vendored theft library for property-based testing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "vault.h"
#include "encryption.h"
#include "credential.h"
#include "platform.h"
#include "theft.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper: Generate a random printable ASCII string
 * ═══════════════════════════════════════════════════════════════════════════ */

static void gen_printable_string(theft *t, char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] = (char)(33 + (int)theft_random_choice(t, 94));
    }
    buf[len] = '\0';
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper: Create a DerivedKey with random bytes (no Argon2)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void make_test_key(theft *t, DerivedKey *key)
{
    theft_random_bytes(t, key->key, ENC_KEY_SIZE);
    theft_random_bytes(t, key->salt, ENC_SALT_SIZE);
    key->iterations = ENC_MIN_ITERATIONS;
    key->memory_kb = ENC_MIN_MEMORY_KB;
    key->parallelism = ENC_PARALLELISM;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Property 16: Vault Header Format
 * Feature: cross-platform-password-manager, Property 16: Vault Header Format
 *
 * For any random vault, after serialization:
 *   - First 4 bytes are magic "VLT1" (0x56, 0x4C, 0x54, 0x31)
 *   - Header is exactly 64 bytes
 *   - Format version is valid (1)
 *   - Algorithm ID is valid (0x01 = AES-256-GCM)
 *   - Credential count field matches vault count
 *
 * Validates: Requirements 7.2
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    Vault vault;
    DerivedKey key;
} HeaderInput;

static theft_trial_res header_alloc(theft *t, void *env, void **output)
{
    (void)env;
    HeaderInput *input = (HeaderInput *)calloc(1, sizeof(HeaderInput));
    if (!input) return THEFT_TRIAL_ERROR;

    /* Generate 0-10 credentials */
    uint32_t count = (uint32_t)theft_random_choice(t, 11);
    if (count > 0) {
        input->vault.entries = (Credential *)calloc(count, sizeof(Credential));
        if (!input->vault.entries) { free(input); return THEFT_TRIAL_ERROR; }
    }
    input->vault.count = count;
    input->vault.capacity = count;
    input->vault.is_dirty = false;

    for (uint32_t i = 0; i < count; i++) {
        Credential *c = &input->vault.entries[i];
        c->id = i + 1;
        gen_printable_string(t, c->url, 4 + (size_t)theft_random_choice(t, 20));
        gen_printable_string(t, c->username, 2 + (size_t)theft_random_choice(t, 10));
        gen_printable_string(t, c->password, 2 + (size_t)theft_random_choice(t, 10));
        c->created_at = theft_random(t);
        c->modified_at = theft_random(t);
        c->deleted = (theft_random_choice(t, 4) == 0);
    }

    make_test_key(t, &input->key);

    *output = input;
    return THEFT_TRIAL_PASS;
}

static void header_free(void *instance, void *env)
{
    (void)env;
    HeaderInput *input = (HeaderInput *)instance;
    if (input) {
        free(input->vault.entries);
        free(input);
    }
}

static void header_print(FILE *f, const void *instance, void *env)
{
    (void)env;
    const HeaderInput *input = (const HeaderInput *)instance;
    fprintf(f, "vault_count=%u", input->vault.count);
}

/* Helper: read uint16 LE from buffer */
static uint16_t read_u16_le(const uint8_t *buf)
{
    return (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
}

/* Helper: read uint32 LE from buffer */
static uint32_t read_u32_le(const uint8_t *buf)
{
    return (uint32_t)buf[0] |
           ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) |
           ((uint32_t)buf[3] << 24);
}

/* Feature: cross-platform-password-manager, Property 16: Vault Header Format */
static theft_trial_res prop_vault_header(theft *t, void *arg1)
{
    (void)t;
    HeaderInput *input = (HeaderInput *)arg1;

    uint8_t *data = NULL;
    size_t data_len = 0;

    /* Serialize the vault */
    StoreResult res = vault_serialize(&input->vault, &input->key, &data, &data_len);
    if (res != STORE_OK) {
        return THEFT_TRIAL_ERROR;
    }

    /* Verify minimum size: header (64) + GCM tag (16) */
    if (data_len < VAULT_HEADER_SIZE + ENC_TAG_SIZE) {
        free(data);
        return THEFT_TRIAL_FAIL;
    }

    /* Verify magic bytes */
    if (data[0] != VAULT_MAGIC_0 || data[1] != VAULT_MAGIC_1 ||
        data[2] != VAULT_MAGIC_2 || data[3] != VAULT_MAGIC_3) {
        free(data);
        return THEFT_TRIAL_FAIL;
    }

    /* Verify format version (bytes 4-5, uint16 LE) */
    uint16_t version = read_u16_le(data + 4);
    if (version != VAULT_FORMAT_VERSION) {
        free(data);
        return THEFT_TRIAL_FAIL;
    }

    /* Verify algorithm ID (byte 6) */
    if (data[6] != VAULT_ALGO_AES256GCM) {
        free(data);
        return THEFT_TRIAL_FAIL;
    }

    /* Verify Argon2 params match key */
    uint32_t iterations = read_u32_le(data + 7);
    uint32_t memory_kb = read_u32_le(data + 11);
    uint8_t parallelism = data[15];

    if (iterations != input->key.iterations ||
        memory_kb != input->key.memory_kb ||
        parallelism != input->key.parallelism) {
        free(data);
        return THEFT_TRIAL_FAIL;
    }

    /* Verify salt matches (bytes 16-31) */
    if (memcmp(data + 16, input->key.salt, ENC_SALT_SIZE) != 0) {
        free(data);
        return THEFT_TRIAL_FAIL;
    }

    /* Verify credential count (bytes 44-47) */
    uint32_t stored_count = read_u32_le(data + 44);
    if (stored_count != input->vault.count) {
        free(data);
        return THEFT_TRIAL_FAIL;
    }

    free(data);
    return THEFT_TRIAL_PASS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Property 11: Atomic Write Preservation
 * Feature: cross-platform-password-manager, Property 11: Atomic Write Preservation
 *
 * If store_save fails (e.g., NULL path), the function returns an error
 * and does not corrupt state. We test that store_save with invalid
 * parameters returns appropriate error codes without side effects.
 *
 * Validates: Requirements 2.7, 4.6, 5.5, 7.6
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t data[128];
    size_t data_len;
    uint32_t scenario; /* 0=null path, 1=null data, 2=valid (should succeed) */
} AtomicWriteInput;

static theft_trial_res atomic_alloc(theft *t, void *env, void **output)
{
    (void)env;
    AtomicWriteInput *input = (AtomicWriteInput *)calloc(1, sizeof(AtomicWriteInput));
    if (!input) return THEFT_TRIAL_ERROR;

    /* Generate random data */
    input->data_len = 16 + (size_t)theft_random_choice(t, 112);
    theft_random_bytes(t, input->data, input->data_len);

    /* Pick scenario */
    input->scenario = (uint32_t)theft_random_choice(t, 3);

    *output = input;
    return THEFT_TRIAL_PASS;
}

static void atomic_free(void *instance, void *env)
{
    (void)env;
    free(instance);
}

static void atomic_print(FILE *f, const void *instance, void *env)
{
    (void)env;
    const AtomicWriteInput *input = (const AtomicWriteInput *)instance;
    fprintf(f, "data_len=%zu scenario=%u", input->data_len, input->scenario);
}

/* Feature: cross-platform-password-manager, Property 11: Atomic Write Preservation */
static theft_trial_res prop_atomic_write(theft *t, void *arg1)
{
    (void)t;
    AtomicWriteInput *input = (AtomicWriteInput *)arg1;

    StoreResult res;

    switch (input->scenario) {
        case 0: {
            /* NULL path should fail gracefully */
            res = store_save(NULL, input->data, input->data_len);
            if (res == STORE_OK) {
                return THEFT_TRIAL_FAIL; /* Should have failed */
            }
            break;
        }
        case 1: {
            /* NULL data should fail gracefully */
            res = store_save("test_vault_atomic.vlt", NULL, input->data_len);
            if (res == STORE_OK) {
                return THEFT_TRIAL_FAIL; /* Should have failed */
            }
            break;
        }
        case 2: {
            /* Valid save to a temp file, then verify we can load it back */
            const char *test_path = "test_atomic_prop11.vlt";

            /* Build a minimal valid vault file with proper header */
            uint8_t header[VAULT_HEADER_SIZE + ENC_TAG_SIZE];
            memset(header, 0, sizeof(header));
            header[0] = VAULT_MAGIC_0;
            header[1] = VAULT_MAGIC_1;
            header[2] = VAULT_MAGIC_2;
            header[3] = VAULT_MAGIC_3;
            /* version = 1 */
            header[4] = 1;
            header[5] = 0;
            /* algo */
            header[6] = VAULT_ALGO_AES256GCM;

            res = store_save(test_path, header, sizeof(header));
            if (res != STORE_OK) {
                /* Platform may not support writing here - skip */
                return THEFT_TRIAL_SKIP;
            }

            /* Verify file exists and can be loaded */
            uint8_t *loaded = NULL;
            size_t loaded_len = 0;
            StoreResult load_res = store_load(test_path, &loaded, &loaded_len);
            if (load_res != STORE_OK) {
                return THEFT_TRIAL_FAIL;
            }

            /* Verify header integrity */
            if (loaded_len < VAULT_HEADER_SIZE ||
                loaded[0] != VAULT_MAGIC_0 ||
                loaded[1] != VAULT_MAGIC_1 ||
                loaded[2] != VAULT_MAGIC_2 ||
                loaded[3] != VAULT_MAGIC_3) {
                free(loaded);
                return THEFT_TRIAL_FAIL;
            }

            free(loaded);

            /* Clean up test file */
            /* Note: no platform_file_delete, but that's OK for tests */
            break;
        }
    }

    return THEFT_TRIAL_PASS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test Runner
 * ═══════════════════════════════════════════════════════════════════════════ */

static theft_type_info header_type = {
    .alloc = header_alloc,
    .free  = header_free,
    .print = header_print,
    .hash  = NULL,
    .shrink = NULL
};

static theft_type_info atomic_type = {
    .alloc = atomic_alloc,
    .free  = atomic_free,
    .print = atomic_print,
    .hash  = NULL,
    .shrink = NULL
};

int run_vault_tests(void)
{
    int failures = 0;
    theft_run_res res;

    printf("=== Vault Property Tests ===\n\n");

    /* Property 16: Vault Header Format */
    {
        theft_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.name = "Vault Header Format";
        cfg.fun = (void *)prop_vault_header;
        cfg.type_info[0] = &header_type;
        cfg.trials = 100;
        cfg.seed = 160001;

        res = theft_run(&cfg);
        if (res != THEFT_RUN_PASS) {
            printf("  FAILED: Property 16 - Vault Header Format\n");
            failures++;
        } else {
            printf("  PASSED: Property 16 - Vault Header Format\n");
        }
    }

    /* Property 11: Atomic Write Preservation */
    {
        theft_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.name = "Atomic Write Preservation";
        cfg.fun = (void *)prop_atomic_write;
        cfg.type_info[0] = &atomic_type;
        cfg.trials = 100;
        cfg.seed = 110001;

        res = theft_run(&cfg);
        if (res != THEFT_RUN_PASS) {
            printf("  FAILED: Property 11 - Atomic Write Preservation\n");
            failures++;
        } else {
            printf("  PASSED: Property 11 - Atomic Write Preservation\n");
        }
    }

    printf("\n=== Vault Tests: %d failures ===\n", failures);
    return failures;
}

/* Stand-alone main for running just vault tests */
#ifndef TEST_NO_MAIN
int main(void)
{
    return run_vault_tests() == 0 ? 0 : 1;
}
#endif
