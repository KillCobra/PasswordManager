/**
 * test_encryption.c - Property-based tests for encryption engine
 *
 * Properties tested:
 *   1: Vault Serialization Round-Trip
 *   2: Encryption Conceals Plaintext
 *   3: Wrong Password Rejection
 *   4: Secure Memory Clearing
 *  13: Tamper Detection
 *
 * Uses the vendored theft library for property-based testing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "encryption.h"
#include "vault.h"
#include "credential.h"
#include "platform.h"
#include "theft.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper: Generate a random printable ASCII string of given length
 * ═══════════════════════════════════════════════════════════════════════════ */

static void gen_printable_string(theft *t, char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        /* Printable ASCII range: 33-126 (avoid space for substring search) */
        buf[i] = (char)(33 + (int)theft_random_choice(t, 94));
    }
    buf[len] = '\0';
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper: Create a DerivedKey with a fixed test password (fast, low params)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void make_test_key(theft *t, DerivedKey *key)
{
    /* Use random bytes directly as the key to avoid slow Argon2 in tests */
    theft_random_bytes(t, key->key, ENC_KEY_SIZE);
    theft_random_bytes(t, key->salt, ENC_SALT_SIZE);
    key->iterations = ENC_MIN_ITERATIONS;
    key->memory_kb = ENC_MIN_MEMORY_KB;
    key->parallelism = ENC_PARALLELISM;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Property 1: Vault Serialization Round-Trip
 * Feature: cross-platform-password-manager, Property 1: Vault Serialization Round-Trip
 *
 * For any valid set of credentials, serialize → encrypt → decrypt →
 * deserialize SHALL produce identical field values.
 *
 * Validates: Requirements 1.6, 7.5
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    Vault vault;
    DerivedKey key;
} RoundTripInput;

static theft_trial_res roundtrip_alloc(theft *t, void *env, void **output)
{
    (void)env;
    RoundTripInput *input = (RoundTripInput *)calloc(1, sizeof(RoundTripInput));
    if (!input) return THEFT_TRIAL_ERROR;

    /* Generate 1-10 credentials for speed */
    uint32_t count = (uint32_t)(1 + theft_random_choice(t, 10));
    input->vault.entries = (Credential *)calloc(count, sizeof(Credential));
    if (!input->vault.entries) {
        free(input);
        return THEFT_TRIAL_ERROR;
    }
    input->vault.count = count;
    input->vault.capacity = count;
    input->vault.is_dirty = false;

    for (uint32_t i = 0; i < count; i++) {
        Credential *c = &input->vault.entries[i];
        c->id = i + 1;

        /* Random field lengths within bounds */
        size_t url_len = 1 + (size_t)theft_random_choice(t, 64);
        size_t user_len = 1 + (size_t)theft_random_choice(t, 32);
        size_t pass_len = 1 + (size_t)theft_random_choice(t, 32);

        gen_printable_string(t, c->url, url_len);
        gen_printable_string(t, c->username, user_len);
        gen_printable_string(t, c->password, pass_len);

        c->created_at = theft_random(t);
        c->modified_at = theft_random(t);
        c->deleted = (theft_random_choice(t, 2) == 1);
    }

    /* Generate a test key */
    make_test_key(t, &input->key);

    *output = input;
    return THEFT_TRIAL_PASS;
}

static void roundtrip_free(void *instance, void *env)
{
    (void)env;
    RoundTripInput *input = (RoundTripInput *)instance;
    if (input) {
        free(input->vault.entries);
        free(input);
    }
}

static void roundtrip_print(FILE *f, const void *instance, void *env)
{
    (void)env;
    const RoundTripInput *input = (const RoundTripInput *)instance;
    fprintf(f, "Vault with %u credentials", input->vault.count);
}

/* Feature: cross-platform-password-manager, Property 1: Vault Serialization Round-Trip */
static theft_trial_res prop_vault_roundtrip(theft *t, void *arg1)
{
    (void)t;
    RoundTripInput *input = (RoundTripInput *)arg1;
    uint8_t *serialized = NULL;
    size_t serialized_len = 0;
    Vault deserialized;
    memset(&deserialized, 0, sizeof(deserialized));

    /* Serialize the vault */
    StoreResult res = vault_serialize(&input->vault, &input->key,
                                      &serialized, &serialized_len);
    if (res != STORE_OK) {
        return THEFT_TRIAL_ERROR;
    }

    /* Deserialize back */
    res = vault_deserialize(serialized, serialized_len,
                            &input->key, &deserialized);
    free(serialized);

    if (res != STORE_OK) {
        return THEFT_TRIAL_FAIL;
    }

    /* Verify credential count matches */
    if (deserialized.count != input->vault.count) {
        free(deserialized.entries);
        return THEFT_TRIAL_FAIL;
    }

    /* Verify each credential field is identical */
    for (uint32_t i = 0; i < input->vault.count; i++) {
        const Credential *orig = &input->vault.entries[i];
        const Credential *got = &deserialized.entries[i];

        if (orig->id != got->id ||
            strcmp(orig->url, got->url) != 0 ||
            strcmp(orig->username, got->username) != 0 ||
            strcmp(orig->password, got->password) != 0 ||
            orig->created_at != got->created_at ||
            orig->modified_at != got->modified_at ||
            orig->deleted != got->deleted) {
            free(deserialized.entries);
            return THEFT_TRIAL_FAIL;
        }
    }

    free(deserialized.entries);
    return THEFT_TRIAL_PASS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Property 2: Encryption Conceals Plaintext
 * Feature: cross-platform-password-manager, Property 2: Encryption Conceals Plaintext
 *
 * For any valid credential with printable ASCII fields, after encryption
 * the raw ciphertext bytes SHALL NOT contain any plaintext field values.
 *
 * Validates: Requirements 1.2
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    char url[65];
    char username[33];
    char password[33];
    DerivedKey key;
} ConcealInput;

static theft_trial_res conceal_alloc(theft *t, void *env, void **output)
{
    (void)env;
    ConcealInput *input = (ConcealInput *)calloc(1, sizeof(ConcealInput));
    if (!input) return THEFT_TRIAL_ERROR;

    /* Generate fields with minimum length 4 to make substring search meaningful */
    size_t url_len = 4 + (size_t)theft_random_choice(t, 60);
    size_t user_len = 4 + (size_t)theft_random_choice(t, 28);
    size_t pass_len = 4 + (size_t)theft_random_choice(t, 28);

    gen_printable_string(t, input->url, url_len);
    gen_printable_string(t, input->username, user_len);
    gen_printable_string(t, input->password, pass_len);

    make_test_key(t, &input->key);

    *output = input;
    return THEFT_TRIAL_PASS;
}

static void conceal_free(void *instance, void *env)
{
    (void)env;
    free(instance);
}

static void conceal_print(FILE *f, const void *instance, void *env)
{
    (void)env;
    const ConcealInput *input = (const ConcealInput *)instance;
    fprintf(f, "url='%s' user='%s' pass='%s'",
            input->url, input->username, input->password);
}

/**
 * Search for a substring within a byte buffer.
 * Returns true if needle is found in haystack.
 */
static bool find_substring(const uint8_t *haystack, size_t haystack_len,
                           const char *needle, size_t needle_len)
{
    if (needle_len == 0 || needle_len > haystack_len) return false;
    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

/* Feature: cross-platform-password-manager, Property 2: Encryption Conceals Plaintext */
static theft_trial_res prop_encryption_conceals(theft *t, void *arg1)
{
    (void)t;
    ConcealInput *input = (ConcealInput *)arg1;

    /* Build a plaintext buffer containing the credential fields */
    size_t url_len = strlen(input->url);
    size_t user_len = strlen(input->username);
    size_t pass_len = strlen(input->password);
    size_t pt_len = url_len + user_len + pass_len + 32; /* extra for framing */

    uint8_t *plaintext = (uint8_t *)calloc(1, pt_len);
    if (!plaintext) return THEFT_TRIAL_ERROR;

    /* Pack fields into plaintext (simulating credential serialization) */
    size_t offset = 0;
    memcpy(plaintext + offset, input->url, url_len);
    offset += url_len;
    memcpy(plaintext + offset, input->username, user_len);
    offset += user_len;
    memcpy(plaintext + offset, input->password, pass_len);
    offset += pass_len;

    /* Encrypt */
    uint8_t *ciphertext = (uint8_t *)malloc(pt_len);
    if (!ciphertext) { free(plaintext); return THEFT_TRIAL_ERROR; }

    size_t ct_len = 0;
    uint8_t nonce[ENC_NONCE_SIZE];
    uint8_t tag[ENC_TAG_SIZE];

    EncResult enc_res = enc_encrypt(&input->key, plaintext, offset,
                                    ciphertext, &ct_len, nonce, tag);
    free(plaintext);

    if (enc_res != ENC_OK) {
        free(ciphertext);
        return THEFT_TRIAL_ERROR;
    }

    /* Scan ciphertext for plaintext substrings */
    bool found_url = find_substring(ciphertext, ct_len,
                                    input->url, url_len);
    bool found_user = find_substring(ciphertext, ct_len,
                                     input->username, user_len);
    bool found_pass = find_substring(ciphertext, ct_len,
                                     input->password, pass_len);

    free(ciphertext);

    if (found_url || found_user || found_pass) {
        return THEFT_TRIAL_FAIL;
    }

    return THEFT_TRIAL_PASS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Property 3: Wrong Password Rejection
 * Feature: cross-platform-password-manager, Property 3: Wrong Password Rejection
 *
 * For any two different passwords P and Q, encrypting with P and
 * attempting to decrypt with Q SHALL fail with ENC_ERR_INTEGRITY_FAILED.
 *
 * Validates: Requirements 1.4
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    DerivedKey key_p;  /* Key derived from password P */
    DerivedKey key_q;  /* Key derived from password Q (different) */
    uint8_t plaintext[64];
    size_t pt_len;
} WrongPasswordInput;

static theft_trial_res wrong_pw_alloc(theft *t, void *env, void **output)
{
    (void)env;
    WrongPasswordInput *input = (WrongPasswordInput *)calloc(1, sizeof(WrongPasswordInput));
    if (!input) return THEFT_TRIAL_ERROR;

    /* Generate two different keys (simulating different passwords) */
    make_test_key(t, &input->key_p);
    make_test_key(t, &input->key_q);

    /* Ensure keys are actually different */
    while (memcmp(input->key_p.key, input->key_q.key, ENC_KEY_SIZE) == 0) {
        make_test_key(t, &input->key_q);
    }

    /* Generate random plaintext (8-64 bytes) */
    input->pt_len = 8 + (size_t)theft_random_choice(t, 56);
    theft_random_bytes(t, input->plaintext, input->pt_len);

    *output = input;
    return THEFT_TRIAL_PASS;
}

static void wrong_pw_free(void *instance, void *env)
{
    (void)env;
    free(instance);
}

static void wrong_pw_print(FILE *f, const void *instance, void *env)
{
    (void)env;
    const WrongPasswordInput *input = (const WrongPasswordInput *)instance;
    fprintf(f, "pt_len=%zu, keys differ=%s", input->pt_len,
            memcmp(input->key_p.key, input->key_q.key, ENC_KEY_SIZE) != 0 ? "yes" : "no");
}

/* Feature: cross-platform-password-manager, Property 3: Wrong Password Rejection */
static theft_trial_res prop_wrong_password(theft *t, void *arg1)
{
    (void)t;
    WrongPasswordInput *input = (WrongPasswordInput *)arg1;

    /* Encrypt with key P */
    uint8_t ciphertext[64];
    size_t ct_len = 0;
    uint8_t nonce[ENC_NONCE_SIZE];
    uint8_t tag[ENC_TAG_SIZE];

    EncResult res = enc_encrypt(&input->key_p, input->plaintext, input->pt_len,
                                ciphertext, &ct_len, nonce, tag);
    if (res != ENC_OK) {
        return THEFT_TRIAL_ERROR;
    }

    /* Attempt decrypt with key Q (different key) */
    uint8_t decrypted[64];
    size_t dec_len = 0;

    res = enc_decrypt(&input->key_q, ciphertext, ct_len,
                      nonce, tag, decrypted, &dec_len);

    /* Must fail with integrity error */
    if (res != ENC_ERR_INTEGRITY_FAILED) {
        return THEFT_TRIAL_FAIL;
    }

    return THEFT_TRIAL_PASS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Property 4: Secure Memory Clearing
 * Feature: cross-platform-password-manager, Property 4: Secure Memory Clearing
 *
 * For any buffer filled with random data, after calling enc_secure_zero(),
 * all bytes SHALL be zero.
 *
 * Validates: Requirements 1.5
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t *buffer;
    size_t len;
} SecureZeroInput;

static theft_trial_res secure_zero_alloc(theft *t, void *env, void **output)
{
    (void)env;
    SecureZeroInput *input = (SecureZeroInput *)calloc(1, sizeof(SecureZeroInput));
    if (!input) return THEFT_TRIAL_ERROR;

    /* Random buffer size: 1-1024 bytes */
    input->len = 1 + (size_t)theft_random_choice(t, 1024);
    input->buffer = (uint8_t *)malloc(input->len);
    if (!input->buffer) {
        free(input);
        return THEFT_TRIAL_ERROR;
    }

    /* Fill with random non-zero data */
    theft_random_bytes(t, input->buffer, input->len);
    /* Ensure at least some bytes are non-zero */
    for (size_t i = 0; i < input->len && i < 8; i++) {
        if (input->buffer[i] == 0) {
            input->buffer[i] = (uint8_t)(1 + theft_random_choice(t, 254));
        }
    }

    *output = input;
    return THEFT_TRIAL_PASS;
}

static void secure_zero_free(void *instance, void *env)
{
    (void)env;
    SecureZeroInput *input = (SecureZeroInput *)instance;
    if (input) {
        free(input->buffer);
        free(input);
    }
}

static void secure_zero_print(FILE *f, const void *instance, void *env)
{
    (void)env;
    const SecureZeroInput *input = (const SecureZeroInput *)instance;
    fprintf(f, "buffer_len=%zu", input->len);
}

/* Feature: cross-platform-password-manager, Property 4: Secure Memory Clearing */
static theft_trial_res prop_secure_zero(theft *t, void *arg1)
{
    (void)t;
    SecureZeroInput *input = (SecureZeroInput *)arg1;

    /* Call enc_secure_zero on the buffer */
    enc_secure_zero(input->buffer, input->len);

    /* Verify all bytes are zero */
    for (size_t i = 0; i < input->len; i++) {
        if (input->buffer[i] != 0) {
            return THEFT_TRIAL_FAIL;
        }
    }

    return THEFT_TRIAL_PASS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Property 13: Tamper Detection
 * Feature: cross-platform-password-manager, Property 13: Tamper Detection
 *
 * For any valid encrypted data, if any single bit in the ciphertext or
 * GCM tag is flipped, decryption SHALL fail with an integrity error.
 *
 * Validates: Requirements 7.3
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    DerivedKey key;
    uint8_t plaintext[64];
    size_t pt_len;
    uint8_t ciphertext[64];
    size_t ct_len;
    uint8_t nonce[ENC_NONCE_SIZE];
    uint8_t tag[ENC_TAG_SIZE];
    size_t flip_byte;   /* Which byte to flip */
    uint8_t flip_bit;   /* Which bit within that byte */
    bool flip_in_tag;   /* true = flip in tag, false = flip in ciphertext */
} TamperInput;

static theft_trial_res tamper_alloc(theft *t, void *env, void **output)
{
    (void)env;
    TamperInput *input = (TamperInput *)calloc(1, sizeof(TamperInput));
    if (!input) return THEFT_TRIAL_ERROR;

    /* Generate key and plaintext */
    make_test_key(t, &input->key);
    input->pt_len = 8 + (size_t)theft_random_choice(t, 56);
    theft_random_bytes(t, input->plaintext, input->pt_len);

    /* Encrypt to get valid ciphertext + tag */
    EncResult res = enc_encrypt(&input->key, input->plaintext, input->pt_len,
                                input->ciphertext, &input->ct_len,
                                input->nonce, input->tag);
    if (res != ENC_OK) {
        free(input);
        return THEFT_TRIAL_ERROR;
    }

    /* Decide where to flip: in ciphertext or in tag */
    size_t total_bytes = input->ct_len + ENC_TAG_SIZE;
    size_t flip_pos = (size_t)theft_random_choice(t, total_bytes);

    if (flip_pos < input->ct_len) {
        input->flip_in_tag = false;
        input->flip_byte = flip_pos;
    } else {
        input->flip_in_tag = true;
        input->flip_byte = flip_pos - input->ct_len;
    }
    input->flip_bit = (uint8_t)theft_random_choice(t, 8);

    *output = input;
    return THEFT_TRIAL_PASS;
}

static void tamper_free(void *instance, void *env)
{
    (void)env;
    free(instance);
}

static void tamper_print(FILE *f, const void *instance, void *env)
{
    (void)env;
    const TamperInput *input = (const TamperInput *)instance;
    fprintf(f, "pt_len=%zu, flip_%s[%zu] bit %u",
            input->pt_len,
            input->flip_in_tag ? "tag" : "ct",
            input->flip_byte, input->flip_bit);
}

/* Feature: cross-platform-password-manager, Property 13: Tamper Detection */
static theft_trial_res prop_tamper_detection(theft *t, void *arg1)
{
    (void)t;
    TamperInput *input = (TamperInput *)arg1;

    /* Make copies of ciphertext and tag so we can tamper */
    uint8_t tampered_ct[64];
    uint8_t tampered_tag[ENC_TAG_SIZE];
    memcpy(tampered_ct, input->ciphertext, input->ct_len);
    memcpy(tampered_tag, input->tag, ENC_TAG_SIZE);

    /* Flip the chosen bit */
    if (input->flip_in_tag) {
        tampered_tag[input->flip_byte] ^= (1 << input->flip_bit);
    } else {
        tampered_ct[input->flip_byte] ^= (1 << input->flip_bit);
    }

    /* Attempt decryption with tampered data */
    uint8_t decrypted[64];
    size_t dec_len = 0;

    EncResult res = enc_decrypt(&input->key, tampered_ct, input->ct_len,
                                input->nonce, tampered_tag,
                                decrypted, &dec_len);

    /* Must fail with integrity error */
    if (res != ENC_ERR_INTEGRITY_FAILED) {
        return THEFT_TRIAL_FAIL;
    }

    return THEFT_TRIAL_PASS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test Runner
 * ═══════════════════════════════════════════════════════════════════════════ */

static theft_type_info roundtrip_type = {
    .alloc = roundtrip_alloc,
    .free  = roundtrip_free,
    .print = roundtrip_print,
    .hash  = NULL,
    .shrink = NULL
};

static theft_type_info conceal_type = {
    .alloc = conceal_alloc,
    .free  = conceal_free,
    .print = conceal_print,
    .hash  = NULL,
    .shrink = NULL
};

static theft_type_info wrong_pw_type = {
    .alloc = wrong_pw_alloc,
    .free  = wrong_pw_free,
    .print = wrong_pw_print,
    .hash  = NULL,
    .shrink = NULL
};

static theft_type_info secure_zero_type = {
    .alloc = secure_zero_alloc,
    .free  = secure_zero_free,
    .print = secure_zero_print,
    .hash  = NULL,
    .shrink = NULL
};

static theft_type_info tamper_type = {
    .alloc = tamper_alloc,
    .free  = tamper_free,
    .print = tamper_print,
    .hash  = NULL,
    .shrink = NULL
};

int run_encryption_tests(void)
{
    int failures = 0;
    theft_run_res res;

    printf("=== Encryption Property Tests ===\n\n");

    /* Property 1: Vault Serialization Round-Trip */
    {
        theft_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.name = "Vault Serialization Round-Trip";
        cfg.fun = (void *)prop_vault_roundtrip;
        cfg.type_info[0] = &roundtrip_type;
        cfg.trials = 100;
        cfg.seed = 12345;

        res = theft_run(&cfg);
        if (res != THEFT_RUN_PASS) {
            printf("  FAILED: Property 1 - Vault Serialization Round-Trip\n");
            failures++;
        } else {
            printf("  PASSED: Property 1 - Vault Serialization Round-Trip\n");
        }
    }

    /* Property 2: Encryption Conceals Plaintext */
    {
        theft_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.name = "Encryption Conceals Plaintext";
        cfg.fun = (void *)prop_encryption_conceals;
        cfg.type_info[0] = &conceal_type;
        cfg.trials = 100;
        cfg.seed = 23456;

        res = theft_run(&cfg);
        if (res != THEFT_RUN_PASS) {
            printf("  FAILED: Property 2 - Encryption Conceals Plaintext\n");
            failures++;
        } else {
            printf("  PASSED: Property 2 - Encryption Conceals Plaintext\n");
        }
    }

    /* Property 3: Wrong Password Rejection */
    {
        theft_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.name = "Wrong Password Rejection";
        cfg.fun = (void *)prop_wrong_password;
        cfg.type_info[0] = &wrong_pw_type;
        cfg.trials = 100;
        cfg.seed = 34567;

        res = theft_run(&cfg);
        if (res != THEFT_RUN_PASS) {
            printf("  FAILED: Property 3 - Wrong Password Rejection\n");
            failures++;
        } else {
            printf("  PASSED: Property 3 - Wrong Password Rejection\n");
        }
    }

    /* Property 4: Secure Memory Clearing */
    {
        theft_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.name = "Secure Memory Clearing";
        cfg.fun = (void *)prop_secure_zero;
        cfg.type_info[0] = &secure_zero_type;
        cfg.trials = 100;
        cfg.seed = 45678;

        res = theft_run(&cfg);
        if (res != THEFT_RUN_PASS) {
            printf("  FAILED: Property 4 - Secure Memory Clearing\n");
            failures++;
        } else {
            printf("  PASSED: Property 4 - Secure Memory Clearing\n");
        }
    }

    /* Property 13: Tamper Detection */
    {
        theft_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.name = "Tamper Detection";
        cfg.fun = (void *)prop_tamper_detection;
        cfg.type_info[0] = &tamper_type;
        cfg.trials = 100;
        cfg.seed = 56789;

        res = theft_run(&cfg);
        if (res != THEFT_RUN_PASS) {
            printf("  FAILED: Property 13 - Tamper Detection\n");
            failures++;
        } else {
            printf("  PASSED: Property 13 - Tamper Detection\n");
        }
    }

    printf("\n=== Encryption Tests: %d failures ===\n", failures);
    return failures;
}

/* Stand-alone main for running just encryption tests */
#ifndef TEST_NO_MAIN
int main(void)
{
    return run_encryption_tests() == 0 ? 0 : 1;
}
#endif
