/**
 * test_sync.c - Property-based tests for sync engine
 *
 * Properties tested:
 *  14: Sync Merge Correctness (content-based matching by URL+username)
 *
 * Uses the vendored theft library for property-based testing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "sync.h"
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
 * Helper: Create a test vault
 * ═══════════════════════════════════════════════════════════════════════════ */

static Vault* create_test_vault(uint32_t capacity)
{
    Vault *vault = (Vault *)calloc(1, sizeof(Vault));
    if (!vault) return NULL;
    if (capacity > 0) {
        vault->entries = (Credential *)calloc(capacity, sizeof(Credential));
        if (!vault->entries) { free(vault); return NULL; }
    }
    vault->count = 0;
    vault->capacity = capacity;
    vault->is_dirty = false;
    return vault;
}

static void free_test_vault(Vault *vault)
{
    if (vault) {
        free(vault->entries);
        free(vault);
    }
}

/* Helper: find credential by URL+username in vault */
static Credential* find_by_content(Vault *vault, const char *url, const char *username)
{
    for (uint32_t i = 0; i < vault->count; i++) {
        if (strcmp(vault->entries[i].url, url) == 0 &&
            strcmp(vault->entries[i].username, username) == 0) {
            return &vault->entries[i];
        }
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Property 14: Sync Merge Correctness
 * Feature: cross-platform-password-manager, Property 14: Sync Merge Correctness
 *
 * Tests:
 *   (a) Unique remote entries (different URL+username) are added to local
 *   (b) Overlapping entries: newer modified_at wins
 *   (c) Identical timestamps: initiator wins
 *   (d) All original local entries are preserved
 *
 * Validates: Requirements 5.4, 5.6
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    Vault *local;
    Vault *remote;
    bool is_initiator;
    uint32_t overlap_count; /* How many remote entries share URL+username with local */
} MergeInput;

static theft_trial_res merge_alloc(theft *t, void *env, void **output)
{
    (void)env;
    MergeInput *input = (MergeInput *)calloc(1, sizeof(MergeInput));
    if (!input) return THEFT_TRIAL_ERROR;

    uint32_t local_count = 2 + (uint32_t)theft_random_choice(t, 5);
    uint32_t remote_count = 2 + (uint32_t)theft_random_choice(t, 5);
    /* Some remote entries will overlap with local (same URL+username) */
    uint32_t overlap = (uint32_t)theft_random_choice(t, (local_count < remote_count ? local_count : remote_count));
    input->overlap_count = overlap;

    uint32_t max_cap = local_count + remote_count;
    input->local = create_test_vault(max_cap);
    input->remote = create_test_vault(remote_count);
    if (!input->local || !input->remote) {
        free_test_vault(input->local);
        free_test_vault(input->remote);
        free(input);
        return THEFT_TRIAL_ERROR;
    }

    /* Populate local vault with unique URL+username combos */
    for (uint32_t i = 0; i < local_count; i++) {
        Credential *c = &input->local->entries[i];
        c->id = i + 1;
        /* Use index in URL to guarantee uniqueness */
        snprintf(c->url, MAX_URL_LEN, "local_%u_", i);
        size_t prefix_len = strlen(c->url);
        gen_printable_string(t, c->url + prefix_len, 4 + (size_t)theft_random_choice(t, 8));
        gen_printable_string(t, c->username, 2 + (size_t)theft_random_choice(t, 8));
        gen_printable_string(t, c->password, 2 + (size_t)theft_random_choice(t, 8));
        c->created_at = 1000000;
        c->modified_at = 1000000 + theft_random_choice(t, 10000);
        c->deleted = false;
    }
    input->local->count = local_count;

    /* Populate remote vault */
    for (uint32_t i = 0; i < remote_count; i++) {
        Credential *c = &input->remote->entries[i];
        c->id = 100 + i; /* Different ID space */

        if (i < overlap) {
            /* This entry overlaps with local[i] — same URL+username, different password/timestamp */
            strcpy(c->url, input->local->entries[i].url);
            strcpy(c->username, input->local->entries[i].username);
            gen_printable_string(t, c->password, 2 + (size_t)theft_random_choice(t, 8));
            c->modified_at = 1000000 + theft_random_choice(t, 10000);
        } else {
            /* Unique remote entry */
            snprintf(c->url, MAX_URL_LEN, "remote_%u_", i);
            size_t prefix_len = strlen(c->url);
            gen_printable_string(t, c->url + prefix_len, 4 + (size_t)theft_random_choice(t, 8));
            gen_printable_string(t, c->username, 2 + (size_t)theft_random_choice(t, 8));
            gen_printable_string(t, c->password, 2 + (size_t)theft_random_choice(t, 8));
            c->modified_at = 1000000 + theft_random_choice(t, 10000);
        }
        c->created_at = 1000000;
        c->deleted = false;
    }
    input->remote->count = remote_count;

    input->is_initiator = (theft_random_choice(t, 2) == 0);

    *output = input;
    return THEFT_TRIAL_PASS;
}

static void merge_free(void *instance, void *env)
{
    (void)env;
    MergeInput *input = (MergeInput *)instance;
    if (input) {
        free_test_vault(input->local);
        free_test_vault(input->remote);
        free(input);
    }
}

static void merge_print(FILE *f, const void *instance, void *env)
{
    (void)env;
    const MergeInput *input = (const MergeInput *)instance;
    fprintf(f, "local_count=%u remote_count=%u overlap=%u initiator=%s",
            input->local->count, input->remote->count, input->overlap_count,
            input->is_initiator ? "yes" : "no");
}

/* Feature: cross-platform-password-manager, Property 14: Sync Merge Correctness */
static theft_trial_res prop_sync_merge(theft *t, void *arg1)
{
    (void)t;
    MergeInput *input = (MergeInput *)arg1;

    /* Snapshot original local entries */
    uint32_t orig_local_count = input->local->count;
    Credential *orig_local = (Credential *)malloc(orig_local_count * sizeof(Credential));
    if (!orig_local && orig_local_count > 0) return THEFT_TRIAL_ERROR;
    if (orig_local_count > 0) {
        memcpy(orig_local, input->local->entries, orig_local_count * sizeof(Credential));
    }

    /* Perform merge */
    SyncSummary summary;
    memset(&summary, 0, sizeof(summary));
    SyncResult res = sync_merge(input->local, input->remote,
                                input->is_initiator, &summary);
    if (res != SYNC_OK) {
        free(orig_local);
        return THEFT_TRIAL_ERROR;
    }

    /* Verify (a): All unique remote entries should now be in local vault */
    for (uint32_t i = 0; i < input->remote->count; i++) {
        const Credential *remote_cred = &input->remote->entries[i];
        if (remote_cred->deleted) continue; /* Deleted remote entries not in local are skipped */

        Credential *merged = find_by_content(input->local,
                                              remote_cred->url, remote_cred->username);
        if (!merged) {
            free(orig_local);
            return THEFT_TRIAL_FAIL; /* Remote entry missing from merged vault */
        }
    }

    /* Verify (d): All original local entries still present (by their original ID) */
    for (uint32_t i = 0; i < orig_local_count; i++) {
        bool found = false;
        for (uint32_t j = 0; j < input->local->count; j++) {
            if (input->local->entries[j].id == orig_local[i].id) {
                found = true;
                break;
            }
        }
        if (!found) {
            free(orig_local);
            return THEFT_TRIAL_FAIL; /* Original local entry was lost */
        }
    }

    /* Verify (b)/(c): For overlapping entries, the correct winner was chosen */
    for (uint32_t i = 0; i < input->overlap_count && i < input->remote->count; i++) {
        const Credential *remote_cred = &input->remote->entries[i];
        Credential *merged = find_by_content(input->local,
                                              remote_cred->url, remote_cred->username);
        if (!merged) {
            free(orig_local);
            return THEFT_TRIAL_FAIL;
        }

        /* Find the original local version */
        Credential *orig = NULL;
        for (uint32_t j = 0; j < orig_local_count; j++) {
            if (strcmp(orig_local[j].url, remote_cred->url) == 0 &&
                strcmp(orig_local[j].username, remote_cred->username) == 0) {
                orig = &orig_local[j];
                break;
            }
        }

        if (orig) {
            bool remote_should_win = false;
            if (remote_cred->modified_at > orig->modified_at) {
                remote_should_win = true;
            } else if (remote_cred->modified_at == orig->modified_at) {
                remote_should_win = !input->is_initiator;
            }

            if (remote_should_win) {
                /* Password should match remote */
                if (strcmp(merged->password, remote_cred->password) != 0) {
                    free(orig_local);
                    return THEFT_TRIAL_FAIL;
                }
            } else {
                /* Password should match original local */
                if (strcmp(merged->password, orig->password) != 0) {
                    free(orig_local);
                    return THEFT_TRIAL_FAIL;
                }
            }
        }
    }

    /* Verify summary.added matches the number of unique remote entries added */
    uint32_t expected_added = 0;
    for (uint32_t i = input->overlap_count; i < input->remote->count; i++) {
        if (!input->remote->entries[i].deleted) {
            expected_added++;
        }
    }
    if (summary.added != expected_added) {
        free(orig_local);
        return THEFT_TRIAL_FAIL;
    }

    free(orig_local);
    return THEFT_TRIAL_PASS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test Runner
 * ═══════════════════════════════════════════════════════════════════════════ */

static theft_type_info merge_type = {
    .alloc = merge_alloc,
    .free  = merge_free,
    .print = merge_print,
    .hash  = NULL,
    .shrink = NULL
};

int run_sync_tests(void)
{
    int failures = 0;
    theft_run_res res;

    printf("=== Sync Property Tests ===\n\n");

    /* Property 14: Sync Merge Correctness */
    {
        theft_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.name = "Sync Merge Correctness";
        cfg.fun = (void *)prop_sync_merge;
        cfg.type_info[0] = &merge_type;
        cfg.trials = 100;
        cfg.seed = 140001;

        res = theft_run(&cfg);
        if (res != THEFT_RUN_PASS) {
            printf("  FAILED: Property 14 - Sync Merge Correctness\n");
            failures++;
        } else {
            printf("  PASSED: Property 14 - Sync Merge Correctness\n");
        }
    }

    printf("\n=== Sync Tests: %d failures ===\n", failures);
    return failures;
}

/* Stand-alone main for running just sync tests */
#ifndef TEST_NO_MAIN
int main(void)
{
    return run_sync_tests() == 0 ? 0 : 1;
}
#endif
