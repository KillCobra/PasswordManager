/**
 * test_credentials.c - Property-based tests for credential manager
 *
 * Properties tested:
 *   6: Credential Field Validation
 *   7: Search Correctness
 *   8: Edit Persistence
 *   9: Deletion Removes Credential
 *  10: Alphabetical Sort Invariant
 *  12: Clipboard Auto-Clear Timer
 *
 * Uses the vendored theft library for property-based testing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#include "credential.h"
#include "platform.h"
#include "theft.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Note: Clipboard tests exercise clip_copy/clip_tick/clip_clear logic
 * directly. The platform_clipboard_set/clear calls go through the real
 * platform layer (which is a no-op in test context on some systems).
 * ═══════════════════════════════════════════════════════════════════════════ */

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
 * Helper: Case-insensitive substring check (mirrors credential.c logic)
 * ═══════════════════════════════════════════════════════════════════════════ */

static bool ci_contains(const char *haystack, const char *needle)
{
    if (!needle || !needle[0]) return true;
    if (!haystack) return false;

    size_t hay_len = strlen(haystack);
    size_t nee_len = strlen(needle);

    if (nee_len > hay_len) return false;

    for (size_t i = 0; i <= hay_len - nee_len; i++) {
        bool match = true;
        for (size_t j = 0; j < nee_len; j++) {
            if (tolower((unsigned char)haystack[i + j]) !=
                tolower((unsigned char)needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper: Case-insensitive string compare for sort verification
 * ═══════════════════════════════════════════════════════════════════════════ */

static int ci_strcmp(const char *a, const char *b)
{
    while (*a && *b) {
        int ca = tolower((unsigned char)*a);
        int cb = tolower((unsigned char)*b);
        if (ca != cb) return ca - cb;
        a++;
        b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper: Create and initialize a vault
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

/* ═══════════════════════════════════════════════════════════════════════════
 * Property 6: Credential Field Validation
 * Feature: cross-platform-password-manager, Property 6: Credential Field Validation
 *
 * Valid lengths (URL [1,2048], username [1,256], password [1,256]) succeed.
 * Invalid lengths (empty or exceeding max) fail validation.
 *
 * Validates: Requirements 2.1, 2.6
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    char url[2050];
    char username[258];
    char password[258];
    size_t url_len;
    size_t user_len;
    size_t pass_len;
    bool expect_valid;
} ValidationInput;

static theft_trial_res validation_alloc(theft *t, void *env, void **output)
{
    (void)env;
    ValidationInput *input = (ValidationInput *)calloc(1, sizeof(ValidationInput));
    if (!input) return THEFT_TRIAL_ERROR;

    /* 50% chance of generating valid input, 50% invalid */
    bool make_valid = (theft_random_choice(t, 2) == 0);

    if (make_valid) {
        /* Generate valid lengths */
        input->url_len = 1 + (size_t)theft_random_choice(t, 128); /* Keep reasonable for speed */
        input->user_len = 1 + (size_t)theft_random_choice(t, 64);
        input->pass_len = 1 + (size_t)theft_random_choice(t, 64);
        input->expect_valid = true;
    } else {
        /* Generate at least one invalid field */
        uint32_t which = (uint32_t)theft_random_choice(t, 6);
        switch (which) {
            case 0: /* Empty URL */
                input->url_len = 0;
                input->user_len = 1 + (size_t)theft_random_choice(t, 32);
                input->pass_len = 1 + (size_t)theft_random_choice(t, 32);
                break;
            case 1: /* URL too long */
                input->url_len = MAX_URL_LEN + 1;
                input->user_len = 1 + (size_t)theft_random_choice(t, 32);
                input->pass_len = 1 + (size_t)theft_random_choice(t, 32);
                break;
            case 2: /* Empty username */
                input->url_len = 1 + (size_t)theft_random_choice(t, 32);
                input->user_len = 0;
                input->pass_len = 1 + (size_t)theft_random_choice(t, 32);
                break;
            case 3: /* Username too long */
                input->url_len = 1 + (size_t)theft_random_choice(t, 32);
                input->user_len = MAX_USERNAME_LEN + 1;
                input->pass_len = 1 + (size_t)theft_random_choice(t, 32);
                break;
            case 4: /* Empty password */
                input->url_len = 1 + (size_t)theft_random_choice(t, 32);
                input->user_len = 1 + (size_t)theft_random_choice(t, 32);
                input->pass_len = 0;
                break;
            case 5: /* Password too long */
                input->url_len = 1 + (size_t)theft_random_choice(t, 32);
                input->user_len = 1 + (size_t)theft_random_choice(t, 32);
                input->pass_len = MAX_PASSWORD_LEN + 1;
                break;
        }
        input->expect_valid = false;
    }

    /* Fill strings with printable chars */
    if (input->url_len > 0) gen_printable_string(t, input->url, input->url_len);
    else input->url[0] = '\0';

    if (input->user_len > 0) gen_printable_string(t, input->username, input->user_len);
    else input->username[0] = '\0';

    if (input->pass_len > 0) gen_printable_string(t, input->password, input->pass_len);
    else input->password[0] = '\0';

    *output = input;
    return THEFT_TRIAL_PASS;
}

static void validation_free(void *instance, void *env)
{
    (void)env;
    free(instance);
}

static void validation_print(FILE *f, const void *instance, void *env)
{
    (void)env;
    const ValidationInput *input = (const ValidationInput *)instance;
    fprintf(f, "url_len=%zu user_len=%zu pass_len=%zu expect_valid=%s",
            input->url_len, input->user_len, input->pass_len,
            input->expect_valid ? "true" : "false");
}

/* Feature: cross-platform-password-manager, Property 6: Credential Field Validation */
static theft_trial_res prop_credential_validation(theft *t, void *arg1)
{
    (void)t;
    ValidationInput *input = (ValidationInput *)arg1;

    char error_msg[256] = {0};
    bool result = cred_validate(
        input->url_len > 0 ? input->url : NULL,
        input->user_len > 0 ? input->username : NULL,
        input->pass_len > 0 ? input->password : NULL,
        error_msg, sizeof(error_msg));

    if (result != input->expect_valid) {
        return THEFT_TRIAL_FAIL;
    }

    return THEFT_TRIAL_PASS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Property 7: Search Correctness
 * Feature: cross-platform-password-manager, Property 7: Search Correctness
 *
 * For any vault and search term, cred_search returns exactly those entries
 * whose URL contains the term as a case-insensitive substring.
 *
 * Validates: Requirements 2.2
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    Vault *vault;
    char query[32];
} SearchInput;

static theft_trial_res search_alloc(theft *t, void *env, void **output)
{
    (void)env;
    SearchInput *input = (SearchInput *)calloc(1, sizeof(SearchInput));
    if (!input) return THEFT_TRIAL_ERROR;

    /* Create vault with 2-20 credentials */
    uint32_t count = 2 + (uint32_t)theft_random_choice(t, 18);
    input->vault = create_test_vault(count);
    if (!input->vault) { free(input); return THEFT_TRIAL_ERROR; }

    for (uint32_t i = 0; i < count; i++) {
        Credential *c = &input->vault->entries[i];
        c->id = i + 1;
        size_t url_len = 4 + (size_t)theft_random_choice(t, 28);
        size_t user_len = 2 + (size_t)theft_random_choice(t, 16);
        size_t pass_len = 2 + (size_t)theft_random_choice(t, 16);
        gen_printable_string(t, c->url, url_len);
        gen_printable_string(t, c->username, user_len);
        gen_printable_string(t, c->password, pass_len);
        c->created_at = 1000000 + i;
        c->modified_at = 1000000 + i;
        c->deleted = false;
    }
    input->vault->count = count;

    /* Mark some as deleted (0-3 entries) */
    uint32_t del_count = (uint32_t)theft_random_choice(t, 4);
    for (uint32_t i = 0; i < del_count && i < count; i++) {
        uint32_t idx = (uint32_t)theft_random_choice(t, count);
        input->vault->entries[idx].deleted = true;
    }

    /* Generate a short search query (1-6 chars) */
    size_t qlen = 1 + (size_t)theft_random_choice(t, 5);
    gen_printable_string(t, input->query, qlen);

    *output = input;
    return THEFT_TRIAL_PASS;
}

static void search_free(void *instance, void *env)
{
    (void)env;
    SearchInput *input = (SearchInput *)instance;
    if (input) {
        free_test_vault(input->vault);
        free(input);
    }
}

static void search_print(FILE *f, const void *instance, void *env)
{
    (void)env;
    const SearchInput *input = (const SearchInput *)instance;
    fprintf(f, "vault_count=%u query='%s'", input->vault->count, input->query);
}

/* Feature: cross-platform-password-manager, Property 7: Search Correctness */
static theft_trial_res prop_search_correctness(theft *t, void *arg1)
{
    (void)t;
    SearchInput *input = (SearchInput *)arg1;

    /* Run the search */
    Credential *results = NULL;
    uint32_t result_count = 0;
    CredResult res = cred_search(input->vault, input->query, &results, &result_count);
    if (res != CRED_OK) {
        return THEFT_TRIAL_ERROR;
    }

    /* Manually compute expected matches */
    uint32_t expected_count = 0;
    for (uint32_t i = 0; i < input->vault->count; i++) {
        if (!input->vault->entries[i].deleted &&
            ci_contains(input->vault->entries[i].url, input->query)) {
            expected_count++;
        }
    }

    /* Verify count matches */
    if (result_count != expected_count) {
        free(results);
        return THEFT_TRIAL_FAIL;
    }

    /* Verify each result actually matches */
    for (uint32_t i = 0; i < result_count; i++) {
        if (!ci_contains(results[i].url, input->query)) {
            free(results);
            return THEFT_TRIAL_FAIL;
        }
        /* Verify not deleted */
        if (results[i].deleted) {
            free(results);
            return THEFT_TRIAL_FAIL;
        }
    }

    free(results);
    return THEFT_TRIAL_PASS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Property 8: Edit Persistence
 * Feature: cross-platform-password-manager, Property 8: Edit Persistence
 *
 * After editing a credential with new values, retrieving by ID returns
 * the new values with an updated modified_at timestamp.
 *
 * Validates: Requirements 2.3
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    Vault *vault;
    uint32_t edit_id;
    char new_url[65];
    char new_username[33];
    char new_password[33];
} EditInput;

static theft_trial_res edit_alloc(theft *t, void *env, void **output)
{
    (void)env;
    EditInput *input = (EditInput *)calloc(1, sizeof(EditInput));
    if (!input) return THEFT_TRIAL_ERROR;

    /* Create vault with 3-10 credentials */
    uint32_t count = 3 + (uint32_t)theft_random_choice(t, 7);
    input->vault = create_test_vault(count);
    if (!input->vault) { free(input); return THEFT_TRIAL_ERROR; }

    for (uint32_t i = 0; i < count; i++) {
        Credential *c = &input->vault->entries[i];
        c->id = i + 1;
        gen_printable_string(t, c->url, 4 + (size_t)theft_random_choice(t, 20));
        gen_printable_string(t, c->username, 2 + (size_t)theft_random_choice(t, 10));
        gen_printable_string(t, c->password, 2 + (size_t)theft_random_choice(t, 10));
        c->created_at = 1000000;
        c->modified_at = 1000000;
        c->deleted = false;
    }
    input->vault->count = count;

    /* Pick a random credential to edit */
    input->edit_id = 1 + (uint32_t)theft_random_choice(t, count);

    /* Generate new values */
    gen_printable_string(t, input->new_url, 4 + (size_t)theft_random_choice(t, 20));
    gen_printable_string(t, input->new_username, 2 + (size_t)theft_random_choice(t, 10));
    gen_printable_string(t, input->new_password, 2 + (size_t)theft_random_choice(t, 10));

    *output = input;
    return THEFT_TRIAL_PASS;
}

static void edit_free(void *instance, void *env)
{
    (void)env;
    EditInput *input = (EditInput *)instance;
    if (input) {
        free_test_vault(input->vault);
        free(input);
    }
}

static void edit_print(FILE *f, const void *instance, void *env)
{
    (void)env;
    const EditInput *input = (const EditInput *)instance;
    fprintf(f, "vault_count=%u edit_id=%u new_url='%s'",
            input->vault->count, input->edit_id, input->new_url);
}

/* Feature: cross-platform-password-manager, Property 8: Edit Persistence */
static theft_trial_res prop_edit_persistence(theft *t, void *arg1)
{
    (void)t;
    EditInput *input = (EditInput *)arg1;

    /* Get the original modified_at */
    Credential *orig = cred_get(input->vault, input->edit_id);
    if (!orig) return THEFT_TRIAL_ERROR;
    uint64_t orig_modified = orig->modified_at;

    /* Edit the credential */
    CredResult res = cred_edit(input->vault, input->edit_id,
                               input->new_url, input->new_username,
                               input->new_password);
    if (res != CRED_OK) {
        return THEFT_TRIAL_FAIL;
    }

    /* Retrieve and verify */
    Credential *edited = cred_get(input->vault, input->edit_id);
    if (!edited) return THEFT_TRIAL_FAIL;

    if (strcmp(edited->url, input->new_url) != 0 ||
        strcmp(edited->username, input->new_username) != 0 ||
        strcmp(edited->password, input->new_password) != 0) {
        return THEFT_TRIAL_FAIL;
    }

    /* modified_at should be >= original (platform_time_unix may return same value) */
    if (edited->modified_at < orig_modified) {
        return THEFT_TRIAL_FAIL;
    }

    return THEFT_TRIAL_PASS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Property 9: Deletion Removes Credential
 * Feature: cross-platform-password-manager, Property 9: Deletion Removes Credential
 *
 * After deleting a credential, it does not appear in search results
 * or via cred_get.
 *
 * Validates: Requirements 2.4
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    Vault *vault;
    uint32_t delete_id;
} DeleteInput;

static theft_trial_res delete_alloc(theft *t, void *env, void **output)
{
    (void)env;
    DeleteInput *input = (DeleteInput *)calloc(1, sizeof(DeleteInput));
    if (!input) return THEFT_TRIAL_ERROR;

    /* Create vault with 3-15 credentials */
    uint32_t count = 3 + (uint32_t)theft_random_choice(t, 12);
    input->vault = create_test_vault(count);
    if (!input->vault) { free(input); return THEFT_TRIAL_ERROR; }

    for (uint32_t i = 0; i < count; i++) {
        Credential *c = &input->vault->entries[i];
        c->id = i + 1;
        gen_printable_string(t, c->url, 4 + (size_t)theft_random_choice(t, 20));
        gen_printable_string(t, c->username, 2 + (size_t)theft_random_choice(t, 10));
        gen_printable_string(t, c->password, 2 + (size_t)theft_random_choice(t, 10));
        c->created_at = 1000000;
        c->modified_at = 1000000;
        c->deleted = false;
    }
    input->vault->count = count;

    /* Pick a random credential to delete */
    input->delete_id = 1 + (uint32_t)theft_random_choice(t, count);

    *output = input;
    return THEFT_TRIAL_PASS;
}

static void delete_free(void *instance, void *env)
{
    (void)env;
    DeleteInput *input = (DeleteInput *)instance;
    if (input) {
        free_test_vault(input->vault);
        free(input);
    }
}

static void delete_print(FILE *f, const void *instance, void *env)
{
    (void)env;
    const DeleteInput *input = (const DeleteInput *)instance;
    fprintf(f, "vault_count=%u delete_id=%u", input->vault->count, input->delete_id);
}

/* Feature: cross-platform-password-manager, Property 9: Deletion Removes Credential */
static theft_trial_res prop_deletion_removes(theft *t, void *arg1)
{
    (void)t;
    DeleteInput *input = (DeleteInput *)arg1;

    /* Get the URL of the credential we're about to delete (for search test) */
    Credential *target = cred_get(input->vault, input->delete_id);
    if (!target) return THEFT_TRIAL_ERROR;
    char target_url[MAX_URL_LEN + 1];
    strncpy(target_url, target->url, MAX_URL_LEN);
    target_url[MAX_URL_LEN] = '\0';

    /* Delete the credential */
    CredResult res = cred_delete(input->vault, input->delete_id);
    if (res != CRED_OK) {
        return THEFT_TRIAL_FAIL;
    }

    /* Verify cred_get returns NULL for deleted credential */
    if (cred_get(input->vault, input->delete_id) != NULL) {
        return THEFT_TRIAL_FAIL;
    }

    /* Verify search does not return the deleted credential */
    Credential *results = NULL;
    uint32_t result_count = 0;
    res = cred_search(input->vault, target_url, &results, &result_count);
    if (res != CRED_OK) {
        return THEFT_TRIAL_ERROR;
    }

    /* Check that deleted ID is not in results */
    for (uint32_t i = 0; i < result_count; i++) {
        if (results[i].id == input->delete_id) {
            free(results);
            return THEFT_TRIAL_FAIL;
        }
    }

    free(results);
    return THEFT_TRIAL_PASS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Property 10: Alphabetical Sort Invariant
 * Feature: cross-platform-password-manager, Property 10: Alphabetical Sort Invariant
 *
 * After sorting, for every consecutive pair entry[i].url <= entry[i+1].url
 * (case-insensitive comparison).
 *
 * Validates: Requirements 2.5
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    Vault *vault;
} SortInput;

static theft_trial_res sort_alloc(theft *t, void *env, void **output)
{
    (void)env;
    SortInput *input = (SortInput *)calloc(1, sizeof(SortInput));
    if (!input) return THEFT_TRIAL_ERROR;

    /* Create vault with 2-30 credentials */
    uint32_t count = 2 + (uint32_t)theft_random_choice(t, 28);
    input->vault = create_test_vault(count);
    if (!input->vault) { free(input); return THEFT_TRIAL_ERROR; }

    for (uint32_t i = 0; i < count; i++) {
        Credential *c = &input->vault->entries[i];
        c->id = i + 1;
        /* Generate URLs with mixed case to test case-insensitive sort */
        size_t url_len = 3 + (size_t)theft_random_choice(t, 20);
        for (size_t j = 0; j < url_len; j++) {
            /* Mix of upper and lower case letters */
            if (theft_random_choice(t, 2) == 0) {
                c->url[j] = (char)('A' + theft_random_choice(t, 26));
            } else {
                c->url[j] = (char)('a' + theft_random_choice(t, 26));
            }
        }
        c->url[url_len] = '\0';
        gen_printable_string(t, c->username, 2 + (size_t)theft_random_choice(t, 8));
        gen_printable_string(t, c->password, 2 + (size_t)theft_random_choice(t, 8));
        c->deleted = false;
    }
    input->vault->count = count;

    *output = input;
    return THEFT_TRIAL_PASS;
}

static void sort_free(void *instance, void *env)
{
    (void)env;
    SortInput *input = (SortInput *)instance;
    if (input) {
        free_test_vault(input->vault);
        free(input);
    }
}

static void sort_print(FILE *f, const void *instance, void *env)
{
    (void)env;
    const SortInput *input = (const SortInput *)instance;
    fprintf(f, "vault_count=%u", input->vault->count);
}

/* Feature: cross-platform-password-manager, Property 10: Alphabetical Sort Invariant */
static theft_trial_res prop_sort_invariant(theft *t, void *arg1)
{
    (void)t;
    SortInput *input = (SortInput *)arg1;

    /* Sort the vault */
    cred_sort_by_url(input->vault);

    /* Verify sorted order */
    for (uint32_t i = 0; i + 1 < input->vault->count; i++) {
        if (ci_strcmp(input->vault->entries[i].url,
                      input->vault->entries[i + 1].url) > 0) {
            return THEFT_TRIAL_FAIL;
        }
    }

    return THEFT_TRIAL_PASS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Property 12: Clipboard Auto-Clear Timer
 * Feature: cross-platform-password-manager, Property 12: Clipboard Auto-Clear Timer
 *
 * After clip_copy, the clipboard is cleared exactly 30 ticks later.
 * A new copy resets the countdown to 30.
 *
 * Validates: Requirements 3.3, 3.4
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint32_t ticks_before_second_copy;  /* 0 means no second copy */
    uint32_t ticks_after_second_copy;   /* Additional ticks after second copy */
    bool do_second_copy;
} ClipboardInput;

static theft_trial_res clipboard_alloc(theft *t, void *env, void **output)
{
    (void)env;
    ClipboardInput *input = (ClipboardInput *)calloc(1, sizeof(ClipboardInput));
    if (!input) return THEFT_TRIAL_ERROR;

    input->do_second_copy = (theft_random_choice(t, 2) == 0);
    input->ticks_before_second_copy = (uint32_t)theft_random_choice(t, 29); /* 0-28 ticks */
    input->ticks_after_second_copy = (uint32_t)theft_random_choice(t, 35);  /* 0-34 ticks */

    *output = input;
    return THEFT_TRIAL_PASS;
}

static void clipboard_free(void *instance, void *env)
{
    (void)env;
    free(instance);
}

static void clipboard_print(FILE *f, const void *instance, void *env)
{
    (void)env;
    const ClipboardInput *input = (const ClipboardInput *)instance;
    fprintf(f, "second_copy=%s ticks_before=%u ticks_after=%u",
            input->do_second_copy ? "yes" : "no",
            input->ticks_before_second_copy,
            input->ticks_after_second_copy);
}

/* Feature: cross-platform-password-manager, Property 12: Clipboard Auto-Clear Timer */
static theft_trial_res prop_clipboard_timer(theft *t, void *arg1)
{
    (void)t;
    ClipboardInput *input = (ClipboardInput *)arg1;

    /* First copy */
    ClipResult cr = clip_copy("test_password", 13);
    if (cr != CLIP_OK) return THEFT_TRIAL_ERROR;

    /* Verify countdown starts at 30 */
    if (clip_get_remaining_seconds() != 30) {
        return THEFT_TRIAL_FAIL;
    }

    if (input->do_second_copy) {
        /* Tick some amount before second copy */
        for (uint32_t i = 0; i < input->ticks_before_second_copy; i++) {
            clip_tick();
        }

        /* Verify countdown decreased correctly */
        uint32_t expected_remaining = 30 - input->ticks_before_second_copy;
        if (expected_remaining > 0) {
            if (clip_get_remaining_seconds() != expected_remaining) {
                return THEFT_TRIAL_FAIL;
            }
        }

        /* Second copy resets timer */
        cr = clip_copy("another_password", 16);
        if (cr != CLIP_OK) return THEFT_TRIAL_ERROR;

        /* Timer should be reset to 30 */
        if (clip_get_remaining_seconds() != 30) {
            return THEFT_TRIAL_FAIL;
        }

        /* Tick after second copy */
        for (uint32_t i = 0; i < input->ticks_after_second_copy; i++) {
            clip_tick();
        }

        /* Verify final state */
        if (input->ticks_after_second_copy >= 30) {
            /* Should have cleared */
            if (clip_get_remaining_seconds() != 0) {
                return THEFT_TRIAL_FAIL;
            }
        } else {
            uint32_t expected = 30 - input->ticks_after_second_copy;
            if (clip_get_remaining_seconds() != expected) {
                return THEFT_TRIAL_FAIL;
            }
        }
    } else {
        /* No second copy - just tick 30 times and verify clear */
        for (uint32_t i = 0; i < 30; i++) {
            clip_tick();
        }
        if (clip_get_remaining_seconds() != 0) {
            return THEFT_TRIAL_FAIL;
        }
    }

    /* Reset clipboard state for next trial */
    clip_clear();

    return THEFT_TRIAL_PASS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test Runner
 * ═══════════════════════════════════════════════════════════════════════════ */

static theft_type_info validation_type = {
    .alloc = validation_alloc,
    .free  = validation_free,
    .print = validation_print,
    .hash  = NULL,
    .shrink = NULL
};

static theft_type_info search_type = {
    .alloc = search_alloc,
    .free  = search_free,
    .print = search_print,
    .hash  = NULL,
    .shrink = NULL
};

static theft_type_info edit_type = {
    .alloc = edit_alloc,
    .free  = edit_free,
    .print = edit_print,
    .hash  = NULL,
    .shrink = NULL
};

static theft_type_info delete_type = {
    .alloc = delete_alloc,
    .free  = delete_free,
    .print = delete_print,
    .hash  = NULL,
    .shrink = NULL
};

static theft_type_info sort_type = {
    .alloc = sort_alloc,
    .free  = sort_free,
    .print = sort_print,
    .hash  = NULL,
    .shrink = NULL
};

static theft_type_info clipboard_type = {
    .alloc = clipboard_alloc,
    .free  = clipboard_free,
    .print = clipboard_print,
    .hash  = NULL,
    .shrink = NULL
};

int run_credential_tests(void)
{
    int failures = 0;
    theft_run_res res;

    printf("=== Credential Property Tests ===\n\n");

    /* Property 6: Credential Field Validation */
    {
        theft_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.name = "Credential Field Validation";
        cfg.fun = (void *)prop_credential_validation;
        cfg.type_info[0] = &validation_type;
        cfg.trials = 100;
        cfg.seed = 60001;

        res = theft_run(&cfg);
        if (res != THEFT_RUN_PASS) {
            printf("  FAILED: Property 6 - Credential Field Validation\n");
            failures++;
        } else {
            printf("  PASSED: Property 6 - Credential Field Validation\n");
        }
    }

    /* Property 7: Search Correctness */
    {
        theft_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.name = "Search Correctness";
        cfg.fun = (void *)prop_search_correctness;
        cfg.type_info[0] = &search_type;
        cfg.trials = 100;
        cfg.seed = 70001;

        res = theft_run(&cfg);
        if (res != THEFT_RUN_PASS) {
            printf("  FAILED: Property 7 - Search Correctness\n");
            failures++;
        } else {
            printf("  PASSED: Property 7 - Search Correctness\n");
        }
    }

    /* Property 8: Edit Persistence */
    {
        theft_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.name = "Edit Persistence";
        cfg.fun = (void *)prop_edit_persistence;
        cfg.type_info[0] = &edit_type;
        cfg.trials = 100;
        cfg.seed = 80001;

        res = theft_run(&cfg);
        if (res != THEFT_RUN_PASS) {
            printf("  FAILED: Property 8 - Edit Persistence\n");
            failures++;
        } else {
            printf("  PASSED: Property 8 - Edit Persistence\n");
        }
    }

    /* Property 9: Deletion Removes Credential */
    {
        theft_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.name = "Deletion Removes Credential";
        cfg.fun = (void *)prop_deletion_removes;
        cfg.type_info[0] = &delete_type;
        cfg.trials = 100;
        cfg.seed = 90001;

        res = theft_run(&cfg);
        if (res != THEFT_RUN_PASS) {
            printf("  FAILED: Property 9 - Deletion Removes Credential\n");
            failures++;
        } else {
            printf("  PASSED: Property 9 - Deletion Removes Credential\n");
        }
    }

    /* Property 10: Alphabetical Sort Invariant */
    {
        theft_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.name = "Alphabetical Sort Invariant";
        cfg.fun = (void *)prop_sort_invariant;
        cfg.type_info[0] = &sort_type;
        cfg.trials = 100;
        cfg.seed = 100001;

        res = theft_run(&cfg);
        if (res != THEFT_RUN_PASS) {
            printf("  FAILED: Property 10 - Alphabetical Sort Invariant\n");
            failures++;
        } else {
            printf("  PASSED: Property 10 - Alphabetical Sort Invariant\n");
        }
    }

    /* Property 12: Clipboard Auto-Clear Timer */
    {
        theft_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.name = "Clipboard Auto-Clear Timer";
        cfg.fun = (void *)prop_clipboard_timer;
        cfg.type_info[0] = &clipboard_type;
        cfg.trials = 100;
        cfg.seed = 120001;

        res = theft_run(&cfg);
        if (res != THEFT_RUN_PASS) {
            printf("  FAILED: Property 12 - Clipboard Auto-Clear Timer\n");
            failures++;
        } else {
            printf("  PASSED: Property 12 - Clipboard Auto-Clear Timer\n");
        }
    }

    printf("\n=== Credential Tests: %d failures ===\n", failures);
    return failures;
}

/* Stand-alone main for running just credential tests */
#ifndef TEST_NO_MAIN
int main(void)
{
    return run_credential_tests() == 0 ? 0 : 1;
}
#endif
