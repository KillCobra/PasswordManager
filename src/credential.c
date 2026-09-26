/**
 * credential.c - Credential Manager Implementation
 *
 * Currently implements:
 * - Master password validation (length check)
 * - Progressive delay on authentication failure
 *
 * Credential CRUD and clipboard functions will be added in subsequent tasks.
 */

#include "credential.h"
#include "platform.h"
#include <string.h>
#include <stdio.h>

/* ─── Static State ────────────────────────────────────────────────────────── */

static uint32_t s_consecutive_failures = 0;

/* ─── Master Password Validation ──────────────────────────────────────────── */

bool master_password_validate(const char *password, size_t len)
{
    if (password == NULL) {
        return false;
    }
    return len >= MASTER_PASSWORD_MIN_LEN;
}

void master_password_record_failure_no_delay(void)
{
    s_consecutive_failures++;
}

uint32_t master_password_get_delay_ms(void)
{
    return s_consecutive_failures * 1000;
}

void master_password_record_failure(void)
{
    /* Increment the counter, then enforce the progressive delay on the
     * calling thread. Kept for callers/tests that rely on the blocking
     * behavior; UI code should prefer the _no_delay variant. */
    master_password_record_failure_no_delay();
    platform_sleep_ms(master_password_get_delay_ms());
}

void master_password_record_success(void)
{
    s_consecutive_failures = 0;
}

uint32_t master_password_get_failure_count(void)
{
    return s_consecutive_failures;
}

void master_password_set_failure_count(uint32_t count)
{
    s_consecutive_failures = count;
}

/* ─── Additional Includes for CRUD and Clipboard ──────────────────────────── */

#include <stdlib.h>
#include <ctype.h>

/* ─── Static State for Clipboard Timer ────────────────────────────────────── */

static uint32_t s_clip_countdown = 0;
static bool s_clip_active = false;

/* ─── Static State for Credential ID Generation ───────────────────────────── */

static uint32_t s_next_id = 1;

/* ─── Helper: Case-insensitive substring search ───────────────────────────── */

static bool ci_strstr(const char *haystack, const char *needle)
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

/* ─── Helper: Case-insensitive string comparison for sorting ──────────────── */

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

/* ─── Credential Validation ───────────────────────────────────────────────── */

bool cred_validate(const char *url, const char *username,
                   const char *password, char *error_msg, size_t msg_len)
{
    if (!url || strlen(url) == 0) {
        if (error_msg && msg_len > 0)
            snprintf(error_msg, msg_len, "URL must not be empty");
        return false;
    }
    if (strlen(url) > MAX_URL_LEN) {
        if (error_msg && msg_len > 0)
            snprintf(error_msg, msg_len, "URL exceeds maximum length of %d characters", MAX_URL_LEN);
        return false;
    }
    if (!username || strlen(username) == 0) {
        if (error_msg && msg_len > 0)
            snprintf(error_msg, msg_len, "Username must not be empty");
        return false;
    }
    if (strlen(username) > MAX_USERNAME_LEN) {
        if (error_msg && msg_len > 0)
            snprintf(error_msg, msg_len, "Username exceeds maximum length of %d characters", MAX_USERNAME_LEN);
        return false;
    }
    if (!password || strlen(password) == 0) {
        if (error_msg && msg_len > 0)
            snprintf(error_msg, msg_len, "Password must not be empty");
        return false;
    }
    if (strlen(password) > MAX_PASSWORD_LEN) {
        if (error_msg && msg_len > 0)
            snprintf(error_msg, msg_len, "Password exceeds maximum length of %d characters", MAX_PASSWORD_LEN);
        return false;
    }
    return true;
}

/* ─── Credential CRUD ─────────────────────────────────────────────────────── */

CredResult cred_add(Vault *vault, const char *url,
                    const char *username, const char *password)
{
    if (!vault) return CRED_ERR_VALIDATION;

    char err[256];
    if (!cred_validate(url, username, password, err, sizeof(err))) {
        return CRED_ERR_VALIDATION;
    }

    if (vault->count >= MAX_CREDENTIALS) {
        return CRED_ERR_VAULT_FULL;
    }

    /* Grow capacity if needed */
    if (vault->count >= vault->capacity) {
        uint32_t new_cap = vault->capacity == 0 ? 16 : vault->capacity * 2;
        if (new_cap > MAX_CREDENTIALS) new_cap = MAX_CREDENTIALS;
        Credential *new_entries = realloc(vault->entries,
                                          new_cap * sizeof(Credential));
        if (!new_entries) return CRED_ERR_VAULT_FULL;
        vault->entries = new_entries;
        vault->capacity = new_cap;
    }

    /* Find max existing ID to ensure uniqueness */
    uint32_t max_id = 0;
    for (uint32_t i = 0; i < vault->count; i++) {
        if (vault->entries[i].id > max_id) {
            max_id = vault->entries[i].id;
        }
    }
    if (s_next_id <= max_id) {
        s_next_id = max_id + 1;
    }

    Credential *cred = &vault->entries[vault->count];
    memset(cred, 0, sizeof(Credential));
    cred->id = s_next_id++;
    strncpy(cred->url, url, MAX_URL_LEN);
    cred->url[MAX_URL_LEN] = '\0';
    strncpy(cred->username, username, MAX_USERNAME_LEN);
    cred->username[MAX_USERNAME_LEN] = '\0';
    strncpy(cred->password, password, MAX_PASSWORD_LEN);
    cred->password[MAX_PASSWORD_LEN] = '\0';
    cred->created_at = platform_time_unix();
    cred->modified_at = cred->created_at;
    cred->deleted = false;

    vault->count++;
    vault->is_dirty = true;

    return CRED_OK;
}

CredResult cred_edit(Vault *vault, uint32_t id, const char *url,
                     const char *username, const char *password)
{
    if (!vault) return CRED_ERR_VALIDATION;

    char err[256];
    if (!cred_validate(url, username, password, err, sizeof(err))) {
        return CRED_ERR_VALIDATION;
    }

    /* Find credential by ID, skip soft-deleted */
    Credential *cred = NULL;
    for (uint32_t i = 0; i < vault->count; i++) {
        if (vault->entries[i].id == id && !vault->entries[i].deleted) {
            cred = &vault->entries[i];
            break;
        }
    }

    if (!cred) return CRED_ERR_NOT_FOUND;

    strncpy(cred->url, url, MAX_URL_LEN);
    cred->url[MAX_URL_LEN] = '\0';
    strncpy(cred->username, username, MAX_USERNAME_LEN);
    cred->username[MAX_USERNAME_LEN] = '\0';
    strncpy(cred->password, password, MAX_PASSWORD_LEN);
    cred->password[MAX_PASSWORD_LEN] = '\0';
    cred->modified_at = platform_time_unix();
    vault->is_dirty = true;

    return CRED_OK;
}

CredResult cred_delete(Vault *vault, uint32_t id)
{
    if (!vault) return CRED_ERR_NOT_FOUND;

    for (uint32_t i = 0; i < vault->count; i++) {
        if (vault->entries[i].id == id && !vault->entries[i].deleted) {
            vault->entries[i].deleted = true;
            vault->entries[i].modified_at = platform_time_unix();
            vault->is_dirty = true;
            return CRED_OK;
        }
    }

    return CRED_ERR_NOT_FOUND;
}

Credential* cred_get(const Vault *vault, uint32_t id)
{
    if (!vault) return NULL;

    for (uint32_t i = 0; i < vault->count; i++) {
        if (vault->entries[i].id == id && !vault->entries[i].deleted) {
            return &vault->entries[i];
        }
    }

    return NULL;
}

CredResult cred_search(const Vault *vault, const char *query,
                       Credential **results, uint32_t *result_count)
{
    if (!vault || !results || !result_count) return CRED_ERR_VALIDATION;

    *results = NULL;
    *result_count = 0;

    /* First pass: count matches */
    uint32_t match_count = 0;
    for (uint32_t i = 0; i < vault->count; i++) {
        if (!vault->entries[i].deleted &&
            ci_strstr(vault->entries[i].url, query)) {
            match_count++;
        }
    }

    if (match_count == 0) {
        return CRED_OK;
    }

    /* Allocate results array */
    Credential *res = malloc(match_count * sizeof(Credential));
    if (!res) return CRED_ERR_VAULT_FULL;

    /* Second pass: copy matches */
    uint32_t idx = 0;
    for (uint32_t i = 0; i < vault->count; i++) {
        if (!vault->entries[i].deleted &&
            ci_strstr(vault->entries[i].url, query)) {
            res[idx++] = vault->entries[i];
        }
    }

    *results = res;
    *result_count = match_count;
    return CRED_OK;
}

/* ─── qsort comparator for cred_sort_by_url ──────────────────────────────── */

static int cred_url_cmp(const void *a, const void *b)
{
    const Credential *ca = (const Credential *)a;
    const Credential *cb = (const Credential *)b;
    return ci_strcmp(ca->url, cb->url);
}

void cred_sort_by_url(Vault *vault)
{
    if (!vault || !vault->entries || vault->count <= 1) return;
    qsort(vault->entries, vault->count, sizeof(Credential), cred_url_cmp);
}

/* ─── Clipboard Functions ─────────────────────────────────────────────────── */

ClipResult clip_copy(const char *value, size_t len)
{
    if (!value) return CLIP_ERR_UNAVAILABLE;

    bool ok = platform_clipboard_set(value, len);
    if (!ok) return CLIP_ERR_ACCESS_DENIED;

    /* Start/reset 30-second countdown */
    s_clip_countdown = 30;
    s_clip_active = true;

    return CLIP_OK;
}

void clip_tick(void)
{
    if (!s_clip_active) return;

    if (s_clip_countdown > 0) {
        s_clip_countdown--;
    }

    if (s_clip_countdown == 0) {
        platform_clipboard_clear();
        s_clip_active = false;
    }
}

uint32_t clip_get_remaining_seconds(void)
{
    return s_clip_countdown;
}

ClipResult clip_clear(void)
{
    bool ok = platform_clipboard_clear();
    s_clip_countdown = 0;
    s_clip_active = false;

    if (!ok) return CLIP_ERR_ACCESS_DENIED;
    return CLIP_OK;
}
