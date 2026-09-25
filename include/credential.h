/**
 * credential.h - Credential Manager and Master Password Validation
 *
 * Provides credential CRUD operations, master password validation with
 * progressive delay, and clipboard management with auto-clear timer.
 */

#ifndef CREDENTIAL_H
#define CREDENTIAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Constants ───────────────────────────────────────────────────────────── */

#define MAX_URL_LEN 2048
#define MAX_USERNAME_LEN 256
#define MAX_PASSWORD_LEN 256
#define MAX_CREDENTIALS 10000
#define MASTER_PASSWORD_MIN_LEN 8

/* ─── Data Structures ─────────────────────────────────────────────────────── */

typedef struct {
    uint32_t id;
    char url[MAX_URL_LEN + 1];
    char username[MAX_USERNAME_LEN + 1];
    char password[MAX_PASSWORD_LEN + 1];
    uint64_t created_at;
    uint64_t modified_at;
    bool deleted;
} Credential;

typedef struct {
    Credential *entries;
    uint32_t count;
    uint32_t capacity;
    bool is_dirty;
} Vault;

typedef enum {
    CRED_OK = 0,
    CRED_ERR_VALIDATION,
    CRED_ERR_NOT_FOUND,
    CRED_ERR_VAULT_FULL,
    CRED_ERR_SAVE_FAILED
} CredResult;

/* ─── Master Password Validation ──────────────────────────────────────────── */

/**
 * Validate a master password.
 * Returns true if the password meets the minimum length requirement (8 chars).
 * Returns false otherwise.
 */
bool master_password_validate(const char *password, size_t len);

/**
 * Record a failed authentication attempt and enforce progressive delay.
 * Increments the consecutive failure counter and sleeps for
 * (consecutive_failures * 1) seconds using platform_sleep_ms().
 *
 * Note: this blocks the calling thread for the delay. UI code that must stay
 * responsive should instead use master_password_record_failure_no_delay() to
 * update the counter and then enforce the delay via
 * master_password_get_delay_ms() on a non-UI thread or with a responsive wait.
 */
void master_password_record_failure(void);

/**
 * Record a failed authentication attempt WITHOUT sleeping.
 * Increments the consecutive failure counter only. The caller is responsible
 * for enforcing the progressive delay (see master_password_get_delay_ms()).
 */
void master_password_record_failure_no_delay(void);

/**
 * Record a successful authentication, resetting the failure counter to zero.
 */
void master_password_record_success(void);

/**
 * Get the current number of consecutive authentication failures.
 */
uint32_t master_password_get_failure_count(void);

/**
 * Get the progressive delay, in milliseconds, that should be enforced for the
 * current consecutive-failure count (consecutive_failures * 1000 ms).
 */
uint32_t master_password_get_delay_ms(void);

/* ─── Credential CRUD ─────────────────────────────────────────────────────── */

CredResult cred_add(Vault *vault, const char *url,
                    const char *username, const char *password);
CredResult cred_edit(Vault *vault, uint32_t id, const char *url,
                     const char *username, const char *password);
CredResult cred_delete(Vault *vault, uint32_t id);
Credential* cred_get(const Vault *vault, uint32_t id);

CredResult cred_search(const Vault *vault, const char *query,
                       Credential **results, uint32_t *result_count);

void cred_sort_by_url(Vault *vault);

bool cred_validate(const char *url, const char *username,
                   const char *password, char *error_msg, size_t msg_len);

/* ─── Clipboard Functions ─────────────────────────────────────────────────── */

typedef enum {
    CLIP_OK = 0,
    CLIP_ERR_ACCESS_DENIED,
    CLIP_ERR_UNAVAILABLE
} ClipResult;

ClipResult clip_copy(const char *value, size_t len);
uint32_t clip_get_remaining_seconds(void);
ClipResult clip_clear(void);
void clip_tick(void);

#ifdef __cplusplus
}
#endif

#endif /* CREDENTIAL_H */
