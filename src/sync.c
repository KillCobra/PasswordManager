/**
 * sync.c - Sync Engine Implementation
 *
 * Implements last-writer-wins vault merge logic for ADB-based USB sync.
 */

#include "sync.h"
#include "platform.h"
#include "vault.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ─── Internal Helpers ────────────────────────────────────────────────────── */

/**
 * Find a credential in the vault by ID.
 * Returns pointer to the credential or NULL if not found.
 */
static Credential* find_credential_by_id(Vault *vault, uint32_t id)
{
    if (!vault || !vault->entries) return NULL;
    for (uint32_t i = 0; i < vault->count; i++) {
        if (vault->entries[i].id == id) {
            return &vault->entries[i];
        }
    }
    return NULL;
}

/**
 * Find a credential in the vault by URL + username (case-sensitive match).
 * This is used for merge to identify "same" credentials across devices
 * that may have different IDs.
 * Returns pointer to the credential or NULL if not found.
 */
static Credential* find_credential_by_content(Vault *vault, const char *url, const char *username)
{
    if (!vault || !vault->entries) return NULL;
    for (uint32_t i = 0; i < vault->count; i++) {
        if (!vault->entries[i].deleted &&
            strcmp(vault->entries[i].url, url) == 0 &&
            strcmp(vault->entries[i].username, username) == 0) {
            return &vault->entries[i];
        }
    }
    return NULL;
}

/**
 * Add a credential to the vault (used during merge).
 * Returns true on success, false if vault is full.
 */
static bool vault_append_credential(Vault *vault, const Credential *cred)
{
    if (vault->count >= vault->capacity) {
        /* Try to grow the capacity */
        uint32_t new_capacity = vault->capacity == 0 ? 16 : vault->capacity * 2;
        if (new_capacity > MAX_CREDENTIALS) {
            new_capacity = MAX_CREDENTIALS;
        }
        if (vault->count >= new_capacity) {
            return false;
        }

        Credential *new_entries = (Credential *)realloc(
            vault->entries, new_capacity * sizeof(Credential));
        if (!new_entries) {
            return false;
        }
        vault->entries = new_entries;
        vault->capacity = new_capacity;
    }

    memcpy(&vault->entries[vault->count], cred, sizeof(Credential));
    vault->count++;
    vault->is_dirty = true;
    return true;
}

/* ─── Merge Logic Implementation ──────────────────────────────────────────── */

SyncResult sync_merge(Vault *local, const Vault *remote,
                      bool is_initiator, SyncSummary *summary)
{
    if (!local || !remote || !summary) {
        return SYNC_ERR_NETWORK;
    }

    /* Initialize summary counts */
    summary->added = 0;
    summary->updated = 0;
    summary->deleted = 0;
    summary->deleted_id_count = 0;

    /* Find the max ID in local vault so new entries get unique IDs */
    uint32_t max_local_id = 0;
    for (uint32_t i = 0; i < local->count; i++) {
        if (local->entries[i].id > max_local_id) {
            max_local_id = local->entries[i].id;
        }
    }

    /* Process each credential in the remote vault */
    for (uint32_t i = 0; i < remote->count; i++) {
        const Credential *remote_cred = &remote->entries[i];

        /* Skip deleted entries from remote that we've never seen */
        /* Find matching credential by URL + username (content-based match) */
        Credential *local_cred = find_credential_by_content(local,
                                                             remote_cred->url,
                                                             remote_cred->username);

        if (!local_cred) {
            /* Credential not in local vault: add it with a new unique ID */
            if (remote_cred->deleted) {
                /* Don't add already-deleted entries we never had */
                continue;
            }

            Credential new_cred;
            memcpy(&new_cred, remote_cred, sizeof(Credential));
            new_cred.id = ++max_local_id; /* Assign new unique ID */

            if (!vault_append_credential(local, &new_cred)) {
                continue; /* Vault full */
            }
            summary->added++;
        } else {
            /* Credential exists in both vaults: resolve conflict */
            bool remote_wins = false;

            if (remote_cred->modified_at > local_cred->modified_at) {
                remote_wins = true;
            } else if (remote_cred->modified_at == local_cred->modified_at) {
                /* Identical timestamps: initiator wins (keep local) */
                remote_wins = !is_initiator;
            }

            if (remote_wins) {
                bool was_deleted = local_cred->deleted;
                bool now_deleted = remote_cred->deleted;

                /* Update local entry with remote data, keep local ID */
                uint32_t saved_id = local_cred->id;
                memcpy(local_cred, remote_cred, sizeof(Credential));
                local_cred->id = saved_id; /* Preserve local ID */
                local->is_dirty = true;

                if (!was_deleted && now_deleted) {
                    summary->deleted++;
                    if (summary->deleted_id_count < 100) {
                        summary->deleted_ids[summary->deleted_id_count++] = saved_id;
                    }
                } else if (was_deleted && !now_deleted) {
                    summary->updated++;
                } else {
                    summary->updated++;
                }
            }
        }
    }

    if (summary->added > 0 || summary->updated > 0 || summary->deleted > 0) {
        local->is_dirty = true;
    }

    return SYNC_OK;
}
