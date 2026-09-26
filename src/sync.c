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

/* Find any credential (including soft-deleted) by URL + username. */
static Credential* find_any_by_content(Vault *vault, const char *url, const char *username)
{
    if (!vault || !vault->entries) return NULL;
    for (uint32_t i = 0; i < vault->count; i++) {
        if (strcmp(vault->entries[i].url, url) == 0 &&
            strcmp(vault->entries[i].username, username) == 0) {
            return &vault->entries[i];
        }
    }
    return NULL;
}

SyncResult sync_merge(Vault *local, const Vault *remote,
                      bool is_initiator, SyncSummary *summary)
{
    if (!local || !remote || !summary) {
        return SYNC_ERR_NETWORK;
    }

    summary->added = 0;
    summary->updated = 0;
    summary->pending_delete_count = 0;

    /* Find the max ID in local vault so new entries get unique IDs */
    uint32_t max_local_id = 0;
    for (uint32_t i = 0; i < local->count; i++) {
        if (local->entries[i].id > max_local_id) {
            max_local_id = local->entries[i].id;
        }
    }

    for (uint32_t i = 0; i < remote->count; i++) {
        const Credential *remote_cred = &remote->entries[i];

        if (remote_cred->deleted) {
            /* Remote says this entry is deleted. If we have a LIVE copy of the
             * same entry, record it as a PENDING deletion for the user to
             * confirm - do not apply it here. If we don't have it (or already
             * deleted it), there is nothing to do. */
            Credential *live = find_credential_by_content(local,
                                                          remote_cred->url,
                                                          remote_cred->username);
            if (live && !live->deleted) {
                if (summary->pending_delete_count < SYNC_MAX_PENDING_DELETES) {
                    summary->pending_delete_ids[summary->pending_delete_count++] = live->id;
                }
            }
            continue;
        }

        /* Remote entry is live. Match against any local entry (incl. deleted). */
        Credential *local_cred = find_any_by_content(local,
                                                     remote_cred->url,
                                                     remote_cred->username);

        if (!local_cred) {
            /* Not present locally: add it with a fresh unique ID. */
            Credential new_cred;
            memcpy(&new_cred, remote_cred, sizeof(Credential));
            new_cred.id = ++max_local_id;
            if (!vault_append_credential(local, &new_cred)) {
                continue; /* Vault full */
            }
            summary->added++;
        } else {
            /* Present on both: newer non-deleted edit wins (ties -> initiator). */
            bool remote_wins = false;
            if (remote_cred->modified_at > local_cred->modified_at) {
                remote_wins = true;
            } else if (remote_cred->modified_at == local_cred->modified_at) {
                remote_wins = !is_initiator;
            }

            if (remote_wins) {
                uint32_t saved_id = local_cred->id;
                bool was_deleted = local_cred->deleted;
                memcpy(local_cred, remote_cred, sizeof(Credential));
                local_cred->id = saved_id;
                local->is_dirty = true;
                /* Count as updated (this also "undeletes" a locally-deleted
                 * entry that the other device revived with a newer edit). */
                (void)was_deleted;
                summary->updated++;
            }
        }
    }

    if (summary->added > 0 || summary->updated > 0) {
        local->is_dirty = true;
    }

    return SYNC_OK;
}

bool sync_apply_deletion(Vault *local, uint32_t id)
{
    if (!local || !local->entries) return false;
    for (uint32_t i = 0; i < local->count; i++) {
        if (local->entries[i].id == id && !local->entries[i].deleted) {
            local->entries[i].deleted = true;
            local->entries[i].modified_at = platform_time_unix();
            local->is_dirty = true;
            return true;
        }
    }
    return false;
}
