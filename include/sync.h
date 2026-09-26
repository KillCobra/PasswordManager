/**
 * sync.h - Sync Engine
 *
 * Provides vault merge logic using last-writer-wins strategy for
 * synchronization between devices via ADB USB connection.
 */

#ifndef SYNC_H
#define SYNC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "credential.h"
#include "vault.h"
#include "encryption.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Data Structures ─────────────────────────────────────────────────────── */

#define SYNC_MAX_PENDING_DELETES 100

typedef struct {
    uint32_t added;         /* Remote-only entries added to local            */
    uint32_t updated;       /* Entries updated on local from a newer remote  */

    /* Deletions are NOT applied automatically. When an entry exists on both
     * devices but was deleted on the remote (and not yet on local), the merge
     * records it here as a PENDING deletion for the caller to confirm with the
     * user ("this was deleted on the other device - delete here too?"). The
     * caller applies only the confirmed ones via sync_apply_deletion(). */
    uint32_t pending_delete_ids[SYNC_MAX_PENDING_DELETES];   /* local IDs */
    uint32_t pending_delete_count;
} SyncSummary;

/* ─── Result Codes ────────────────────────────────────────────────────────── */

typedef enum {
    SYNC_OK = 0,
    SYNC_ERR_AUTH_FAILED,
    SYNC_ERR_TIMEOUT,
    SYNC_ERR_NETWORK,
    SYNC_ERR_MAX_ATTEMPTS,
    SYNC_ERR_EXPIRED_CODE
} SyncResult;

/* ─── Merge Logic ─────────────────────────────────────────────────────────── */

/**
 * Merge a remote vault into the local vault.
 *
 * Rules:
 *   - Remote entry not present locally (and not deleted): add it (added++).
 *   - Entry present on both, remote is a newer NON-deleted edit: update local
 *     (updated++), newer modified_at wins; ties go to the initiator.
 *   - Entry present on both, remote is DELETED but local is not: this is a
 *     pending deletion - it is NOT applied. The local ID is recorded in
 *     summary.pending_delete_ids for the caller to confirm per-entry.
 *   - Remote entry that is deleted and has no live local match is ignored
 *     (nothing to delete here).
 *
 * This function never removes credentials on its own; deletions are always
 * confirmed by the user via sync_apply_deletion().
 *
 * @param local        Local vault to merge into (modified in place)
 * @param remote       Remote vault to merge from
 * @param is_initiator Whether the local device initiated the sync (tie-break)
 * @param summary      Output merge summary (added/updated counts + pending deletes)
 * @return SYNC_OK on success, SYNC_ERR_NETWORK on invalid arguments
 */
SyncResult sync_merge(Vault *local, const Vault *remote,
                      bool is_initiator, SyncSummary *summary);

/**
 * Apply a confirmed deletion to the local vault: mark the credential with the
 * given local ID as deleted and bump its modified_at so the deletion will
 * propagate on the next sync. Call this only for pending deletions the user
 * confirmed.
 *
 * @param local  Local vault (modified in place)
 * @param id     Local credential ID to delete
 * @return true if the entry was found and marked deleted, false otherwise
 */
bool sync_apply_deletion(Vault *local, uint32_t id);

#ifdef __cplusplus
}
#endif

#endif /* SYNC_H */
