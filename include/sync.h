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

typedef struct {
    uint32_t added;
    uint32_t updated;
    uint32_t deleted;
    uint32_t deleted_ids[100];      /* IDs of credentials deleted during merge */
    uint32_t deleted_id_count;      /* Number of entries in deleted_ids */
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
 * Merge a remote vault into the local vault using last-writer-wins strategy.
 *
 * Rules:
 *   - Remote credential not in local: add it (summary.added++)
 *   - Both have same credential: newer modified_at wins (summary.updated++)
 *   - Identical timestamps: initiator's version wins
 *   - Deletion with newer timestamp wins over modification (summary.deleted++)
 *
 * @param local        Local vault to merge into (modified in place)
 * @param remote       Remote vault to merge from
 * @param is_initiator Whether the local device initiated the sync
 * @param summary      Output merge summary with counts
 * @return SYNC_OK on success, SYNC_ERR_NETWORK on failure
 */
SyncResult sync_merge(Vault *local, const Vault *remote,
                      bool is_initiator, SyncSummary *summary);

#ifdef __cplusplus
}
#endif

#endif /* SYNC_H */
