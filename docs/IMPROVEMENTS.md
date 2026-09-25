# Password Manager — RCA & Improvement Backlog

A review of the codebase (core C library, platform layers, Windows/Android front-ends,
build system, and CI) with concrete, prioritized improvement opportunities. Each item
notes **where** it lives, **why** it matters, and a **suggested fix**.

> Scope note: this is an analysis document. Nothing here has been changed. Items are
> grouped by severity. Anything touching the on-disk `.vlt` format is flagged as
> **format-affecting** because it must stay backward-compatible with existing vaults on
> the desktop and mobile apps.

Severity legend: 🔴 High · 🟠 Medium · 🟢 Low / polish

---

## 🔴 High priority

### H1. KDF parameters in the header are ignored on decrypt
- **Where:** `src/encryption.c` (`enc_derive_key`), `src/vault.c` (`vault_deserialize`), `include/encryption.h`.
- **What:** `enc_derive_key` always overwrites `iterations`/`memory_kb`/`parallelism` with
  the compile-time minimums (`ENC_MIN_*`) and ignores the values stored in the vault header
  (bytes 7–15). Decrypt reads the nonce and salt from the header but never reads the KDF
  params back into the key derivation.
- **Why it matters:** The format is advertised as self-describing (it stores KDF params),
  but a vault written with anything other than the current hard-coded minimums could not be
  re-derived and would fail to open. It also blocks ever increasing the Argon2 cost without a
  migration, which is a normal security-hardening step.
- **Fix:** In `vault_deserialize`, read iterations/memory/parallelism from the header and pass
  them into a param-aware key-derivation call; keep `ENC_MIN_*` only as a validation floor.
  **Format-affecting (read path only)** — safe and backward compatible since existing vaults
  already store their params.

### H2. Wrong password is reported as "file corrupted"
- **Where:** `src/vault.c` (`vault_deserialize` maps `ENC_ERR_INTEGRITY_FAILED` → `STORE_ERR_CORRUPT`), surfaced in `platform/win32_ui.c` unlock flow.
- **What:** AES-GCM tag verification fails identically for (a) a wrong master password and
  (b) a genuinely tampered/corrupt file. Both become `STORE_ERR_CORRUPT`, and the desktop UI
  shows "Vault file is corrupted."
- **Why it matters:** A user who simply mistyped their password is told their vault is
  corrupt — alarming and misleading. It also muddies real corruption diagnosis.
- **Fix:** Add a distinct result (e.g. `STORE_ERR_AUTH` / surface `ENC_ERR_INTEGRITY_FAILED`
  as "wrong password or tampered data") and show a "incorrect password" message in both UIs.
  No format change.

### H3. Failed-attempt lockout is in-memory only and trivially bypassed
- **Where:** `src/credential.c` (`s_consecutive_failures` static), used by `win32_ui.c` and `jni_bridge.c`.
- **What:** The progressive-delay counter is a process-global `static` that starts at zero
  every launch. Closing and reopening the app resets it.
- **Why it matters:** The brute-force throttle can be defeated by restarting the process
  between guesses, so it provides little real protection.
- **Fix:** Persist a failure count + last-fail timestamp (e.g. in the vault header reserved
  bytes, or a small sidecar file) and enforce the delay across restarts. Consider a hard cap.
  If stored in the header, this is **format-affecting** — use the reserved region and default
  to zero for old files so they stay readable.

### H4. Synchronous sleep on the UI thread during auth delay
- **Where:** `src/credential.c` (`master_password_record_failure` → `platform_sleep_ms`), called from `win32_ui.c` `UI_UnlockVault` (also an explicit `platform_sleep_ms(failures * 1000)`).
- **What:** The progressive delay is a blocking `Sleep` on the calling thread, which is the
  Windows UI thread during unlock.
- **Why it matters:** The whole window freezes (no repaint, "not responding") for the delay
  duration, and the delay is applied twice in the desktop path (once in the recorder, once
  explicitly in the UI).
- **Fix:** Move the delay off the UI thread (worker thread + disabled dialog, or a timer),
  and remove the double-application. No format change.

### H5. Windows clipboard uses `CF_TEXT` (ANSI), mangling non-ASCII secrets
- **Where:** `platform/platform_win32.c` (`platform_clipboard_set` uses `CF_TEXT`).
- **What:** Passwords/usernames are copied as ANSI code-page text, not Unicode.
- **Why it matters:** Any credential containing non-ASCII characters (accents, symbols,
  non-Latin scripts) is corrupted on copy — a silent data-integrity bug for real passwords.
- **Fix:** Provide `CF_UNICODETEXT` (convert UTF-8 → UTF-16 and set wide clipboard data).
  No format change.

### H6. Android clipboard copy is a no-op stub
- **Where:** `platform/platform_android.c` (`platform_clipboard_set`/`_clear` are `__attribute__((weak))` stubs returning `false`); `platform/jni_bridge.c` `nativeClipCopy` calls `clip_copy` → the stub.
- **What:** On Android there is no real clipboard implementation in native code; the weak
  stubs just return failure. Real clipboard access needs `ClipboardManager` via a `Context`.
- **Why it matters:** "Copy password" likely fails silently on Android (or does nothing),
  undercutting a core feature on mobile.
- **Fix:** Implement clipboard on the Java side (`MainActivity` using `ClipboardManager`) and
  have the native tick/clear coordinate with it, or call back into Java from JNI. Verify the
  end-to-end copy + 30s auto-clear actually works on device. No format change.

### H7. Test suite is not run in CI
- **Where:** `tests/` + `build_tests.bat`; `.github/workflows/` has build/release but no test job.
- **What:** There's a real unit/property test suite (encryption, vault, credentials,
  validation, sync, master password) but nothing runs it automatically.
- **Why it matters:** Regressions — especially in crypto/format code where a subtle break can
  corrupt or expose vault data — can land silently.
- **Fix:** Add a CI job that compiles and runs the tests on push/PR. Note `build_tests.bat`
  hard-codes a local MinGW `gcc.exe` path (see L1) that must be fixed first, or drive the
  tests via CMake instead.

---

## 🟠 Medium priority

### M1. Vendored crypto is unpinned and unaudited
- **Where:** `vendor/argon2/*`, `vendor/aesgcm/*`.
- **What:** Argon2 and AES-GCM are vendored as source with no recorded upstream version,
  commit, or provenance, and no integrity check.
- **Why it matters:** For a password manager, the crypto primitives are the crown jewels. An
  unpinned/unknown-provenance AES-GCM or Argon2 is a supply-chain and correctness risk.
- **Fix:** Record exact upstream source + version in a `vendor/README`, add known-answer
  tests (NIST GCM test vectors, Argon2 RFC 9106 vectors) to the suite, and ideally check the
  GCM implementation against a reference. No format change.

### M2. Sync merge exists but transport/protocol appears incomplete
- **Where:** `src/sync.c` (`sync_merge` only), `platform/*` TCP + `platform_tcp_accept`/`platform_get_local_ip` (Android/Linux only), Win32 `IDC_BTN_SYNC` button.
- **What:** The merge algorithm is implemented and the platform layer has TCP primitives, but
  there's no visible end-to-end sync session (handshake, auth code, vault exchange, conflict
  application) wiring the two together, and `platform_tcp_accept`/`platform_get_local_ip` are
  not implemented for Win32.
- **Why it matters:** Sync is advertised as a feature (README, sync.h mentions ADB/USB, an
  auth-code/expiry result enum exists) but may not be usable, and the Win32 side lacks the
  accept/local-IP primitives the Android side has.
- **Fix:** Confirm the intended transport (the code comments say ADB USB; `SyncResult` has
  `AUTH_FAILED`/`TIMEOUT`/`EXPIRED_CODE`), then implement a documented session protocol and the
  missing Win32 primitives — or, if sync is not shipping yet, mark it clearly as WIP. No format
  change, but the wire protocol should be versioned.

### M3. Credential capacity vs. serialization length fields
- **Where:** `src/vault.c` (`serialize_credentials` uses `uint16_t` length prefixes), `include/credential.h` (`MAX_URL_LEN 2048`).
- **What:** URL length prefix is `uint16` (max 65535) while `MAX_URL_LEN` is 2048, so it fits
  today — but the invariant is implicit. `MAX_CREDENTIALS` is 10000 and the count field is
  `uint32`, also fine. These are only safe by coincidence of current constants.
- **Why it matters:** If any `MAX_*` grows past 65535 later, serialization silently truncates.
- **Fix:** Add static assertions tying `MAX_*_LEN <= UINT16_MAX` to the format, or widen the
  length fields deliberately. Widening would be **format-affecting** and needs a version bump.

### M4. `vault_serialize` re-uses the same salt every save; nonce is fresh (good) but key never rotates
- **Where:** `src/vault.c` (`vault_serialize` writes `key->salt`), `win32_ui.c`/`jni_bridge.c` keep the derived key for the session.
- **What:** The salt is fixed at vault creation and every save re-encrypts under the same
  Argon2-derived key with a fresh random nonce (nonce freshness is correct for GCM).
- **Why it matters:** Fresh nonces make this safe in practice, but there's no key/salt rotation
  path (e.g. on master-password change) and no re-encryption-cost upgrade path (ties into H1).
- **Fix:** Add a "change master password" flow that generates a new salt, re-derives, and
  re-encrypts. Ensure nonce uniqueness is documented as a hard requirement. No format change.

### M5. Error handling collapses distinct failures
- **Where:** `src/sync.c` (`sync_merge` returns `SYNC_ERR_NETWORK` for any null arg), `src/vault.c` (multiple failures → `STORE_ERR_WRITE_FAILED`), `src/credential.c` (`cred_search` OOM → `CRED_ERR_VAULT_FULL`).
- **What:** Several functions map unrelated failure modes onto a single, sometimes misleading,
  error code (e.g. out-of-memory reported as "vault full").
- **Why it matters:** Harder to diagnose real issues; user-facing messages can be wrong.
- **Fix:** Introduce specific error codes (e.g. `*_ERR_INVALID_ARG`, `*_ERR_MEMORY`) and map
  them to accurate messages. No format change.

### M6. No autosave-failure recovery / dirty-state guarantees
- **Where:** `platform/win32_ui.c` (`UI_AutoSave`), `platform/jni_bridge.c` (`autosave_vault`).
- **What:** On a save failure the desktop shows a message box and returns; `is_dirty` stays
  true but there's no retry/backoff, and on Android a failed autosave is swallowed (returns
  false, caller ignores).
- **Why it matters:** A transient write failure can lead to silent data loss on Android, or a
  confusing state on desktop.
- **Fix:** Surface save failures on Android, add a retry, and consider keeping a backup of the
  last-good vault before overwriting. The atomic temp+rename already helps; a `.bak` rotation
  would add a recovery path. No format change.

### M7. Android app config is minimal / dated
- **Where:** `android/app/build.gradle`.
- **What:** `compileSdk 33` / `targetSdk 33` (old), `versionCode`/`versionName` hard-coded,
  release build type has `minifyEnabled false` and no signing config, `allowBackup="false"`
  is good but there's no explicit `android:exported` review beyond MainActivity.
- **Why it matters:** Newer Play requirements expect a higher `targetSdk`; unsigned release
  builds can't ship; hard-coded versions complicate releases.
- **Fix:** Bump `compile/targetSdk`, wire `versionName`/`versionCode` from a single source
  (e.g. git tag), and add a signing config for release (kept out of CI secrets). No format change.

---

## 🟢 Low priority / polish

### L1. `build_tests.bat` hard-codes a machine-specific compiler path
- **Where:** `build_tests.bat` (`set GCC=C:\Users\617866396\...\gcc.exe`).
- **What:** The test build points at one specific user's MinGW install.
- **Fix:** Use `gcc` from PATH (or a `%GCC%` override with a sensible default), or build tests
  via CMake so they work anywhere (prerequisite for H7).

### L2. `README` build/test instructions are unverified on a clean machine
- **Where:** `README.md`.
- **What:** The documented steps are transcribed from the scripts but haven't been run on a
  fresh environment.
- **Fix:** Validate on a clean checkout (the new CI helps here) and adjust as needed.

### L3. Fixed-size stack buffers for paths and entries
- **Where:** `jni_bridge.c` (`char path[4096]`), `win32_ui.c` (`MAX_PATH`), `entry_buf` sized by `MAX_*`.
- **What:** Paths and formatted entries use fixed stack buffers with truncation on overflow.
- **Fix:** These are bounded and truncation-safe today, but consider explicit length checks /
  dynamic sizing if limits ever grow.

### L4. Pipe-delimited JNI serialization is fragile
- **Where:** `jni_bridge.c` (`"id|url|username|password"`).
- **What:** Credentials cross the JNI boundary as pipe-joined strings; a `|` in any field would
  break parsing on the Java side.
- **Fix:** Escape the delimiter or return structured data (parallel arrays / a small parcelable),
  and ensure the buffer holding plaintext is zeroed (it already is). No format change.

### L5. Consistent secure-zero coverage
- **Where:** core + bridges.
- **What:** Secure-zeroing is applied in most places (good), but `cred_search` returns a
  `malloc`'d array of full `Credential` structs (incl. passwords) to callers; the desktop path
  should ensure those are zeroed after use too.
- **Fix:** Audit every path that copies plaintext credential data and zero it on release.

### L6. Git commit identity
- **Where:** repo history.
- **What:** Commits are authored as an auto-derived `name <email>` that may not be intended.
- **Fix:** Set `git config user.name` / `user.email` to the desired identity going forward.

---

## Suggested sequencing

1. **Correctness/UX safety first:** H2, H4, H5, H6 (bad-password message, UI freeze, clipboard
   correctness on both platforms) — user-visible, low risk, no format change.
2. **Security hardening:** H1 (honor header KDF params), H3 (persistent lockout), M1 (pin +
   test crypto), M4 (change-password/rotation).
3. **Confidence:** H7 + L1 (tests in CI) so the above changes are guarded.
4. **Feature completeness:** M2 (sync end-to-end), M7 (Android config).
5. **Polish:** remaining M/L items.

> Format-affecting items (H1 read-path, H3 if header-stored, M3 widening) must preserve
> backward compatibility with existing `.vlt` files used by the shipped desktop and mobile
> apps. Any wire/file format change should bump the version field and default old files to the
> current behavior.
