# Password Manager

A cross-platform, offline-first password manager written in portable C11. A single
core library handles encryption, vault storage, credential management, and
device-to-device sync. Platform-specific layers wrap that core in a native
Windows desktop app and an Android app (via JNI).

There is no cloud, no account, and no telemetry. Your vault is a single encrypted
file on your device, and the only way to sync is a direct USB connection between
two devices.

## Highlights

- **Modern crypto** — Argon2id key derivation + AES-256-GCM authenticated encryption.
- **Single encrypted vault file** (`vault.vlt`) with a self-describing binary format.
- **Atomic saves** — writes go to a temp file, flush to disk, then rename, so a crash
  can never leave a half-written vault.
- **Master-password protection** with a minimum length requirement and a progressive
  delay after failed unlock attempts.
- **Clipboard auto-clear** — copied secrets are wiped from the clipboard after 30 seconds.
- **Soft-delete + last-writer-wins sync** for merging two vaults over USB.
- **Native UIs** — a dark-themed Win32 desktop app and an Android app, both driven by
  the same C core.

## Architecture

The project is split into a platform-independent core, a platform abstraction layer,
and two platform front-ends.

```
include/        Public headers (the core API surface)
src/            Core library — encryption, vault I/O, credentials, sync
platform/       Platform layer — Win32 desktop, Android JNI bridge, OS primitives
android/        Android app (Java UI + Gradle build)
vendor/         Bundled crypto (Argon2, AES-GCM) and a test harness (theft)
tests/          Unit and property-based tests for the core
CMakeLists.txt  Android/NDK shared-library build
build.bat       Windows desktop build (MSVC or MinGW)
```

### Core library (`src/`, `include/`)

| Module | Files | Responsibility |
|--------|-------|----------------|
| Encryption | `encryption.c` / `encryption.h` | Argon2id key derivation, AES-256-GCM encrypt/decrypt, secure memory zeroing |
| Vault storage | `vault.c` / `vault.h` | Binary serialization, the encrypt/decrypt file pipeline, atomic file I/O |
| Credentials | `credential.c` / `credential.h` | Credential CRUD, search, sort, master-password rules, clipboard timer |
| Sync | `sync.c` / `sync.h` | Merging a remote vault into the local one |

The core has **no OS dependencies of its own**. Everything OS-specific (files,
clipboard, sockets, random bytes, timing, secure zeroing) is reached through the
`platform.h` interface, which each platform implements.

### Platform layer (`platform/`)

| File | Platform | Role |
|------|----------|------|
| `platform_win32.c` | Windows | Implements `platform.h` with Win32 APIs (files, clipboard, Winsock, `BCryptGenRandom`, `SecureZeroMemory`) |
| `win32_ui.c` | Windows | The full dark-themed desktop GUI |
| `platform_android.c` | Android | Implements `platform.h` for Android |
| `jni_bridge.c` | Android | JNI glue exposing the core to Java |

## How it works

### Encryption pipeline

1. **Key derivation** (`enc_derive_key`): the master password plus a random 128-bit
   salt are fed to **Argon2id**. Parameters are enforced at minimums of 3 iterations,
   64 MB memory, and parallelism 1, producing a 256-bit key.
2. **Encryption** (`enc_encrypt`): the serialized credential blob is encrypted with
   **AES-256-GCM** using a freshly generated random 96-bit nonce. GCM produces a
   128-bit authentication tag.
3. **Decryption** (`enc_decrypt`): the GCM tag is verified before any plaintext is
   returned. A tag mismatch (wrong password or tampered file) fails with an integrity
   error rather than returning garbage.

Random bytes come from the OS CSPRNG (`BCryptGenRandom` on Windows). Sensitive
buffers — derived keys, plaintext, the master password — are wiped with a
non-optimizable secure-zero after use.

### Vault file format (`.vlt`)

A vault file is a 64-byte header, an encrypted body, and a trailing 16-byte GCM tag:

```
┌─────────────────────────── 64-byte header ───────────────────────────┐
│ off 0   magic "VLT1"            (4 bytes)                              │
│ off 4   format version          (u16, LE)                             │
│ off 6   algorithm id            (1 byte, 0x01 = AES-256-GCM)          │
│ off 7   Argon2 iterations       (u32, LE)                             │
│ off 11  Argon2 memory KB        (u32, LE)                             │
│ off 15  Argon2 parallelism      (1 byte)                              │
│ off 16  salt                    (16 bytes)                            │
│ off 32  nonce                   (12 bytes)                            │
│ off 44  credential count        (u32, LE)                             │
│ off 48  reserved                (16 bytes, zero)                      │
├───────────────────────────────────────────────────────────────────────┤
│ AES-256-GCM ciphertext of the serialized credentials                  │
├───────────────────────────────────────────────────────────────────────┤
│ 16-byte GCM authentication tag                                        │
└───────────────────────────────────────────────────────────────────────┘
```

The header stores the KDF parameters and salt in the clear (they aren't secret),
which lets any device re-derive the key from the master password. Each credential
is serialized as: id, length-prefixed URL / username / password, created-at and
modified-at timestamps, and a soft-delete flag.

Saves are **atomic**: data is written to `<path>.tmp`, flushed to disk, and then
renamed over the real file, so the vault is never left in a partially written state.

### Credentials

Each credential holds a URL, username, password, creation/modification timestamps,
and a `deleted` flag. Full CRUD is supported:

- **Add / edit / delete** with validation (fields required, length limits enforced).
- **Delete is a soft delete** — the entry is flagged rather than removed, so deletions
  can propagate correctly during sync.
- **Search** does a case-insensitive substring match on the URL.
- **Sort** orders entries case-insensitively by URL for display.

### Master password and lockout

- Minimum length is 8 characters (`master_password_validate`).
- After a failed unlock, a **progressive delay** kicks in: the Nth consecutive failure
  waits N seconds before the next attempt. A successful unlock resets the counter.
- Locking the vault securely zeroes the decrypted entries, the derived key, and the
  in-memory master password.

### Clipboard auto-clear

Copying a value starts a 30-second countdown. A per-second tick decrements it, and
when it reaches zero the clipboard is cleared automatically so secrets don't linger.

### Sync (last-writer-wins)

Sync merges a remote vault into the local one (`sync_merge`), pairing entries by
URL + username rather than by ID (IDs can differ across devices):

- A remote entry with no local match is **added** with a fresh local ID.
- When both sides have the entry, the one with the newer `modified_at` **wins**.
- On identical timestamps, the **sync initiator's** copy is kept.
- A newer deletion wins over an older edit, so deletes propagate correctly.

The merge returns a summary of how many entries were added, updated, and deleted.
The transport is a direct device-to-device link (USB / ADB); there is no server.

## Platforms

### Windows desktop (`win32_ui.c`)

A native Win32 GUI with a dark theme (dark title bar via DWM, owner-drawn flat
buttons with hover states, a custom-colored `ListView`). It shows credentials in a
URL / Username / Password table (passwords masked), with:

- **Double-click to copy** any cell (URL, username, or the real password).
- Add / Edit / Delete / Sync / Lock actions and a search box.
- A status bar that shows credential count and the clipboard-clear countdown.
- **Auto-save** whenever the vault is marked dirty.

On first run it prompts you to create a vault and master password; on later runs it
prompts to unlock. The default vault file is `vault.vlt` in the working directory.

### Android (`android/`, `jni_bridge.c`)

The core C library is compiled to a shared library (`libpassword_manager.so`) and
loaded by `com.passwordmanager.NativeLib`, which declares the native methods
(create/unlock/lock vault, credential CRUD, search, clipboard control). `jni_bridge.c`
implements them, converting strings across the JNI boundary and securely zeroing
buffers. `MainActivity.java` provides the UI. The app declares `INTERNET` and
`ACCESS_NETWORK_STATE` permissions and disables Android backup for the vault.

## Building

### Windows

Requires either MSVC (`cl.exe`) or MinGW (`gcc`).

```bat
:: Defaults to MSVC release
build.bat

:: Or specify compiler and config
build.bat msvc release
build.bat mingw debug
```

This produces `password_manager.exe`. It links against `advapi32`, `ws2_32`,
`user32`, `gdi32`, and `bcrypt` (plus `comctl32` / `dwmapi` for the MinGW UI build).

### Android

The `CMakeLists.txt` builds the `password_manager` shared library for the Android NDK
(it compiles the core, the Android platform layer, the JNI bridge, and the vendored
Argon2 / AES-GCM sources). Build the app through Gradle:

```bat
cd android
gradlew.bat assembleDebug
```

## Testing

Unit and property-based tests live in `tests/` and cover encryption, credentials,
validation, sync, the vault format, and the master-password logic. They use the
bundled [`theft`](vendor/theft) property-testing harness.

Build and run them on Windows with:

```bat
build_tests.bat
test_runner.exe
```

> Note: `build_tests.bat` currently points at a hard-coded local MinGW `gcc.exe` path.
> Update that path to match your toolchain before running it.

## Third-party code (`vendor/`)

- **Argon2** — reference Argon2id implementation for password-based key derivation.
- **AES-GCM** — AES and GCM implementation for authenticated encryption.
- **theft** — property-based testing library used by the test suite.

## Security notes

- The vault is only as strong as the master password; there is no recovery path if
  it's forgotten — that's by design.
- KDF parameters and salt are stored in the vault header (they aren't secret) so the
  key can be re-derived on any device.
- Decrypted data, keys, and the master password are securely zeroed from memory when
  the vault is locked.
- Sync is a direct device-to-device transfer; no data is sent to any server.
