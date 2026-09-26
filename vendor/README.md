# Vendored third-party code

This directory contains the cryptographic primitives and the test harness that
the password manager builds against. They are vendored (checked in) so builds
are reproducible without network access.

> Security note: for a password manager the crypto primitives are the most
> sensitive dependency. Treat any change here as security-critical and keep the
> known-answer tests (`tests/test_crypto_kat.c`) passing.

## argon2/  — Argon2id password hashing / key derivation
- Purpose: derive the 256-bit vault key from the master password (`enc_derive_key*`).
- Reference: Argon2 as specified in RFC 9106; upstream reference implementation
  is https://github.com/P-H-C/phc-winner-argon2.
- **Provenance: record the exact upstream version/commit here.** (Unknown at
  time of writing — please pin the source revision this was taken from.)
- Files: argon2.c/.h, core.c/.h, ref.c, blake2b.c/.h, encoding.c

## aesgcm/ — AES-256-GCM authenticated encryption
- Purpose: encrypt/decrypt the vault body with integrity (`enc_encrypt`/`enc_decrypt`).
- Reference: AES (FIPS-197) + GCM (NIST SP 800-38D).
- **Provenance: record the exact upstream source/version here.** (Unknown at
  time of writing.)
- Files: aes.c/.h, gcm.c/.h
- Pinned by `tests/test_crypto_kat.c` against the GCM Test Case 14 vector.

## theft/ — property-based testing harness
- Purpose: drives the property tests under `tests/`.
- Reference: https://github.com/silentbicycle/theft
- Test-only; not shipped in the app binaries.

## Verifying integrity
The known-answer tests pin AES-256-GCM to a published vector and check Argon2id
determinism/salt-sensitivity. Run them via `build_tests.sh` (Linux/CI) or
`build_tests.bat` (Windows). If you update any vendored file, re-run the tests
and update the provenance notes above.
