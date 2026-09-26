#!/bin/sh
# Build and run the C test runner on Linux/macOS (used by CI).
# Uses the POSIX/Linux platform layer (platform_android.c compiles for __linux__).
set -eu

CC="${CC:-cc}"

"$CC" -std=c11 -Wall -Wextra -DTEST_NO_MAIN \
  -Iinclude -Ivendor/argon2 -Ivendor/aesgcm -Ivendor/theft \
  tests/test_main.c tests/test_encryption.c tests/test_credentials.c \
  tests/test_validation.c tests/test_sync.c tests/test_vault.c tests/test_crypto_kat.c \
  src/encryption.c src/vault.c src/credential.c src/sync.c \
  platform/platform_android.c \
  vendor/argon2/argon2.c vendor/argon2/core.c vendor/argon2/ref.c \
  vendor/argon2/blake2b.c vendor/argon2/encoding.c \
  vendor/aesgcm/aes.c vendor/aesgcm/gcm.c \
  vendor/theft/theft.c \
  -o test_runner -lpthread

echo "BUILD SUCCEEDED: test_runner"
./test_runner
