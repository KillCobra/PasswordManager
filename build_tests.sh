#!/bin/sh
# Build and run the C test runner on Linux/macOS (used by CI).
# Uses the POSIX/Linux platform layer (platform_android.c compiles for __linux__).
set -eu

CC="${CC:-cc}"

# Use gnu11 + _GNU_SOURCE so POSIX/GNU symbols used by the Linux platform layer
# (popen, clock_gettime, nanosleep, getaddrinfo, MSG_NOSIGNAL, ...) are visible.
# Strict -std=c11 hides these behind feature-test macros and the build fails.
"$CC" -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -DTEST_NO_MAIN \
  -Iinclude -Ivendor/argon2 -Ivendor/aesgcm -Ivendor/theft \
  tests/test_main.c tests/test_encryption.c tests/test_credentials.c \
  tests/test_validation.c tests/test_sync.c tests/test_vault.c tests/test_crypto_kat.c \
  src/encryption.c src/vault.c src/credential.c src/sync.c \
  tests/platform_test_posix.c \
  vendor/argon2/argon2.c vendor/argon2/core.c vendor/argon2/ref.c \
  vendor/argon2/blake2b.c vendor/argon2/encoding.c \
  vendor/aesgcm/aes.c vendor/aesgcm/gcm.c \
  vendor/theft/theft.c \
  -o test_runner -lpthread

echo "BUILD SUCCEEDED: test_runner"
./test_runner
