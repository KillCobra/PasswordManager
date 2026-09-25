@echo off
set GCC=C:\Users\617866396\Downloads\TFV\msys64\mingw64\bin\gcc.exe
%GCC% -std=c11 -Wall -Wextra -DTEST_NO_MAIN -Iinclude -Ivendor/argon2 -Ivendor/aesgcm -Ivendor/theft ^
  tests/test_main.c tests/test_encryption.c tests/test_credentials.c ^
  tests/test_validation.c tests/test_sync.c tests/test_vault.c ^
  src/encryption.c src/vault.c src/credential.c src/sync.c ^
  platform/platform_win32.c ^
  vendor/argon2/argon2.c vendor/argon2/core.c vendor/argon2/ref.c vendor/argon2/blake2b.c vendor/argon2/encoding.c ^
  vendor/aesgcm/aes.c vendor/aesgcm/gcm.c ^
  vendor/theft/theft.c ^
  -o test_runner.exe -ladvapi32 -lws2_32 -luser32 -lgdi32 -lbcrypt
if errorlevel 1 (echo BUILD FAILED & exit /b 1)
echo BUILD SUCCEEDED: test_runner.exe
