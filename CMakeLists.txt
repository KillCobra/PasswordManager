cmake_minimum_required(VERSION 3.18)
project(password_manager C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ============================================================
# Cross-Platform Password Manager - Android NDK CMakeLists.txt
# Builds the shared library for use via JNI on Android
# ============================================================

# --- Core source files ---
set(CORE_SOURCES
    src/encryption.c
    src/vault.c
    src/credential.c
    src/sync.c
)

# --- Platform-specific sources (Android) ---
set(PLATFORM_SOURCES
    platform/platform_android.c
    platform/jni_bridge.c
)

# --- Vendored Argon2 reference implementation ---
set(VENDOR_ARGON2
    vendor/argon2/argon2.c
    vendor/argon2/core.c
    vendor/argon2/ref.c
    vendor/argon2/blake2b.c
    vendor/argon2/encoding.c
)

# --- Vendored AES-GCM implementation ---
set(VENDOR_AESGCM
    vendor/aesgcm/aes.c
    vendor/aesgcm/gcm.c
)

# --- Include directories ---
include_directories(
    include
    vendor/argon2
    vendor/aesgcm
)

# --- Build shared library for Android ---
add_library(password_manager SHARED
    ${CORE_SOURCES}
    ${PLATFORM_SOURCES}
    ${VENDOR_ARGON2}
    ${VENDOR_AESGCM}
)

# --- Link Android system libraries ---
target_link_libraries(password_manager
    log
)

# --- Compiler flags ---
target_compile_options(password_manager PRIVATE
    -Wall
    -Wextra
    -Werror=implicit-function-declaration
)

# --- Definitions ---
target_compile_definitions(password_manager PRIVATE
    PLATFORM_ANDROID
)
