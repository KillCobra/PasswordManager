
/**
 * jni_bridge.c - JNI Native Method Implementations for Android
 *
 * Exposes all core password manager functions to Java/Kotlin via JNI.
 * Handles string conversion between Java UTF-16 and C UTF-8, and ensures
 * secure memory clearing on the JNI boundary.
 *
 * Java class: com.passwordmanager.NativeLib
 */

#if defined(__ANDROID__) || defined(PLATFORM_ANDROID)

#include <jni.h>
#include <string.h>
#include <stdlib.h>

#include "vault.h"
#include "credential.h"
#include "encryption.h"
#include "platform.h"

/* ─── Static Vault State ──────────────────────────────────────────────────── */

static Vault g_vault = { .entries = NULL, .count = 0, .capacity = 0, .is_dirty = false };
static DerivedKey g_derived_key;
static char g_vault_path[4096] = {0};
static bool g_vault_unlocked = false;

/* ─── Internal Helpers ────────────────────────────────────────────────────── */

/**
 * Safely get a UTF-8 C string from a jstring, copy it into a local buffer,
 * then release the JNI string. Returns true on success.
 * The caller must ensure buf is large enough.
 */
static bool jstring_to_utf8(JNIEnv *env, jstring jstr, char *buf, size_t buf_size)
{
    if (!jstr) {
        buf[0] = '\0';
        return false;
    }

    const char *utf8 = (*env)->GetStringUTFChars(env, jstr, NULL);
    if (!utf8) {
        buf[0] = '\0';
        return false;
    }

    size_t len = strlen(utf8);
    if (len >= buf_size) {
        len = buf_size - 1;
    }
    memcpy(buf, utf8, len);
    buf[len] = '\0';

    (*env)->ReleaseStringUTFChars(env, jstr, utf8);
    return true;
}

/**
 * Create a jstring from a C string, then securely zero the source buffer.
 */
static jstring utf8_to_jstring_secure(JNIEnv *env, char *buf, size_t buf_size)
{
    jstring result = (*env)->NewStringUTF(env, buf);
    platform_secure_zero(buf, buf_size);
    return result;
}

/**
 * Auto-save vault to disk if dirty.
 */
static bool autosave_vault(void)
{
    if (!g_vault_unlocked || !g_vault.is_dirty) {
        return true;
    }

    uint8_t *data = NULL;
    size_t data_len = 0;

    StoreResult sr = vault_serialize(&g_vault, &g_derived_key, &data, &data_len);
    if (sr != STORE_OK) {
        return false;
    }

    sr = store_save(g_vault_path, data, data_len);
    free(data);

    if (sr == STORE_OK) {
        g_vault.is_dirty = false;
        return true;
    }
    return false;
}

/* ─── JNI Method Implementations ──────────────────────────────────────────── */

/**
 * nativeCreateVault(String path, String masterPassword) -> boolean
 *
 * Creates a new empty vault file at the given path, encrypted with the
 * master password. Returns true on success.
 */
JNIEXPORT jboolean JNICALL
Java_com_passwordmanager_NativeLib_nativeCreateVault(
    JNIEnv *env, jobject thiz, jstring jpath, jstring jpassword)
{
    (void)thiz;

    char path[4096];
    char password[MAX_PASSWORD_LEN + 1];

    if (!jstring_to_utf8(env, jpath, path, sizeof(path))) {
        return JNI_FALSE;
    }
    if (!jstring_to_utf8(env, jpassword, password, sizeof(password))) {
        return JNI_FALSE;
    }

    /* Validate master password */
    size_t pw_len = strlen(password);
    if (!master_password_validate(password, pw_len)) {
        platform_secure_zero(password, sizeof(password));
        return JNI_FALSE;
    }

    /* Generate salt and derive key */
    uint8_t salt[ENC_SALT_SIZE];
    if (!platform_random_bytes(salt, ENC_SALT_SIZE)) {
        platform_secure_zero(password, sizeof(password));
        return JNI_FALSE;
    }

    DerivedKey key;
    EncResult er = enc_derive_key(password, pw_len, salt, &key);
    platform_secure_zero(password, sizeof(password));

    if (er != ENC_OK) {
        return JNI_FALSE;
    }

    /* Create empty vault */
    Vault empty_vault = { .entries = NULL, .count = 0, .capacity = 0, .is_dirty = false };

    uint8_t *data = NULL;
    size_t data_len = 0;
    StoreResult sr = vault_serialize(&empty_vault, &key, &data, &data_len);
    if (sr != STORE_OK) {
        enc_secure_zero(&key, sizeof(key));
        return JNI_FALSE;
    }

    sr = store_save(path, data, data_len);
    free(data);
    enc_secure_zero(&key, sizeof(key));

    return (sr == STORE_OK) ? JNI_TRUE : JNI_FALSE;
}

/**
 * nativeUnlockVault(String path, String masterPassword) -> boolean
 *
 * Loads and decrypts the vault file. On success, the vault is held in
 * memory for subsequent operations. Returns true on success.
 */
JNIEXPORT jboolean JNICALL
Java_com_passwordmanager_NativeLib_nativeUnlockVault(
    JNIEnv *env, jobject thiz, jstring jpath, jstring jpassword)
{
    (void)thiz;

    char path[4096];
    char password[MAX_PASSWORD_LEN + 1];

    if (!jstring_to_utf8(env, jpath, path, sizeof(path))) {
        return JNI_FALSE;
    }
    if (!jstring_to_utf8(env, jpassword, password, sizeof(password))) {
        return JNI_FALSE;
    }

    size_t pw_len = strlen(password);

    /* Load vault file */
    uint8_t *file_data = NULL;
    size_t file_len = 0;
    StoreResult sr = store_load(path, &file_data, &file_len);
    if (sr != STORE_OK) {
        platform_secure_zero(password, sizeof(password));
        master_password_record_failure();
        return JNI_FALSE;
    }

    /* Extract salt from header (offset 8, after magic + version + algo) */
    if (file_len < VAULT_HEADER_SIZE) {
        free(file_data);
        platform_secure_zero(password, sizeof(password));
        master_password_record_failure();
        return JNI_FALSE;
    }

    /* Derive key using salt from vault header
     * Header layout: magic(4) + version(2) + algo(1) + iterations(4) +
     *                memory_kb(4) + parallelism(1) + salt(16) + nonce(12) +
     *                count(4) + reserved(16) = 64 bytes
     */
    uint8_t salt[ENC_SALT_SIZE];
    memcpy(salt, file_data + 16, ENC_SALT_SIZE); /* salt at offset 16 */

    DerivedKey key;
    EncResult er = enc_derive_key(password, pw_len, salt, &key);
    platform_secure_zero(password, sizeof(password));

    if (er != ENC_OK) {
        free(file_data);
        master_password_record_failure();
        return JNI_FALSE;
    }

    /* Deserialize (decrypt) vault */
    Vault new_vault = {0};
    sr = vault_deserialize(file_data, file_len, &key, &new_vault);
    free(file_data);

    if (sr != STORE_OK) {
        enc_secure_zero(&key, sizeof(key));
        master_password_record_failure();
        return JNI_FALSE;
    }

    /* Lock any previously open vault */
    if (g_vault_unlocked && g_vault.entries) {
        platform_secure_zero(g_vault.entries,
                             g_vault.capacity * sizeof(Credential));
        free(g_vault.entries);
    }

    /* Store state */
    g_vault = new_vault;
    g_derived_key = key;
    strncpy(g_vault_path, path, sizeof(g_vault_path) - 1);
    g_vault_path[sizeof(g_vault_path) - 1] = '\0';
    g_vault_unlocked = true;

    master_password_record_success();
    return JNI_TRUE;
}

/**
 * nativeLockVault() -> void
 *
 * Securely clears all decrypted vault data from memory.
 */
JNIEXPORT void JNICALL
Java_com_passwordmanager_NativeLib_nativeLockVault(
    JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;

    if (g_vault_unlocked) {
        /* Auto-save before locking */
        autosave_vault();

        /* Securely clear credentials */
        if (g_vault.entries) {
            platform_secure_zero(g_vault.entries,
                                 g_vault.capacity * sizeof(Credential));
            free(g_vault.entries);
            g_vault.entries = NULL;
        }
        g_vault.count = 0;
        g_vault.capacity = 0;
        g_vault.is_dirty = false;

        /* Clear derived key */
        enc_secure_zero(&g_derived_key, sizeof(g_derived_key));

        /* Clear vault path */
        platform_secure_zero(g_vault_path, sizeof(g_vault_path));

        g_vault_unlocked = false;
    }
}

/**
 * nativeAddCredential(String url, String username, String password) -> boolean
 *
 * Adds a new credential to the unlocked vault. Auto-saves on success.
 */
JNIEXPORT jboolean JNICALL
Java_com_passwordmanager_NativeLib_nativeAddCredential(
    JNIEnv *env, jobject thiz, jstring jurl, jstring jusername, jstring jpassword)
{
    (void)thiz;

    if (!g_vault_unlocked) {
        return JNI_FALSE;
    }

    char url[MAX_URL_LEN + 1];
    char username[MAX_USERNAME_LEN + 1];
    char password[MAX_PASSWORD_LEN + 1];

    if (!jstring_to_utf8(env, jurl, url, sizeof(url))) {
        return JNI_FALSE;
    }
    if (!jstring_to_utf8(env, jusername, username, sizeof(username))) {
        return JNI_FALSE;
    }
    if (!jstring_to_utf8(env, jpassword, password, sizeof(password))) {
        platform_secure_zero(password, sizeof(password));
        return JNI_FALSE;
    }

    CredResult cr = cred_add(&g_vault, url, username, password);
    platform_secure_zero(password, sizeof(password));

    if (cr != CRED_OK) {
        return JNI_FALSE;
    }

    autosave_vault();
    return JNI_TRUE;
}

/**
 * nativeEditCredential(int id, String url, String username, String password) -> boolean
 *
 * Edits an existing credential by ID. Auto-saves on success.
 */
JNIEXPORT jboolean JNICALL
Java_com_passwordmanager_NativeLib_nativeEditCredential(
    JNIEnv *env, jobject thiz, jint jid, jstring jurl,
    jstring jusername, jstring jpassword)
{
    (void)thiz;

    if (!g_vault_unlocked) {
        return JNI_FALSE;
    }

    char url[MAX_URL_LEN + 1];
    char username[MAX_USERNAME_LEN + 1];
    char password[MAX_PASSWORD_LEN + 1];

    if (!jstring_to_utf8(env, jurl, url, sizeof(url))) {
        return JNI_FALSE;
    }
    if (!jstring_to_utf8(env, jusername, username, sizeof(username))) {
        return JNI_FALSE;
    }
    if (!jstring_to_utf8(env, jpassword, password, sizeof(password))) {
        platform_secure_zero(password, sizeof(password));
        return JNI_FALSE;
    }

    CredResult cr = cred_edit(&g_vault, (uint32_t)jid, url, username, password);
    platform_secure_zero(password, sizeof(password));

    if (cr != CRED_OK) {
        return JNI_FALSE;
    }

    autosave_vault();
    return JNI_TRUE;
}

/**
 * nativeDeleteCredential(int id) -> boolean
 *
 * Soft-deletes a credential by ID. Auto-saves on success.
 */
JNIEXPORT jboolean JNICALL
Java_com_passwordmanager_NativeLib_nativeDeleteCredential(
    JNIEnv *env, jobject thiz, jint jid)
{
    (void)env;
    (void)thiz;

    if (!g_vault_unlocked) {
        return JNI_FALSE;
    }

    CredResult cr = cred_delete(&g_vault, (uint32_t)jid);
    if (cr != CRED_OK) {
        return JNI_FALSE;
    }

    autosave_vault();
    return JNI_TRUE;
}

/**
 * nativeSearchCredentials(String query) -> String[]
 *
 * Searches credentials by URL substring (case-insensitive).
 * Returns an array of pipe-delimited strings: "id|url|username|password"
 */
JNIEXPORT jobjectArray JNICALL
Java_com_passwordmanager_NativeLib_nativeSearchCredentials(
    JNIEnv *env, jobject thiz, jstring jquery)
{
    (void)thiz;

    if (!g_vault_unlocked) {
        return NULL;
    }

    char query[MAX_URL_LEN + 1];
    if (!jstring_to_utf8(env, jquery, query, sizeof(query))) {
        return NULL;
    }

    Credential *results = NULL;
    uint32_t result_count = 0;

    CredResult cr = cred_search(&g_vault, query, &results, &result_count);
    if (cr != CRED_OK || result_count == 0) {
        /* Return empty array */
        jclass string_class = (*env)->FindClass(env, "java/lang/String");
        return (*env)->NewObjectArray(env, 0, string_class, NULL);
    }

    /* Build Java String array */
    jclass string_class = (*env)->FindClass(env, "java/lang/String");
    jobjectArray jarray = (*env)->NewObjectArray(env, (jsize)result_count,
                                                  string_class, NULL);
    if (!jarray) {
        free(results);
        return NULL;
    }

    char entry_buf[MAX_URL_LEN + MAX_USERNAME_LEN + MAX_PASSWORD_LEN + 64];

    for (uint32_t i = 0; i < result_count; i++) {
        /* Format: "id|url|username|password" */
        snprintf(entry_buf, sizeof(entry_buf), "%u|%s|%s|%s",
                 results[i].id, results[i].url,
                 results[i].username, results[i].password);

        jstring jentry = (*env)->NewStringUTF(env, entry_buf);
        (*env)->SetObjectArrayElement(env, jarray, (jsize)i, jentry);
        (*env)->DeleteLocalRef(env, jentry);

        /* Securely clear the buffer containing password data */
        platform_secure_zero(entry_buf, sizeof(entry_buf));
    }

    free(results);
    return jarray;
}

/**
 * nativeGetAllCredentials() -> String[]
 *
 * Returns all non-deleted credentials as pipe-delimited strings.
 * Format: "id|url|username|password"
 */
JNIEXPORT jobjectArray JNICALL
Java_com_passwordmanager_NativeLib_nativeGetAllCredentials(
    JNIEnv *env, jobject thiz)
{
    (void)thiz;

    if (!g_vault_unlocked) {
        return NULL;
    }

    /* Count non-deleted entries */
    uint32_t active_count = 0;
    for (uint32_t i = 0; i < g_vault.count; i++) {
        if (!g_vault.entries[i].deleted) {
            active_count++;
        }
    }

    jclass string_class = (*env)->FindClass(env, "java/lang/String");
    jobjectArray jarray = (*env)->NewObjectArray(env, (jsize)active_count,
                                                  string_class, NULL);
    if (!jarray) {
        return NULL;
    }

    char entry_buf[MAX_URL_LEN + MAX_USERNAME_LEN + MAX_PASSWORD_LEN + 64];
    jsize idx = 0;

    for (uint32_t i = 0; i < g_vault.count; i++) {
        if (g_vault.entries[i].deleted) {
            continue;
        }

        snprintf(entry_buf, sizeof(entry_buf), "%u|%s|%s|%s",
                 g_vault.entries[i].id, g_vault.entries[i].url,
                 g_vault.entries[i].username, g_vault.entries[i].password);

        jstring jentry = (*env)->NewStringUTF(env, entry_buf);
        (*env)->SetObjectArrayElement(env, jarray, idx, jentry);
        (*env)->DeleteLocalRef(env, jentry);

        platform_secure_zero(entry_buf, sizeof(entry_buf));
        idx++;
    }

    return jarray;
}

/**
 * nativeClipCopy(String value) -> boolean
 *
 * Copies the given value to the clipboard with 30-second auto-clear.
 */
JNIEXPORT jboolean JNICALL
Java_com_passwordmanager_NativeLib_nativeClipCopy(
    JNIEnv *env, jobject thiz, jstring jvalue)
{
    (void)thiz;

    char value[MAX_PASSWORD_LEN + 1];
    if (!jstring_to_utf8(env, jvalue, value, sizeof(value))) {
        return JNI_FALSE;
    }

    size_t len = strlen(value);
    ClipResult cr = clip_copy(value, len);
    platform_secure_zero(value, sizeof(value));

    return (cr == CLIP_OK) ? JNI_TRUE : JNI_FALSE;
}

/**
 * nativeClipClear() -> void
 *
 * Immediately clears the clipboard.
 */
JNIEXPORT void JNICALL
Java_com_passwordmanager_NativeLib_nativeClipClear(
    JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;

    clip_clear();
}

/**
 * nativeClipGetRemaining() -> int
 *
 * Returns the number of seconds remaining before clipboard auto-clear.
 */
JNIEXPORT jint JNICALL
Java_com_passwordmanager_NativeLib_nativeClipGetRemaining(
    JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;

    return (jint)clip_get_remaining_seconds();
}

/**
 * nativeClipTick() -> void
 *
 * Advances the clipboard auto-clear timer by one second.
 * Should be called from a periodic Android timer/handler.
 */
JNIEXPORT void JNICALL
Java_com_passwordmanager_NativeLib_nativeClipTick(
    JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;

    clip_tick();
}

#endif /* __ANDROID__ || PLATFORM_ANDROID */