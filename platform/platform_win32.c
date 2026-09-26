
/**
 * platform_win32.c - Windows platform implementation
 *
 * Implements platform abstraction using Win32 APIs:
 * - File I/O: CreateFile, WriteFile, ReadFile, MoveFileEx
 * - Clipboard: OpenClipboard, SetClipboardData
 * - Networking: Winsock2
 * - Secure memory: SecureZeroMemory
 * - Random: BCryptGenRandom
 * - Timing: GetSystemTimeAsFileTime, Sleep
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "platform.h"
#include <windows.h>
#include <bcrypt.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ws2_32.lib")

/* ─── File Operations ─────────────────────────────────────────────────────── */

bool platform_file_exists(const char *path)
{
    DWORD attrs = GetFileAttributesA(path);
    return (attrs != INVALID_FILE_ATTRIBUTES &&
            !(attrs & FILE_ATTRIBUTE_DIRECTORY));
}

bool platform_file_write_atomic(const char *path, const uint8_t *data, size_t len)
{
    if (!path || (!data && len > 0)) {
        return false;
    }

    /* Build temp file path: <path>.tmp */
    size_t path_len = strlen(path);
    char *tmp_path = (char *)malloc(path_len + 5); /* ".tmp" + null */
    if (!tmp_path) {
        return false;
    }
    snprintf(tmp_path, path_len + 5, "%s.tmp", path);

    bool success = false;

    /* Step 1: Write data to temporary file */
    HANDLE hFile = CreateFileA(
        tmp_path,
        GENERIC_WRITE,
        0,                          /* No sharing */
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }

    if (len > 0) {
        DWORD written = 0;
        size_t remaining = len;
        const uint8_t *ptr = data;

        while (remaining > 0) {
            DWORD to_write = (remaining > 0xFFFFFFFF) ? 0xFFFFFFFF : (DWORD)remaining;
            if (!WriteFile(hFile, ptr, to_write, &written, NULL)) {
                CloseHandle(hFile);
                goto cleanup_delete;
            }
            ptr += written;
            remaining -= written;
        }
    }

    /* Step 2: Flush to disk */
    if (!FlushFileBuffers(hFile)) {
        CloseHandle(hFile);
        goto cleanup_delete;
    }

    CloseHandle(hFile);

    /* Step 3: Atomically rename temp file to target path */
    if (!MoveFileExA(tmp_path, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        goto cleanup_delete;
    }

    success = true;
    goto cleanup;

cleanup_delete:
    DeleteFileA(tmp_path);

cleanup:
    free(tmp_path);
    return success;
}

bool platform_file_read(const char *path, uint8_t **data, size_t *len)
{
    if (!path || !data || !len) {
        return false;
    }

    *data = NULL;
    *len = 0;

    HANDLE hFile = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(hFile, &file_size)) {
        CloseHandle(hFile);
        return false;
    }

    size_t size = (size_t)file_size.QuadPart;
    if (size == 0) {
        /* Empty file */
        CloseHandle(hFile);
        *data = NULL;
        *len = 0;
        return true;
    }

    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) {
        CloseHandle(hFile);
        return false;
    }

    size_t total_read = 0;
    while (total_read < size) {
        DWORD to_read = ((size - total_read) > 0xFFFFFFFF) ? 0xFFFFFFFF : (DWORD)(size - total_read);
        DWORD bytes_read = 0;
        if (!ReadFile(hFile, buf + total_read, to_read, &bytes_read, NULL) || bytes_read == 0) {
            free(buf);
            CloseHandle(hFile);
            return false;
        }
        total_read += bytes_read;
    }

    CloseHandle(hFile);
    *data = buf;
    *len = size;
    return true;
}

/* ─── Clipboard ───────────────────────────────────────────────────────────── */

bool platform_clipboard_set(const char *text, size_t len)
{
    if (!text || len == 0) {
        return false;
    }

    /* The stored text is UTF-8. Convert to UTF-16 and place it on the
     * clipboard as CF_UNICODETEXT so non-ASCII characters (accents, symbols,
     * non-Latin scripts) are preserved instead of being mangled by the ANSI
     * code page (which CF_TEXT would use). */
    int wlen = MultiByteToWideChar(CP_UTF8, 0, text, (int)len, NULL, 0);
    if (wlen < 0) {
        return false;
    }

    if (!OpenClipboard(NULL)) {
        return false;
    }

    EmptyClipboard();

    /* Allocate room for the wide text plus a null terminator. */
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, ((size_t)wlen + 1) * sizeof(wchar_t));
    if (!hMem) {
        CloseClipboard();
        return false;
    }

    wchar_t *pMem = (wchar_t *)GlobalLock(hMem);
    if (!pMem) {
        GlobalFree(hMem);
        CloseClipboard();
        return false;
    }

    if (wlen > 0) {
        MultiByteToWideChar(CP_UTF8, 0, text, (int)len, pMem, wlen);
    }
    pMem[wlen] = L'\0';
    GlobalUnlock(hMem);

    if (!SetClipboardData(CF_UNICODETEXT, hMem)) {
        GlobalFree(hMem);
        CloseClipboard();
        return false;
    }

    CloseClipboard();
    return true;
}

bool platform_clipboard_clear(void)
{
    if (!OpenClipboard(NULL)) {
        return false;
    }

    EmptyClipboard();
    CloseClipboard();
    return true;
}

/* ─── Networking ──────────────────────────────────────────────────────────── */

static bool winsock_initialized = false;

static bool ensure_winsock(void)
{
    if (!winsock_initialized) {
        WSADATA wsa_data;
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            return false;
        }
        winsock_initialized = true;
    }
    return true;
}

int platform_tcp_listen(const char *ip, uint16_t port)
{
    if (!ensure_winsock()) {
        return -1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return -1;
    }

    /* Allow address reuse */
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (ip && ip[0] != '\0') {
        if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
            closesocket(sock);
            return -1;
        }
    } else {
        addr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return -1;
    }

    if (listen(sock, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(sock);
        return -1;
    }

    return (int)sock;
}

int platform_tcp_connect(const char *ip, uint16_t port)
{
    if (!ensure_winsock() || !ip) {
        return -1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        closesocket(sock);
        return -1;
    }

    /* Set 30-second timeout for connect */
    DWORD timeout = 30000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return -1;
    }

    return (int)sock;
}

int platform_tcp_send(int sock, const uint8_t *data, size_t len)
{
    if (sock < 0 || !data || len == 0) {
        return -1;
    }

    int sent = send((SOCKET)sock, (const char *)data, (int)len, 0);
    if (sent == SOCKET_ERROR) {
        return -1;
    }
    return sent;
}

int platform_tcp_recv(int sock, uint8_t *buf, size_t buf_len, size_t *received)
{
    if (sock < 0 || !buf || buf_len == 0 || !received) {
        return -1;
    }

    int result = recv((SOCKET)sock, (char *)buf, (int)buf_len, 0);
    if (result == SOCKET_ERROR || result < 0) {
        *received = 0;
        return -1;
    }

    *received = (size_t)result;
    return 0;
}

void platform_tcp_close(int sock)
{
    if (sock >= 0) {
        closesocket((SOCKET)sock);
    }
}

/* ─── Secure Memory ───────────────────────────────────────────────────────── */

void platform_secure_zero(void *ptr, size_t len)
{
    if (ptr && len > 0) {
        SecureZeroMemory(ptr, len);
    }
}

/* ─── Random Bytes ────────────────────────────────────────────────────────── */

bool platform_random_bytes(uint8_t *buf, size_t len)
{
    if (!buf || len == 0) {
        return false;
    }

    NTSTATUS status = BCryptGenRandom(
        NULL,
        buf,
        (ULONG)len,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    return (status == 0); /* STATUS_SUCCESS == 0 */
}

/* ─── Timing ──────────────────────────────────────────────────────────────── */

uint64_t platform_time_unix(void)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);

    /* FILETIME is 100-nanosecond intervals since Jan 1, 1601.
     * Unix epoch is Jan 1, 1970. Difference is 11644473600 seconds. */
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    /* Convert to seconds and adjust for Unix epoch */
    return (uint64_t)((uli.QuadPart / 10000000ULL) - 11644473600ULL);
}

void platform_sleep_ms(uint32_t ms)
{
    Sleep((DWORD)ms);
}

#endif /* _WIN32 */