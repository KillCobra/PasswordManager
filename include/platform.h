/**
 * platform.h - Platform Abstraction Layer
 *
 * Declares all platform-specific functions for file I/O, clipboard,
 * networking, secure memory, random bytes, and timing.
 * Implementations are in platform/platform_win32.c and platform/platform_android.c.
 */

#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─── File Operations ─────────────────────────────────────────────────────── */

/**
 * Check if a file exists at the given path.
 * Returns true if the file exists, false otherwise.
 */
bool platform_file_exists(const char *path);

/**
 * Atomically write data to a file using temp-file + rename pattern.
 * Steps:
 *   1. Write data to a temporary file (<path>.tmp)
 *   2. Flush/sync to ensure data is on disk
 *   3. Atomically rename temp file to target path
 *   4. On failure, delete temp file and return false
 * Returns true on success, false on failure.
 */
bool platform_file_write_atomic(const char *path, const uint8_t *data, size_t len);

/**
 * Read entire file contents into a newly allocated buffer.
 * Caller is responsible for freeing *data.
 * Returns true on success, false on failure.
 */
bool platform_file_read(const char *path, uint8_t **data, size_t *len);

/* ─── Clipboard ───────────────────────────────────────────────────────────── */

/**
 * Set the system clipboard to the given text.
 * Returns true on success, false on failure.
 */
bool platform_clipboard_set(const char *text, size_t len);

/**
 * Clear the system clipboard contents.
 * Returns true on success, false on failure.
 */
bool platform_clipboard_clear(void);

/* ─── Networking ──────────────────────────────────────────────────────────── */

/**
 * Create a TCP listening socket bound to the given IP and port.
 * Returns socket descriptor on success, -1 on failure.
 */
int platform_tcp_listen(const char *ip, uint16_t port);

/**
 * Connect to a TCP server at the given IP and port.
 * Returns socket descriptor on success, -1 on failure.
 */
int platform_tcp_connect(const char *ip, uint16_t port);

/**
 * Send data over a TCP socket.
 * Returns number of bytes sent on success, -1 on failure.
 */
int platform_tcp_send(int sock, const uint8_t *data, size_t len);

/**
 * Receive data from a TCP socket.
 * Stores number of bytes received in *received.
 * Returns 0 on success, -1 on failure.
 */
int platform_tcp_recv(int sock, uint8_t *buf, size_t buf_len, size_t *received);

/**
 * Close a TCP socket.
 */
void platform_tcp_close(int sock);

/* ─── Secure Memory ───────────────────────────────────────────────────────── */

/**
 * Securely zero memory, preventing compiler optimizations from
 * removing the operation.
 */
void platform_secure_zero(void *ptr, size_t len);

/* ─── Random Bytes ────────────────────────────────────────────────────────── */

/**
 * Fill buffer with cryptographically secure random bytes from the OS CSPRNG.
 * Returns true on success, false on failure.
 */
bool platform_random_bytes(uint8_t *buf, size_t len);

/* ─── Timing ──────────────────────────────────────────────────────────────── */

/**
 * Get current Unix timestamp in seconds since epoch.
 */
uint64_t platform_time_unix(void);

/**
 * Sleep for the specified number of milliseconds.
 */
void platform_sleep_ms(uint32_t ms);



#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_H */
