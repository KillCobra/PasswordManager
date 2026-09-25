/**
 * platform_android.c - Android/Linux platform implementation
 *
 * Implements platform abstraction using POSIX/Linux APIs:
 * - File I/O: open, write, read, rename
 * - Clipboard: Android clipboard via JNI (stub - actual impl in JNI bridge)
 * - Networking: BSD sockets
 * - Secure memory: explicit_bzero
 * - Random: /dev/urandom
 * - Timing: clock_gettime, nanosleep
 */

#if defined(__ANDROID__) || defined(__linux__)

#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

/* ─── File Operations ─────────────────────────────────────────────────────── */

bool platform_file_exists(const char *path)
{
    if (!path) {
        return false;
    }
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
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
    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        goto cleanup;
    }

    if (len > 0) {
        size_t remaining = len;
        const uint8_t *ptr = data;

        while (remaining > 0) {
            ssize_t written = write(fd, ptr, remaining);
            if (written < 0) {
                if (errno == EINTR) {
                    continue; /* Retry on interrupt */
                }
                close(fd);
                goto cleanup_delete;
            }
            ptr += written;
            remaining -= (size_t)written;
        }
    }

    /* Step 2: Flush to disk with fsync */
    if (fsync(fd) != 0) {
        close(fd);
        goto cleanup_delete;
    }

    close(fd);

    /* Step 3: Atomically rename temp file to target path */
    if (rename(tmp_path, path) != 0) {
        goto cleanup_delete;
    }

    success = true;
    goto cleanup;

cleanup_delete:
    unlink(tmp_path);

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

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }

    /* Get file size */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return false;
    }

    size_t size = (size_t)st.st_size;
    if (size == 0) {
        /* Empty file */
        close(fd);
        *data = NULL;
        *len = 0;
        return true;
    }

    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) {
        close(fd);
        return false;
    }

    size_t total_read = 0;
    while (total_read < size) {
        ssize_t bytes_read = read(fd, buf + total_read, size - total_read);
        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue; /* Retry on interrupt */
            }
            free(buf);
            close(fd);
            return false;
        }
        if (bytes_read == 0) {
            break; /* EOF */
        }
        total_read += (size_t)bytes_read;
    }

    close(fd);
    *data = buf;
    *len = total_read;
    return true;
}

/* ─── Clipboard ───────────────────────────────────────────────────────────── */

/*
 * On Android, clipboard access requires the Android framework (Context).
 * The actual clipboard operations are handled through the JNI bridge
 * (platform/jni_bridge.c) which calls into the Android ClipboardManager.
 * These implementations provide a POSIX-level stub that the JNI bridge
 * overrides at runtime.
 */

/* Weak symbols allow the JNI bridge to override these */
#if defined(__ANDROID__)

/* On Android, these are implemented via JNI in jni_bridge.c.
 * Provide default stubs that return failure if JNI is not available. */
__attribute__((weak))
bool platform_clipboard_set(const char *text, size_t len)
{
    (void)text;
    (void)len;
    return false; /* No clipboard access without Android framework */
}

__attribute__((weak))
bool platform_clipboard_clear(void)
{
    return false; /* No clipboard access without Android framework */
}

#else
/* Linux desktop: use xclip/xsel as a simple fallback */

bool platform_clipboard_set(const char *text, size_t len)
{
    if (!text || len == 0) {
        return false;
    }

    FILE *pipe = popen("xclip -selection clipboard 2>/dev/null", "w");
    if (!pipe) {
        /* Try xsel as fallback */
        pipe = popen("xsel --clipboard --input 2>/dev/null", "w");
        if (!pipe) {
            return false;
        }
    }

    size_t written = fwrite(text, 1, len, pipe);
    int result = pclose(pipe);

    return (written == len && result == 0);
}

bool platform_clipboard_clear(void)
{
    /* Write empty string to clipboard */
    FILE *pipe = popen("xclip -selection clipboard 2>/dev/null", "w");
    if (!pipe) {
        pipe = popen("xsel --clipboard --clear 2>/dev/null", "w");
        if (!pipe) {
            return false;
        }
    }

    int result = pclose(pipe);
    return (result == 0);
}

#endif /* __ANDROID__ */

/* ─── Networking ──────────────────────────────────────────────────────────── */

int platform_tcp_listen(const char *ip, uint16_t port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    /* Allow address reuse */
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (ip && ip[0] != '\0') {
        if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
            close(sock);
            return -1;
        }
    } else {
        addr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    if (listen(sock, SOMAXCONN) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

int platform_tcp_connect(const char *ip, uint16_t port)
{
    if (!ip) {
        return -1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    /* Set 30-second timeout */
    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

int platform_tcp_send(int sock, const uint8_t *data, size_t len)
{
    if (sock < 0 || !data || len == 0) {
        return -1;
    }

    ssize_t sent = send(sock, data, len, MSG_NOSIGNAL);
    if (sent < 0) {
        return -1;
    }
    return (int)sent;
}

int platform_tcp_recv(int sock, uint8_t *buf, size_t buf_len, size_t *received)
{
    if (sock < 0 || !buf || buf_len == 0 || !received) {
        return -1;
    }

    ssize_t result = recv(sock, buf, buf_len, 0);
    if (result < 0) {
        *received = 0;
        return -1;
    }

    *received = (size_t)result;
    return 0;
}

void platform_tcp_close(int sock)
{
    if (sock >= 0) {
        close(sock);
    }
}

/* ─── Secure Memory ───────────────────────────────────────────────────────── */

void platform_secure_zero(void *ptr, size_t len)
{
    if (ptr && len > 0) {
        /* Volatile pointer prevents compiler from optimizing away the zeroing */
        volatile unsigned char *p = (volatile unsigned char *)ptr;
        while (len--) {
            *p++ = 0;
        }
    }
}

/* ─── Random Bytes ────────────────────────────────────────────────────────── */

bool platform_random_bytes(uint8_t *buf, size_t len)
{
    if (!buf || len == 0) {
        return false;
    }

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return false;
    }

    size_t total_read = 0;
    while (total_read < len) {
        ssize_t bytes_read = read(fd, buf + total_read, len - total_read);
        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return false;
        }
        if (bytes_read == 0) {
            close(fd);
            return false; /* Unexpected EOF from /dev/urandom */
        }
        total_read += (size_t)bytes_read;
    }

    close(fd);
    return true;
}

/* ─── Timing ──────────────────────────────────────────────────────────────── */

uint64_t platform_time_unix(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec;
}

void platform_sleep_ms(uint32_t ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;

    /* Handle interrupts */
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
        /* Continue sleeping */
    }
}

/* ─── Network Utilities ───────────────────────────────────────────────────── */

bool platform_get_local_ip(char *ip_buf, size_t buf_len)
{
    if (!ip_buf || buf_len < 16) {
        return false;
    }

    /*
     * On Android the phone is typically the hotspot provider (client role).
     * Use gethostname + getaddrinfo as a simple approach.
     * If no non-loopback address is found, return "0.0.0.0" as fallback.
     */
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strncpy(ip_buf, "0.0.0.0", buf_len - 1);
        ip_buf[buf_len - 1] = '\0';
        return false;
    }

    struct addrinfo hints;
    struct addrinfo *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0) {
        strncpy(ip_buf, "0.0.0.0", buf_len - 1);
        ip_buf[buf_len - 1] = '\0';
        return false;
    }

    bool found = false;
    for (struct addrinfo *ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        struct sockaddr_in *addr = (struct sockaddr_in *)ptr->ai_addr;
        uint32_t ip_val = ntohl(addr->sin_addr.s_addr);

        /* Skip loopback (127.x.x.x) */
        if ((ip_val >> 24) == 127) {
            continue;
        }

        /* Skip 0.0.0.0 */
        if (ip_val == 0) {
            continue;
        }

        if (inet_ntop(AF_INET, &addr->sin_addr, ip_buf, (socklen_t)buf_len)) {
            found = true;
            break;
        }
    }

    freeaddrinfo(result);

    if (!found) {
        strncpy(ip_buf, "0.0.0.0", buf_len - 1);
        ip_buf[buf_len - 1] = '\0';
    }

    return found;
}

int platform_tcp_accept(int listen_sock, uint32_t timeout_secs)
{
    if (listen_sock < 0) {
        return -1;
    }

    /* Use select() for timeout */
    if (timeout_secs > 0) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_sock, &read_fds);

        struct timeval tv;
        tv.tv_sec = (time_t)timeout_secs;
        tv.tv_usec = 0;

        int sel_result = select(listen_sock + 1, &read_fds, NULL, NULL, &tv);
        if (sel_result <= 0) {
            return -1; /* Timeout or error */
        }
    }

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_sock = accept(listen_sock,
                             (struct sockaddr *)&client_addr, &addr_len);
    if (client_sock < 0) {
        return -1;
    }

    /* Set timeouts on the accepted socket */
    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    return client_sock;
}

#endif /* __ANDROID__ || __linux__ */
