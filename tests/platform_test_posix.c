/**
 * platform_test_posix.c - Minimal POSIX platform layer for the test runner.
 *
 * The unit/property tests exercise the core (encryption, vault, credential,
 * sync merge) which only needs file I/O, random bytes, timing, sleep, and
 * secure-zero from platform.h. They do NOT use the networking or real
 * clipboard functions. This slim implementation provides exactly what the
 * core needs using portable POSIX calls, avoiding the socket/getaddrinfo
 * surface of the full platform_android.c so the CI test build is robust.
 *
 * Used only by build_tests.sh / the C Tests CI job (Linux/macOS).
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>

/* ─── File Operations ─────────────────────────────────────────────────────── */

bool platform_file_exists(const char *path)
{
    if (!path) return false;
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
}

bool platform_file_write_atomic(const char *path, const uint8_t *data, size_t len)
{
    if (!path || (!data && len > 0)) return false;

    size_t path_len = strlen(path);
    char *tmp = (char *)malloc(path_len + 5);
    if (!tmp) return false;
    snprintf(tmp, path_len + 5, "%s.tmp", path);

    bool ok = false;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { free(tmp); return false; }

    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0) { if (errno == EINTR) continue; close(fd); unlink(tmp); free(tmp); return false; }
        off += (size_t)w;
    }
    if (fsync(fd) != 0) { close(fd); unlink(tmp); free(tmp); return false; }
    close(fd);

    if (rename(tmp, path) == 0) ok = true;
    else unlink(tmp);

    free(tmp);
    return ok;
}

bool platform_file_read(const char *path, uint8_t **data, size_t *len)
{
    if (!path || !data || !len) return false;
    *data = NULL; *len = 0;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return false; }
    size_t size = (size_t)st.st_size;
    if (size == 0) { close(fd); return true; }

    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) { close(fd); return false; }

    size_t total = 0;
    while (total < size) {
        ssize_t r = read(fd, buf + total, size - total);
        if (r < 0) { if (errno == EINTR) continue; free(buf); close(fd); return false; }
        if (r == 0) break;
        total += (size_t)r;
    }
    close(fd);
    *data = buf; *len = total;
    return true;
}

/* ─── Clipboard (no-op in tests) ──────────────────────────────────────────── */

bool platform_clipboard_set(const char *text, size_t len) { (void)text; (void)len; return true; }
bool platform_clipboard_clear(void) { return true; }

/* ─── Networking (not used by the core/tests; provide stubs for linkage) ──── */

int  platform_tcp_listen(const char *ip, uint16_t port) { (void)ip; (void)port; return -1; }
int  platform_tcp_connect(const char *ip, uint16_t port) { (void)ip; (void)port; return -1; }
int  platform_tcp_send(int s, const uint8_t *d, size_t n) { (void)s; (void)d; (void)n; return -1; }
int  platform_tcp_recv(int s, uint8_t *b, size_t n, size_t *r) { (void)s; (void)b; (void)n; if (r) *r = 0; return -1; }
void platform_tcp_close(int s) { (void)s; }

/* ─── Secure Memory ───────────────────────────────────────────────────────── */

void platform_secure_zero(void *ptr, size_t len)
{
    if (ptr && len > 0) {
        volatile unsigned char *p = (volatile unsigned char *)ptr;
        while (len--) *p++ = 0;
    }
}

/* ─── Random Bytes ────────────────────────────────────────────────────────── */

bool platform_random_bytes(uint8_t *buf, size_t len)
{
    if (!buf || len == 0) return false;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;
    size_t total = 0;
    while (total < len) {
        ssize_t r = read(fd, buf + total, len - total);
        if (r < 0) { if (errno == EINTR) continue; close(fd); return false; }
        if (r == 0) { close(fd); return false; }
        total += (size_t)r;
    }
    close(fd);
    return true;
}

/* ─── Timing ──────────────────────────────────────────────────────────────── */

uint64_t platform_time_unix(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec;
}

void platform_sleep_ms(uint32_t ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) { }
}
