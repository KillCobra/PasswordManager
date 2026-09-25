/**
 * test_master_password.c - Unit tests for master password validation
 *
 * Tests:
 * - Password length validation (min 8 characters)
 * - Progressive delay failure tracking
 * - Success resets failure counter
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "credential.h"

/* Track platform_sleep_ms calls for testing without actual delays */
static uint32_t g_last_sleep_ms = 0;
static uint32_t g_sleep_call_count = 0;

/* Override platform_sleep_ms for testing */
void platform_sleep_ms(uint32_t ms)
{
    g_last_sleep_ms = ms;
    g_sleep_call_count++;
}

static void reset_sleep_tracking(void)
{
    g_last_sleep_ms = 0;
    g_sleep_call_count = 0;
}

/* ─── Test: Password length validation ────────────────────────────────────── */

static void test_reject_empty_password(void)
{
    assert(!master_password_validate("", 0));
    printf("  PASS: reject empty password\n");
}

static void test_reject_null_password(void)
{
    assert(!master_password_validate(NULL, 0));
    printf("  PASS: reject NULL password\n");
}

static void test_reject_short_passwords(void)
{
    assert(!master_password_validate("a", 1));
    assert(!master_password_validate("ab", 2));
    assert(!master_password_validate("abc", 3));
    assert(!master_password_validate("abcd", 4));
    assert(!master_password_validate("abcde", 5));
    assert(!master_password_validate("abcdef", 6));
    assert(!master_password_validate("abcdefg", 7));
    printf("  PASS: reject passwords shorter than 8 chars\n");
}

static void test_accept_exactly_8_chars(void)
{
    assert(master_password_validate("abcdefgh", 8));
    printf("  PASS: accept password of exactly 8 chars\n");
}

static void test_accept_longer_passwords(void)
{
    assert(master_password_validate("abcdefghi", 9));
    assert(master_password_validate("abcdefghijklmnop", 16));
    assert(master_password_validate("a very long master password indeed!", 35));
    printf("  PASS: accept passwords longer than 8 chars\n");
}

/* ─── Test: Progressive delay ─────────────────────────────────────────────── */

static void test_failure_counter_increments(void)
{
    /* Reset state */
    master_password_record_success();
    assert(master_password_get_failure_count() == 0);

    reset_sleep_tracking();
    master_password_record_failure();
    assert(master_password_get_failure_count() == 1);
    assert(g_last_sleep_ms == 1000);

    reset_sleep_tracking();
    master_password_record_failure();
    assert(master_password_get_failure_count() == 2);
    assert(g_last_sleep_ms == 2000);

    reset_sleep_tracking();
    master_password_record_failure();
    assert(master_password_get_failure_count() == 3);
    assert(g_last_sleep_ms == 3000);

    printf("  PASS: failure counter increments and delay scales\n");
}

static void test_success_resets_counter(void)
{
    /* Set up some failures first */
    master_password_record_success(); /* reset */
    master_password_record_failure();
    master_password_record_failure();
    assert(master_password_get_failure_count() == 2);

    /* Success should reset */
    master_password_record_success();
    assert(master_password_get_failure_count() == 0);

    printf("  PASS: success resets failure counter\n");
}

static void test_delay_after_reset(void)
{
    /* After reset, first failure should delay 1 second */
    master_password_record_success();
    reset_sleep_tracking();

    master_password_record_failure();
    assert(master_password_get_failure_count() == 1);
    assert(g_last_sleep_ms == 1000);
    assert(g_sleep_call_count == 1);

    printf("  PASS: delay correct after counter reset\n");
}

/* ─── Main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("=== Master Password Validation Tests ===\n\n");

    printf("[Length Validation]\n");
    test_reject_empty_password();
    test_reject_null_password();
    test_reject_short_passwords();
    test_accept_exactly_8_chars();
    test_accept_longer_passwords();

    printf("\n[Progressive Delay]\n");
    test_failure_counter_increments();
    test_success_resets_counter();
    test_delay_after_reset();

    printf("\n=== All tests passed! ===\n");
    return 0;
}
