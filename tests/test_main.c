/**
 * test_main.c - Test runner for all property-based test suites
 *
 * Invokes all test suites and returns non-zero on any failure.
 * Compile with -DTEST_NO_MAIN to suppress individual main() functions
 * in each test file.
 */

#include <stdio.h>
#include <stdlib.h>

/* Forward declarations of test suite runners */
extern int run_encryption_tests(void);
extern int run_credential_tests(void);
extern int run_validation_tests(void);
extern int run_sync_tests(void);
extern int run_vault_tests(void);

int main(void)
{
    int total_failures = 0;

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  Cross-Platform Password Manager - Property Test Suite      ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    /* Run all test suites */
    total_failures += run_encryption_tests();
    printf("\n");

    total_failures += run_credential_tests();
    printf("\n");

    total_failures += run_validation_tests();
    printf("\n");

    total_failures += run_sync_tests();
    printf("\n");

    total_failures += run_vault_tests();
    printf("\n");

    /* Summary */
    printf("══════════════════════════════════════════════════════════════\n");
    if (total_failures == 0) {
        printf("  ALL TESTS PASSED\n");
    } else {
        printf("  TOTAL FAILURES: %d\n", total_failures);
    }
    printf("══════════════════════════════════════════════════════════════\n");

    return total_failures == 0 ? 0 : 1;
}
