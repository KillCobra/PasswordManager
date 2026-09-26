/**
 * test_crypto_kat.c - Known-Answer Tests for the vendored crypto primitives.
 *
 * These are deterministic checks (no property harness) that pin the vendored
 * AES-256-GCM and Argon2id implementations to published expected outputs, so a
 * regression or an accidental swap of the vendored code is caught immediately.
 *
 * AES-256-GCM vector: McGrew & Viega, "The Galois/Counter Mode of Operation
 * (GCM)", Test Case 14 (also widely reproduced in NIST CAVP GCM vectors):
 *   Key = 00..00 (32 bytes), IV = 00..00 (12 bytes),
 *   PT  = 00..00 (16 bytes), AAD = empty
 *   CT  = cea7403d4d606b6e074ec5d3baf39d18
 *   Tag = d0d1c8a799996bf0265b98b5d48ab919
 *
 * Argon2id: a self-consistency check (same inputs -> same output; different
 * salt -> different output) plus verification that our KDF wrapper produces a
 * stable 32-byte key. (A full RFC 9106 vector requires secret/AD inputs the
 * wrapper does not expose, so we pin determinism instead.)
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "gcm.h"
#include "encryption.h"

static int hexeq(const uint8_t *got, const char *hex, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char b[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        unsigned v;
        sscanf(b, "%2x", &v);
        if (got[i] != (uint8_t)v) return 0;
    }
    return 1;
}

static int kat_aes256_gcm(void)
{
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t pt[16] = {0};
    uint8_t ct[16] = {0};
    uint8_t tag[16] = {0};

    gcm_context ctx;
    if (gcm_init(&ctx, key) != 0) {
        printf("  FAILED: AES-256-GCM KAT (gcm_init)\n");
        return 1;
    }
    if (gcm_encrypt(&ctx, nonce, pt, sizeof(pt), NULL, 0, ct, tag) != 0) {
        printf("  FAILED: AES-256-GCM KAT (gcm_encrypt)\n");
        gcm_free(&ctx);
        return 1;
    }

    int ok = hexeq(ct, "cea7403d4d606b6e074ec5d3baf39d18", 16)
          && hexeq(tag, "d0d1c8a799996bf0265b98b5d48ab919", 16);

    /* Round-trip: the same context must decrypt+verify back to plaintext. */
    uint8_t dec[16] = {0};
    int dec_ok = (gcm_decrypt(&ctx, nonce, ct, sizeof(ct), NULL, 0, tag, dec) == 0)
              && (memcmp(dec, pt, sizeof(pt)) == 0);

    /* Tag tamper must fail. */
    uint8_t bad_tag[16];
    memcpy(bad_tag, tag, 16);
    bad_tag[0] ^= 0x01;
    int tamper_rejected = (gcm_decrypt(&ctx, nonce, ct, sizeof(ct), NULL, 0, bad_tag, dec) != 0);

    gcm_free(&ctx);

    if (ok && dec_ok && tamper_rejected) {
        printf("  PASSED: AES-256-GCM known-answer + round-trip + tamper\n");
        return 0;
    }
    printf("  FAILED: AES-256-GCM KAT (ct/tag mismatch=%d decrypt=%d tamper=%d)\n",
           !ok, !dec_ok, !tamper_rejected);
    return 1;
}

static int kat_argon2id(void)
{
    const char *pw = "correct horse battery staple";
    uint8_t salt_a[ENC_SALT_SIZE];
    uint8_t salt_b[ENC_SALT_SIZE];
    for (int i = 0; i < ENC_SALT_SIZE; i++) { salt_a[i] = (uint8_t)i; salt_b[i] = (uint8_t)(0xFF - i); }

    DerivedKey k1, k2, k3;
    EncResult r1 = enc_derive_key(pw, strlen(pw), salt_a, &k1);
    EncResult r2 = enc_derive_key(pw, strlen(pw), salt_a, &k2);   /* same inputs */
    EncResult r3 = enc_derive_key(pw, strlen(pw), salt_b, &k3);   /* different salt */

    if (r1 != ENC_OK || r2 != ENC_OK || r3 != ENC_OK) {
        printf("  FAILED: Argon2id KAT (derive returned error)\n");
        return 1;
    }

    int deterministic = (memcmp(k1.key, k2.key, ENC_KEY_SIZE) == 0);
    int salt_matters  = (memcmp(k1.key, k3.key, ENC_KEY_SIZE) != 0);

    /* Key must not be all zeros. */
    int nonzero = 0;
    for (int i = 0; i < ENC_KEY_SIZE; i++) if (k1.key[i]) { nonzero = 1; break; }

    if (deterministic && salt_matters && nonzero) {
        printf("  PASSED: Argon2id determinism + salt-sensitivity\n");
        return 0;
    }
    printf("  FAILED: Argon2id KAT (deterministic=%d salt_matters=%d nonzero=%d)\n",
           deterministic, salt_matters, nonzero);
    return 1;
}

int run_crypto_kat_tests(void)
{
    int failures = 0;
    printf("=== Crypto Known-Answer Tests ===\n\n");
    failures += kat_aes256_gcm();
    failures += kat_argon2id();
    printf("\n=== Crypto KAT: %d failures ===\n", failures);
    return failures;
}

#ifndef TEST_NO_MAIN
int main(void)
{
    return run_crypto_kat_tests() == 0 ? 0 : 1;
}
#endif
