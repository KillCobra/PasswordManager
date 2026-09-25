/*
 * Argon2 reference implementation - Main entry point
 * Based on the reference C implementation by the Argon2 authors.
 * https://github.com/P-H-C/phc-winner-argon2
 * License: CC0 1.0 Universal / Apache 2.0
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "argon2.h"
#include "core.h"

int argon2id_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                      const uint32_t parallelism, const void *pwd,
                      const size_t pwdlen, const void *salt,
                      const size_t saltlen, void *hash,
                      const size_t hashlen) {
    argon2_context context;
    memset(&context, 0, sizeof(argon2_context));

    context.out = (uint8_t *)hash;
    context.outlen = (uint32_t)hashlen;
    context.pwd = (uint8_t *)pwd;
    context.pwdlen = (uint32_t)pwdlen;
    context.salt = (uint8_t *)salt;
    context.saltlen = (uint32_t)saltlen;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = parallelism;
    context.threads = parallelism;
    context.version = ARGON2_VERSION_NUMBER;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = 0;

    return argon2_ctx(&context, Argon2_id);
}

const char *argon2_error_message(int error_code) {
    switch (error_code) {
    case ARGON2_OK:
        return "OK";
    case ARGON2_OUTPUT_PTR_NULL:
        return "Output pointer is NULL";
    case ARGON2_OUTPUT_TOO_SHORT:
        return "Output is too short";
    case ARGON2_OUTPUT_TOO_LONG:
        return "Output is too long";
    case ARGON2_PWD_TOO_SHORT:
        return "Password is too short";
    case ARGON2_PWD_TOO_LONG:
        return "Password is too long";
    case ARGON2_SALT_TOO_SHORT:
        return "Salt is too short";
    case ARGON2_SALT_TOO_LONG:
        return "Salt is too long";
    case ARGON2_TIME_TOO_SMALL:
        return "Time cost is too small";
    case ARGON2_TIME_TOO_LARGE:
        return "Time cost is too large";
    case ARGON2_MEMORY_TOO_LITTLE:
        return "Memory cost is too small";
    case ARGON2_MEMORY_TOO_MUCH:
        return "Memory cost is too large";
    case ARGON2_LANES_TOO_FEW:
        return "Too few lanes";
    case ARGON2_LANES_TOO_MANY:
        return "Too many lanes";
    case ARGON2_MEMORY_ALLOCATION_ERROR:
        return "Memory allocation error";
    case ARGON2_THREAD_FAIL:
        return "Threading failure";
    default:
        return "Unknown error";
    }
}
