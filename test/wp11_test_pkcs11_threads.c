/* wp11_test_pkcs11_threads.c -- thread-safety tests for the wolfP11 PKCS#11 layer
 *
 * wolfP11-6v0: concurrent sign/verify
 * wolfP11-7by: concurrent login/logout
 * wolfP11-qnt: concurrent init/finalize
 *
 * Compile with -DWOLFP11_CFG_TEST -DWOLFP11_CFG_TEST_THREADS to enable.
 * Returns 0 on full pass, or the count of failures.
 */

/* POSIX barriers require _POSIX_C_SOURCE 200809L */
#define _POSIX_C_SOURCE 200809L

#include "test/wp11_test_pkcs11_threads.h"

#ifdef WOLFP11_CFG_TEST_THREADS

/* wolfssl header order: options.h must precede all other wolfssl includes */
#include <wolfssl/options.h>
#include "wolfp11/wp11_pkcs11.h"
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Test helper declared in src/wp11_pkcs11.c under WOLFP11_CFG_TEST.
 * Exports the soft key's EC public key in X9.62 uncompressed format.
 * Acquires the global lock internally; call from outside the PKCS#11 lock. */
int wp11_test_soft_export_pub_x963(CK_OBJECT_HANDLE hKey,
                                    uint8_t *out, CK_ULONG *outlen);

/* -------------------------------------------------------------------------
 * Shared constants
 * ---------------------------------------------------------------------- */

/* 32-byte fixed hash for sign tests -- independent of code under test */
static const uint8_t test_hash[32] = {
    0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67,
    0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
    0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc
};

static const CK_UTF8CHAR soft_pin[]  = "softtest";
static const CK_ULONG    soft_pinlen = 8;

static const CK_UTF8CHAR login_pin[]  = "1234";
static const CK_ULONG    login_pinlen = 4;

/* -------------------------------------------------------------------------
 * Shared helper
 * ---------------------------------------------------------------------- */

static int check(int pass, const char *label)
{
    printf("%s: %s\n", pass ? "PASS" : "FAIL", label);
    return pass ? 0 : 1;
}

/* =========================================================================
 * wolfP11-6v0: concurrent sign/verify
 * ====================================================================== */

/* ------------------------------------------------------------------
 * Test 1: N independent sign threads
 *
 * Each thread has its own session and key pair.  All threads start
 * simultaneously via a barrier, then loop 200 times signing test_hash
 * with CKM_ECDSA and verifying the result via wc_ecc_verify_hash using
 * the pre-exported public key (independent oracle).
 * ------------------------------------------------------------------ */

#define SIGN_THREAD_COUNT  8
#define SIGN_ITER          200

/* Per-thread context passed at pthread_create time */
typedef struct {
    pthread_barrier_t  *barrier;
    CK_SESSION_HANDLE   hSess;
    CK_OBJECT_HANDLE    hPriv;
    ecc_key             pub_oracle;   /* wolfCrypt ECC key, public-only */
    int                 oracle_ready; /* 1 if pub_oracle was imported */
} sign_thread_ctx_t;

static void *sign_thread_fn(void *arg)
{
    sign_thread_ctx_t *ctx  = (sign_thread_ctx_t *)arg;
    CK_MECHANISM       mech = { CKM_ECDSA, NULL_PTR, 0 };
    CK_BYTE            sig[128];
    CK_ULONG           siglen;
    CK_RV              rv;
    int                stat;
    int                ret;
    int                f = 0;
    int                i;

    pthread_barrier_wait(ctx->barrier);

    for (i = 0; i < SIGN_ITER; i++) {
        rv = C_SignInit(ctx->hSess, &mech, ctx->hPriv);
        if (rv != CKR_OK) {
            printf("FAIL: sign_independent: C_SignInit iter %d rv=%lu\n",
                   i, (unsigned long)rv);
            f++;
            continue;
        }

        siglen = (CK_ULONG)sizeof(sig);
        rv = C_Sign(ctx->hSess, (CK_BYTE_PTR)test_hash, (CK_ULONG)sizeof(test_hash),
                    sig, &siglen);
        if (rv != CKR_OK) {
            printf("FAIL: sign_independent: C_Sign iter %d rv=%lu\n",
                   i, (unsigned long)rv);
            f++;
            continue;
        }

        if (!ctx->oracle_ready) {
            f++;
            printf("FAIL: sign_independent: oracle not ready at iter %d\n", i);
            continue;
        }

        stat = 0;
        ret  = wc_ecc_verify_hash(sig, (word32)siglen,
                                   test_hash, (word32)sizeof(test_hash),
                                   &stat, &ctx->pub_oracle);
        if (ret != 0 || stat != 1) {
            printf("FAIL: sign_independent: oracle verify iter %d ret=%d stat=%d\n",
                   i, ret, stat);
            f++;
        }
    }

    return (void *)(intptr_t)f;
}

static int test_concurrent_sign_independent(void)
{
    CK_MECHANISM       mech   = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_SESSION_HANDLE  sess[SIGN_THREAD_COUNT];
    CK_OBJECT_HANDLE   hPub[SIGN_THREAD_COUNT];
    CK_OBJECT_HANDLE   hPriv[SIGN_THREAD_COUNT];
    sign_thread_ctx_t  ctx[SIGN_THREAD_COUNT];
    pthread_barrier_t  barrier;
    pthread_t          tid[SIGN_THREAD_COUNT];
    uint8_t            pub_x963[65];
    CK_ULONG           pub_x963_len;
    ecc_key            oracle_key;
    CK_RV              rv;
    void              *ret;
    int                f = 0;
    int                i;

    setenv("WOLFP11_SOFT_KEYSTORE_PATH", "", 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "sign_independent: C_Initialize");
    if (rv != CKR_OK) goto done;

    /* Open one session per thread, login each, generate one key pair each */
    for (i = 0; i < SIGN_THREAD_COUNT; i++) {
        sess[i] = 0;
        rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                           NULL_PTR, NULL, &sess[i]);
        if (rv != CKR_OK) {
            printf("FAIL: sign_independent: C_OpenSession[%d] rv=%lu\n",
                   i, (unsigned long)rv);
            f++;
            /* Cannot continue -- not enough sessions */
            for (i--; i >= 0; i--) C_CloseSession(sess[i]);
            goto finalize;
        }

        rv = C_Login(sess[i], CKU_USER,
                     (CK_UTF8CHAR_PTR)soft_pin, soft_pinlen);
        /* CKR_USER_ALREADY_LOGGED_IN is fine: same slot, already logged in */
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
            printf("FAIL: sign_independent: C_Login[%d] rv=%lu\n",
                   i, (unsigned long)rv);
            f++;
        }

        rv = C_GenerateKeyPair(sess[i], &mech,
                               NULL_PTR, 0, NULL_PTR, 0,
                               &hPub[i], &hPriv[i]);
        if (rv != CKR_OK) {
            printf("FAIL: sign_independent: C_GenerateKeyPair[%d] rv=%lu\n",
                   i, (unsigned long)rv);
            f++;
            hPub[i]  = 0;
            hPriv[i] = 0;
        }
    }

    pthread_barrier_init(&barrier, NULL, SIGN_THREAD_COUNT);

    /* Build per-thread context: import public key into wolfCrypt oracle */
    for (i = 0; i < SIGN_THREAD_COUNT; i++) {
        ctx[i].barrier      = &barrier;
        ctx[i].hSess        = sess[i];
        ctx[i].hPriv        = hPriv[i];
        ctx[i].oracle_ready = 0;

        if (hPub[i] == 0) continue;

        pub_x963_len = sizeof(pub_x963);
        if (wp11_test_soft_export_pub_x963(hPub[i], pub_x963, &pub_x963_len) != 0) {
            printf("FAIL: sign_independent: export_pub_x963[%d]\n", i);
            f++;
            continue;
        }

        if (wc_ecc_init(&oracle_key) != 0) {
            printf("FAIL: sign_independent: wc_ecc_init[%d]\n", i);
            f++;
            continue;
        }
        if (wc_ecc_import_x963(pub_x963, (word32)pub_x963_len, &oracle_key) != 0) {
            printf("FAIL: sign_independent: wc_ecc_import_x963[%d]\n", i);
            wc_ecc_free(&oracle_key);
            f++;
            continue;
        }
        ctx[i].pub_oracle   = oracle_key;
        ctx[i].oracle_ready = 1;
    }

    /* Launch all threads */
    for (i = 0; i < SIGN_THREAD_COUNT; i++) {
        if (pthread_create(&tid[i], NULL, sign_thread_fn, &ctx[i]) != 0) {
            printf("FAIL: sign_independent: pthread_create[%d]\n", i);
            f++;
            tid[i] = 0;
        }
    }

    /* Join and accumulate failures */
    for (i = 0; i < SIGN_THREAD_COUNT; i++) {
        if (tid[i] == 0) continue;
        pthread_join(tid[i], &ret);
        f += (int)(intptr_t)ret;
    }

    pthread_barrier_destroy(&barrier);

    /* Free oracle keys */
    for (i = 0; i < SIGN_THREAD_COUNT; i++) {
        if (ctx[i].oracle_ready)
            wc_ecc_free(&ctx[i].pub_oracle);
    }

    f += check(f == 0, "sign_independent: all threads pass");

    /* Close sessions */
    for (i = 0; i < SIGN_THREAD_COUNT; i++) {
        if (sess[i] != 0) C_CloseSession(sess[i]);
    }

finalize:
    C_Finalize(NULL);
done:
    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}

/* ------------------------------------------------------------------
 * Test 2: concurrent sign + session open/close
 *
 * Thread A: signs 200 times on a fixed session/key.
 * Thread B: opens and closes sessions 200 times.
 * ------------------------------------------------------------------ */

typedef struct {
    pthread_barrier_t *barrier;
    CK_SESSION_HANDLE  hSess;
    CK_OBJECT_HANDLE   hPriv;
    int                failures;
} sign_churn_sign_ctx_t;

typedef struct {
    pthread_barrier_t *barrier;
    int                failures;
} sign_churn_open_ctx_t;

static void *sign_churn_sign_fn(void *arg)
{
    sign_churn_sign_ctx_t *ctx  = (sign_churn_sign_ctx_t *)arg;
    CK_MECHANISM           mech = { CKM_ECDSA, NULL_PTR, 0 };
    CK_BYTE                sig[128];
    CK_ULONG               siglen;
    CK_RV                  rv;
    int                    f = 0;
    int                    i;

    pthread_barrier_wait(ctx->barrier);

    for (i = 0; i < 200; i++) {
        rv = C_SignInit(ctx->hSess, &mech, ctx->hPriv);
        if (rv != CKR_OK) {
            printf("FAIL: sign_session_churn: C_SignInit iter %d rv=%lu\n",
                   i, (unsigned long)rv);
            f++;
            continue;
        }

        siglen = (CK_ULONG)sizeof(sig);
        rv = C_Sign(ctx->hSess, (CK_BYTE_PTR)test_hash,
                    (CK_ULONG)sizeof(test_hash), sig, &siglen);
        if (rv != CKR_OK) {
            printf("FAIL: sign_session_churn: C_Sign iter %d rv=%lu\n",
                   i, (unsigned long)rv);
            f++;
        }
    }

    return (void *)(intptr_t)f;
}

static void *sign_churn_open_fn(void *arg)
{
    sign_churn_open_ctx_t *ctx = (sign_churn_open_ctx_t *)arg;
    CK_SESSION_HANDLE      hTmp;
    CK_RV                  rv;
    int                    f = 0;
    int                    i;

    pthread_barrier_wait(ctx->barrier);

    for (i = 0; i < 200; i++) {
        hTmp = 0;
        rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                           NULL_PTR, NULL, &hTmp);
        if (rv == CKR_OK && hTmp != 0) {
            C_CloseSession(hTmp);
        }
        /* CKR_SESSION_COUNT (table full) is acceptable under contention */
    }

    return (void *)(intptr_t)f;
}

static int test_concurrent_sign_and_session_churn(void)
{
    CK_MECHANISM       mech   = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_SESSION_HANDLE  hSess  = 0;
    CK_OBJECT_HANDLE   hPub   = 0;
    CK_OBJECT_HANDLE   hPriv  = 0;
    pthread_barrier_t  barrier;
    pthread_t          tid_sign, tid_open;
    sign_churn_sign_ctx_t sign_ctx;
    sign_churn_open_ctx_t open_ctx;
    void              *ret;
    CK_RV              rv;
    int                f = 0;

    setenv("WOLFP11_SOFT_KEYSTORE_PATH", "", 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "sign_session_churn: C_Initialize");
    if (rv != CKR_OK) goto done;

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL_PTR, NULL, &hSess);
    f += check(rv == CKR_OK, "sign_session_churn: C_OpenSession");
    if (rv != CKR_OK) goto finalize;

    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)soft_pin, soft_pinlen);
    f += check(rv == CKR_OK, "sign_session_churn: C_Login");
    if (rv != CKR_OK) goto close_sess;

    rv = C_GenerateKeyPair(hSess, &mech,
                           NULL_PTR, 0, NULL_PTR, 0,
                           &hPub, &hPriv);
    f += check(rv == CKR_OK, "sign_session_churn: C_GenerateKeyPair");
    if (rv != CKR_OK) goto close_sess;

    pthread_barrier_init(&barrier, NULL, 2);

    sign_ctx.barrier  = &barrier;
    sign_ctx.hSess    = hSess;
    sign_ctx.hPriv    = hPriv;
    sign_ctx.failures = 0;

    open_ctx.barrier  = &barrier;
    open_ctx.failures = 0;

    pthread_create(&tid_sign, NULL, sign_churn_sign_fn, &sign_ctx);
    pthread_create(&tid_open, NULL, sign_churn_open_fn, &open_ctx);

    pthread_join(tid_sign, &ret);
    f += (int)(intptr_t)ret;

    pthread_join(tid_open, &ret);
    f += (int)(intptr_t)ret;

    pthread_barrier_destroy(&barrier);

    f += check(f == 0, "sign_session_churn: no errors under churn");

close_sess:
    C_CloseSession(hSess);
finalize:
    C_Finalize(NULL);
done:
    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}

/* ------------------------------------------------------------------
 * Test 3: sign vs FindObjects
 *
 * Thread A: signs 200 times on hSess_a.
 * Thread B: FindObjectsInit/FindObjects/FindObjectsFinal 200 times on hSess_b.
 * ------------------------------------------------------------------ */

typedef struct {
    pthread_barrier_t *barrier;
    CK_SESSION_HANDLE  hSess;
    CK_OBJECT_HANDLE   hPriv;
} sign_vs_find_sign_ctx_t;

typedef struct {
    pthread_barrier_t *barrier;
    CK_SESSION_HANDLE  hSess;
} sign_vs_find_find_ctx_t;

static void *sign_vs_find_sign_fn(void *arg)
{
    sign_vs_find_sign_ctx_t *ctx  = (sign_vs_find_sign_ctx_t *)arg;
    CK_MECHANISM             mech = { CKM_ECDSA, NULL_PTR, 0 };
    CK_BYTE                  sig[128];
    CK_ULONG                 siglen;
    CK_RV                    rv;
    int                      f = 0;
    int                      i;

    pthread_barrier_wait(ctx->barrier);

    for (i = 0; i < 200; i++) {
        rv = C_SignInit(ctx->hSess, &mech, ctx->hPriv);
        if (rv != CKR_OK) {
            printf("FAIL: sign_vs_find: C_SignInit iter %d rv=%lu\n",
                   i, (unsigned long)rv);
            f++;
            continue;
        }

        siglen = (CK_ULONG)sizeof(sig);
        rv = C_Sign(ctx->hSess, (CK_BYTE_PTR)test_hash,
                    (CK_ULONG)sizeof(test_hash), sig, &siglen);
        if (rv != CKR_OK) {
            printf("FAIL: sign_vs_find: C_Sign iter %d rv=%lu\n",
                   i, (unsigned long)rv);
            f++;
        }
    }

    return (void *)(intptr_t)f;
}

static void *sign_vs_find_find_fn(void *arg)
{
    sign_vs_find_find_ctx_t *ctx = (sign_vs_find_find_ctx_t *)arg;
    CK_OBJECT_HANDLE         found[16];
    CK_ULONG                 nfound;
    CK_RV                    rv;
    int                      f = 0;
    int                      i;

    pthread_barrier_wait(ctx->barrier);

    for (i = 0; i < 200; i++) {
        rv = C_FindObjectsInit(ctx->hSess, NULL_PTR, 0);
        if (rv != CKR_OK) {
            printf("FAIL: sign_vs_find: C_FindObjectsInit iter %d rv=%lu\n",
                   i, (unsigned long)rv);
            f++;
            continue;
        }

        nfound = 0;
        rv = C_FindObjects(ctx->hSess, found, 16, &nfound);
        if (rv != CKR_OK) {
            printf("FAIL: sign_vs_find: C_FindObjects iter %d rv=%lu\n",
                   i, (unsigned long)rv);
            f++;
        }

        rv = C_FindObjectsFinal(ctx->hSess);
        if (rv != CKR_OK) {
            printf("FAIL: sign_vs_find: C_FindObjectsFinal iter %d rv=%lu\n",
                   i, (unsigned long)rv);
            f++;
        }
    }

    return (void *)(intptr_t)f;
}

static int test_concurrent_sign_vs_find(void)
{
    CK_MECHANISM              mech   = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_SESSION_HANDLE         hSess_a = 0, hSess_b = 0;
    CK_OBJECT_HANDLE          hPub   = 0, hPriv = 0;
    pthread_barrier_t         barrier;
    pthread_t                 tid_sign, tid_find;
    sign_vs_find_sign_ctx_t   sign_ctx;
    sign_vs_find_find_ctx_t   find_ctx;
    void                     *ret;
    CK_RV                     rv;
    int                       f = 0;

    setenv("WOLFP11_SOFT_KEYSTORE_PATH", "", 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "sign_vs_find: C_Initialize");
    if (rv != CKR_OK) goto done;

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL_PTR, NULL, &hSess_a);
    f += check(rv == CKR_OK, "sign_vs_find: C_OpenSession A");
    if (rv != CKR_OK) goto finalize;

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL_PTR, NULL, &hSess_b);
    f += check(rv == CKR_OK, "sign_vs_find: C_OpenSession B");
    if (rv != CKR_OK) goto close_a;

    rv = C_Login(hSess_a, CKU_USER,
                 (CK_UTF8CHAR_PTR)soft_pin, soft_pinlen);
    f += check(rv == CKR_OK, "sign_vs_find: C_Login");
    if (rv != CKR_OK) goto close_both;

    rv = C_GenerateKeyPair(hSess_a, &mech,
                           NULL_PTR, 0, NULL_PTR, 0,
                           &hPub, &hPriv);
    f += check(rv == CKR_OK, "sign_vs_find: C_GenerateKeyPair");
    if (rv != CKR_OK) goto close_both;

    pthread_barrier_init(&barrier, NULL, 2);

    sign_ctx.barrier = &barrier;
    sign_ctx.hSess   = hSess_a;
    sign_ctx.hPriv   = hPriv;

    find_ctx.barrier = &barrier;
    find_ctx.hSess   = hSess_b;

    pthread_create(&tid_sign, NULL, sign_vs_find_sign_fn, &sign_ctx);
    pthread_create(&tid_find, NULL, sign_vs_find_find_fn, &find_ctx);

    pthread_join(tid_sign, &ret);
    f += (int)(intptr_t)ret;

    pthread_join(tid_find, &ret);
    f += (int)(intptr_t)ret;

    pthread_barrier_destroy(&barrier);

    f += check(f == 0, "sign_vs_find: no errors under concurrent FindObjects");

close_both:
    if (hSess_b != 0) C_CloseSession(hSess_b);
close_a:
    if (hSess_a != 0) C_CloseSession(hSess_a);
finalize:
    C_Finalize(NULL);
done:
    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}

/* =========================================================================
 * test_threads_sign entry point
 * ====================================================================== */

static int test_threads_sign(void)
{
    int f = 0;

    f += test_concurrent_sign_independent();
    f += test_concurrent_sign_and_session_churn();
    f += test_concurrent_sign_vs_find();

    return f;
}

/* =========================================================================
 * wolfP11-7by: concurrent login/logout
 * ====================================================================== */

/* ------------------------------------------------------------------
 * Test 1: concurrent login same slot
 *
 * 4 threads each call C_Login simultaneously.
 * Accepted returns: CKR_OK or CKR_USER_ALREADY_LOGGED_IN.
 * ------------------------------------------------------------------ */

#define LOGIN_THREAD_COUNT 4

typedef struct {
    pthread_barrier_t *barrier;
    CK_SESSION_HANDLE  hSess;
} login_ctx_t;

static void *login_thread_fn(void *arg)
{
    login_ctx_t *ctx = (login_ctx_t *)arg;
    CK_RV        rv;
    int          f = 0;

    pthread_barrier_wait(ctx->barrier);

    rv = C_Login(ctx->hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)login_pin, login_pinlen);
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
        printf("FAIL: concurrent_login: unexpected rv=%lu\n",
               (unsigned long)rv);
        f++;
    }

    return (void *)(intptr_t)f;
}

static int test_concurrent_login_same_slot(void)
{
    CK_SESSION_HANDLE  sess[LOGIN_THREAD_COUNT];
    login_ctx_t        ctx[LOGIN_THREAD_COUNT];
    pthread_barrier_t  barrier;
    pthread_t          tid[LOGIN_THREAD_COUNT];
    void              *ret;
    CK_RV              rv;
    int                f = 0;
    int                i;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "concurrent_login: C_Initialize");
    if (rv != CKR_OK) return f;

    for (i = 0; i < LOGIN_THREAD_COUNT; i++) {
        sess[i] = 0;
        rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                           NULL_PTR, NULL, &sess[i]);
        if (rv != CKR_OK) {
            printf("FAIL: concurrent_login: C_OpenSession[%d] rv=%lu\n",
                   i, (unsigned long)rv);
            f++;
            for (i--; i >= 0; i--) C_CloseSession(sess[i]);
            C_Finalize(NULL);
            return f;
        }
    }

    pthread_barrier_init(&barrier, NULL, LOGIN_THREAD_COUNT);

    for (i = 0; i < LOGIN_THREAD_COUNT; i++) {
        ctx[i].barrier = &barrier;
        ctx[i].hSess   = sess[i];
        pthread_create(&tid[i], NULL, login_thread_fn, &ctx[i]);
    }

    for (i = 0; i < LOGIN_THREAD_COUNT; i++) {
        pthread_join(tid[i], &ret);
        f += (int)(intptr_t)ret;
    }

    pthread_barrier_destroy(&barrier);

    f += check(f == 0, "concurrent_login: no unexpected errors from any thread");

    C_Logout(sess[0]);

    for (i = 0; i < LOGIN_THREAD_COUNT; i++) {
        C_CloseSession(sess[i]);
    }

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "concurrent_login: C_Finalize");

    return f;
}

/* ------------------------------------------------------------------
 * Test 2: login/logout interleave
 *
 * Thread A: 50 iters -- C_Login then C_Logout on hSess_a.
 * Thread B: 50 iters -- C_Login on hSess_b; accepts CKR_OK or
 *                       CKR_USER_ALREADY_LOGGED_IN.
 * ------------------------------------------------------------------ */

typedef struct {
    pthread_barrier_t *barrier;
    CK_SESSION_HANDLE  hSess;
    int                is_logout_thread; /* 1 -> login+logout loop; 0 -> login only */
} interleave_ctx_t;

static void *interleave_thread_fn(void *arg)
{
    interleave_ctx_t *ctx = (interleave_ctx_t *)arg;
    CK_RV             rv;
    int               f = 0;
    int               i;

    pthread_barrier_wait(ctx->barrier);

    if (ctx->is_logout_thread) {
        for (i = 0; i < 50; i++) {
            rv = C_Login(ctx->hSess, CKU_USER,
                         (CK_UTF8CHAR_PTR)login_pin, login_pinlen);
            /* CKR_USER_ALREADY_LOGGED_IN acceptable between interleaved calls */
            if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
                printf("FAIL: login_logout_interleave: A C_Login iter %d rv=%lu\n",
                       i, (unsigned long)rv);
                f++;
            }

            rv = C_Logout(ctx->hSess);
            /* CKR_USER_NOT_LOGGED_IN acceptable if thread B logged out first */
            if (rv != CKR_OK && rv != CKR_USER_NOT_LOGGED_IN) {
                printf("FAIL: login_logout_interleave: A C_Logout iter %d rv=%lu\n",
                       i, (unsigned long)rv);
                f++;
            }
        }
    } else {
        for (i = 0; i < 50; i++) {
            rv = C_Login(ctx->hSess, CKU_USER,
                         (CK_UTF8CHAR_PTR)login_pin, login_pinlen);
            if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
                printf("FAIL: login_logout_interleave: B C_Login iter %d rv=%lu\n",
                       i, (unsigned long)rv);
                f++;
            }
        }
    }

    return (void *)(intptr_t)f;
}

static int test_concurrent_login_logout_interleave(void)
{
    CK_SESSION_HANDLE  hSess_a = 0, hSess_b = 0;
    interleave_ctx_t   ctx_a, ctx_b;
    pthread_barrier_t  barrier;
    pthread_t          tid_a, tid_b;
    void              *ret;
    CK_RV              rv;
    int                f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "login_logout_interleave: C_Initialize");
    if (rv != CKR_OK) return f;

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL_PTR, NULL, &hSess_a);
    f += check(rv == CKR_OK, "login_logout_interleave: C_OpenSession A");
    if (rv != CKR_OK) goto finalize;

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL_PTR, NULL, &hSess_b);
    f += check(rv == CKR_OK, "login_logout_interleave: C_OpenSession B");
    if (rv != CKR_OK) goto close_a;

    pthread_barrier_init(&barrier, NULL, 2);

    ctx_a.barrier          = &barrier;
    ctx_a.hSess            = hSess_a;
    ctx_a.is_logout_thread = 1;

    ctx_b.barrier          = &barrier;
    ctx_b.hSess            = hSess_b;
    ctx_b.is_logout_thread = 0;

    pthread_create(&tid_a, NULL, interleave_thread_fn, &ctx_a);
    pthread_create(&tid_b, NULL, interleave_thread_fn, &ctx_b);

    pthread_join(tid_a, &ret);
    f += (int)(intptr_t)ret;

    pthread_join(tid_b, &ret);
    f += (int)(intptr_t)ret;

    pthread_barrier_destroy(&barrier);

    f += check(f == 0, "login_logout_interleave: no unexpected errors");

    /* Best-effort cleanup: ignore return of Logout if already logged out */
    C_Logout(hSess_a);
    C_CloseSession(hSess_b);
close_a:
    C_CloseSession(hSess_a);
finalize:
    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "login_logout_interleave: C_Finalize");

    return f;
}

/* =========================================================================
 * test_threads_login entry point
 * ====================================================================== */

static int test_threads_login(void)
{
    int f = 0;

    f += test_concurrent_login_same_slot();
    f += test_concurrent_login_logout_interleave();

    return f;
}

/* =========================================================================
 * wolfP11-qnt: concurrent init/finalize
 * ====================================================================== */

/* ------------------------------------------------------------------
 * Test 1: double C_Initialize
 *
 * Two threads call C_Initialize simultaneously.
 * Exactly one returns CKR_OK; the other returns
 * CKR_CRYPTOKI_ALREADY_INITIALIZED.
 * ------------------------------------------------------------------ */

typedef struct {
    pthread_barrier_t *barrier;
    CK_RV              rv;
} init_ctx_t;

static void *double_init_thread_fn(void *arg)
{
    init_ctx_t *ctx = (init_ctx_t *)arg;

    pthread_barrier_wait(ctx->barrier);

    ctx->rv = C_Initialize(NULL_PTR);

    return NULL;
}

static int test_concurrent_double_init(void)
{
    init_ctx_t        ctx_a, ctx_b;
    pthread_barrier_t barrier;
    pthread_t         tid_a, tid_b;
    int               ok_count;
    int               f = 0;

    pthread_barrier_init(&barrier, NULL, 2);

    ctx_a.barrier = &barrier;
    ctx_a.rv      = CKR_GENERAL_ERROR;
    ctx_b.barrier = &barrier;
    ctx_b.rv      = CKR_GENERAL_ERROR;

    pthread_create(&tid_a, NULL, double_init_thread_fn, &ctx_a);
    pthread_create(&tid_b, NULL, double_init_thread_fn, &ctx_b);

    pthread_join(tid_a, NULL);
    pthread_join(tid_b, NULL);

    pthread_barrier_destroy(&barrier);

    /* Each return must be one of the two expected values */
    f += check(ctx_a.rv == CKR_OK ||
               ctx_a.rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
               "double_init: thread A returned expected value");
    f += check(ctx_b.rv == CKR_OK ||
               ctx_b.rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
               "double_init: thread B returned expected value");

    /* Exactly one thread must have received CKR_OK */
    ok_count = (ctx_a.rv == CKR_OK ? 1 : 0) +
               (ctx_b.rv == CKR_OK ? 1 : 0);
    f += check(ok_count == 1,
               "double_init: exactly one thread received CKR_OK");

    C_Finalize(NULL_PTR);

    return f;
}

/* ------------------------------------------------------------------
 * Test 2: C_Finalize races C_OpenSession
 *
 * Thread A: 20 iters -- C_OpenSession then C_CloseSession.
 * Thread B: after 5ms, calls C_Finalize once.
 * Acceptable for thread A: CKR_OK or CKR_CRYPTOKI_NOT_INITIALIZED.
 * Thread B must receive CKR_OK from C_Finalize.
 * ------------------------------------------------------------------ */

typedef struct {
    pthread_barrier_t *barrier;
    int                failures;
} finalize_open_ctx_t;

typedef struct {
    pthread_barrier_t *barrier;
    CK_RV              finalize_rv;
} finalize_ctx_t;

static void *finalize_open_fn(void *arg)
{
    finalize_open_ctx_t *ctx = (finalize_open_ctx_t *)arg;
    CK_SESSION_HANDLE    hTmp;
    CK_RV                rv;
    int                  f = 0;
    int                  i;

    pthread_barrier_wait(ctx->barrier);

    for (i = 0; i < 20; i++) {
        hTmp = 0;
        rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                           NULL_PTR, NULL, &hTmp);
        if (rv == CKR_OK) {
            C_CloseSession(hTmp);
        } else if (rv != CKR_CRYPTOKI_NOT_INITIALIZED &&
                   rv != CKR_SESSION_COUNT) {
            printf("FAIL: finalize_vs_opensession: C_OpenSession iter %d rv=%lu\n",
                   i, (unsigned long)rv);
            f++;
        }
    }

    return (void *)(intptr_t)f;
}

static void *finalize_fn(void *arg)
{
    finalize_ctx_t *ctx = (finalize_ctx_t *)arg;
    struct timespec  ts;

    pthread_barrier_wait(ctx->barrier);

    /* Small delay so thread A gets a head start */
    ts.tv_sec  = 0;
    ts.tv_nsec = 5000000L; /* 5 ms */
    nanosleep(&ts, NULL);

    ctx->finalize_rv = C_Finalize(NULL_PTR);

    return NULL;
}

static int test_concurrent_finalize_vs_opensession(void)
{
    finalize_open_ctx_t open_ctx;
    finalize_ctx_t      fin_ctx;
    pthread_barrier_t   barrier;
    pthread_t           tid_open, tid_fin;
    void               *ret;
    CK_RV               rv;
    int                 f = 0;

    rv = C_Initialize(NULL_PTR);
    f += check(rv == CKR_OK, "finalize_vs_opensession: C_Initialize");
    if (rv != CKR_OK) return f;

    pthread_barrier_init(&barrier, NULL, 2);

    open_ctx.barrier  = &barrier;
    open_ctx.failures = 0;

    fin_ctx.barrier     = &barrier;
    fin_ctx.finalize_rv = CKR_GENERAL_ERROR;

    pthread_create(&tid_open, NULL, finalize_open_fn, &open_ctx);
    pthread_create(&tid_fin,  NULL, finalize_fn,      &fin_ctx);

    pthread_join(tid_open, &ret);
    f += (int)(intptr_t)ret;

    pthread_join(tid_fin, NULL);

    pthread_barrier_destroy(&barrier);

    f += check(fin_ctx.finalize_rv == CKR_OK,
               "finalize_vs_opensession: C_Finalize returned CKR_OK");

    /* If C_Finalize raced and won before C_Initialize in the next test,
     * the library is now uninitialized -- that is the expected state. */

    return f;
}

/* =========================================================================
 * test_threads_init entry point
 * ====================================================================== */

static int test_threads_init(void)
{
    int f = 0;

    f += test_concurrent_double_init();
    f += test_concurrent_finalize_vs_opensession();

    return f;
}

/* =========================================================================
 * Top-level entry point
 * ====================================================================== */

int wp11_test_pkcs11_threads(void)
{
    int failures = 0;

    failures += test_threads_sign();
    failures += test_threads_login();
    failures += test_threads_init();

    return failures;
}

#else /* WOLFP11_CFG_TEST_THREADS not defined */

int wp11_test_pkcs11_threads(void)
{
    return 0;
}

#endif /* WOLFP11_CFG_TEST_THREADS */
