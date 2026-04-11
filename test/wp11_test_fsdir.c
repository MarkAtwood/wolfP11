/* wolfP11
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfP11.
 *
 * wolfP11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfP11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * For a commercial license, contact wolfSSL Inc. at licensing@wolfssl.com.
 */

/* wp11_test_fsdir.c -- integration tests for the wolfP11 FSDIR backend
 *
 * Requires -DWOLFP11_CFG_TEST and -DWOLFP11_CFG_FSDIR_BACKEND.
 *
 * Test oracle discipline:
 *   - Slot detection: a real .p11k file is created in a mkdtemp directory;
 *     the FSDIR watcher's initial scan (triggered by C_Initialize) is the
 *     code under test.  The oracle is the PKCS#11 slot count reported by
 *     C_GetSlotList.
 *   - Authentication: correct PIN is accepted (CKR_OK), wrong PIN is
 *     rejected (CKR_PIN_INCORRECT).  The oracle is the PKCS#11 return
 *     value, which maps directly to the keystore layer's AES-GCM auth-tag
 *     outcome.
 *   - Key visibility: C_FindObjects after C_Login on an empty keystore
 *     returns zero objects; that count is the oracle (independent of any
 *     DER parsing path since no key material was ever stored).
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L  /* mkdtemp, nanosleep */
#endif

#include "test/wp11_test_fsdir.h"

#ifdef WOLFP11_CFG_TEST
#ifdef WOLFP11_CFG_FSDIR_BACKEND

#include "wolfp11/wp11_pkcs11.h"
#include "wolfp11/wp11_keystore.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>     /* nanosleep, struct timespec */
#include <sys/stat.h>

/* -------------------------------------------------------------------------
 * Shared helper
 * ---------------------------------------------------------------------- */

static int check(int pass, const char *label)
{
    if (pass) {
        printf("PASS: %s\n", label);
    } else {
        printf("FAIL: %s\n", label);
    }
    return pass ? 0 : 1;
}

/* -------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

#define FSDIR_TEST_PIN           "fsdir1234"
#define FSDIR_TEST_PIN_BYTES     ((const uint8_t *)FSDIR_TEST_PIN)
#define FSDIR_TEST_PIN_LEN       9u
#define FSDIR_TEST_WRONG_PIN     "wrongpass"
#define FSDIR_TEST_WRONG_PIN_BYTES ((const uint8_t *)FSDIR_TEST_WRONG_PIN)
#define FSDIR_TEST_WRONG_PIN_LEN 9u

/* -------------------------------------------------------------------------
 * test_fsdir_slot_detected
 *
 * Creates a temp dir with a single empty .p11k file, points
 * WOLFP11_FSDIR_PATH at it, calls C_Initialize, and verifies that
 * C_GetSlotList reports a second slot (the FSDIR slot) in addition to
 * the soft-token slot.
 *
 * Oracle: slot count == 2 after C_Initialize with a pre-existing .p11k.
 * ---------------------------------------------------------------------- */
static int test_fsdir_slot_detected(void)
{
    char    tmpdir[64];
    char    p11k_path[128];
    CK_RV   rv;
    CK_SLOT_ID slots[16];
    CK_ULONG   count;
    int     ret;
    int     f = 0;

    /* Create temp directory */
    strncpy(tmpdir, "/tmp/wp11_fsdir_test_XXXXXX", sizeof(tmpdir) - 1u);
    tmpdir[sizeof(tmpdir) - 1u] = '\0';
    if (mkdtemp(tmpdir) == NULL) {
        printf("SKIP: fsdir_slot_detected: mkdtemp failed\n");
        return f + 1; /* wolfP11-4prd */
    }

    if (snprintf(p11k_path, sizeof(p11k_path), "%s/test.p11k", tmpdir)
            >= (int)sizeof(p11k_path)) {
        rmdir(tmpdir);
        printf("SKIP: fsdir_slot_detected: path too long\n");
        return f + 1; /* wolfP11-4prd */
    }

    /* Create an empty keystore (zero keys) in the temp dir */
    ret = wp11_keystore_create(p11k_path, FSDIR_TEST_PIN_BYTES,
                               FSDIR_TEST_PIN_LEN, NULL, 0u);
    if (ret != WP11_KEYSTORE_OK) {
        rmdir(tmpdir);
        printf("SKIP: fsdir_slot_detected: keystore_create failed (%d)\n", ret);
        return f + 1; /* wolfP11-4prd */
    }

    /* Point the FSDIR watcher at the temp dir */
    if (setenv("WOLFP11_FSDIR_PATH", tmpdir, 1 /* overwrite */) != 0) {
        unlink(p11k_path);
        rmdir(tmpdir);
        printf("SKIP: fsdir_slot_detected: setenv failed\n");
        return f + 1; /* wolfP11-4prd */
    }

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "fsdir_slot_detected: C_Initialize");
    if (rv != CKR_OK) {
        unsetenv("WOLFP11_FSDIR_PATH");
        unlink(p11k_path);
        rmdir(tmpdir);
        return f;
    }

    /* Allow the FSDIR watcher thread to complete its initial directory scan */
    { struct timespec ts_ = {0, 50000000L}; nanosleep(&ts_, NULL); }

    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    f += check(rv == CKR_OK, "fsdir_slot_detected: C_GetSlotList");
    f += check(count >= 2,
               "fsdir_slot_detected: FSDIR slot visible after C_Initialize");

    if (count >= 2) {
        CK_SLOT_INFO info;
        rv = C_GetSlotInfo(slots[1], &info);
        f += check(rv == CKR_OK,
                   "fsdir_slot_detected: C_GetSlotInfo on FSDIR slot");
        f += check((info.flags & CKF_TOKEN_PRESENT) != 0,
                   "fsdir_slot_detected: FSDIR slot has CKF_TOKEN_PRESENT");
    }

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "fsdir_slot_detected: C_Finalize");

    unsetenv("WOLFP11_FSDIR_PATH");
    unlink(p11k_path);
    rmdir(tmpdir);
    return f;
}

/* -------------------------------------------------------------------------
 * test_fsdir_login_correct_pin
 *
 * Verifies that C_Login with the correct keystore PIN returns CKR_OK and
 * that C_FindObjects returns zero objects (the keystore is empty).
 *
 * Oracle: CKR_OK from C_Login; nfound == 0 from C_FindObjects.
 * ---------------------------------------------------------------------- */
static int test_fsdir_login_correct_pin(void)
{
    char    tmpdir[64];
    char    p11k_path[128];
    CK_RV   rv;
    CK_SLOT_ID        slots[16];
    CK_ULONG          count;
    CK_SESSION_HANDLE hSess = 0;
    CK_OBJECT_HANDLE  objs[16];
    CK_ULONG          nfound;
    int     ret;
    int     f = 0;

    strncpy(tmpdir, "/tmp/wp11_fsdir_test_XXXXXX", sizeof(tmpdir) - 1u);
    tmpdir[sizeof(tmpdir) - 1u] = '\0';
    if (mkdtemp(tmpdir) == NULL) {
        printf("SKIP: fsdir_login_correct_pin: mkdtemp failed\n");
        return f + 1; /* wolfP11-4prd */
    }

    if (snprintf(p11k_path, sizeof(p11k_path), "%s/test.p11k", tmpdir)
            >= (int)sizeof(p11k_path)) {
        rmdir(tmpdir);
        printf("SKIP: fsdir_login_correct_pin: path too long\n");
        return f + 1; /* wolfP11-4prd */
    }

    ret = wp11_keystore_create(p11k_path, FSDIR_TEST_PIN_BYTES,
                               FSDIR_TEST_PIN_LEN, NULL, 0u);
    if (ret != WP11_KEYSTORE_OK) {
        rmdir(tmpdir);
        printf("SKIP: fsdir_login_correct_pin: keystore_create failed (%d)\n",
               ret);
        return f + 1; /* wolfP11-4prd */
    }

    if (setenv("WOLFP11_FSDIR_PATH", tmpdir, 1) != 0) {
        unlink(p11k_path);
        rmdir(tmpdir);
        printf("SKIP: fsdir_login_correct_pin: setenv failed\n");
        return f + 1; /* wolfP11-4prd */
    }

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "fsdir_login_correct_pin: C_Initialize");
    if (rv != CKR_OK) {
        unsetenv("WOLFP11_FSDIR_PATH");
        unlink(p11k_path);
        rmdir(tmpdir);
        return f;
    }

    { struct timespec ts_ = {0, 50000000L}; nanosleep(&ts_, NULL); }

    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    f += check(rv == CKR_OK && count >= 2,
               "fsdir_login_correct_pin: FSDIR slot present");
    if (count < 2) {
        C_Finalize(NULL);
        unsetenv("WOLFP11_FSDIR_PATH");
        unlink(p11k_path);
        rmdir(tmpdir);
        return f;
    }

    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "fsdir_login_correct_pin: C_OpenSession");
    if (rv != CKR_OK) {
        C_Finalize(NULL);
        unsetenv("WOLFP11_FSDIR_PATH");
        unlink(p11k_path);
        rmdir(tmpdir);
        return f;
    }

    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)FSDIR_TEST_PIN,
                 (CK_ULONG)FSDIR_TEST_PIN_LEN);
    f += check(rv == CKR_OK,
               "fsdir_login_correct_pin: correct PIN returns CKR_OK");

    if (rv == CKR_OK) {
        rv = C_FindObjectsInit(hSess, NULL, 0);
        f += check(rv == CKR_OK,
                   "fsdir_login_correct_pin: C_FindObjectsInit after login");

        nfound = 1; /* non-zero so we detect it being zeroed */
        rv = C_FindObjects(hSess, objs, 16, &nfound);
        f += check(rv == CKR_OK,
                   "fsdir_login_correct_pin: C_FindObjects returns CKR_OK");
        f += check(nfound == 0,
                   "fsdir_login_correct_pin: zero objects in empty keystore");

        C_FindObjectsFinal(hSess);

        rv = C_Logout(hSess);
        f += check(rv == CKR_OK,
                   "fsdir_login_correct_pin: C_Logout returns CKR_OK");
    }

    C_CloseSession(hSess);

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "fsdir_login_correct_pin: C_Finalize");

    unsetenv("WOLFP11_FSDIR_PATH");
    unlink(p11k_path);
    rmdir(tmpdir);
    return f;
}

/* -------------------------------------------------------------------------
 * test_fsdir_login_wrong_pin
 *
 * Verifies that C_Login with the wrong PIN returns CKR_PIN_INCORRECT.
 *
 * Oracle: CKR_PIN_INCORRECT from C_Login.
 * ---------------------------------------------------------------------- */
static int test_fsdir_login_wrong_pin(void)
{
    char    tmpdir[64];
    char    p11k_path[128];
    CK_RV   rv;
    CK_SLOT_ID        slots[16];
    CK_ULONG          count;
    CK_SESSION_HANDLE hSess = 0;
    int     ret;
    int     f = 0;

    strncpy(tmpdir, "/tmp/wp11_fsdir_test_XXXXXX", sizeof(tmpdir) - 1u);
    tmpdir[sizeof(tmpdir) - 1u] = '\0';
    if (mkdtemp(tmpdir) == NULL) {
        printf("SKIP: fsdir_login_wrong_pin: mkdtemp failed\n");
        return f + 1; /* wolfP11-4prd */
    }

    if (snprintf(p11k_path, sizeof(p11k_path), "%s/test.p11k", tmpdir)
            >= (int)sizeof(p11k_path)) {
        rmdir(tmpdir);
        printf("SKIP: fsdir_login_wrong_pin: path too long\n");
        return f + 1; /* wolfP11-4prd */
    }

    ret = wp11_keystore_create(p11k_path, FSDIR_TEST_PIN_BYTES,
                               FSDIR_TEST_PIN_LEN, NULL, 0u);
    if (ret != WP11_KEYSTORE_OK) {
        rmdir(tmpdir);
        printf("SKIP: fsdir_login_wrong_pin: keystore_create failed (%d)\n",
               ret);
        return f + 1; /* wolfP11-4prd */
    }

    if (setenv("WOLFP11_FSDIR_PATH", tmpdir, 1) != 0) {
        unlink(p11k_path);
        rmdir(tmpdir);
        printf("SKIP: fsdir_login_wrong_pin: setenv failed\n");
        return f + 1; /* wolfP11-4prd */
    }

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "fsdir_login_wrong_pin: C_Initialize");
    if (rv != CKR_OK) {
        unsetenv("WOLFP11_FSDIR_PATH");
        unlink(p11k_path);
        rmdir(tmpdir);
        return f;
    }

    { struct timespec ts_ = {0, 50000000L}; nanosleep(&ts_, NULL); }

    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    f += check(rv == CKR_OK && count >= 2,
               "fsdir_login_wrong_pin: FSDIR slot present");
    if (count < 2) {
        C_Finalize(NULL);
        unsetenv("WOLFP11_FSDIR_PATH");
        unlink(p11k_path);
        rmdir(tmpdir);
        return f;
    }

    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "fsdir_login_wrong_pin: C_OpenSession");
    if (rv != CKR_OK) {
        C_Finalize(NULL);
        unsetenv("WOLFP11_FSDIR_PATH");
        unlink(p11k_path);
        rmdir(tmpdir);
        return f;
    }

    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)FSDIR_TEST_WRONG_PIN,
                 (CK_ULONG)FSDIR_TEST_WRONG_PIN_LEN);
    f += check(rv == CKR_PIN_INCORRECT,
               "fsdir_login_wrong_pin: wrong PIN returns CKR_PIN_INCORRECT");

    C_CloseSession(hSess);

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "fsdir_login_wrong_pin: C_Finalize");

    unsetenv("WOLFP11_FSDIR_PATH");
    unlink(p11k_path);
    rmdir(tmpdir);
    return f;
}

/* -------------------------------------------------------------------------
 * test_fsdir_logout_clears_keys
 *
 * After C_Logout, C_FindObjects must return zero objects -- the keystore
 * is freed on logout and g_keys[] entries for the FSDIR slot are cleared.
 *
 * Oracle: nfound == 0 after C_Logout; this is independent of any per-key
 * state because the keystore is empty (zero keys created).
 * ---------------------------------------------------------------------- */
static int test_fsdir_logout_clears_keys(void)
{
    char    tmpdir[64];
    char    p11k_path[128];
    CK_RV   rv;
    CK_SLOT_ID        slots[16];
    CK_ULONG          count;
    CK_SESSION_HANDLE hSess = 0;
    CK_OBJECT_HANDLE  objs[16];
    CK_ULONG          nfound;
    int     ret;
    int     f = 0;

    strncpy(tmpdir, "/tmp/wp11_fsdir_test_XXXXXX", sizeof(tmpdir) - 1u);
    tmpdir[sizeof(tmpdir) - 1u] = '\0';
    if (mkdtemp(tmpdir) == NULL) {
        printf("SKIP: fsdir_logout_clears_keys: mkdtemp failed\n");
        return f + 1; /* wolfP11-4prd */
    }

    if (snprintf(p11k_path, sizeof(p11k_path), "%s/test.p11k", tmpdir)
            >= (int)sizeof(p11k_path)) {
        rmdir(tmpdir);
        printf("SKIP: fsdir_logout_clears_keys: path too long\n");
        return f + 1; /* wolfP11-4prd */
    }

    ret = wp11_keystore_create(p11k_path, FSDIR_TEST_PIN_BYTES,
                               FSDIR_TEST_PIN_LEN, NULL, 0u);
    if (ret != WP11_KEYSTORE_OK) {
        rmdir(tmpdir);
        printf("SKIP: fsdir_logout_clears_keys: keystore_create failed (%d)\n",
               ret);
        return f + 1; /* wolfP11-4prd */
    }

    if (setenv("WOLFP11_FSDIR_PATH", tmpdir, 1) != 0) {
        unlink(p11k_path);
        rmdir(tmpdir);
        printf("SKIP: fsdir_logout_clears_keys: setenv failed\n");
        return f + 1; /* wolfP11-4prd */
    }

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "fsdir_logout_clears_keys: C_Initialize");
    if (rv != CKR_OK) {
        unsetenv("WOLFP11_FSDIR_PATH");
        unlink(p11k_path);
        rmdir(tmpdir);
        return f;
    }

    { struct timespec ts_ = {0, 50000000L}; nanosleep(&ts_, NULL); }

    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    if (count < 2) {
        C_Finalize(NULL);
        unsetenv("WOLFP11_FSDIR_PATH");
        unlink(p11k_path);
        rmdir(tmpdir);
        return f + 1; /* count prerequisite failure */
    }

    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "fsdir_logout_clears_keys: C_OpenSession");
    if (rv != CKR_OK) {
        C_Finalize(NULL);
        unsetenv("WOLFP11_FSDIR_PATH");
        unlink(p11k_path);
        rmdir(tmpdir);
        return f;
    }

    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)FSDIR_TEST_PIN,
                 (CK_ULONG)FSDIR_TEST_PIN_LEN);
    f += check(rv == CKR_OK, "fsdir_logout_clears_keys: C_Login");
    if (rv != CKR_OK) {
        C_CloseSession(hSess);
        C_Finalize(NULL);
        unsetenv("WOLFP11_FSDIR_PATH");
        unlink(p11k_path);
        rmdir(tmpdir);
        return f;
    }

    rv = C_Logout(hSess);
    f += check(rv == CKR_OK, "fsdir_logout_clears_keys: C_Logout");

    /* After logout, C_FindObjects must see zero key objects */
    rv = C_FindObjectsInit(hSess, NULL, 0);
    f += check(rv == CKR_OK,
               "fsdir_logout_clears_keys: FindObjectsInit after logout");

    nfound = 1;
    rv = C_FindObjects(hSess, objs, 16, &nfound);
    f += check(rv == CKR_OK,
               "fsdir_logout_clears_keys: FindObjects after logout");
    f += check(nfound == 0,
               "fsdir_logout_clears_keys: no keys visible after logout");

    C_FindObjectsFinal(hSess);
    C_CloseSession(hSess);

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "fsdir_logout_clears_keys: C_Finalize");

    unsetenv("WOLFP11_FSDIR_PATH");
    unlink(p11k_path);
    rmdir(tmpdir);
    return f;
}

/* -------------------------------------------------------------------------
 * test_fsdir_inotify_arrival
 *
 * Start C_Initialize with an empty directory, create a .p11k file after
 * init, and verify that the inotify thread detects it and fires a slot
 * event within 500 ms.
 *
 * Oracle: C_WaitForSlotEvent returns CKR_OK and slot count becomes 2.
 * Guarded by WOLFP11_CFG_TEST_INOTIFY because the inotify event delivery
 * depends on kernel scheduling; skip in latency-constrained CI.
 * ---------------------------------------------------------------------- */
#ifdef WOLFP11_CFG_TEST_INOTIFY
static int test_fsdir_inotify_arrival(void)
{
    char       tmpdir[64];
    char       p11k_path[128];
    CK_RV      rv;
    CK_SLOT_ID slots[16];
    CK_SLOT_ID ev_slot;
    CK_ULONG   count;
    int        ret;
    int        i;
    int        f = 0;

    strncpy(tmpdir, "/tmp/wp11_fsdir_ino_XXXXXX", sizeof(tmpdir) - 1u);
    tmpdir[sizeof(tmpdir) - 1u] = '\0';
    if (mkdtemp(tmpdir) == NULL) {
        printf("SKIP: fsdir_inotify_arrival: mkdtemp failed\n");
        return f + 1; /* wolfP11-4prd */
    }

    if (snprintf(p11k_path, sizeof(p11k_path), "%s/arrive.p11k", tmpdir)
            >= (int)sizeof(p11k_path)) {
        rmdir(tmpdir);
        printf("SKIP: fsdir_inotify_arrival: path too long\n");
        return f + 1; /* wolfP11-4prd */
    }

    if (setenv("WOLFP11_FSDIR_PATH", tmpdir, 1) != 0) {
        rmdir(tmpdir);
        printf("SKIP: fsdir_inotify_arrival: setenv failed\n");
        return f + 1; /* wolfP11-4prd */
    }

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "fsdir_inotify_arrival: C_Initialize");
    if (rv != CKR_OK) {
        unsetenv("WOLFP11_FSDIR_PATH");
        rmdir(tmpdir);
        return f;
    }

    /* Allow the initial scan to complete.  Dir is empty so no event fires. */
    { struct timespec ts_ = {0, 50000000L}; nanosleep(&ts_, NULL); }

    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    f += check(rv == CKR_OK && count == 1,
               "fsdir_inotify_arrival: empty dir yields 1 slot before file");

    /* Create the keystore file -- triggers IN_CREATE then IN_CLOSE_WRITE. */
    ret = wp11_keystore_create(p11k_path, FSDIR_TEST_PIN_BYTES,
                               FSDIR_TEST_PIN_LEN, NULL, 0u);
    if (ret != WP11_KEYSTORE_OK) {
        C_Finalize(NULL);
        unsetenv("WOLFP11_FSDIR_PATH");
        rmdir(tmpdir);
        printf("SKIP: fsdir_inotify_arrival: keystore_create failed (%d)\n", ret);
        return f;
    }

    /* Poll up to 500 ms (50 * 10 ms) for the slot-arrival event. */
    rv = CKR_NO_EVENT;
    ev_slot = (CK_SLOT_ID)-1u;
    for (i = 0; i < 50; i++) {
        rv = C_WaitForSlotEvent(CKF_DONT_BLOCK, &ev_slot, NULL);
        if (rv == CKR_OK) break;
        { struct timespec ts_ = {0, 10000000L}; nanosleep(&ts_, NULL); }
    }
    f += check(rv == CKR_OK,
               "fsdir_inotify_arrival: C_WaitForSlotEvent fires on file create");

    count = 16;
    C_GetSlotList(CK_FALSE, slots, &count);
    f += check(count == 2,
               "fsdir_inotify_arrival: slot count == 2 after .p11k arrives");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "fsdir_inotify_arrival: C_Finalize");

    unsetenv("WOLFP11_FSDIR_PATH");
    unlink(p11k_path);
    rmdir(tmpdir);
    return f;
}

/* -------------------------------------------------------------------------
 * test_fsdir_inotify_departure
 *
 * Start C_Initialize with one .p11k file, wait for the initial scan, then
 * remove the file and verify the inotify thread fires a departure event
 * within 500 ms.
 *
 * Oracle: C_WaitForSlotEvent returns CKR_OK and slot count drops to 1.
 * ---------------------------------------------------------------------- */
static int test_fsdir_inotify_departure(void)
{
    char       tmpdir[64];
    char       p11k_path[128];
    CK_RV      rv;
    CK_SLOT_ID slots[16];
    CK_SLOT_ID ev_slot;
    CK_ULONG   count;
    int        ret;
    int        i;
    int        f = 0;

    strncpy(tmpdir, "/tmp/wp11_fsdir_ino_XXXXXX", sizeof(tmpdir) - 1u);
    tmpdir[sizeof(tmpdir) - 1u] = '\0';
    if (mkdtemp(tmpdir) == NULL) {
        printf("SKIP: fsdir_inotify_departure: mkdtemp failed\n");
        return f + 1; /* wolfP11-4prd */
    }

    if (snprintf(p11k_path, sizeof(p11k_path), "%s/depart.p11k", tmpdir)
            >= (int)sizeof(p11k_path)) {
        rmdir(tmpdir);
        printf("SKIP: fsdir_inotify_departure: path too long\n");
        return f + 1; /* wolfP11-4prd */
    }

    ret = wp11_keystore_create(p11k_path, FSDIR_TEST_PIN_BYTES,
                               FSDIR_TEST_PIN_LEN, NULL, 0u);
    if (ret != WP11_KEYSTORE_OK) {
        rmdir(tmpdir);
        printf("SKIP: fsdir_inotify_departure: keystore_create failed (%d)\n",
               ret);
        return f + 1; /* wolfP11-4prd */
    }

    if (setenv("WOLFP11_FSDIR_PATH", tmpdir, 1) != 0) {
        unlink(p11k_path);
        rmdir(tmpdir);
        printf("SKIP: fsdir_inotify_departure: setenv failed\n");
        return f + 1; /* wolfP11-4prd */
    }

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "fsdir_inotify_departure: C_Initialize");
    if (rv != CKR_OK) {
        unsetenv("WOLFP11_FSDIR_PATH");
        unlink(p11k_path);
        rmdir(tmpdir);
        return f;
    }

    /* Allow the initial scan to complete. */
    { struct timespec ts_ = {0, 50000000L}; nanosleep(&ts_, NULL); }

    count = 16;
    C_GetSlotList(CK_FALSE, slots, &count);
    if (count < 2) {
        C_Finalize(NULL);
        unsetenv("WOLFP11_FSDIR_PATH");
        unlink(p11k_path);
        rmdir(tmpdir);
        printf("SKIP: fsdir_inotify_departure: initial scan missed the file\n");
        return f + 1;
    }

    /* Consume the arrival event so the departure poll starts from a clean queue */
    ev_slot = (CK_SLOT_ID)-1u;
    C_WaitForSlotEvent(CKF_DONT_BLOCK, &ev_slot, NULL);

    /* Remove the .p11k file -- triggers IN_DELETE. */
    unlink(p11k_path);

    /* Poll up to 500 ms for the departure event. */
    rv = CKR_NO_EVENT;
    ev_slot = (CK_SLOT_ID)-1u;
    for (i = 0; i < 50; i++) {
        rv = C_WaitForSlotEvent(CKF_DONT_BLOCK, &ev_slot, NULL);
        if (rv == CKR_OK) break;
        { struct timespec ts_ = {0, 10000000L}; nanosleep(&ts_, NULL); }
    }
    f += check(rv == CKR_OK,
               "fsdir_inotify_departure: C_WaitForSlotEvent fires on file delete");

    /* CK_TRUE: count only token-present slots.  Departed FSDIR slot stays
     * in_use (slot-list slot) but token_present is cleared on departure,
     * mirroring the flash and USB hotplug backends. */
    count = 16;
    C_GetSlotList(CK_TRUE, slots, &count);
    f += check(count == 1,
               "fsdir_inotify_departure: 1 token-present slot after .p11k departs");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "fsdir_inotify_departure: C_Finalize");

    unsetenv("WOLFP11_FSDIR_PATH");
    rmdir(tmpdir);
    return f;
}
#endif /* WOLFP11_CFG_TEST_INOTIFY */

/* -------------------------------------------------------------------------
 * Public entry point
 * ---------------------------------------------------------------------- */

int wp11_test_fsdir(void)
{
    int failures = 0;
    failures += test_fsdir_slot_detected();
    failures += test_fsdir_login_correct_pin();
    failures += test_fsdir_login_wrong_pin();
    failures += test_fsdir_logout_clears_keys();
#ifdef WOLFP11_CFG_TEST_INOTIFY
    failures += test_fsdir_inotify_arrival();
    failures += test_fsdir_inotify_departure();
#endif
    return failures;
}

#else /* WOLFP11_CFG_FSDIR_BACKEND */

int wp11_test_fsdir(void)
{
    return 0;
}

#endif /* WOLFP11_CFG_FSDIR_BACKEND */
#endif /* WOLFP11_CFG_TEST */
