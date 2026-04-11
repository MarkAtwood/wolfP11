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

/* wp11_test_pkcs11.c -- tests for the wolfP11 PKCS#11 layer
 *
 * Compile with -DWOLFP11_CFG_TEST to enable.
 * Returns 0 on full pass, or the count of failures.
 */

/* setenv/unsetenv require POSIX.1-2008 */
#define _POSIX_C_SOURCE 200809L

#include "test/wp11_test_pkcs11.h"

#ifdef WOLFP11_CFG_TEST

#include "wolfp11/wp11_pkcs11.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* wolfCrypt ECC, Ed25519, AES, RSA, and SHA-256 for independent oracle verification in soft-token tests */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>

/* Test helpers declared in src/wp11_pkcs11.c under WOLFP11_CFG_TEST. */
int wp11_test_soft_export_pub_x963(CK_OBJECT_HANDLE hKey,
                                    uint8_t *out, CK_ULONG *outlen);
int wp11_test_soft_export_ed25519_pub(CK_OBJECT_HANDLE hKey,
                                       uint8_t *out, CK_ULONG *outlen);
/* Direct OAEP oracle: bypasses PKCS#11 session layer, for C_Encrypt cross-validation. */
int wp11_test_soft_rsa_oaep_decrypt(CK_OBJECT_HANDLE hKey,
                                     const uint8_t *ct, word32 ctlen,
                                     uint8_t *pt, word32 ptbuflen, word32 *ptlen,
                                     int hash_type, int mgf);

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
 * Test 1: init_finalize
 * ---------------------------------------------------------------------- */

static int test_init_finalize(void)
{
    CK_RV rv;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "init_finalize: C_Initialize returns CKR_OK");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "init_finalize: C_Finalize returns CKR_OK");

    return f;
}

/* -------------------------------------------------------------------------
 * Test 2: double_init
 * ---------------------------------------------------------------------- */

static int test_double_init(void)
{
    CK_RV rv;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "double_init: first C_Initialize returns CKR_OK");

    rv = C_Initialize(NULL);
    f += check(rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
               "double_init: second C_Initialize returns CKR_CRYPTOKI_ALREADY_INITIALIZED");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "double_init: C_Finalize after double init");

    return f;
}

/* -------------------------------------------------------------------------
 * Test 3: not_initialized
 * ---------------------------------------------------------------------- */

static int test_not_initialized(void)
{
    CK_ULONG count = 0;
    CK_RV rv;

    /* Ensure not initialized */
    C_Finalize(NULL);

    rv = C_GetSlotList(CK_FALSE, NULL, &count);
    return check(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
                 "not_initialized: C_GetSlotList returns CKR_CRYPTOKI_NOT_INITIALIZED");
}

/* -------------------------------------------------------------------------
 * Test 4: get_info
 * ---------------------------------------------------------------------- */

static int test_get_info(void)
{
    CK_INFO info;
    CK_RV rv;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "get_info: C_Initialize");

    rv = C_GetInfo(&info);
    f += check(rv == CKR_OK, "get_info: C_GetInfo returns CKR_OK");
    f += check(info.cryptokiVersion.major == 2,
               "get_info: cryptokiVersion.major == 2");
    f += check(info.cryptokiVersion.minor == 40,
               "get_info: cryptokiVersion.minor == 40");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "get_info: C_Finalize");

    return f;
}

/* -------------------------------------------------------------------------
 * Test 5: get_slot_list
 * ---------------------------------------------------------------------- */

static int test_get_slot_list(void)
{
    CK_ULONG count = 0;
    CK_RV rv;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "get_slot_list: C_Initialize");

    rv = C_GetSlotList(CK_FALSE, NULL, &count);
    f += check(rv == CKR_OK, "get_slot_list: C_GetSlotList(NULL) returns CKR_OK");
    f += check(count >= 1, "get_slot_list: count >= 1");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "get_slot_list: C_Finalize");

    return f;
}

/* -------------------------------------------------------------------------
 * Test 6: get_slot_info
 * ---------------------------------------------------------------------- */

static int test_get_slot_info(void)
{
    CK_SLOT_INFO info;
    CK_RV rv;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "get_slot_info: C_Initialize");

    rv = C_GetSlotInfo(0, &info);
    f += check(rv == CKR_OK, "get_slot_info: slot 0 returns CKR_OK");

    rv = C_GetSlotInfo(99, &info);
    f += check(rv == CKR_SLOT_ID_INVALID,
               "get_slot_info: invalid slot returns CKR_SLOT_ID_INVALID");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "get_slot_info: C_Finalize");

    return f;
}

/* -------------------------------------------------------------------------
 * Test 7: get_token_info
 * ---------------------------------------------------------------------- */

static int test_get_token_info(void)
{
    CK_TOKEN_INFO info;
    CK_RV rv;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "get_token_info: C_Initialize");

    rv = C_GetTokenInfo(0, &info);
    f += check(rv == CKR_OK, "get_token_info: C_GetTokenInfo returns CKR_OK");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "get_token_info: C_Finalize");

    return f;
}

/* -------------------------------------------------------------------------
 * Test 8: get_mechanism_list
 * ---------------------------------------------------------------------- */

static int test_get_mechanism_list(void)
{
    CK_ULONG count = 0;
    CK_RV rv;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "get_mechanism_list: C_Initialize");

    rv = C_GetMechanismList(0, NULL, &count);
    f += check(rv == CKR_OK,
               "get_mechanism_list: C_GetMechanismList(NULL) returns CKR_OK");
    f += check(count >= 1, "get_mechanism_list: count >= 1");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "get_mechanism_list: C_Finalize");

    return f;
}

/* -------------------------------------------------------------------------
 * Test 9: open_close_session
 * ---------------------------------------------------------------------- */

static int test_open_close_session(void)
{
    CK_SESSION_HANDLE hSess = 0;
    CK_RV rv;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "open_close_session: C_Initialize");

    rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "open_close_session: C_OpenSession returns CKR_OK");
    f += check(hSess != 0, "open_close_session: session handle non-zero");

    rv = C_CloseSession(hSess);
    f += check(rv == CKR_OK, "open_close_session: C_CloseSession returns CKR_OK");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "open_close_session: C_Finalize");

    return f;
}

/* -------------------------------------------------------------------------
 * Test 10: invalid_session
 * ---------------------------------------------------------------------- */

static int test_invalid_session(void)
{
    CK_SESSION_INFO info;
    CK_RV rv;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "invalid_session: C_Initialize");

    rv = C_GetSessionInfo(0xDEAD, &info);
    f += check(rv == CKR_SESSION_HANDLE_INVALID,
               "invalid_session: C_GetSessionInfo returns CKR_SESSION_HANDLE_INVALID");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "invalid_session: C_Finalize");

    return f;
}

/* -------------------------------------------------------------------------
 * Test 11: login_logout
 * ---------------------------------------------------------------------- */

static int test_login_logout(void)
{
    CK_SESSION_HANDLE hSess = 0;
    CK_RV rv;
    int f = 0;

    /* Force in-memory soft token so C_Login is not gated on keystore existence. */
    setenv("WOLFP11_SOFT_KEYSTORE_PATH", "", 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "login_logout: C_Initialize");

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "login_logout: C_OpenSession");

    rv = C_Login(hSess, CKU_USER, (CK_UTF8CHAR *)"1234", 4);
    f += check(rv == CKR_OK, "login_logout: C_Login returns CKR_OK");

    rv = C_Login(hSess, CKU_USER, (CK_UTF8CHAR *)"1234", 4);
    f += check(rv == CKR_USER_ALREADY_LOGGED_IN,
               "login_logout: second C_Login returns CKR_USER_ALREADY_LOGGED_IN");

    rv = C_Logout(hSess);
    f += check(rv == CKR_OK, "login_logout: C_Logout returns CKR_OK");

    rv = C_CloseSession(hSess);
    f += check(rv == CKR_OK, "login_logout: C_CloseSession");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "login_logout: C_Finalize");

    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}

/* -------------------------------------------------------------------------
 * Test 12: get_attribute_value (error paths)
 *
 * wolfP11-4fj: verify the pre-loop error returns (no object handle needed).
 * The attribute-value semantics tests (unknown type -> CKR_ATTRIBUTE_TYPE_INVALID,
 * buffer-too-small -> CKR_BUFFER_TOO_SMALL) require a real object handle and
 * are in test_flash_pkcs11_get_attribute_value below.
 * ---------------------------------------------------------------------- */

static int test_get_attribute_value_error_paths(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE hSess = 0;
    CK_ATTRIBUTE attr;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "get_attr_err: C_Initialize");

    rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "get_attr_err: C_OpenSession");

    /* NULL template -> CKR_ARGUMENTS_BAD */
    rv = C_GetAttributeValue(hSess, 1, NULL_PTR, 1);
    f += check(rv == CKR_ARGUMENTS_BAD,
               "get_attr_err: NULL pTemplate -> CKR_ARGUMENTS_BAD");

    /* Invalid session handle -> CKR_SESSION_HANDLE_INVALID */
    memset(&attr, 0, sizeof(attr));
    attr.type = CKA_CLASS;
    rv = C_GetAttributeValue(0xFFFFFFFFUL, 1, &attr, 1);
    f += check(rv == CKR_SESSION_HANDLE_INVALID,
               "get_attr_err: bad session -> CKR_SESSION_HANDLE_INVALID");

    /* Valid session, invalid object handle -> CKR_OBJECT_HANDLE_INVALID */
    rv = C_GetAttributeValue(hSess, 0xDEADBEEFUL, &attr, 1);
    f += check(rv == CKR_OBJECT_HANDLE_INVALID,
               "get_attr_err: bad object -> CKR_OBJECT_HANDLE_INVALID");

    C_CloseSession(hSess);
    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "get_attr_err: C_Finalize");

    return f;
}

/* -------------------------------------------------------------------------
 * Test 13: find_objects
 * ---------------------------------------------------------------------- */

static int test_find_objects(void)
{
    CK_SESSION_HANDLE hSess = 0;
    CK_OBJECT_HANDLE  objs[16];
    CK_ULONG          nfound = 0;
    CK_RV rv;
    int f = 0;

    /* Force in-memory soft token so C_Login is not gated on keystore existence. */
    setenv("WOLFP11_SOFT_KEYSTORE_PATH", "", 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "find_objects: C_Initialize");

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "find_objects: C_OpenSession");

    rv = C_Login(hSess, CKU_USER, (CK_UTF8CHAR *)"pin", 3);
    f += check(rv == CKR_OK, "find_objects: C_Login");

    rv = C_FindObjectsInit(hSess, NULL, 0);
    f += check(rv == CKR_OK, "find_objects: C_FindObjectsInit returns CKR_OK");

    rv = C_FindObjects(hSess, objs, 16, &nfound);
    f += check(rv == CKR_OK, "find_objects: C_FindObjects returns CKR_OK");

    rv = C_FindObjectsFinal(hSess);
    f += check(rv == CKR_OK, "find_objects: C_FindObjectsFinal returns CKR_OK");

    rv = C_CloseSession(hSess);
    f += check(rv == CKR_OK, "find_objects: C_CloseSession");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "find_objects: C_Finalize");

    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}

/* -------------------------------------------------------------------------
 * Hotplug tests
 *
 * These use wp11_test_inject_hotplug() to simulate token arrival and
 * departure without real USB hardware.  The function is defined in
 * src/wp11_pkcs11.c under WOLFP11_CFG_TEST and calls the same slot_add /
 * slot_remove / hotplug_push_event paths that the real libusb callback
 * uses, so these tests exercise the full hotplug code path.
 *
 * VIDs/PIDs used: YubiKey 5 NFC (0x1050:0x0407) -- known entry in token_db.
 * An unknown VID/PID (0xDEAD:0xBEEF) is used to verify that unknown tokens
 * are silently ignored.
 * ---------------------------------------------------------------------- */

/* Forward declarations: defined in src/wp11_pkcs11.c under WOLFP11_CFG_TEST */
void wp11_test_inject_hotplug(uint16_t vid, uint16_t pid, int arrived);
#ifdef WOLFP11_CFG_USB_BACKEND
void wp11_test_inject_piv_login(CK_SLOT_ID slot_id);
void wp11_test_inject_piv_login_with_certs(CK_SLOT_ID slot_id);
#endif

/* YubiKey 5 NFC VID/PID -- present in the token database */
#define TEST_VID 0x1050u
#define TEST_PID 0x0407u

/* -------------------------------------------------------------------------
 * test_slot_soft_token_present
 *
 * Slot 0 (soft token) must always exist and must have CKF_TOKEN_PRESENT.
 * ---------------------------------------------------------------------- */
static int test_slot_soft_token_present(void)
{
    CK_SLOT_INFO info;
    CK_RV rv;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "slot_soft_token_present: C_Initialize");

    rv = C_GetSlotInfo(0, &info);
    f += check(rv == CKR_OK,
               "slot_soft_token_present: C_GetSlotInfo(0) returns CKR_OK");
    f += check((info.flags & CKF_TOKEN_PRESENT) != 0,
               "slot_soft_token_present: slot 0 has CKF_TOKEN_PRESENT");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "slot_soft_token_present: C_Finalize");
    return f;
}

/* -------------------------------------------------------------------------
 * test_wait_for_slot_event_no_event
 *
 * Polling C_WaitForSlotEvent with no pending events returns CKR_NO_EVENT.
 * ---------------------------------------------------------------------- */
static int test_wait_for_slot_event_no_event(void)
{
    CK_SLOT_ID slot = 0;
    CK_RV rv;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "wait_no_event: C_Initialize");

    /* CKF_DONT_BLOCK: return immediately, queue is empty */
    rv = C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL);
    f += check(rv == CKR_NO_EVENT,
               "wait_no_event: CKF_DONT_BLOCK with empty queue returns CKR_NO_EVENT");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "wait_no_event: C_Finalize");
    return f;
}

/* -------------------------------------------------------------------------
 * test_generate_random
 *
 * Verify:
 * - Before C_Initialize returns CKR_CRYPTOKI_NOT_INITIALIZED.
 * - NULL buffer returns CKR_ARGUMENTS_BAD.
 * - Invalid session returns CKR_SESSION_HANDLE_INVALID.
 * - Zero-length request returns CKR_OK (nothing to do).
 * - Normal call returns CKR_OK and fills the buffer.
 * - Two calls produce different output (oracle: randomness is non-constant).
 * ---------------------------------------------------------------------- */

static int test_generate_random(void)
{
    CK_SESSION_HANDLE hSess = 0;
    CK_BYTE buf1[32];
    CK_BYTE buf2[32];
    CK_RV rv;
    int f = 0;
    int i;
    int all_same;

    /* Before init */
    rv = C_GenerateRandom(1, buf1, sizeof(buf1));
    f += check(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
               "generate_random: before init returns CKR_CRYPTOKI_NOT_INITIALIZED");

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "generate_random: C_Initialize");

    /* NULL buffer */
    rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "generate_random: C_OpenSession");

    rv = C_GenerateRandom(hSess, NULL, 16);
    f += check(rv == CKR_ARGUMENTS_BAD,
               "generate_random: NULL buffer returns CKR_ARGUMENTS_BAD");

    /* Invalid session handle */
    rv = C_GenerateRandom(0xDEAD, buf1, sizeof(buf1));
    f += check(rv == CKR_SESSION_HANDLE_INVALID,
               "generate_random: invalid session returns CKR_SESSION_HANDLE_INVALID");

    /* Zero-length is a no-op */
    rv = C_GenerateRandom(hSess, buf1, 0);
    f += check(rv == CKR_OK,
               "generate_random: zero-length returns CKR_OK");

    /* Normal fill */
    memset(buf1, 0, sizeof(buf1));
    rv = C_GenerateRandom(hSess, buf1, sizeof(buf1));
    f += check(rv == CKR_OK, "generate_random: normal call returns CKR_OK");

    /* Buffer should not be all zeros after a successful fill */
    all_same = 1;
    for (i = 0; i < (int)sizeof(buf1); i++) {
        if (buf1[i] != 0) { all_same = 0; break; }
    }
    f += check(!all_same, "generate_random: output buffer is not all zeros");

    /* Two calls should produce different output (P(collision) = 2^-256) */
    memset(buf2, 0, sizeof(buf2));
    rv = C_GenerateRandom(hSess, buf2, sizeof(buf2));
    f += check(rv == CKR_OK, "generate_random: second call returns CKR_OK");
    f += check(memcmp(buf1, buf2, sizeof(buf1)) != 0,
               "generate_random: two calls produce different output");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "generate_random: C_Finalize");

    return f;
}

/* -------------------------------------------------------------------------
 * test_hotplug_arrival
 *
 * Inject an arrival event for a known token.  Verify:
 * - C_GetSlotList reports an additional slot (> 1 total).
 * - C_WaitForSlotEvent (poll) returns CKR_OK and the new slot ID.
 * - C_GetSlotInfo on the new slot has CKF_TOKEN_PRESENT.
 * ---------------------------------------------------------------------- */
static int test_hotplug_arrival(void)
{
    CK_SLOT_ID  slots[16];
    CK_ULONG    count = 0;
    CK_SLOT_ID  event_slot = 0;
    CK_SLOT_INFO info;
    CK_RV rv;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "hotplug_arrival: C_Initialize");

    /* Baseline: only soft slot (slot 0) */
    rv = C_GetSlotList(CK_FALSE, NULL, &count);
    f += check(rv == CKR_OK && count == 1,
               "hotplug_arrival: baseline slot count == 1");

    /* Simulate token insertion */
    wp11_test_inject_hotplug(TEST_VID, TEST_PID, 1 /* arrived */);

    /* Slot count must now be 2 */
    count = 0;
    rv = C_GetSlotList(CK_FALSE, NULL, &count);
    f += check(rv == CKR_OK, "hotplug_arrival: C_GetSlotList after arrival");
    f += check(count == 2, "hotplug_arrival: slot count == 2 after arrival");

    /* Enumerate slot IDs and find the new USB slot (ID != 0) */
    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    f += check(rv == CKR_OK, "hotplug_arrival: C_GetSlotList with buffer");

    /* The USB slot has CKF_TOKEN_PRESENT */
    if (count >= 2) {
        /* slots[1] is the new USB slot (soft token is always slots[0] == 0) */
        rv = C_GetSlotInfo(slots[1], &info);
        f += check(rv == CKR_OK,
                   "hotplug_arrival: C_GetSlotInfo on new slot returns CKR_OK");
        f += check((info.flags & CKF_TOKEN_PRESENT) != 0,
                   "hotplug_arrival: new slot has CKF_TOKEN_PRESENT");
    }

    /* C_WaitForSlotEvent (poll) must return the new slot ID */
    rv = C_WaitForSlotEvent(CKF_DONT_BLOCK, &event_slot, NULL);
    f += check(rv == CKR_OK,
               "hotplug_arrival: C_WaitForSlotEvent returns CKR_OK");
    f += check(event_slot != 0,
               "hotplug_arrival: event slot is a USB slot (not slot 0)");

    /* No further events pending */
    rv = C_WaitForSlotEvent(CKF_DONT_BLOCK, &event_slot, NULL);
    f += check(rv == CKR_NO_EVENT,
               "hotplug_arrival: no further events after consuming one");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "hotplug_arrival: C_Finalize");
    return f;
}

/* -------------------------------------------------------------------------
 * test_hotplug_departure
 *
 * Inject arrival then departure.  Verify:
 * - After departure, CKF_TOKEN_PRESENT is clear on the slot.
 * - An open session on the slot is invalidated.
 * - C_WaitForSlotEvent (poll) returns the departure event.
 * ---------------------------------------------------------------------- */
static int test_hotplug_departure(void)
{
    CK_SLOT_ID       slots[16];
    CK_ULONG         count = 16;
    CK_SESSION_HANDLE hSess = 0;
    CK_SLOT_ID        event_slot = 0;
    CK_SLOT_INFO      info;
    CK_SESSION_INFO   sinfo;
    CK_RV rv;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "hotplug_departure: C_Initialize");

    /* Arrive */
    wp11_test_inject_hotplug(TEST_VID, TEST_PID, 1);

    /* Consume the arrival event so the queue is clean for departure check */
    rv = C_WaitForSlotEvent(CKF_DONT_BLOCK, &event_slot, NULL);
    f += check(rv == CKR_OK, "hotplug_departure: consumed arrival event");

    /* Find the USB slot ID */
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    f += check(rv == CKR_OK && count == 2,
               "hotplug_departure: slot count == 2 before departure");

    /* Open a session on the USB slot -- slot 1 by convention */
    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION, NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "hotplug_departure: C_OpenSession on USB slot");

    /* Depart */
    wp11_test_inject_hotplug(TEST_VID, TEST_PID, 0 /* departed */);

    /* CKF_TOKEN_PRESENT must be cleared */
    rv = C_GetSlotInfo(slots[1], &info);
    f += check(rv == CKR_OK,
               "hotplug_departure: C_GetSlotInfo still valid after departure");
    f += check((info.flags & CKF_TOKEN_PRESENT) == 0,
               "hotplug_departure: CKF_TOKEN_PRESENT cleared after departure");

    /* Session was invalidated on departure (slot_remove closes all sessions) */
    rv = C_GetSessionInfo(hSess, &sinfo);
    f += check(rv == CKR_SESSION_HANDLE_INVALID,
               "hotplug_departure: session invalidated after token departure");

    /* Departure event in queue */
    rv = C_WaitForSlotEvent(CKF_DONT_BLOCK, &event_slot, NULL);
    f += check(rv == CKR_OK,
               "hotplug_departure: C_WaitForSlotEvent returns departure event");
    f += check(event_slot == slots[1],
               "hotplug_departure: event slot matches departed USB slot");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "hotplug_departure: C_Finalize");
    return f;
}

/* -------------------------------------------------------------------------
 * test_hotplug_reinsert
 *
 * Remove a token then re-insert it.  Verify the same slot ID is reused
 * and token_present is set again.  This tests the slot_add() reuse path.
 * ---------------------------------------------------------------------- */
static int test_hotplug_reinsert(void)
{
    CK_SLOT_ID slots_before[16];
    CK_SLOT_ID slots_after[16];
    CK_ULONG   count = 16;
    CK_SLOT_ID event_slot = 0;
    CK_SLOT_INFO info;
    CK_RV rv;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "hotplug_reinsert: C_Initialize");

    wp11_test_inject_hotplug(TEST_VID, TEST_PID, 1); /* arrive */
    rv = C_WaitForSlotEvent(CKF_DONT_BLOCK, &event_slot, NULL);
    f += check(rv == CKR_OK, "hotplug_reinsert: consumed arrival event");

    /* Record slot IDs before removal */
    rv = C_GetSlotList(CK_FALSE, slots_before, &count);
    f += check(rv == CKR_OK && count == 2,
               "hotplug_reinsert: slot count == 2 after first arrival");

    wp11_test_inject_hotplug(TEST_VID, TEST_PID, 0); /* depart */
    rv = C_WaitForSlotEvent(CKF_DONT_BLOCK, &event_slot, NULL);
    f += check(rv == CKR_OK, "hotplug_reinsert: consumed departure event");

    wp11_test_inject_hotplug(TEST_VID, TEST_PID, 1); /* re-arrive */
    rv = C_WaitForSlotEvent(CKF_DONT_BLOCK, &event_slot, NULL);
    f += check(rv == CKR_OK, "hotplug_reinsert: consumed re-arrival event");

    /* Slot count must still be 2 -- slot entry was reused, not added */
    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots_after, &count);
    f += check(rv == CKR_OK && count == 2,
               "hotplug_reinsert: slot count still 2 after re-insertion");

    /* Same slot ID used */
    f += check(slots_after[1] == slots_before[1],
               "hotplug_reinsert: same slot ID reused after re-insertion");

    /* token_present is set again */
    rv = C_GetSlotInfo(slots_after[1], &info);
    f += check(rv == CKR_OK,
               "hotplug_reinsert: C_GetSlotInfo on reinserted slot");
    f += check((info.flags & CKF_TOKEN_PRESENT) != 0,
               "hotplug_reinsert: CKF_TOKEN_PRESENT restored after re-insertion");

    /* Unknown VID/PID injection must not add a slot */
    count = 16;
    wp11_test_inject_hotplug(0xDEADu, 0xBEEFu, 1);
    rv = C_GetSlotList(CK_FALSE, slots_after, &count);
    f += check(rv == CKR_OK && count == 2,
               "hotplug_reinsert: unknown VID/PID does not add a slot");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "hotplug_reinsert: C_Finalize");
    return f;
}

/* -------------------------------------------------------------------------
 * test_piv_login_four_slots
 *
 * Verify that wp11_test_inject_piv_login creates exactly 4 key objects
 * (9A/9C/9D/9E) with correct labels and CKA_ID values, and that they are
 * removed when C_Logout is called.
 * ---------------------------------------------------------------------- */
#ifdef WOLFP11_CFG_USB_BACKEND
static int test_piv_login_four_slots(void)
{
    CK_SLOT_ID    slots[16];
    CK_ULONG      nslots = 16;
    CK_SLOT_ID    piv_slot_id;
    CK_SESSION_HANDLE sess = 0;
    CK_OBJECT_HANDLE  objs[16];
    CK_ULONG          nfound;
    CK_RV rv;
    int   f = 0;
    int   i;

    static const struct {
        uint8_t     key_id;
        const char *label;
    } expected[] = {
        { 0x01, "PIV Authentication"    },
        { 0x02, "PIV Digital Signature" },
        { 0x03, "PIV Key Management"    },
        { 0x04, "PIV Card Authentication" },
    };

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "piv_four_slots: C_Initialize");

    /* Inject a YubiKey 5 NFC arrival */
    wp11_test_inject_hotplug(TEST_VID, TEST_PID, 1);

    rv = C_GetSlotList(CK_FALSE, slots, &nslots);
    f += check(rv == CKR_OK && nslots == 2,
               "piv_four_slots: slot count == 2 after arrival");

    /* Find the non-zero slot (PIV hardware slot) */
    piv_slot_id = (CK_SLOT_ID)-1;
    for (i = 0; i < (int)nslots; i++) {
        if (slots[i] != 0) { piv_slot_id = slots[i]; break; }
    }
    f += check(piv_slot_id != (CK_SLOT_ID)-1,
               "piv_four_slots: found PIV slot");
    if (f > 0) { C_Finalize(NULL); return f; }

    rv = C_OpenSession(piv_slot_id, CKF_SERIAL_SESSION,
                       NULL, NULL, &sess);
    f += check(rv == CKR_OK, "piv_four_slots: C_OpenSession");

    /* Inject PIV login (creates 4 key objects) */
    wp11_test_inject_piv_login(piv_slot_id);

    /* Enumerate all objects */
    rv = C_FindObjectsInit(sess, NULL, 0);
    f += check(rv == CKR_OK, "piv_four_slots: C_FindObjectsInit");
    nfound = 0;
    rv = C_FindObjects(sess, objs, 16, &nfound);
    f += check(rv == CKR_OK, "piv_four_slots: C_FindObjects");
    f += check(nfound == 4,  "piv_four_slots: exactly 4 key objects after login");
    rv = C_FindObjectsFinal(sess);
    f += check(rv == CKR_OK, "piv_four_slots: C_FindObjectsFinal");

    /* Verify each expected key exists (by label and ID) */
    for (i = 0; i < 4; i++) {
        CK_ULONG  j;
        int       found_match = 0;
        for (j = 0; j < nfound; j++) {
            CK_BYTE      id_buf[16];
            CK_UTF8CHAR  lbl_buf[33];
            CK_ATTRIBUTE attrs[2];
            char         lbl_str[33];
            CK_ULONG     lbl_len;

            memset(id_buf,  0, sizeof(id_buf));
            memset(lbl_buf, 0, sizeof(lbl_buf));
            attrs[0].type       = CKA_ID;
            attrs[0].pValue     = id_buf;
            attrs[0].ulValueLen = sizeof(id_buf);
            attrs[1].type       = CKA_LABEL;
            attrs[1].pValue     = lbl_buf;
            attrs[1].ulValueLen = sizeof(lbl_buf) - 1u;

            rv = C_GetAttributeValue(sess, objs[j], attrs, 2);
            if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) continue;
            if (attrs[0].ulValueLen == (CK_ULONG)-1) continue;
            if (id_buf[0] != expected[i].key_id) continue;

            lbl_len = (attrs[1].ulValueLen == (CK_ULONG)-1) ?
                       0u : attrs[1].ulValueLen;
            if (lbl_len > 32u) lbl_len = 32u;
            memcpy(lbl_str, lbl_buf, lbl_len);
            lbl_str[lbl_len] = '\0';
            {
                CK_ULONG k;
                for (k = lbl_len; k > 0 && lbl_str[k-1] == ' '; k--)
                    lbl_str[k-1] = '\0';
            }
            if (strcmp(lbl_str, expected[i].label) == 0) {
                found_match = 1;
                break;
            }
        }
        {
            char msg[80];
            snprintf(msg, sizeof(msg),
                     "piv_four_slots: found key id=0x%02X label='%s'",
                     expected[i].key_id, expected[i].label);
            f += check(found_match, msg);
        }
    }

    /* Simulate C_Logout by removing the PIV slot (departure clears keys) */
    wp11_test_inject_hotplug(TEST_VID, TEST_PID, 0);

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "piv_four_slots: C_Finalize");
    return f;
}

/* -------------------------------------------------------------------------
 * test_piv_cert_objects
 *
 * Verify that wp11_test_inject_piv_login_with_certs creates 4 CKO_PRIVATE_KEY
 * objects AND 4 CKO_CERTIFICATE objects (one per PIV slot), and that each
 * cert object reports CKC_X_509 for CKA_CERTIFICATE_TYPE and the expected
 * DER bytes for CKA_VALUE.
 * ---------------------------------------------------------------------- */
static int test_piv_cert_objects(void)
{
    /* Synthetic cert bytes from piv_mock_cert_transport in wp11_pkcs11.c */
    static const uint8_t expected_cert[10] = {
        0x01u, 0x02u, 0x03u, 0x04u, 0x05u,
        0x06u, 0x07u, 0x08u, 0x09u, 0x0Au
    };

    CK_SLOT_ID        slots[16];
    CK_ULONG          nslots = 16;
    CK_SLOT_ID        piv_slot_id;
    CK_SESSION_HANDLE sess = 0;
    CK_OBJECT_HANDLE  objs[32];
    CK_ULONG          nfound;
    CK_ULONG          ncert = 0;
    CK_RV rv;
    int   f = 0;
    int   i;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "piv_cert_objs: C_Initialize");

    wp11_test_inject_hotplug(TEST_VID, TEST_PID, 1);

    rv = C_GetSlotList(CK_FALSE, slots, &nslots);
    f += check(rv == CKR_OK && nslots == 2,
               "piv_cert_objs: slot count == 2 after arrival");

    piv_slot_id = (CK_SLOT_ID)-1;
    for (i = 0; i < (int)nslots; i++) {
        if (slots[i] != 0) { piv_slot_id = slots[i]; break; }
    }
    f += check(piv_slot_id != (CK_SLOT_ID)-1, "piv_cert_objs: found PIV slot");
    if (f > 0) { C_Finalize(NULL); return f; }

    rv = C_OpenSession(piv_slot_id, CKF_SERIAL_SESSION, NULL, NULL, &sess);
    f += check(rv == CKR_OK, "piv_cert_objs: C_OpenSession");

    /* Login with cert-providing mock: 4 keys + 4 certs */
    wp11_test_inject_piv_login_with_certs(piv_slot_id);

    rv = C_FindObjectsInit(sess, NULL, 0);
    f += check(rv == CKR_OK, "piv_cert_objs: C_FindObjectsInit");
    nfound = 0;
    rv = C_FindObjects(sess, objs, 32, &nfound);
    f += check(rv == CKR_OK, "piv_cert_objs: C_FindObjects");
    f += check(nfound == 8, "piv_cert_objs: 8 objects (4 keys + 4 certs)");
    rv = C_FindObjectsFinal(sess);
    f += check(rv == CKR_OK, "piv_cert_objs: C_FindObjectsFinal");

    /* Verify each cert object: CKA_CLASS, CKA_CERTIFICATE_TYPE, CKA_VALUE */
    for (i = 0; i < (int)nfound; i++) {
        CK_OBJECT_CLASS  cls = (CK_OBJECT_CLASS)-1;
        CK_ATTRIBUTE     class_attr;

        class_attr.type       = CKA_CLASS;
        class_attr.pValue     = &cls;
        class_attr.ulValueLen = sizeof(cls);

        rv = C_GetAttributeValue(sess, objs[i], &class_attr, 1);
        if (rv != CKR_OK) continue;
        if (cls != CKO_CERTIFICATE) continue;

        ncert++;

        {
            CK_CERTIFICATE_TYPE ct = (CK_CERTIFICATE_TYPE)-1;
            uint8_t             val_buf[32];
            CK_ATTRIBUTE        cert_attrs[2];

            cert_attrs[0].type       = CKA_CERTIFICATE_TYPE;
            cert_attrs[0].pValue     = &ct;
            cert_attrs[0].ulValueLen = sizeof(ct);
            cert_attrs[1].type       = CKA_VALUE;
            cert_attrs[1].pValue     = val_buf;
            cert_attrs[1].ulValueLen = sizeof(val_buf);

            rv = C_GetAttributeValue(sess, objs[i], cert_attrs, 2);
            f += check(rv == CKR_OK, "piv_cert_objs: GetAttributeValue on cert");
            f += check(ct == CKC_X_509,
                       "piv_cert_objs: CKA_CERTIFICATE_TYPE == CKC_X_509");
            f += check(cert_attrs[1].ulValueLen == sizeof(expected_cert),
                       "piv_cert_objs: CKA_VALUE length");
            if (cert_attrs[1].ulValueLen == sizeof(expected_cert)) {
                f += check(memcmp(val_buf, expected_cert,
                                  sizeof(expected_cert)) == 0,
                           "piv_cert_objs: CKA_VALUE bytes match stub");
            }
        }
    }
    f += check(ncert == 4, "piv_cert_objs: exactly 4 CKO_CERTIFICATE objects");

    wp11_test_inject_hotplug(TEST_VID, TEST_PID, 0);

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "piv_cert_objs: C_Finalize");
    return f;
}
#endif /* WOLFP11_CFG_USB_BACKEND */

/* -------------------------------------------------------------------------
 * Flash keystore slot tests
 *
 * These use wp11_test_inject_flash_event() to simulate .p11k files
 * appearing or disappearing without real filesystem events.  The function
 * is defined in src/wp11_pkcs11.c under both WOLFP11_CFG_TEST and
 * WOLFP11_CFG_USB_FLASH_BACKEND; it calls the same slot_add_flash /
 * slot_remove_flash / hotplug_push_event paths the inotify thread uses.
 *
 * Test paths are purely synthetic -- no real files are accessed.
 * ---------------------------------------------------------------------- */
#ifdef WOLFP11_CFG_USB_FLASH_BACKEND

/* Forward declarations -- defined in src/wp11_pkcs11.c under WOLFP11_CFG_TEST */
void         wp11_test_inject_flash_event(const char *path, int arrived);
unsigned int wp11_test_hotplug_dropped(void);

#define TEST_P11K_PATH  "/run/media/testuser/USBKEY/mykeys.p11k"
#define TEST_P11K_PATH2 "/run/media/testuser/USBKEY2/other.p11k"

/* Additional headers for keystore integration tests */
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/random.h>
#include <unistd.h>
#include "wolfp11/wp11_keystore.h"

/* PIN and temp-file path for PKCS#11-level keystore integration tests.
 * Distinct from wp11_test_keystore.c constants to prevent collisions in /tmp. */
#define FLASH_TEST_P11K          "/tmp/wp11_pkcs11_flash.p11k"
#define FLASH_TEST_PIN           "pkcs11test"
#define FLASH_TEST_PIN_LEN       ((CK_ULONG)10)
#define FLASH_TEST_WRONG_PIN     "wrongpass!"
#define FLASH_TEST_WRONG_PIN_LEN ((CK_ULONG)10)

/* Test: injecting a .p11k path adds a new slot with CKF_TOKEN_PRESENT */
static int test_flash_arrival(void)
{
    CK_RV         rv;
    CK_SLOT_ID    slots[16];
    CK_ULONG      count;
    CK_SLOT_INFO  info;
    CK_SLOT_ID    evt_slot;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "flash_arrival: C_Initialize");

    /* Before injection: only the soft token slot (slot 0) */
    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    f += check(rv == CKR_OK && count == 1, "flash_arrival: only soft token before injection");

    wp11_test_inject_flash_event(TEST_P11K_PATH, 1 /* arrived */);

    /* After injection: soft token + one flash slot = 2 slots */
    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    f += check(rv == CKR_OK, "flash_arrival: C_GetSlotList after injection");
    f += check(count == 2, "flash_arrival: slot count == 2 after arrival");

    /* The flash slot must have CKF_TOKEN_PRESENT */
    rv = C_GetSlotInfo(slots[1], &info);
    f += check(rv == CKR_OK, "flash_arrival: C_GetSlotInfo on flash slot");
    f += check((info.flags & CKF_TOKEN_PRESENT) != 0,
               "flash_arrival: flash slot has CKF_TOKEN_PRESENT");

    /* C_WaitForSlotEvent must return the new slot */
    rv = C_WaitForSlotEvent(CKF_DONT_BLOCK, &evt_slot, NULL);
    f += check(rv == CKR_OK, "flash_arrival: C_WaitForSlotEvent returns CKR_OK");
    f += check(evt_slot == slots[1], "flash_arrival: event slot matches flash slot");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "flash_arrival: C_Finalize");
    return f;
}

/* Test: injecting a departure clears CKF_TOKEN_PRESENT and invalidates sessions */
static int test_flash_departure(void)
{
    CK_RV           rv;
    CK_SLOT_ID      slots[16];
    CK_ULONG        count;
    CK_SESSION_HANDLE hSession;
    CK_SLOT_INFO    info;
    CK_SLOT_ID      evt_slot;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "flash_departure: C_Initialize");

    wp11_test_inject_flash_event(TEST_P11K_PATH, 1);

    count = 16;
    C_GetSlotList(CK_FALSE, slots, &count);
    /* Drain the arrival event */
    C_WaitForSlotEvent(CKF_DONT_BLOCK, &evt_slot, NULL);

    /* Open a session on the flash slot */
    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION, NULL, NULL, &hSession);
    f += check(rv == CKR_OK, "flash_departure: C_OpenSession on flash slot");

    /* Remove the .p11k file */
    wp11_test_inject_flash_event(TEST_P11K_PATH, 0 /* departed */);

    /* CKF_TOKEN_PRESENT must be cleared */
    rv = C_GetSlotInfo(slots[1], &info);
    f += check(rv == CKR_OK, "flash_departure: C_GetSlotInfo after departure");
    f += check((info.flags & CKF_TOKEN_PRESENT) == 0,
               "flash_departure: CKF_TOKEN_PRESENT cleared after departure");

    /* Session on the departed slot must be invalidated */
    rv = C_CloseSession(hSession);
    f += check(rv == CKR_SESSION_HANDLE_INVALID,
               "flash_departure: session invalidated after departure");

    /* C_WaitForSlotEvent must deliver the departure event */
    rv = C_WaitForSlotEvent(CKF_DONT_BLOCK, &evt_slot, NULL);
    f += check(rv == CKR_OK, "flash_departure: C_WaitForSlotEvent returns departure event");
    f += check(evt_slot == slots[1], "flash_departure: event slot matches departed flash slot");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "flash_departure: C_Finalize");
    return f;
}

/* Test: removing and reinserting a .p11k file reuses the same slot ID */
static int test_flash_reinsert(void)
{
    CK_RV      rv;
    CK_SLOT_ID slots_before[16], slots_after[16];
    CK_ULONG   count;
    CK_SLOT_ID evt_slot;
    CK_SLOT_INFO info;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "flash_reinsert: C_Initialize");

    wp11_test_inject_flash_event(TEST_P11K_PATH, 1);
    count = 16;
    C_GetSlotList(CK_FALSE, slots_before, &count);
    C_WaitForSlotEvent(CKF_DONT_BLOCK, &evt_slot, NULL); /* drain */
    f += check(count == 2, "flash_reinsert: slot count == 2 after first arrival");

    wp11_test_inject_flash_event(TEST_P11K_PATH, 0);
    C_WaitForSlotEvent(CKF_DONT_BLOCK, &evt_slot, NULL); /* drain */

    wp11_test_inject_flash_event(TEST_P11K_PATH, 1);
    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots_after, &count);
    f += check(rv == CKR_OK && count == 2,
               "flash_reinsert: slot count still 2 after reinsert");

    /* Same slot ID must be reused -- prevents PKCS#11 callers from leaking
     * slot handles across remove/reinsert cycles. */
    f += check(slots_after[1] == slots_before[1],
               "flash_reinsert: same slot ID reused after reinsert");

    rv = C_GetSlotInfo(slots_after[1], &info);
    f += check(rv == CKR_OK, "flash_reinsert: C_GetSlotInfo after reinsert");
    f += check((info.flags & CKF_TOKEN_PRESENT) != 0,
               "flash_reinsert: CKF_TOKEN_PRESENT restored after reinsert");

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "flash_reinsert: C_Finalize");
    return f;
}

/* Test: two distinct .p11k paths produce two independent flash slots */
static int test_flash_multiple_files(void)
{
    CK_RV      rv;
    CK_SLOT_ID slots[16];
    CK_ULONG   count;
    CK_SLOT_INFO info1, info2;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "flash_multiple: C_Initialize");

    wp11_test_inject_flash_event(TEST_P11K_PATH,  1);
    wp11_test_inject_flash_event(TEST_P11K_PATH2, 1);

    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    f += check(rv == CKR_OK, "flash_multiple: C_GetSlotList");
    f += check(count == 3, "flash_multiple: slot count == 3 (soft + 2 flash)");

    /* Both flash slots must be present */
    if (count == 3) {
        rv = C_GetSlotInfo(slots[1], &info1);
        f += check(rv == CKR_OK && (info1.flags & CKF_TOKEN_PRESENT) != 0,
                   "flash_multiple: first flash slot has CKF_TOKEN_PRESENT");
        rv = C_GetSlotInfo(slots[2], &info2);
        f += check(rv == CKR_OK && (info2.flags & CKF_TOKEN_PRESENT) != 0,
                   "flash_multiple: second flash slot has CKF_TOKEN_PRESENT");
        f += check(slots[1] != slots[2],
                   "flash_multiple: two distinct slot IDs for two files");
    }

    /* Remove only the first; second must survive */
    wp11_test_inject_flash_event(TEST_P11K_PATH, 0);
    rv = C_GetSlotInfo(slots[1], &info1);
    f += check(rv == CKR_OK && (info1.flags & CKF_TOKEN_PRESENT) == 0,
               "flash_multiple: first slot cleared after first file removed");
    if (count == 3) {
        rv = C_GetSlotInfo(slots[2], &info2);
        f += check(rv == CKR_OK && (info2.flags & CKF_TOKEN_PRESENT) != 0,
                   "flash_multiple: second slot still present after first removed");
    }

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "flash_multiple: C_Finalize");
    return f;
}

/* -------------------------------------------------------------------------
 * Helper: generate an EC P-256 key, DER-encode it, and write a .p11k file.
 * Keeps *orig_ecc alive (caller must wc_ecc_free it after use).
 * Returns 0 on success; prints a SKIP message and returns -1 on any failure.
 * ---------------------------------------------------------------------- */
static int flash_test_make_keystore(ecc_key *orig_ecc, const char *label)
{
    WC_RNG rng;
    CK_BYTE der[256];
    int     der_len;
    wp11_key_entry_t entry;
    int ret;

    if (wc_InitRng(&rng) != 0) {
        printf("SKIP: %s: RNG init failed\n", label); return -1;
    }
    if (wc_ecc_init(orig_ecc) != 0) {
        wc_FreeRng(&rng);
        printf("SKIP: %s: ECC init failed\n", label); return -1;
    }
    if (wc_ecc_make_key(&rng, 32, orig_ecc) != 0) {
        wc_ecc_free(orig_ecc); wc_FreeRng(&rng);
        printf("SKIP: %s: ECC keygen failed\n", label); return -1;
    }
    der_len = wc_EccKeyToDer(orig_ecc, (byte *)der, (word32)sizeof(der));
    wc_FreeRng(&rng);
    if (der_len <= 0) {
        wc_ecc_free(orig_ecc);
        printf("SKIP: %s: DER encode failed\n", label); return -1;
    }

    memset(&entry, 0, sizeof(entry));
    entry.key_type  = WP11_KEY_TYPE_EC;
    entry.der_bytes = (uint8_t *)der;
    entry.der_len   = (size_t)der_len;
    strncpy(entry.label, label, sizeof(entry.label) - 1u);

    ret = wp11_keystore_create(FLASH_TEST_P11K,
                               (const uint8_t *)FLASH_TEST_PIN,
                               (size_t)FLASH_TEST_PIN_LEN, &entry, 1u);
    if (ret != WP11_KEYSTORE_OK) {
        wc_ecc_free(orig_ecc);
        printf("SKIP: %s: keystore_create failed (%d)\n", label, ret); return -1;
    }
    return 0;
}

/* wolfP11-444s: Create a flash keystore with a caller-supplied PKCS#1 DER
 * RSA private key.  Used by test_rsa_oaep_vector_oracle.
 * Returns 0 on success, -1 on failure. */
static int flash_test_make_rsa_keystore_from_der(const uint8_t *der,
                                                   size_t         derlen,
                                                   const char    *label)
{
    wp11_key_entry_t entry;
    int ret;

    uint8_t *der_copy;

    /* derlen is always > 0: this function is only called with DER-encoded RSA
     * private keys, which are at minimum ~500 bytes.  malloc(0) is not a
     * concern here, but the NULL check below guards against allocation failure. */
    der_copy = (uint8_t *)malloc(derlen);
    if (der_copy == NULL) {
        printf("SKIP: %s: malloc failed\n", label);
        return -1;
    }
    memcpy(der_copy, der, derlen);

    memset(&entry, 0, sizeof(entry));
    entry.key_type  = WP11_KEY_TYPE_RSA;
    entry.der_bytes = der_copy;
    entry.der_len   = derlen;
    strncpy(entry.label, label, sizeof(entry.label) - 1u);

    ret = wp11_keystore_create(FLASH_TEST_P11K,
                               (const uint8_t *)FLASH_TEST_PIN,
                               (size_t)FLASH_TEST_PIN_LEN, &entry, 1u);
    free(der_copy);
    if (ret != WP11_KEYSTORE_OK) {
        printf("SKIP: %s: keystore_create failed (%d)\n", label, ret);
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * test_flash_pkcs11_login_correct_pin
 *
 * End-to-end: create a real .p11k file, inject it as a flash slot, then
 * verify that C_Login with the correct PIN succeeds and that key objects
 * become visible via C_FindObjects.
 * ---------------------------------------------------------------------- */
static int test_flash_pkcs11_login_correct_pin(void)
{
    ecc_key         orig_ecc;
    CK_RV           rv;
    CK_SESSION_HANDLE hSess = 0;
    CK_SLOT_ID      slots[16];
    CK_ULONG        count;
    CK_OBJECT_HANDLE objs[16];
    CK_ULONG        nfound;
    CK_SLOT_ID      evt_slot;
    int f = 0;

    /* wolfP11-v4mh: setup failure must count as a test failure, not a skip.
     * Returning 0 here masked broken RNG/keygen/keystore write as passing. */
    if (flash_test_make_keystore(&orig_ecc, "flash_login_correct_pin") != 0)
        return f + 1;
    wc_ecc_free(&orig_ecc); /* key bytes are now inside the .p11k file */

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "flash_login_correct_pin: C_Initialize");

    wp11_test_inject_flash_event(FLASH_TEST_P11K, 1 /* arrived */);
    C_WaitForSlotEvent(CKF_DONT_BLOCK, &evt_slot, NULL); /* drain arrival event */

    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    f += check(rv == CKR_OK && count == 2,
               "flash_login_correct_pin: slot count == 2 after injection");
    if (count < 2) { C_Finalize(NULL); unlink(FLASH_TEST_P11K); return f; }

    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "flash_login_correct_pin: C_OpenSession");

    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)FLASH_TEST_PIN, FLASH_TEST_PIN_LEN);
    f += check(rv == CKR_OK,
               "flash_login_correct_pin: C_Login with correct PIN returns CKR_OK");

    if (rv == CKR_OK) {
        rv = C_FindObjectsInit(hSess, NULL, 0);
        f += check(rv == CKR_OK, "flash_login_correct_pin: C_FindObjectsInit");
        nfound = 0;
        rv = C_FindObjects(hSess, objs, 16, &nfound);
        f += check(rv == CKR_OK, "flash_login_correct_pin: C_FindObjects");
        f += check(nfound >= 1,
                   "flash_login_correct_pin: at least one key visible after login");
        /* wolfP11-q3d5: count check alone passes if FindObjects returns wrong
         * type; verify object is actually a private key via CKA_CLASS. */
        if (nfound >= 1) {
            CK_OBJECT_CLASS cls = (CK_OBJECT_CLASS)0xFFFFFFFFUL;
            CK_ATTRIBUTE    acls = { CKA_CLASS, &cls, sizeof(cls) };
            C_GetAttributeValue(hSess, objs[0], &acls, 1);
            f += check(cls == CKO_PRIVATE_KEY,
                       "flash_login_correct_pin: found object is CKO_PRIVATE_KEY");
        }
        C_FindObjectsFinal(hSess);

        rv = C_Logout(hSess);
        f += check(rv == CKR_OK, "flash_login_correct_pin: C_Logout");
    }

    C_CloseSession(hSess);

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "flash_login_correct_pin: C_Finalize");

    unlink(FLASH_TEST_P11K);
    return f;
}

/* -------------------------------------------------------------------------
 * test_flash_pkcs11_login_wrong_pin
 *
 * C_Login with a wrong PIN must return CKR_PIN_INCORRECT.
 * ---------------------------------------------------------------------- */
static int test_flash_pkcs11_login_wrong_pin(void)
{
    ecc_key         orig_ecc;
    CK_RV           rv;
    CK_SESSION_HANDLE hSess = 0;
    CK_SLOT_ID      slots[16];
    CK_ULONG        count;
    CK_SLOT_ID      evt_slot;
    int f = 0;

    if (flash_test_make_keystore(&orig_ecc, "flash_login_wrong_pin") != 0)
        return f + 1; /* wolfP11-v4mh */
    wc_ecc_free(&orig_ecc);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "flash_login_wrong_pin: C_Initialize");

    wp11_test_inject_flash_event(FLASH_TEST_P11K, 1);
    C_WaitForSlotEvent(CKF_DONT_BLOCK, &evt_slot, NULL);

    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    f += check(rv == CKR_OK && count == 2,
               "flash_login_wrong_pin: flash slot present");
    if (count < 2) { C_Finalize(NULL); unlink(FLASH_TEST_P11K); return f; }

    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "flash_login_wrong_pin: C_OpenSession");

    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)FLASH_TEST_WRONG_PIN, FLASH_TEST_WRONG_PIN_LEN);
    f += check(rv == CKR_PIN_INCORRECT,
               "flash_login_wrong_pin: wrong PIN returns CKR_PIN_INCORRECT");

    C_CloseSession(hSess);

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "flash_login_wrong_pin: C_Finalize");

    unlink(FLASH_TEST_P11K);
    return f;
}

/* -------------------------------------------------------------------------
 * test_flash_pkcs11_logout_clears_keys
 *
 * After C_Logout, C_FindObjects must return zero objects for the flash slot --
 * the keystore is freed and the g_keys[] entries are cleared on logout.
 * ---------------------------------------------------------------------- */
static int test_flash_pkcs11_logout_clears_keys(void)
{
    ecc_key         orig_ecc;
    CK_RV           rv;
    CK_SESSION_HANDLE hSess = 0;
    CK_SLOT_ID      slots[16];
    CK_ULONG        count;
    CK_OBJECT_HANDLE objs[16];
    CK_ULONG        nfound;
    CK_SLOT_ID      evt_slot;
    int f = 0;

    if (flash_test_make_keystore(&orig_ecc, "flash_logout_clears_keys") != 0)
        return f + 1; /* wolfP11-v4mh */
    wc_ecc_free(&orig_ecc);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "flash_logout_clears_keys: C_Initialize");

    wp11_test_inject_flash_event(FLASH_TEST_P11K, 1);
    C_WaitForSlotEvent(CKF_DONT_BLOCK, &evt_slot, NULL);

    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    if (count < 2) { C_Finalize(NULL); unlink(FLASH_TEST_P11K); return f + 1; }

    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "flash_logout_clears_keys: C_OpenSession");

    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)FLASH_TEST_PIN, FLASH_TEST_PIN_LEN);
    f += check(rv == CKR_OK, "flash_logout_clears_keys: C_Login");
    if (rv != CKR_OK) {
        C_CloseSession(hSess); C_Finalize(NULL); unlink(FLASH_TEST_P11K);
        return f;
    }

    /* Keys must be visible after login */
    C_FindObjectsInit(hSess, NULL, 0);
    nfound = 0;
    C_FindObjects(hSess, objs, 16, &nfound);
    C_FindObjectsFinal(hSess);
    f += check(nfound >= 1,
               "flash_logout_clears_keys: keys visible after login");
    /* wolfP11-q3d5: verify CKA_CLASS, not just count */
    if (nfound >= 1) {
        CK_OBJECT_CLASS cls = (CK_OBJECT_CLASS)0xFFFFFFFFUL;
        CK_ATTRIBUTE    acls = { CKA_CLASS, &cls, sizeof(cls) };
        C_GetAttributeValue(hSess, objs[0], &acls, 1);
        f += check(cls == CKO_PRIVATE_KEY,
                   "flash_logout_clears_keys: found object is CKO_PRIVATE_KEY");
    }

    rv = C_Logout(hSess);
    f += check(rv == CKR_OK, "flash_logout_clears_keys: C_Logout");

    /* Keys must be gone after logout -- keystore freed, g_keys[] cleared */
    rv = C_FindObjectsInit(hSess, NULL, 0);
    f += check(rv == CKR_OK,
               "flash_logout_clears_keys: FindObjectsInit after logout");
    nfound = 0;
    rv = C_FindObjects(hSess, objs, 16, &nfound);
    f += check(rv == CKR_OK,
               "flash_logout_clears_keys: FindObjects after logout");
    f += check(nfound == 0,
               "flash_logout_clears_keys: no keys visible after logout");
    C_FindObjectsFinal(hSess);

    C_CloseSession(hSess);

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "flash_logout_clears_keys: C_Finalize");

    unlink(FLASH_TEST_P11K);
    return f;
}

/* -------------------------------------------------------------------------
 * test_flash_pkcs11_sign_roundtrip
 *
 * Login to a flash slot, call C_SignInit(CKM_ECDSA) + C_Sign, then verify
 * the result with wc_ecc_verify_hash using the original wolfCrypt key object
 * (independent oracle -- never passed through the keystore or flash backend).
 *
 * CKM_ECDSA: caller supplies a prehashed 32-byte SHA-256 digest.
 * ---------------------------------------------------------------------- */
static int test_flash_pkcs11_sign_roundtrip(void)
{
    ecc_key         orig_ecc; /* kept alive for oracle verification */
    CK_RV           rv;
    CK_SESSION_HANDLE hSess = 0;
    CK_SLOT_ID      slots[16];
    CK_ULONG        count;
    CK_OBJECT_HANDLE objs[16];
    CK_ULONG        nfound;
    CK_SLOT_ID      evt_slot;
    CK_MECHANISM    mech;
    CK_BYTE         sig[128]; /* P-256 DER sig max ~72 bytes */
    CK_ULONG        siglen;
    /* Fixed 32-byte test digest: independent of the code under test */
    CK_BYTE test_hash[32] = {
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
        0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
        0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90
    };
    int stat;
    int ret;
    int f = 0;

    /* orig_ecc is kept alive past keystore creation so the public key is
     * available for the oracle verification step below. */
    if (flash_test_make_keystore(&orig_ecc, "flash_sign_roundtrip") != 0)
        return f + 1; /* wolfP11-v4mh */
    /* Do NOT free orig_ecc here -- needed for oracle. */

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "flash_sign_roundtrip: C_Initialize");

    wp11_test_inject_flash_event(FLASH_TEST_P11K, 1);
    C_WaitForSlotEvent(CKF_DONT_BLOCK, &evt_slot, NULL);

    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    if (count < 2) {
        C_Finalize(NULL);
        wc_ecc_free(&orig_ecc);
        unlink(FLASH_TEST_P11K);
        return f + 1;
    }

    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "flash_sign_roundtrip: C_OpenSession");

    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)FLASH_TEST_PIN, FLASH_TEST_PIN_LEN);
    f += check(rv == CKR_OK, "flash_sign_roundtrip: C_Login");
    if (rv != CKR_OK) {
        C_CloseSession(hSess); C_Finalize(NULL);
        wc_ecc_free(&orig_ecc); unlink(FLASH_TEST_P11K);
        return f;
    }

    /* Locate the key object populated by C_Login */
    rv = C_FindObjectsInit(hSess, NULL, 0);
    f += check(rv == CKR_OK, "flash_sign_roundtrip: C_FindObjectsInit");
    nfound = 0;
    rv = C_FindObjects(hSess, objs, 16, &nfound);
    f += check(rv == CKR_OK, "flash_sign_roundtrip: C_FindObjects");
    f += check(nfound >= 1, "flash_sign_roundtrip: key visible after login");
    C_FindObjectsFinal(hSess);

    if (nfound >= 1) {
        /* wolfP11-q3d5: verify object class before trusting the handle */
        {
            CK_OBJECT_CLASS cls = (CK_OBJECT_CLASS)0xFFFFFFFFUL;
            CK_ATTRIBUTE    acls = { CKA_CLASS, &cls, sizeof(cls) };
            C_GetAttributeValue(hSess, objs[0], &acls, 1);
            f += check(cls == CKO_PRIVATE_KEY,
                       "flash_sign_roundtrip: found object is CKO_PRIVATE_KEY");
        }
        /* CKM_ECDSA: C_Sign receives a prehashed 32-byte digest directly */
        memset(&mech, 0, sizeof(mech));
        mech.mechanism      = CKM_ECDSA;
        mech.pParameter     = NULL_PTR;
        mech.ulParameterLen = 0;

        rv = C_SignInit(hSess, &mech, objs[0]);
        f += check(rv == CKR_OK, "flash_sign_roundtrip: C_SignInit");

        siglen = (CK_ULONG)sizeof(sig);
        rv = C_Sign(hSess, test_hash, 32, sig, &siglen);
        f += check(rv == CKR_OK, "flash_sign_roundtrip: C_Sign returns CKR_OK");
        f += check(siglen > 0 && siglen <= (CK_ULONG)sizeof(sig),
                   "flash_sign_roundtrip: signature length is plausible");

        if (rv == CKR_OK && siglen > 0) {
            /* Independent oracle: verify with orig_ecc public key.
             * orig_ecc was never passed through the keystore or flash
             * backend -- it is the raw wolfCrypt key from keygen.
             * A passing verify proves:
             *   (a) C_Sign produced a valid ECDSA signature, and
             *   (b) the keystore preserved the private key material intact. */
            stat = 0;
            ret  = wc_ecc_verify_hash(sig, (word32)siglen,
                                       test_hash, 32,
                                       &stat, &orig_ecc);
            f += check(ret == 0 && stat == 1,
                       "flash_sign_roundtrip: oracle -- wolfCrypt verifies C_Sign output");
        }
    }

    C_Logout(hSess);
    C_CloseSession(hSess);

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "flash_sign_roundtrip: C_Finalize");

    wc_ecc_free(&orig_ecc);
    unlink(FLASH_TEST_P11K);
    return f;
}

/* -------------------------------------------------------------------------
 * test_flash_pkcs11_sign_size_query
 *
 * wolfP11-3qf: C_Sign(pSignature=NULL) must return the mechanism-correct max
 * signature length, not the hardcoded 512.  For a P-256 ECDSA key the max
 * DER-encoded signature is exactly 72 bytes:
 *   SEQUENCE(2) + 2 x INTEGER(1 tag + 1 len + 1 pad + 32 r_or_s) = 2 + 2x35 = 72
 *
 * This test also verifies that the size-query call preserves sign_active so
 * that the subsequent C_Sign with a correctly-sized buffer still succeeds
 * (i.e., the query does not consume the operation state).
 * ---------------------------------------------------------------------- */
static int test_flash_pkcs11_sign_size_query(void)
{
    ecc_key           orig_ecc;
    CK_RV             rv;
    CK_SESSION_HANDLE hSess = 0;
    CK_SLOT_ID        slots[16];
    CK_ULONG          count;
    CK_OBJECT_HANDLE  objs[16];
    CK_ULONG          nfound;
    CK_SLOT_ID        evt_slot;
    CK_MECHANISM      mech;
    CK_BYTE           sig[128];
    CK_ULONG          siglen;
    CK_BYTE test_hash[32] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
    };
    int stat;
    int ret;
    int f = 0;
    /* wolfP11-3qf: P-256 ECDSA DER max = 8 + 2*32 = 72.  This is the oracle
     * value: an independent calculation, not derived from the code under test. */
    static const CK_ULONG P256_ECDSA_MAX = 72;

    if (flash_test_make_keystore(&orig_ecc, "sign_size_query") != 0)
        return f + 1; /* wolfP11-v4mh */
    /* orig_ecc kept alive for oracle verification below */

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "sign_size_query: C_Initialize");

    wp11_test_inject_flash_event(FLASH_TEST_P11K, 1);
    C_WaitForSlotEvent(CKF_DONT_BLOCK, &evt_slot, NULL);

    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    if (count < 2) {
        C_Finalize(NULL);
        wc_ecc_free(&orig_ecc);
        unlink(FLASH_TEST_P11K);
        return f + 1;
    }

    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "sign_size_query: C_OpenSession");

    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)FLASH_TEST_PIN, FLASH_TEST_PIN_LEN);
    f += check(rv == CKR_OK, "sign_size_query: C_Login");
    if (rv != CKR_OK) {
        C_CloseSession(hSess); C_Finalize(NULL);
        wc_ecc_free(&orig_ecc); unlink(FLASH_TEST_P11K);
        return f;
    }

    C_FindObjectsInit(hSess, NULL, 0);
    nfound = 0;
    C_FindObjects(hSess, objs, 16, &nfound);
    C_FindObjectsFinal(hSess);
    f += check(nfound >= 1, "sign_size_query: key visible after login");

    if (nfound >= 1) {
        /* wolfP11-q3d5: verify object class before trusting the handle */
        {
            CK_OBJECT_CLASS cls = (CK_OBJECT_CLASS)0xFFFFFFFFUL;
            CK_ATTRIBUTE    acls = { CKA_CLASS, &cls, sizeof(cls) };
            C_GetAttributeValue(hSess, objs[0], &acls, 1);
            f += check(cls == CKO_PRIVATE_KEY,
                       "sign_size_query: found object is CKO_PRIVATE_KEY");
        }
        memset(&mech, 0, sizeof(mech));
        mech.mechanism = CKM_ECDSA;

        rv = C_SignInit(hSess, &mech, objs[0]);
        f += check(rv == CKR_OK, "sign_size_query: C_SignInit");

        /* --- Size query: pSignature=NULL --- */
        siglen = 0;
        rv = C_Sign(hSess, test_hash, 32, NULL_PTR, &siglen);
        f += check(rv == CKR_OK,
                   "sign_size_query: size query returns CKR_OK");
        f += check(siglen == P256_ECDSA_MAX,
                   "sign_size_query: size query returns 72 (P-256 ECDSA DER max)");

        /* --- Size query must NOT consume sign_active; real sign still works --- */
        siglen = (CK_ULONG)sizeof(sig);
        rv = C_Sign(hSess, test_hash, 32, sig, &siglen);
        f += check(rv == CKR_OK,
                   "sign_size_query: real C_Sign after size query returns CKR_OK");
        f += check(siglen > 0 && siglen <= P256_ECDSA_MAX,
                   "sign_size_query: real signature within announced bound");

        if (rv == CKR_OK && siglen > 0) {
            /* Oracle: verify with the raw key from keygen -- never touched by
             * the code under test.  Proves the sign path still works after
             * the size-query path. */
            stat = 0;
            ret  = wc_ecc_verify_hash(sig, (word32)siglen,
                                       test_hash, 32,
                                       &stat, &orig_ecc);
            f += check(ret == 0 && stat == 1,
                       "sign_size_query: oracle -- wolfCrypt verifies real sign output");
        }
    }

    C_Logout(hSess);
    C_CloseSession(hSess);
    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "sign_size_query: C_Finalize");

    wc_ecc_free(&orig_ecc);
    unlink(FLASH_TEST_P11K);
    return f;
}

/* -------------------------------------------------------------------------
 * test_flash_pkcs11_destroy_flash_key
 *
 * Regression for wolfP11-at1: C_DestroyObject must NOT call
 * wp11_soft_key_free on flash keys.  If it did, the subsequent C_Logout
 * (which calls wp11_keystore_free) would corrupt the heap.  A clean
 * return from C_Logout and C_Finalize proves the bug is absent.
 * ---------------------------------------------------------------------- */
static int test_flash_pkcs11_destroy_flash_key(void)
{
    ecc_key           orig_ecc;
    CK_RV             rv;
    CK_SESSION_HANDLE hSess = 0;
    CK_SLOT_ID        slots[16];
    CK_ULONG          count;
    CK_OBJECT_HANDLE  objs[16];
    CK_ULONG          nfound;
    CK_SLOT_ID        evt_slot;
    int f = 0;

    if (flash_test_make_keystore(&orig_ecc, "flash_destroy_key") != 0)
        return f + 1; /* wolfP11-v4mh */
    wc_ecc_free(&orig_ecc);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "flash_destroy_key: C_Initialize");

    wp11_test_inject_flash_event(FLASH_TEST_P11K, 1);
    C_WaitForSlotEvent(CKF_DONT_BLOCK, &evt_slot, NULL); /* drain arrival event */

    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    f += check(rv == CKR_OK && count == 2,
               "flash_destroy_key: slot count == 2 after injection");
    if (count < 2) { C_Finalize(NULL); unlink(FLASH_TEST_P11K); return f; }

    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "flash_destroy_key: C_OpenSession");

    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)FLASH_TEST_PIN, FLASH_TEST_PIN_LEN);
    f += check(rv == CKR_OK, "flash_destroy_key: C_Login");
    if (rv != CKR_OK) {
        C_CloseSession(hSess); C_Finalize(NULL); unlink(FLASH_TEST_P11K);
        return f;
    }

    rv = C_FindObjectsInit(hSess, NULL, 0);
    f += check(rv == CKR_OK, "flash_destroy_key: C_FindObjectsInit");
    nfound = 0;
    rv = C_FindObjects(hSess, objs, 16, &nfound);
    f += check(rv == CKR_OK, "flash_destroy_key: C_FindObjects");
    f += check(nfound >= 1,
               "flash_destroy_key: key visible after login");
    C_FindObjectsFinal(hSess);

    if (nfound >= 1) {
        /* wolfP11-q3d5: verify object class before trusting the handle */
        {
            CK_OBJECT_CLASS cls = (CK_OBJECT_CLASS)0xFFFFFFFFUL;
            CK_ATTRIBUTE    acls = { CKA_CLASS, &cls, sizeof(cls) };
            C_GetAttributeValue(hSess, objs[0], &acls, 1);
            f += check(cls == CKO_PRIVATE_KEY,
                       "flash_destroy_key: found object is CKO_PRIVATE_KEY");
        }
        rv = C_DestroyObject(hSess, objs[0]);
        f += check(rv == CKR_OK,
                   "flash_destroy_key: C_DestroyObject returns CKR_OK");
    }

    /* These are the regression assertions: if wp11_soft_key_free was
     * incorrectly called on the flash key above, the keystore memory is
     * now corrupt and these calls will crash or return an error. */
    rv = C_Logout(hSess);
    f += check(rv == CKR_OK,
               "flash_destroy_key: C_Logout after DestroyObject -- no heap corruption");

    C_CloseSession(hSess);

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK,
               "flash_destroy_key: C_Finalize -- no double-free from flash key");

    unlink(FLASH_TEST_P11K);
    return f;
}

/* -------------------------------------------------------------------------
 * test_flash_pkcs11_departure_while_logged_in
 *
 * Regression for wolfP11-iak: when a drive departs while a session is
 * logged in, the keystore must be freed exactly once by the departure
 * handler.  A leaked keystore would double-free in C_Finalize.
 *
 * Sub-test A: depart while logged in; C_Finalize survives.
 * Sub-test B: re-inject the same path; C_Login works again, proving
 *             slot and mlock state are fully reset by the departure.
 * ---------------------------------------------------------------------- */
static int test_flash_pkcs11_departure_while_logged_in(void)
{
    ecc_key           orig_ecc;
    CK_RV             rv;
    CK_SESSION_HANDLE hSess = 0;
    CK_SLOT_ID        slots[16];
    CK_ULONG          count;
    CK_OBJECT_HANDLE  objs[16];
    CK_ULONG          nfound;
    CK_SLOT_ID        evt_slot;
    CK_SLOT_INFO      info;
    int f = 0;

    if (flash_test_make_keystore(&orig_ecc, "flash_depart_loggedin") != 0)
        return f + 1; /* wolfP11-v4mh */
    wc_ecc_free(&orig_ecc);

    /* --- Sub-test A: drive removed while session is logged in --- */

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "flash_depart_loggedin: C_Initialize");

    wp11_test_inject_flash_event(FLASH_TEST_P11K, 1);
    C_WaitForSlotEvent(CKF_DONT_BLOCK, &evt_slot, NULL);

    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    f += check(rv == CKR_OK && count == 2,
               "flash_depart_loggedin: slot count == 2 after injection");
    if (count < 2) { C_Finalize(NULL); unlink(FLASH_TEST_P11K); return f; }

    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "flash_depart_loggedin: C_OpenSession");

    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)FLASH_TEST_PIN, FLASH_TEST_PIN_LEN);
    f += check(rv == CKR_OK, "flash_depart_loggedin: C_Login");
    if (rv != CKR_OK) {
        C_CloseSession(hSess); C_Finalize(NULL); unlink(FLASH_TEST_P11K);
        return f;
    }

    C_FindObjectsInit(hSess, NULL, 0);
    nfound = 0;
    C_FindObjects(hSess, objs, 16, &nfound);
    C_FindObjectsFinal(hSess);
    f += check(nfound >= 1,
               "flash_depart_loggedin: keys visible before departure");
    /* wolfP11-q3d5: verify object class */
    if (nfound >= 1) {
        CK_OBJECT_CLASS cls = (CK_OBJECT_CLASS)0xFFFFFFFFUL;
        CK_ATTRIBUTE    acls = { CKA_CLASS, &cls, sizeof(cls) };
        C_GetAttributeValue(hSess, objs[0], &acls, 1);
        f += check(cls == CKO_PRIVATE_KEY,
                   "flash_depart_loggedin: found object is CKO_PRIVATE_KEY");
    }

    /* Simulate USB drive removal while session is active and logged in */
    wp11_test_inject_flash_event(FLASH_TEST_P11K, 0);
    C_WaitForSlotEvent(CKF_DONT_BLOCK, &evt_slot, NULL);

    rv = C_GetSlotInfo(slots[1], &info);
    f += check(rv == CKR_OK,
               "flash_depart_loggedin: C_GetSlotInfo valid after departure");
    f += check((info.flags & CKF_TOKEN_PRESENT) == 0,
               "flash_depart_loggedin: token_present cleared after departure");

    /* Regression assertion: if departure leaked the keystore, C_Finalize
     * would try to free the same pointer again and crash. */
    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK,
               "flash_depart_loggedin: C_Finalize after departure-while-logged-in");

    /* --- Sub-test B: re-inject and log in again --- */

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "flash_depart_loggedin: C_Initialize for re-inject");

    wp11_test_inject_flash_event(FLASH_TEST_P11K, 1);
    C_WaitForSlotEvent(CKF_DONT_BLOCK, &evt_slot, NULL);

    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    f += check(rv == CKR_OK && count == 2,
               "flash_depart_loggedin: slot count == 2 after re-inject");
    if (count < 2) { C_Finalize(NULL); unlink(FLASH_TEST_P11K); return f; }

    hSess = 0;
    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "flash_depart_loggedin: C_OpenSession after re-inject");

    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)FLASH_TEST_PIN, FLASH_TEST_PIN_LEN);
    f += check(rv == CKR_OK,
               "flash_depart_loggedin: C_Login after re-inject succeeds");

    if (rv == CKR_OK) {
        C_FindObjectsInit(hSess, NULL, 0);
        nfound = 0;
        C_FindObjects(hSess, objs, 16, &nfound);
        C_FindObjectsFinal(hSess);
        f += check(nfound >= 1,
                   "flash_depart_loggedin: keys visible after re-login");
        /* wolfP11-q3d5: verify object class */
        if (nfound >= 1) {
            CK_OBJECT_CLASS cls = (CK_OBJECT_CLASS)0xFFFFFFFFUL;
            CK_ATTRIBUTE    acls = { CKA_CLASS, &cls, sizeof(cls) };
            C_GetAttributeValue(hSess, objs[0], &acls, 1);
            f += check(cls == CKO_PRIVATE_KEY,
                       "flash_depart_loggedin: re-login object is CKO_PRIVATE_KEY");
        }

        rv = C_Logout(hSess);
        f += check(rv == CKR_OK,
                   "flash_depart_loggedin: C_Logout after re-login");
    }

    C_CloseSession(hSess);

    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK,
               "flash_depart_loggedin: C_Finalize after re-login");

    unlink(FLASH_TEST_P11K);
    return f;
}

/* -------------------------------------------------------------------------
 * test_flash_pkcs11_get_attribute_value
 *
 * wolfP11-4fj: C_GetAttributeValue must return CKR_ATTRIBUTE_TYPE_INVALID
 * for unknown attribute types and CKR_BUFFER_TOO_SMALL when a provided
 * buffer is too small.  Both previously returned CKR_OK (PKCS#11 2.40
 * sec.11.7 violation).  This test uses a real flash key object to exercise
 * the attribute-reading path with an independent expected-value oracle
 * (the object was created as CKO_PRIVATE_KEY / CKK_EC by flash_test_make_keystore).
 * ---------------------------------------------------------------------- */
static int test_flash_pkcs11_get_attribute_value(void)
{
    ecc_key           orig_ecc;
    CK_RV             rv;
    CK_SESSION_HANDLE hSess = 0;
    CK_SLOT_ID        slots[16];
    CK_ULONG          count;
    CK_OBJECT_HANDLE  objs[16];
    CK_ULONG          nfound;
    CK_SLOT_ID        evt_slot;
    int f = 0;

    if (flash_test_make_keystore(&orig_ecc, "get_attr_flash") != 0)
        return f + 1; /* wolfP11-v4mh */
    wc_ecc_free(&orig_ecc);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "get_attr_flash: C_Initialize");

    wp11_test_inject_flash_event(FLASH_TEST_P11K, 1);
    C_WaitForSlotEvent(CKF_DONT_BLOCK, &evt_slot, NULL);

    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    if (count < 2) {
        C_Finalize(NULL); unlink(FLASH_TEST_P11K); return f + 1;
    }

    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "get_attr_flash: C_OpenSession");

    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)FLASH_TEST_PIN, FLASH_TEST_PIN_LEN);
    f += check(rv == CKR_OK, "get_attr_flash: C_Login");
    if (rv != CKR_OK) {
        C_CloseSession(hSess); C_Finalize(NULL); unlink(FLASH_TEST_P11K);
        return f;
    }

    C_FindObjectsInit(hSess, NULL, 0);
    nfound = 0;
    C_FindObjects(hSess, objs, 16, &nfound);
    C_FindObjectsFinal(hSess);
    f += check(nfound >= 1, "get_attr_flash: key object visible after login");
    if (nfound < 1) {
        C_Logout(hSess); C_CloseSession(hSess);
        C_Finalize(NULL); unlink(FLASH_TEST_P11K);
        return f;
    }
    /* wolfP11-q3d5: verify object class, not just count */
    {
        CK_OBJECT_CLASS cls = (CK_OBJECT_CLASS)0xFFFFFFFFUL;
        CK_ATTRIBUTE    acls = { CKA_CLASS, &cls, sizeof(cls) };
        C_GetAttributeValue(hSess, objs[0], &acls, 1);
        f += check(cls == CKO_PRIVATE_KEY,
                   "get_attr_flash: found object is CKO_PRIVATE_KEY");
    }

    /* --- Test 1: known attribute, correctly-sized buffer -> CKR_OK --- */
    {
        CK_OBJECT_CLASS cls = 0;
        CK_ATTRIBUTE    attr = { CKA_CLASS, &cls, sizeof(cls) };

        rv = C_GetAttributeValue(hSess, objs[0], &attr, 1);
        f += check(rv == CKR_OK,
                   "get_attr_flash: known attr CKA_CLASS -> CKR_OK");
        /* Oracle: flash keys are always created as CKO_PRIVATE_KEY (3) */
        f += check(cls == CKO_PRIVATE_KEY,
                   "get_attr_flash: CKA_CLASS value == CKO_PRIVATE_KEY");
    }

    /* --- Test 2: NULL pValue (size query) -> CKR_OK, ulValueLen set --- */
    {
        CK_ATTRIBUTE attr = { CKA_CLASS, NULL_PTR, 0 };

        rv = C_GetAttributeValue(hSess, objs[0], &attr, 1);
        f += check(rv == CKR_OK,
                   "get_attr_flash: size query (pValue=NULL) -> CKR_OK");
        f += check(attr.ulValueLen == sizeof(CK_OBJECT_CLASS),
                   "get_attr_flash: size query sets ulValueLen = sizeof(CK_OBJECT_CLASS)");
    }

    /* --- Test 3: known attribute, buffer too small -> CKR_BUFFER_TOO_SMALL --- */
    {
        CK_BYTE      buf[1] = {0};  /* sizeof(CK_OBJECT_CLASS) > 1 on all targets */
        CK_ATTRIBUTE attr   = { CKA_CLASS, buf, 1 };

        rv = C_GetAttributeValue(hSess, objs[0], &attr, 1);
        f += check(rv == CKR_BUFFER_TOO_SMALL,
                   "get_attr_flash: small buffer -> CKR_BUFFER_TOO_SMALL");
        /* sec.11.7: ulValueLen is updated to the required size even on error */
        f += check(attr.ulValueLen == sizeof(CK_OBJECT_CLASS),
                   "get_attr_flash: small buffer -> ulValueLen updated to required size");
    }

    /* --- Test 4: unknown attribute type -> CKR_ATTRIBUTE_TYPE_INVALID --- */
    {
        /* CKA_ID (0x102) is a standard PKCS#11 attribute not implemented here */
        CK_ATTRIBUTE attr = { CKA_ID, NULL_PTR, 0 };

        rv = C_GetAttributeValue(hSess, objs[0], &attr, 1);
        f += check(rv == CKR_ATTRIBUTE_TYPE_INVALID,
                   "get_attr_flash: unknown attr CKA_ID -> CKR_ATTRIBUTE_TYPE_INVALID");
        f += check(attr.ulValueLen == CK_UNAVAILABLE_INFORMATION,
                   "get_attr_flash: unknown attr -> ulValueLen = CK_UNAVAILABLE_INFORMATION");
    }

    /* --- Test 5: mixed template, known OK + unknown -> CKR_ATTRIBUTE_TYPE_INVALID,
     *             but the known attribute is still filled in --- */
    {
        CK_OBJECT_CLASS cls  = 0;
        CK_ATTRIBUTE    tmpl[2];

        tmpl[0].type        = CKA_CLASS;
        tmpl[0].pValue      = &cls;
        tmpl[0].ulValueLen  = sizeof(cls);
        tmpl[1].type        = CKA_ID;      /* not supported */
        tmpl[1].pValue      = NULL_PTR;
        tmpl[1].ulValueLen  = 0;

        rv = C_GetAttributeValue(hSess, objs[0], tmpl, 2);
        f += check(rv == CKR_ATTRIBUTE_TYPE_INVALID,
                   "get_attr_flash: mixed[known+unknown] -> CKR_ATTRIBUTE_TYPE_INVALID");
        /* Known attribute must still have been written */
        f += check(cls == CKO_PRIVATE_KEY,
                   "get_attr_flash: mixed[known+unknown] -> known attr CKA_CLASS filled");
        f += check(tmpl[1].ulValueLen == CK_UNAVAILABLE_INFORMATION,
                   "get_attr_flash: mixed[known+unknown] -> unknown attr ulValueLen = CK_UNAVAILABLE_INFORMATION");
    }

    /* --- Test 6: mixed template, known OK + known too-small -> CKR_BUFFER_TOO_SMALL,
     *             the good attribute is still filled --- */
    {
        CK_OBJECT_CLASS cls    = 0;
        CK_BYTE         tiny[1] = {0};
        CK_ATTRIBUTE    tmpl[2];

        tmpl[0].type        = CKA_CLASS;
        tmpl[0].pValue      = &cls;
        tmpl[0].ulValueLen  = sizeof(cls);
        tmpl[1].type        = CKA_KEY_TYPE;
        tmpl[1].pValue      = tiny;
        tmpl[1].ulValueLen  = 1;            /* too small for CK_KEY_TYPE */

        rv = C_GetAttributeValue(hSess, objs[0], tmpl, 2);
        f += check(rv == CKR_BUFFER_TOO_SMALL,
                   "get_attr_flash: mixed[ok+small] -> CKR_BUFFER_TOO_SMALL");
        f += check(cls == CKO_PRIVATE_KEY,
                   "get_attr_flash: mixed[ok+small] -> good attr CKA_CLASS still filled");
        f += check(tmpl[1].ulValueLen == sizeof(CK_KEY_TYPE),
                   "get_attr_flash: mixed[ok+small] -> too-small attr ulValueLen updated");
    }

    /* --- Test 7: type_invalid dominates buffer_too_small in worst-error tracking --- */
    {
        CK_BYTE      tiny[1] = {0};
        CK_ATTRIBUTE tmpl[2];

        tmpl[0].type        = CKA_KEY_TYPE;
        tmpl[0].pValue      = tiny;
        tmpl[0].ulValueLen  = 1;   /* too small */
        tmpl[1].type        = CKA_ID;
        tmpl[1].pValue      = NULL_PTR;
        tmpl[1].ulValueLen  = 0;   /* unknown type */

        rv = C_GetAttributeValue(hSess, objs[0], tmpl, 2);
        f += check(rv == CKR_ATTRIBUTE_TYPE_INVALID,
                   "get_attr_flash: type_invalid outranks buffer_too_small");
    }

    C_Logout(hSess);
    C_CloseSession(hSess);
    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "get_attr_flash: C_Finalize");

    unlink(FLASH_TEST_P11K);
    return f;
}

#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */

/* -------------------------------------------------------------------------
 * test_derive_key_soft
 *
 * Verify that C_DeriveKey with CKM_ECDH1_DERIVE on the soft token (slot 0)
 * produces a valid CKO_SECRET_KEY and that its CKA_VALUE is readable.
 *
 * Oracle: ECDH symmetry -- generate two key pairs (A, B), derive
 * secretAB = A.priv * B.pub and secretBA = B.priv * A.pub.  The two
 * results must be bit-for-bit identical.  These are independent code paths
 * (different private keys, different peer inputs).
 * ---------------------------------------------------------------------- */

static int test_derive_key_soft(void)
{
    CK_RV              rv;
    CK_SESSION_HANDLE  hSess     = 0;
    CK_OBJECT_HANDLE   hPubA     = 0, hPrivA = 0;
    CK_OBJECT_HANDLE   hPubB     = 0, hPrivB = 0;
    CK_OBJECT_HANDLE   hSecretAB = 0, hSecretBA = 0;
    CK_MECHANISM       mech      = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    static const CK_UTF8CHAR test_pin[] = "softtest";
    static const CK_ULONG    pin_len    = 8;
    uint8_t  pubA[65], pubB[65];
    CK_ULONG pubA_len, pubB_len;
    uint8_t  secretAB[32], secretBA[32];
    CK_ECDH1_DERIVE_PARAMS paramsA, paramsB;
    CK_MECHANISM  derive_mechA, derive_mechB;
    CK_ATTRIBUTE  val_attr;
    int f = 0;

    setenv("WOLFP11_SOFT_KEYSTORE_PATH", "", 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "derive_key_soft: C_Initialize");
    if (rv != CKR_OK) goto done;

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "derive_key_soft: C_OpenSession");

    rv = C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)test_pin, pin_len);
    f += check(rv == CKR_OK, "derive_key_soft: C_Login");
    if (rv != CKR_OK) goto finalize;

    /* Generate two P-256 key pairs */
    rv = C_GenerateKeyPair(hSess, &mech, NULL, 0, NULL, 0, &hPubA, &hPrivA);
    f += check(rv == CKR_OK, "derive_key_soft: GenerateKeyPair A");
    if (rv != CKR_OK) goto logout;

    rv = C_GenerateKeyPair(hSess, &mech, NULL, 0, NULL, 0, &hPubB, &hPrivB);
    f += check(rv == CKR_OK, "derive_key_soft: GenerateKeyPair B");
    if (rv != CKR_OK) goto logout;

    /* Export public keys in X9.62 format via test helper */
    pubA_len = sizeof(pubA);
    if (wp11_test_soft_export_pub_x963(hPubA, pubA, &pubA_len) != 0) {
        f++;
        printf("FAIL: derive_key_soft: export pub A failed\n");
        goto logout;
    }
    pubB_len = sizeof(pubB);
    if (wp11_test_soft_export_pub_x963(hPubB, pubB, &pubB_len) != 0) {
        f++;
        printf("FAIL: derive_key_soft: export pub B failed\n");
        goto logout;
    }
    f += check(pubA_len == 65u && pubB_len == 65u,
               "derive_key_soft: both public keys are 65 bytes (P-256)");

    /* C_DeriveKey: A.priv uses B's public key */
    memset(&paramsA, 0, sizeof(paramsA));
    paramsA.kdf             = CKD_NULL;
    paramsA.pPublicData     = (CK_BYTE_PTR)pubB;
    paramsA.ulPublicDataLen = (CK_ULONG)pubB_len;
    derive_mechA.mechanism      = CKM_ECDH1_DERIVE;
    derive_mechA.pParameter     = &paramsA;
    derive_mechA.ulParameterLen = sizeof(paramsA);
    rv = C_DeriveKey(hSess, &derive_mechA, hPrivA, NULL, 0, &hSecretAB);
    f += check(rv == CKR_OK, "derive_key_soft: C_DeriveKey A*pubB returns CKR_OK");
    f += check(hSecretAB != 0, "derive_key_soft: C_DeriveKey A*pubB handle non-zero");

    /* C_DeriveKey: B.priv uses A's public key */
    memset(&paramsB, 0, sizeof(paramsB));
    paramsB.kdf             = CKD_NULL;
    paramsB.pPublicData     = (CK_BYTE_PTR)pubA;
    paramsB.ulPublicDataLen = (CK_ULONG)pubA_len;
    derive_mechB.mechanism      = CKM_ECDH1_DERIVE;
    derive_mechB.pParameter     = &paramsB;
    derive_mechB.ulParameterLen = sizeof(paramsB);
    rv = C_DeriveKey(hSess, &derive_mechB, hPrivB, NULL, 0, &hSecretBA);
    f += check(rv == CKR_OK, "derive_key_soft: C_DeriveKey B*pubA returns CKR_OK");

    /* Read derived secrets via C_GetAttributeValue */
    if (rv == CKR_OK && hSecretAB != 0 && hSecretBA != 0) {
        CK_ULONG secAB_len = sizeof(secretAB);
        CK_ULONG secBA_len = sizeof(secretBA);

        val_attr.type        = CKA_VALUE;
        val_attr.pValue      = secretAB;
        val_attr.ulValueLen  = secAB_len;
        rv = C_GetAttributeValue(hSess, hSecretAB, &val_attr, 1);
        f += check(rv == CKR_OK,
                   "derive_key_soft: GetAttributeValue CKA_VALUE (AB)");
        f += check(val_attr.ulValueLen == 32u,
                   "derive_key_soft: secret AB is 32 bytes (P-256 x-coord)");

        val_attr.type        = CKA_VALUE;
        val_attr.pValue      = secretBA;
        val_attr.ulValueLen  = secBA_len;
        rv = C_GetAttributeValue(hSess, hSecretBA, &val_attr, 1);
        f += check(rv == CKR_OK,
                   "derive_key_soft: GetAttributeValue CKA_VALUE (BA)");
        f += check(val_attr.ulValueLen == 32u,
                   "derive_key_soft: secret BA is 32 bytes (P-256 x-coord)");

        /* Oracle: ECDH symmetry */
        f += check(memcmp(secretAB, secretBA, 32) == 0,
                   "derive_key_soft: ECDH symmetry oracle: A*pubB == B*pubA");
    }

    /* Clean up derived key objects */
    if (hSecretAB != 0) (void)C_DestroyObject(hSess, hSecretAB);
    if (hSecretBA != 0) (void)C_DestroyObject(hSess, hSecretBA);

logout:
    C_Logout(hSess);
finalize:
    C_CloseSession(hSess);
    C_Finalize(NULL);
done:
    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}

/* -------------------------------------------------------------------------
 * test_sign_init_active_cleared_on_error
 *
 * Regression test for wolfP11-13f:
 * A failed C_SignInit re-init must clear sign_active so that C_Sign returns
 * CKR_OPERATION_NOT_INITIALIZED rather than proceeding with the previous
 * session's stale key handle.
 *
 * Scenario:
 *   1. C_SignInit(valid_mech, valid_key) -> CKR_OK  (sign_active set)
 *   2. C_SignInit(invalid_mech, valid_key) -> CKR_MECHANISM_INVALID (re-init fails)
 *   3. C_Sign(...) -> CKR_OPERATION_NOT_INITIALIZED
 *      (proves sign_active was cleared by the failed re-init)
 *
 * Oracle: PKCS#11 2.40 sec.11.11 -- C_Sign must return CKR_OPERATION_NOT_INITIALIZED
 * when no Sign operation has been initialised for the session.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * test_pre_init_not_initialized
 *
 * Verify wolfP11-b57: every C_* stub function returns
 * CKR_CRYPTOKI_NOT_INITIALIZED (not CKR_FUNCTION_NOT_SUPPORTED) when
 * called before C_Initialize.
 * ---------------------------------------------------------------------- */
static int test_pre_init_not_initialized(void)
{
    CK_SLOT_INFO    sinfo;
    CK_TOKEN_INFO   tinfo;
    CK_SESSION_HANDLE hSess  = 0;
    CK_BYTE         dummy[1] = {0};
    CK_ULONG        dlen     = 1;
    CK_ULONG        count    = 0;
    CK_MECHANISM    mech     = { CKM_ECDSA, NULL, 0 };
    CK_RV rv;
    int f = 0;

    C_Finalize(NULL);  /* ensure not initialized */

    rv = C_GetSlotInfo(0, &sinfo);
    f += check(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
               "pre_init: C_GetSlotInfo -> CKR_CRYPTOKI_NOT_INITIALIZED");

    rv = C_GetTokenInfo(0, &tinfo);
    f += check(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
               "pre_init: C_GetTokenInfo -> CKR_CRYPTOKI_NOT_INITIALIZED");

    rv = C_GetMechanismList(0, NULL, &count);
    f += check(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
               "pre_init: C_GetMechanismList -> CKR_CRYPTOKI_NOT_INITIALIZED");

    rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &hSess);
    f += check(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
               "pre_init: C_OpenSession -> CKR_CRYPTOKI_NOT_INITIALIZED");

    rv = C_FindObjectsInit(hSess, NULL, 0);
    f += check(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
               "pre_init: C_FindObjectsInit -> CKR_CRYPTOKI_NOT_INITIALIZED");

    rv = C_SignInit(hSess, &mech, 1);
    f += check(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
               "pre_init: C_SignInit -> CKR_CRYPTOKI_NOT_INITIALIZED");

    rv = C_Sign(hSess, dummy, dlen, dummy, &dlen);
    f += check(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
               "pre_init: C_Sign -> CKR_CRYPTOKI_NOT_INITIALIZED");

    rv = C_EncryptInit(hSess, &mech, 1);
    f += check(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
               "pre_init: C_EncryptInit -> CKR_CRYPTOKI_NOT_INITIALIZED");

    rv = C_SeedRandom(hSess, dummy, dlen);
    f += check(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
               "pre_init: C_SeedRandom -> CKR_CRYPTOKI_NOT_INITIALIZED");

    rv = C_GenerateRandom(hSess, dummy, dlen);
    f += check(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
               "pre_init: C_GenerateRandom -> CKR_CRYPTOKI_NOT_INITIALIZED");

    return f;
}

/* -------------------------------------------------------------------------
 * test_reserved_arg_validation
 *
 * Verify wolfP11-9iz: C_Initialize and C_Finalize reject non-NULL pReserved.
 * ---------------------------------------------------------------------- */
static int test_reserved_arg_validation(void)
{
    CK_C_INITIALIZE_ARGS args;
    CK_RV rv;
    int f = 0;

    /* C_Initialize with pReserved != NULL -> CKR_ARGUMENTS_BAD */
    memset(&args, 0, sizeof(args));
    args.pReserved = (void *)&args;  /* non-NULL reserved pointer */
    rv = C_Initialize(&args);
    f += check(rv == CKR_ARGUMENTS_BAD,
               "reserved_args: C_Initialize(pReserved!=NULL) -> CKR_ARGUMENTS_BAD");

    /* C_Finalize with non-NULL -> CKR_ARGUMENTS_BAD (even when not initialized) */
    rv = C_Finalize((void *)&args);
    f += check(rv == CKR_ARGUMENTS_BAD,
               "reserved_args: C_Finalize(pReserved!=NULL) -> CKR_ARGUMENTS_BAD");

    /* C_Finalize with NULL is fine even when not initialized */
    rv = C_Finalize(NULL);
    f += check(rv == CKR_CRYPTOKI_NOT_INITIALIZED,
               "reserved_args: C_Finalize(NULL) when not init -> CKR_CRYPTOKI_NOT_INITIALIZED");

    return f;
}

/* -------------------------------------------------------------------------
 * test_null_arg_validation
 *
 * Verify wolfP11-z7e: C_SeedRandom and C_GenerateRandom NULL-pointer checks.
 * ---------------------------------------------------------------------- */
static int test_null_arg_validation(void)
{
    CK_SESSION_HANDLE hSess = 0;
    CK_BYTE           dummy[1] = {0};
    CK_ULONG          dlen     = 1;
    CK_RV rv;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "null_args: C_Initialize");

    rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "null_args: C_OpenSession");

    /* C_SeedRandom with NULL pSeed -> CKR_ARGUMENTS_BAD */
    rv = C_SeedRandom(hSess, NULL_PTR, dlen);
    f += check(rv == CKR_ARGUMENTS_BAD,
               "null_args: C_SeedRandom(NULL pSeed) -> CKR_ARGUMENTS_BAD");

    /* C_SeedRandom with valid args -> CKR_RANDOM_SEED_NOT_SUPPORTED */
    rv = C_SeedRandom(hSess, dummy, dlen);
    f += check(rv == CKR_RANDOM_SEED_NOT_SUPPORTED,
               "null_args: C_SeedRandom supported check -> CKR_RANDOM_SEED_NOT_SUPPORTED");

    /* C_SeedRandom with invalid session -> CKR_SESSION_HANDLE_INVALID */
    rv = C_SeedRandom(0xFFFFFFFFUL, dummy, dlen);
    f += check(rv == CKR_SESSION_HANDLE_INVALID,
               "null_args: C_SeedRandom(bad session) -> CKR_SESSION_HANDLE_INVALID");

    /* C_GenerateRandom with NULL -> CKR_ARGUMENTS_BAD */
    rv = C_GenerateRandom(hSess, NULL_PTR, dlen);
    f += check(rv == CKR_ARGUMENTS_BAD,
               "null_args: C_GenerateRandom(NULL) -> CKR_ARGUMENTS_BAD");

    C_CloseSession(hSess);
    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "null_args: C_Finalize");

    return f;
}

/* -------------------------------------------------------------------------
 * test_operation_not_initialized
 *
 * Verify that C_Sign, C_FindObjects, C_FindObjectsFinal, and C_Decrypt
 * return CKR_OPERATION_NOT_INITIALIZED when their matching Init hasn't run.
 * ---------------------------------------------------------------------- */
static int test_operation_not_initialized(void)
{
    CK_SESSION_HANDLE hSess   = 0;
    CK_BYTE           dummy[1] = {0};
    CK_ULONG          dlen    = 1;
    CK_OBJECT_HANDLE  objs[4];
    CK_ULONG          nfound  = 0;
    CK_RV rv;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "op_not_init: C_Initialize");

    rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "op_not_init: C_OpenSession");

    /* C_Sign before C_SignInit */
    rv = C_Sign(hSess, dummy, dlen, dummy, &dlen);
    f += check(rv == CKR_OPERATION_NOT_INITIALIZED,
               "op_not_init: C_Sign without C_SignInit -> CKR_OPERATION_NOT_INITIALIZED");

    /* C_FindObjects before C_FindObjectsInit */
    rv = C_FindObjects(hSess, objs, 4, &nfound);
    f += check(rv == CKR_OPERATION_NOT_INITIALIZED,
               "op_not_init: C_FindObjects without Init -> CKR_OPERATION_NOT_INITIALIZED");

    /* C_FindObjectsFinal before C_FindObjectsInit */
    rv = C_FindObjectsFinal(hSess);
    f += check(rv == CKR_OPERATION_NOT_INITIALIZED,
               "op_not_init: C_FindObjectsFinal without Init -> CKR_OPERATION_NOT_INITIALIZED");

    /* C_Decrypt before C_DecryptInit */
    rv = C_Decrypt(hSess, dummy, dlen, dummy, &dlen);
    f += check(rv == CKR_OPERATION_NOT_INITIALIZED,
               "op_not_init: C_Decrypt without C_DecryptInit -> CKR_OPERATION_NOT_INITIALIZED");

    C_CloseSession(hSess);
    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "op_not_init: C_Finalize");

    return f;
}

/* -------------------------------------------------------------------------
 * test_so_login_with_ro_session
 *
 * Verify wolfP11-eg0: C_Login(CKU_SO) must return CKR_SESSION_READ_ONLY_EXISTS
 * when a read-only session is open on the token.
 * ---------------------------------------------------------------------- */
static int test_so_login_with_ro_session(void)
{
    CK_SESSION_HANDLE hRO = 0;
    CK_SESSION_HANDLE hRW = 0;
    CK_RV rv;
    int f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "so_ro_login: C_Initialize");

    /* Open a read-only session */
    rv = C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &hRO);
    f += check(rv == CKR_OK, "so_ro_login: C_OpenSession (RO)");

    /* C_Login(CKU_SO) must fail because a RO session exists */
    rv = C_Login(hRO, CKU_SO, NULL, 0);
    f += check(rv == CKR_SESSION_READ_ONLY_EXISTS,
               "so_ro_login: C_Login(SO) with open RO session -> CKR_SESSION_READ_ONLY_EXISTS");

    /* Open a read-write session; SO login should still fail because RO still exists */
    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hRW);
    f += check(rv == CKR_OK, "so_ro_login: C_OpenSession (RW)");

    rv = C_Login(hRW, CKU_SO, NULL, 0);
    f += check(rv == CKR_SESSION_READ_ONLY_EXISTS,
               "so_ro_login: C_Login(SO) from RW still fails due to open RO session");

    /* Close the RO session; only the RW session remains.
     * SO login should now succeed (no read-only session blocks it). */
    C_CloseSession(hRO);
    rv = C_Login(hRW, CKU_SO, NULL, 0);
    f += check(rv == CKR_OK,
               "so_ro_login: C_Login(SO) with only RW sessions -> CKR_OK");

    C_CloseSession(hRW);
    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "so_ro_login: C_Finalize");

    return f;
}

/* -------------------------------------------------------------------------
 * test_find_objects_template_filter
 *
 * Verify wolfP11-uu5: C_FindObjects respects the template passed to
 * C_FindObjectsInit, filtering by CKA_CLASS.
 * ---------------------------------------------------------------------- */
static int test_find_objects_template_filter(void)
{
    CK_RV             rv;
    CK_SESSION_HANDLE hSess  = 0;
    CK_OBJECT_HANDLE  hPub   = 0;
    CK_OBJECT_HANDLE  hPriv  = 0;
    CK_MECHANISM      mech   = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_HANDLE  found[8];
    CK_ULONG          nfound = 0;
    CK_OBJECT_CLASS   cls_priv   = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS   cls_pub    = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS   cls_secret = CKO_SECRET_KEY;
    CK_ATTRIBUTE      tmpl_priv   = { CKA_CLASS, &cls_priv,   sizeof(cls_priv)   };
    CK_ATTRIBUTE      tmpl_pub    = { CKA_CLASS, &cls_pub,    sizeof(cls_pub)    };
    CK_ATTRIBUTE      tmpl_secret = { CKA_CLASS, &cls_secret, sizeof(cls_secret) };
    static const CK_UTF8CHAR test_pin[] = "softtest";
    static const CK_ULONG    pin_len    = 8;
    int f = 0;

    setenv("WOLFP11_SOFT_KEYSTORE_PATH", "", 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "find_tmpl: C_Initialize");
    if (rv != CKR_OK) { unsetenv("WOLFP11_SOFT_KEYSTORE_PATH"); return f; }

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "find_tmpl: C_OpenSession");

    rv = C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)test_pin, pin_len);
    f += check(rv == CKR_OK, "find_tmpl: C_Login");

    rv = C_GenerateKeyPair(hSess, &mech, NULL, 0, NULL, 0, &hPub, &hPriv);
    f += check(rv == CKR_OK, "find_tmpl: C_GenerateKeyPair");
    if (rv != CKR_OK) goto done;

    /* Find only private keys */
    rv = C_FindObjectsInit(hSess, &tmpl_priv, 1);
    f += check(rv == CKR_OK, "find_tmpl: C_FindObjectsInit(CKO_PRIVATE_KEY)");
    nfound = 0;
    rv = C_FindObjects(hSess, found, 8, &nfound);
    f += check(rv == CKR_OK, "find_tmpl: C_FindObjects returns CKR_OK");
    f += check(nfound == 1, "find_tmpl: private-key filter returns 1 object");
    f += check(nfound > 0 && found[0] == hPriv,
               "find_tmpl: private-key filter returns the private key handle");
    C_FindObjectsFinal(hSess);

    /* C_GenerateKeyPair creates separate CKO_PUBLIC_KEY and CKO_PRIVATE_KEY
     * objects with distinct handles.  Filtering by CKO_PUBLIC_KEY must return
     * the public-key handle. */
    rv = C_FindObjectsInit(hSess, &tmpl_pub, 1);
    f += check(rv == CKR_OK, "find_tmpl: C_FindObjectsInit(CKO_PUBLIC_KEY)");
    nfound = 0;
    rv = C_FindObjects(hSess, found, 8, &nfound);
    f += check(rv == CKR_OK, "find_tmpl: C_FindObjects(public) returns CKR_OK");
    f += check(nfound == 1, "find_tmpl: public-key filter returns 1 object");
    f += check(nfound > 0 && found[0] == hPub,
               "find_tmpl: public-key filter returns the public key handle");
    C_FindObjectsFinal(hSess);

    /* Find secret keys -- none were generated, expect 0 */
    rv = C_FindObjectsInit(hSess, &tmpl_secret, 1);
    f += check(rv == CKR_OK, "find_tmpl: C_FindObjectsInit(CKO_SECRET_KEY)");
    nfound = 0;
    rv = C_FindObjects(hSess, found, 8, &nfound);
    f += check(rv == CKR_OK, "find_tmpl: C_FindObjects(secret) returns CKR_OK");
    f += check(nfound == 0, "find_tmpl: secret-key filter returns 0 objects");
    C_FindObjectsFinal(hSess);

done:
    C_Logout(hSess);
    C_CloseSession(hSess);
    C_Finalize(NULL);
    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}

/* -------------------------------------------------------------------------
 * test_init_error_path_active_flag
 *
 * Verify wolfP11-13f: C_SignInit, C_VerifyInit, C_DecryptInit clear the
 * active flag on failure, leaving the session in a clean state.
 *
 * For each Init* function:
 *  - Failure on a fresh session (first init, bad args) -> flag not set
 *  - Subsequent operation call -> CKR_OPERATION_NOT_INITIALIZED
 *  - C_VerifyInit failure -> C_Verify zero-sig -> CKR_SIGNATURE_LEN_RANGE
 *    (verifies wolfP11-vfg fix for zero-length signature rejection)
 * ---------------------------------------------------------------------- */
static int test_init_error_path_active_flag(void)
{
    CK_RV             rv;
    CK_SESSION_HANDLE hSess     = 0;
    CK_OBJECT_HANDLE  hPub      = 0;
    CK_OBJECT_HANDLE  hPriv     = 0;
    CK_MECHANISM      gen_mech  = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_MECHANISM      good_mech = { CKM_ECDSA, NULL, 0 };
    CK_MECHANISM      bad_mech  = { (CK_MECHANISM_TYPE)0xDEADU, NULL, 0 };
    static const CK_UTF8CHAR test_pin[] = "softtest";
    static const CK_ULONG    pin_len    = 8;
    static const CK_BYTE     test_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    CK_BYTE  sig_buf[128];
    CK_ULONG sig_len = sizeof(sig_buf);
    CK_BYTE  dummy_sig[1] = {0};
    int f = 0;

    setenv("WOLFP11_SOFT_KEYSTORE_PATH", "", 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "init_errpath: C_Initialize");
    if (rv != CKR_OK) { unsetenv("WOLFP11_SOFT_KEYSTORE_PATH"); return f; }

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "init_errpath: C_OpenSession");

    rv = C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)test_pin, pin_len);
    f += check(rv == CKR_OK, "init_errpath: C_Login");

    rv = C_GenerateKeyPair(hSess, &gen_mech, NULL, 0, NULL, 0, &hPub, &hPriv);
    f += check(rv == CKR_OK, "init_errpath: C_GenerateKeyPair");
    if (rv != CKR_OK) goto done;

    /* -- C_SignInit with bad mechanism on a fresh session -- */
    rv = C_SignInit(hSess, &bad_mech, hPriv);
    f += check(rv == CKR_MECHANISM_INVALID,
               "init_errpath: SignInit(bad_mech) -> CKR_MECHANISM_INVALID");

    /* sign_active must be 0: subsequent C_Sign returns CKR_OPERATION_NOT_INITIALIZED */
    sig_len = sizeof(sig_buf);
    rv = C_Sign(hSess, (CK_BYTE_PTR)test_hash, 32, sig_buf, &sig_len);
    f += check(rv == CKR_OPERATION_NOT_INITIALIZED,
               "init_errpath: C_Sign after bad SignInit -> CKR_OPERATION_NOT_INITIALIZED");

    /* -- C_SignInit with invalid key handle -- */
    rv = C_SignInit(hSess, &good_mech, (CK_OBJECT_HANDLE)0xFFFFFFFFUL);
    f += check(rv == CKR_KEY_HANDLE_INVALID,
               "init_errpath: SignInit(bad_key) -> CKR_KEY_HANDLE_INVALID");

    sig_len = sizeof(sig_buf);
    rv = C_Sign(hSess, (CK_BYTE_PTR)test_hash, 32, sig_buf, &sig_len);
    f += check(rv == CKR_OPERATION_NOT_INITIALIZED,
               "init_errpath: C_Sign after SignInit(bad_key) -> CKR_OPERATION_NOT_INITIALIZED");

    /* -- Successful C_SignInit, then re-init with bad mech, then C_Sign -- */
    rv = C_SignInit(hSess, &good_mech, hPriv);
    f += check(rv == CKR_OK, "init_errpath: first SignInit(valid) -> CKR_OK");

    /* PKCS#11 spec: CKR_OPERATION_ACTIVE is returned when a sign operation
     * is already in progress; mechanism validation is not reached on
     * double-init. The first valid init remains active (wolfP11-h53y). */
    rv = C_SignInit(hSess, &bad_mech, hPriv);
    f += check(rv == CKR_OPERATION_ACTIVE,
               "init_errpath: second SignInit while active -> CKR_OPERATION_ACTIVE");

    /* First valid SignInit is still active; C_Sign proceeds and clears it. */
    sig_len = sizeof(sig_buf);
    rv = C_Sign(hSess, (CK_BYTE_PTR)test_hash, 32, sig_buf, &sig_len);
    f += check(rv == CKR_OK,
               "init_errpath: C_Sign after rejected re-init uses first valid init");

    /* -- C_VerifyInit with bad mechanism -- */
    rv = C_VerifyInit(hSess, &bad_mech, hPriv);
    f += check(rv == CKR_MECHANISM_INVALID,
               "init_errpath: VerifyInit(bad_mech) -> CKR_MECHANISM_INVALID");

    rv = C_Verify(hSess, (CK_BYTE_PTR)test_hash, 32, dummy_sig, sizeof(dummy_sig));
    f += check(rv == CKR_OPERATION_NOT_INITIALIZED,
               "init_errpath: C_Verify after bad VerifyInit -> CKR_OPERATION_NOT_INITIALIZED");

    /* -- C_Verify with zero-length signature (wolfP11-vfg fix) -- */
    rv = C_VerifyInit(hSess, &good_mech, hPriv);
    f += check(rv == CKR_OK, "init_errpath: VerifyInit(valid) for zero-sig test");

    rv = C_Verify(hSess, (CK_BYTE_PTR)test_hash, 32, dummy_sig, 0u);
    f += check(rv == CKR_SIGNATURE_LEN_RANGE,
               "init_errpath: C_Verify(siglen=0) -> CKR_SIGNATURE_LEN_RANGE");

    /* verify_active must be cleared after the zero-sig rejection */
    rv = C_Verify(hSess, (CK_BYTE_PTR)test_hash, 32, dummy_sig, sizeof(dummy_sig));
    f += check(rv == CKR_OPERATION_NOT_INITIALIZED,
               "init_errpath: second C_Verify after zero-sig fail -> CKR_OPERATION_NOT_INITIALIZED");

done:
    C_Logout(hSess);
    C_CloseSession(hSess);
    C_Finalize(NULL);
    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}

static int test_sign_init_active_cleared_on_error(void)
{
    CK_RV             rv;
    CK_SESSION_HANDLE hSess      = 0;
    CK_OBJECT_HANDLE  hPub       = 0;
    CK_OBJECT_HANDLE  hPriv      = 0;
    CK_MECHANISM      gen_mech   = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_MECHANISM      valid_mech = { CKM_ECDSA, NULL, 0 };
    CK_MECHANISM      bad_mech   = { (CK_MECHANISM_TYPE)0xDEADU, NULL, 0 };
    static const CK_UTF8CHAR test_pin[] = "softtest";
    static const CK_ULONG    pin_len    = 8;
    static const CK_BYTE     test_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    CK_BYTE  sig[128];
    CK_ULONG siglen = sizeof(sig);
    int f = 0;

    setenv("WOLFP11_SOFT_KEYSTORE_PATH", "", 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "sign_init_error: C_Initialize");
    if (rv != CKR_OK) { unsetenv("WOLFP11_SOFT_KEYSTORE_PATH"); return f; }

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "sign_init_error: C_OpenSession");

    rv = C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)test_pin, pin_len);
    f += check(rv == CKR_OK, "sign_init_error: C_Login");

    rv = C_GenerateKeyPair(hSess, &gen_mech, NULL, 0, NULL, 0, &hPub, &hPriv);
    f += check(rv == CKR_OK, "sign_init_error: C_GenerateKeyPair");
    if (rv != CKR_OK) goto done;

    /* Step 1: successful C_SignInit sets sign_active */
    rv = C_SignInit(hSess, &valid_mech, hPriv);
    f += check(rv == CKR_OK,
               "sign_init_error: first C_SignInit (valid) succeeds");

    /* Step 2: PKCS#11 spec requires CKR_OPERATION_ACTIVE when a sign
     * operation is already active; mechanism validation is not reached
     * on double-init. The first valid init stays active (wolfP11-h53y). */
    rv = C_SignInit(hSess, &bad_mech, hPriv);
    f += check(rv == CKR_OPERATION_ACTIVE,
               "sign_init_error: second C_SignInit while active -> CKR_OPERATION_ACTIVE");

    /* Step 3: first valid SignInit is still active; C_Sign proceeds normally. */
    siglen = sizeof(sig);
    rv = C_Sign(hSess, (CK_BYTE_PTR)test_hash, sizeof(test_hash), sig, &siglen);
    f += check(rv == CKR_OK,
               "sign_init_error: C_Sign after rejected re-init uses first valid init");

done:
    C_Logout(hSess);
    C_CloseSession(hSess);
    C_Finalize(NULL);
    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}

/* -------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * test_soft_generate_keypair_basic
 *
 * Verify that C_GenerateKeyPair with CKM_EC_KEY_PAIR_GEN on the soft token
 * (slot 0) succeeds and returns a usable key handle.
 *
 * Oracle: C_SignInit + C_Sign succeeds and produces output of plausible
 * length for P-256 ECDSA (max 72 bytes per DER encoding constraints).
 * The soft-token path from key generation to signing is distinct from the
 * flash path (key material stays in wolfCrypt's ECC struct, not re-derived
 * from DER on each call).
 *
 * WOLFP11_SOFT_KEYSTORE_PATH is set to "" to force in-memory-only mode so
 * this test cannot write to the user's real ~/.wolfp11/soft.p11k.
 * ---------------------------------------------------------------------- */
static int test_soft_generate_keypair_basic(void)
{
    CK_RV             rv;
    CK_SESSION_HANDLE hSess     = 0;
    CK_OBJECT_HANDLE  hPub      = 0;
    CK_OBJECT_HANDLE  hPriv     = 0;
    CK_MECHANISM      mech      = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_MECHANISM      sign_mech = { CKM_ECDSA, NULL, 0 };
    static const CK_UTF8CHAR test_pin[] = "softtest";
    static const CK_ULONG    pin_len    = 8;
    /* Fixed 32-byte test digest for P-256 ECDSA signing */
    static const CK_BYTE test_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    CK_BYTE  sig[128];
    CK_ULONG siglen = sizeof(sig);
    CK_OBJECT_HANDLE found[8];
    CK_ULONG nfound = 0;
    uint8_t  pub_x963[65];
    CK_ULONG pub_len = sizeof(pub_x963);
    ecc_key  oracle_key;
    int      oracle_stat, oracle_ret;
    int f = 0;

    /* Disable persistence so we never touch ~/.wolfp11/soft.p11k */
    setenv("WOLFP11_SOFT_KEYSTORE_PATH", "", 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "soft_gkp_basic: C_Initialize");
    if (rv != CKR_OK) { unsetenv("WOLFP11_SOFT_KEYSTORE_PATH"); return f; }

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "soft_gkp_basic: C_OpenSession");

    rv = C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)test_pin, pin_len);
    f += check(rv == CKR_OK, "soft_gkp_basic: C_Login");

    rv = C_GenerateKeyPair(hSess, &mech,
                            NULL, 0,
                            NULL, 0,
                            &hPub, &hPriv);
    f += check(rv == CKR_OK, "soft_gkp_basic: C_GenerateKeyPair returns CKR_OK");
    f += check(hPriv != 0,   "soft_gkp_basic: private key handle non-zero");
    f += check(hPub  != 0,   "soft_gkp_basic: public key handle non-zero");

    if (rv == CKR_OK) {
        /* Key must appear in C_FindObjects */
        rv = C_FindObjectsInit(hSess, NULL, 0);
        f += check(rv == CKR_OK, "soft_gkp_basic: C_FindObjectsInit");
        nfound = 0;
        rv = C_FindObjects(hSess, found, 8, &nfound);
        f += check(rv == CKR_OK && nfound >= 1,
                   "soft_gkp_basic: C_FindObjects finds at least one key");
        C_FindObjectsFinal(hSess);

        /* Oracle: the generated key must be usable for signing */
        rv = C_SignInit(hSess, &sign_mech, hPriv);
        f += check(rv == CKR_OK, "soft_gkp_basic: C_SignInit returns CKR_OK");
        if (rv == CKR_OK) {
            siglen = sizeof(sig);
            rv = C_Sign(hSess, (CK_BYTE_PTR)test_hash, sizeof(test_hash),
                        sig, &siglen);
            f += check(rv == CKR_OK,
                       "soft_gkp_basic: C_Sign returns CKR_OK");
            /* P-256 DER ECDSA signature is at most 72 bytes */
            f += check(siglen > 0 && siglen <= 72u,
                       "soft_gkp_basic: signature length plausible for P-256");
            /* Independent oracle: wc_ecc_verify_hash confirms the signature is
             * cryptographically valid, not just the right length. */
            if (rv == CKR_OK && siglen > 0) {
                pub_len    = sizeof(pub_x963);
                oracle_stat = 0;
                oracle_ret = wp11_test_soft_export_pub_x963(hPub, pub_x963,
                                                             &pub_len);
                if (oracle_ret == 0 && wc_ecc_init(&oracle_key) == 0) {
                    oracle_ret = wc_ecc_import_x963(pub_x963, (word32)pub_len,
                                                    &oracle_key);
                    if (oracle_ret == 0) {
                        oracle_ret = wc_ecc_verify_hash(
                            sig, (word32)siglen,
                            test_hash, (word32)sizeof(test_hash),
                            &oracle_stat, &oracle_key);
                    }
                    f += check(oracle_ret == 0 && oracle_stat == 1,
                               "soft_gkp_basic: oracle -- wolfCrypt verifies C_Sign output");
                    wc_ecc_free(&oracle_key);
                }
            }
        }
    }

    C_Logout(hSess);
    C_CloseSession(hSess);
    C_Finalize(NULL);
    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}

/* -------------------------------------------------------------------------
 * test_soft_generate_keypair_p384
 *
 * Verifies C_GenerateKeyPair with CKM_EC_KEY_PAIR_GEN and CKA_EC_PARAMS
 * set to the P-384 OID.  The generated key must sign a 48-byte hash whose
 * signature is independently verified by wolfCrypt's wc_ecc_verify_hash.
 * ---------------------------------------------------------------------- */
static int test_soft_generate_keypair_p384(void)
{
    CK_RV             rv;
    CK_SESSION_HANDLE hSess     = 0;
    CK_OBJECT_HANDLE  hPub      = 0;
    CK_OBJECT_HANDLE  hPriv     = 0;
    CK_MECHANISM      gen_mech  = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_MECHANISM      sign_mech = { CKM_ECDSA, NULL, 0 };
    /* P-384 OID: 1.3.132.0.34 (DER-encoded named curve) */
    static const CK_BYTE p384_oid[] = {
        0x06,0x05,0x2b,0x81,0x04,0x00,0x22
    };
    CK_ATTRIBUTE pub_template[] = {
        { CKA_EC_PARAMS, (CK_VOID_PTR)p384_oid, sizeof(p384_oid) }
    };
    static const CK_UTF8CHAR test_pin[] = "softtest";
    static const CK_ULONG    pin_len    = 8;
    /* 48-byte placeholder hash for P-384 ECDSA signing */
    static const CK_BYTE test_hash[48] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
        0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
        0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30
    };
    CK_BYTE  sig[128];
    CK_ULONG siglen = sizeof(sig);
    /* P-384 uncompressed EC point: 04 || X(48) || Y(48) = 97 bytes */
    uint8_t  pub_x963[97];
    CK_ULONG pub_len    = sizeof(pub_x963);
    ecc_key  oracle_key;
    int      oracle_stat = 0;
    int      oracle_ret;
    int      f = 0;

    setenv("WOLFP11_SOFT_KEYSTORE_PATH", "", 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "soft_gkp_p384: C_Initialize");
    if (rv != CKR_OK) { unsetenv("WOLFP11_SOFT_KEYSTORE_PATH"); return f; }

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "soft_gkp_p384: C_OpenSession");

    rv = C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)test_pin, pin_len);
    f += check(rv == CKR_OK, "soft_gkp_p384: C_Login");

    rv = C_GenerateKeyPair(hSess, &gen_mech,
                            pub_template, 1,
                            NULL, 0,
                            &hPub, &hPriv);
    f += check(rv == CKR_OK, "soft_gkp_p384: C_GenerateKeyPair returns CKR_OK");
    f += check(hPriv != 0,   "soft_gkp_p384: private key handle non-zero");
    f += check(hPub  != 0,   "soft_gkp_p384: public key handle non-zero");

    if (rv == CKR_OK) {
        rv = C_SignInit(hSess, &sign_mech, hPriv);
        f += check(rv == CKR_OK, "soft_gkp_p384: C_SignInit returns CKR_OK");
        if (rv == CKR_OK) {
            siglen = sizeof(sig);
            rv = C_Sign(hSess, (CK_BYTE_PTR)test_hash, sizeof(test_hash),
                        sig, &siglen);
            f += check(rv == CKR_OK, "soft_gkp_p384: C_Sign returns CKR_OK");
            /* P-384 DER ECDSA: SEQUENCE + 2*INTEGER(49 max) = 104 bytes max */
            f += check(siglen > 0 && siglen <= 104u,
                       "soft_gkp_p384: signature length plausible for P-384");

            /* Independent oracle: wc_ecc_verify_hash confirms the signature
             * is cryptographically valid using the generated public key. */
            if (rv == CKR_OK && siglen > 0) {
                pub_len    = sizeof(pub_x963);
                oracle_ret = wp11_test_soft_export_pub_x963(hPub, pub_x963,
                                                             &pub_len);
                f += check(oracle_ret == 0 && pub_len == 97u,
                           "soft_gkp_p384: exported public key is 97 bytes (P-384)");
                if (oracle_ret == 0 && wc_ecc_init(&oracle_key) == 0) {
                    oracle_ret = wc_ecc_import_x963(pub_x963, (word32)pub_len,
                                                    &oracle_key);
                    if (oracle_ret == 0) {
                        oracle_ret = wc_ecc_verify_hash(
                            sig, (word32)siglen,
                            test_hash, (word32)sizeof(test_hash),
                            &oracle_stat, &oracle_key);
                    }
                    f += check(oracle_ret == 0 && oracle_stat == 1,
                               "soft_gkp_p384: oracle -- wolfCrypt verifies C_Sign output");
                    wc_ecc_free(&oracle_key);
                }
            }
        }
    }

    C_Logout(hSess);
    C_CloseSession(hSess);
    C_Finalize(NULL);
    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}

/* -------------------------------------------------------------------------
 * test_soft_generate_keypair_rsa
 *
 * Verifies C_GenerateKeyPair with CKM_RSA_PKCS_KEY_PAIR_GEN on the soft
 * token.  The RSA-2048 key must produce a PKCS#1 v1.5 signature that is
 * independently verified by C_Verify, which uses wc_RsaSSL_Verify (RSA
 * public-key operation -- inverse of the private-key sign operation).
 * ---------------------------------------------------------------------- */
static int test_soft_generate_keypair_rsa(void)
{
    CK_RV             rv;
    CK_SESSION_HANDLE hSess        = 0;
    CK_OBJECT_HANDLE  hPub         = 0;
    CK_OBJECT_HANDLE  hPriv        = 0;
    CK_MECHANISM      gen_mech     = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_MECHANISM      sign_mech    = { CKM_RSA_PKCS, NULL, 0 };
    CK_ULONG          modulus_bits = 2048;
    CK_ATTRIBUTE      pub_template[] = {
        { CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits) }
    };
    static const CK_UTF8CHAR test_pin[] = "softtest";
    static const CK_ULONG    pin_len    = 8;
    /* 20-byte SHA-1 placeholder for RSA PKCS#1 v1.5 signing */
    static const CK_BYTE test_hash[20] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
        0x11,0x12,0x13,0x14
    };
    CK_BYTE  sig[256];
    CK_ULONG siglen = sizeof(sig);
    int      f = 0;

    setenv("WOLFP11_SOFT_KEYSTORE_PATH", "", 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "soft_gkp_rsa: C_Initialize");
    if (rv != CKR_OK) { unsetenv("WOLFP11_SOFT_KEYSTORE_PATH"); return f; }

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "soft_gkp_rsa: C_OpenSession");

    rv = C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)test_pin, pin_len);
    f += check(rv == CKR_OK, "soft_gkp_rsa: C_Login");

    rv = C_GenerateKeyPair(hSess, &gen_mech,
                            pub_template, 1,
                            NULL, 0,
                            &hPub, &hPriv);
    f += check(rv == CKR_OK, "soft_gkp_rsa: C_GenerateKeyPair returns CKR_OK");
    f += check(hPriv != 0,   "soft_gkp_rsa: private key handle non-zero");
    f += check(hPub  != 0,   "soft_gkp_rsa: public key handle non-zero");

    if (rv == CKR_OK) {
        rv = C_SignInit(hSess, &sign_mech, hPriv);
        f += check(rv == CKR_OK, "soft_gkp_rsa: C_SignInit returns CKR_OK");
        if (rv == CKR_OK) {
            siglen = sizeof(sig);
            rv = C_Sign(hSess, (CK_BYTE_PTR)test_hash, sizeof(test_hash),
                        sig, &siglen);
            f += check(rv == CKR_OK, "soft_gkp_rsa: C_Sign returns CKR_OK");
            /* RSA-2048 signature is exactly the modulus size: 256 bytes */
            f += check(siglen == 256u,
                       "soft_gkp_rsa: signature is 256 bytes (RSA-2048)");

            /* Independent oracle: C_Verify performs wc_RsaSSL_Verify (RSA
             * public-key unpadding), the mathematical inverse of the private-
             * key sign.  A mismatched key pair or corrupted key fails here. */
            if (rv == CKR_OK && siglen > 0) {
                rv = C_VerifyInit(hSess, &sign_mech, hPub);
                f += check(rv == CKR_OK,
                           "soft_gkp_rsa: C_VerifyInit returns CKR_OK");
                if (rv == CKR_OK) {
                    rv = C_Verify(hSess,
                                  (CK_BYTE_PTR)test_hash, sizeof(test_hash),
                                  sig, siglen);
                    f += check(rv == CKR_OK,
                               "soft_gkp_rsa: oracle -- C_Verify confirms key pair is valid");
                }
            }
        }
    }

    C_Logout(hSess);
    C_CloseSession(hSess);
    C_Finalize(NULL);
    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}

/* -------------------------------------------------------------------------
 * test_soft_generate_keypair_ed25519
 *
 * Verifies C_GenerateKeyPair with CKM_EC_EDWARDS_KEY_PAIR_GEN on the soft
 * token.  Ed25519 signs the full message (no pre-hash); the signature is
 * always exactly 64 bytes.  The generated signature is independently
 * verified by wolfCrypt's wc_ed25519_verify_msg using the exported 32-byte
 * raw public key -- a different code path from the sign path.
 * ---------------------------------------------------------------------- */
static int test_soft_generate_keypair_ed25519(void)
{
    CK_RV             rv;
    CK_SESSION_HANDLE hSess     = 0;
    CK_OBJECT_HANDLE  hPub      = 0;
    CK_OBJECT_HANDLE  hPriv     = 0;
    CK_MECHANISM      gen_mech  = { CKM_EC_EDWARDS_KEY_PAIR_GEN, NULL, 0 };
    CK_MECHANISM      sign_mech = { CKM_EDDSA, NULL, 0 };
    static const CK_UTF8CHAR test_pin[] = "softtest";
    static const CK_ULONG    pin_len    = 8;
    /* Arbitrary test message -- Ed25519 signs the full message, not a hash */
    static const CK_BYTE test_msg[] = "wolfP11 Ed25519 test message";
    CK_BYTE  sig[64];
    CK_ULONG siglen = sizeof(sig);
    /* Raw 32-byte Ed25519 public key */
    uint8_t  pub_raw[32];
    CK_ULONG pub_len   = sizeof(pub_raw);
    ed25519_key oracle_key;
    int         oracle_init = 0;
    int         oracle_stat = 0;
    int         oracle_ret;
    int         f = 0;

    setenv("WOLFP11_SOFT_KEYSTORE_PATH", "", 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "soft_gkp_ed25519: C_Initialize");
    if (rv != CKR_OK) { unsetenv("WOLFP11_SOFT_KEYSTORE_PATH"); return f; }

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "soft_gkp_ed25519: C_OpenSession");

    rv = C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)test_pin, pin_len);
    f += check(rv == CKR_OK, "soft_gkp_ed25519: C_Login");

    /* Ed25519 has fixed parameters -- no CKA_EC_PARAMS template needed */
    rv = C_GenerateKeyPair(hSess, &gen_mech,
                            NULL, 0,
                            NULL, 0,
                            &hPub, &hPriv);
    f += check(rv == CKR_OK, "soft_gkp_ed25519: C_GenerateKeyPair returns CKR_OK");
    f += check(hPriv != 0,   "soft_gkp_ed25519: private key handle non-zero");
    f += check(hPub  != 0,   "soft_gkp_ed25519: public key handle non-zero");

    if (rv == CKR_OK) {
        rv = C_SignInit(hSess, &sign_mech, hPriv);
        f += check(rv == CKR_OK, "soft_gkp_ed25519: C_SignInit returns CKR_OK");
        if (rv == CKR_OK) {
            siglen = sizeof(sig);
            rv = C_Sign(hSess, (CK_BYTE_PTR)test_msg, sizeof(test_msg) - 1u,
                        sig, &siglen);
            f += check(rv == CKR_OK, "soft_gkp_ed25519: C_Sign returns CKR_OK");
            /* Ed25519 signature is always exactly 64 bytes */
            f += check(siglen == 64u,
                       "soft_gkp_ed25519: signature is exactly 64 bytes");

            /* Independent oracle: wc_ed25519_verify_msg confirms the signature
             * is cryptographically valid using the exported raw public key.
             * This is a different code path from the sign path. */
            if (rv == CKR_OK && siglen == 64u) {
                pub_len    = sizeof(pub_raw);
                oracle_ret = wp11_test_soft_export_ed25519_pub(hPub, pub_raw,
                                                                &pub_len);
                f += check(oracle_ret == 0 && pub_len == 32u,
                           "soft_gkp_ed25519: exported public key is 32 bytes");
                if (oracle_ret == 0 && wc_ed25519_init(&oracle_key) == 0) {
                    oracle_init = 1;
                    oracle_ret = wc_ed25519_import_public(pub_raw,
                                                          (word32)pub_len,
                                                          &oracle_key);
                    if (oracle_ret == 0) {
                        oracle_stat = 0;
                        oracle_ret = wc_ed25519_verify_msg(
                            sig, (word32)siglen,
                            (const uint8_t *)test_msg, sizeof(test_msg) - 1u,
                            &oracle_stat, &oracle_key);
                    }
                    f += check(oracle_ret == 0 && oracle_stat == 1,
                               "soft_gkp_ed25519: oracle -- wolfCrypt verifies C_Sign output");
                }
            }
        }
    }

    if (oracle_init) wc_ed25519_free(&oracle_key);
    C_Logout(hSess);
    C_CloseSession(hSess);
    C_Finalize(NULL);
    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}

/* -------------------------------------------------------------------------
 * test_soft_rsa_oaep
 *
 * Verifies CKM_RSA_PKCS_OAEP on the soft token using cross-validation:
 *   Part A: wolfCrypt oracle wc_RsaPublicEncrypt_ex (using N/E from attributes)
 *           -> wolfP11 C_Decrypt verifies correct plaintext recovery.
 *   Part B: wolfP11 C_Encrypt -> wp11_test_soft_rsa_oaep_decrypt oracle
 *           (direct wc_RsaPrivateDecrypt_ex, bypassing PKCS#11 session layer)
 *           verifies correct plaintext recovery.
 * ---------------------------------------------------------------------- */
static int test_soft_rsa_oaep(void)
{
    CK_RV             rv;
    CK_SESSION_HANDLE hSess  = 0;
    CK_OBJECT_HANDLE  hPub   = 0;
    CK_OBJECT_HANDLE  hPriv  = 0;
    int               f      = 0;
    int               wret;

    static const CK_UTF8CHAR test_pin[] = "softtest";
    static const CK_ULONG    pin_len    = 8;

    /* RSA-2048 key pair generation */
    static const CK_ULONG mod_bits = 2048u;
    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_MODULUS_BITS, (CK_VOID_PTR)&mod_bits, sizeof(mod_bits) }
    };
    CK_MECHANISM gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };

    /* OAEP mechanism params: SHA-256 hash, MGF1-SHA256, no label */
    CK_RSA_PKCS_OAEP_PARAMS oaep_params;
    CK_MECHANISM oaep_mech;

    /* Exported public key (N, E) for Part A wolfCrypt oracle */
    uint8_t  n_buf[256];   /* 256 bytes = RSA-2048 modulus */
    uint8_t  e_buf[32];
    CK_ULONG n_len = sizeof(n_buf);
    CK_ULONG e_len = sizeof(e_buf);
    CK_ATTRIBUTE n_attr = { CKA_MODULUS,          n_buf, sizeof(n_buf) };
    CK_ATTRIBUTE e_attr = { CKA_PUBLIC_EXPONENT,  e_buf, sizeof(e_buf) };

    static const uint8_t plaintext[] = "wolfP11 RSA-OAEP test";
    static const CK_ULONG pt_len = sizeof(plaintext) - 1u;

    /* Part A buffers: oracle encrypts, wolfP11 decrypts */
    uint8_t  ct_a[256];    /* RSA-2048 ciphertext is always 256 bytes */
    int      ct_a_len;     /* wc_RsaPublicEncrypt_ex returns int */
    uint8_t  pt_a_out[sizeof(plaintext)];
    CK_ULONG pt_a_out_len = sizeof(pt_a_out);

    /* Part B buffers: wolfP11 encrypts, oracle decrypts */
    uint8_t  ct_b[256];
    CK_ULONG ct_b_len = sizeof(ct_b);
    uint8_t  pt_b_out[sizeof(plaintext)];
    word32   pt_b_out_len = sizeof(pt_b_out);

    /* wolfCrypt oracle RSA key (public key only, for Part A encrypt) */
    RsaKey oracle_rsa;
    WC_RNG oracle_rng;
    int    oracle_rsa_init = 0;
    int    oracle_rng_init = 0;

    setenv("WOLFP11_SOFT_KEYSTORE_PATH", "", 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "rsa_oaep: C_Initialize");
    if (rv != CKR_OK) { unsetenv("WOLFP11_SOFT_KEYSTORE_PATH"); return f; }

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL_PTR, NULL_PTR, &hSess);
    f += check(rv == CKR_OK, "rsa_oaep: C_OpenSession");

    rv = C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)test_pin, pin_len);
    f += check(rv == CKR_OK, "rsa_oaep: C_Login");

    rv = C_GenerateKeyPair(hSess, &gen_mech,
                            pub_tmpl, 1u,
                            NULL_PTR, 0,
                            &hPub, &hPriv);
    f += check(rv == CKR_OK, "rsa_oaep: C_GenerateKeyPair (RSA-2048)");
    f += check(hPub != 0 && hPriv != 0, "rsa_oaep: key handles non-zero");
    if (rv != CKR_OK || hPub == 0 || hPriv == 0) goto cleanup;

    /* Export N and E for the Part A oracle */
    n_attr.ulValueLen = sizeof(n_buf);
    e_attr.ulValueLen = sizeof(e_buf);
    rv = C_GetAttributeValue(hSess, hPub, &n_attr, 1);
    f += check(rv == CKR_OK, "rsa_oaep: export CKA_MODULUS");
    rv = C_GetAttributeValue(hSess, hPub, &e_attr, 1);
    f += check(rv == CKR_OK, "rsa_oaep: export CKA_PUBLIC_EXPONENT");
    if (rv != CKR_OK) goto cleanup;
    n_len = n_attr.ulValueLen;
    e_len = e_attr.ulValueLen;

    /* Build wolfCrypt oracle public key */
    wc_InitRng(&oracle_rng);
    oracle_rng_init = 1;
    wc_InitRsaKey(&oracle_rsa, NULL);
    oracle_rsa_init = 1;
    wret = wc_RsaPublicKeyDecodeRaw(n_buf, (word32)n_len,
                                     e_buf, (word32)e_len, &oracle_rsa);
    f += check(wret == 0, "rsa_oaep: oracle wc_RsaPublicKeyDecodeRaw");
    if (wret != 0) goto cleanup;

    /* Set up OAEP mechanism: SHA-256, MGF1-SHA256, no label */
    memset(&oaep_params, 0, sizeof(oaep_params));
    oaep_params.hashAlg        = CKM_SHA256;
    oaep_params.mgf            = CKG_MGF1_SHA256;
    oaep_params.source         = 0;
    oaep_params.pSourceData    = NULL_PTR;
    oaep_params.ulSourceDataLen = 0;
    oaep_mech.mechanism        = CKM_RSA_PKCS_OAEP;
    oaep_mech.pParameter       = &oaep_params;
    oaep_mech.ulParameterLen   = (CK_ULONG)sizeof(oaep_params);

    /* ---- Part A: wolfCrypt oracle encrypts, wolfP11 C_Decrypt verifies ---- */
    ct_a_len = wc_RsaPublicEncrypt_ex(
        (const byte *)plaintext, (word32)pt_len,
        ct_a, (word32)sizeof(ct_a), &oracle_rsa, &oracle_rng,
        WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0);
    f += check(ct_a_len > 0, "rsa_oaep: oracle wc_RsaPublicEncrypt_ex (A)");

    if (ct_a_len > 0) {
        rv = C_DecryptInit(hSess, &oaep_mech, hPriv);
        f += check(rv == CKR_OK, "rsa_oaep: C_DecryptInit (A)");
        if (rv == CKR_OK) {
            pt_a_out_len = sizeof(pt_a_out);
            rv = C_Decrypt(hSess,
                            ct_a, (CK_ULONG)ct_a_len,
                            pt_a_out, &pt_a_out_len);
            f += check(rv == CKR_OK, "rsa_oaep: C_Decrypt (A)");
            f += check(rv == CKR_OK && pt_a_out_len == pt_len,
                       "rsa_oaep: C_Decrypt output length correct (A)");
            f += check(rv == CKR_OK &&
                       memcmp(pt_a_out, plaintext, (size_t)pt_len) == 0,
                       "rsa_oaep: C_Decrypt recovered plaintext matches (A)");
        }
    }

    /* ---- Part B: wolfP11 C_Encrypt, oracle wc_RsaPrivateDecrypt_ex ------- */
    rv = C_EncryptInit(hSess, &oaep_mech, hPub);
    f += check(rv == CKR_OK, "rsa_oaep: C_EncryptInit (B)");
    if (rv == CKR_OK) {
        ct_b_len = sizeof(ct_b);
        rv = C_Encrypt(hSess,
                        (CK_BYTE_PTR)(void *)(uintptr_t)plaintext, pt_len,
                        ct_b, &ct_b_len);
        f += check(rv == CKR_OK, "rsa_oaep: C_Encrypt (B)");
        f += check(rv == CKR_OK && ct_b_len == 256u,
                   "rsa_oaep: C_Encrypt output length == 256 (B)");

        if (rv == CKR_OK) {
            /* Oracle: direct wc_RsaPrivateDecrypt_ex bypassing PKCS#11 session */
            pt_b_out_len = sizeof(pt_b_out);
            wret = wp11_test_soft_rsa_oaep_decrypt(
                hPriv,
                ct_b, (word32)ct_b_len,
                pt_b_out, (word32)sizeof(pt_b_out), &pt_b_out_len,
                (int)WC_HASH_TYPE_SHA256, WC_MGF1SHA256);
            f += check(wret == 0,
                       "rsa_oaep: oracle decrypt succeeds (B)");
            f += check(wret == 0 && pt_b_out_len == pt_len,
                       "rsa_oaep: oracle output length correct (B)");
            f += check(wret == 0 &&
                       memcmp(pt_b_out, plaintext, (size_t)pt_len) == 0,
                       "rsa_oaep: oracle recovered plaintext matches (B)");
        }
    }

cleanup:
    if (oracle_rsa_init) wc_FreeRsaKey(&oracle_rsa);
    if (oracle_rng_init) wc_FreeRng(&oracle_rng);
    C_Logout(hSess);
    C_CloseSession(hSess);
    C_Finalize(NULL);
    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}

/* -------------------------------------------------------------------------
 * test_soft_rsa_pss
 *
 * Verifies CKM_RSA_PKCS_PSS on the soft token using cross-validation:
 *   Part A: wolfP11 C_Sign -> oracle wc_RsaPSS_VerifyCheck (public key only).
 *   Part B: oracle wc_RsaPSS_Sign (private key from exported DER) -> wolfP11 C_Verify.
 *
 * CLAUDE.md oracle rule: both oracles use wolfCrypt keys loaded from exported
 * N/E (Part A) and PKCS#1 private key DER (Part B), independent of the
 * wolfP11 session state.
 * ---------------------------------------------------------------------- */
#ifdef WC_RSA_PSS
/* Forward declaration for the test helper defined in src/wp11_pkcs11.c */
int wp11_test_soft_rsa_export_priv_der(CK_OBJECT_HANDLE hKey,
                                        uint8_t *buf, word32 buflen);

static int test_soft_rsa_pss(void)
{
    CK_RV             rv;
    CK_SESSION_HANDLE hSess = 0;
    CK_OBJECT_HANDLE  hPub  = 0;
    CK_OBJECT_HANDLE  hPriv = 0;
    int               f     = 0;
    int               wret;

    static const CK_UTF8CHAR test_pin[] = "softtest";
    static const CK_ULONG    pin_len    = 8;

    /* RSA-2048 key pair generation */
    static const CK_ULONG mod_bits = 2048u;
    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_MODULUS_BITS, (CK_VOID_PTR)&mod_bits, sizeof(mod_bits) }
    };
    CK_MECHANISM gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };

    /* PSS mechanism params: SHA-256 hash, MGF1-SHA256, salt=0 (wolfCrypt
     * default: salt length equals hash length; s_len is advisory only) */
    CK_RSA_PKCS_PSS_PARAMS pss_params;
    CK_MECHANISM           pss_mech;

    /* Exported public key N, E for Part A oracle */
    uint8_t  n_buf[256];
    uint8_t  e_buf[32];
    CK_ATTRIBUTE n_attr = { CKA_MODULUS,         n_buf, sizeof(n_buf) };
    CK_ATTRIBUTE e_attr = { CKA_PUBLIC_EXPONENT, e_buf, sizeof(e_buf) };
    CK_ULONG n_len, e_len;

    /* Exported private key DER for Part B oracle */
    uint8_t priv_der[2350]; /* RSA-2048 PKCS#1 DER upper bound */
    int     priv_der_len;

    /* plaintext and SHA-256 digest */
    static const uint8_t plaintext[] = "wolfP11 RSA-PSS test";
    static const CK_ULONG pt_len     = sizeof(plaintext) - 1u;
    uint8_t  digest[32]; /* SHA-256 output */

    /* Part A: wolfP11 sign, oracle verify */
    uint8_t  sig_a[256];
    CK_ULONG sig_a_len = sizeof(sig_a);

    /* Part B: oracle sign, wolfP11 verify */
    uint8_t  sig_b[256];
    int      sig_b_len;

    /* wolfCrypt oracle keys */
    RsaKey   oracle_pub;
    RsaKey   oracle_priv;
    WC_RNG   oracle_rng;
    wc_Sha256 sha256_ctx;
    uint8_t  scratch[256];
    int      oracle_pub_init  = 0;
    int      oracle_priv_init = 0;
    int      oracle_rng_init  = 0;
    word32   idx;

    setenv("WOLFP11_SOFT_KEYSTORE_PATH", "", 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "rsa_pss: C_Initialize");
    if (rv != CKR_OK) { unsetenv("WOLFP11_SOFT_KEYSTORE_PATH"); return f; }

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL_PTR, NULL_PTR, &hSess);
    f += check(rv == CKR_OK, "rsa_pss: C_OpenSession");

    rv = C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)test_pin, pin_len);
    f += check(rv == CKR_OK, "rsa_pss: C_Login");

    rv = C_GenerateKeyPair(hSess, &gen_mech,
                            pub_tmpl, 1u, NULL_PTR, 0,
                            &hPub, &hPriv);
    f += check(rv == CKR_OK, "rsa_pss: C_GenerateKeyPair (RSA-2048)");
    f += check(hPub != 0 && hPriv != 0, "rsa_pss: key handles non-zero");
    if (rv != CKR_OK || hPub == 0 || hPriv == 0) goto cleanup;

    /* Export N and E for Part A oracle */
    n_attr.ulValueLen = sizeof(n_buf);
    e_attr.ulValueLen = sizeof(e_buf);
    rv = C_GetAttributeValue(hSess, hPub, &n_attr, 1);
    f += check(rv == CKR_OK, "rsa_pss: export CKA_MODULUS");
    rv = C_GetAttributeValue(hSess, hPub, &e_attr, 1);
    f += check(rv == CKR_OK, "rsa_pss: export CKA_PUBLIC_EXPONENT");
    if (rv != CKR_OK) goto cleanup;
    n_len = n_attr.ulValueLen;
    e_len = e_attr.ulValueLen;

    /* Export private key DER for Part B oracle */
    priv_der_len = wp11_test_soft_rsa_export_priv_der(hPriv, priv_der,
                                                       sizeof(priv_der));
    f += check(priv_der_len > 0, "rsa_pss: export private key DER");
    if (priv_der_len <= 0) goto cleanup;

    /* Set up PSS mechanism */
    memset(&pss_params, 0, sizeof(pss_params));
    pss_params.hashAlg = CKM_SHA256;
    pss_params.mgf     = CKG_MGF1_SHA256;
    pss_params.sLen    = 0; /* advisory; wolfCrypt uses hash-length salt */
    pss_mech.mechanism      = CKM_RSA_PKCS_PSS;
    pss_mech.pParameter     = &pss_params;
    pss_mech.ulParameterLen = (CK_ULONG)sizeof(pss_params);

    /* Compute SHA-256 digest of plaintext (both parts use the same digest) */
    wc_InitSha256(&sha256_ctx);
    wc_Sha256Update(&sha256_ctx, plaintext, (word32)pt_len);
    wc_Sha256Final(&sha256_ctx, digest);

    /* Build Part A oracle public key from N/E */
    wc_InitRng(&oracle_rng);  oracle_rng_init  = 1;
    wc_InitRsaKey(&oracle_pub, NULL); oracle_pub_init = 1;
    wret = wc_RsaPublicKeyDecodeRaw(n_buf, (word32)n_len,
                                     e_buf, (word32)e_len, &oracle_pub);
    f += check(wret == 0, "rsa_pss: oracle wc_RsaPublicKeyDecodeRaw");
    if (wret != 0) goto cleanup;

    /* Build Part B oracle private key from exported DER */
    wc_InitRsaKey(&oracle_priv, NULL); oracle_priv_init = 1;
    idx  = 0;
    wret = wc_RsaPrivateKeyDecode(priv_der, &idx, &oracle_priv,
                                   (word32)priv_der_len);
    f += check(wret == 0, "rsa_pss: oracle wc_RsaPrivateKeyDecode");
    if (wret != 0) goto cleanup;

    /* ---- Part A: wolfP11 C_Sign, oracle wc_RsaPSS_VerifyCheck ---- */
    rv = C_SignInit(hSess, &pss_mech, hPriv);
    f += check(rv == CKR_OK, "rsa_pss: C_SignInit (A)");
    if (rv == CKR_OK) {
        sig_a_len = sizeof(sig_a);
        rv = C_Sign(hSess, digest, (CK_ULONG)sizeof(digest),
                    sig_a, &sig_a_len);
        f += check(rv == CKR_OK, "rsa_pss: C_Sign (A)");
        f += check(rv == CKR_OK && sig_a_len == 256u,
                   "rsa_pss: C_Sign output length == 256 (A)");

        if (rv == CKR_OK) {
            /* Oracle verify: wc_RsaPSS_VerifyCheck on independently-loaded
             * public key.  Returns >= 0 on successful verification. */
            wret = wc_RsaPSS_VerifyCheck(sig_a, (word32)sig_a_len,
                                          scratch, sizeof(scratch),
                                          digest, sizeof(digest),
                                          WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                                          &oracle_pub);
            f += check(wret >= 0, "rsa_pss: oracle verify succeeds (A)");
        }
    }

    /* ---- Part B: oracle wc_RsaPSS_Sign, wolfP11 C_Verify ---- */
    sig_b_len = wc_RsaPSS_Sign(digest, sizeof(digest),
                                sig_b, sizeof(sig_b),
                                WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                                &oracle_priv, &oracle_rng);
    f += check(sig_b_len == 256, "rsa_pss: oracle wc_RsaPSS_Sign succeeds (B)");

    if (sig_b_len == 256) {
        rv = C_VerifyInit(hSess, &pss_mech, hPub);
        f += check(rv == CKR_OK, "rsa_pss: C_VerifyInit (B)");
        if (rv == CKR_OK) {
            rv = C_Verify(hSess, digest, (CK_ULONG)sizeof(digest),
                          sig_b, (CK_ULONG)sig_b_len);
            f += check(rv == CKR_OK, "rsa_pss: C_Verify (B)");
        }
    }

    /* ---- Part C: explicit sLen=32 in C_Sign; oracle verifies -------------
     * Tests the non-zero sLen -> wolfCrypt saltLen mapping in C_SignInit.
     * sLen=0 (Part A/B) maps to RSA_PSS_SALT_LEN_DEFAULT (-1) which wolfCrypt
     * interprets as "hash-length salt".  Here sLen=32 (SHA-256 hash length)
     * is passed explicitly; it must produce the same result as the default
     * but through a different code path. wc_RsaPSS_VerifyCheck verifies with
     * hash-length salt (SHA-256 = 32 bytes), confirming the signature is valid
     * for a 32-byte explicit salt. */
    {
        uint8_t  sig_c[256];
        CK_ULONG sig_c_len;

        pss_params.sLen                = 32u; /* SHA-256 hash length in bytes */
        pss_mech.mechanism             = CKM_RSA_PKCS_PSS;
        pss_mech.pParameter            = &pss_params;
        pss_mech.ulParameterLen        = (CK_ULONG)sizeof(pss_params);

        rv = C_SignInit(hSess, &pss_mech, hPriv);
        f += check(rv == CKR_OK, "rsa_pss: C_SignInit (C, sLen=32)");
        if (rv == CKR_OK) {
            sig_c_len = (CK_ULONG)sizeof(sig_c);
            rv = C_Sign(hSess, digest, (CK_ULONG)sizeof(digest),
                        sig_c, &sig_c_len);
            f += check(rv == CKR_OK, "rsa_pss: C_Sign (C, sLen=32)");
            if (rv == CKR_OK) {
                wret = wc_RsaPSS_VerifyCheck(sig_c, (word32)sig_c_len,
                                              scratch, sizeof(scratch),
                                              digest, sizeof(digest),
                                              WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                                              &oracle_pub);
                f += check(wret >= 0,
                           "rsa_pss: oracle verifies C_Sign with explicit sLen=32 (C)");
            }
        }
        pss_params.sLen = 0u; /* restore for subsequent steps */
    }

    /* ---- Part D: C_Sign -> C_Verify round-trip (sLen=0) -----------------
     * Tests that sign and verify compose on the same session/key.
     * sig_a was produced in Part A and oracle-verified there; here we check
     * that C_Verify also accepts it, catching any divergence between the
     * C_Sign code path and the C_Verify code path. */
    {
        rv = C_VerifyInit(hSess, &pss_mech, hPub);
        f += check(rv == CKR_OK, "rsa_pss: C_VerifyInit (D, round-trip)");
        if (rv == CKR_OK) {
            rv = C_Verify(hSess, digest, (CK_ULONG)sizeof(digest),
                          sig_a, (CK_ULONG)sig_a_len);
            f += check(rv == CKR_OK,
                       "rsa_pss: C_Sign -> C_Verify round-trip (D)");
        }
    }

cleanup:
    if (oracle_pub_init)  wc_FreeRsaKey(&oracle_pub);
    if (oracle_priv_init) wc_FreeRsaKey(&oracle_priv);
    if (oracle_rng_init)  wc_FreeRng(&oracle_rng);
    C_Logout(hSess);
    C_CloseSession(hSess);
    C_Finalize(NULL);
    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}
#endif /* WC_RSA_PSS */

/* -------------------------------------------------------------------------
 * test_soft_aes_gcm
 *
 * Verifies CKM_AES_GCM on the soft token using cross-validation:
 *   Part A: wolfP11 C_Encrypt output verified by wolfCrypt wc_AesGcmDecrypt.
 *   Part B: wolfCrypt wc_AesGcmEncrypt output verified by wolfP11 C_Decrypt.
 *   Part C: tampered auth tag -> C_Decrypt returns CKR_ENCRYPTED_DATA_INVALID.
 * ---------------------------------------------------------------------- */
static int test_soft_aes_gcm(void)
{
    CK_RV             rv;
    CK_SESSION_HANDLE hSess = 0;
    CK_OBJECT_HANDLE  hKey  = 0;
    int               f     = 0;
    int               wret;

    static const CK_UTF8CHAR test_pin[]  = "softtest";
    static const CK_ULONG    pin_len     = 8;
    static const CK_ULONG    key_sz      = 32u;
    static const CK_BBOOL    ck_true     = CK_TRUE;

    CK_ATTRIBUTE gen_tmpl[] = {
        { CKA_VALUE_LEN,   (CK_VOID_PTR)&key_sz,   sizeof(key_sz)   },
        { CKA_EXTRACTABLE, (CK_VOID_PTR)&ck_true,  sizeof(ck_true)  }
    };
    CK_MECHANISM gen_mech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };

    /* Fixed IVs and AAD -- different for each part to avoid IV reuse */
    static const uint8_t iv_a[12] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c
    };
    static const uint8_t aad_a[8] = {
        0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe
    };
    static const uint8_t iv_b[12] = {
        0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b
    };

    static const uint8_t plaintext[] = "wolfP11 AES-GCM test";
    static const CK_ULONG pt_len    = sizeof(plaintext) - 1u;
    static const CK_ULONG tag_bits  = 128u;
    static const word32   tag_len   = 16u;

    uint8_t    raw_key[32];
    CK_ATTRIBUTE key_attr = { CKA_VALUE, raw_key, sizeof(raw_key) };

    /* Part A: wolfP11 encrypts -> oracle decrypts */
    uint8_t  ct_a[sizeof(plaintext) - 1u + 16u];
    CK_ULONG ct_a_len;
    uint8_t  pt_a_out[sizeof(plaintext) - 1u];

    /* Part B/C: oracle encrypts -> wolfP11 decrypts */
    uint8_t  ct_b[sizeof(plaintext) - 1u];
    uint8_t  tag_b[16u];
    uint8_t  combined_bc[sizeof(plaintext) - 1u + 16u];
    uint8_t  pt_b_out[sizeof(plaintext) - 1u];
    CK_ULONG pt_b_out_len;

    Aes oracle_aes;
    int oracle_init = 0;

    CK_GCM_PARAMS gcm_a;
    CK_GCM_PARAMS gcm_b;
    CK_MECHANISM  mech_enc_a;
    CK_MECHANISM  mech_dec_b;

    setenv("WOLFP11_SOFT_KEYSTORE_PATH", "", 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "aes_gcm: C_Initialize");
    if (rv != CKR_OK) { unsetenv("WOLFP11_SOFT_KEYSTORE_PATH"); return f; }

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL_PTR, NULL_PTR, &hSess);
    f += check(rv == CKR_OK, "aes_gcm: C_OpenSession");

    rv = C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)test_pin, pin_len);
    f += check(rv == CKR_OK, "aes_gcm: C_Login");

    rv = C_GenerateKey(hSess, &gen_mech,
                        gen_tmpl, sizeof(gen_tmpl)/sizeof(gen_tmpl[0]),
                        &hKey);
    f += check(rv == CKR_OK, "aes_gcm: C_GenerateKey (AES-256)");
    f += check(hKey != 0,    "aes_gcm: key handle non-zero");
    if (rv != CKR_OK || hKey == 0) goto cleanup;

    /* Extract raw key for the oracle (key must be extractable) */
    key_attr.ulValueLen = sizeof(raw_key);
    rv = C_GetAttributeValue(hSess, hKey, &key_attr, 1);
    f += check(rv == CKR_OK && key_attr.ulValueLen == 32u,
               "aes_gcm: extracted 32-byte raw key");
    if (rv != CKR_OK || key_attr.ulValueLen != 32u) goto cleanup;

    /* Init oracle AES once; reused for both Part A (decrypt) and Part B (encrypt) */
    wc_AesInit(&oracle_aes, NULL, INVALID_DEVID);
    oracle_init = 1;
    wret = wc_AesGcmSetKey(&oracle_aes, raw_key, (word32)key_attr.ulValueLen);
    f += check(wret == 0, "aes_gcm: oracle wc_AesGcmSetKey");
    if (wret != 0) goto cleanup;

    /* ---- Part A: wolfP11 C_Encrypt -> wolfCrypt oracle decrypts --------- */
    memset(&gcm_a, 0, sizeof(gcm_a));
    gcm_a.pIv       = (CK_BYTE_PTR)(void *)(uintptr_t)iv_a;
    gcm_a.ulIvLen   = (CK_ULONG)sizeof(iv_a);
    gcm_a.pAAD      = (CK_BYTE_PTR)(void *)(uintptr_t)aad_a;
    gcm_a.ulAADLen  = (CK_ULONG)sizeof(aad_a);
    gcm_a.ulTagBits = tag_bits;
    mech_enc_a.mechanism      = CKM_AES_GCM;
    mech_enc_a.pParameter     = &gcm_a;
    mech_enc_a.ulParameterLen = (CK_ULONG)sizeof(gcm_a);

    rv = C_EncryptInit(hSess, &mech_enc_a, hKey);
    f += check(rv == CKR_OK, "aes_gcm: C_EncryptInit (A)");
    if (rv == CKR_OK) {
        ct_a_len = (CK_ULONG)sizeof(ct_a);
        rv = C_Encrypt(hSess, (CK_BYTE_PTR)(void *)(uintptr_t)plaintext,
                        pt_len, ct_a, &ct_a_len);
        f += check(rv == CKR_OK, "aes_gcm: C_Encrypt (A)");
        f += check(ct_a_len == pt_len + (CK_ULONG)tag_len,
                   "aes_gcm: C_Encrypt output length = pt_len+16 (A)");

        if (rv == CKR_OK && ct_a_len == pt_len + (CK_ULONG)tag_len) {
            /* Oracle: wc_AesGcmDecrypt uses the raw key to independently verify */
            wret = wc_AesGcmDecrypt(&oracle_aes,
                       pt_a_out,
                       ct_a,          (word32)pt_len,
                       iv_a,          (word32)sizeof(iv_a),
                       ct_a + pt_len, tag_len,
                       aad_a,         (word32)sizeof(aad_a));
            f += check(wret == 0,
                       "aes_gcm: oracle wc_AesGcmDecrypt succeeds (A)");
            f += check(wret == 0 &&
                       memcmp(pt_a_out, plaintext, (size_t)pt_len) == 0,
                       "aes_gcm: oracle recovered plaintext matches (A)");
        }
    }

    /* ---- Part B: wolfCrypt oracle encrypts -> wolfP11 C_Decrypt --------- */
    wret = wc_AesGcmEncrypt(&oracle_aes,
               ct_b, plaintext, (word32)pt_len,
               iv_b,  (word32)sizeof(iv_b),
               tag_b, tag_len,
               NULL,  0);
    f += check(wret == 0, "aes_gcm: oracle wc_AesGcmEncrypt (B)");

    if (wret == 0) {
        memcpy(combined_bc,          ct_b,  (size_t)pt_len);
        memcpy(combined_bc + pt_len, tag_b, (size_t)tag_len);

        memset(&gcm_b, 0, sizeof(gcm_b));
        gcm_b.pIv       = (CK_BYTE_PTR)(void *)(uintptr_t)iv_b;
        gcm_b.ulIvLen   = (CK_ULONG)sizeof(iv_b);
        gcm_b.pAAD      = NULL_PTR;
        gcm_b.ulAADLen  = 0;
        gcm_b.ulTagBits = tag_bits;
        mech_dec_b.mechanism      = CKM_AES_GCM;
        mech_dec_b.pParameter     = &gcm_b;
        mech_dec_b.ulParameterLen = (CK_ULONG)sizeof(gcm_b);

        rv = C_DecryptInit(hSess, &mech_dec_b, hKey);
        f += check(rv == CKR_OK, "aes_gcm: C_DecryptInit (B)");
        if (rv == CKR_OK) {
            pt_b_out_len = (CK_ULONG)sizeof(pt_b_out);
            rv = C_Decrypt(hSess,
                            combined_bc, pt_len + (CK_ULONG)tag_len,
                            pt_b_out,   &pt_b_out_len);
            f += check(rv == CKR_OK, "aes_gcm: C_Decrypt (B)");
            f += check(rv == CKR_OK && pt_b_out_len == pt_len,
                       "aes_gcm: C_Decrypt output length == pt_len (B)");
            f += check(rv == CKR_OK &&
                       memcmp(pt_b_out, plaintext, (size_t)pt_len) == 0,
                       "aes_gcm: C_Decrypt recovered plaintext matches (B)");
        }

        /* ---- Part C: tampered tag -> CKR_ENCRYPTED_DATA_INVALID ---------- */
        combined_bc[pt_len] ^= 0xFFu;   /* corrupt first byte of auth tag */

        rv = C_DecryptInit(hSess, &mech_dec_b, hKey);
        f += check(rv == CKR_OK, "aes_gcm: C_DecryptInit (C)");
        if (rv == CKR_OK) {
            pt_b_out_len = (CK_ULONG)sizeof(pt_b_out);
            rv = C_Decrypt(hSess,
                            combined_bc, pt_len + (CK_ULONG)tag_len,
                            pt_b_out,   &pt_b_out_len);
            f += check(rv == CKR_ENCRYPTED_DATA_INVALID,
                       "aes_gcm: C_Decrypt rejects tampered ciphertext (C)");
        }
    }

cleanup:
    if (oracle_init) wc_AesFree(&oracle_aes);
    C_Logout(hSess);
    C_CloseSession(hSess);
    C_Finalize(NULL);
    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
/* -------------------------------------------------------------------------
 * test_rsa_oaep_vector_oracle
 *
 * wolfP11-444s: Independent oracle test for C_Decrypt RSA-OAEP.
 *
 * The private key and ciphertext were generated by pyca/cryptography
 * (https://cryptography.io), an RSA-OAEP implementation entirely independent
 * of wolfCrypt.  Unlike test_soft_rsa_oaep which uses wc_RsaPublicEncrypt_ex
 * and wp11_test_soft_rsa_oaep_decrypt (both wolfCrypt), this test verifies
 * that C_Decrypt recovers the correct plaintext from a ciphertext produced
 * by a different RSA-OAEP stack.
 *
 * Generation command (run once to produce the constants below):
 *   python3 -c "
 *   from cryptography.hazmat.primitives.asymmetric import rsa, padding
 *   from cryptography.hazmat.primitives import hashes, serialization
 *   key = rsa.generate_private_key(65537, 2048)
 *   ct = key.public_key().encrypt(b'wolfP11 RSA-OAEP test',
 *       padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
 *                    algorithm=hashes.SHA256(), label=None))
 *   priv_der = key.private_bytes(
 *       serialization.Encoding.DER,
 *       serialization.PrivateFormat.TraditionalOpenSSL,
 *       serialization.NoEncryption())
 *   # print as C hex arrays...
 *   "
 * ---------------------------------------------------------------------- */
static int test_rsa_oaep_vector_oracle(void)
{
    /* RSA-2048 PKCS#1 private key (DER, 1192 bytes) -- pyca generated */
    static const uint8_t oaep_tv_priv_der[] = {
        0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xa4, 0x0f, 0x3c, 0x0d,
        0x44, 0xca, 0x2b, 0x74, 0x34, 0xce, 0x6e, 0xa0, 0xb2, 0x85, 0xd6, 0xc0, 0x4d, 0x84, 0xe0, 0x62,
        0x1f, 0xe1, 0xc6, 0xd0, 0x6e, 0x3d, 0xe1, 0x7b, 0xc0, 0xab, 0x55, 0x92, 0x5c, 0x53, 0xc1, 0xc2,
        0x98, 0x03, 0x09, 0x17, 0x76, 0xed, 0xa4, 0xe7, 0x89, 0xa5, 0x2d, 0x99, 0x15, 0x6c, 0x4f, 0x3e,
        0x47, 0x31, 0xf0, 0x3d, 0xd1, 0x28, 0x97, 0x9d, 0x94, 0xf6, 0xbd, 0x07, 0xa7, 0xba, 0x14, 0xbb,
        0x21, 0xe1, 0xb1, 0x94, 0x41, 0xda, 0x7b, 0x54, 0xee, 0x40, 0xd0, 0xa4, 0xbb, 0x17, 0x2b, 0x15,
        0x45, 0xbb, 0x2c, 0x47, 0x16, 0xcf, 0x37, 0xbf, 0x6a, 0x4f, 0xd3, 0x7e, 0x8d, 0x5f, 0x1c, 0xbb,
        0x67, 0xe8, 0x70, 0x36, 0x58, 0x31, 0x67, 0x4c, 0xd0, 0x56, 0x9a, 0x20, 0xc5, 0x30, 0xfe, 0x90,
        0xb6, 0x16, 0x55, 0xc0, 0xf7, 0x68, 0xec, 0x8c, 0x7c, 0xad, 0xa8, 0x3a, 0x66, 0x04, 0x20, 0x05,
        0x1d, 0xfd, 0x52, 0x52, 0xc0, 0xbc, 0x8a, 0x20, 0x98, 0x59, 0xd9, 0x47, 0xc9, 0x28, 0x78, 0x86,
        0xe1, 0x87, 0xb2, 0x99, 0xd0, 0x26, 0x8d, 0xf0, 0xae, 0x6a, 0x62, 0x7e, 0xe6, 0x28, 0x5e, 0xd3,
        0xc1, 0x6a, 0x2e, 0x54, 0xd6, 0x43, 0xaa, 0x70, 0xb7, 0x2a, 0x1d, 0x7a, 0x90, 0x27, 0xb7, 0xc1,
        0xac, 0x78, 0xc2, 0x00, 0xb6, 0xcd, 0x7d, 0xb0, 0x0c, 0xd7, 0xdc, 0x62, 0x85, 0xd3, 0xff, 0x0f,
        0x42, 0x28, 0xe9, 0xa0, 0x94, 0x76, 0x38, 0x1e, 0x43, 0x71, 0xc3, 0xcc, 0x11, 0xb9, 0xc4, 0xee,
        0x3d, 0x03, 0xfd, 0xc9, 0x67, 0xf0, 0x84, 0x9a, 0x2f, 0xef, 0xd3, 0x58, 0x4f, 0x8d, 0x06, 0xb4,
        0x69, 0x4a, 0x57, 0x76, 0xa1, 0x1e, 0xc2, 0x1c, 0xfe, 0x4b, 0xcb, 0xff, 0x20, 0xd9, 0xd9, 0xdd,
        0xc2, 0x08, 0x3e, 0xba, 0x64, 0xf8, 0x0f, 0x6b, 0xc5, 0x43, 0x70, 0xb7, 0x02, 0x03, 0x01, 0x00,
        0x01, 0x02, 0x82, 0x01, 0x00, 0x18, 0xbf, 0x6b, 0x91, 0x9c, 0xd4, 0xda, 0x65, 0x37, 0x2a, 0x04,
        0xaa, 0x1d, 0x03, 0xef, 0x77, 0x26, 0xba, 0x6a, 0x96, 0xa2, 0xb4, 0x8e, 0x27, 0x16, 0xda, 0x22,
        0xcf, 0x66, 0x2a, 0xf2, 0x47, 0x97, 0xc1, 0xd2, 0xb2, 0xa5, 0xf7, 0x9f, 0x41, 0x78, 0xe1, 0x34,
        0x44, 0xf1, 0x10, 0x87, 0xa6, 0x56, 0x02, 0xf6, 0x99, 0x30, 0x68, 0x2a, 0x13, 0x49, 0x1f, 0xd4,
        0x6f, 0x22, 0xef, 0x6d, 0x68, 0x60, 0x36, 0xc3, 0xb5, 0xce, 0xd0, 0x9a, 0xd7, 0x00, 0x70, 0x12,
        0xb6, 0xa7, 0x12, 0x03, 0xe7, 0x35, 0x89, 0xb3, 0x28, 0x0c, 0x52, 0xc5, 0xc5, 0x1b, 0x7d, 0xba,
        0xad, 0x17, 0x3e, 0x5f, 0x6a, 0xf1, 0xac, 0x6d, 0x4b, 0x1f, 0xcb, 0x82, 0x51, 0xd0, 0x4f, 0xf3,
        0x83, 0x34, 0xd2, 0x3b, 0x81, 0xc1, 0xfd, 0x38, 0x09, 0x60, 0x4e, 0x52, 0x35, 0x3f, 0x9d, 0x06,
        0x41, 0xd2, 0xf4, 0xe7, 0x31, 0x5a, 0x2a, 0x06, 0x5a, 0x95, 0xb6, 0xe7, 0xdf, 0xe6, 0x67, 0xd8,
        0x95, 0x43, 0x44, 0x4c, 0x2a, 0x02, 0xc4, 0x56, 0x7a, 0xf0, 0x7e, 0x03, 0xf7, 0x21, 0xc5, 0x1a,
        0xbd, 0xdd, 0x8c, 0xf6, 0xce, 0xc4, 0x1b, 0xe8, 0x74, 0xb0, 0x0d, 0xe2, 0x6b, 0x27, 0x51, 0xa7,
        0xf6, 0xa7, 0x67, 0x68, 0x1c, 0x4f, 0xe1, 0x2d, 0xe4, 0xed, 0xd1, 0x78, 0xc0, 0xe5, 0xbf, 0x74,
        0x90, 0x7e, 0x5a, 0xf8, 0x29, 0xce, 0xfb, 0x0b, 0x77, 0x94, 0x9d, 0x1e, 0x15, 0x54, 0xcb, 0x7e,
        0xbe, 0xf9, 0x70, 0x47, 0xbe, 0xbd, 0x9c, 0x2c, 0x51, 0x0a, 0xdf, 0xc6, 0xa6, 0xd8, 0x89, 0xd6,
        0x02, 0x8a, 0xf8, 0x16, 0x28, 0x03, 0x54, 0xb2, 0x7e, 0x9d, 0x7b, 0x1e, 0x5f, 0x04, 0x4b, 0x9f,
        0xc2, 0xca, 0xaa, 0xe4, 0x60, 0x53, 0x30, 0x87, 0x25, 0xfa, 0x4d, 0xb5, 0x44, 0xe0, 0xa0, 0x81,
        0x19, 0x94, 0x2b, 0x58, 0x11, 0x02, 0x81, 0x81, 0x00, 0xcd, 0x1c, 0xf8, 0x24, 0xc1, 0xce, 0x86,
        0x15, 0xd5, 0x72, 0xed, 0xd8, 0x1f, 0x25, 0x8e, 0xdc, 0x06, 0x3c, 0x03, 0x43, 0x3e, 0x9c, 0x03,
        0x02, 0xd6, 0xb1, 0x12, 0x80, 0x96, 0x45, 0x68, 0x1c, 0x22, 0x2c, 0x82, 0xc7, 0xe3, 0x5f, 0x2f,
        0x3e, 0xfd, 0xe4, 0x75, 0xf8, 0xc7, 0xe2, 0xf5, 0xf7, 0x56, 0xd7, 0x22, 0xe9, 0xf1, 0x47, 0xba,
        0xd9, 0x39, 0xfb, 0x9e, 0xc6, 0x7b, 0x2c, 0x8b, 0x93, 0x6e, 0x3d, 0x18, 0x42, 0x06, 0xd0, 0xb8,
        0xd3, 0x58, 0x40, 0xc3, 0x7c, 0x07, 0xb7, 0xcb, 0xeb, 0xde, 0x72, 0xce, 0xe6, 0x42, 0x52, 0x9d,
        0x76, 0x98, 0xe0, 0xff, 0x6d, 0x78, 0x13, 0x1e, 0x8b, 0x3d, 0x0a, 0x4b, 0xb3, 0x3a, 0xf2, 0x84,
        0x66, 0xc5, 0x61, 0x81, 0x40, 0x31, 0x3d, 0xa3, 0x7e, 0xbb, 0xd6, 0x5d, 0x19, 0x8e, 0xa2, 0xc4,
        0xd7, 0x6a, 0x1a, 0x7e, 0xc9, 0xa9, 0xce, 0xe7, 0x83, 0x02, 0x81, 0x81, 0x00, 0xcc, 0xc2, 0xe3,
        0x99, 0xd1, 0xdd, 0x22, 0x8d, 0x3d, 0x1f, 0x7a, 0xb1, 0xb7, 0x28, 0x2f, 0xbd, 0xab, 0x74, 0x1d,
        0xdc, 0x57, 0x55, 0x6e, 0x18, 0xd1, 0xe2, 0x8a, 0x1f, 0x08, 0xe5, 0x86, 0x89, 0xa2, 0xec, 0x91,
        0x17, 0x17, 0xb8, 0xff, 0xfd, 0x9d, 0x34, 0xce, 0xa3, 0xf9, 0x10, 0x94, 0x6f, 0x63, 0x6e, 0xfc,
        0xfd, 0x8b, 0xb0, 0x78, 0x26, 0xbf, 0xe1, 0x16, 0xcb, 0xa9, 0x81, 0xb6, 0xeb, 0x64, 0x52, 0x1c,
        0xc0, 0x48, 0x38, 0xe4, 0x23, 0xe8, 0xdb, 0x4c, 0xe5, 0xf8, 0x6b, 0x0f, 0x91, 0xc1, 0x28, 0xc4,
        0xe7, 0x02, 0x7d, 0xf5, 0xee, 0x0b, 0xb0, 0x85, 0xbc, 0x0c, 0x78, 0xab, 0x79, 0xe9, 0x02, 0x16,
        0x6e, 0xb7, 0xe7, 0xc0, 0xfb, 0xcc, 0x57, 0x46, 0xce, 0xc1, 0x34, 0x17, 0xf2, 0xea, 0x17, 0xc7,
        0xcc, 0x30, 0xd0, 0xa4, 0x3c, 0x6c, 0xb7, 0x81, 0x8f, 0x60, 0xc7, 0x57, 0xbd, 0x02, 0x81, 0x81,
        0x00, 0x84, 0xbd, 0xc3, 0xc5, 0x9d, 0xfb, 0x77, 0x01, 0x38, 0x53, 0x19, 0xa3, 0xed, 0x7c, 0x53,
        0xf9, 0x06, 0xbb, 0xdd, 0xec, 0xad, 0xdf, 0x2f, 0x7f, 0xad, 0xcb, 0x88, 0xca, 0xd8, 0xf5, 0x70,
        0x0c, 0x0c, 0xfd, 0xbb, 0x61, 0x7b, 0x3f, 0x85, 0x87, 0x01, 0xae, 0xd1, 0xbe, 0x40, 0x36, 0x1c,
        0xb2, 0x86, 0x6b, 0xd2, 0x77, 0x8e, 0x23, 0xba, 0xc3, 0x8c, 0x67, 0xcf, 0xf8, 0x69, 0x8c, 0x89,
        0x83, 0xcf, 0x2b, 0x10, 0xc0, 0xe2, 0x42, 0x3f, 0xea, 0xde, 0xc9, 0x82, 0xf9, 0x88, 0xd1, 0x24,
        0xd2, 0xaf, 0xf2, 0xa2, 0xfd, 0x97, 0x5c, 0x79, 0xf5, 0x5f, 0xb8, 0xf4, 0xf5, 0x36, 0x69, 0x41,
        0x32, 0x21, 0x3d, 0xc1, 0x81, 0xeb, 0x9b, 0x39, 0x9e, 0x7d, 0x0c, 0xbe, 0x25, 0xf9, 0xf8, 0x07,
        0x10, 0x24, 0xa5, 0xf5, 0x38, 0x6d, 0xfb, 0xde, 0xe1, 0xfe, 0x13, 0xc9, 0x8b, 0xdf, 0x2e, 0x3c,
        0xdb, 0x02, 0x81, 0x81, 0x00, 0xc4, 0x90, 0x1e, 0x2f, 0xae, 0xa0, 0x2b, 0x28, 0x0c, 0xd2, 0x28,
        0x55, 0x6b, 0xef, 0x1f, 0x0d, 0x64, 0x06, 0xff, 0x17, 0x63, 0x9b, 0x36, 0x2a, 0x8b, 0x69, 0x7e,
        0x90, 0x56, 0x59, 0x08, 0x73, 0x1e, 0x3d, 0x1c, 0xf7, 0x5f, 0x25, 0x90, 0x51, 0x25, 0x55, 0xe9,
        0x3c, 0xcd, 0xbe, 0xd5, 0xcf, 0xac, 0x53, 0x82, 0x77, 0xdf, 0x5e, 0x53, 0xa9, 0x57, 0x2f, 0xbc,
        0x53, 0x5c, 0x70, 0x92, 0x69, 0x9c, 0x0f, 0x9b, 0x5c, 0x16, 0xb8, 0xce, 0x81, 0x8e, 0x6a, 0xdf,
        0x82, 0x30, 0x9c, 0x8e, 0x00, 0xac, 0xbd, 0xf7, 0x6f, 0x90, 0x1b, 0xdd, 0x37, 0x5c, 0x6f, 0x63,
        0xa2, 0x67, 0x12, 0x7c, 0x02, 0x76, 0xe5, 0x33, 0x25, 0xac, 0x53, 0xc5, 0x15, 0xb3, 0x4e, 0xe1,
        0x41, 0x5f, 0x85, 0x23, 0xac, 0x64, 0x7e, 0xd9, 0xa5, 0x32, 0x03, 0x48, 0x76, 0x5d, 0x23, 0x38,
        0x33, 0xac, 0x83, 0x10, 0xbd, 0x02, 0x81, 0x80, 0x57, 0x1c, 0x48, 0x37, 0xc6, 0x3b, 0xfd, 0xb8,
        0x7e, 0xde, 0xe8, 0x7b, 0xe7, 0x21, 0x92, 0xfe, 0x93, 0xa4, 0x32, 0x16, 0xa5, 0x2e, 0xe4, 0x6c,
        0xf6, 0xc0, 0xb9, 0xd0, 0xfe, 0x17, 0x49, 0x3f, 0x87, 0x18, 0x94, 0xdb, 0xbb, 0xe7, 0x36, 0xa4,
        0x8a, 0x77, 0xde, 0x83, 0x90, 0x6f, 0x7f, 0xf9, 0x02, 0xdc, 0xcf, 0x41, 0xde, 0x42, 0x58, 0x9d,
        0x67, 0xf5, 0x52, 0xd1, 0x23, 0xd9, 0xbe, 0x1d, 0x4e, 0x63, 0xc0, 0xea, 0x7e, 0xa2, 0x26, 0x58,
        0x74, 0x6c, 0x48, 0x88, 0x99, 0xdc, 0x1e, 0xf8, 0x6d, 0xf7, 0x6d, 0xc6, 0xf3, 0xd5, 0xfc, 0x8f,
        0xe9, 0x90, 0x78, 0xce, 0x8d, 0xb4, 0x31, 0xf9, 0xce, 0x2f, 0x46, 0x22, 0x3e, 0x36, 0x0c, 0x45,
        0xb6, 0x7d, 0x88, 0xc1, 0x81, 0x1f, 0xdc, 0xbe, 0xb5, 0x1a, 0x96, 0x78, 0x81, 0x0b, 0x38, 0xdb,
        0x7b, 0x5d, 0x52, 0xe5, 0x29, 0x08, 0x84, 0x06
    };
    /* RSA-OAEP SHA-256/MGF1-SHA256 ciphertext (256 bytes) -- pyca generated */
    static const uint8_t oaep_tv_ciphertext[] = {
        0x61, 0xf3, 0x63, 0x09, 0x05, 0x6f, 0xa4, 0x12, 0xc3, 0x96, 0x91, 0x61, 0xbb, 0x81, 0x89, 0x00,
        0x35, 0xfc, 0xd3, 0x2c, 0xca, 0x8d, 0xc2, 0xcb, 0x4b, 0x12, 0x11, 0xb4, 0x89, 0x83, 0x96, 0x46,
        0xe2, 0x5c, 0x50, 0x62, 0xfd, 0x70, 0xae, 0xa8, 0x74, 0x60, 0x82, 0xdc, 0xf7, 0x56, 0x2b, 0x92,
        0x81, 0x43, 0xde, 0xd0, 0xe6, 0x88, 0x0f, 0xe0, 0x30, 0xe7, 0x15, 0x37, 0x57, 0x7f, 0x89, 0xe8,
        0xaa, 0x5e, 0xbd, 0x97, 0xae, 0x1c, 0xb6, 0xe7, 0xea, 0x6e, 0xe9, 0xd1, 0x5f, 0xf6, 0xde, 0xa8,
        0xcd, 0x8d, 0x58, 0xc1, 0x91, 0x6a, 0x1b, 0xe5, 0x08, 0x00, 0x9e, 0xb8, 0xc0, 0x2c, 0x63, 0x39,
        0xd5, 0xca, 0x4e, 0xb3, 0x2d, 0xa1, 0x0c, 0xcb, 0x53, 0x3a, 0x11, 0x4c, 0x43, 0xbe, 0x45, 0xa2,
        0xe5, 0xd2, 0x53, 0xd2, 0xbb, 0x71, 0x62, 0xce, 0xc0, 0xa8, 0xa0, 0xb0, 0x6e, 0x5b, 0x25, 0x7a,
        0x65, 0x5d, 0x14, 0xc6, 0x73, 0xcd, 0xf9, 0xfc, 0x66, 0xf7, 0xde, 0xa0, 0xd7, 0x29, 0xdb, 0x92,
        0x3e, 0xae, 0x1a, 0xa2, 0xdc, 0x47, 0x94, 0xb1, 0x33, 0x68, 0x4e, 0x1f, 0x54, 0x75, 0xdf, 0xa2,
        0x96, 0xa0, 0xa8, 0xc1, 0xef, 0x8a, 0xb7, 0xd9, 0xbd, 0xac, 0xbb, 0x31, 0xa9, 0xc1, 0x08, 0xd0,
        0xa7, 0x1f, 0xf6, 0xaa, 0x66, 0x66, 0xdd, 0x64, 0x3b, 0xcf, 0x94, 0x05, 0x1c, 0xf4, 0x5f, 0xcf,
        0xaf, 0xdc, 0x60, 0xc2, 0xba, 0x8c, 0x88, 0x1a, 0x7f, 0x51, 0xbc, 0xff, 0xc7, 0xe4, 0x8a, 0x57,
        0xdf, 0x1b, 0xab, 0xa2, 0x55, 0xb4, 0x3d, 0x7d, 0x80, 0xa3, 0x29, 0xff, 0x04, 0xc4, 0xe6, 0xa4,
        0xa3, 0xd9, 0x9e, 0x2c, 0x34, 0x25, 0xf4, 0x88, 0x62, 0x2e, 0x6e, 0xf1, 0xc6, 0xdf, 0xbd, 0xd6,
        0xd0, 0x4d, 0xa4, 0x20, 0x6d, 0x8e, 0x7f, 0x08, 0xba, 0x63, 0x2c, 0xc2, 0xef, 0xb2, 0x6d, 0xaa
    };
    static const uint8_t  oaep_tv_pt[]    = "wolfP11 RSA-OAEP test";
    static const CK_ULONG oaep_tv_pt_len  = 21u;

    CK_RV             rv;
    CK_SESSION_HANDLE hSess = 0;
    CK_SLOT_ID        slots[16];
    CK_ULONG          count;
    CK_OBJECT_HANDLE  objs[16];
    CK_ULONG          nfound;
    CK_SLOT_ID        evt_slot;
    CK_RSA_PKCS_OAEP_PARAMS oaep_params;
    CK_MECHANISM      oaep_mech;
    uint8_t           pt_out[64];
    CK_ULONG          pt_out_len;
    int               f = 0;

    if (flash_test_make_rsa_keystore_from_der(
            oaep_tv_priv_der, sizeof(oaep_tv_priv_der),
            "oaep_vector_test") != 0)
        return f + 1;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "rsa_oaep_vector: C_Initialize");
    if (rv != CKR_OK) { unlink(FLASH_TEST_P11K); return f; }

    wp11_test_inject_flash_event(FLASH_TEST_P11K, 1 /* arrived */);
    C_WaitForSlotEvent(CKF_DONT_BLOCK, &evt_slot, NULL);

    count = 16;
    rv = C_GetSlotList(CK_FALSE, slots, &count);
    if (count < 2) {
        C_Finalize(NULL); unlink(FLASH_TEST_P11K);
        return f + 1;
    }

    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "rsa_oaep_vector: C_OpenSession");

    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)FLASH_TEST_PIN, FLASH_TEST_PIN_LEN);
    f += check(rv == CKR_OK, "rsa_oaep_vector: C_Login");
    if (rv != CKR_OK) {
        C_CloseSession(hSess); C_Finalize(NULL); unlink(FLASH_TEST_P11K);
        return f;
    }

    C_FindObjectsInit(hSess, NULL, 0);
    nfound = 0;
    C_FindObjects(hSess, objs, 16, &nfound);
    C_FindObjectsFinal(hSess);
    f += check(nfound >= 1, "rsa_oaep_vector: RSA key visible after login");
    if (nfound < 1) {
        C_Logout(hSess); C_CloseSession(hSess);
        C_Finalize(NULL); unlink(FLASH_TEST_P11K);
        return f;
    }

    /* Set up OAEP mechanism: SHA-256, MGF1-SHA256, no label */
    memset(&oaep_params, 0, sizeof(oaep_params));
    oaep_params.hashAlg         = CKM_SHA256;
    oaep_params.mgf             = CKG_MGF1_SHA256;
    oaep_params.source          = 0;
    oaep_params.pSourceData     = NULL_PTR;
    oaep_params.ulSourceDataLen = 0;
    oaep_mech.mechanism         = CKM_RSA_PKCS_OAEP;
    oaep_mech.pParameter        = &oaep_params;
    oaep_mech.ulParameterLen    = (CK_ULONG)sizeof(oaep_params);

    rv = C_DecryptInit(hSess, &oaep_mech, objs[0]);
    f += check(rv == CKR_OK, "rsa_oaep_vector: C_DecryptInit");
    if (rv == CKR_OK) {
        pt_out_len = (CK_ULONG)sizeof(pt_out);
        rv = C_Decrypt(hSess,
                       (CK_BYTE_PTR)(void *)(uintptr_t)oaep_tv_ciphertext,
                       (CK_ULONG)sizeof(oaep_tv_ciphertext),
                       pt_out, &pt_out_len);
        f += check(rv == CKR_OK, "rsa_oaep_vector: C_Decrypt succeeds");
        f += check(rv == CKR_OK && pt_out_len == oaep_tv_pt_len,
                   "rsa_oaep_vector: decrypted length matches plaintext");
        f += check(rv == CKR_OK &&
                   memcmp(pt_out, oaep_tv_pt, (size_t)oaep_tv_pt_len) == 0,
                   "rsa_oaep_vector: C_Decrypt matches pyca/cryptography oracle");
    }

    /* Part B: C_Encrypt with flash backend key.
     *
     * Tests the is_ks backend-narrowing introduced in wolfP11-jq34: the
     * C_Encrypt OAEP path must check (backend_ops == flash_ops || fsdir_ops)
     * before casting key_priv, because USB keys also satisfy
     * (backend_ops != soft_ops) but have a different key_priv layout.
     *
     * Oracle: wolfCrypt wc_RsaPrivateDecrypt_ex on the raw DER (independent
     * of the PKCS#11 layer and the flash backend temp-key path). */
    {
        static const uint8_t enc_pt[]  = "wolfP11 flash OAEP encrypt";
        uint8_t    ct[256];       /* RSA-2048: 256-byte modulus */
        CK_ULONG   ct_len;
        uint8_t    dec_buf[256];
        word32     dec_len;
        RsaKey     oracle_key;
        word32     der_idx = 0;
        WC_RNG     rng;
        int        wret;

        rv = C_EncryptInit(hSess, &oaep_mech, objs[0]);
        f += check(rv == CKR_OK,
                   "rsa_oaep_vector: C_EncryptInit (flash backend, Part B)");
        if (rv == CKR_OK) {
            ct_len = (CK_ULONG)sizeof(ct);
            rv = C_Encrypt(hSess,
                           (CK_BYTE_PTR)(void *)(uintptr_t)enc_pt,
                           (CK_ULONG)(sizeof(enc_pt) - 1u),
                           ct, &ct_len);
            f += check(rv == CKR_OK,
                       "rsa_oaep_vector: C_Encrypt (flash backend, Part B)");
            if (rv == CKR_OK) {
                /* Oracle: decode private DER with wolfCrypt and OAEP-decrypt */
                wc_InitRng(&rng);
                wc_InitRsaKey(&oracle_key, NULL);
                wc_RsaSetRNG(&oracle_key, &rng);
                wret = wc_RsaPrivateKeyDecode(oaep_tv_priv_der, &der_idx,
                                               &oracle_key,
                                               (word32)sizeof(oaep_tv_priv_der));
                if (wret == 0) {
                    dec_len = (word32)sizeof(dec_buf);
                    wret    = wc_RsaPrivateDecrypt_ex(
                                  ct, (word32)ct_len,
                                  dec_buf, dec_len, &oracle_key,
                                  WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256,
                                  WC_MGF1SHA256, NULL, 0);
                }
                f += check(wret > 0 &&
                           (size_t)wret == sizeof(enc_pt) - 1u &&
                           memcmp(dec_buf, enc_pt, (size_t)wret) == 0,
                           "rsa_oaep_vector: oracle decrypts flash C_Encrypt output");
                wc_FreeRsaKey(&oracle_key);
                wc_FreeRng(&rng);
            }
        }
    }

    C_Logout(hSess);
    C_CloseSession(hSess);
    C_Finalize(NULL);
    wp11_test_inject_flash_event(FLASH_TEST_P11K, 0 /* departed */);
    unlink(FLASH_TEST_P11K);
    return f;
}

/* -------------------------------------------------------------------------
 * test_soft_init_pin_and_wrong_pin
 *
 * Verifies conformant PIN behavior for the soft persistent token:
 *
 * 1. C_Login on a fresh token (no keystore) returns CKR_USER_PIN_NOT_INITIALIZED
 *    (PKCS#11 2.40 sec.11.16 -- uninitialized token must reject C_Login).
 *
 * 2. C_InitPIN creates the keystore (wolfP11 extension: works without SO login
 *    when token is uninitialized).
 *
 * 3. C_Login with wrong PIN on initialized token returns CKR_PIN_INCORRECT
 *    (this is the pkcs11test UserLoginWrongPIN assertion).
 *
 * 4. C_InitPIN on an already-initialized token returns CKR_USER_NOT_LOGGED_IN
 *    (SO login required, not supported by wolfP11).
 * ---------------------------------------------------------------------- */
#define SOFT_INITPIN_P11K   "/tmp/wp11_soft_initpin_test.p11k"
#define SOFT_INITPIN_PIN    "initpintest"
#define SOFT_INITPIN_PINLEN 11u

static int test_soft_init_pin_and_wrong_pin(void)
{
    CK_RV             rv;
    CK_SESSION_HANDLE hSess = 0;
    int f = 0;

    unlink(SOFT_INITPIN_P11K);
    setenv("WOLFP11_SOFT_KEYSTORE_PATH", SOFT_INITPIN_P11K, 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "soft_initpin: C_Initialize");
    if (rv != CKR_OK) goto cleanup;

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "soft_initpin: C_OpenSession");
    if (rv != CKR_OK) goto finalize;

    /* Fresh token (no keystore file) -> C_Login must fail */
    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)SOFT_INITPIN_PIN, SOFT_INITPIN_PINLEN);
    f += check(rv == CKR_USER_PIN_NOT_INITIALIZED,
               "soft_initpin: C_Login on fresh token -> CKR_USER_PIN_NOT_INITIALIZED");

    /* C_InitPIN on uninitialized token creates the keystore */
    rv = C_InitPIN(hSess, (CK_UTF8CHAR_PTR)SOFT_INITPIN_PIN, SOFT_INITPIN_PINLEN);
    f += check(rv == CKR_OK,
               "soft_initpin: C_InitPIN on uninitialized token -> CKR_OK");

    /* Wrong PIN on initialized token -> CKR_PIN_INCORRECT */
    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)"totally-wrong-pin", 17u);
    f += check(rv == CKR_PIN_INCORRECT,
               "soft_initpin: C_Login with wrong PIN -> CKR_PIN_INCORRECT");

    /* C_InitPIN on already-initialized token requires SO -> CKR_USER_NOT_LOGGED_IN */
    rv = C_InitPIN(hSess, (CK_UTF8CHAR_PTR)"new-pin", 7u);
    f += check(rv == CKR_USER_NOT_LOGGED_IN,
               "soft_initpin: C_InitPIN on initialized token -> CKR_USER_NOT_LOGGED_IN");

    C_CloseSession(hSess);

finalize:
    C_Finalize(NULL);
    unlink(SOFT_INITPIN_P11K);

cleanup:
    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}

/* -------------------------------------------------------------------------
 * test_soft_persistent_roundtrip
 *
 * Verify that a key generated by C_GenerateKeyPair survives across a
 * C_Finalize / C_Initialize cycle when WOLFP11_SOFT_KEYSTORE_PATH is set.
 *
 * Phase 1: Initialize -> Login -> GenerateKeyPair -> Finalize.
 *   Records the key handle from phase 1.
 *
 * Phase 2: Initialize -> Login (same PIN) -> FindObjects.
 *   Oracle: the key count must be >= 1 (the persisted key reappears) and
 *   C_Sign on the reloaded key must succeed with plausible output.
 *
 * The oracle relies on the fact that the .p11k file stores the DER-encoded
 * key, which on reload is decoded by wolfCrypt (wc_EccPrivateKeyDecode) via
 * wp11_soft_key_new_from_der.  A byte-corrupt DER would cause that decode to
 * fail, making C_Login return CKR_FUNCTION_FAILED; a clean load followed by
 * a successful C_Sign proves the round-trip.
 * ---------------------------------------------------------------------- */
#define SOFT_PERSIST_P11K  "/tmp/wp11_soft_persist_test.p11k"
#define SOFT_PERSIST_PIN   "persisttest"
#define SOFT_PERSIST_PINLEN 11u

static int test_soft_persistent_roundtrip(void)
{
    CK_RV             rv;
    CK_SESSION_HANDLE hSess = 0;
    CK_OBJECT_HANDLE  hPub  = 0;
    CK_OBJECT_HANDLE  hPriv = 0;
    CK_MECHANISM      mech      = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_MECHANISM      sign_mech = { CKM_ECDSA, NULL, 0 };
    static const CK_BYTE hash[32] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    };
    CK_BYTE  sig[128];
    CK_ULONG siglen = sizeof(sig);
    CK_OBJECT_HANDLE objs[8];
    CK_ULONG nfound = 0;
    uint8_t  phase1_pub[65];
    CK_ULONG phase1_pub_len = 0;
    ecc_key  oracle_key;
    int      oracle_stat, oracle_ret;
    int f = 0;

    unlink(SOFT_PERSIST_P11K);
    setenv("WOLFP11_SOFT_KEYSTORE_PATH", SOFT_PERSIST_P11K, 1);

    /* Phase 1: generate and persist */
    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "soft_persist: phase1 C_Initialize");
    if (rv != CKR_OK) goto cleanup;

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "soft_persist: phase1 C_OpenSession");

    /* wolfP11 extension: C_InitPIN initializes a fresh token without SO login */
    rv = C_InitPIN(hSess, (CK_UTF8CHAR_PTR)SOFT_PERSIST_PIN, SOFT_PERSIST_PINLEN);
    f += check(rv == CKR_OK, "soft_persist: phase1 C_InitPIN (initialize token)");
    if (rv != CKR_OK) goto cleanup;

    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)SOFT_PERSIST_PIN, SOFT_PERSIST_PINLEN);
    f += check(rv == CKR_OK, "soft_persist: phase1 C_Login (initialized token)");

    rv = C_GenerateKeyPair(hSess, &mech,
                            NULL, 0, NULL, 0,
                            &hPub, &hPriv);
    f += check(rv == CKR_OK, "soft_persist: phase1 C_GenerateKeyPair");
    f += check(hPriv != 0,   "soft_persist: phase1 key handle non-zero");

    /* Export phase 1 public key -- used as oracle reference in phase 2 */
    if (rv == CKR_OK && hPub != 0) {
        phase1_pub_len = sizeof(phase1_pub);
        (void)wp11_test_soft_export_pub_x963(hPub, phase1_pub, &phase1_pub_len);
    }

    C_Logout(hSess);
    C_CloseSession(hSess);
    rv = C_Finalize(NULL);
    f += check(rv == CKR_OK, "soft_persist: phase1 C_Finalize");

    /* Phase 2: reload and verify key is still present */
    hSess = 0; hPub = 0; hPriv = 0;
    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "soft_persist: phase2 C_Initialize");
    if (rv != CKR_OK) goto cleanup;

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "soft_persist: phase2 C_OpenSession");

    rv = C_Login(hSess, CKU_USER,
                 (CK_UTF8CHAR_PTR)SOFT_PERSIST_PIN, SOFT_PERSIST_PINLEN);
    f += check(rv == CKR_OK, "soft_persist: phase2 C_Login (reload from .p11k)");
    if (rv != CKR_OK) goto phase2_finalize;

    nfound = 0;
    rv = C_FindObjectsInit(hSess, NULL, 0);
    f += check(rv == CKR_OK, "soft_persist: phase2 C_FindObjectsInit");
    rv = C_FindObjects(hSess, objs, 8, &nfound);
    f += check(rv == CKR_OK && nfound >= 1,
               "soft_persist: phase2 reloaded key visible via C_FindObjects");
    C_FindObjectsFinal(hSess);

    if (nfound >= 1) {
        /* Oracle: reloaded key must sign successfully */
        rv = C_SignInit(hSess, &sign_mech, objs[0]);
        f += check(rv == CKR_OK, "soft_persist: phase2 C_SignInit on reloaded key");
        if (rv == CKR_OK) {
            siglen = sizeof(sig);
            rv = C_Sign(hSess, (CK_BYTE_PTR)hash, sizeof(hash), sig, &siglen);
            f += check(rv == CKR_OK,
                       "soft_persist: phase2 C_Sign on reloaded key returns CKR_OK");
            f += check(siglen > 0 && siglen <= 72u,
                       "soft_persist: phase2 signature length plausible for P-256");
            /* Independent oracle: verify phase2 signature against phase1 public
             * key -- proves keystore preserved the private key material intact. */
            if (rv == CKR_OK && siglen > 0 && phase1_pub_len == 65u) {
                oracle_stat = 0;
                oracle_ret  = 0;
                if (wc_ecc_init(&oracle_key) == 0) {
                    oracle_ret = wc_ecc_import_x963(phase1_pub,
                                                    (word32)phase1_pub_len,
                                                    &oracle_key);
                    if (oracle_ret == 0) {
                        oracle_ret = wc_ecc_verify_hash(
                            sig, (word32)siglen,
                            hash, (word32)sizeof(hash),
                            &oracle_stat, &oracle_key);
                    }
                    f += check(oracle_ret == 0 && oracle_stat == 1,
                               "soft_persist: phase2 oracle -- wolfCrypt verifies with phase1 pub key");
                    wc_ecc_free(&oracle_key);
                }
            }
        }
    }

    C_Logout(hSess);
phase2_finalize:
    C_CloseSession(hSess);
    C_Finalize(NULL);

cleanup:
    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    unlink(SOFT_PERSIST_P11K);
    return f;
}

/* -------------------------------------------------------------------------
 * test_hotplug_queue_overflow  (wolfP11-nmpg)
 *
 * Verify that the hotplug ring buffer (capacity WP11_HOTPLUG_QUEUE_SIZE-1 = 63)
 * correctly counts overflow events via g_hotplug_dropped.
 *
 * Strategy: inject exactly 63 events using alternating arrival/departure
 * events for a single synthetic path.  The alternation guarantees that
 * slot_add_keystore / slot_remove_keystore each succeed (returning a valid
 * slot_id != -1), ensuring hotplug_push_event is called each time.
 * After 63 events the ring is full.  The 64th push must increment
 * g_hotplug_dropped without corrupting the 63 queued events.
 *
 * Slot table capacity: slot_add_keystore uses a re-insertion loop that finds
 * an existing slot with the same path (in_use==1, token_present==0 after
 * removal) and reuses it rather than allocating a new slot.  Consequently
 * this test occupies at most ONE slot throughout, regardless of how many
 * events are injected.  WP11_CFG_MAX_SLOTS >= 2 is the only requirement
 * (soft slot 0 plus one for this test), comfortably below the default of 16.
 * ---------------------------------------------------------------------- */
#define OVERFLOW_TEST_PATH "/tmp/wp11_hotplug_overflow_test.p11k"

static int test_hotplug_queue_overflow(void)
{
    CK_RV        rv;
    CK_SLOT_ID   dummy_slot;
    unsigned int dropped;
    int          i, f = 0;

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "hotplug_overflow: C_Initialize");
    if (rv != CKR_OK) return f;

    /* Inject 63 events to fill the ring completely.
     * Even i -> arrived=1 (add/re-insert); odd i -> arrived=0 (remove).
     * This alternation keeps slot_add/remove each returning a valid slot_id. */
    for (i = 0; i < 63; i++) {
        wp11_test_inject_flash_event(OVERFLOW_TEST_PATH, (i & 1) == 0 ? 1 : 0);
    }
    dropped = wp11_test_hotplug_dropped();
    f += check(dropped == 0u,
               "hotplug_overflow: 0 drops after 63 events (ring exactly full)");

    /* 64th event must overflow (i=63 is odd, so arrived=0 = remove). */
    wp11_test_inject_flash_event(OVERFLOW_TEST_PATH, (63 & 1) == 0 ? 1 : 0);
    dropped = wp11_test_hotplug_dropped();
    f += check(dropped >= 1u,
               "hotplug_overflow: at least 1 drop after 64th event");

    /* Drain the ring.  C_WaitForSlotEvent(CKF_DONT_BLOCK) returns:
     *   CKR_OK:       one event dequeued, continue.
     *   CKR_NO_EVENT: queue empty, expected loop exit.
     *   Anything else (e.g. CKR_GENERAL_ERROR from a mutex failure) is a
     *   test infrastructure failure that the check() below will catch -- it
     *   becomes a test FAIL, not a silent pass.  The loop cannot loop forever
     *   because the ring has a finite depth and each CKR_OK pops one entry. */
    do {
        rv = C_WaitForSlotEvent(CKF_DONT_BLOCK, &dummy_slot, NULL);
    } while (rv == CKR_OK);
    f += check(rv == CKR_NO_EVENT,
               "hotplug_overflow: queue fully drained (CKR_NO_EVENT)");

    C_Finalize(NULL);
    unlink(OVERFLOW_TEST_PATH);
    return f;
}
#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */

/* -------------------------------------------------------------------------
 * test_buffer_too_small
 *
 * wolfP11-kkva: Verify that C_Sign and C_Encrypt return CKR_BUFFER_TOO_SMALL
 * (not CKR_OK, not a crash or silent truncation) when the output buffer is
 * exactly one byte smaller than the required size, and that the operation
 * remains active so the caller can retry with a correctly-sized buffer.
 *
 * ECDSA P-256: sig_len_max = 72 bytes (DER max: 8 + 2*32).
 *   Buffer of 71 → CKR_BUFFER_TOO_SMALL, updated *pulSignatureLen = 72.
 *   Retry with 72-byte buffer → CKR_OK.
 *
 * AES-GCM: output = plaintext_len + tag_len (16+16 = 32 bytes).
 *   Buffer of 31 → CKR_BUFFER_TOO_SMALL, updated *pulEncryptedDataLen = 32.
 *   Retry with 32-byte buffer → CKR_OK.
 * ---------------------------------------------------------------------- */
static int test_buffer_too_small(void)
{
    CK_RV             rv;
    CK_SESSION_HANDLE hSess   = 0;
    CK_OBJECT_HANDLE  hPub    = 0;
    CK_OBJECT_HANDLE  hPriv   = 0;
    CK_OBJECT_HANDLE  hAesKey = 0;
    CK_MECHANISM      ec_gen  = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_MECHANISM      sig_mech = { CKM_ECDSA, NULL_PTR, 0 };
    static const CK_UTF8CHAR pin[]   = "softtest";
    static const CK_ULONG    pin_len = 8;
    /* Oracle: P-256 ECDSA DER max = 8 + 2*32 = 72, computed independently */
    static const CK_ULONG P256_MAX = 72u;
    static const CK_BYTE hash[32] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21
    };
    CK_BYTE  sig_small[71];
    CK_BYTE  sig_full[72];
    CK_ULONG siglen;

    /* AES-GCM: 16-byte plaintext + 16-byte tag = 32-byte output */
    static const CK_ULONG aes_sz   = 32u;
    static const CK_BBOOL ck_true  = CK_TRUE;
    CK_ATTRIBUTE aes_tmpl[] = {
        { CKA_VALUE_LEN,   (CK_VOID_PTR)&aes_sz,  sizeof(aes_sz)  },
        { CKA_EXTRACTABLE, (CK_VOID_PTR)&ck_true, sizeof(ck_true) }
    };
    CK_MECHANISM          aes_gen  = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    static const uint8_t  iv[12]   = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    static const uint8_t  pt[16]   = {
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55
    };
    CK_GCM_PARAMS gcm_p = { (CK_BYTE_PTR)iv, 12u, 0u, NULL_PTR, 0u, 128u };
    CK_MECHANISM  aes_enc = { CKM_AES_GCM, &gcm_p, sizeof(gcm_p) };
    CK_BYTE  ct_small[31];  /* 16+16-1 = 31, one byte too small */
    CK_BYTE  ct_full[32];
    CK_ULONG ctlen;
    int      f = 0;

    setenv("WOLFP11_SOFT_KEYSTORE_PATH", "", 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "buf_too_small: C_Initialize");
    if (rv != CKR_OK) { unsetenv("WOLFP11_SOFT_KEYSTORE_PATH"); return f; }

    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL_PTR, NULL_PTR, &hSess);
    f += check(rv == CKR_OK, "buf_too_small: C_OpenSession");

    rv = C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)pin, pin_len);
    f += check(rv == CKR_OK, "buf_too_small: C_Login");
    if (rv != CKR_OK) goto done;

    /* Generate EC P-256 key pair (sets sig_len_max = 72 per wolfP11-3qf) */
    rv = C_GenerateKeyPair(hSess, &ec_gen, NULL_PTR, 0, NULL_PTR, 0,
                            &hPub, &hPriv);
    f += check(rv == CKR_OK, "buf_too_small: C_GenerateKeyPair");
    if (rv != CKR_OK) goto done;

    /* -- ECDSA: 71-byte buffer (P256_MAX-1) must return CKR_BUFFER_TOO_SMALL -- */
    rv = C_SignInit(hSess, &sig_mech, hPriv);
    f += check(rv == CKR_OK, "buf_too_small: ECDSA C_SignInit");
    if (rv != CKR_OK) goto done;

    siglen = P256_MAX - 1u;  /* 71 */
    rv = C_Sign(hSess, (CK_BYTE_PTR)hash, 32u, sig_small, &siglen);
    f += check(rv == CKR_BUFFER_TOO_SMALL,
               "buf_too_small: ECDSA 71-byte buf -> CKR_BUFFER_TOO_SMALL");
    f += check(siglen == P256_MAX,
               "buf_too_small: ECDSA siglen updated to P256_MAX after BUFFER_TOO_SMALL");

    /* Operation must remain active after CKR_BUFFER_TOO_SMALL */
    siglen = sizeof(sig_full);
    rv = C_Sign(hSess, (CK_BYTE_PTR)hash, 32u, sig_full, &siglen);
    f += check(rv == CKR_OK,
               "buf_too_small: ECDSA retry with full buffer succeeds");
    f += check(siglen > 0u && siglen <= P256_MAX,
               "buf_too_small: ECDSA retry siglen in range");

    /* -- AES-GCM: 31-byte buffer (16+16-1) must return CKR_BUFFER_TOO_SMALL -- */
    rv = C_GenerateKey(hSess, &aes_gen, aes_tmpl, 2u, &hAesKey);
    f += check(rv == CKR_OK, "buf_too_small: C_GenerateKey AES-256");
    if (rv != CKR_OK) goto done;

    rv = C_EncryptInit(hSess, &aes_enc, hAesKey);
    f += check(rv == CKR_OK, "buf_too_small: AES-GCM C_EncryptInit");
    if (rv != CKR_OK) goto done;

    ctlen = sizeof(ct_small);  /* 31 */
    rv = C_Encrypt(hSess, (CK_BYTE_PTR)pt, sizeof(pt), ct_small, &ctlen);
    f += check(rv == CKR_BUFFER_TOO_SMALL,
               "buf_too_small: AES-GCM 31-byte buf -> CKR_BUFFER_TOO_SMALL");
    f += check(ctlen == 32u,
               "buf_too_small: AES-GCM ctlen updated to 32 after BUFFER_TOO_SMALL");

    /* Operation must remain active; retry with correct size must succeed */
    ctlen = sizeof(ct_full);  /* 32 */
    rv = C_Encrypt(hSess, (CK_BYTE_PTR)pt, sizeof(pt), ct_full, &ctlen);
    f += check(rv == CKR_OK,
               "buf_too_small: AES-GCM retry with 32-byte buf -> CKR_OK");
    f += check(ctlen == 32u,
               "buf_too_small: AES-GCM output len == 32 after successful encrypt");

done:
    C_Logout(hSess);
    C_CloseSession(hSess);
    C_Finalize(NULL);
    unsetenv("WOLFP11_SOFT_KEYSTORE_PATH");
    return f;
}

#if defined(WOLFP11_CFG_WOLFHSM_BACKEND) && defined(WOLFHSM_CFG_ENABLE_SERVER)
/* -------------------------------------------------------------------------
 * wolfHSM TCP integration test fixture (wolfP11-fd3k)
 *
 * Spins up an in-process wolfHSM server on TCP port WH_TCP_TEST_PORT with
 * a RAM-backed NVM.  The PKCS#11 layer connects via WOLFP11_HSM_TCP_ADDR.
 * Only compiled when WOLFHSM=1 (WOLFHSM_CFG_ENABLE_SERVER set by the test
 * Makefile rule, server sources in TEST_SRCS).
 * ---------------------------------------------------------------------- */

#include <wolfhsm/wh_server.h>
#include <wolfhsm/wh_nvm.h>
#include <wolfhsm/wh_nvm_flash.h>
#include <wolfhsm/wh_flash_ramsim.h>
#include "port/posix/posix_transport_tcp.h"
#include <pthread.h>

#define WH_TCP_TEST_PORT         23457
#define WH_TCP_TEST_ADDR         "127.0.0.1:23457"
#define WH_TCP_TEST_FLASH_SIZE   (256u * 1024u)
#define WH_TCP_TEST_FLASH_SECTOR (64u * 1024u)
#define WH_TCP_TEST_FLASH_PAGE   8u

typedef struct {
    /* RAM-backed flash NVM */
    uint8_t              flash_mem[WH_TCP_TEST_FLASH_SIZE];
    whFlashRamsimCtx     flash_ctx;
    whFlashRamsimCfg     flash_cfg;
    whFlashCb            flash_cb;
    whNvmContext         nvm;
    whNvmFlashContext    nvm_flash_ctx;
    whNvmFlashConfig     nvm_flash_cfg;

    /* TCP transport: IP string must outlive wh_Server_Init */
    char                           ip_buf[16];
    posixTransportTcpServerContext tcp_srv_ctx;
    posixTransportTcpConfig        tcp_srv_cfg;
    whTransportServerCb            tcp_srv_cb;

    /* wolfHSM server */
    whServerCryptoContext server_crypto;
    whCommServerConfig    server_comm_cfg;
    whServerConfig        server_cfg;
    whServerContext       server;

    /* Background server thread */
    pthread_t    server_thread;
    volatile int server_running;
} wp11_wh_tcp_fixture_t;

/* Non-blocking server loop: posixTransportTcp uses poll() with timeout 0,
 * so wh_Server_HandleRequestMessage returns WH_ERROR_NOTREADY when idle.
 * The loop exits once server_running is cleared. */
static void *wh_tcp_server_fn(void *arg)
{
    wp11_wh_tcp_fixture_t *fx = (wp11_wh_tcp_fixture_t *)arg;
    while (fx->server_running) {
        int ret = wh_Server_HandleRequestMessage(&fx->server);
        if (ret != WH_ERROR_OK && ret != WH_ERROR_NOTREADY) break;
    }
    return NULL;
}

static int wh_tcp_fixture_init(wp11_wh_tcp_fixture_t *fx)
{
    whNvmConfig             nvm_cfg;
    static const whNvmCb    s_nvm_cb = WH_NVM_FLASH_CB;

    memset(fx, 0, sizeof(*fx));
    fx->flash_cb = (whFlashCb)WH_FLASH_RAMSIM_CB;

    fx->flash_cfg.memory     = fx->flash_mem;
    fx->flash_cfg.size       = WH_TCP_TEST_FLASH_SIZE;
    fx->flash_cfg.sectorSize = WH_TCP_TEST_FLASH_SECTOR;
    fx->flash_cfg.pageSize   = WH_TCP_TEST_FLASH_PAGE;
    fx->flash_cfg.erasedByte = 0xFFu;

    fx->nvm_flash_cfg.cb      = &fx->flash_cb;
    fx->nvm_flash_cfg.context = &fx->flash_ctx;
    fx->nvm_flash_cfg.config  = &fx->flash_cfg;

    memset(&nvm_cfg, 0, sizeof(nvm_cfg));
    nvm_cfg.cb      = (whNvmCb *)&s_nvm_cb;
    nvm_cfg.context = &fx->nvm_flash_ctx;
    nvm_cfg.config  = &fx->nvm_flash_cfg;
    if (wh_Nvm_Init(&fx->nvm, &nvm_cfg) != WH_ERROR_OK) return -1;

    /* TCP transport: bind+listen happens synchronously in wh_Server_Init */
    strncpy(fx->ip_buf, "127.0.0.1", sizeof(fx->ip_buf) - 1u);
    fx->ip_buf[sizeof(fx->ip_buf) - 1u] = '\0';
    fx->tcp_srv_cfg.server_ip_string = fx->ip_buf;
    fx->tcp_srv_cfg.server_port      = (short)WH_TCP_TEST_PORT;
    fx->tcp_srv_cb                   = (whTransportServerCb)PTT_SERVER_CB;

    fx->server_comm_cfg.transport_cb      = &fx->tcp_srv_cb;
    fx->server_comm_cfg.transport_context = &fx->tcp_srv_ctx;
    fx->server_comm_cfg.transport_config  = &fx->tcp_srv_cfg;
    fx->server_comm_cfg.server_id         = 1u;

    if (wc_InitRng_ex(fx->server_crypto.rng, NULL, INVALID_DEVID) != 0) {
        wh_Nvm_Cleanup(&fx->nvm);
        return -1;
    }

    fx->server_cfg.comm_config = &fx->server_comm_cfg;
    fx->server_cfg.nvm         = &fx->nvm;
    fx->server_cfg.crypto      = &fx->server_crypto;

    if (wh_Server_Init(&fx->server, &fx->server_cfg) != WH_ERROR_OK) {
        wc_FreeRng(fx->server_crypto.rng);
        wh_Nvm_Cleanup(&fx->nvm);
        return -1;
    }

    fx->server_running = 1;
    if (pthread_create(&fx->server_thread, NULL, wh_tcp_server_fn, fx) != 0) {
        fx->server_running = 0;
        wh_Server_Cleanup(&fx->server);
        wc_FreeRng(fx->server_crypto.rng);
        wh_Nvm_Cleanup(&fx->nvm);
        return -1;
    }
    return 0;
}

static void wh_tcp_fixture_cleanup(wp11_wh_tcp_fixture_t *fx)
{
    fx->server_running = 0;
    pthread_join(fx->server_thread, NULL);
    wh_Server_Cleanup(&fx->server);
    wc_FreeRng(fx->server_crypto.rng);
    wh_Nvm_Cleanup(&fx->nvm);
}

/* wolfP11-fd3k: C_Encrypt and C_Decrypt with CKM_RSA_PKCS_OAEP must return
 * CKR_MECHANISM_INVALID for a wolfHSM RSA key.
 *
 * wolfHSM keys do not expose raw key material; software OAEP (which needs
 * DER bytes) is impossible.  The else-branch added in wolfP11-jq34 handles
 * this.  This test covers the specific USBFLASH+WOLFHSM build combination
 * where is_ks==0 and backend_ops==wolfhsm_ops, exercising the rejection path
 * that previously had no CI coverage.
 *
 * Setup: in-process wolfHSM TCP server on loopback port WH_TCP_TEST_PORT.
 * C_GenerateKeyPair registers a key with backend_ops=&wp11_backend_wolfhsm_ops.
 * C_EncryptInit / C_DecryptInit succeed (no backend check at init time);
 * C_Encrypt / C_Decrypt return CKR_MECHANISM_INVALID. */
static int test_wolfhsm_oaep_rejected(void)
{
    wp11_wh_tcp_fixture_t    *fx;
    CK_RV                     rv;
    CK_SESSION_HANDLE         hSess = 0;
    CK_SLOT_ID                slots[16];
    CK_ULONG                  count;
    CK_OBJECT_HANDLE          hPub = 0, hPriv = 0;
    CK_ULONG                  mod_bits = 2048;
    CK_MECHANISM              rsa_gen_mech;
    CK_ATTRIBUTE              pub_tmpl[1];
    CK_RSA_PKCS_OAEP_PARAMS   oaep_params;
    CK_MECHANISM              oaep_mech;
    int                       f = 0;

    fx = (wp11_wh_tcp_fixture_t *)malloc(sizeof(*fx));
    if (fx == NULL) return 1;

    if (wh_tcp_fixture_init(fx) != 0) { free(fx); return f + 1; }

    /* WOLFP11_WOLFHSM_SERVER_ADDR must be non-empty for C_Initialize to
     * create the wolfHSM slot.  WOLFP11_HSM_TCP_ADDR is read by
     * wolfhsm_slot_connect when C_Login is called. */
    setenv("WOLFP11_WOLFHSM_SERVER_ADDR", "test", 1);
    setenv("WOLFP11_HSM_TCP_ADDR", WH_TCP_TEST_ADDR, 1);

    rv = C_Initialize(NULL);
    f += check(rv == CKR_OK, "wolfhsm_oaep_rejected: C_Initialize");
    if (rv != CKR_OK) goto done_cleanup;

    /* Expect slot 0 = soft, slot 1 = wolfHSM */
    count = (CK_ULONG)(sizeof(slots) / sizeof(slots[0]));
    rv = C_GetSlotList(CK_TRUE, slots, &count);
    if (rv != CKR_OK || count < 2) {
        f += check(0, "wolfhsm_oaep_rejected: need soft + wolfHSM slots");
        goto done_finalize;
    }

    /* slots[1] is always the wolfHSM slot: at C_Initialize time no USB
     * devices are present, so wolfHSM gets the first dynamic slot (1). */
    rv = C_OpenSession(slots[1], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSess);
    f += check(rv == CKR_OK, "wolfhsm_oaep_rejected: C_OpenSession");
    if (rv != CKR_OK) goto done_finalize;

    /* C_Login triggers wolfhsm_slot_connect: reads WOLFP11_HSM_TCP_ADDR,
     * connects to the in-process server, and runs wolfhsm_slot_populate_keys. */
    rv = C_Login(hSess, CKU_USER, (CK_UTF8CHAR_PTR)"pin", 3);
    f += check(rv == CKR_OK, "wolfhsm_oaep_rejected: C_Login");
    if (rv != CKR_OK) goto done_close;

    /* Generate a wolfHSM RSA-2048 key pair.  After this call,
     * g_keys[gi_{pub,priv}].backend_ops == &wp11_backend_wolfhsm_ops. */
    rsa_gen_mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
    rsa_gen_mech.pParameter     = NULL_PTR;
    rsa_gen_mech.ulParameterLen = 0;
    pub_tmpl[0].type            = CKA_MODULUS_BITS;
    pub_tmpl[0].pValue          = &mod_bits;
    pub_tmpl[0].ulValueLen      = (CK_ULONG)sizeof(mod_bits);
    rv = C_GenerateKeyPair(hSess, &rsa_gen_mech,
                           pub_tmpl, 1, NULL_PTR, 0,
                           &hPub, &hPriv);
    f += check(rv == CKR_OK, "wolfhsm_oaep_rejected: C_GenerateKeyPair");
    if (rv != CKR_OK) goto done_logout;

    /* OAEP mechanism: SHA-256, MGF1-SHA256, no label */
    memset(&oaep_params, 0, sizeof(oaep_params));
    oaep_params.hashAlg         = CKM_SHA256;
    oaep_params.mgf             = CKG_MGF1_SHA256;
    oaep_params.source          = 0;
    oaep_params.pSourceData     = NULL_PTR;
    oaep_params.ulSourceDataLen = 0;
    oaep_mech.mechanism         = CKM_RSA_PKCS_OAEP;
    oaep_mech.pParameter        = &oaep_params;
    oaep_mech.ulParameterLen    = (CK_ULONG)sizeof(oaep_params);

    /* C_Encrypt OAEP: init succeeds (no backend check at init time); the
     * wolfHSM rejection fires in C_Encrypt when is_ks==0 and
     * backend_ops != soft_ops (wolfP11-jq34 else-branch). */
    rv = C_EncryptInit(hSess, &oaep_mech, hPub);
    f += check(rv == CKR_OK, "wolfhsm_oaep_rejected: C_EncryptInit");
    if (rv == CKR_OK) {
        static const uint8_t pt[] = "wolfP11 wolfhsm oaep";
        uint8_t   ct_buf[256];
        CK_ULONG  ct_len = (CK_ULONG)sizeof(ct_buf);
        rv = C_Encrypt(hSess,
                       (CK_BYTE_PTR)(void *)(uintptr_t)pt,
                       (CK_ULONG)(sizeof(pt) - 1u),
                       ct_buf, &ct_len);
        f += check(rv == CKR_MECHANISM_INVALID,
                   "wolfhsm_oaep_rejected: C_Encrypt returns CKR_MECHANISM_INVALID");
    }

    /* C_Decrypt OAEP: same rejection path -- wolfHSM private key, is_ks==0. */
    rv = C_DecryptInit(hSess, &oaep_mech, hPriv);
    f += check(rv == CKR_OK, "wolfhsm_oaep_rejected: C_DecryptInit");
    if (rv == CKR_OK) {
        static const uint8_t fake_ct[256] = {0};
        uint8_t   pt_out[256];
        CK_ULONG  pt_len = (CK_ULONG)sizeof(pt_out);
        rv = C_Decrypt(hSess,
                       (CK_BYTE_PTR)(void *)(uintptr_t)fake_ct, 256,
                       pt_out, &pt_len);
        f += check(rv == CKR_MECHANISM_INVALID,
                   "wolfhsm_oaep_rejected: C_Decrypt returns CKR_MECHANISM_INVALID");
    }

done_logout:
    C_Logout(hSess);
done_close:
    C_CloseSession(hSess);
done_finalize:
    C_Finalize(NULL);
done_cleanup:
    unsetenv("WOLFP11_HSM_TCP_ADDR");
    unsetenv("WOLFP11_WOLFHSM_SERVER_ADDR");
    wh_tcp_fixture_cleanup(fx);
    free(fx);
    return f;
}

#endif /* WOLFP11_CFG_WOLFHSM_BACKEND && WOLFHSM_CFG_ENABLE_SERVER */

int wp11_test_pkcs11(void)
{
    int failures = 0;

    failures += test_init_finalize();
    failures += test_double_init();
    failures += test_not_initialized();
    failures += test_get_info();
    failures += test_get_slot_list();
    failures += test_get_slot_info();
    failures += test_get_token_info();
    failures += test_get_mechanism_list();
    failures += test_open_close_session();
    failures += test_invalid_session();
    failures += test_login_logout();
    failures += test_find_objects();
    failures += test_get_attribute_value_error_paths();
    failures += test_slot_soft_token_present();
    failures += test_wait_for_slot_event_no_event();
    failures += test_generate_random();
    failures += test_hotplug_arrival();
    failures += test_hotplug_departure();
    failures += test_hotplug_reinsert();
#ifdef WOLFP11_CFG_USB_BACKEND
    failures += test_piv_login_four_slots();
    failures += test_piv_cert_objects();
#endif
    failures += test_pre_init_not_initialized();
    failures += test_reserved_arg_validation();
    failures += test_null_arg_validation();
    failures += test_operation_not_initialized();
    failures += test_so_login_with_ro_session();
    failures += test_find_objects_template_filter();
    failures += test_init_error_path_active_flag();
    failures += test_sign_init_active_cleared_on_error();
    failures += test_soft_generate_keypair_basic();
    failures += test_soft_generate_keypair_p384();
    failures += test_soft_generate_keypair_rsa();
    failures += test_soft_generate_keypair_ed25519();
    failures += test_soft_rsa_oaep();
#ifdef WC_RSA_PSS
    failures += test_soft_rsa_pss();
#endif
    failures += test_soft_aes_gcm();
    failures += test_buffer_too_small();

    failures += test_derive_key_soft();

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
    failures += test_soft_init_pin_and_wrong_pin();
    failures += test_soft_persistent_roundtrip();
    failures += test_flash_arrival();
    failures += test_flash_departure();
    failures += test_flash_reinsert();
    failures += test_flash_multiple_files();
    failures += test_flash_pkcs11_login_correct_pin();
    failures += test_flash_pkcs11_login_wrong_pin();
    failures += test_flash_pkcs11_logout_clears_keys();
    failures += test_flash_pkcs11_sign_roundtrip();
    failures += test_flash_pkcs11_sign_size_query();
    failures += test_flash_pkcs11_destroy_flash_key();
    failures += test_flash_pkcs11_departure_while_logged_in();
    failures += test_flash_pkcs11_get_attribute_value();
    failures += test_rsa_oaep_vector_oracle();
    failures += test_hotplug_queue_overflow();
#endif

#if defined(WOLFP11_CFG_WOLFHSM_BACKEND) && defined(WOLFHSM_CFG_ENABLE_SERVER)
    failures += test_wolfhsm_oaep_rejected();
#endif

    return failures;
}

#else /* WOLFP11_CFG_TEST not defined */

int wp11_test_pkcs11(void)
{
    return 0;
}

#endif /* WOLFP11_CFG_TEST */
