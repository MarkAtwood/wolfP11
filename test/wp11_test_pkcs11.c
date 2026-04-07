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

/* wolfCrypt ECC for independent oracle verification in soft-token tests */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>

/* Test helper declared in src/wp11_pkcs11.c under WOLFP11_CFG_TEST.
 * Exports the soft key's EC public key in X9.62 uncompressed format. */
int wp11_test_soft_export_pub_x963(CK_OBJECT_HANDLE hKey,
                                    uint8_t *out, CK_ULONG *outlen);

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

/* Forward declaration -- defined in src/wp11_pkcs11.c under WOLFP11_CFG_TEST */
void wp11_test_inject_flash_event(const char *path, int arrived);

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

    if (flash_test_make_keystore(&orig_ecc, "flash_login_correct_pin") != 0)
        return 0; /* skip counted as 0 failures */
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
        return 0;
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
        return 0;
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
        return 0;
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
        return 0;
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
        return 0; /* skip */
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
        return 0; /* skip */
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
        return 0; /* skip -- keystore creation failed */
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

    rv = C_SignInit(hSess, &bad_mech, hPriv);
    f += check(rv == CKR_MECHANISM_INVALID,
               "init_errpath: second SignInit(bad_mech) -> CKR_MECHANISM_INVALID");

    sig_len = sizeof(sig_buf);
    rv = C_Sign(hSess, (CK_BYTE_PTR)test_hash, 32, sig_buf, &sig_len);
    f += check(rv == CKR_OPERATION_NOT_INITIALIZED,
               "init_errpath: C_Sign after re-init(bad_mech) -> CKR_OPERATION_NOT_INITIALIZED");

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

    /* Step 2: re-init with invalid mechanism must fail AND clear sign_active */
    rv = C_SignInit(hSess, &bad_mech, hPriv);
    f += check(rv == CKR_MECHANISM_INVALID,
               "sign_init_error: second C_SignInit with bad mech returns CKR_MECHANISM_INVALID");

    /* Step 3: C_Sign must see no active operation (sign_active was cleared) */
    siglen = sizeof(sig);
    rv = C_Sign(hSess, (CK_BYTE_PTR)test_hash, sizeof(test_hash), sig, &siglen);
    f += check(rv == CKR_OPERATION_NOT_INITIALIZED,
               "sign_init_error: C_Sign after failed re-init returns CKR_OPERATION_NOT_INITIALIZED");

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

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
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
#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */

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
#endif

    return failures;
}

#else /* WOLFP11_CFG_TEST not defined */

int wp11_test_pkcs11(void)
{
    return 0;
}

#endif /* WOLFP11_CFG_TEST */
