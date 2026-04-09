/* wp11_test_openpgp.c -- OpenPGP card protocol APDU tests
 * Reference: OpenPGP card application spec v3.4 (gnupg.org)
 * Test vectors: openpgp_apdu.json derived from spec Sections 7.2.1, 7.2.2, 7.2.6, 7.2.10
 */

#include "wp11_test_openpgp.h"

#ifdef WOLFP11_CFG_TEST

#include "wolfp11/wp11_proto_openpgp.h"
#include "wolfp11/wp11_ccid.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Test helper
 * ---------------------------------------------------------------------- */

static int check(int pass, const char *label)
{
    printf("%s: %s\n", pass ? "PASS" : "FAIL", label);
    return pass ? 0 : 1;
}

/* -------------------------------------------------------------------------
 * CCID frame constants (must match wp11_ccid.c internals)
 * ---------------------------------------------------------------------- */

#define CCID_HEADER_LEN         10
#define CCID_MSG_RDR_TO_PC_DATABLOCK 0x80u

/* -------------------------------------------------------------------------
 * Mock state: captures the APDU bytes sent by the protocol layer and
 * returns a programmable synthetic CCID response frame.
 * ---------------------------------------------------------------------- */

typedef struct {
    /* captured outgoing APDU (stripped of CCID header) */
    uint8_t  apdu[512];
    size_t   apdu_len;

    /* response payload the mock should return (APDU data + SW, no header) */
    uint8_t  resp_payload[512];
    size_t   resp_payload_len;
} mock_state_t;

static int mock_transport(void          *userdata,
                           const uint8_t *out, size_t  outlen,
                           uint8_t       *in,  size_t *inlen)
{
    mock_state_t *st = (mock_state_t *)userdata;
    size_t        apdu_len;
    size_t        frame_in_len;

    /* The outgoing frame is CCID_HEADER_LEN bytes of header + raw APDU. */
    if (outlen < (size_t)CCID_HEADER_LEN) {
        return -1;
    }
    apdu_len = outlen - (size_t)CCID_HEADER_LEN;
    if (apdu_len > sizeof(st->apdu)) {
        return -1;
    }

    memcpy(st->apdu, out + CCID_HEADER_LEN, apdu_len);
    st->apdu_len = apdu_len;

    /* Build a valid RDR_to_PC_DataBlock frame around resp_payload. */
    frame_in_len = (size_t)CCID_HEADER_LEN + st->resp_payload_len;
    if (frame_in_len > *inlen) {
        return -1;
    }

    memset(in, 0, frame_in_len);
    in[0] = CCID_MSG_RDR_TO_PC_DATABLOCK;  /* bMessageType */
    /* dwLength (little-endian) */
    in[1] = (uint8_t)(st->resp_payload_len        & 0xFFu);
    in[2] = (uint8_t)((st->resp_payload_len >>  8) & 0xFFu);
    in[3] = (uint8_t)((st->resp_payload_len >> 16) & 0xFFu);
    in[4] = (uint8_t)((st->resp_payload_len >> 24) & 0xFFu);
    in[5] = 0x00u;             /* bSlot */
    in[6] = out[6];            /* bSeq: mirror sequence number from request */
    in[7] = 0x00u;             /* bStatus: ok */
    in[8] = 0x00u;             /* bError */
    in[9] = 0x00u;             /* bChainParameter */
    memcpy(in + CCID_HEADER_LEN, st->resp_payload, st->resp_payload_len);

    *inlen = frame_in_len;
    return 0;
}

/* -------------------------------------------------------------------------
 * Helper: set the mock response to a bare SW word
 * ---------------------------------------------------------------------- */

static void set_sw_response(mock_state_t *st, uint8_t sw1, uint8_t sw2)
{
    st->resp_payload[0]  = sw1;
    st->resp_payload[1]  = sw2;
    st->resp_payload_len = 2u;
}

/* -------------------------------------------------------------------------
 * Helper: open a mock ccid context
 * ---------------------------------------------------------------------- */

static wp11_ccid_ctx_t *open_mock(mock_state_t *st)
{
    wp11_ccid_ctx_t *ccid = NULL;
    int rc = wp11_ccid_open_mock(mock_transport, st, &ccid);
    if (rc != WP11_CCID_OK) {
        return NULL;
    }
    return ccid;
}

/* -------------------------------------------------------------------------
 * Test 1: vector_file_nonempty
 * Open test/vectors/openpgp_apdu.json, assert it exists and has content.
 *
 * The JSON file is a human-readable spec reference, not a machine-driven
 * fixture (wolfP11-7fr). The test oracle is the hardcoded hex in this file.
 * We verify the file exists and is non-empty to catch accidental deletion.
 * ---------------------------------------------------------------------- */

static int test_vector_file_nonempty(void)
{
    FILE  *f;
    long   size;
    int    pass;

    f = fopen("test/vectors/openpgp_apdu.json", "r");
    if (f == NULL) {
        return check(0, "vector_file_nonempty");
    }

    fseek(f, 0L, SEEK_END);
    size = ftell(f);
    fclose(f);

    pass = (size > 0L);
    return check(pass, "vector_file_nonempty");
}

/* -------------------------------------------------------------------------
 * Test 2: select_aid_apdu
 * Verify the 11-byte SELECT AID APDU matches the spec vector.
 * ---------------------------------------------------------------------- */

static int test_select_aid_apdu(void)
{
    static const uint8_t expected[] = {
        0x00u, 0xA4u, 0x04u, 0x00u, 0x06u,
        0xD2u, 0x76u, 0x00u, 0x01u, 0x24u, 0x01u
    };
    mock_state_t     st;
    wp11_ccid_ctx_t *ccid;
    int              rc;
    int              pass;

    memset(&st, 0, sizeof(st));
    set_sw_response(&st, 0x90u, 0x00u);

    ccid = open_mock(&st);
    if (ccid == NULL) {
        return check(0, "select_aid_apdu");
    }

    rc = wp11_openpgp_select(ccid);
    wp11_ccid_close(ccid);

    pass = (rc == WP11_OPENPGP_OK)
        && (st.apdu_len == sizeof(expected))
        && (memcmp(st.apdu, expected, sizeof(expected)) == 0);

    return check(pass, "select_aid_apdu");
}

/* -------------------------------------------------------------------------
 * Test 3: verify_pw1_sign_apdu
 * VERIFY PW1 with mode=0x81, password "123456".
 * ---------------------------------------------------------------------- */

static int test_verify_pw1_sign_apdu(void)
{
    static const uint8_t pw[]       = { 0x31u, 0x32u, 0x33u, 0x34u, 0x35u, 0x36u };
    mock_state_t     st;
    wp11_ccid_ctx_t *ccid;
    int              rc;
    int              pass;

    memset(&st, 0, sizeof(st));
    set_sw_response(&st, 0x90u, 0x00u);

    ccid = open_mock(&st);
    if (ccid == NULL) {
        return check(0, "verify_pw1_sign_apdu");
    }

    rc = wp11_openpgp_verify_pw1(ccid, pw, sizeof(pw), WP11_OPENPGP_PW1_MODE_SIGN);
    wp11_ccid_close(ccid);

    pass = (rc == WP11_OPENPGP_OK)
        && (st.apdu_len == 11u)
        && (st.apdu[0] == 0x00u)
        && (st.apdu[1] == 0x20u)
        && (st.apdu[2] == 0x00u)
        && (st.apdu[3] == 0x81u)
        && (st.apdu[4] == 0x06u);

    return check(pass, "verify_pw1_sign_apdu");
}

/* -------------------------------------------------------------------------
 * Test 4: verify_pw1_other_apdu
 * VERIFY PW1 with mode=0x82.
 * ---------------------------------------------------------------------- */

static int test_verify_pw1_other_apdu(void)
{
    static const uint8_t pw[] = { 0x31u, 0x32u, 0x33u, 0x34u, 0x35u, 0x36u };
    mock_state_t     st;
    wp11_ccid_ctx_t *ccid;
    int              rc;
    int              pass;

    memset(&st, 0, sizeof(st));
    set_sw_response(&st, 0x90u, 0x00u);

    ccid = open_mock(&st);
    if (ccid == NULL) {
        return check(0, "verify_pw1_other_apdu");
    }

    rc = wp11_openpgp_verify_pw1(ccid, pw, sizeof(pw), WP11_OPENPGP_PW1_MODE_OTHER);
    wp11_ccid_close(ccid);

    pass = (rc == WP11_OPENPGP_OK)
        && (st.apdu_len == 11u)
        && (st.apdu[3] == 0x82u);

    return check(pass, "verify_pw1_other_apdu");
}

/* -------------------------------------------------------------------------
 * Test 5: compute_sig_apdu
 * COMPUTE DIGITAL SIGNATURE with 32-byte hash (all 0xAB).
 * ---------------------------------------------------------------------- */

static int test_compute_sig_apdu(void)
{
    uint8_t          hash[32];
    uint8_t          sig[256];
    size_t           siglen = sizeof(sig);
    /* fake signature bytes + SW 90 00 */
    static const uint8_t fake_sig[] = { 0xAAu, 0xBBu, 0xCCu };
    mock_state_t     st;
    wp11_ccid_ctx_t *ccid;
    int              rc;
    int              pass;

    memset(hash, 0xABu, sizeof(hash));
    memset(&st, 0, sizeof(st));

    /* Response: fake_sig bytes followed by SW 90 00 */
    memcpy(st.resp_payload, fake_sig, sizeof(fake_sig));
    st.resp_payload[sizeof(fake_sig)]     = 0x90u;
    st.resp_payload[sizeof(fake_sig) + 1u] = 0x00u;
    st.resp_payload_len = sizeof(fake_sig) + 2u;

    ccid = open_mock(&st);
    if (ccid == NULL) {
        return check(0, "compute_sig_apdu");
    }

    rc = wp11_openpgp_sign(ccid, hash, sizeof(hash), sig, &siglen);
    wp11_ccid_close(ccid);

    /* APDU: 00 2A 9E 9A 20 [32 bytes] 00 = 38 bytes */
    pass = (rc == WP11_OPENPGP_OK)
        && (st.apdu_len == 38u)
        && (st.apdu[0] == 0x00u)
        && (st.apdu[1] == 0x2Au)
        && (st.apdu[2] == 0x9Eu)
        && (st.apdu[3] == 0x9Au)
        && (st.apdu[4] == 0x20u)
        && (siglen == sizeof(fake_sig));

    return check(pass, "compute_sig_apdu");
}

/* -------------------------------------------------------------------------
 * Test 6: pw_bad_sw
 * SW 63 C2 -> WP11_OPENPGP_ERR_PW_BAD
 * ---------------------------------------------------------------------- */

static int test_pw_bad_sw(void)
{
    static const uint8_t pw[] = { 0x31u, 0x32u, 0x33u };
    mock_state_t     st;
    wp11_ccid_ctx_t *ccid;
    int              rc;

    memset(&st, 0, sizeof(st));
    set_sw_response(&st, 0x63u, 0xC2u);

    ccid = open_mock(&st);
    if (ccid == NULL) {
        return check(0, "pw_bad_sw");
    }

    rc = wp11_openpgp_verify_pw1(ccid, pw, sizeof(pw), WP11_OPENPGP_PW1_MODE_SIGN);
    wp11_ccid_close(ccid);

    return check(rc == WP11_OPENPGP_ERR_PW_BAD, "pw_bad_sw");
}

/* -------------------------------------------------------------------------
 * Test 7: pw_locked_sw
 * SW 69 83 -> WP11_OPENPGP_ERR_PW_LOCKED
 * ---------------------------------------------------------------------- */

static int test_pw_locked_sw(void)
{
    static const uint8_t pw[] = { 0x31u, 0x32u, 0x33u };
    mock_state_t     st;
    wp11_ccid_ctx_t *ccid;
    int              rc;

    memset(&st, 0, sizeof(st));
    set_sw_response(&st, 0x69u, 0x83u);

    ccid = open_mock(&st);
    if (ccid == NULL) {
        return check(0, "pw_locked_sw");
    }

    rc = wp11_openpgp_verify_pw1(ccid, pw, sizeof(pw), WP11_OPENPGP_PW1_MODE_SIGN);
    wp11_ccid_close(ccid);

    return check(rc == WP11_OPENPGP_ERR_PW_LOCKED, "pw_locked_sw");
}

/* -------------------------------------------------------------------------
 * Test 8: authenticate_apdu
 * INTERNAL AUTHENTICATE: verify APDU bytes and response data passthrough.
 *
 * Input data: 4 bytes {0x11, 0x22, 0x33, 0x44}.
 * Expected APDU (OpenPGP spec §7.2.10):
 *   00 88 00 00 04 11 22 33 44 00   (CLA INS P1 P2 Lc [data] Le)
 * ---------------------------------------------------------------------- */

static int test_authenticate_apdu(void)
{
    static const uint8_t data[]     = { 0x11u, 0x22u, 0x33u, 0x44u };
    /* fake authentication response data + SW 90 00 */
    static const uint8_t fake_resp[] = { 0xAAu, 0xBBu, 0xCCu, 0xDDu };
    mock_state_t     st;
    wp11_ccid_ctx_t *ccid;
    uint8_t          resp_out[64];
    size_t           resp_len = sizeof(resp_out);
    int              rc;
    int              f = 0;

    memset(&st, 0, sizeof(st));
    memcpy(st.resp_payload, fake_resp, sizeof(fake_resp));
    st.resp_payload[sizeof(fake_resp)]      = 0x90u;
    st.resp_payload[sizeof(fake_resp) + 1u] = 0x00u;
    st.resp_payload_len = sizeof(fake_resp) + 2u;

    ccid = open_mock(&st);
    if (ccid == NULL) {
        return check(0, "authenticate_apdu: open_mock");
    }

    rc = wp11_openpgp_authenticate(ccid, data, sizeof(data), resp_out, &resp_len);
    wp11_ccid_close(ccid);

    /* APDU: 00 88 00 00 04 11 22 33 44 00 = 10 bytes */
    f += check(rc == WP11_OPENPGP_OK,
               "authenticate_apdu: returns WP11_OPENPGP_OK");
    f += check(st.apdu_len == 10u,
               "authenticate_apdu: APDU length is 10");
    f += check(st.apdu[0] == 0x00u && st.apdu[1] == 0x88u &&
               st.apdu[2] == 0x00u && st.apdu[3] == 0x00u,
               "authenticate_apdu: CLA=00 INS=88 P1=00 P2=00");
    f += check(st.apdu[4] == 0x04u,
               "authenticate_apdu: Lc=04 (data length)");
    f += check(memcmp(&st.apdu[5], data, sizeof(data)) == 0,
               "authenticate_apdu: data bytes in APDU match input");
    f += check(st.apdu[9] == 0x00u,
               "authenticate_apdu: Le=00");
    f += check(resp_len == sizeof(fake_resp) &&
               memcmp(resp_out, fake_resp, sizeof(fake_resp)) == 0,
               "authenticate_apdu: response data returned correctly");

    return f;
}

/* -------------------------------------------------------------------------
 * Test 9: authenticate_bad_sw
 * SW 69 82 (conditions of use not satisfied) -> WP11_OPENPGP_ERR_SW
 * ---------------------------------------------------------------------- */

static int test_authenticate_bad_sw(void)
{
    static const uint8_t data[] = { 0xDEu, 0xADu };
    mock_state_t     st;
    wp11_ccid_ctx_t *ccid;
    uint8_t          resp_out[64];
    size_t           resp_len = sizeof(resp_out);
    int              rc;

    memset(&st, 0, sizeof(st));
    set_sw_response(&st, 0x69u, 0x82u);

    ccid = open_mock(&st);
    if (ccid == NULL) {
        return check(0, "authenticate_bad_sw: open_mock");
    }

    rc = wp11_openpgp_authenticate(ccid, data, sizeof(data), resp_out, &resp_len);
    wp11_ccid_close(ccid);

    return check(rc == WP11_OPENPGP_ERR_SW,
                 "authenticate_bad_sw: SW 69 82 returns WP11_OPENPGP_ERR_SW");
}

/* -------------------------------------------------------------------------
 * Test 10: authenticate_null_param
 * NULL ccid / NULL data / NULL resp_out / NULL resplen -> WP11_OPENPGP_ERR_PARAM
 * Also datalen==0 -> WP11_OPENPGP_ERR_PARAM (empty data not allowed).
 * ---------------------------------------------------------------------- */

static int test_authenticate_null_param(void)
{
    static const uint8_t data[] = { 0x01u };
    uint8_t  resp_out[64];
    size_t   resp_len = sizeof(resp_out);
    int      f = 0;

    f += check(wp11_openpgp_authenticate(NULL, data, sizeof(data),
                                          resp_out, &resp_len)
               == WP11_OPENPGP_ERR_PARAM,
               "authenticate_null_param: NULL ccid returns ERR_PARAM");

    f += check(wp11_openpgp_authenticate((wp11_ccid_ctx_t *)1u,
                                          NULL, sizeof(data),
                                          resp_out, &resp_len)
               == WP11_OPENPGP_ERR_PARAM,
               "authenticate_null_param: NULL data returns ERR_PARAM");

    f += check(wp11_openpgp_authenticate((wp11_ccid_ctx_t *)1u,
                                          data, 0u,
                                          resp_out, &resp_len)
               == WP11_OPENPGP_ERR_PARAM,
               "authenticate_null_param: datalen=0 returns ERR_PARAM");

    f += check(wp11_openpgp_authenticate((wp11_ccid_ctx_t *)1u,
                                          data, sizeof(data),
                                          NULL, &resp_len)
               == WP11_OPENPGP_ERR_PARAM,
               "authenticate_null_param: NULL resp_out returns ERR_PARAM");

    f += check(wp11_openpgp_authenticate((wp11_ccid_ctx_t *)1u,
                                          data, sizeof(data),
                                          resp_out, NULL)
               == WP11_OPENPGP_ERR_PARAM,
               "authenticate_null_param: NULL resplen returns ERR_PARAM");

    return f;
}

/* -------------------------------------------------------------------------
 * Test 11: get_ard_apdu
 * GET DATA DO 006E: verify APDU bytes and response data passthrough.
 *
 * Expected APDU (OpenPGP spec §7.2.3 / GET DATA):
 *   00 CA 00 6E 00   (CLA INS P1=00 P2=6E Le=00)
 * ---------------------------------------------------------------------- */

static int test_get_ard_apdu(void)
{
    /* fake ARD content + SW 90 00 */
    static const uint8_t fake_ard[] = { 0x6Eu, 0x03u, 0x11u, 0x22u, 0x33u };
    mock_state_t     st;
    wp11_ccid_ctx_t *ccid;
    uint8_t          buf[64];
    size_t           buflen = sizeof(buf);
    int              rc;
    int              f = 0;

    memset(&st, 0, sizeof(st));
    memcpy(st.resp_payload, fake_ard, sizeof(fake_ard));
    st.resp_payload[sizeof(fake_ard)]      = 0x90u;
    st.resp_payload[sizeof(fake_ard) + 1u] = 0x00u;
    st.resp_payload_len = sizeof(fake_ard) + 2u;

    ccid = open_mock(&st);
    if (ccid == NULL) {
        return check(0, "get_ard_apdu: open_mock");
    }

    rc = wp11_openpgp_get_ard(ccid, buf, &buflen);
    wp11_ccid_close(ccid);

    /* APDU: 00 CA 00 6E 00 = 5 bytes */
    f += check(rc == WP11_OPENPGP_OK,
               "get_ard_apdu: returns WP11_OPENPGP_OK");
    f += check(st.apdu_len == 5u,
               "get_ard_apdu: APDU length is 5");
    f += check(st.apdu[0] == 0x00u && st.apdu[1] == 0xCAu &&
               st.apdu[2] == 0x00u && st.apdu[3] == 0x6Eu &&
               st.apdu[4] == 0x00u,
               "get_ard_apdu: CLA=00 INS=CA P1=00 P2=6E Le=00");
    f += check(buflen == sizeof(fake_ard) &&
               memcmp(buf, fake_ard, sizeof(fake_ard)) == 0,
               "get_ard_apdu: ARD bytes returned correctly");

    return f;
}

/* -------------------------------------------------------------------------
 * Test 12: get_ard_bad_sw
 * SW 6A 88 (referenced data not found) -> WP11_OPENPGP_ERR_SW
 * ---------------------------------------------------------------------- */

static int test_get_ard_bad_sw(void)
{
    mock_state_t     st;
    wp11_ccid_ctx_t *ccid;
    uint8_t          buf[64];
    size_t           buflen = sizeof(buf);
    int              rc;

    memset(&st, 0, sizeof(st));
    set_sw_response(&st, 0x6Au, 0x88u);

    ccid = open_mock(&st);
    if (ccid == NULL) {
        return check(0, "get_ard_bad_sw: open_mock");
    }

    rc = wp11_openpgp_get_ard(ccid, buf, &buflen);
    wp11_ccid_close(ccid);

    return check(rc == WP11_OPENPGP_ERR_SW,
                 "get_ard_bad_sw: SW 6A 88 returns WP11_OPENPGP_ERR_SW");
}

/* -------------------------------------------------------------------------
 * Test 13: get_ard_null_param
 * ---------------------------------------------------------------------- */

static int test_get_ard_null_param(void)
{
    uint8_t buf[64];
    size_t  buflen = sizeof(buf);
    int     f = 0;

    f += check(wp11_openpgp_get_ard(NULL, buf, &buflen) == WP11_OPENPGP_ERR_PARAM,
               "get_ard_null_param: NULL ccid returns ERR_PARAM");
    f += check(wp11_openpgp_get_ard((wp11_ccid_ctx_t *)1u, NULL, &buflen)
               == WP11_OPENPGP_ERR_PARAM,
               "get_ard_null_param: NULL buf returns ERR_PARAM");
    f += check(wp11_openpgp_get_ard((wp11_ccid_ctx_t *)1u, buf, NULL)
               == WP11_OPENPGP_ERR_PARAM,
               "get_ard_null_param: NULL buflen returns ERR_PARAM");

    return f;
}

/* -------------------------------------------------------------------------
 * Test 14: get_ard_bufsize
 * Response has 5 data bytes; caller provides a 2-byte buffer -> ERR_BUFSIZE.
 * ---------------------------------------------------------------------- */

static int test_get_ard_bufsize(void)
{
    static const uint8_t fake_ard[] = { 0x6Eu, 0x03u, 0x11u, 0x22u, 0x33u };
    mock_state_t     st;
    wp11_ccid_ctx_t *ccid;
    uint8_t          buf[2]; /* intentionally too small */
    size_t           buflen = sizeof(buf);
    int              rc;

    memset(&st, 0, sizeof(st));
    memcpy(st.resp_payload, fake_ard, sizeof(fake_ard));
    st.resp_payload[sizeof(fake_ard)]      = 0x90u;
    st.resp_payload[sizeof(fake_ard) + 1u] = 0x00u;
    st.resp_payload_len = sizeof(fake_ard) + 2u;

    ccid = open_mock(&st);
    if (ccid == NULL) {
        return check(0, "get_ard_bufsize: open_mock");
    }

    rc = wp11_openpgp_get_ard(ccid, buf, &buflen);
    wp11_ccid_close(ccid);

    return check(rc == WP11_OPENPGP_ERR_BUFSIZE,
                 "get_ard_bufsize: 2-byte buffer for 5-byte ARD returns ERR_BUFSIZE");
}

/* -------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */

int wp11_test_openpgp(void)
{
    int failures = 0;

    failures += test_vector_file_nonempty();
    failures += test_select_aid_apdu();
    failures += test_verify_pw1_sign_apdu();
    failures += test_verify_pw1_other_apdu();
    failures += test_compute_sig_apdu();
    failures += test_pw_bad_sw();
    failures += test_pw_locked_sw();
    failures += test_authenticate_apdu();
    failures += test_authenticate_bad_sw();
    failures += test_authenticate_null_param();
    failures += test_get_ard_apdu();
    failures += test_get_ard_bad_sw();
    failures += test_get_ard_null_param();
    failures += test_get_ard_bufsize();

    return failures;
}

#else /* WOLFP11_CFG_TEST not defined */

int wp11_test_openpgp(void)
{
    return 0;
}

#endif /* WOLFP11_CFG_TEST */
