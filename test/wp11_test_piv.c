/* wp11_test_piv.c -- PIV protocol unit tests
 *
 * Tests verify APDU framing byte-for-byte against NIST SP 800-73-4 vectors.
 * No crypto round-trips; only structural and framing correctness is checked.
 *
 * Reference: NIST SP 800-73-4
 * Test vectors: piv_apdu.json derived from SP 800-73-4 Section 2.2, 3.2.1, 3.2.4
 *
 * Compile with -DWOLFP11_CFG_TEST to enable.
 * Returns 0 on full pass, or the count of failures.
 */

#include "wp11_test_piv.h"

#ifdef WOLFP11_CFG_TEST

#include "wolfp11/wp11_proto_piv.h"
#include "wolfp11/wp11_ccid.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Internal helpers
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
 * Mock CCID transport
 *
 * The CCID transport function receives the raw CCID bulk-out packet and must
 * fill in the raw CCID bulk-in packet.  Standard CCID framing places the APDU
 * at offset 10 within the PC_to_RDR_XfrBlock message (CCID spec Table 6.1).
 *
 * The mock:
 *   - saves the outgoing APDU bytes (offset 10 .. end) for inspection
 *   - returns a configurable two-byte SW wrapped in a RDR_to_PC_DataBlock
 * ---------------------------------------------------------------------- */

/* CCID message type constants */
#define CCID_MSG_XFRBLOCK    0x6Fu  /* PC_to_RDR_XfrBlock */
#define CCID_MSG_DATABLOCK   0x80u  /* RDR_to_PC_DataBlock */

/* Offset of the APDU data within a CCID bulk message */
#define CCID_APDU_OFFSET     10u

/* Maximum APDU size the mock will capture */
#define MOCK_APDU_MAX        300u

/* Maximum CCID response size the mock will produce */
#define MOCK_RESP_MAX        300u

typedef struct {
    /* Captured outgoing APDU bytes */
    uint8_t  captured[MOCK_APDU_MAX];
    size_t   captured_len;

    /* SW1/SW2 to return */
    uint8_t  sw1;
    uint8_t  sw2;

    /* Optional extra response data before SW (e.g. a fake signature) */
    uint8_t  extra[MOCK_APDU_MAX];
    size_t   extra_len;
} mock_state_t;

static int mock_transport(void          *userdata,
                          const uint8_t *out, size_t  outlen,
                          uint8_t       *in,  size_t *inlen)
{
    mock_state_t *m = (mock_state_t *)userdata;
    size_t apdu_len;
    size_t resp_data_len;

    if (m == NULL || out == NULL || in == NULL || inlen == NULL) {
        return -1;
    }

    /* Extract APDU from CCID message (starts at offset 10) */
    if (outlen <= CCID_APDU_OFFSET) {
        m->captured_len = 0;
    } else {
        apdu_len = outlen - CCID_APDU_OFFSET;
        if (apdu_len > MOCK_APDU_MAX) {
            apdu_len = MOCK_APDU_MAX;
        }
        (void)memcpy(m->captured, &out[CCID_APDU_OFFSET], apdu_len);
        m->captured_len = apdu_len;
    }

    /*
     * Build RDR_to_PC_DataBlock response:
     *   Byte 0:    bMessageType = 0x80
     *   Bytes 1-4: dwLength = extra_len + 2  (little-endian)
     *   Byte 5:    bSlot = 0
     *   Byte 6:    bSeq = seq from request (byte 6 of out)
     *   Byte 7:    bStatus = 0
     *   Byte 8:    bError = 0
     *   Byte 9:    bChainParameter = 0
     *   Bytes 10+: [extra data] SW1 SW2
     */
    resp_data_len = m->extra_len + 2u;  /* extra bytes + SW1 + SW2 */

    if ((CCID_APDU_OFFSET + resp_data_len) > MOCK_RESP_MAX) {
        return -1;
    }

    in[0] = CCID_MSG_DATABLOCK;
    in[1] = (uint8_t)(resp_data_len & 0xFFu);
    in[2] = (uint8_t)((resp_data_len >> 8)  & 0xFFu);
    in[3] = (uint8_t)((resp_data_len >> 16) & 0xFFu);
    in[4] = (uint8_t)((resp_data_len >> 24) & 0xFFu);
    in[5] = 0x00u;                         /* bSlot */
    in[6] = (outlen > 6u) ? out[6] : 0u;  /* bSeq echoed */
    in[7] = 0x00u;                         /* bStatus: success */
    in[8] = 0x00u;                         /* bError */
    in[9] = 0x00u;                         /* bChainParameter */

    if (m->extra_len > 0u) {
        (void)memcpy(&in[CCID_APDU_OFFSET], m->extra, m->extra_len);
    }
    in[CCID_APDU_OFFSET + m->extra_len]      = m->sw1;
    in[CCID_APDU_OFFSET + m->extra_len + 1u] = m->sw2;

    *inlen = CCID_APDU_OFFSET + resp_data_len;
    return 0;
}

/* -------------------------------------------------------------------------
 * Hex comparison helper: compare captured bytes against a hex string literal.
 * Returns 1 if equal, 0 if not.
 * ---------------------------------------------------------------------- */

static int hex_decode(const char *hex, uint8_t *out, size_t *outlen)
{
    size_t i;
    size_t hexlen = strlen(hex);

    if (hexlen % 2u != 0u) {
        return 0;
    }
    *outlen = hexlen / 2u;
    for (i = 0; i < *outlen; i++) {
        unsigned int hi;
        unsigned int lo;
        char hc = hex[i * 2u];
        char lc = hex[i * 2u + 1u];

        if (hc >= '0' && hc <= '9') { hi = (unsigned int)(hc - '0'); }
        else if (hc >= 'A' && hc <= 'F') { hi = (unsigned int)(hc - 'A') + 10u; }
        else if (hc >= 'a' && hc <= 'f') { hi = (unsigned int)(hc - 'a') + 10u; }
        else { return 0; }

        if (lc >= '0' && lc <= '9') { lo = (unsigned int)(lc - '0'); }
        else if (lc >= 'A' && lc <= 'F') { lo = (unsigned int)(lc - 'A') + 10u; }
        else if (lc >= 'a' && lc <= 'f') { lo = (unsigned int)(lc - 'a') + 10u; }
        else { return 0; }

        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

static int apdu_matches_hex(const uint8_t *actual, size_t actual_len,
                            const char *expected_hex)
{
    uint8_t expected[MOCK_APDU_MAX];
    size_t  expected_len = 0;

    if (!hex_decode(expected_hex, expected, &expected_len)) {
        return 0;
    }
    if (actual_len != expected_len) {
        return 0;
    }
    return (memcmp(actual, expected, expected_len) == 0) ? 1 : 0;
}

/* -------------------------------------------------------------------------
 * Test 1: vector_file_nonempty
 *
 * SP 800-73-4: all sections
 * Open test/vectors/piv_apdu.json and verify it exists and has content.
 * Tests run from project root, so the relative path is correct.
 *
 * The JSON file is a human-readable spec reference, not a machine-driven
 * fixture (wolfP11-7fr). The test oracle is the hardcoded hex in this file.
 * We verify the file exists and is non-empty to catch accidental deletion.
 * ---------------------------------------------------------------------- */

static int test_vector_file_nonempty(void)
{
    FILE *f = fopen("test/vectors/piv_apdu.json", "r");
    long  sz;
    int   pass;

    if (f == NULL) {
        printf("FAIL: vector_file_nonempty (file not found)\n");
        return 1;
    }

    (void)fseek(f, 0L, SEEK_END);
    sz = ftell(f);
    (void)fclose(f);

    pass = (sz > 0L);
    return check(pass, "vector_file_nonempty");
}

/* -------------------------------------------------------------------------
 * Test 2: select_aid_apdu
 *
 * SP 800-73-4 Section 2.2
 * Expected APDU: 00 A4 04 00 0B A0 00 00 03 08 00 00 10 00 01 00
 * ---------------------------------------------------------------------- */

static int test_select_aid_apdu(void)
{
    mock_state_t  state;
    wp11_ccid_ctx_t *ccid = NULL;
    int rc;
    int pass;

    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: select_aid_apdu (open_mock failed: %d)\n", rc);
        return 1;
    }

    rc = wp11_piv_select(ccid);
    wp11_ccid_close(ccid);

    pass = (rc == WP11_PIV_OK) &&
           apdu_matches_hex(state.captured, state.captured_len,
                            "00A404000BA000000308000010000100");

    return check(pass, "select_aid_apdu (SP 800-73-4 Section 2.2)");
}

/* -------------------------------------------------------------------------
 * Test 3: verify_pin_apdu
 *
 * SP 800-73-4 Section 3.2.1
 * PIN "123456" (0x31..0x36) padded to 8 bytes with 0xFF.
 * Expected APDU: 00 20 00 80 08 31 32 33 34 35 36 FF FF
 * ---------------------------------------------------------------------- */

static int test_verify_pin_apdu(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    /* "123456" in ASCII */
    const uint8_t    pin[] = { 0x31u, 0x32u, 0x33u, 0x34u, 0x35u, 0x36u };
    int rc;
    int pass;

    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: verify_pin_apdu (open_mock failed: %d)\n", rc);
        return 1;
    }

    rc = wp11_piv_verify_pin(ccid, pin, sizeof(pin));
    wp11_ccid_close(ccid);

    pass = (rc == WP11_PIV_OK) &&
           apdu_matches_hex(state.captured, state.captured_len,
                            "0020008008313233343536FFFF");

    return check(pass, "verify_pin_apdu (SP 800-73-4 Section 3.2.1)");
}

/* -------------------------------------------------------------------------
 * Test 4: general_authenticate_p256_apdu
 *
 * SP 800-73-4 Section 3.2.4
 * slot=0x9C, alg=0x11, 32-byte challenge (all 0xDE).
 * Verify APDU header bytes and DAT tag structure.
 * Mock returns a fake signature in 7C/82 wrapper.
 * ---------------------------------------------------------------------- */

static int test_general_authenticate_p256_apdu(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          challenge[32];
    uint8_t          sig[128];
    size_t           siglen = sizeof(sig);
    int              rc;
    int              pass;

    /*
     * Fake signature response wrapped as: 7C [len] 82 [siglen] [sig bytes]
     * We use a 4-byte dummy signature for simplicity.
     */
    const uint8_t fake_sig_payload[] = { 0xAA, 0xBB, 0xCC, 0xDD };
    const uint8_t fake_response[] = {
        0x7Cu,                      /* TAG_DAT */
        0x06u,                      /* length: 82 + 00 + 04 sig bytes */
        0x82u,                      /* TAG_RESPONSE */
        0x04u,                      /* sig length */
        0xAAu, 0xBBu, 0xCCu, 0xDDu /* sig bytes */
    };

    (void)memset(challenge, 0xDEu, sizeof(challenge));
    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;
    (void)memcpy(state.extra, fake_response, sizeof(fake_response));
    state.extra_len = sizeof(fake_response);

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: general_authenticate_p256_apdu (open_mock failed: %d)\n", rc);
        return 1;
    }

    rc = wp11_piv_sign(ccid,
                       WP11_PIV_SLOT_SIGN, WP11_PIV_ALG_EC_P256,
                       challenge, sizeof(challenge),
                       sig, &siglen);
    wp11_ccid_close(ccid);

    /* Verify return code */
    pass = (rc == WP11_PIV_OK);

    /* Verify APDU header: [0]=0x00 [1]=0x87 [2]=0x11 [3]=0x9C */
    pass = pass &&
           (state.captured_len > 5u) &&
           (state.captured[0] == 0x00u) &&
           (state.captured[1] == 0x87u) &&
           (state.captured[2] == WP11_PIV_ALG_EC_P256) &&
           (state.captured[3] == WP11_PIV_SLOT_SIGN);

    /* Verify DAT tag 0x7C at byte[5] */
    pass = pass && (state.captured[5] == 0x7Cu);

    /* Verify signature was correctly extracted from mock response */
    pass = pass &&
           (siglen == sizeof(fake_sig_payload)) &&
           (memcmp(sig, fake_sig_payload, siglen) == 0);

    return check(pass, "general_authenticate_p256_apdu (SP 800-73-4 Section 3.2.4)");
}

/* -------------------------------------------------------------------------
 * Test 5: pin_bad_sw
 *
 * SP 800-73-4 Section 3.2.1
 * Mock returns SW 63 C2 (wrong PIN, 2 retries remaining).
 * Verify wp11_piv_verify_pin() returns WP11_PIV_ERR_PIN_BAD.
 * ---------------------------------------------------------------------- */

static int test_pin_bad_sw(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    const uint8_t    pin[] = { 0x31u, 0x32u, 0x33u, 0x34u };
    int rc;

    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x63u;
    state.sw2 = 0xC2u;  /* 2 retries remaining */

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: pin_bad_sw (open_mock failed: %d)\n", rc);
        return 1;
    }

    rc = wp11_piv_verify_pin(ccid, pin, sizeof(pin));
    wp11_ccid_close(ccid);

    return check(rc == WP11_PIV_ERR_PIN_BAD,
                 "pin_bad_sw SW 63 C2 returns WP11_PIV_ERR_PIN_BAD "
                 "(SP 800-73-4 Section 3.2.1)");
}

/* -------------------------------------------------------------------------
 * Test 6: pin_locked_sw
 *
 * SP 800-73-4 Section 3.2.1
 * Mock returns SW 69 83 (PIN blocked).
 * Verify wp11_piv_verify_pin() returns WP11_PIV_ERR_PIN_LOCKED.
 * ---------------------------------------------------------------------- */

static int test_pin_locked_sw(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    const uint8_t    pin[] = { 0x31u, 0x32u, 0x33u, 0x34u };
    int rc;

    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x69u;
    state.sw2 = 0x83u;

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: pin_locked_sw (open_mock failed: %d)\n", rc);
        return 1;
    }

    rc = wp11_piv_verify_pin(ccid, pin, sizeof(pin));
    wp11_ccid_close(ccid);

    return check(rc == WP11_PIV_ERR_PIN_LOCKED,
                 "pin_locked_sw SW 69 83 returns WP11_PIV_ERR_PIN_LOCKED "
                 "(SP 800-73-4 Section 3.2.1)");
}

/* -------------------------------------------------------------------------
 * Test 7: test_rsa2048_response_parsing
 *
 * SP 800-73-4 Section 3.2.4, Table 13
 * Feed a mock RSA-2048 GENERAL AUTHENTICATE response (266 bytes total) to
 * wp11_piv_sign() and verify ber_len_decode() handles the 3-byte length fields.
 *
 * Response layout (extra[] passed to mock, SW appended separately):
 *   7C 82 01 04   -- TAG_DAT, 2-byte BER length 260 (0x0104)
 *   82 82 01 00   -- TAG_RESPONSE, 2-byte BER length 256 (0x0100)
 *   AB AB ... AB  -- 256 bytes of fake signature
 * extra_len = 4 + 4 + 256 = 264 bytes; mock appends 90 00 -> total 266 bytes.
 * ---------------------------------------------------------------------- */

static int test_rsa2048_response_parsing(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          challenge[16];
    uint8_t          sig[300];
    size_t           siglen = sizeof(sig);
    int              rc;
    int              pass;
    size_t           k;

    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;

    /* Build extra[]: 7C 82 01 04  82 82 01 00  AB*256 */
    k = 0u;
    state.extra[k++] = 0x7Cu;   /* TAG_DAT */
    state.extra[k++] = 0x82u;   /* 2-byte length follows */
    state.extra[k++] = 0x01u;   /* high byte: 260 = 0x0104 */
    state.extra[k++] = 0x04u;   /* low byte */
    state.extra[k++] = 0x82u;   /* TAG_RESPONSE */
    state.extra[k++] = 0x82u;   /* 2-byte length follows */
    state.extra[k++] = 0x01u;   /* high byte: 256 = 0x0100 */
    state.extra[k++] = 0x00u;   /* low byte */
    (void)memset(&state.extra[k], 0xABu, 256u);
    k += 256u;
    state.extra_len = k;   /* 264 */

    (void)memset(challenge, 0x11u, sizeof(challenge));

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: rsa2048_response_parsing (open_mock failed: %d)\n", rc);
        return 1;
    }

    rc = wp11_piv_sign(ccid,
                       WP11_PIV_SLOT_SIGN, WP11_PIV_ALG_RSA2048,
                       challenge, sizeof(challenge),
                       sig, &siglen);
    wp11_ccid_close(ccid);

    pass = (rc == WP11_PIV_OK);
    pass = pass && (siglen == 256u);
    pass = pass && (sig[0]   == 0xABu);
    pass = pass && (sig[255] == 0xABu);

    return check(pass,
                 "rsa2048_response_parsing: 3-byte BER-TLV lengths parsed correctly");
}

/* -------------------------------------------------------------------------
 * Test 8: test_ber_malformed_response
 *
 * Feed a response with 7C 0x83 ... -- a 3-byte-count long form that we reject.
 * Verify wp11_piv_sign returns WP11_PIV_ERR_ENCODING.
 * ---------------------------------------------------------------------- */

static int test_ber_malformed_response(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          challenge[16];
    uint8_t          sig[300];
    size_t           siglen = sizeof(sig);
    int              rc;

    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;

    /* 7C 83 00 01 04: 0x83 means 3 length bytes follow -- unsupported */
    state.extra[0] = 0x7Cu;
    state.extra[1] = 0x83u;
    state.extra[2] = 0x00u;
    state.extra[3] = 0x01u;
    state.extra[4] = 0x04u;
    state.extra_len = 5u;

    (void)memset(challenge, 0x22u, sizeof(challenge));

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: ber_malformed_response (open_mock failed: %d)\n", rc);
        return 1;
    }

    rc = wp11_piv_sign(ccid,
                       WP11_PIV_SLOT_SIGN, WP11_PIV_ALG_RSA2048,
                       challenge, sizeof(challenge),
                       sig, &siglen);
    wp11_ccid_close(ccid);

    return check(rc == WP11_PIV_ERR_ENCODING,
                 "ber_malformed_response: 0x83 long-form returns WP11_PIV_ERR_ENCODING");
}

/* -------------------------------------------------------------------------
 * Test 9: test_ber_truncated_length
 *
 * Feed a response with 7C 0x82 [only 1 more byte] -- truncated 2-byte length.
 * Verify wp11_piv_sign returns WP11_PIV_ERR_ENCODING.
 * ---------------------------------------------------------------------- */

static int test_ber_truncated_length(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          challenge[16];
    uint8_t          sig[300];
    size_t           siglen = sizeof(sig);
    int              rc;

    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;

    /* 7C 82 01: 0x82 says 2 more bytes, but only 1 follows -> truncated */
    state.extra[0] = 0x7Cu;
    state.extra[1] = 0x82u;
    state.extra[2] = 0x01u;
    state.extra_len = 3u;

    (void)memset(challenge, 0x33u, sizeof(challenge));

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: ber_truncated_length (open_mock failed: %d)\n", rc);
        return 1;
    }

    rc = wp11_piv_sign(ccid,
                       WP11_PIV_SLOT_SIGN, WP11_PIV_ALG_RSA2048,
                       challenge, sizeof(challenge),
                       sig, &siglen);
    wp11_ccid_close(ccid);

    return check(rc == WP11_PIV_ERR_ENCODING,
                 "ber_truncated_length: truncated 0x82 length returns WP11_PIV_ERR_ENCODING");
}

/* -------------------------------------------------------------------------
 * Test: ber_encode_7c_long_form
 *
 * wolfP11-oki regression: challengelen=124 produces dat_content_len=128,
 * which requires a 2-byte BER-TLV length in the 7C field.  Before the fix,
 * the (uint8_t)128 cast produced 0x80 (the indefinite-length marker, illegal
 * in PIV per ISO 7816-4 Section 5.2.2).
 *
 * Expected APDU wire bytes at bytes [5..7]: 7C 81 80
 *   7C   = TAG_DAT
 *   0x81 = one-byte long-form BER marker
 *   0x80 = dat_content_len = 128
 *
 * Oracle: manually computed from first principles (independent of the code).
 * ---------------------------------------------------------------------- */
static int test_ber_encode_7c_long_form(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          challenge[124];
    uint8_t          sig[128];
    size_t           siglen = sizeof(sig);
    int              rc;
    int              f = 0;

    (void)memset(challenge, 0xA5u, sizeof(challenge));
    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;
    /* Minimal valid response: 7C 06 82 04 [4 fake sig bytes] */
    state.extra[0] = 0x7Cu;
    state.extra[1] = 0x06u;
    state.extra[2] = 0x82u;
    state.extra[3] = 0x04u;
    state.extra[4] = 0x11u;
    state.extra[5] = 0x22u;
    state.extra[6] = 0x33u;
    state.extra[7] = 0x44u;
    state.extra_len = 8u;

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: ber_encode_7c_long_form (open_mock failed)\n");
        return 1;
    }

    rc = wp11_piv_sign(ccid, WP11_PIV_SLOT_SIGN, WP11_PIV_ALG_EC_P256,
                       challenge, sizeof(challenge), sig, &siglen);
    wp11_ccid_close(ccid);

    f += check(rc == WP11_PIV_OK,
               "ber_encode_7c_long_form: wp11_piv_sign returns WP11_PIV_OK");

    /* Lc (byte[4]) = apdu_data_size = 1(7C) + 2(BER) + 128(content) = 131 = 0x83 */
    f += check(state.captured_len > 7u && state.captured[4] == 0x83u,
               "ber_encode_7c_long_form: Lc == 0x83 (131 bytes)");

    /* 7C BER-TLV length: byte[6]=0x81 (long-form), byte[7]=0x80 (128) */
    f += check(state.captured_len > 7u &&
               state.captured[5] == 0x7Cu &&   /* TAG_DAT */
               state.captured[6] == 0x81u &&   /* long-form marker */
               state.captured[7] == 0x80u,     /* length = 128 */
               "ber_encode_7c_long_form: 7C uses 2-byte BER length 0x81 0x80");

    /* TAG_CHALLENGE at byte[10], length in short-form at byte[11] = 0x7C (124) */
    f += check(state.captured_len > 11u &&
               state.captured[10] == 0x81u &&  /* TAG_CHALLENGE */
               state.captured[11] == 0x7Cu,    /* short-form len 124 */
               "ber_encode_7c_long_form: 81 challenge len is short-form 0x7C (124)");

    return f;
}

/* -------------------------------------------------------------------------
 * Test: ber_encode_81_long_form
 *
 * wolfP11-oki regression: challengelen=128 requires a 2-byte BER length for
 * the 81 (TAG_CHALLENGE) field.  Before the fix, the (uint8_t)128 cast
 * produced 0x80 (indefinite-length marker, illegal).
 *
 * Expected at bytes [10..12]: 81 81 80
 *   81   = TAG_CHALLENGE
 *   0x81 = one-byte long-form BER marker
 *   0x80 = challengelen = 128
 *
 * Oracle: manually computed.
 * ---------------------------------------------------------------------- */
static int test_ber_encode_81_long_form(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          challenge[128];
    uint8_t          sig[128];
    size_t           siglen = sizeof(sig);
    int              rc;
    int              f = 0;

    (void)memset(challenge, 0xB7u, sizeof(challenge));
    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;
    state.extra[0] = 0x7Cu;
    state.extra[1] = 0x06u;
    state.extra[2] = 0x82u;
    state.extra[3] = 0x04u;
    state.extra[4] = 0xAAu;
    state.extra[5] = 0xBBu;
    state.extra[6] = 0xCCu;
    state.extra[7] = 0xDDu;
    state.extra_len = 8u;

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: ber_encode_81_long_form (open_mock failed)\n");
        return 1;
    }

    rc = wp11_piv_sign(ccid, WP11_PIV_SLOT_SIGN, WP11_PIV_ALG_EC_P256,
                       challenge, sizeof(challenge), sig, &siglen);
    wp11_ccid_close(ccid);

    f += check(rc == WP11_PIV_OK,
               "ber_encode_81_long_form: wp11_piv_sign returns WP11_PIV_OK");

    /* dat_content_len = 2(82 00) + 1(81) + 2(BER) + 128 = 133 = 0x85
     * apdu_data_size = 1(7C) + 2(BER for 133) + 133 = 136 = 0x88 */
    f += check(state.captured_len > 12u && state.captured[4] == 0x88u,
               "ber_encode_81_long_form: Lc == 0x88 (136 bytes)");

    /* 7C BER length: byte[6]=0x81 byte[7]=0x85 (= 133 = 0x85) */
    f += check(state.captured_len > 12u &&
               state.captured[5] == 0x7Cu &&
               state.captured[6] == 0x81u &&
               state.captured[7] == 0x85u,
               "ber_encode_81_long_form: 7C BER length is 0x81 0x85 (133)");

    /* TAG_CHALLENGE at byte[10], 2-byte BER length at bytes[11..12] */
    f += check(state.captured[10] == 0x81u &&  /* TAG_CHALLENGE */
               state.captured[11] == 0x81u &&  /* long-form BER marker */
               state.captured[12] == 0x80u,    /* value = 128 */
               "ber_encode_81_long_form: 81 uses 2-byte BER length 0x81 0x80 (128)");

    return f;
}

/* -------------------------------------------------------------------------
 * Test: ber_challengelen_too_large
 *
 * wolfP11-oki: challengelen=248 would produce apdu_data_size=256, exceeding
 * the 255-byte Lc limit for short APDUs.  The new guard (> 247) must reject it.
 * ---------------------------------------------------------------------- */
static int test_ber_challengelen_too_large(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          challenge[248];
    uint8_t          sig[128];
    size_t           siglen = sizeof(sig);
    int              rc;

    (void)memset(challenge, 0x00u, sizeof(challenge));
    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: ber_challengelen_too_large (open_mock failed)\n");
        return 1;
    }

    rc = wp11_piv_sign(ccid, WP11_PIV_SLOT_SIGN, WP11_PIV_ALG_EC_P256,
                       challenge, sizeof(challenge), sig, &siglen);
    wp11_ccid_close(ccid);

    return check(rc == WP11_PIV_ERR_PARAM,
                 "ber_challengelen_too_large: challengelen=248 -> WP11_PIV_ERR_PARAM");
}

/* -------------------------------------------------------------------------
 * test_generate_keypair_ec_p256_apdu
 *
 * SP 800-73-4 Section 3.3.2
 * slot=0x9A, alg=0x11 (EC P-256).
 * Expected APDU: 00 47 00 9A 05 AC 03 80 01 11 00
 *   INS=0x47, P1=0x00, P2=0x9A, Lc=5, Data=AC 03 80 01 11, Le=0x00
 *
 * Mock returns a valid 7F49/86 response with a fake 65-byte EC point.
 * Oracle: APDU bytes match spec; return code is WP11_PIV_OK; public key
 * bytes returned match the fake point in the mock response.
 * ---------------------------------------------------------------------- */

#define FAKE_EC_POINT_LEN 65u  /* uncompressed P-256 point: 04 || X(32) || Y(32) */

static int test_generate_keypair_ec_p256_apdu(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          pubkey[FAKE_EC_POINT_LEN];
    size_t           pubkey_len = sizeof(pubkey);
    int              rc;
    int              f = 0;

    /* Construct mock response: 7F 49 43 86 41 04 [63 zero bytes] SW 90 00
     *   7F 49:  2-byte outer tag (Public Key Object)
     *   43:     outer length = 67 = 1(tag 86) + 1(len 41) + 65(point bytes)
     *   86:     inner tag (EC public key)
     *   41:     inner length = 65 (0x41 = 65)
     *   04 [64 zeros]: fake EC point (uncompressed, all-zero coordinates) */
    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;
    state.extra_len = 2u + 1u + 1u + 1u + FAKE_EC_POINT_LEN;  /* 70 bytes */
    state.extra[0]  = 0x7Fu;  /* outer tag byte 1 */
    state.extra[1]  = 0x49u;  /* outer tag byte 2 */
    state.extra[2]  = 0x43u;  /* outer length = 67 */
    state.extra[3]  = 0x86u;  /* inner tag: EC public key */
    state.extra[4]  = 0x41u;  /* inner length = 65 */
    state.extra[5]  = 0x04u;  /* uncompressed point marker */
    /* bytes 6..69: all zero (fake X and Y coordinates) */

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: generate_keypair_ec_p256: open_mock failed: %d\n", rc);
        return 1;
    }

    rc = wp11_piv_generate_key(ccid, WP11_PIV_SLOT_AUTH, WP11_PIV_ALG_EC_P256,
                                pubkey, &pubkey_len);
    wp11_ccid_close(ccid);

    /* APDU: 00 47 00 9A 05 AC 03 80 01 11 00
     * CLA=00 INS=47 P1=00 P2=9A Lc=05 Data=AC0380_0111 Le=00 */
    f += check(rc == WP11_PIV_OK,
               "generate_keypair_ec_p256: returns WP11_PIV_OK");
    f += check(apdu_matches_hex(state.captured, state.captured_len,
                                "0047009A05AC0380011100"),
               "generate_keypair_ec_p256: APDU bytes match SP 800-73-4 sec.3.3.2");
    f += check(pubkey_len == FAKE_EC_POINT_LEN,
               "generate_keypair_ec_p256: pubkey_len == 65");
    f += check(pubkey[0] == 0x04u,
               "generate_keypair_ec_p256: pubkey starts with 04 (uncompressed)");

    return f;
}

/* -------------------------------------------------------------------------
 * test_generate_keypair_bad_sw
 *
 * Verify that specific non-9000 SW codes are mapped to typed error values.
 * Oracle: SW 69 82 (security status) -> WP11_PIV_ERR_SECURITY_STATUS per
 * the piv_sw_to_err dispatch table added in wolfP11-dgv.
 * ---------------------------------------------------------------------- */

static int test_generate_keypair_bad_sw(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    int              rc;

    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x69u;
    state.sw2 = 0x82u;  /* Security status not satisfied */

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: generate_keypair_bad_sw: open_mock failed\n");
        return 1;
    }

    rc = wp11_piv_generate_key(ccid, WP11_PIV_SLOT_SIGN, WP11_PIV_ALG_EC_P256,
                                NULL, NULL);
    wp11_ccid_close(ccid);

    return check(rc == WP11_PIV_ERR_SECURITY_STATUS,
                 "generate_keypair_bad_sw: SW 69 82 returns WP11_PIV_ERR_SECURITY_STATUS");
}

/* -------------------------------------------------------------------------
 * Test: test_piv_attest_apdu
 *
 * YubiKey attestation APDU: 00 F9 00 9A 00
 *   INS=0xF9, P1=0x00, P2=0x9A (PIV_SLOT_AUTH), Le=0x00
 *
 * Mock returns a 10-byte synthetic DER cert as the raw response (no BER-TLV
 * wrapper) followed by SW 90 00.
 *
 * Oracles:
 *   - APDU bytes match the spec (manually derived)
 *   - Return code is WP11_PIV_OK
 *   - DER output matches the fake cert bytes in extra[]
 * ---------------------------------------------------------------------- */

#define FAKE_ATTEST_DER_LEN 10u

static int test_piv_attest_apdu(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          der[256];
    size_t           derlen = sizeof(der);
    int              rc;
    int              f = 0;
    size_t           k;
    static const uint8_t fake_cert[FAKE_ATTEST_DER_LEN] = {
        0x30u, 0x08u, 0x02u, 0x01u, 0x01u,
        0x02u, 0x01u, 0x02u, 0x02u, 0x01u
    };

    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;

    for (k = 0; k < FAKE_ATTEST_DER_LEN; k++) {
        state.extra[k] = fake_cert[k];
    }
    state.extra_len = FAKE_ATTEST_DER_LEN;

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: piv_attest_apdu (open_mock failed: %d)\n", rc);
        return 1;
    }

    rc = wp11_piv_attest(ccid, WP11_PIV_SLOT_AUTH, der, &derlen);
    wp11_ccid_close(ccid);

    f += check(rc == WP11_PIV_OK,
               "piv_attest_apdu: returns WP11_PIV_OK");

    /* APDU: 00 F9 00 9A 00 */
    f += check(apdu_matches_hex(state.captured, state.captured_len,
                                "00F9009A00"),
               "piv_attest_apdu: APDU bytes match YubiKey attestation spec");

    f += check(derlen == FAKE_ATTEST_DER_LEN,
               "piv_attest_apdu: derlen == 10");

    f += check(memcmp(der, fake_cert, FAKE_ATTEST_DER_LEN) == 0,
               "piv_attest_apdu: DER output matches fake cert bytes");

    return f;
}

/* -------------------------------------------------------------------------
 * Test: test_piv_ecdh_apdu
 *
 * SP 800-73-4 sec.3.2.4 -- GENERAL AUTHENTICATE in key-agreement mode.
 * slot=0x9D (KEYMGMT), alg=0x11 (EC P-256), 65-byte peer point (04||zeros).
 *
 * Expected APDU structure (77 bytes total):
 *   00 87 11 9D 47   -- CLA INS P1(alg) P2(slot) Lc(71)
 *   7C 45            -- TAG_DAT, dat_content_len=69
 *   82 00            -- empty response template
 *   85 41            -- TAG_EXPONENT, peer_pub_len=65
 *   04 {64 zeros}    -- uncompressed EC point
 *   00               -- Le
 *
 * Mock returns 7C 22 82 20 {32 bytes 0xAB} SW 90 00 (fake shared secret).
 *
 * Oracle: APDU tag/position bytes match spec; return is WP11_PIV_OK;
 *         shared secret bytes match the mock-returned value.
 * ---------------------------------------------------------------------- */

#define FAKE_SHARED_LEN 32u  /* P-256 shared secret: x-coordinate = 32 bytes */

static int test_piv_ecdh_apdu(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          peer_pub[65];
    uint8_t          shared[64];
    size_t           sharedlen = sizeof(shared);
    int              rc;
    int              f = 0;
    size_t           k;

    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;

    /* Fake peer public key: 04 followed by 64 zeros */
    (void)memset(peer_pub, 0x00u, sizeof(peer_pub));
    peer_pub[0] = 0x04u;

    /* Mock response: 7C 22 82 20 {32 bytes 0xAB} */
    state.extra[0] = 0x7Cu;  /* TAG_DAT */
    state.extra[1] = 0x22u;  /* 34 = 2(82 20) + 32(secret) */
    state.extra[2] = 0x82u;  /* TAG_RESPONSE */
    state.extra[3] = 0x20u;  /* 32 bytes */
    for (k = 4u; k < 4u + FAKE_SHARED_LEN; k++) {
        state.extra[k] = 0xABu;
    }
    state.extra_len = 4u + FAKE_SHARED_LEN;

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: piv_ecdh_apdu (open_mock failed: %d)\n", rc);
        return 1;
    }

    rc = wp11_piv_ecdh(ccid, WP11_PIV_SLOT_KEYMGMT, WP11_PIV_ALG_EC_P256,
                       peer_pub, sizeof(peer_pub), shared, &sharedlen);
    wp11_ccid_close(ccid);

    f += check(rc == WP11_PIV_OK,
               "piv_ecdh_apdu: returns WP11_PIV_OK");

    /* Verify APDU header bytes:
     *   [0]=00 [1]=87 [2]=11 [3]=9D [4]=47 [5]=7C [6]=45
     *   [7]=82 [8]=00 [9]=85 */
    f += check(state.captured_len >= 10u &&
               state.captured[0] == 0x00u &&   /* CLA */
               state.captured[1] == 0x87u &&   /* INS GEN_AUTH */
               state.captured[2] == 0x11u &&   /* P1 = EC P-256 alg */
               state.captured[3] == 0x9Du &&   /* P2 = KEYMGMT slot */
               state.captured[4] == 0x47u &&   /* Lc = 71 */
               state.captured[5] == 0x7Cu &&   /* TAG_DAT */
               state.captured[6] == 0x45u &&   /* dat_content_len = 69 */
               state.captured[7] == 0x82u &&   /* TAG_RESPONSE */
               state.captured[8] == 0x00u &&   /* empty */
               state.captured[9] == 0x85u,     /* TAG_EXPONENT (not 0x81) */
               "piv_ecdh_apdu: APDU header matches SP 800-73-4 sec.3.2.4 (tag 0x85)");

    f += check(sharedlen == FAKE_SHARED_LEN,
               "piv_ecdh_apdu: sharedlen == 32");

    {
        int all_ab = 1;
        for (k = 0; k < FAKE_SHARED_LEN; k++) {
            if (shared[k] != 0xABu) { all_ab = 0; break; }
        }
        f += check(all_ab,
                   "piv_ecdh_apdu: shared secret bytes match mock response");
    }

    return f;
}

/* -------------------------------------------------------------------------
 * tlv_expect error paths
 *
 * The following eight tests exercise the three tlv_expect()-refactored sites
 * (wp11_piv_sign, wp11_piv_ecdh, wp11_piv_get_cert) with malformed response
 * bodies constructed from first principles.  They act as independent oracles
 * for tlv_expect() since the helper is static and not directly callable.
 *
 * SP 800-73-4 Section 3.2.4, Table 13 (sign/ecdh); Section 3.1.2 (cert).
 * ---------------------------------------------------------------------- */

/* sign: wrong outer tag (0xFF instead of 0x7C) -> ERR_ENCODING */
static int test_tlv_sign_wrong_outer_tag(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          challenge[16];
    uint8_t          sig[64];
    size_t           siglen = sizeof(sig);
    int              rc;

    (void)memset(challenge, 0x01u, sizeof(challenge));
    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;
    /* Wrong outer tag: 0xFF instead of TAG_DAT (0x7C) */
    state.extra[0] = 0xFFu;
    state.extra[1] = 0x06u;
    state.extra[2] = 0x82u;
    state.extra[3] = 0x04u;
    state.extra[4] = 0xAAu;
    state.extra[5] = 0xBBu;
    state.extra[6] = 0xCCu;
    state.extra[7] = 0xDDu;
    state.extra_len = 8u;

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: tlv_sign_wrong_outer_tag (open_mock failed)\n");
        return 1;
    }
    rc = wp11_piv_sign(ccid, WP11_PIV_SLOT_SIGN, WP11_PIV_ALG_EC_P256,
                       challenge, sizeof(challenge), sig, &siglen);
    wp11_ccid_close(ccid);

    return check(rc == WP11_PIV_ERR_ENCODING,
                 "tlv_sign_wrong_outer_tag: 0xFF outer -> WP11_PIV_ERR_ENCODING");
}

/* sign: wrong inner tag (0xFF instead of 0x82) -> ERR_SW */
static int test_tlv_sign_wrong_inner_tag(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          challenge[16];
    uint8_t          sig[64];
    size_t           siglen = sizeof(sig);
    int              rc;

    (void)memset(challenge, 0x02u, sizeof(challenge));
    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;
    /* Outer 7C is correct; inner tag 0xFF instead of TAG_RESPONSE (0x82) */
    state.extra[0] = 0x7Cu;
    state.extra[1] = 0x06u;
    state.extra[2] = 0xFFu;  /* wrong inner tag */
    state.extra[3] = 0x04u;
    state.extra[4] = 0xAAu;
    state.extra[5] = 0xBBu;
    state.extra[6] = 0xCCu;
    state.extra[7] = 0xDDu;
    state.extra_len = 8u;

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: tlv_sign_wrong_inner_tag (open_mock failed)\n");
        return 1;
    }
    rc = wp11_piv_sign(ccid, WP11_PIV_SLOT_SIGN, WP11_PIV_ALG_EC_P256,
                       challenge, sizeof(challenge), sig, &siglen);
    wp11_ccid_close(ccid);

    return check(rc == WP11_PIV_ERR_SW,
                 "tlv_sign_wrong_inner_tag: 0xFF inner -> WP11_PIV_ERR_SW");
}

/* sign: outer container length overruns response -> ERR_ENCODING */
static int test_tlv_sign_outer_overrun(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          challenge[16];
    uint8_t          sig[64];
    size_t           siglen = sizeof(sig);
    int              rc;

    (void)memset(challenge, 0x03u, sizeof(challenge));
    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;
    /* 7C claims len=16 but only 2 bytes follow */
    state.extra[0] = 0x7Cu;
    state.extra[1] = 0x10u;  /* claims 16 bytes of container content */
    state.extra[2] = 0x82u;
    state.extra[3] = 0x04u;
    state.extra_len = 4u;    /* only 2 bytes actually present */

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: tlv_sign_outer_overrun (open_mock failed)\n");
        return 1;
    }
    rc = wp11_piv_sign(ccid, WP11_PIV_SLOT_SIGN, WP11_PIV_ALG_EC_P256,
                       challenge, sizeof(challenge), sig, &siglen);
    wp11_ccid_close(ccid);

    return check(rc == WP11_PIV_ERR_ENCODING,
                 "tlv_sign_outer_overrun: outer len > available -> WP11_PIV_ERR_ENCODING");
}

/* sign: inner value length overruns outer container -> ERR_ENCODING */
static int test_tlv_sign_inner_overrun(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          challenge[16];
    uint8_t          sig[64];
    size_t           siglen = sizeof(sig);
    int              rc;

    (void)memset(challenge, 0x04u, sizeof(challenge));
    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;
    /* 7C len=6, 82 claims len=15 but outer container ends at 6 bytes */
    state.extra[0] = 0x7Cu;
    state.extra[1] = 0x06u;  /* outer container: 6 bytes */
    state.extra[2] = 0x82u;
    state.extra[3] = 0x0Fu;  /* inner claims 15 bytes, but only 4 bytes left */
    state.extra[4] = 0xAAu;
    state.extra[5] = 0xBBu;
    state.extra[6] = 0xCCu;
    state.extra[7] = 0xDDu;
    state.extra_len = 8u;

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: tlv_sign_inner_overrun (open_mock failed)\n");
        return 1;
    }
    rc = wp11_piv_sign(ccid, WP11_PIV_SLOT_SIGN, WP11_PIV_ALG_EC_P256,
                       challenge, sizeof(challenge), sig, &siglen);
    wp11_ccid_close(ccid);

    return check(rc == WP11_PIV_ERR_ENCODING,
                 "tlv_sign_inner_overrun: inner len > container -> WP11_PIV_ERR_ENCODING");
}

/* ecdh: wrong outer tag -> ERR_SW */
static int test_tlv_ecdh_wrong_outer_tag(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          peer_pub[65];
    uint8_t          shared[32];
    size_t           sharedlen = sizeof(shared);
    int              rc;

    (void)memset(peer_pub, 0x00u, sizeof(peer_pub));
    peer_pub[0] = 0x04u;
    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;
    /* Wrong outer tag: 0xFF instead of TAG_DAT (0x7C) */
    state.extra[0] = 0xFFu;
    state.extra[1] = 0x06u;
    state.extra[2] = 0x82u;
    state.extra[3] = 0x04u;
    state.extra[4] = 0xAAu;
    state.extra[5] = 0xBBu;
    state.extra[6] = 0xCCu;
    state.extra[7] = 0xDDu;
    state.extra_len = 8u;

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: tlv_ecdh_wrong_outer_tag (open_mock failed)\n");
        return 1;
    }
    rc = wp11_piv_ecdh(ccid, WP11_PIV_SLOT_KEYMGMT, WP11_PIV_ALG_EC_P256,
                       peer_pub, sizeof(peer_pub), shared, &sharedlen);
    wp11_ccid_close(ccid);

    return check(rc == WP11_PIV_ERR_SW,
                 "tlv_ecdh_wrong_outer_tag: 0xFF outer -> WP11_PIV_ERR_SW");
}

/* ecdh: wrong inner tag -> ERR_SW */
static int test_tlv_ecdh_wrong_inner_tag(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          peer_pub[65];
    uint8_t          shared[32];
    size_t           sharedlen = sizeof(shared);
    int              rc;

    (void)memset(peer_pub, 0x00u, sizeof(peer_pub));
    peer_pub[0] = 0x04u;
    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;
    /* Correct outer 7C; inner tag 0xFF instead of TAG_RESPONSE (0x82) */
    state.extra[0] = 0x7Cu;
    state.extra[1] = 0x06u;
    state.extra[2] = 0xFFu;  /* wrong inner tag */
    state.extra[3] = 0x04u;
    state.extra[4] = 0xAAu;
    state.extra[5] = 0xBBu;
    state.extra[6] = 0xCCu;
    state.extra[7] = 0xDDu;
    state.extra_len = 8u;

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: tlv_ecdh_wrong_inner_tag (open_mock failed)\n");
        return 1;
    }
    rc = wp11_piv_ecdh(ccid, WP11_PIV_SLOT_KEYMGMT, WP11_PIV_ALG_EC_P256,
                       peer_pub, sizeof(peer_pub), shared, &sharedlen);
    wp11_ccid_close(ccid);

    return check(rc == WP11_PIV_ERR_SW,
                 "tlv_ecdh_wrong_inner_tag: 0xFF inner -> WP11_PIV_ERR_SW");
}

/* get_cert: wrong outer tag -> ERR_ENCODING */
static int test_tlv_get_cert_wrong_outer_tag(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          cert[256];
    size_t           certlen = sizeof(cert);
    int              rc;

    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;
    /* Wrong outer tag: 0xFF instead of 0x53 */
    state.extra[0] = 0xFFu;  /* wrong outer tag */
    state.extra[1] = 0x06u;
    state.extra[2] = 0x70u;
    state.extra[3] = 0x04u;
    state.extra[4] = 0xAAu;
    state.extra[5] = 0xBBu;
    state.extra[6] = 0xCCu;
    state.extra[7] = 0xDDu;
    state.extra_len = 8u;

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: tlv_get_cert_wrong_outer_tag (open_mock failed)\n");
        return 1;
    }
    rc = wp11_piv_get_cert(ccid, WP11_PIV_SLOT_AUTH, cert, &certlen);
    wp11_ccid_close(ccid);

    return check(rc == WP11_PIV_ERR_ENCODING,
                 "tlv_get_cert_wrong_outer_tag: 0xFF outer -> WP11_PIV_ERR_ENCODING");
}

/* get_cert: wrong inner tag -> ERR_ENCODING
 * SP 800-73-4 Section 3.1.2: inner tag must be 0x70 (Certificate). */
static int test_tlv_get_cert_wrong_inner_tag(void)
{
    mock_state_t     state;
    wp11_ccid_ctx_t *ccid = NULL;
    uint8_t          cert[256];
    size_t           certlen = sizeof(cert);
    int              rc;
    size_t           k;

    (void)memset(&state, 0, sizeof(state));
    state.sw1 = 0x90u;
    state.sw2 = 0x00u;
    /* Outer 0x53, len=10; inner tag 0xFF (wrong) instead of 0x70, len=8 */
    state.extra[0] = 0x53u;  /* correct outer tag */
    state.extra[1] = 0x0Au;  /* outer len = 10 */
    state.extra[2] = 0xFFu;  /* wrong inner tag */
    state.extra[3] = 0x08u;  /* inner len = 8 */
    for (k = 4u; k < 12u; k++) { state.extra[k] = 0xABu; }
    state.extra_len = 12u;

    rc = wp11_ccid_open_mock(mock_transport, &state, &ccid);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: tlv_get_cert_wrong_inner_tag (open_mock failed)\n");
        return 1;
    }
    rc = wp11_piv_get_cert(ccid, WP11_PIV_SLOT_AUTH, cert, &certlen);
    wp11_ccid_close(ccid);

    return check(rc == WP11_PIV_ERR_ENCODING,
                 "tlv_get_cert_wrong_inner_tag: 0xFF inner -> WP11_PIV_ERR_ENCODING");
}

/* -------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */

int wp11_test_piv(void)
{
    int failures = 0;

    failures += test_vector_file_nonempty();
    failures += test_select_aid_apdu();
    failures += test_verify_pin_apdu();
    failures += test_general_authenticate_p256_apdu();
    failures += test_pin_bad_sw();
    failures += test_pin_locked_sw();
    failures += test_rsa2048_response_parsing();
    failures += test_ber_malformed_response();
    failures += test_ber_truncated_length();
    failures += test_ber_encode_7c_long_form();
    failures += test_ber_encode_81_long_form();
    failures += test_ber_challengelen_too_large();
    failures += test_generate_keypair_ec_p256_apdu();
    failures += test_generate_keypair_bad_sw();
    failures += test_piv_attest_apdu();
    failures += test_piv_ecdh_apdu();
    failures += test_tlv_sign_wrong_outer_tag();
    failures += test_tlv_sign_wrong_inner_tag();
    failures += test_tlv_sign_outer_overrun();
    failures += test_tlv_sign_inner_overrun();
    failures += test_tlv_ecdh_wrong_outer_tag();
    failures += test_tlv_ecdh_wrong_inner_tag();
    failures += test_tlv_get_cert_wrong_outer_tag();
    failures += test_tlv_get_cert_wrong_inner_tag();

    return failures;
}

#else /* WOLFP11_CFG_TEST not defined */

int wp11_test_piv(void)
{
    return 0;
}

#endif /* WOLFP11_CFG_TEST */
