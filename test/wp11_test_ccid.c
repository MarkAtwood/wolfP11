/* wp11_test_ccid.c -- unit tests for the CCID transport layer
 *
 * All tests use the mock transport; no libusb or real hardware is required.
 */

#ifdef WOLFP11_CFG_TEST

#include "wolfp11/wp11_ccid.h"
#include "test/wp11_test_ccid.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* -------------------------------------------------------------------------
 * Shared mock infrastructure
 * ---------------------------------------------------------------------- */

#define CCID_HEADER_LEN 10

typedef struct {
    uint8_t  resp_frame[512];   /* pre-built RDR_to_PC_DataBlock frame     */
    size_t   resp_len;          /* total frame length including header      */
    uint8_t  captured_out[512]; /* copy of last outgoing frame              */
    size_t   captured_outlen;   /* length of last outgoing frame            */
    int      call_count;        /* number of times mock was invoked         */
} mock_state_t;

/* Build a valid RDR_to_PC_DataBlock frame into dst.
 * bSeq is set to seq_placeholder; the actual mock callback will patch it
 * to echo the request's bSeq.
 * abData is data[0..datalen-1]; bStatus is status_byte. */
static size_t build_response(uint8_t *dst,
                              const uint8_t *data, size_t datalen,
                              uint8_t status_byte)
{
    uint32_t dw = (uint32_t)datalen;

    dst[0]  = 0x80u;                              /* bMessageType          */
    dst[1]  = (uint8_t)(dw        & 0xFFu);       /* dwLength lo           */
    dst[2]  = (uint8_t)((dw >>  8) & 0xFFu);
    dst[3]  = (uint8_t)((dw >> 16) & 0xFFu);
    dst[4]  = (uint8_t)((dw >> 24) & 0xFFu);
    dst[5]  = 0x00u;                              /* bSlot                 */
    dst[6]  = 0x00u;                              /* bSeq -- patched live   */
    dst[7]  = status_byte;                        /* bStatus               */
    dst[8]  = 0x00u;                              /* bError                */
    dst[9]  = 0x00u;                              /* bChainParameter       */
    if (datalen > 0u && data != NULL) {
        memcpy(&dst[10], data, datalen);
    }
    return CCID_HEADER_LEN + datalen;
}

/* Generic mock callback: copies the outgoing frame, patches bSeq into the
 * pre-built response frame, then returns it. */
static int mock_transport(void *ud,
                          const uint8_t *out, size_t outlen,
                          uint8_t       *in,  size_t *inlen)
{
    mock_state_t *s = (mock_state_t *)ud;

    memcpy(s->captured_out, out, outlen);
    s->captured_outlen = outlen;
    s->call_count++;

    /* Echo the request bSeq into the response so the seq check passes. */
    s->resp_frame[6] = out[6];

    memcpy(in, s->resp_frame, s->resp_len);
    *inlen = s->resp_len;
    return 0;
}

/* -------------------------------------------------------------------------
 * Test 1: correct bMessageType and dwLength in outgoing frame
 * ---------------------------------------------------------------------- */

static int test_frame_format(void)
{
    wp11_ccid_ctx_t *ctx = NULL;
    mock_state_t     s;
    uint8_t          apdu[]  = { 0x00u, 0xA4u, 0x04u, 0x00u, 0x05u,
                                 0xA0u, 0x00u, 0x00u, 0x03u, 0x08u };
    uint8_t          sw[]    = { 0x90u, 0x00u };
    uint8_t          resp[64];
    size_t           resplen = sizeof(resp);
    uint32_t         dw_got;
    int              rc;

    memset(&s, 0, sizeof(s));
    s.resp_len = build_response(s.resp_frame, sw, sizeof(sw), 0x00u);

    rc = wp11_ccid_open_mock(mock_transport, &s, &ctx);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: ccid frame format -- open_mock returned %d\n", rc);
        return 1;
    }

    rc = wp11_ccid_apdu(ctx, apdu, sizeof(apdu), resp, &resplen);
    wp11_ccid_close(ctx);

    if (rc != WP11_CCID_OK) {
        printf("FAIL: ccid frame format -- apdu returned %d\n", rc);
        return 1;
    }

    /* Check bMessageType at byte [0] */
    if (s.captured_out[0] != 0x6Fu) {
        printf("FAIL: ccid frame bMessageType -- got 0x%02X, want 0x6F\n",
               s.captured_out[0]);
        return 1;
    }

    /* Check dwLength at bytes [1..4] encodes APDU length as little-endian */
    dw_got = ((uint32_t)s.captured_out[1])
           | ((uint32_t)s.captured_out[2] <<  8)
           | ((uint32_t)s.captured_out[3] << 16)
           | ((uint32_t)s.captured_out[4] << 24);
    if (dw_got != (uint32_t)sizeof(apdu)) {
        printf("FAIL: ccid frame dwLength -- got %u, want %u\n",
               (unsigned)dw_got, (unsigned)sizeof(apdu));
        return 1;
    }

    printf("PASS: ccid frame bMessageType\n");
    printf("PASS: ccid frame dwLength little-endian\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * Test 2: bSeq increments across successive calls
 * ---------------------------------------------------------------------- */

/* Each call needs its own captured bSeq.  We store them in order. */
typedef struct {
    uint8_t seq_captured[3];
    int     call_count;
    uint8_t sw[2];
    uint8_t resp_frame[512];
    size_t  resp_len;
} seq_state_t;

static int seq_mock_transport(void *ud,
                              const uint8_t *out, size_t outlen,
                              uint8_t       *in,  size_t *inlen)
{
    seq_state_t *s = (seq_state_t *)ud;
    int          idx = s->call_count;

    (void)outlen;

    if (idx < 3) {
        s->seq_captured[idx] = out[6];
    }
    s->call_count++;

    /* Patch bSeq and return the pre-built success frame */
    s->resp_frame[6] = out[6];
    memcpy(in, s->resp_frame, s->resp_len);
    *inlen = s->resp_len;
    return 0;
}

static int test_seq_increments(void)
{
    wp11_ccid_ctx_t *ctx = NULL;
    seq_state_t      s;
    uint8_t          apdu[] = { 0x00u, 0xC0u, 0x00u, 0x00u, 0x00u };
    uint8_t          sw[]   = { 0x90u, 0x00u };
    uint8_t          resp[64];
    size_t           resplen;
    int              rc, i, fail = 0;

    memset(&s, 0, sizeof(s));
    s.sw[0] = 0x90u;
    s.sw[1] = 0x00u;
    s.resp_len = build_response(s.resp_frame, sw, sizeof(sw), 0x00u);

    rc = wp11_ccid_open_mock(seq_mock_transport, &s, &ctx);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: ccid seq increment -- open_mock returned %d\n", rc);
        return 1;
    }

    for (i = 0; i < 3; i++) {
        resplen = sizeof(resp);
        rc = wp11_ccid_apdu(ctx, apdu, sizeof(apdu), resp, &resplen);
        if (rc != WP11_CCID_OK) {
            printf("FAIL: ccid seq increment -- call %d returned %d\n", i, rc);
            fail++;
        }
    }

    wp11_ccid_close(ctx);

    if (fail) {
        return fail;
    }

    for (i = 0; i < 3; i++) {
        if (s.seq_captured[i] != (uint8_t)i) {
            printf("FAIL: ccid seq increment -- call %d bSeq=%u, want %d\n",
                   i, (unsigned)s.seq_captured[i], i);
            fail++;
        }
    }

    if (!fail) {
        printf("PASS: ccid bSeq increments\n");
    }
    return fail;
}

/* -------------------------------------------------------------------------
 * Test 3: bStatus != 0 returns WP11_CCID_ERR_STATUS
 * ---------------------------------------------------------------------- */

static int test_bstatus_error(void)
{
    wp11_ccid_ctx_t *ctx = NULL;
    mock_state_t     s;
    uint8_t          apdu[] = { 0x00u, 0xC0u, 0x00u, 0x00u, 0x00u };
    uint8_t          resp[64];
    size_t           resplen = sizeof(resp);
    int              rc;

    memset(&s, 0, sizeof(s));
    /* Build a response with bStatus = 0x40 (error) and no data */
    s.resp_len = build_response(s.resp_frame, NULL, 0u, 0x40u);

    rc = wp11_ccid_open_mock(mock_transport, &s, &ctx);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: ccid bStatus error -- open_mock returned %d\n", rc);
        return 1;
    }

    rc = wp11_ccid_apdu(ctx, apdu, sizeof(apdu), resp, &resplen);
    wp11_ccid_close(ctx);

    if (rc != WP11_CCID_ERR_STATUS) {
        printf("FAIL: ccid bStatus error -- got %d, want %d\n",
               rc, WP11_CCID_ERR_STATUS);
        return 1;
    }

    printf("PASS: ccid bStatus error returns WP11_CCID_ERR_STATUS\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * Test 4: response APDU bytes extracted correctly
 * ---------------------------------------------------------------------- */

static int test_response_data(void)
{
    wp11_ccid_ctx_t *ctx = NULL;
    mock_state_t     s;
    uint8_t          apdu[] = { 0x00u, 0xC0u, 0x00u, 0x00u, 0x00u };
    uint8_t          sw[]   = { 0x90u, 0x00u };
    uint8_t          resp[64];
    size_t           resplen = sizeof(resp);
    int              rc, fail = 0;

    memset(&s, 0, sizeof(s));
    s.resp_len = build_response(s.resp_frame, sw, sizeof(sw), 0x00u);

    rc = wp11_ccid_open_mock(mock_transport, &s, &ctx);
    if (rc != WP11_CCID_OK) {
        printf("FAIL: ccid response data -- open_mock returned %d\n", rc);
        return 1;
    }

    rc = wp11_ccid_apdu(ctx, apdu, sizeof(apdu), resp, &resplen);
    wp11_ccid_close(ctx);

    if (rc != WP11_CCID_OK) {
        printf("FAIL: ccid response data -- apdu returned %d\n", rc);
        return 1;
    }

    if (resplen != 2u) {
        printf("FAIL: ccid response data -- resplen=%u, want 2\n",
               (unsigned)resplen);
        fail++;
    }

    if (resplen >= 2u && (resp[0] != 0x90u || resp[1] != 0x00u)) {
        printf("FAIL: ccid response data -- bytes 0x%02X 0x%02X, want 0x90 0x00\n",
               resp[0], resp[1]);
        fail++;
    }

    if (!fail) {
        printf("PASS: ccid response APDU extracted correctly\n");
    }
    return fail;
}

/* -------------------------------------------------------------------------
 * Test entry point
 * ---------------------------------------------------------------------- */

int wp11_test_ccid(void)
{
    int failures = 0;

    failures += test_frame_format();
    failures += test_seq_increments();
    failures += test_bstatus_error();
    failures += test_response_data();

    return failures;
}

#endif /* WOLFP11_CFG_TEST */
