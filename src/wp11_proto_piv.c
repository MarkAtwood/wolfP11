/* wp11_proto_piv.c -- wolfP11 PIV protocol implementation
 *
 * Implements NIST SP 800-73-4 PIV applet APDU sequences over CCID transport.
 *
 * This file constructs APDUs and sends them via wp11_ccid_apdu.
 * It does NOT parse certificates or perform cryptographic operations --
 * those are wolfCrypt's responsibility.
 *
 * Reference: NIST SP 800-73-4
 */

#include "wolfp11/wp11_proto_piv.h"
#include "wolfp11/wp11_ccid.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* -------------------------------------------------------------------------
 * Internal constants
 * ---------------------------------------------------------------------- */

/* Maximum APDU command buffer: header(5) + 255 data + Le(1) */
#define PIV_APDU_MAX_CMD    261

/* Maximum APDU response buffer.
 * RSA-2048 GENERAL AUTHENTICATE responses carry 256-byte signatures with
 * 3-byte BER-TLV length fields, totalling 266 bytes (1+3 outer tag/len +
 * 1+3 inner tag/len + 256 sig + 2 SW).  512 gives comfortable headroom
 * for all GENERAL AUTHENTICATE and VERIFY PIN responses.
 *
 * For wp11_piv_get_cert, the initial GET DATA and each GET RESPONSE chunk
 * returns at most 256 bytes of data plus 2 bytes of SW; 512 is therefore
 * sufficient per APDU exchange.  Chunks are accumulated into a separate
 * WP11_PIV_CERT_MAX_LEN-byte heap buffer via GET RESPONSE chaining. */
#define PIV_APDU_MAX_RESP   512

/* PIV PIN is always padded to exactly 8 bytes */
#define PIV_PIN_PADDED_LEN  8

/* ISO 7816 class byte for all PIV commands */
#define PIV_CLA             0x00u

/* PIV instruction bytes */
#define PIV_INS_SELECT       0xA4u
#define PIV_INS_VERIFY       0x20u
#define PIV_INS_GEN_AUTH     0x87u
#define PIV_INS_GET_DATA     0xCBu
#define PIV_INS_GET_RESPONSE 0xC0u  /* ISO 7816-4 sec.7.6.1 GET RESPONSE */
#define PIV_INS_GEN_KEYPAIR  0x47u
#define PIV_INS_ATTEST       0xF9u  /* YubiKey attestation (INS 0xF9)  */

/* SW1/SW2 values */
#define SW1_SUCCESS         0x90u
#define SW2_SUCCESS         0x00u
#define SW1_PIN_RETRIES     0x63u   /* SW2 low nibble = retries remaining */
#define SW1_AUTH_BLOCKED    0x69u
#define SW2_PIN_LOCKED      0x83u
#define SW1_NOT_FOUND       0x6Au
#define SW2_FILE_NOT_FOUND  0x82u
#define SW1_MORE_DATA       0x61u   /* ISO 7816-4 sec.7.6.1: more data available */

/* BER-TLV tags used in GENERAL AUTHENTICATE */
#define TAG_DAT             0x7Cu   /* Dynamic Authentication Template */
#define TAG_RESPONSE        0x82u   /* Response field (output) */
#define TAG_CHALLENGE       0x81u   /* Challenge field (input -- sign) */
#define TAG_EXPONENT        0x85u   /* Exponentiation component (input -- ECDH) */

/* -------------------------------------------------------------------------
 * ber_len_decode -- decode a BER-TLV length field per ISO 7816-4 Section 5.2.2
 *
 * Supports:
 *   Short form:         buf[0] in 0x00..0x7F -> val = buf[0], consumed = 1
 *   One-byte long form: buf[0] = 0x81, val = buf[1], consumed = 2
 *   Two-byte long form: buf[0] = 0x82, val = (buf[1]<<8)|buf[2], consumed = 3
 *
 * Does NOT support:
 *   0x80 -- indefinite length (not permitted in PIV/PKCS#11 context)
 *   0x83..0xFE -- lengths requiring >2 follow-on bytes (not used in PIV)
 *   0xFF -- reserved
 *
 * Returns 0 on success, -1 on error (truncated buffer or unsupported form).
 * On success, *val and *consumed are set.
 * On error, *val and *consumed are undefined.
 *
 * Defensive: all array accesses validated against buflen before use.
 * ---------------------------------------------------------------------- */

static int ber_len_decode(const uint8_t *buf, size_t buflen,
                          size_t *val, size_t *consumed)
{
    if (buf == NULL || val == NULL || consumed == NULL || buflen == 0u) {
        return -1;
    }

    if (buf[0] <= 0x7Fu) {
        /* Short form: single byte carries the length value directly */
        *val      = (size_t)buf[0];
        *consumed = 1u;
        return 0;
    }
    if (buf[0] == 0x81u) {
        /* One-byte long form: next byte is the length */
        if (buflen < 2u) {
            return -1; /* truncated */
        }
        *val      = (size_t)buf[1];
        *consumed = 2u;
        return 0;
    }
    if (buf[0] == 0x82u) {
        /* Two-byte long form: next two bytes are the length, big-endian */
        if (buflen < 3u) {
            return -1; /* truncated */
        }
        *val      = ((size_t)buf[1] << 8) | (size_t)buf[2];
        *consumed = 3u;
        return 0;
    }
    /* 0x80 (indefinite), 0x83-0xFE (>2 length bytes), 0xFF (reserved):
     * none of these appear in SP 800-73-4 responses; treat as encoding error */
    return -1;
}

/* -------------------------------------------------------------------------
 * Internal helper: extract SW1/SW2 from a response buffer
 * ---------------------------------------------------------------------- */

static void piv_get_sw(const uint8_t *resp, size_t resplen,
                       uint8_t *sw1, uint8_t *sw2)
{
    /* All callers pre-check resplen >= 2, but defend internally against future
     * callers that omit the guard.  SW 0x0000 is not a valid ISO 7816 status
     * word and will be caught by callers as WP11_PIV_ERR_SW. */
    if (resplen < 2u) { *sw1 = 0u; *sw2 = 0u; return; }
    *sw1 = resp[resplen - 2u];
    *sw2 = resp[resplen - 1u];
}

/* -------------------------------------------------------------------------
 * piv_sw_to_err -- map ISO 7816 / SP 800-73-4 SW codes to typed error values
 *
 * SP 800-73-4 sec.3.2.4, ISO 7816-4 sec.5.1.3.
 * Called for any non-9000 SW that is not handled inline (e.g., 63 Cx, 6A 82).
 * ---------------------------------------------------------------------- */
static int piv_sw_to_err(uint8_t sw1, uint8_t sw2)
{
    /* SW 69 85: conditions of use not satisfied.
     * YubiKey: user did not touch within the touch-confirmation window.
     * Also returned if PIN verification is required before the crypto op. */
    if (sw1 == 0x69u && sw2 == 0x85u) return WP11_PIV_ERR_USER_PRESENCE;
    /* SW 69 82: security status not satisfied (PIN not verified). */
    if (sw1 == 0x69u && sw2 == 0x82u) return WP11_PIV_ERR_SECURITY_STATUS;
    /* SW 6A 81: function not supported (wrong algorithm or unsupported slot). */
    if (sw1 == 0x6Au && sw2 == 0x81u) return WP11_PIV_ERR_NOT_SUPPORTED;
    /* SW 6A 88: reference data not found (key slot is empty). */
    if (sw1 == 0x6Au && sw2 == 0x88u) return WP11_PIV_ERR_NOT_FOUND;
    return WP11_PIV_ERR_SW;
}

/* -------------------------------------------------------------------------
 * wp11_piv_select -- SELECT PIV AID (SP 800-73-4 Section 2.2)
 *
 * APDU: 00 A4 04 00 0B [AID: A0 00 00 03 08 00 00 10 00 01 00]
 * ---------------------------------------------------------------------- */

int wp11_piv_select(wp11_ccid_ctx_t *ccid)
{
    uint8_t cmd[PIV_APDU_MAX_CMD];
    uint8_t resp[PIV_APDU_MAX_RESP];
    size_t  cmdlen;
    size_t  resplen = sizeof(resp);
    uint8_t sw1;
    uint8_t sw2;
    int     rc;

    if (ccid == NULL) {
        return WP11_PIV_ERR_PARAM;
    }

    /* Build SELECT APDU */
    cmdlen = 0;
    cmd[cmdlen++] = PIV_CLA;
    cmd[cmdlen++] = PIV_INS_SELECT;
    cmd[cmdlen++] = 0x04u;              /* P1: select by DF name */
    cmd[cmdlen++] = 0x00u;              /* P2 */
    cmd[cmdlen++] = WP11_PIV_AID_LEN;  /* Lc */
    (void)memcpy(&cmd[cmdlen], WP11_PIV_AID, WP11_PIV_AID_LEN);
    cmdlen += WP11_PIV_AID_LEN;

    rc = wp11_ccid_apdu(ccid, cmd, cmdlen, resp, &resplen);
    if (rc != WP11_CCID_OK) {
        return WP11_PIV_ERR_TRANSPORT;
    }
    /* SW1/SW2 are the final 2 bytes of every PIV response.
     * A response shorter than 2 bytes indicates transport truncation,
     * not a card error -- treat separately to avoid size_t underflow. */
    if (resplen < 2u) {
        return WP11_PIV_ERR_TRUNCATED;
    }

    piv_get_sw(resp, resplen, &sw1, &sw2);

    if (sw1 != SW1_SUCCESS || sw2 != SW2_SUCCESS) {
        return WP11_PIV_ERR_SW;
    }

    /* SP 800-73-4 sec.2.3.1 / ISO 7816-4 sec.7.1.1: If SELECT returns a response
     * body, scan it for tag 0x84 (DF name = AID).  If found, it must match
     * the PIV AID.  An empty body (just SW 9000) is also valid -- not all
     * tokens return FCI.  This prevents silent applet confusion on
     * multi-applet tokens that return 9000 for any SELECT. */
    if (resplen > 2u) {
        size_t body_len = resplen - 2u;
        size_t pos = 0;
        /* Skip outer FCI template tag (0x6F or 0x61) and its length field */
        if (pos < body_len && (resp[pos] == 0x6Fu || resp[pos] == 0x61u)) {
            size_t skip_len;
            size_t skip_consumed;
            pos++;
            if (pos < body_len &&
                ber_len_decode(resp + pos, body_len - pos,
                               &skip_len, &skip_consumed) == 0) {
                pos += skip_consumed;
            }
        }
        /* Linear scan for tag 0x84 (DF name) */
        while (pos + 1u <= body_len) {
            uint8_t tag = resp[pos++];
            size_t  tlen;
            size_t  tconsumed;
            if (pos >= body_len) break;
            if (ber_len_decode(resp + pos, body_len - pos,
                               &tlen, &tconsumed) < 0) break;
            pos += tconsumed;
            if (pos + tlen > body_len) break;
            if (tag == 0x84u) {
                /* Found DF name -- must match the PIV AID exactly */
                if (tlen != WP11_PIV_AID_LEN ||
                    memcmp(resp + pos, WP11_PIV_AID, WP11_PIV_AID_LEN) != 0) {
                    return WP11_PIV_ERR_SW; /* Wrong applet selected */
                }
                break;
            }
            pos += tlen;
        }
    }

    return WP11_PIV_OK;
}

/* -------------------------------------------------------------------------
 * wp11_piv_verify_pin -- VERIFY PIV PIN (SP 800-73-4 Section 3.2.1)
 *
 * APDU: 00 20 00 80 08 [PIN padded to 8 bytes with 0xFF]
 * ---------------------------------------------------------------------- */

int wp11_piv_verify_pin(wp11_ccid_ctx_t *ccid,
                        const uint8_t   *pin, size_t pinlen)
{
    uint8_t cmd[PIV_APDU_MAX_CMD];
    uint8_t resp[PIV_APDU_MAX_RESP];
    size_t  cmdlen;
    size_t  resplen = sizeof(resp);
    uint8_t sw1;
    uint8_t sw2;
    int     rc;

    if (ccid == NULL || pin == NULL || pinlen < 4u || pinlen > 8u) {
        return WP11_PIV_ERR_PARAM;
    }

    /* Build VERIFY APDU header */
    cmdlen = 0;
    cmd[cmdlen++] = PIV_CLA;
    cmd[cmdlen++] = PIV_INS_VERIFY;
    cmd[cmdlen++] = 0x00u;                  /* P1 */
    cmd[cmdlen++] = 0x80u;                  /* P2: PIV card application PIN */
    cmd[cmdlen++] = PIV_PIN_PADDED_LEN;     /* Lc: always 8 */

    /* Copy PIN bytes then pad the remainder with 0xFF */
    (void)memcpy(&cmd[cmdlen], pin, pinlen);
    cmdlen += pinlen;
    (void)memset(&cmd[cmdlen], 0xFFu, PIV_PIN_PADDED_LEN - pinlen);
    cmdlen += PIV_PIN_PADDED_LEN - pinlen;

    rc = wp11_ccid_apdu(ccid, cmd, cmdlen, resp, &resplen);
    if (rc != WP11_CCID_OK) {
        return WP11_PIV_ERR_TRANSPORT;
    }
    /* SW1/SW2 are the final 2 bytes of every PIV response.
     * A response shorter than 2 bytes indicates transport truncation,
     * not a card error -- treat separately to avoid size_t underflow. */
    if (resplen < 2u) {
        return WP11_PIV_ERR_TRUNCATED;
    }

    piv_get_sw(resp, resplen, &sw1, &sw2);

    if (sw1 == SW1_SUCCESS && sw2 == SW2_SUCCESS) {
        return WP11_PIV_OK;
    }
    /* SW 63 Cx: wrong PIN, x retries remaining */
    if (sw1 == SW1_PIN_RETRIES && (sw2 & 0xF0u) == 0xC0u) {
        return WP11_PIV_ERR_PIN_BAD;
    }
    /* SW 69 83: PIN blocked */
    if (sw1 == SW1_AUTH_BLOCKED && sw2 == SW2_PIN_LOCKED) {
        return WP11_PIV_ERR_PIN_LOCKED;
    }
    return WP11_PIV_ERR_SW;
}

/* -------------------------------------------------------------------------
 * ber_len_encode -- encode a BER-TLV length field per ISO 7816-4 Section 5.2.2
 *
 * Writes the length value 'val' into buf[] using the appropriate BER form:
 *   Short form (val <= 0x7F):   1 byte
 *   One-byte long form (128..255):  0x81 + 1 byte = 2 bytes
 *   Two-byte long form (256..65535): 0x82 + 2 bytes = 3 bytes
 *
 * buf must have at least 3 bytes of space.
 * Returns the number of bytes written (1, 2, or 3).
 *
 * wolfP11-oki: this is the companion encoder to ber_len_decode.  Prior to
 * this function, wp11_piv_sign used a bare (uint8_t) cast that truncated
 * lengths >= 128 to a single invalid byte (e.g. 0x80 = indefinite-length
 * marker, illegal in PIV per ISO 7816-4 Section 5.2.2). */
static size_t ber_len_encode(uint8_t *buf, size_t val)
{
    if (val <= 0x7Fu) {
        buf[0] = (uint8_t)val;
        return 1u;
    }
    if (val <= 0xFFu) {
        /* One-byte long form */
        buf[0] = 0x81u;
        buf[1] = (uint8_t)val;
        return 2u;
    }
    /* Two-byte long form (supports up to 0xFFFF) */
    buf[0] = 0x82u;
    buf[1] = (uint8_t)(val >> 8);
    buf[2] = (uint8_t)(val & 0xFFu);
    return 3u;
}

/* -------------------------------------------------------------------------
 * wp11_piv_sign -- GENERAL AUTHENTICATE (SP 800-73-4 Section 3.2.4)
 *
 * Builds the Dynamic Authentication Template (DAT) and sends it.
 * Parses the 7C/82 wrapped signature from the response.
 *
 * DAT structure (BER-TLV per ISO 7816-4 Section 5.2.2):
 *   7C [ber_len(dat_content_len)]
 *     82 00                                (empty response template)
 *     81 [ber_len(challengelen)] [bytes]   (challenge field)
 *
 * Short APDU constraint: the full 7C TLV (apdu_data_size) must fit in the
 * 1-byte Lc field (max 255).  With correct BER-TLV encoding this limits
 * challengelen to 247 (challengelen=248 would produce apdu_data_size=256).
 * Derivation:
 *   challenge field: 1(tag) + ber_len_bytes(clen) + clen
 *   dat_content: 2(82 00) + challenge_field
 *   apdu_data:  1(7C) + ber_len_bytes(dat_content) + dat_content
 *   For clen=247: apdu_data = 1 + 2 + 2(82 00) + 1(81) + 2(BER len) + 247 = 255 [x]
 *   For clen=248: apdu_data = 256 > 255 [!]
 * ---------------------------------------------------------------------- */

int wp11_piv_sign(wp11_ccid_ctx_t *ccid,
                  uint8_t          slot,
                  uint8_t          alg,
                  const uint8_t   *challenge, size_t  challengelen,
                  uint8_t         *sig,       size_t *siglen)
{
    uint8_t cmd[PIV_APDU_MAX_CMD];
    uint8_t resp[PIV_APDU_MAX_RESP];
    size_t  cmdlen;
    size_t  resplen = sizeof(resp);
    size_t  dat_content_len;
    size_t  apdu_data_size;     /* full 7C TLV byte count = Lc value */
    size_t  i;
    size_t  data_end;
    uint8_t sw1;
    uint8_t sw2;
    int     rc;
    uint8_t len_buf[3];    /* scratch buffer for ber_len_encode output */
    size_t  len_bytes;     /* number of bytes written by ber_len_encode */

    if (ccid == NULL || challenge == NULL || sig == NULL || siglen == NULL) {
        return WP11_PIV_ERR_PARAM;
    }
    /* wolfP11-oki: the correct short-APDU upper bound is 247, not 255.
     * With proper BER-TLV encoding the 81-field length consumes 2 bytes for
     * challengelen >= 128, pushing apdu_data_size above the 255-byte Lc limit
     * at challengelen = 248.  See derivation in the function comment above. */
    if (challengelen > 247u) {
        return WP11_PIV_ERR_PARAM;
    }

    /* Compute sizes using correct BER-TLV length field widths.
     *
     * Challenge TLV: TAG_CHALLENGE(1) + ber_len(clen) + clen
     *   ber_len(clen) is 1 byte for clen 0..127, 2 bytes for 128..247.
     * dat_content: TAG_RESPONSE(1) + 0x00(1) + challenge TLV
     * apdu_data:   TAG_DAT(1) + ber_len(dat_content_len) + dat_content
     *   ber_len(dat_content_len) is 1 byte for content <= 127, 2 bytes otherwise.
     */
    {
        size_t clen_bw = (challengelen <= 0x7Fu) ? 1u : 2u; /* BER-len bytes for clen */
        dat_content_len = 2u                /* TAG_RESPONSE + 0x00 */
                        + 1u                /* TAG_CHALLENGE */
                        + clen_bw           /* BER-encoded challengelen */
                        + challengelen;
    }
    {
        size_t dlen_bw = (dat_content_len <= 0x7Fu) ? 1u : 2u; /* BER-len bytes for dat_content */
        apdu_data_size = 1u                 /* TAG_DAT */
                       + dlen_bw            /* BER-encoded dat_content_len */
                       + dat_content_len;
    }

    /* Paranoid overflow guard -- the guard above already prevents this
     * for challengelen <= 247, but defend in depth. */
    if (apdu_data_size > 0xFFu ||
        (5u + apdu_data_size + 1u) > sizeof(cmd)) {
        return WP11_PIV_ERR_BUFSIZE;
    }

    /* Build APDU header */
    cmdlen = 0;
    cmd[cmdlen++] = PIV_CLA;
    cmd[cmdlen++] = PIV_INS_GEN_AUTH;
    cmd[cmdlen++] = alg;
    cmd[cmdlen++] = slot;
    cmd[cmdlen++] = (uint8_t)apdu_data_size;  /* Lc: always fits (guard above) */

    /* 7C [ber_len(dat_content_len)] */
    cmd[cmdlen++] = TAG_DAT;
    len_bytes = ber_len_encode(len_buf, dat_content_len);
    (void)memcpy(&cmd[cmdlen], len_buf, len_bytes);
    cmdlen += len_bytes;

    /* 82 00 -- empty response template */
    cmd[cmdlen++] = TAG_RESPONSE;
    cmd[cmdlen++] = 0x00u;

    /* 81 [ber_len(challengelen)] [challenge bytes] */
    cmd[cmdlen++] = TAG_CHALLENGE;
    len_bytes = ber_len_encode(len_buf, challengelen);
    (void)memcpy(&cmd[cmdlen], len_buf, len_bytes);
    cmdlen += len_bytes;
    (void)memcpy(&cmd[cmdlen], challenge, challengelen);
    cmdlen += challengelen;

    /* Le = 0x00 (expect any length) */
    cmd[cmdlen++] = 0x00u;

    rc = wp11_ccid_apdu(ccid, cmd, cmdlen, resp, &resplen);
    if (rc != WP11_CCID_OK) {
        return WP11_PIV_ERR_TRANSPORT;
    }
    /* SW1/SW2 are the final 2 bytes of every PIV response.
     * A response shorter than 2 bytes indicates transport truncation,
     * not a card error -- treat separately to avoid size_t underflow. */
    if (resplen < 2u) {
        return WP11_PIV_ERR_TRUNCATED;
    }

    piv_get_sw(resp, resplen, &sw1, &sw2);

    /* ISO 7816-4 sec.5.1.3: SW 6C xx means wrong Le; retry once with Le=sw2. */
    if (sw1 == 0x6Cu) {
        cmd[cmdlen - 1u] = sw2;  /* patch Le in-place */
        resplen = sizeof(resp);
        rc = wp11_ccid_apdu(ccid, cmd, cmdlen, resp, &resplen);
        if (rc != WP11_CCID_OK) return WP11_PIV_ERR_TRANSPORT;
        if (resplen < 2u)        return WP11_PIV_ERR_TRUNCATED;
        piv_get_sw(resp, resplen, &sw1, &sw2);
        /* If 6C again, fall through to error -- avoid infinite loop */
    }

    if (sw1 != SW1_SUCCESS || sw2 != SW2_SUCCESS) {
        return piv_sw_to_err(sw1, sw2);
    }

    i = 0u;
    /* data_end excludes the trailing SW1/SW2 bytes */
    data_end = resplen - 2u;

    /* SP 800-73-4 Table 13: GENERAL AUTHENTICATE response must contain the
     * 7C/82 BER-TLV structure (at minimum 4 bytes before SW). */
    if (data_end == 0u) {
        return WP11_PIV_ERR_ENCODING;
    }

    /*
     * SP 800-73-4 Section 3.2.4, Table 13:
     * GENERAL AUTHENTICATE response: 7C [len] 82 [siglen] [sig bytes]
     *
     * BER-TLV length fields use ISO 7816-4 Section 5.2.2 encoding:
     *   - RSA-2048: sig = 256 bytes -> lengths encoded as 3 bytes (0x82 0x01 0x00)
     *   - EC P-256:  sig ~= 64 bytes  -> length encoded as 1 byte
     * We use ber_len_decode() for both length fields.
     */

    /* Expect TAG_DAT (0x7C) first */
    if (i >= data_end || resp[i] != TAG_DAT) {
        return WP11_PIV_ERR_SW;
    }
    i++;

    /* Decode 7C container length */
    {
        size_t container_len;
        size_t len_bytes;
        size_t container_end;

        if (ber_len_decode(resp + i, data_end - i,
                           &container_len, &len_bytes) < 0) {
            return WP11_PIV_ERR_ENCODING;
        }
        i += len_bytes;

        /* container must fit within the data region */
        if (container_len > data_end - i) {
            return WP11_PIV_ERR_ENCODING;
        }
        container_end = i + container_len;

        /* Expect TAG_RESPONSE (0x82) inside the 7C container */
        if (i >= container_end || resp[i] != TAG_RESPONSE) {
            return WP11_PIV_ERR_SW;
        }
        i++;

        /* Decode 82 signature length */
        {
            size_t sig_data_len;
            size_t sig_len_bytes;

            if (ber_len_decode(resp + i, container_end - i,
                               &sig_data_len, &sig_len_bytes) < 0) {
                return WP11_PIV_ERR_ENCODING;
            }
            i += sig_len_bytes;

            /* signature bytes must fit in both the container and the caller's buffer */
            if (i + sig_data_len > container_end) {
                return WP11_PIV_ERR_ENCODING;
            }
            if (sig_data_len > *siglen) {
                return WP11_PIV_ERR_BUFSIZE;
            }

            (void)memcpy(sig, resp + i, sig_data_len);
            *siglen = sig_data_len;
        }
    }

    return WP11_PIV_OK;
}

/* -------------------------------------------------------------------------
 * wp11_piv_get_cert -- GET DATA for a PIV certificate object
 *                     (SP 800-73-4 Section 3.1.2, Table 4b)
 *
 * Slot-to-data-tag mapping:
 *   0x9A -> 5C 03 5F C1 05
 *   0x9C -> 5C 03 5F C1 0A
 *   0x9D -> 5C 03 5F C1 0B
 *   0x9E -> 5C 03 5F C1 01
 *
 * APDU: 00 CB 3F FF 05 [5C 03 xx xx xx] 00
 *
 * The response is a BER-TLV object: 53 { 70 { <DER cert> } 71 01 xx FE 00 }.
 * This function extracts and returns only the DER cert bytes (tag 0x70 content).
 *
 * For cards that cannot return the full object in one APDU, this function
 * performs GET RESPONSE chaining per ISO 7816-4 Section 7.6.1 until the
 * card returns SW 90 00.  Each chunk is accumulated in a heap buffer up to
 * WP11_PIV_CERT_MAX_LEN bytes.
 *
 * Returns WP11_PIV_ERR_NOT_FOUND if the cert slot is not provisioned (SW 6A 82).
 * Returns WP11_PIV_ERR_ENCODING if the card response is malformed BER-TLV.
 * ---------------------------------------------------------------------- */

int wp11_piv_get_cert(wp11_ccid_ctx_t *ccid,
                      uint8_t          slot,
                      uint8_t         *cert, size_t *certlen)
{
    /* Slot-to-GET-DATA-tag mapping (SP 800-73-4 Table 4b) */
    static const struct {
        uint8_t slot_id;
        uint8_t tag[3];
    } tag_map[] = {
        { WP11_PIV_SLOT_AUTH,     { 0x5Fu, 0xC1u, 0x05u } },
        { WP11_PIV_SLOT_SIGN,     { 0x5Fu, 0xC1u, 0x0Au } },
        { WP11_PIV_SLOT_KEYMGMT,  { 0x5Fu, 0xC1u, 0x0Bu } },
        { WP11_PIV_SLOT_CARDAUTH, { 0x5Fu, 0xC1u, 0x01u } },
    };

    uint8_t        *accum = NULL;     /* heap buffer accumulating all chunks */
    size_t          accum_len = 0;    /* bytes written into accum so far */
    uint8_t         cmd[PIV_APDU_MAX_CMD];
    uint8_t         chunk[PIV_APDU_MAX_RESP];
    size_t          cmdlen;
    size_t          chunk_len;
    size_t          data_len;
    size_t          i;
    uint8_t         sw1;
    uint8_t         sw2;
    int             rc;
    const uint8_t  *tag_bytes = NULL;
    size_t          pos;
    size_t          outer_val;
    size_t          outer_consumed;
    size_t          inner_val;
    size_t          inner_consumed;

    if (ccid == NULL || cert == NULL || certlen == NULL) {
        return WP11_PIV_ERR_PARAM;
    }

    /* Resolve slot to GET DATA tag bytes */
    for (i = 0; i < sizeof(tag_map) / sizeof(tag_map[0]); i++) {
        if (tag_map[i].slot_id == slot) {
            tag_bytes = tag_map[i].tag;
            break;
        }
    }
    if (tag_bytes == NULL) {
        return WP11_PIV_ERR_PARAM;
    }

    /* Allocate accumulation buffer for GET RESPONSE chaining */
    accum = (uint8_t *)malloc(WP11_PIV_CERT_MAX_LEN);
    if (accum == NULL) {
        /* wolfP11-dkm: return NOMEM, not PARAM -- OOM is not a caller error */
        return WP11_PIV_ERR_NOMEM;
    }

    /* Build and send initial GET DATA APDU */
    cmdlen = 0;
    cmd[cmdlen++] = PIV_CLA;
    cmd[cmdlen++] = PIV_INS_GET_DATA;
    cmd[cmdlen++] = 0x3Fu;  /* P1 */
    cmd[cmdlen++] = 0xFFu;  /* P2 */
    cmd[cmdlen++] = 0x05u;  /* Lc: 5C 03 + 3 tag bytes */
    cmd[cmdlen++] = 0x5Cu;  /* tag list tag */
    cmd[cmdlen++] = 0x03u;  /* tag list length */
    cmd[cmdlen++] = tag_bytes[0];
    cmd[cmdlen++] = tag_bytes[1];
    cmd[cmdlen++] = tag_bytes[2];
    cmd[cmdlen++] = 0x00u;  /* Le: request up to 256 bytes */

    chunk_len = sizeof(chunk);
    rc = wp11_ccid_apdu(ccid, cmd, cmdlen, chunk, &chunk_len);
    if (rc != WP11_CCID_OK) {
        free(accum);
        return WP11_PIV_ERR_TRANSPORT;
    }
    if (chunk_len < 2u) {
        free(accum);
        return WP11_PIV_ERR_TRUNCATED;
    }

    piv_get_sw(chunk, chunk_len, &sw1, &sw2);

    /* SW 6A 82: object not found -- cert slot not provisioned */
    if (sw1 == SW1_NOT_FOUND && sw2 == SW2_FILE_NOT_FOUND) {
        free(accum);
        return WP11_PIV_ERR_NOT_FOUND;
    }

    /* Accumulate first chunk (payload excludes SW bytes) */
    data_len = chunk_len - 2u;
    if (data_len > WP11_PIV_CERT_MAX_LEN) {
        free(accum);
        return WP11_PIV_ERR_BUFSIZE;
    }
    memcpy(accum, chunk, data_len);
    accum_len = data_len;

    /* GET RESPONSE chaining: ISO 7816-4 Section 7.6.1.
     * SW 61 xx means "more data available"; issue GET RESPONSE to fetch.
     * Le=0x00 means "up to 256 bytes" in ISO 7816-4 short APDU form -- more
     * compatible than Le=sw2 on tokens that have strict Le-matching behavior
     * or firmware bugs when sw2 != 0x00.  Note: sw2==0x00 in SW 61 00 means
     * 256 bytes per ISO 7816-4, not zero; Le=0x00 handles this correctly too. */
    while (sw1 == SW1_MORE_DATA) {
        cmd[0] = PIV_CLA;
        cmd[1] = PIV_INS_GET_RESPONSE;
        cmd[2] = 0x00u;
        cmd[3] = 0x00u;
        cmd[4] = 0x00u; /* Le=0x00: ISO 7816-4 sec.7.6.1 "up to 256 bytes" */
        cmdlen = 5u;

        chunk_len = sizeof(chunk);
        rc = wp11_ccid_apdu(ccid, cmd, cmdlen, chunk, &chunk_len);
        if (rc != WP11_CCID_OK) {
            free(accum);
            return WP11_PIV_ERR_TRANSPORT;
        }
        if (chunk_len < 2u) {
            free(accum);
            return WP11_PIV_ERR_TRUNCATED;
        }

        piv_get_sw(chunk, chunk_len, &sw1, &sw2);

        /* After GET RESPONSE only SW 90 00 or SW 61 xx are valid */
        if (sw1 != SW1_SUCCESS && sw1 != SW1_MORE_DATA) {
            free(accum);
            return WP11_PIV_ERR_SW;
        }

        data_len = chunk_len - 2u;
        /* wolfP11-0mx: SW 61 00 means "more data, 256 bytes" per ISO 7816-4
         * sec.7.6.1 (sw2=0x00 is the extended-length indicator, NOT zero bytes).
         * If a token sends SW 61 xx but the CCID response carried zero payload
         * bytes, the token firmware is broken.  Fail hard rather than looping
         * forever accumulating nothing. */
        if (data_len == 0u && sw1 == SW1_MORE_DATA) {
            free(accum);
            return WP11_PIV_ERR_SW;
        }
        if (accum_len + data_len > WP11_PIV_CERT_MAX_LEN) {
            free(accum);
            return WP11_PIV_ERR_BUFSIZE;
        }
        memcpy(accum + accum_len, chunk, data_len);
        accum_len += data_len;
    }

    if (sw1 != SW1_SUCCESS || sw2 != SW2_SUCCESS) {
        free(accum);
        return WP11_PIV_ERR_SW;
    }

    /* Parse BER-TLV: outer container tag 0x53, DER cert inner tag 0x70 */
    pos = 0;
    if (pos >= accum_len || accum[pos] != 0x53u) {
        free(accum);
        return WP11_PIV_ERR_ENCODING;
    }
    pos++;

    if (ber_len_decode(accum + pos, accum_len - pos,
                       &outer_val, &outer_consumed) != 0) {
        free(accum);
        return WP11_PIV_ERR_ENCODING;
    }
    pos += outer_consumed;

    /* Validate outer container does not claim to extend beyond the buffer */
    if (pos + outer_val > accum_len) {
        free(accum);
        return WP11_PIV_ERR_ENCODING;
    }

    /* Locate tag 0x70 (Certificate) inside the outer container */
    if (pos >= accum_len || accum[pos] != 0x70u) {
        free(accum);
        return WP11_PIV_ERR_ENCODING;
    }
    pos++;

    if (ber_len_decode(accum + pos, accum_len - pos,
                       &inner_val, &inner_consumed) != 0) {
        free(accum);
        return WP11_PIV_ERR_ENCODING;
    }
    pos += inner_consumed;

    if (pos + inner_val > accum_len) {
        free(accum);
        return WP11_PIV_ERR_ENCODING;
    }

    if (inner_val > *certlen) {
        free(accum);
        return WP11_PIV_ERR_BUFSIZE;
    }

    memcpy(cert, accum + pos, inner_val);
    *certlen = inner_val;

    free(accum);
    return WP11_PIV_OK;
}

/* -------------------------------------------------------------------------
 * wp11_piv_generate_key -- GENERATE ASYMMETRIC KEY PAIR (SP 800-73-4 sec.3.3.2)
 *
 * Generates a fresh key pair in the specified PIV slot.  The private key is
 * generated on the token and never exported.
 *
 * APDU: 00 47 00 <slot> 05 AC 03 80 01 <alg> 00
 *   INS 0x47:  GENERATE ASYMMETRIC KEY PAIR
 *   P1 0x00:   generate fresh key pair
 *   P2 <slot>: slot reference (WP11_PIV_SLOT_*)
 *   Lc 0x05:   5 bytes of command data
 *   Data:      AC 03 80 01 <alg>
 *     AC = Algorithm Cryptographic template tag
 *     80 = Cryptographic Algorithm Identifier tag (length 1)
 *     <alg> = WP11_PIV_ALG_EC_P256 (0x11), WP11_PIV_ALG_EC_P384 (0x14),
 *             or WP11_PIV_ALG_RSA2048 (0x07)
 *   Le 0x00:   any response length
 *
 * Response (BER-TLV, excluding SW1/SW2):
 *   7F 49 [len]                    -- Public Key Object (constructed 2-byte tag)
 *     For ECC:
 *       86 [len] [04 X Y]          -- EC public key, uncompressed ANSI X9.62 point
 *         P-256: 65 bytes (04 + 32-byte X + 32-byte Y)
 *         P-384: 97 bytes (04 + 48-byte X + 48-byte Y)
 *     For RSA-2048:
 *       81 [len] [modulus]         -- 256-byte RSA modulus
 *       82 [len] [exponent]        -- public exponent (typically 01 00 01)
 *
 * pubkey_out / *pubkey_len:
 *   On success, filled with the contents of the first inner tag:
 *     ECC: raw EC point bytes (04 || X || Y)
 *     RSA: raw modulus bytes
 *   If pubkey_out is NULL the copy is skipped (fire-and-forget: confirms
 *   the key was generated but discards the public key bytes).
 *   If pubkey_out is non-NULL, *pubkey_len must be set to the buffer size
 *   before the call.  If the response does not fit, WP11_PIV_ERR_BUFSIZE
 *   is returned.
 *
 * Returns WP11_PIV_OK on success, negative error code on failure.
 * ---------------------------------------------------------------------- */
int wp11_piv_generate_key(wp11_ccid_ctx_t *ccid,
                           uint8_t          slot,
                           uint8_t          alg,
                           uint8_t         *pubkey_out,
                           size_t          *pubkey_len)
{
    uint8_t cmd[PIV_APDU_MAX_CMD];
    uint8_t resp[PIV_APDU_MAX_RESP];
    size_t  cmdlen;
    size_t  resplen = sizeof(resp);
    uint8_t sw1;
    uint8_t sw2;
    int     rc;
    size_t  i;
    size_t  data_end;
    size_t  outer_len;
    size_t  len_bytes;
    size_t  inner_len;

    if (ccid == NULL) {
        return WP11_PIV_ERR_PARAM;
    }

    /* Build GENERATE ASYMMETRIC KEY PAIR APDU */
    cmdlen = 0;
    cmd[cmdlen++] = PIV_CLA;
    cmd[cmdlen++] = PIV_INS_GEN_KEYPAIR;  /* 0x47 */
    cmd[cmdlen++] = 0x00u;                /* P1: generate fresh key pair */
    cmd[cmdlen++] = slot;                 /* P2: slot reference */
    cmd[cmdlen++] = 0x05u;                /* Lc: 5 data bytes */
    cmd[cmdlen++] = 0xACu;                /* AC: Algorithm Cryptographic template */
    cmd[cmdlen++] = 0x03u;                /* AC length: 3 bytes */
    cmd[cmdlen++] = 0x80u;                /* Cryptographic Algorithm Identifier tag */
    cmd[cmdlen++] = 0x01u;                /* length: 1 */
    cmd[cmdlen++] = alg;                  /* algorithm reference */
    cmd[cmdlen++] = 0x00u;                /* Le */

    rc = wp11_ccid_apdu(ccid, cmd, cmdlen, resp, &resplen);
    if (rc != WP11_CCID_OK) {
        return WP11_PIV_ERR_TRANSPORT;
    }
    if (resplen < 2u) {
        return WP11_PIV_ERR_TRUNCATED;
    }

    piv_get_sw(resp, resplen, &sw1, &sw2);

    /* ISO 7816-4 sec.5.1.3: SW 6C xx means wrong Le; retry once with Le=sw2. */
    if (sw1 == 0x6Cu) {
        cmd[cmdlen - 1u] = sw2;  /* patch Le in-place */
        resplen = sizeof(resp);
        rc = wp11_ccid_apdu(ccid, cmd, cmdlen, resp, &resplen);
        if (rc != WP11_CCID_OK) return WP11_PIV_ERR_TRANSPORT;
        if (resplen < 2u)        return WP11_PIV_ERR_TRUNCATED;
        piv_get_sw(resp, resplen, &sw1, &sw2);
    }

    if (sw1 != SW1_SUCCESS || sw2 != SW2_SUCCESS) {
        return piv_sw_to_err(sw1, sw2);
    }

    /* data_end: response bytes excluding the 2 SW bytes */
    data_end = resplen - 2u;
    i = 0u;

    /* Parse outer 7F 49 constructed tag (2-byte BER tag, sec.SP 800-73-4 Table 7) */
    if (i + 2u > data_end ||
        resp[i] != 0x7Fu || resp[i + 1u] != 0x49u) {
        return WP11_PIV_ERR_ENCODING;
    }
    i += 2u;

    /* Decode outer object BER length */
    if (ber_len_decode(resp + i, data_end - i, &outer_len, &len_bytes) < 0) {
        return WP11_PIV_ERR_ENCODING;
    }
    i += len_bytes;
    if (outer_len > data_end - i) {
        return WP11_PIV_ERR_ENCODING;
    }

    /* Skip the inner tag byte (86 for ECC, 81 for RSA modulus) */
    if (i >= data_end) {
        return WP11_PIV_ERR_ENCODING;
    }
    i++;  /* consume inner tag byte */

    /* Decode inner object BER length */
    if (ber_len_decode(resp + i, data_end - i, &inner_len, &len_bytes) < 0) {
        return WP11_PIV_ERR_ENCODING;
    }
    i += len_bytes;
    if (inner_len > data_end - i) {
        return WP11_PIV_ERR_ENCODING;
    }

    /* Return public key bytes to caller if requested */
    if (pubkey_out != NULL) {
        if (pubkey_len == NULL || inner_len > *pubkey_len) {
            return WP11_PIV_ERR_BUFSIZE;
        }
        (void)memcpy(pubkey_out, resp + i, inner_len);
        *pubkey_len = inner_len;
    }

    return WP11_PIV_OK;
}

/* -------------------------------------------------------------------------
 * wp11_piv_attest -- retrieve a YubiKey PIV attestation certificate
 *
 * YubiKey-specific command (INS 0xF9).  The card generates a certificate
 * signed by the YubiKey attestation key, proving that the key in the given
 * slot was generated on the device.
 *
 * APDU: 00 F9 00 <slot> 00
 *   INS 0xF9:   YubiKey attestation
 *   P1 0x00:    reserved
 *   P2 <slot>:  slot reference (WP11_PIV_SLOT_*)
 *   Le 0x00:    any response length
 *
 * The response is raw DER -- no BER-TLV wrapper.  GET RESPONSE chaining
 * is used if the certificate spans multiple APDU payloads.
 *
 * Returns WP11_PIV_ERR_NOT_FOUND if the slot has no key to attest (SW 6A 82).
 * ---------------------------------------------------------------------- */

int wp11_piv_attest(wp11_ccid_ctx_t *ccid,
                    uint8_t          slot,
                    uint8_t         *der, size_t *derlen)
{
    uint8_t *accum = NULL;
    size_t   accum_len = 0;
    uint8_t  cmd[PIV_APDU_MAX_CMD];
    uint8_t  chunk[PIV_APDU_MAX_RESP];
    size_t   cmdlen;
    size_t   chunk_len;
    size_t   data_len;
    uint8_t  sw1;
    uint8_t  sw2;
    int      rc;

    if (ccid == NULL || der == NULL || derlen == NULL) {
        return WP11_PIV_ERR_PARAM;
    }

    accum = (uint8_t *)malloc(WP11_PIV_CERT_MAX_LEN);
    if (accum == NULL) {
        /* wolfP11-dkm: return NOMEM, not PARAM -- OOM is not a caller error */
        return WP11_PIV_ERR_NOMEM;
    }

    /* Build YubiKey attestation APDU */
    cmdlen = 0;
    cmd[cmdlen++] = PIV_CLA;
    cmd[cmdlen++] = PIV_INS_ATTEST;
    cmd[cmdlen++] = 0x00u;  /* P1 */
    cmd[cmdlen++] = slot;   /* P2: target key slot */
    cmd[cmdlen++] = 0x00u;  /* Le: any response length */

    chunk_len = sizeof(chunk);
    rc = wp11_ccid_apdu(ccid, cmd, cmdlen, chunk, &chunk_len);
    if (rc != WP11_CCID_OK) {
        free(accum);
        return WP11_PIV_ERR_TRANSPORT;
    }
    if (chunk_len < 2u) {
        free(accum);
        return WP11_PIV_ERR_TRUNCATED;
    }

    piv_get_sw(chunk, chunk_len, &sw1, &sw2);

    /* SW 6A 82: key slot not provisioned -- no key to attest */
    if (sw1 == SW1_NOT_FOUND && sw2 == SW2_FILE_NOT_FOUND) {
        free(accum);
        return WP11_PIV_ERR_NOT_FOUND;
    }

    /* Accumulate first chunk (payload = response minus SW bytes) */
    data_len = chunk_len - 2u;
    if (data_len > WP11_PIV_CERT_MAX_LEN) {
        free(accum);
        return WP11_PIV_ERR_BUFSIZE;
    }
    (void)memcpy(accum, chunk, data_len);
    accum_len = data_len;

    /* GET RESPONSE chaining: ISO 7816-4 Section 7.6.1.
     * Le=0x00 for maximum compatibility -- see wp11_piv_get_cert for rationale. */
    while (sw1 == SW1_MORE_DATA) {
        cmd[0] = PIV_CLA;
        cmd[1] = PIV_INS_GET_RESPONSE;
        cmd[2] = 0x00u;
        cmd[3] = 0x00u;
        cmd[4] = 0x00u; /* Le=0x00: ISO 7816-4 sec.7.6.1 "up to 256 bytes" */
        cmdlen = 5u;

        chunk_len = sizeof(chunk);
        rc = wp11_ccid_apdu(ccid, cmd, cmdlen, chunk, &chunk_len);
        if (rc != WP11_CCID_OK) {
            free(accum);
            return WP11_PIV_ERR_TRANSPORT;
        }
        if (chunk_len < 2u) {
            free(accum);
            return WP11_PIV_ERR_TRUNCATED;
        }

        piv_get_sw(chunk, chunk_len, &sw1, &sw2);

        /* After GET RESPONSE only SW 90 00 or SW 61 xx are valid */
        if (sw1 != SW1_SUCCESS && sw1 != SW1_MORE_DATA) {
            free(accum);
            return WP11_PIV_ERR_SW;
        }

        data_len = chunk_len - 2u;
        /* wolfP11-0mx: same zero-byte guard as wp11_piv_get_cert -- see
         * that function for the SW 61 00 rationale. */
        if (data_len == 0u && sw1 == SW1_MORE_DATA) {
            free(accum);
            return WP11_PIV_ERR_SW;
        }
        if (accum_len + data_len > WP11_PIV_CERT_MAX_LEN) {
            free(accum);
            return WP11_PIV_ERR_BUFSIZE;
        }
        (void)memcpy(accum + accum_len, chunk, data_len);
        accum_len += data_len;
    }

    if (sw1 != SW1_SUCCESS || sw2 != SW2_SUCCESS) {
        free(accum);
        return WP11_PIV_ERR_SW;
    }

    if (accum_len > *derlen) {
        free(accum);
        return WP11_PIV_ERR_BUFSIZE;
    }

    (void)memcpy(der, accum, accum_len);
    *derlen = accum_len;

    free(accum);
    return WP11_PIV_OK;
}

/* -------------------------------------------------------------------------
 * wp11_piv_ecdh -- GENERAL AUTHENTICATE in key-agreement mode
 *                 (SP 800-73-4 sec.3.2.4)
 *
 * Identical structure to wp11_piv_sign, but uses TAG_EXPONENT (0x85) in
 * place of TAG_CHALLENGE (0x81) to convey the peer EC public key, and the
 * response 82 field carries the ECDH x-coordinate (shared secret) rather
 * than a signature.
 *
 * DAT structure:
 *   7C [ber_len(dat_content_len)]
 *     82 00                                   (empty response template)
 *     85 [ber_len(peer_pub_len)] [peer_pub]   (peer EC point)
 * ---------------------------------------------------------------------- */

int wp11_piv_ecdh(wp11_ccid_ctx_t *ccid,
                  uint8_t          slot,
                  uint8_t          alg,
                  const uint8_t   *peer_pub,    size_t  peer_pub_len,
                  uint8_t         *shared,      size_t *sharedlen)
{
    uint8_t cmd[PIV_APDU_MAX_CMD];
    uint8_t resp[PIV_APDU_MAX_RESP];
    size_t  cmdlen;
    size_t  resplen = sizeof(resp);
    size_t  dat_content_len;
    size_t  apdu_data_size;
    size_t  i;
    size_t  data_end;
    uint8_t sw1;
    uint8_t sw2;
    int     rc;
    uint8_t len_buf[3];
    size_t  len_bytes;

    if (ccid == NULL || peer_pub == NULL || shared == NULL || sharedlen == NULL) {
        return WP11_PIV_ERR_PARAM;
    }
    /* Same short-APDU upper bound as wp11_piv_sign: peer_pub_len=248 would
     * produce apdu_data_size=256.  EC points are at most 97 bytes (P-384)
     * so this guard is defensive-in-depth only. */
    if (peer_pub_len > 247u) {
        return WP11_PIV_ERR_PARAM;
    }

    {
        size_t clen_bw = (peer_pub_len <= 0x7Fu) ? 1u : 2u;
        dat_content_len = 2u                /* TAG_RESPONSE + 0x00 */
                        + 1u                /* TAG_EXPONENT */
                        + clen_bw           /* BER-encoded peer_pub_len */
                        + peer_pub_len;
    }
    {
        size_t dlen_bw = (dat_content_len <= 0x7Fu) ? 1u : 2u;
        apdu_data_size = 1u                 /* TAG_DAT */
                       + dlen_bw
                       + dat_content_len;
    }

    if (apdu_data_size > 0xFFu ||
        (5u + apdu_data_size + 1u) > sizeof(cmd)) {
        return WP11_PIV_ERR_BUFSIZE;
    }

    cmdlen = 0;
    cmd[cmdlen++] = PIV_CLA;
    cmd[cmdlen++] = PIV_INS_GEN_AUTH;
    cmd[cmdlen++] = alg;
    cmd[cmdlen++] = slot;
    cmd[cmdlen++] = (uint8_t)apdu_data_size;

    /* 7C [ber_len(dat_content_len)] */
    cmd[cmdlen++] = TAG_DAT;
    len_bytes = ber_len_encode(len_buf, dat_content_len);
    (void)memcpy(&cmd[cmdlen], len_buf, len_bytes);
    cmdlen += len_bytes;

    /* 82 00 -- empty response template */
    cmd[cmdlen++] = TAG_RESPONSE;
    cmd[cmdlen++] = 0x00u;

    /* 85 [ber_len(peer_pub_len)] [peer_pub bytes] */
    cmd[cmdlen++] = TAG_EXPONENT;
    len_bytes = ber_len_encode(len_buf, peer_pub_len);
    (void)memcpy(&cmd[cmdlen], len_buf, len_bytes);
    cmdlen += len_bytes;
    (void)memcpy(&cmd[cmdlen], peer_pub, peer_pub_len);
    cmdlen += peer_pub_len;

    /* Le = 0x00 */
    cmd[cmdlen++] = 0x00u;

    rc = wp11_ccid_apdu(ccid, cmd, cmdlen, resp, &resplen);
    if (rc != WP11_CCID_OK) {
        return WP11_PIV_ERR_TRANSPORT;
    }
    if (resplen < 2u) {
        return WP11_PIV_ERR_TRUNCATED;
    }

    piv_get_sw(resp, resplen, &sw1, &sw2);

    /* ISO 7816-4 sec.5.1.3: SW 6C xx means wrong Le; retry once with Le=sw2. */
    if (sw1 == 0x6Cu) {
        cmd[cmdlen - 1u] = sw2;  /* patch Le in-place */
        resplen = sizeof(resp);
        rc = wp11_ccid_apdu(ccid, cmd, cmdlen, resp, &resplen);
        if (rc != WP11_CCID_OK) return WP11_PIV_ERR_TRANSPORT;
        if (resplen < 2u)        return WP11_PIV_ERR_TRUNCATED;
        piv_get_sw(resp, resplen, &sw1, &sw2);
    }

    if (sw1 != SW1_SUCCESS || sw2 != SW2_SUCCESS) {
        return piv_sw_to_err(sw1, sw2);
    }

    i = 0u;
    data_end = resplen - 2u;

    /* SP 800-73-4 Table 13: response must contain the 7C/82 structure. */
    if (data_end == 0u) {
        return WP11_PIV_ERR_ENCODING;
    }

    /* Response: 7C [len] 82 [secretlen] [secret bytes] */
    if (i >= data_end || resp[i] != TAG_DAT) {
        return WP11_PIV_ERR_SW;
    }
    i++;

    {
        size_t container_len;
        size_t container_end;

        if (ber_len_decode(resp + i, data_end - i,
                           &container_len, &len_bytes) < 0) {
            return WP11_PIV_ERR_ENCODING;
        }
        i += len_bytes;

        if (container_len > data_end - i) {
            return WP11_PIV_ERR_ENCODING;
        }
        container_end = i + container_len;

        if (i >= container_end || resp[i] != TAG_RESPONSE) {
            return WP11_PIV_ERR_SW;
        }
        i++;

        {
            size_t secret_data_len;
            size_t secret_len_bytes;

            if (ber_len_decode(resp + i, container_end - i,
                               &secret_data_len, &secret_len_bytes) < 0) {
                return WP11_PIV_ERR_ENCODING;
            }
            i += secret_len_bytes;

            if (i + secret_data_len > container_end) {
                return WP11_PIV_ERR_ENCODING;
            }
            if (secret_data_len > *sharedlen) {
                return WP11_PIV_ERR_BUFSIZE;
            }

            (void)memcpy(shared, resp + i, secret_data_len);
            *sharedlen = secret_data_len;
        }
    }

    return WP11_PIV_OK;
}
