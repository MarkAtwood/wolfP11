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

/* wp11_proto_openpgp.c -- OpenPGP card APDU sequences
 * Reference: OpenPGP card application spec v3.4 (https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf)
 * Sections: 7.2.1 (SELECT), 7.2.2 (VERIFY), 7.2.6 (COMPUTE DIGITAL SIGNATURE),
 *           7.2.10 (INTERNAL AUTHENTICATE), 7.2.11 (DECIPHER)
 */

#include "wolfp11/wp11_proto_openpgp.h"
#include "wolfp11/wp11_ccid.h"
#include <string.h>
#include <stdint.h>

/* Maximum APDU command buffer: 5-byte header + 255-byte data + 1-byte Le */
#define OPENPGP_CMD_MAX  261u
/* Maximum response buffer: up to 512 bytes of data + 2-byte SW */
#define OPENPGP_RESP_MAX 514u

/* -------------------------------------------------------------------------
 * Internal helper: extract SW1/SW2 from the end of a response buffer
 * ---------------------------------------------------------------------- */

static void extract_sw(const uint8_t *resp, size_t resplen,
                        uint8_t *sw1, uint8_t *sw2)
{
    /* wolfP11-ms9a: defensive bounds check inside the function itself.
     * All current callers check resplen >= 2 before calling, but a future
     * caller or a copy-paste of this function could omit that guard.  If
     * resplen < 2 we cannot read a valid SW; return 0x00/0x00 so the caller
     * sees an unrecognised status word and returns WP11_OPENPGP_ERR_SW rather
     * than crashing on a size_t underflow read.  Mirrors piv_get_sw() in
     * wp11_proto_piv.c which has the same defensive check. */
    if (resplen < 2u) {
        *sw1 = 0x00u;
        *sw2 = 0x00u;
        return;
    }
    *sw1 = resp[resplen - 2u];
    *sw2 = resp[resplen - 1u];
}

/* -------------------------------------------------------------------------
 * wp11_openpgp_select -- Section 7.2.1
 * APDU: 00 A4 04 00 06 D2 76 00 01 24 01
 * ---------------------------------------------------------------------- */

int wp11_openpgp_select(wp11_ccid_ctx_t *ccid)
{
    uint8_t cmd[11];
    uint8_t resp[OPENPGP_RESP_MAX];
    size_t  resplen = sizeof(resp);
    int     rc;
    uint8_t sw1, sw2;

    if (ccid == NULL) {
        return WP11_OPENPGP_ERR_PARAM;
    }

    cmd[0]  = 0x00u;  /* CLA */
    cmd[1]  = 0xA4u;  /* INS SELECT */
    cmd[2]  = 0x04u;  /* P1: select by AID */
    cmd[3]  = 0x00u;  /* P2 */
    cmd[4]  = 0x06u;  /* Lc: AID prefix length */
    cmd[5]  = 0xD2u;  /* AID[0] */
    cmd[6]  = 0x76u;  /* AID[1] */
    cmd[7]  = 0x00u;  /* AID[2] */
    cmd[8]  = 0x01u;  /* AID[3] */
    cmd[9]  = 0x24u;  /* AID[4] */
    cmd[10] = 0x01u;  /* AID[5] */

    rc = wp11_ccid_apdu(ccid, cmd, sizeof(cmd), resp, &resplen);
    if (rc != WP11_CCID_OK) {
        return WP11_OPENPGP_ERR_TRANSPORT;
    }
    /* SW1/SW2 are the final 2 bytes of every OpenPGP response.
     * A response shorter than 2 bytes indicates transport truncation,
     * not a card error -- treat separately to avoid size_t underflow. */
    if (resplen < 2u) {
        return WP11_OPENPGP_ERR_TRUNCATED;
    }

    extract_sw(resp, resplen, &sw1, &sw2);
    if (sw1 == 0x90u && sw2 == 0x00u) {
        return WP11_OPENPGP_OK;
    }
    return WP11_OPENPGP_ERR_SW;
}

/* -------------------------------------------------------------------------
 * wp11_openpgp_verify_pw1 -- Section 7.2.2
 * APDU: 00 20 00 <mode> <pwlen> [pw bytes]
 * mode: 0x81 (sign) or 0x82 (other)
 * ---------------------------------------------------------------------- */

int wp11_openpgp_verify_pw1(wp11_ccid_ctx_t *ccid,
                             const uint8_t   *pw, size_t pwlen, int mode)
{
    uint8_t cmd[OPENPGP_CMD_MAX];
    uint8_t resp[OPENPGP_RESP_MAX];
    size_t  resplen = sizeof(resp);
    size_t  cmdlen;
    int     rc;
    uint8_t sw1, sw2;

    if (ccid == NULL || pw == NULL || pwlen == 0u || pwlen > 255u) {
        return WP11_OPENPGP_ERR_PARAM;
    }
    if (mode != WP11_OPENPGP_PW1_MODE_SIGN && mode != WP11_OPENPGP_PW1_MODE_OTHER) {
        return WP11_OPENPGP_ERR_PARAM;
    }

    cmd[0] = 0x00u;           /* CLA */
    cmd[1] = 0x20u;           /* INS VERIFY */
    cmd[2] = 0x00u;           /* P1 */
    cmd[3] = (uint8_t)mode;   /* P2: 0x81 or 0x82 */
    cmd[4] = (uint8_t)pwlen;  /* Lc */
    memcpy(&cmd[5], pw, pwlen);
    cmdlen = 5u + pwlen;

    rc = wp11_ccid_apdu(ccid, cmd, cmdlen, resp, &resplen);
    if (rc != WP11_CCID_OK) {
        return WP11_OPENPGP_ERR_TRANSPORT;
    }
    /* SW1/SW2 are the final 2 bytes of every OpenPGP response.
     * A response shorter than 2 bytes indicates transport truncation,
     * not a card error -- treat separately to avoid size_t underflow. */
    if (resplen < 2u) {
        return WP11_OPENPGP_ERR_TRUNCATED;
    }

    extract_sw(resp, resplen, &sw1, &sw2);

    if (sw1 == 0x90u && sw2 == 0x00u) {
        return WP11_OPENPGP_OK;
    }
    if (sw1 == 0x63u) {
        return WP11_OPENPGP_ERR_PW_BAD;
    }
    if (sw1 == 0x69u && sw2 == 0x83u) {
        return WP11_OPENPGP_ERR_PW_LOCKED;
    }
    return WP11_OPENPGP_ERR_SW;
}

/* -------------------------------------------------------------------------
 * wp11_openpgp_sign -- Section 7.2.6
 * APDU: 00 2A 9E 9A <hashlen> [hash bytes] 00
 * ---------------------------------------------------------------------- */

int wp11_openpgp_sign(wp11_ccid_ctx_t *ccid,
                      const uint8_t   *hash,   size_t  hashlen,
                      uint8_t         *sig,    size_t *siglen)
{
    uint8_t cmd[OPENPGP_CMD_MAX];
    uint8_t resp[OPENPGP_RESP_MAX];
    size_t  resplen = sizeof(resp);
    size_t  cmdlen;
    int     rc;
    uint8_t sw1, sw2;

    if (ccid == NULL || hash == NULL || sig == NULL || siglen == NULL) {
        return WP11_OPENPGP_ERR_PARAM;
    }
    if (hashlen == 0u || hashlen > 255u) {
        return WP11_OPENPGP_ERR_PARAM;
    }

    cmd[0] = 0x00u;              /* CLA */
    cmd[1] = 0x2Au;              /* INS COMPUTE DIGITAL SIGNATURE */
    cmd[2] = 0x9Eu;              /* P1 */
    cmd[3] = 0x9Au;              /* P2 */
    cmd[4] = (uint8_t)hashlen;   /* Lc */
    memcpy(&cmd[5], hash, hashlen);
    cmd[5u + hashlen] = 0x00u;   /* Le */
    cmdlen = 6u + hashlen;

    rc = wp11_ccid_apdu(ccid, cmd, cmdlen, resp, &resplen);
    if (rc != WP11_CCID_OK) {
        return WP11_OPENPGP_ERR_TRANSPORT;
    }
    /* SW1/SW2 are the final 2 bytes of every OpenPGP response.
     * A response shorter than 2 bytes indicates transport truncation,
     * not a card error -- treat separately to avoid size_t underflow. */
    if (resplen < 2u) {
        return WP11_OPENPGP_ERR_TRUNCATED;
    }

    extract_sw(resp, resplen, &sw1, &sw2);

    /* wolfP11-os9k: ISO 7816-4 sec.5.1.3: SW 6C xx means wrong Le;
     * retry once with Le=sw2.  PIV handles this identically (see
     * wp11_proto_piv.c).  Le is the last byte of the command APDU. */
    if (sw1 == 0x6Cu) {
        cmd[cmdlen - 1u] = sw2;          /* patch Le in-place */
        resplen = sizeof(resp);
        rc = wp11_ccid_apdu(ccid, cmd, cmdlen, resp, &resplen);
        if (rc != WP11_CCID_OK) return WP11_OPENPGP_ERR_TRANSPORT;
        if (resplen < 2u)        return WP11_OPENPGP_ERR_TRUNCATED;
        extract_sw(resp, resplen, &sw1, &sw2);
        /* If 6C again, fall through to error -- avoid infinite loop */
    }

    if (sw1 != 0x90u || sw2 != 0x00u) {
        return WP11_OPENPGP_ERR_SW;
    }

    if (resplen - 2u > *siglen) {
        return WP11_OPENPGP_ERR_BUFSIZE;
    }

    memcpy(sig, resp, resplen - 2u);
    *siglen = resplen - 2u;

    return WP11_OPENPGP_OK;
}

/* -------------------------------------------------------------------------
 * wp11_openpgp_authenticate -- Section 7.2.10
 * APDU: 00 88 00 00 <datalen> [data bytes] 00
 * ---------------------------------------------------------------------- */

int wp11_openpgp_authenticate(wp11_ccid_ctx_t *ccid,
                               const uint8_t   *data,    size_t  datalen,
                               uint8_t         *resp_out, size_t *resplen_out)
{
    uint8_t cmd[OPENPGP_CMD_MAX];
    uint8_t resp[OPENPGP_RESP_MAX];
    size_t  resplen = sizeof(resp);
    size_t  cmdlen;
    int     rc;
    uint8_t sw1, sw2;

    if (ccid == NULL || data == NULL || resp_out == NULL || resplen_out == NULL) {
        return WP11_OPENPGP_ERR_PARAM;
    }
    if (datalen == 0u || datalen > 255u) {
        return WP11_OPENPGP_ERR_PARAM;
    }

    cmd[0] = 0x00u;              /* CLA */
    cmd[1] = 0x88u;              /* INS INTERNAL AUTHENTICATE */
    cmd[2] = 0x00u;              /* P1 */
    cmd[3] = 0x00u;              /* P2 */
    cmd[4] = (uint8_t)datalen;   /* Lc */
    memcpy(&cmd[5], data, datalen);
    cmd[5u + datalen] = 0x00u;   /* Le */
    cmdlen = 6u + datalen;

    rc = wp11_ccid_apdu(ccid, cmd, cmdlen, resp, &resplen);
    if (rc != WP11_CCID_OK) {
        return WP11_OPENPGP_ERR_TRANSPORT;
    }
    /* SW1/SW2 are the final 2 bytes of every OpenPGP response.
     * A response shorter than 2 bytes indicates transport truncation,
     * not a card error -- treat separately to avoid size_t underflow. */
    if (resplen < 2u) {
        return WP11_OPENPGP_ERR_TRUNCATED;
    }

    extract_sw(resp, resplen, &sw1, &sw2);

    /* wolfP11-os9k: same 6C retry as wp11_openpgp_sign above. */
    if (sw1 == 0x6Cu) {
        cmd[cmdlen - 1u] = sw2;
        resplen = sizeof(resp);
        rc = wp11_ccid_apdu(ccid, cmd, cmdlen, resp, &resplen);
        if (rc != WP11_CCID_OK) return WP11_OPENPGP_ERR_TRANSPORT;
        if (resplen < 2u)        return WP11_OPENPGP_ERR_TRUNCATED;
        extract_sw(resp, resplen, &sw1, &sw2);
    }

    if (sw1 != 0x90u || sw2 != 0x00u) {
        return WP11_OPENPGP_ERR_SW;
    }

    if (resplen - 2u > *resplen_out) {
        return WP11_OPENPGP_ERR_BUFSIZE;
    }

    memcpy(resp_out, resp, resplen - 2u);
    *resplen_out = resplen - 2u;

    return WP11_OPENPGP_OK;
}

/* -------------------------------------------------------------------------
 * wp11_openpgp_get_ard -- GET DATA for Application Related Data (DO 006E)
 * APDU: 00 CA 00 6E 00
 * ---------------------------------------------------------------------- */

int wp11_openpgp_get_ard(wp11_ccid_ctx_t *ccid,
                          uint8_t         *buf, size_t *buflen)
{
    uint8_t cmd[5];
    uint8_t resp[OPENPGP_RESP_MAX];
    size_t  resplen = sizeof(resp);
    int     rc;
    uint8_t sw1, sw2;

    if (ccid == NULL || buf == NULL || buflen == NULL) {
        return WP11_OPENPGP_ERR_PARAM;
    }

    cmd[0] = 0x00u;  /* CLA */
    cmd[1] = 0xCAu;  /* INS GET DATA */
    cmd[2] = 0x00u;  /* P1: tag high byte (DO 006E) */
    cmd[3] = 0x6Eu;  /* P2: tag low byte */
    cmd[4] = 0x00u;  /* Le */

    rc = wp11_ccid_apdu(ccid, cmd, sizeof(cmd), resp, &resplen);
    if (rc != WP11_CCID_OK) {
        return WP11_OPENPGP_ERR_TRANSPORT;
    }
    /* SW1/SW2 are the final 2 bytes of every OpenPGP response.
     * A response shorter than 2 bytes indicates transport truncation,
     * not a card error -- treat separately to avoid size_t underflow. */
    if (resplen < 2u) {
        return WP11_OPENPGP_ERR_TRUNCATED;
    }

    extract_sw(resp, resplen, &sw1, &sw2);

    /* wolfP11-os9k: same 6C retry as wp11_openpgp_sign above.
     * Le is cmd[4] (the only byte after the 4-byte header). */
    if (sw1 == 0x6Cu) {
        cmd[4u] = sw2;
        resplen = sizeof(resp);
        rc = wp11_ccid_apdu(ccid, cmd, sizeof(cmd), resp, &resplen);
        if (rc != WP11_CCID_OK) return WP11_OPENPGP_ERR_TRANSPORT;
        if (resplen < 2u)        return WP11_OPENPGP_ERR_TRUNCATED;
        extract_sw(resp, resplen, &sw1, &sw2);
    }

    if (sw1 != 0x90u || sw2 != 0x00u) {
        return WP11_OPENPGP_ERR_SW;
    }

    if (resplen - 2u > *buflen) {
        return WP11_OPENPGP_ERR_BUFSIZE;
    }

    memcpy(buf, resp, resplen - 2u);
    *buflen = resplen - 2u;

    return WP11_OPENPGP_OK;
}
