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

/* wp11_token_db.h -- wolfP11 token database public API
 *
 * Maps USB VID/PID to protocol, quirks bitmask, and algo bitmask.
 * Adding a new token that follows an existing protocol is one row in
 * src/wp11_token_db.c -- no new source file, no new driver.
 */

#ifndef WOLFP11_TOKEN_DB_H
#define WOLFP11_TOKEN_DB_H

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Protocol selectors
 * ---------------------------------------------------------------------- */

typedef enum {
    /* WP11_PROTO_SOFT = 0 is the zero-value for this enum intentionally.
     * A zero-initialised wp11_slot_t (memset to 0 or global storage) will
     * therefore have proto == WP11_PROTO_SOFT without an explicit assignment.
     * This prevents a zero-init slot from being misidentified as a PIV device
     * by any future code that switches on proto.  Never change this value. */
    WP11_PROTO_SOFT     = 0,  /* wolfCrypt direct, no hardware, no CCID  */
    WP11_PROTO_PIV      = 1,  /* NIST SP 800-73 PIV applet               */
    WP11_PROTO_OPENPGP  = 2,  /* OpenPGP card specification              */
    WP11_PROTO_PKCS15   = 3,  /* ISO 7816-15 generic fallback            */
    /* Flash-keystore slots: no CCID/APDU protocol.  Key operations are
     * handled by wp11_backend_flash_ops via C_Login/C_Sign/C_Verify/
     * C_Decrypt -- not by the USB dispatch path.  Any switch on proto that
     * handles PIV/OpenPGP/PKCS15 MUST handle WP11_PROTO_FLASH explicitly
     * or have a documented default/fallthrough. */
    WP11_PROTO_FLASH    = 4,  /* Encrypted .p11k keystore on filesystem  */
    /* wolfHSM server backend: no CCID/APDU protocol.  Key operations are
     * routed to a wolfHSM server via the wolfHSM client API.  Any switch
     * on proto that handles PIV/OpenPGP/PKCS15/FLASH MUST handle
     * WP11_PROTO_WOLFHSM explicitly or have a documented default. */
    WP11_PROTO_WOLFHSM  = 5,  /* wolfHSM server via WH_DEV_ID callback   */
    /* Filesystem directory keystore slots: no CCID/APDU protocol.  Key
     * operations are handled by wp11_backend_fsdir_ops.  The watched
     * directory is a flat directory (not a USB mount hierarchy); files
     * that appear/disappear there are treated as token arrival/departure.
     * Any switch on proto MUST handle WP11_PROTO_FSDIR explicitly or have
     * a documented default/fallthrough. */
    WP11_PROTO_FSDIR    = 6,  /* Encrypted .p11k keystore in watched dir  */
} wp11_proto_t;

/* -------------------------------------------------------------------------
 * Quirk flags -- bitmask of known per-token behavioural deviations
 * ---------------------------------------------------------------------- */

#define WP11_QUIRK_NONE           0x00000000u
#define WP11_QUIRK_NO_PSS         0x00000001u  /* RSA-PSS done client-side          */
#define WP11_QUIRK_SHORT_APDU     0x00000002u  /* max 255-byte APDU only            */
#define WP11_QUIRK_EXTENDED_APDU  0x00000004u  /* supports ISO 7816-4 extended APDU */

/* -------------------------------------------------------------------------
 * Algorithm flags -- bitmask of key types supported by the token
 * ---------------------------------------------------------------------- */

#define WP11_ALGO_RSA2048       0x00000001u
#define WP11_ALGO_RSA4096       0x00000002u
#define WP11_ALGO_EC_P256       0x00000010u
#define WP11_ALGO_EC_P384       0x00000020u
#define WP11_ALGO_ED25519       0x00000100u

/* -------------------------------------------------------------------------
 * Token descriptor -- one row per supported token
 * ---------------------------------------------------------------------- */

typedef struct {
    uint16_t        usb_vid;
    uint16_t        usb_pid;
    const char     *name;
    wp11_proto_t    proto;
    uint32_t        quirks;
    uint32_t        algos;
} wp11_token_desc_t;

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/* Look up a token by USB VID/PID.
 * Returns pointer into the static table on success, NULL if not found.
 * Tokens not in this table are attempted as generic PIV with conservative
 * quirks -- see wp11_token_db_lookup_unknown() for the fallback descriptor. */
const wp11_token_desc_t *wp11_token_db_lookup(uint16_t vid, uint16_t pid);

/* Return the generic PIV fallback descriptor for tokens not in the table.
 * The fallback uses WP11_QUIRK_SHORT_APDU (conservative default) and
 * proto=WP11_PROTO_PIV.  Callers that want to attempt PIV on an unrecognised
 * token should use this descriptor rather than hardcoding defaults. */
const wp11_token_desc_t *wp11_token_db_lookup_unknown(void);

/* Return the number of entries in the token database. */
size_t wp11_token_db_count(void);

#endif /* WOLFP11_TOKEN_DB_H */
