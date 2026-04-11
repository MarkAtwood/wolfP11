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

/* wp11_token_db.c -- wolfP11 USB token database
 *
 * Maps USB VID/PID pairs to protocol, quirk flags, and algorithm flags.
 * To add a token that follows an existing protocol, add one row to
 * wp11_token_db[] below.
 *
 * Tokens not in this table are attempted as generic PIV with conservative
 * quirks -- see wp11_token_db_lookup_unknown() for fallback behavior.
 */

#include "wolfp11/wp11_token_db.h"

#include <stdint.h>
#include <stddef.h>
#include <assert.h>

/* -------------------------------------------------------------------------
 * Static token table
 *
 * Adding a new token that follows an existing protocol is one row here.
 * Quirk flags:
 *   WP11_QUIRK_NONE           -- fully compliant, no workarounds needed
 *   WP11_QUIRK_NO_PSS         -- RSA-PSS must be computed client-side
 *   WP11_QUIRK_SHORT_APDU     -- max 255-byte APDU; no extended APDU
 *   WP11_QUIRK_EXTENDED_APDU  -- ISO 7816-4 extended APDU confirmed supported
 *
 * Algorithm flags: bitmask of key types the token can generate/use.
 * ---------------------------------------------------------------------- */

static const wp11_token_desc_t wp11_token_db[] = {
    /* YubiKey 5 NFC -- PIV, extended APDU, RSA-2048, P-256, P-384 */
    {
        0x1050u, 0x0407u,
        "YubiKey 5 NFC",
        WP11_PROTO_PIV,
        WP11_QUIRK_EXTENDED_APDU,
        WP11_ALGO_RSA2048 | WP11_ALGO_EC_P256 | WP11_ALGO_EC_P384
    },
    /* YubiKey 5C -- PIV, extended APDU, RSA-2048, P-256, P-384 */
    {
        0x1050u, 0x0406u,
        "YubiKey 5C",
        WP11_PROTO_PIV,
        WP11_QUIRK_EXTENDED_APDU,
        WP11_ALGO_RSA2048 | WP11_ALGO_EC_P256 | WP11_ALGO_EC_P384
    },
    /* YubiKey 5 Nano -- PIV, extended APDU, RSA-2048, P-256 */
    {
        0x1050u, 0x0410u,
        "YubiKey 5 Nano",
        WP11_PROTO_PIV,
        WP11_QUIRK_EXTENDED_APDU,
        WP11_ALGO_RSA2048 | WP11_ALGO_EC_P256
    },
    /* NitroKey HSM 2 -- PIV, extended APDU, RSA-2048, P-256 */
    {
        0x20A0u, 0x4108u,
        "NitroKey HSM 2",
        WP11_PROTO_PIV,
        WP11_QUIRK_EXTENDED_APDU,
        WP11_ALGO_RSA2048 | WP11_ALGO_EC_P256
    },
    /* NitroKey Pro 2 -- OpenPGP card */
    {
        0x20A0u, 0x4109u,
        "NitroKey Pro 2",
        WP11_PROTO_OPENPGP,
        WP11_QUIRK_NONE,
        WP11_ALGO_RSA2048 | WP11_ALGO_EC_P256
    },
    /* Feitian ePass3003 -- FIDO2 + PIV, short APDU only */
    {
        0x096Eu, 0x0608u,
        "Feitian ePass3003",
        WP11_PROTO_PIV,
        WP11_QUIRK_SHORT_APDU,
        WP11_ALGO_RSA2048 | WP11_ALGO_EC_P256
    },
    /* Feitian FIDO K9 -- PIV-capable, short APDU only */
    {
        0x096Eu, 0x0858u,
        "Feitian FIDO K9",
        WP11_PROTO_PIV,
        WP11_QUIRK_SHORT_APDU,
        WP11_ALGO_RSA2048 | WP11_ALGO_EC_P256
    },
    /*
     * DoD CAC cards: CAC/PIV smart cards typically attach via a generic
     * CCID reader (e.g. SCM SCR3310, ActivKey) whose VID/PID identifies
     * the reader, not the card.  ATR-based matching would be required to
     * distinguish CAC from other ISO 7816 cards in the same reader.
     * wolfP11 does not currently support ATR matching.  Use
     * wp11_token_db_lookup_unknown() to obtain the conservative PIV
     * fallback descriptor for unrecognised reader/card combinations.
     */
};

#define WP11_TOKEN_DB_SIZE \
    (sizeof(wp11_token_db) / sizeof(wp11_token_db[0]))

/* wolfP11-wjbo: _Static_assert gives a human-readable error when the table
 * count drifts (e.g. "Update WP11_TOKEN_DB_SIZE == N...").  The C99 fallback
 * keeps the negative-array trick with a descriptive symbol name. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(WP11_TOKEN_DB_SIZE == 7u,
    "Update expected token count in wp11_token_db.c after adding or removing entries");
#else
extern char wp11_token_db_expected_7_entries[(WP11_TOKEN_DB_SIZE == 7u) ? 1 : -1];
#endif

/* Generic PIV fallback for tokens not in the table.
 * Uses WP11_QUIRK_SHORT_APDU as a conservative default -- assumes extended
 * APDU is not supported until confirmed.  Callers that want to attempt PIV
 * on an unrecognised token should use this rather than hardcoding defaults. */
static const wp11_token_desc_t wp11_token_db_fallback = {
    0x0000u, 0x0000u,
    "Generic PIV Token",
    WP11_PROTO_PIV,
    WP11_QUIRK_SHORT_APDU,
    WP11_ALGO_RSA2048 | WP11_ALGO_EC_P256
};

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

const wp11_token_desc_t *wp11_token_db_lookup(uint16_t vid, uint16_t pid)
{
    size_t i;

    for (i = 0; i < WP11_TOKEN_DB_SIZE; i++) {
        if (wp11_token_db[i].usb_vid == vid &&
            wp11_token_db[i].usb_pid == pid) {
            return &wp11_token_db[i];
        }
    }
    return NULL;
}

const wp11_token_desc_t *wp11_token_db_lookup_unknown(void)
{
    return &wp11_token_db_fallback;
}

size_t wp11_token_db_count(void)
{
    return WP11_TOKEN_DB_SIZE;
}
