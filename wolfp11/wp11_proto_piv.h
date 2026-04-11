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

/* wp11_proto_piv.h -- wolfP11 PIV protocol API
 *
 * Implements NIST SP 800-73 PIV applet APDU sequences.
 * Operates on top of a wp11_ccid_ctx_t transport.
 */

#ifndef WOLFP11_PROTO_PIV_H
#define WOLFP11_PROTO_PIV_H

#include <stdint.h>
#include <stddef.h>
#include "wolfp11/wp11_ccid.h"

/* -------------------------------------------------------------------------
 * PIV AID (SP 800-73-4 Section 2.2)
 * ---------------------------------------------------------------------- */

#define WP11_PIV_AID        "\xA0\x00\x00\x03\x08\x00\x00\x10\x00\x01\x00"
#define WP11_PIV_AID_LEN    11

/* -------------------------------------------------------------------------
 * PIV slot identifiers (SP 800-73 Table 4b)
 * ---------------------------------------------------------------------- */

#define WP11_PIV_SLOT_AUTH      0x9A  /* PIV Authentication             */
#define WP11_PIV_SLOT_SIGN      0x9C  /* Digital Signature              */
#define WP11_PIV_SLOT_KEYMGMT   0x9D  /* Key Management                 */
#define WP11_PIV_SLOT_CARDAUTH  0x9E  /* Card Authentication            */

/* -------------------------------------------------------------------------
 * PIV algorithm identifiers (SP 800-73 Table 5)
 * ---------------------------------------------------------------------- */

#define WP11_PIV_ALG_RSA2048    0x07
#define WP11_PIV_ALG_EC_P256    0x11
#define WP11_PIV_ALG_EC_P384    0x14

/* -------------------------------------------------------------------------
 * Error codes (negative = error)
 * ---------------------------------------------------------------------- */

#define WP11_PIV_OK              0
#define WP11_PIV_ERR_PARAM      -1
#define WP11_PIV_ERR_TRANSPORT  -2
#define WP11_PIV_ERR_SW         -3  /* unexpected SW1/SW2 from card      */
#define WP11_PIV_ERR_BUFSIZE    -4
#define WP11_PIV_ERR_PIN_BAD    -5  /* SW 63 Cx                          */
#define WP11_PIV_ERR_PIN_LOCKED -6  /* SW 69 83                          */
#define WP11_PIV_ERR_TRUNCATED  -7  /* transport delivered fewer than 2 bytes */
#define WP11_PIV_ERR_ENCODING   -8  /* malformed BER-TLV in card response  */
#define WP11_PIV_ERR_NOT_FOUND       -9  /* SW 6A 82: cert slot or key not found    */
#define WP11_PIV_ERR_USER_PRESENCE  -10  /* SW 69 85: touch timeout or PIN required  */
#define WP11_PIV_ERR_SECURITY_STATUS -11 /* SW 69 82: security status not satisfied  */
#define WP11_PIV_ERR_NOT_SUPPORTED  -12  /* SW 6A 81: function not supported by token */
/* wolfP11-dkm: distinct from ERR_PARAM so callers can distinguish OOM from
 * bad-argument bugs and apply the correct recovery (abort vs. retry). */
#define WP11_PIV_ERR_NOMEM          -13  /* malloc/allocation failure                 */

/* Maximum DER certificate size accepted by wp11_piv_get_cert.
 * PIV X.509 certificates in practice are 1-4 KB; 4096 is a safe upper bound. */
#define WP11_PIV_CERT_MAX_LEN 4096u

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/* SELECT the PIV AID on the token. */
int wp11_piv_select(wp11_ccid_ctx_t *ccid);

/* VERIFY a PIV PIN. pin is the raw UTF-8 PIN bytes; pinlen 4..8. */
int wp11_piv_verify_pin(wp11_ccid_ctx_t *ccid,
                        const uint8_t   *pin, size_t pinlen);

/* GENERAL AUTHENTICATE: sign a challenge with a PIV slot.
 * slot:      WP11_PIV_SLOT_* constant
 * alg:       WP11_PIV_ALG_* constant
 * challenge: hash or data to sign
 * sig/siglen: output buffer; *siglen updated to actual length */
int wp11_piv_sign(wp11_ccid_ctx_t *ccid,
                  uint8_t          slot,      uint8_t alg,
                  const uint8_t   *challenge, size_t  challengelen,
                  uint8_t         *sig,       size_t *siglen);

/* GET DATA: retrieve a certificate object.
 * slot:     WP11_PIV_SLOT_* constant (used to select tag)
 * cert/certlen: output buffer; *certlen updated to actual length */
int wp11_piv_get_cert(wp11_ccid_ctx_t *ccid,
                      uint8_t          slot,
                      uint8_t         *cert, size_t *certlen);

/* GENERATE ASYMMETRIC KEY PAIR: generate a fresh key pair on the token.
 * slot:    WP11_PIV_SLOT_* constant (target key slot)
 * alg:     WP11_PIV_ALG_* constant (key type and size)
 * pubkey_out: output buffer for the public key (NULL to discard)
 *   ECC: EC point (04 || X || Y); P-256 = 65 bytes, P-384 = 97 bytes
 *   RSA: modulus bytes (256 bytes for RSA-2048)
 * *pubkey_len: in: buffer size; out: bytes written (ignored if pubkey_out NULL) */
int wp11_piv_generate_key(wp11_ccid_ctx_t *ccid,
                           uint8_t          slot,
                           uint8_t          alg,
                           uint8_t         *pubkey_out,
                           size_t          *pubkey_len);

/* ATTEST: retrieve a YubiKey PIV attestation certificate for a key slot.
 * YubiKey-specific; APDU: 00 F9 00 <slot> 00.
 * Response is raw DER (no BER-TLV wrapper); GET RESPONSE chaining is used
 * for responses that exceed one APDU payload.
 * slot:     WP11_PIV_SLOT_* constant
 * der/derlen: output buffer; *derlen updated to actual length */
int wp11_piv_attest(wp11_ccid_ctx_t *ccid,
                    uint8_t          slot,
                    uint8_t         *der, size_t *derlen);

/* GENERAL AUTHENTICATE in key-agreement mode (SP 800-73-4 sec.3.2.4).
 * Sends the peer EC public key to the token; the token performs ECDH and
 * returns the x-coordinate of the shared point.
 * slot:          WP11_PIV_SLOT_KEYMGMT (0x9D) for key management
 * alg:           WP11_PIV_ALG_EC_P256 or WP11_PIV_ALG_EC_P384
 * peer_pub:      uncompressed EC point (04 || X || Y); P-256: 65 bytes
 * shared/sharedlen: output x-coordinate; P-256: 32 bytes, P-384: 48 bytes */
int wp11_piv_ecdh(wp11_ccid_ctx_t *ccid,
                  uint8_t          slot,
                  uint8_t          alg,
                  const uint8_t   *peer_pub,    size_t  peer_pub_len,
                  uint8_t         *shared,      size_t *sharedlen);

#endif /* WOLFP11_PROTO_PIV_H */
