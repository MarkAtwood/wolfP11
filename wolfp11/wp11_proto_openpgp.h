/* wp11_proto_openpgp.h -- wolfP11 OpenPGP card protocol API
 *
 * Implements OpenPGP card specification APDU sequences.
 * Operates on top of a wp11_ccid_ctx_t transport.
 *
 * Reference: OpenPGP card specification v3.4 (gnupg.org)
 */

#ifndef WOLFP11_PROTO_OPENPGP_H
#define WOLFP11_PROTO_OPENPGP_H

#include <stdint.h>
#include <stddef.h>
#include "wolfp11/wp11_ccid.h"

/* -------------------------------------------------------------------------
 * OpenPGP AID prefix (6 bytes; manufacturer + serial follow)
 * ---------------------------------------------------------------------- */

#define WP11_OPENPGP_AID_PREFIX     "\xD2\x76\x00\x01\x24\x01"
#define WP11_OPENPGP_AID_PREFIX_LEN 6

/* -------------------------------------------------------------------------
 * Data Object (DO) tags used by this implementation
 * ---------------------------------------------------------------------- */

#define WP11_OPENPGP_DO_ARD     0x006E  /* Application Related Data        */
#define WP11_OPENPGP_DO_SST     0x007A  /* Security Support Template       */
#define WP11_OPENPGP_DO_ALG_SIG 0x00C1  /* Algorithm attributes: SIG key   */
#define WP11_OPENPGP_DO_ALG_DEC 0x00C2  /* Algorithm attributes: DEC key   */
#define WP11_OPENPGP_DO_ALG_AUT 0x00C3  /* Algorithm attributes: AUT key   */

/* -------------------------------------------------------------------------
 * PW1 mode for VERIFY (OpenPGP card spec Section 7.2.2)
 * ---------------------------------------------------------------------- */

#define WP11_OPENPGP_PW1_MODE_SIGN  0x81  /* for Compute Digital Signature  */
#define WP11_OPENPGP_PW1_MODE_OTHER 0x82  /* for all other operations        */

/* -------------------------------------------------------------------------
 * Error codes (negative = error)
 * ---------------------------------------------------------------------- */

#define WP11_OPENPGP_OK             0
#define WP11_OPENPGP_ERR_PARAM     -1
#define WP11_OPENPGP_ERR_TRANSPORT -2
#define WP11_OPENPGP_ERR_SW        -3   /* unexpected SW1/SW2              */
#define WP11_OPENPGP_ERR_BUFSIZE   -4
#define WP11_OPENPGP_ERR_PW_BAD   -5   /* wrong password                  */
#define WP11_OPENPGP_ERR_PW_LOCKED -6  /* password blocked                */
#define WP11_OPENPGP_ERR_TRUNCATED -7  /* transport delivered fewer than 2 bytes */

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/* SELECT the OpenPGP AID. */
int wp11_openpgp_select(wp11_ccid_ctx_t *ccid);

/* VERIFY a password.
 * mode: WP11_OPENPGP_PW1_MODE_SIGN or WP11_OPENPGP_PW1_MODE_OTHER */
int wp11_openpgp_verify_pw1(wp11_ccid_ctx_t *ccid,
                             const uint8_t   *pw, size_t pwlen, int mode);

/* COMPUTE DIGITAL SIGNATURE with the SIG subkey.
 * hash/hashlen: the hash to sign
 * sig/siglen:   output buffer; *siglen updated to actual length */
int wp11_openpgp_sign(wp11_ccid_ctx_t *ccid,
                      const uint8_t   *hash,   size_t  hashlen,
                      uint8_t         *sig,    size_t *siglen);

/* INTERNAL AUTHENTICATE with the AUT subkey. */
int wp11_openpgp_authenticate(wp11_ccid_ctx_t *ccid,
                               const uint8_t   *data,    size_t  datalen,
                               uint8_t         *resp,    size_t *resplen);

/* GET DATA: read Application Related Data (DO 006E). */
int wp11_openpgp_get_ard(wp11_ccid_ctx_t *ccid,
                          uint8_t         *buf, size_t *buflen);

#endif /* WOLFP11_PROTO_OPENPGP_H */
