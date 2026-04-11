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

/* wp11_ccid.h -- wolfP11 CCID transport API
 *
 * Frames ISO 7816 APDUs in CCID messages over libusb bulk transfers.
 * An injectable mock transport allows unit tests to run without hardware.
 */

#ifndef WOLFP11_CCID_H
#define WOLFP11_CCID_H

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Error codes returned by CCID functions (negative = error)
 * ---------------------------------------------------------------------- */

#define WP11_CCID_OK            0
#define WP11_CCID_ERR_PARAM    -1   /* bad argument                        */
#define WP11_CCID_ERR_USB      -2   /* libusb transfer error               */
#define WP11_CCID_ERR_STATUS   -3   /* CCID bStatus != 0                   */
#define WP11_CCID_ERR_SEQ      -4   /* sequence number mismatch            */
#define WP11_CCID_ERR_BUFSIZE  -5   /* response buffer too small           */
#define WP11_CCID_ERR_NOMEM    -6   /* allocation failure                  */
#define WP11_CCID_ERR_NOTFOUND -7   /* USB device not found                */
#define WP11_CCID_ERR_TIMEOUT  -8   /* LIBUSB_ERROR_TIMEOUT: device present but slow */
#define WP11_CCID_ERR_NO_CARD  -9   /* ICC absent or inactive (iccStatus 1 or 2)     */

/* -------------------------------------------------------------------------
 * Opaque context
 * ---------------------------------------------------------------------- */

typedef struct wp11_ccid_ctx wp11_ccid_ctx_t;

/* -------------------------------------------------------------------------
 * Mock transport injection (for unit tests without hardware)
 *
 * The transport function receives the outgoing CCID bulk packet and must
 * fill in the incoming CCID bulk packet.  Returns 0 on success.
 * ---------------------------------------------------------------------- */

typedef int (*wp11_ccid_transport_fn)(void          *userdata,
                                      const uint8_t *out, size_t  outlen,
                                      uint8_t       *in,  size_t *inlen);

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/* Open a real USB device.  Finds the first matching VID/PID. */
int  wp11_ccid_open(uint16_t vid, uint16_t pid, wp11_ccid_ctx_t **ctx_out);

/* Open a mock transport for testing. */
int  wp11_ccid_open_mock(wp11_ccid_transport_fn transport,
                         void                   *userdata,
                         wp11_ccid_ctx_t       **ctx_out);

/* Send an APDU and receive the response.
 * On success *resplen is set to the number of bytes written to resp.
 * The two ISO 7816 status bytes are always appended: resp[*resplen-2] is SW1,
 * resp[*resplen-1] is SW2.  *resplen is always >= 2 on success.
 * Protocol callers must strip the final two bytes to obtain the data payload.
 *
 * Thread safety: NOT thread-safe.  The context holds a shared sequence counter
 * (ctx->seq) with no internal locking.  Concurrent calls on the same context
 * will corrupt the CCID conversation.  Each context must be used by at most
 * one thread at a time; use one context per USB device per thread if concurrent
 * access is required (the device itself serializes CCID transactions). */
int  wp11_ccid_apdu(wp11_ccid_ctx_t *ctx,
                    const uint8_t   *cmd,  size_t  cmdlen,
                    uint8_t         *resp, size_t *resplen);

/* Close and free the context. */
void wp11_ccid_close(wp11_ccid_ctx_t *ctx);

#endif /* WOLFP11_CCID_H */
