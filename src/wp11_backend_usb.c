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

/* wp11_backend_usb.c -- wolfP11 USB hardware token (PIV/CCID) backend
 *
 * Implements sign, verify, and decrypt for PIV hardware tokens via CCID.
 *
 * Each key object has a wp11_usb_key_priv_t (defined in wp11_backend.h) as
 * key_priv.  The struct holds a non-owning pointer to the slot's CCID context,
 * the PIV slot reference, and the algorithm identifier.  The CCID context
 * lifetime is managed by the PKCS#11 layer (C_Login opens, C_Logout closes).
 */

#include "wolfp11/wp11_backend.h"
#include "wolfp11/wp11_proto_piv.h"
#include "wolfp11/wp11_ccid.h"

#ifdef WOLFP11_CFG_USB_BACKEND

#include <stdlib.h>
#include <stdint.h>

/* CKM_* values (mirrored from PKCS#11 spec; avoid pulling in the full header) */
#define USB_CKM_RSA_PKCS      0x00000001UL
#define USB_CKM_ECDSA         0x00001041UL
#define USB_CKM_ECDSA_SHA256  0x00001044UL
#define USB_CKM_ECDH1_DERIVE  0x00001050UL

/* -------------------------------------------------------------------------
 * usb_sign
 *
 * Routes signing to the PIV GENERAL AUTHENTICATE APDU.  The caller
 * (C_Sign) passes a pre-hashed digest; the token applies the private key.
 *
 * Supported mechanisms:
 *   USB_CKM_ECDSA       -- raw ECDSA over a pre-hashed digest
 *   USB_CKM_RSA_PKCS    -- RSA PKCS#1 v1.5 over a pre-hashed digest
 *
 * USB_CKM_ECDSA_SHA256 is NOT supported here: the PIV GENERAL AUTHENTICATE
 * command takes a pre-hashed input, so the SHA-256 must be computed on the
 * host before calling this function.  C_Sign with CKM_ECDSA_SHA256 must hash
 * the data before dispatching here.
 * ---------------------------------------------------------------------- */

static int usb_sign(const wp11_key_handle_t *handle,
                    uint32_t                 mechanism,
                    const uint8_t           *in,    size_t  inlen,
                    uint8_t                 *sig,   size_t *siglen)
{
    const wp11_usb_key_priv_t *kp;
    int                        rc;

    if (handle == NULL || handle->priv == NULL ||
        in == NULL || sig == NULL || siglen == NULL) {
        return -1;
    }

    kp = (const wp11_usb_key_priv_t *)handle->priv;
    if (kp->ccid == NULL) return -1;

    if (mechanism == USB_CKM_ECDSA || mechanism == USB_CKM_RSA_PKCS) {
        rc = wp11_piv_sign(kp->ccid, kp->piv_slot, kp->piv_alg,
                           in, inlen, sig, siglen);
        return (rc == WP11_PIV_OK) ? 0 : -1;
    }

    return -1;  /* unsupported mechanism */
}

/* -------------------------------------------------------------------------
 * usb_verify
 *
 * PIV tokens do not expose a verify APDU.  Return -1 (not supported).
 * Callers that need verification must use the public key separately.
 * ---------------------------------------------------------------------- */

static int usb_verify(const wp11_key_handle_t *handle,
                      uint32_t                 mechanism,
                      const uint8_t           *in,    size_t inlen,
                      const uint8_t           *sig,   size_t siglen)
{
    (void)handle; (void)mechanism; (void)in; (void)inlen;
    (void)sig;    (void)siglen;
    return -1;
}

/* -------------------------------------------------------------------------
 * usb_decrypt
 *
 * PIV slot 9D supports RSA decrypt via GENERAL AUTHENTICATE, but that
 * path is not yet implemented (wolfP11-uf1).  Return -1 for now.
 * ---------------------------------------------------------------------- */

static int usb_decrypt(const wp11_key_handle_t *handle,
                       uint32_t                 mechanism,
                       const uint8_t           *ct,    size_t  ctlen,
                       uint8_t                 *pt,    size_t *ptlen)
{
    (void)handle; (void)mechanism; (void)ct; (void)ctlen;
    (void)pt;     (void)ptlen;
    return -1;
}

/* -------------------------------------------------------------------------
 * usb_derive
 *
 * Routes ECDH key agreement to PIV GENERAL AUTHENTICATE with exponentiation
 * component (tag 0x85).  Only slot 9D (KEYMGMT) supports ECDH on PIV tokens.
 * ---------------------------------------------------------------------- */

static int usb_derive(const wp11_key_handle_t *handle,
                      uint32_t                 mechanism,
                      const uint8_t           *peer_pub,    size_t  peer_pub_len,
                      uint8_t                 *shared,      size_t *sharedlen)
{
    const wp11_usb_key_priv_t *kp;
    int                        rc;

    if (handle == NULL || handle->priv == NULL ||
        peer_pub == NULL || shared == NULL || sharedlen == NULL) {
        return -1;
    }

    kp = (const wp11_usb_key_priv_t *)handle->priv;
    if (kp->ccid == NULL) return -1;

    if (mechanism != USB_CKM_ECDH1_DERIVE) {
        return -1;
    }

    rc = wp11_piv_ecdh(kp->ccid, kp->piv_slot, kp->piv_alg,
                       peer_pub, peer_pub_len, shared, sharedlen);
    return (rc == WP11_PIV_OK) ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * usb_free_key_priv
 *
 * Frees the heap-allocated wp11_usb_key_priv_t.  Does NOT close the CCID
 * context -- the slot owns the CCID context lifetime.
 * ---------------------------------------------------------------------- */

static void usb_free_key_priv(void *key_priv)
{
    free(key_priv);
}

/* -------------------------------------------------------------------------
 * wp11_backend_usb_ops -- dispatch table for USB hardware token backend
 * ---------------------------------------------------------------------- */

const wp11_backend_ops_t wp11_backend_usb_ops = {
    WP11_BACKEND_USB,
    usb_sign,
    usb_verify,
    usb_decrypt,
    usb_derive,
    usb_free_key_priv,
};

#endif /* WOLFP11_CFG_USB_BACKEND */
