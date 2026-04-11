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

/* wp11_backend.h -- wolfP11 backend registration interface
 *
 * A backend implements crypto operations for a slot.
 * Each slot has exactly one backend.  The PKCS#11 layer dispatches
 * C_Sign, C_Verify, C_Decrypt calls through this interface.
 */

#ifndef WOLFP11_BACKEND_H
#define WOLFP11_BACKEND_H

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Size downcast safety macros
 *
 * wolfCrypt APIs use word32 (uint32_t) for buffer lengths; wolfHSM APIs
 * use uint16_t.  PKCS#11 callers supply size_t, which is 64 bits on LP64
 * targets.  Every narrowing cast from size_t to a smaller integer type
 * must be preceded by one of these checks.  Silent truncation on a 64-bit
 * host would corrupt the length field, causing wolfCrypt to read/write the
 * wrong number of bytes -- a silent cryptographic failure or buffer overrun.
 *
 * Usage:
 *   if (!WP11_FITS_U32(sz)) { <cleanup>; return -1; }
 *   wolfcrypt_fn(buf, (word32)sz, ...);
 * ---------------------------------------------------------------------- */
#define WP11_FITS_U32(sz)  ((sz) <= (size_t)UINT32_MAX)
#define WP11_FITS_U16(sz)  ((sz) <= (size_t)UINT16_MAX)

/* wolfP11-lf4o: maximum OAEP label length in bytes.
 * Defined here (not in wp11_pkcs11.c or wp11_backend_soft.c) so that the
 * session-side buffer (oaep_enc_label[]) and the backend stack buffer
 * (label_buf[]) are always sized identically.  A divergence between two
 * independent #defines would turn the memcpy of a session label into a stack
 * overflow inside the backend. */
#define WP11_OAEP_LABEL_MAX  64u

/* -------------------------------------------------------------------------
 * Backend error codes -- returned by sign/verify/decrypt/derive callbacks
 *
 * All callbacks return 0 on success and a negative WP11_BACKEND_ERR_*
 * code on failure.  The PKCS#11 layer maps these to CK_RV values via
 * backend_err_to_rv() in wp11_pkcs11.c.
 *
 * The codes are defined here so backend implementations can return them
 * without a compile dependency on the PKCS#11 layer.
 * ---------------------------------------------------------------------- */

#define WP11_BACKEND_ERR_GENERAL        (-1)  /* generic / unclassified failure      */
#define WP11_BACKEND_ERR_NOT_READY      (-2)  /* device not ready -- retry may work   */
#define WP11_BACKEND_ERR_TIMEOUT        (-3)  /* device/server timeout               */
#define WP11_BACKEND_ERR_KEY_NOT_FOUND  (-4)  /* key not found on device             */
#define WP11_BACKEND_ERR_USAGE          (-5)  /* key usage flags reject operation    */
#define WP11_BACKEND_ERR_NOT_IMPL       (-6)  /* operation not implemented on device */
#define WP11_BACKEND_ERR_SIG_INVALID    (-7)  /* signature cryptographically invalid */

/* -------------------------------------------------------------------------
 * Backend type tags
 * ---------------------------------------------------------------------- */

typedef enum {
    WP11_BACKEND_SOFT      = 0,  /* wolfCrypt direct (no hardware)              */
    WP11_BACKEND_USB       = 1,  /* USB token via CCID                          */
    WP11_BACKEND_WOLFHSM   = 2,  /* wolfHSM server via WH_DEV_ID callback       */
    WP11_BACKEND_USB_FLASH = 3,  /* Encrypted .p11k keystore on USB flash drive */
    WP11_BACKEND_FSDIR     = 4,  /* Encrypted .p11k keystore in watched directory */
} wp11_backend_type_t;

/* -------------------------------------------------------------------------
 * Key handle -- opaque to callers; backend-specific meaning
 * ---------------------------------------------------------------------- */

typedef struct wp11_key_handle {
    wp11_backend_type_t backend;
    uint32_t            id;     /* backend-specific key identifier         */
    void               *priv;   /* backend-specific extra data             */
} wp11_key_handle_t;

/* -------------------------------------------------------------------------
 * Backend dispatch table
 * ---------------------------------------------------------------------- */

typedef struct wp11_backend_ops {
    wp11_backend_type_t type;

    /* Sign data using the key identified by handle.
     * mechanism: CKM_* value
     * in/inlen: data or hash to sign
     * sig/siglen: output buffer; *siglen set to actual bytes on success
     *
     * wolfP11-izdd: MUST NOT be NULL.  Every backend must implement sign.
     * wp11_backend_validate() in wp11_pkcs11.c checks all required pointers
     * at C_Initialize time; a misconfigured backend causes CKR_GENERAL_ERROR
     * before any slot is used.
     * If a backend has no signing key support, return WP11_BACKEND_ERR_NOT_IMPL
     * instead of leaving NULL. */
    int (*sign)(const wp11_key_handle_t *handle,
                uint32_t                mechanism,
                const uint8_t          *in,    size_t  inlen,
                uint8_t                *sig,   size_t *siglen);

    /* Verify a signature.
     * Returns 0 on valid, negative on invalid or error.
     *
     * wolfP11-izdd: MUST NOT be NULL.  Same constraint as sign above.
     * Checked by wp11_backend_validate() at C_Initialize time. */
    int (*verify)(const wp11_key_handle_t *handle,
                  uint32_t                 mechanism,
                  const uint8_t           *in,    size_t inlen,
                  const uint8_t           *sig,   size_t siglen);

    /* Decrypt ciphertext.
     *
     * wolfP11-izdd: MUST NOT be NULL.  Same constraint as sign above.
     * Checked by wp11_backend_validate() at C_Initialize time. */
    int (*decrypt)(const wp11_key_handle_t *handle,
                   uint32_t                 mechanism,
                   const uint8_t           *ct,    size_t  ctlen,
                   uint8_t                 *pt,    size_t *ptlen);

    /* Derive a shared secret (ECDH key agreement).
     * mechanism: CKM_ECDH1_DERIVE (0x1050)
     * peer_pub: uncompressed EC point (04 || X || Y); P-256: 65 bytes
     * shared/sharedlen: output x-coordinate; P-256: 32 bytes, P-384: 48 bytes
     * NULL means this backend does not support key derivation. */
    int (*derive)(const wp11_key_handle_t *handle,
                  uint32_t                 mechanism,
                  const uint8_t           *peer_pub,    size_t  peer_pub_len,
                  uint8_t                 *shared,      size_t *sharedlen);

    /* Release backend-private state associated with a key handle's priv
     * pointer.  Called by C_Finalize and C_DestroyObject.
     *
     * wolfP11-be5 invariant -- two ownership models:
     *
     * NULL   -- backend owns key_priv in bulk; the caller MUST NOT free
     *           key_priv individually.  Use this when key_priv points into
     *           a contiguous array allocated and freed as a unit (e.g. the
     *           flash/fsdir keystore: all entries live in one mlock'd block
     *           freed by wp11_keystore_free).  The PKCS#11 layer identifies
     *           keystore-backed keys by free_key_priv == NULL (see
     *           ks_slot_clear_keys in wp11_pkcs11.c); this sentinel MUST be
     *           preserved for those backends.
     *
     * non-NULL -- backend heap-allocates key_priv per key; this function is
     *             called exactly once per key when that key is destroyed.
     *             The soft token (wp11_soft_key_t), USB (wp11_usb_key_priv_t),
     *             and wolfHSM (wp11_wolfhsm_key_priv_t) backends use this. */
    void (*free_key_priv)(void *key_priv);
} wp11_backend_ops_t;

/* -------------------------------------------------------------------------
 * Soft-token backend (always available, no hardware required)
 * ---------------------------------------------------------------------- */

extern const wp11_backend_ops_t wp11_backend_soft_ops;

/* -------------------------------------------------------------------------
 * USB hardware token backend (PIV/CCID; requires WOLFP11_CFG_USB_BACKEND)
 * ---------------------------------------------------------------------- */

#ifdef WOLFP11_CFG_USB_BACKEND

/* Opaque CCID context type -- defined in wp11_ccid.h.
 * Forward-declared here so wp11_usb_key_priv_t can hold a pointer without
 * pulling in the full CCID header from every file that includes wp11_backend.h. */
typedef struct wp11_ccid_ctx wp11_ccid_ctx_t;

/* Per-key state for USB hardware token (PIV) keys.
 * Allocated at C_Login / C_GenerateKeyPair time.
 * Freed by wp11_backend_usb_ops.free_key_priv.
 * ccid is a non-owning pointer (the slot owns the CCID context lifetime). */
typedef struct {
    wp11_ccid_ctx_t *ccid;      /* CCID context -- borrowed from slot     */
    uint8_t          piv_slot;  /* WP11_PIV_SLOT_* (0x9A/9C/9D/9E)      */
    uint8_t          piv_alg;   /* WP11_PIV_ALG_* (0x07/0x11/0x14)      */
} wp11_usb_key_priv_t;

extern const wp11_backend_ops_t wp11_backend_usb_ops;
#endif /* WOLFP11_CFG_USB_BACKEND */

/* -------------------------------------------------------------------------
 * Shared keystore crypto ops (USB flash + FSDIR backends)
 *
 * wp11_backend_keystore.c provides one implementation used by both backends.
 * ---------------------------------------------------------------------- */

#if defined(WOLFP11_CFG_USB_FLASH_BACKEND) || defined(WOLFP11_CFG_FSDIR_BACKEND)
/* Forward declaration for wp11_key_entry_t (defined in wp11_keystore.h).
 * Backends include wp11_keystore.h directly; this forward decl keeps
 * wp11_backend.h self-contained for callers that don't need the full type. */
struct wp11_key_entry;

int wp11_ks_sign(const wp11_key_handle_t *handle,
                 uint32_t                 mechanism,
                 const uint8_t           *in,    size_t  inlen,
                 uint8_t                 *sig,   size_t *siglen);

int wp11_ks_verify(const wp11_key_handle_t *handle,
                   uint32_t                 mechanism,
                   const uint8_t           *in,    size_t inlen,
                   const uint8_t           *sig,   size_t siglen);

int wp11_ks_decrypt(const wp11_key_handle_t *handle,
                    uint32_t                 mechanism,
                    const uint8_t           *ct,    size_t  ctlen,
                    uint8_t                 *pt,    size_t *ptlen);
#endif

/* -------------------------------------------------------------------------
 * USB flash drive keystore backend (requires WOLFP11_CFG_USB_FLASH_BACKEND)
 * ---------------------------------------------------------------------- */

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
extern const wp11_backend_ops_t wp11_backend_flash_ops;
#endif

/* -------------------------------------------------------------------------
 * Filesystem directory keystore backend (requires WOLFP11_CFG_FSDIR_BACKEND)
 * ---------------------------------------------------------------------- */

#ifdef WOLFP11_CFG_FSDIR_BACKEND
extern const wp11_backend_ops_t wp11_backend_fsdir_ops;
#endif

/* -------------------------------------------------------------------------
 * wolfHSM server backend (requires WOLFP11_CFG_WOLFHSM_BACKEND)
 * ---------------------------------------------------------------------- */

#ifdef WOLFP11_CFG_WOLFHSM_BACKEND

/* wolfP11-a0oa: magic sentinel for wp11_wolfhsm_key_priv_t.
 * ctx is stored as void* to decouple wp11_backend.h from wolfHSM headers;
 * the implementation casts it to whClientContext*.  A corrupted key handle
 * or a wrong pointer stored as key_priv would cause the cast to silently
 * operate on garbage memory.  The magic field lets the accessor (hsm_entry
 * in wp11_backend_wolfhsm.c) validate the struct identity before trusting
 * any pointer inside it.  It is set in wp11_wolfhsm_alloc_key_priv and
 * checked before every void* cast. */
#define WP11_WOLFHSM_KEY_MAGIC  0x57483131U  /* 'W','H','1','1' in ASCII */

/* Per-key private state for wolfHSM-backed keys.
 *
 * ctx is a non-owning pointer to the slot's whClientContext.  The slot
 * owns the client context lifetime; the key_priv only borrows it.
 *
 * ctx is stored as void* to avoid pulling wolfHSM headers into every
 * translation unit that includes wp11_backend.h.  The implementation
 * casts it to whClientContext* internally.
 *
 * key_size is the RSA modulus size in bytes (set at key creation);
 * 0 for EC keys.  Caching it here avoids a server round-trip per RSA
 * operation just to query the key size. */
typedef struct {
    uint32_t magic;         /* WP11_WOLFHSM_KEY_MAGIC -- validate before void* cast */
    void    *ctx;           /* whClientContext* -- cast in implementation        */
    uint16_t key_id;        /* wolfHSM server-side key ID (whKeyId = uint16_t)  */
    int      key_type;      /* WP11_KEY_TYPE_RSA or WP11_KEY_TYPE_EC            */
    uint16_t key_size;      /* RSA modulus bytes; 0 for EC                      */
    int      generated_here; /* 1 if created by C_GenerateKeyPair; evict on free */
} wp11_wolfhsm_key_priv_t;

/* Allocate and initialise a wolfHSM key private struct.
 * ctx: whClientContext* (passed as void* to avoid header dependency)
 * key_id: wolfHSM server key ID (whKeyId / uint16_t)
 * key_type: WP11_KEY_TYPE_RSA or WP11_KEY_TYPE_EC
 * key_size: RSA modulus size in bytes; 0 for EC keys
 * Returns a malloc'd struct on success, NULL on allocation failure. */
wp11_wolfhsm_key_priv_t *wp11_wolfhsm_alloc_key_priv(void    *ctx,
                                                       uint16_t key_id,
                                                       int      key_type,
                                                       uint16_t key_size);

extern const wp11_backend_ops_t wp11_backend_wolfhsm_ops;

#endif /* WOLFP11_CFG_WOLFHSM_BACKEND */

#endif /* WOLFP11_BACKEND_H */
