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
     * sig/siglen: output buffer; *siglen set to actual bytes on success */
    int (*sign)(const wp11_key_handle_t *handle,
                uint32_t                mechanism,
                const uint8_t          *in,    size_t  inlen,
                uint8_t                *sig,   size_t *siglen);

    /* Verify a signature.
     * Returns 0 on valid, negative on invalid or error. */
    int (*verify)(const wp11_key_handle_t *handle,
                  uint32_t                 mechanism,
                  const uint8_t           *in,    size_t inlen,
                  const uint8_t           *sig,   size_t siglen);

    /* Decrypt ciphertext. */
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
     * NULL means the backend owns key_priv in bulk and the caller must NOT
     * free it individually (e.g. flash keystore -- wp11_keystore_free handles
     * the bulk free).  Non-NULL means the backend expects this function to
     * be called once per key object when that object is destroyed. */
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
 * USB flash drive keystore backend (requires WOLFP11_CFG_USB_FLASH_BACKEND)
 * ---------------------------------------------------------------------- */

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
extern const wp11_backend_ops_t wp11_backend_flash_ops;
#endif

/* -------------------------------------------------------------------------
 * wolfHSM server backend (requires WOLFP11_CFG_WOLFHSM_BACKEND)
 * ---------------------------------------------------------------------- */

#ifdef WOLFP11_CFG_WOLFHSM_BACKEND

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
    void    *ctx;       /* whClientContext* -- cast in implementation        */
    uint16_t key_id;    /* wolfHSM server-side key ID (whKeyId = uint16_t)  */
    int      key_type;  /* WP11_KEY_TYPE_RSA or WP11_KEY_TYPE_EC            */
    uint16_t key_size;  /* RSA modulus bytes; 0 for EC                      */
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
