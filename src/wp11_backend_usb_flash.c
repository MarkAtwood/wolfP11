/* wp11_backend_usb_flash.c -- wolfP11 USB flash drive keystore backend
 *
 * Crypto operations (sign, verify, decrypt) are implemented in
 * wp11_backend_keystore.c and shared with the FSDIR backend.  This file
 * exports the ops struct that wires the USB flash backend type tag to those
 * shared functions.
 */

#include "wolfp11/wp11_backend.h"
#include "wolfp11/wp11_settings.h"

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND

const wp11_backend_ops_t wp11_backend_flash_ops = {
    WP11_BACKEND_USB_FLASH,
    wp11_ks_sign,
    wp11_ks_verify,
    wp11_ks_decrypt,
    /* derive: flash keys are stored-key-only; no hardware ECDH support. */
    NULL,
    /* wolfP11-be5: free_key_priv is NULL for the flash backend.  key_priv
     * for flash keys points into the wp11_keystore_t entries array, which
     * is owned and freed in bulk by wp11_keystore_free.  Individual per-key
     * free must NOT be called. */
    NULL,
};

#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */
