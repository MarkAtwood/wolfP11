/* wp11_backend_fsdir.c -- wolfP11 filesystem directory keystore backend
 *
 * Crypto operations (sign, verify, decrypt) are implemented in
 * wp11_backend_keystore.c and shared with the USB flash backend.  This file
 * exports the ops struct that wires the FSDIR backend type tag to those
 * shared functions.
 */

#include "wolfp11/wp11_backend.h"
#include "wolfp11/wp11_settings.h"

#ifdef WOLFP11_CFG_FSDIR_BACKEND

const wp11_backend_ops_t wp11_backend_fsdir_ops = {
    WP11_BACKEND_FSDIR,
    wp11_ks_sign,
    wp11_ks_verify,
    wp11_ks_decrypt,
    /* derive: fsdir keys are stored-key-only; no hardware ECDH support. */
    NULL,
    /* free_key_priv is NULL for the fsdir backend.  key_priv for fsdir keys
     * points into the wp11_keystore_t entries array, which is owned and freed
     * in bulk by wp11_keystore_free.  Individual per-key free must NOT be
     * called. */
    NULL,
};

#endif /* WOLFP11_CFG_FSDIR_BACKEND */
