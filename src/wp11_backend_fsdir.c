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
    /* wolfP11-be5: free_key_priv is NULL for the fsdir backend.  key_priv
     * for fsdir keys points into the wp11_keystore_t entries array, which
     * is owned and freed in bulk by wp11_keystore_free.  Individual per-key
     * free must NOT be called.  ks_slot_clear_keys() identifies keystore
     * keys by free_key_priv == NULL; this sentinel must be preserved. */
    NULL,
};

#endif /* WOLFP11_CFG_FSDIR_BACKEND */
