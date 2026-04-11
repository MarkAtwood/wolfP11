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

/* wp11_keystore.h -- wolfP11 encrypted keystore API
 *
 * Loads private keys from an encrypted .p11k file on a USB flash drive
 * (or any filesystem path).  The file format is shared with soft_PKCS11
 * (~/soft_PKCS11) for cross-tool compatibility.
 *
 * Threat model: keys are encrypted at rest on the USB drive with
 * AES-256-GCM, derived from a PIN via PBKDF2-HMAC-SHA256.  Key material
 * is mlock()'d in RAM after decryption and wp11_zero()'d before free.
 *
 * Reference: ~/soft_PKCS11/usb-hsm/src/keystore.rs
 */

#ifndef WOLFP11_KEYSTORE_H
#define WOLFP11_KEYSTORE_H

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * Error codes -- negative = error, 0 = success
 * ---------------------------------------------------------------------- */

#define WP11_KEYSTORE_OK                  0
#define WP11_KEYSTORE_ERR_PARAM          -1
#define WP11_KEYSTORE_ERR_IO             -2
#define WP11_KEYSTORE_ERR_NOMEM          -3
#define WP11_KEYSTORE_ERR_BAD_MAGIC      -4   /* not a .p11k file */
#define WP11_KEYSTORE_ERR_BAD_VERSION    -5   /* unsupported version byte */
#define WP11_KEYSTORE_ERR_BAD_PIN        -6   /* AES-GCM auth tag mismatch */
#define WP11_KEYSTORE_ERR_KDF_WEAK       -7   /* iteration count < 100000 */
#define WP11_KEYSTORE_ERR_TRUNCATED      -8   /* file shorter than header */
#define WP11_KEYSTORE_ERR_CBOR           -9   /* malformed CBOR payload */
#define WP11_KEYSTORE_ERR_MLOCK         -10   /* mlock() failed */
#define WP11_KEYSTORE_ERR_CRYPTO        -11   /* wolfCrypt error */
#define WP11_KEYSTORE_ERR_UNSUPPORTED   -12   /* format not yet supported */
#define WP11_KEYSTORE_ERR_BAD_ITER      -13   /* wolfP11-wgxd: PBKDF2 iteration count out of range (not too-weak, just invalid) */
#define WP11_KEYSTORE_ERR_INVALID_DER   -14   /* wolfP11-wgxd: DER parse failed -- distinct from CBOR format errors */

/* -------------------------------------------------------------------------
 * Key type constants
 * ---------------------------------------------------------------------- */

#define WP11_KEY_TYPE_RSA    0
#define WP11_KEY_TYPE_EC     1

/* -------------------------------------------------------------------------
 * Key entry -- one private key loaded from the keystore
 * ---------------------------------------------------------------------- */

/* Maximum sizes for key entry fields */
#define WP11_KEYSTORE_LABEL_MAX  64u
#define WP11_KEYSTORE_DER_MAX    4096u   /* RSA-4096 DER is ~2350 bytes */
#define WP11_KEYSTORE_CERT_MAX   4096u   /* X.509 certificate DER */

typedef struct {
    uint8_t  id[16];                          /* CKA_ID -- random 16-byte identifier */
    char     label[WP11_KEYSTORE_LABEL_MAX + 1u]; /* NUL-terminated CKA_LABEL */
    int      key_type;                        /* WP11_KEY_TYPE_RSA or WP11_KEY_TYPE_EC */
    uint8_t *der_bytes;  /* heap-alloc, mlock'd; PKCS#1 or SEC1 DER */
    size_t   der_len;
    uint8_t *cert_bytes; /* optional; heap-alloc (not mlock'd); X.509 DER */
    size_t   cert_len;
} wp11_key_entry_t;

/* -------------------------------------------------------------------------
 * Opaque keystore handle
 * ---------------------------------------------------------------------- */

typedef struct wp11_keystore wp11_keystore_t;

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/* Load a .p11k keystore from path, decrypting with PIN.
 * On success: returns WP11_KEYSTORE_OK, *ks_out points to a heap-alloc'd
 * keystore with mlock'd key material.
 * On failure: returns a WP11_KEYSTORE_ERR_* code; *ks_out is NULL. */
int wp11_keystore_load(const char      *path,
                       const uint8_t   *pin,  size_t pinlen,
                       wp11_keystore_t **ks_out);

/* Free the keystore: explicit_bzero all key material while mlock'd, then munlock.
 * Safe to call with NULL. */
void wp11_keystore_free(wp11_keystore_t *ks);

/* Return the number of key entries in the keystore. */
size_t wp11_keystore_count(const wp11_keystore_t *ks);

/* Return a pointer to the i-th key entry.  NULL if i >= count. */
const wp11_key_entry_t *wp11_keystore_get(const wp11_keystore_t *ks, size_t i);

/* Create a new .p11k file at path from a set of key entries and a PIN.
 * Uses wolfCrypt RNG for salt and nonce.  PBKDF2 iterations default to
 * WP11_KEYSTORE_KDF_ITERATIONS.
 * Intended for test setup and provisioning tools; not required at runtime. */
int wp11_keystore_create(const char             *path,
                         const uint8_t          *pin,   size_t pinlen,
                         const wp11_key_entry_t *keys,  size_t nkeys);

/* -------------------------------------------------------------------------
 * Provisioning helpers -- used by the CLI and test tools
 * ---------------------------------------------------------------------- */

/* Generate a random 16-byte key ID via wolfCrypt RNG.
 * Returns WP11_KEYSTORE_OK on success. */
int wp11_keystore_gen_id(uint8_t id[16]);

/* Detect the key type (WP11_KEY_TYPE_RSA or WP11_KEY_TYPE_EC) from a
 * PKCS#1 / SEC1 DER blob.  Returns the key type on success, or a negative
 * WP11_KEYSTORE_ERR_* code if the DER does not parse as either. */
int wp11_keystore_detect_key_type(const uint8_t *der, size_t derlen);

/* Convert a PEM-encoded private key to DER.  The output buffer is a plain
 * malloc'd allocation (not mlock'd -- use in provisioning paths only, where
 * the bytes are passed immediately to wp11_keystore_create and zeroized).
 * Caller must wp11_zero + free the buffer after use.
 * Returns WP11_KEYSTORE_OK on success. */
int wp11_keystore_pem_to_der(const uint8_t *pem, size_t pemlen,
                              uint8_t **der_out, size_t *derlen_out);

/* Convert a PEM-encoded X.509 certificate to DER.  *der_out is a plain
 * malloc'd buffer (not mlock'd; certificates are public data).
 * Returns WP11_KEYSTORE_OK on success. */
int wp11_keystore_cert_pem_to_der(const uint8_t *pem, size_t pemlen,
                                   uint8_t **der_out, size_t *derlen_out);

#endif /* WOLFP11_KEYSTORE_H */
