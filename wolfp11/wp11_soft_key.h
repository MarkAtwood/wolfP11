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

/* wp11_soft_key.h -- wolfP11 soft-token key lifecycle API
 *
 * Declares the opaque wp11_soft_key_t type and the public constructor/
 * destructor functions.  The struct definition lives in
 * src/wp11_backend_soft.c to keep internal wolfCrypt state private.
 *
 * Under WOLFP11_CFG_TEST, also declares wp11_soft_key_test_export_priv_der
 * which exports the raw DER private key for oracle verification in tests.
 * This function MUST NOT be called from production code paths.
 */

#ifndef WOLFP11_SOFT_KEY_H
#define WOLFP11_SOFT_KEY_H

#include <stdint.h>
#include <stddef.h>

/* wolfP11-hp2s: maximum RSA key modulus size in bytes, for RSA-4096.
 * Used to size local scratch buffers in sign/verify/decrypt operations.
 * Named here so that a future increase (e.g. RSA-8192) is a one-line change
 * rather than a grep for magic 512s spread across multiple source files. */
#define WP11_RSA4096_BYTES  512u

/* Opaque soft key type -- struct definition in src/wp11_backend_soft.c */
typedef struct wp11_soft_key wp11_soft_key_t;

/* Allocate and generate a new P-256 ECDSA key.  Returns NULL on failure. */
wp11_soft_key_t *wp11_soft_key_new_ecc_p256(void);

/* Allocate and generate a new P-384 ECDSA key.  Returns NULL on failure. */
wp11_soft_key_t *wp11_soft_key_new_ecc_p384(void);

/* Allocate and generate a new RSA-2048 key.  Returns NULL on failure. */
wp11_soft_key_t *wp11_soft_key_new_rsa2048(void);

/* wolfP11-n1cj: Ed25519 is only compiled when wolfCrypt defines HAVE_ED25519.
 * Guard these declarations to prevent linker errors when building against a
 * wolfCrypt without Ed25519 support.  Mirrors the WC_RSA_PSS guard below. */
#ifdef HAVE_ED25519
/* Allocate and generate a new Ed25519 key.  Returns NULL on failure. */
wp11_soft_key_t *wp11_soft_key_new_ed25519(void);
#endif /* HAVE_ED25519 */

/* Allocate and generate a new RSA key of the given modulus bit length.
 * wolfP11-prlc: valid range is [WOLFSSL_MIN_RSA_BITS, 4096] where the lower
 * bound is set at wolfCrypt build time (typically 1024; 2048 in FIPS builds).
 * The upper bound is 4096 because WP11_KEYSTORE_DER_MAX is sized for RSA-4096;
 * keys larger than 4096 bits would exceed the DER export buffer.
 * Non-power-of-2 sizes and out-of-range values are rejected by wc_MakeRsaKey
 * which returns non-zero; this function then returns NULL.
 * Returns NULL on failure. */
wp11_soft_key_t *wp11_soft_key_new_rsa(int bits);

/* Free a soft key (safe to call with NULL). */
void wp11_soft_key_free(wp11_soft_key_t *key);

/* Load a soft key from an existing DER-encoded private key.
 * key_type: WP11_KEY_TYPE_EC (1) = ECC; WP11_KEY_TYPE_RSA (0) = RSA.
 * Returns NULL on failure. */
wp11_soft_key_t *wp11_soft_key_new_from_der(const uint8_t *der, size_t derlen,
                                             int key_type);

/* Export RSA public key components (big-endian modulus N and public exponent E).
 * n/nlen and e/elen: caller-supplied buffers and their sizes (updated to
 * actual bytes written).  WP11_RSA4096_BYTES each is sufficient for RSA-4096.
 * Returns 0 on success, -1 for non-RSA keys or on error. */
#include <wolfssl/options.h>          /* must precede wolfcrypt types */
#include <wolfssl/wolfcrypt/types.h>  /* word32 */
int wp11_soft_key_export_rsa_pub(wp11_soft_key_t *key,
                                  uint8_t *n, word32 *nlen,
                                  uint8_t *e, word32 *elen);

/* RSA PKCS#1 v1.5 public-key encryption.
 * If out is NULL, writes the required output length to *outlen and returns 0.
 * Otherwise encrypts in[0..inlen) into out[]; *outlen must be >= modulus size.
 * Returns 0 on success, negative on error. */
int wp11_soft_key_rsa_encrypt(wp11_soft_key_t *key,
                               const uint8_t *in, word32 inlen,
                               uint8_t *out, word32 *outlen);

/* RSA-OAEP (PKCS#1 v2.1) public-key encryption.
 * hash_type: WC_HASH_TYPE_* constant; mgf: WC_MGF1* constant.
 * If out is NULL, writes the modulus size to *outlen and returns 0 (size query).
 * label/label_len: optional OAEP label (NULL/0 for no label).
 * Returns 0 on success, negative on error. */
int wp11_soft_key_rsa_oaep_encrypt(wp11_soft_key_t *key,
                                    const uint8_t *in, word32 inlen,
                                    uint8_t *out, word32 *outlen,
                                    int hash_type, int mgf,
                                    const uint8_t *label, word32 label_len);

/* RSA-OAEP (PKCS#1 v2.1) private-key decryption.
 * hash_type: WC_HASH_TYPE_* constant; mgf: WC_MGF1* constant.
 * outbuflen: size of out[] buffer.
 * If out is NULL, writes the modulus size to *outlen and returns 0 (size query).
 * label/label_len: optional OAEP label (NULL/0 for no label).
 * Returns 0 on success, negative on error. */
int wp11_soft_key_rsa_oaep_decrypt(wp11_soft_key_t *key,
                                    const uint8_t *in, word32 inlen,
                                    uint8_t *out, word32 outbuflen, word32 *outlen,
                                    int hash_type, int mgf,
                                    const uint8_t *label, word32 label_len);

/* RSA-PSS sign: digest is the pre-hashed message.
 * salt_len: wolfCrypt saltLen value (RSA_PSS_SALT_LEN_DEFAULT=-1 for
 *   hash-length salt, or an explicit byte count for fixed-length salt).
 * If sig is NULL, writes the modulus size to *siglen and returns 0 (size query).
 * Returns 0 on success, -1 on error.
 * Available only when the wolfCrypt build defines WC_RSA_PSS. */
#ifdef WC_RSA_PSS
int wp11_soft_key_rsa_pss_sign(wp11_soft_key_t *key,
                                const uint8_t *digest, word32 digest_len,
                                uint8_t *sig, word32 *siglen,
                                int hash_type, int mgf, int salt_len);

/* RSA-PSS verify: sig is the signature, digest is the message hash.
 * salt_len: wolfCrypt saltLen value (RSA_PSS_SALT_LEN_DEFAULT or explicit).
 * Returns 0 on success (signature valid), -1 on failure. */
int wp11_soft_key_rsa_pss_verify(wp11_soft_key_t *key,
                                  const uint8_t *sig, word32 siglen,
                                  const uint8_t *digest, word32 digest_len,
                                  int hash_type, int mgf, int salt_len);
#endif /* WC_RSA_PSS */

/* Export the private key as DER for keystore save operations.
 * ECC keys: SEC1 (RFC 5915) DER.  RSA keys: PKCS#1 (RFC 3447) DER.
 * buf must be at least WP11_KEYSTORE_DER_MAX bytes.
 * Returns bytes written on success, negative on error. */
int wp11_soft_key_export_priv_der(wp11_soft_key_t *key,
                                   uint8_t *buf, uint32_t buflen);

#ifdef WOLFP11_CFG_TEST
/* wolfP11-56f: export the private key as DER for test oracle cross-validation.
 * ECC keys: SEC1 / RFC 5915 DER.
 * RSA keys: PKCS#1 / RFC 3447 DER.
 *
 * Returns the number of bytes written on success, negative on error.
 * 'outlen' is the size of the output buffer; must be at least 2350 bytes
 * (RSA-2048 DER upper bound) to guarantee success for all key types.
 *
 * This function is intentionally NOT in the production code path.
 * It exists ONLY to give tests an external oracle for wp11_backend_soft_ops.
 *
 * wolfssl header order: options.h must precede all other wolfssl includes or
 * settings.h emits a #warning that -Werror treats as an error. */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>
int wp11_soft_key_test_export_priv_der(wp11_soft_key_t *key,
                                       uint8_t *out, word32 outlen);

/* Export the EC public key in X9.62 uncompressed format (04 || X || Y).
 * P-256: 65 bytes; P-384: 97 bytes.  *outlen must be at least 97 on entry.
 * Returns 0 on success, negative on error.
 * Only valid for ECC keys; returns -1 for RSA keys. */
int wp11_soft_key_test_export_pub_x963(wp11_soft_key_t *key,
                                        uint8_t *out, word32 *outlen);

/* Export the Ed25519 public key as a 32-byte raw key.
 * *outlen must be at least 32 on entry; updated to 32 on success.
 * Returns 0 on success, negative on error.
 * Only valid for ED25519 keys; returns -1 for other key types. */
#ifdef HAVE_ED25519
int wp11_soft_key_test_export_ed25519_pub(wp11_soft_key_t *key,
                                           uint8_t *out, word32 *outlen);
#endif /* HAVE_ED25519 */
#endif /* WOLFP11_CFG_TEST */

#endif /* WOLFP11_SOFT_KEY_H */
