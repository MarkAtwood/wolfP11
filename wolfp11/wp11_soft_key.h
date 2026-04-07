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

/* Opaque soft key type -- struct definition in src/wp11_backend_soft.c */
typedef struct wp11_soft_key wp11_soft_key_t;

/* Allocate and generate a new P-256 ECDSA key.  Returns NULL on failure. */
wp11_soft_key_t *wp11_soft_key_new_ecc_p256(void);

/* Allocate and generate a new P-384 ECDSA key.  Returns NULL on failure. */
wp11_soft_key_t *wp11_soft_key_new_ecc_p384(void);

/* Allocate and generate a new RSA-2048 key.  Returns NULL on failure. */
wp11_soft_key_t *wp11_soft_key_new_rsa2048(void);

/* Allocate and generate a new RSA key of the given modulus bit length.
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
 * actual bytes written).  512 bytes each is sufficient for RSA-4096.
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
#endif /* WOLFP11_CFG_TEST */

#endif /* WOLFP11_SOFT_KEY_H */
