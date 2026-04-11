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

/* wp11_test_backend_fsdir.c -- independent oracle tests for wp11_backend_fsdir_ops
 *
 * wolfP11-kwzw: fsdir_sign, fsdir_verify, and fsdir_decrypt had zero test
 * coverage.  These tests exercise each operation through the exported
 * wp11_backend_fsdir_ops dispatch table using an INDEPENDENT oracle strategy:
 *
 *   Sign:    wp11_backend_fsdir_ops.sign -> oracle wc_ecc_verify_hash /
 *            wc_RsaSSL_Verify on a fresh key object imported from the same DER.
 *   Verify:  External raw wc_ecc_sign_hash -> wp11_backend_fsdir_ops.verify.
 *   Decrypt: Oracle wc_RsaPublicEncrypt -> wp11_backend_fsdir_ops.decrypt.
 *
 * Each test creates a temporary .p11k keystore via wp11_keystore_create,
 * loads it with wp11_keystore_load, and points a wp11_key_handle_t at the
 * returned entry.  The oracle imports the raw DER into a fresh wolfCrypt key
 * object that never passes through the fsdir backend code -- giving an
 * independent verification path.
 *
 * Compile with -DWOLFP11_CFG_TEST and -DWOLFP11_CFG_FSDIR_BACKEND to enable.
 */

#define _POSIX_C_SOURCE 200809L   /* mkdtemp */

#include "test/wp11_test_backend_fsdir.h"

#ifdef WOLFP11_CFG_TEST

/* wolfssl/options.h must come before all other wolfssl headers */
#include <wolfssl/options.h>
#include "wolfp11/wp11_backend.h"
#include "wolfp11/wp11_keystore.h"
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn.h>

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef WOLFP11_CFG_FSDIR_BACKEND

/* CKM mechanism values -- must match FSDIR_CKM_* in wp11_backend_fsdir.c */
#define TEST_CKM_RSA_PKCS      0x00000001UL
#define TEST_CKM_ECDSA         0x00001041UL
#define TEST_CKM_ECDSA_SHA256  0x00001044UL

/* Buffer sizes */
#define SIG_BUF_SZ  256    /* P-256 DER ECDSA signature max ~72 bytes */
#define DER_BUF_SZ  4096   /* covers RSA-2048 (~1200 B) and EC P-256 (~120 B) */
#define CT_BUF_SZ   256    /* RSA-2048 ciphertext: exactly 256 bytes */

static const uint8_t TEST_PIN[]   = { 'f', 's', 'd', 'i', 'r', 'P', 'i', 'n' };
#define TEST_PIN_LEN  (sizeof(TEST_PIN))

static int check(int pass, const char *label)
{
    printf("%s: %s\n", pass ? "PASS" : "FAIL", label);
    return pass ? 0 : 1;
}

static void make_fsdir_handle(const wp11_key_entry_t *entry,
                               wp11_key_handle_t      *h)
{
    h->backend = WP11_BACKEND_FSDIR;
    h->id      = 0;
    h->priv    = (void *)entry;
}

/* -------------------------------------------------------------------------
 * setup_ec_keystore
 *
 * Generate a fresh EC P-256 key, write it into a .p11k keystore at `path`,
 * then load and return the keystore.  Copies the raw private DER into
 * `der_out`/`*der_len_out` so the caller can build an independent oracle.
 * Returns WP11_KEYSTORE_OK on success.
 * ---------------------------------------------------------------------- */
static int setup_ec_keystore(const char      *path,
                              wp11_keystore_t **ks_out,
                              uint8_t          *der_out,
                              size_t           *der_len_out)
{
    WC_RNG           rng;
    ecc_key          ecc;
    uint8_t          der[DER_BUF_SZ];
    int              der_len;
    wp11_key_entry_t entry;
    int              ret;

    if (wc_InitRng(&rng) != 0)  return -1;
    if (wc_ecc_init(&ecc) != 0) { wc_FreeRng(&rng); return -1; }

    ret = wc_ecc_make_key(&rng, 32, &ecc);   /* P-256 = 32-byte curve */
    if (ret != 0) { wc_ecc_free(&ecc); wc_FreeRng(&rng); return -1; }

    der_len = wc_EccKeyToDer(&ecc, der, (word32)sizeof(der));
    wc_ecc_free(&ecc);
    wc_FreeRng(&rng);
    if (der_len <= 0) return -1;

    memset(&entry, 0, sizeof(entry));
    memcpy(entry.label, "test-ec", 7);
    entry.key_type  = WP11_KEY_TYPE_EC;
    entry.der_bytes = der;
    entry.der_len   = (size_t)der_len;

    ret = wp11_keystore_create(path, TEST_PIN, TEST_PIN_LEN, &entry, 1);
    if (ret != WP11_KEYSTORE_OK) { memset(der, 0, sizeof(der)); return ret; }

    ret = wp11_keystore_load(path, TEST_PIN, TEST_PIN_LEN, ks_out);
    if (ret != WP11_KEYSTORE_OK) { memset(der, 0, sizeof(der)); return ret; }

    /* Give the oracle a copy before we zero the stack buffer */
    if (der_out != NULL && der_len_out != NULL) {
        memcpy(der_out, der, (size_t)der_len);
        *der_len_out = (size_t)der_len;
    }
    memset(der, 0, sizeof(der));   /* zero stack copy; keystore owns mlock'd copy */
    return WP11_KEYSTORE_OK;
}

/* -------------------------------------------------------------------------
 * setup_rsa_keystore
 *
 * Generate a fresh RSA-2048 key, write .p11k, load and return the keystore.
 * ---------------------------------------------------------------------- */
static int setup_rsa_keystore(const char      *path,
                               wp11_keystore_t **ks_out,
                               uint8_t          *der_out,
                               size_t           *der_len_out)
{
    WC_RNG           rng;
    RsaKey           rsa;
    uint8_t          der[DER_BUF_SZ];
    int              der_len;
    wp11_key_entry_t entry;
    int              ret;

    if (wc_InitRng(&rng) != 0) return -1;
    ret = wc_InitRsaKey(&rsa, NULL);
    if (ret != 0) { wc_FreeRng(&rng); return -1; }

    ret = wc_MakeRsaKey(&rsa, 2048, 65537L, &rng);
    if (ret != 0) { wc_FreeRsaKey(&rsa); wc_FreeRng(&rng); return -1; }

    der_len = wc_RsaKeyToDer(&rsa, der, (word32)sizeof(der));
    wc_FreeRsaKey(&rsa);
    wc_FreeRng(&rng);
    if (der_len <= 0) return -1;

    memset(&entry, 0, sizeof(entry));
    memcpy(entry.label, "test-rsa", 8);
    entry.key_type  = WP11_KEY_TYPE_RSA;
    entry.der_bytes = der;
    entry.der_len   = (size_t)der_len;

    ret = wp11_keystore_create(path, TEST_PIN, TEST_PIN_LEN, &entry, 1);
    if (ret != WP11_KEYSTORE_OK) { memset(der, 0, sizeof(der)); return ret; }

    ret = wp11_keystore_load(path, TEST_PIN, TEST_PIN_LEN, ks_out);
    if (ret != WP11_KEYSTORE_OK) { memset(der, 0, sizeof(der)); return ret; }

    if (der_out != NULL && der_len_out != NULL) {
        memcpy(der_out, der, (size_t)der_len);
        *der_len_out = (size_t)der_len;
    }
    memset(der, 0, sizeof(der));
    return WP11_KEYSTORE_OK;
}

/* -------------------------------------------------------------------------
 * Test 1: ECDSA raw sign
 *
 * Sign a 32-byte prehash via the fsdir backend (TEST_CKM_ECDSA).
 * Oracle: import the same private DER into a fresh ecc_key; call
 * wc_ecc_verify_hash directly -- an independent code path.
 * ---------------------------------------------------------------------- */
static int test_fsdir_sign_ecdsa(const char *tmpdir)
{
    char                    path[256];
    wp11_keystore_t        *ks     = NULL;
    const wp11_key_entry_t *entry;
    wp11_key_handle_t       h;
    uint8_t                 sig[SIG_BUF_SZ];
    size_t                  siglen = sizeof(sig);
    uint8_t                 der[DER_BUF_SZ];
    size_t                  der_len = 0;
    ecc_key                 oracle_ecc;
    word32                  idx;
    int                     stat;
    int                     ret;
    int                     f = 0;
    /* Fixed 32-byte hash: independent of the code under test */
    static const uint8_t hash[32] = {
        0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc
    };

    snprintf(path, sizeof(path), "%s/ec_sign.p11k", tmpdir);

    ret = setup_ec_keystore(path, &ks, der, &der_len);
    f += check(ret == WP11_KEYSTORE_OK,
               "fsdir_sign_ecdsa: keystore setup succeeds");
    if (ret != WP11_KEYSTORE_OK || ks == NULL) return f;

    entry = wp11_keystore_get(ks, 0);
    f += check(entry != NULL,
               "fsdir_sign_ecdsa: wp11_keystore_get returns entry");
    if (entry == NULL) { wp11_keystore_free(ks); return f; }

    make_fsdir_handle(entry, &h);

    ret = wp11_backend_fsdir_ops.sign(&h, TEST_CKM_ECDSA,
                                      hash, sizeof(hash),
                                      sig, &siglen);
    f += check(ret == 0,    "fsdir_sign_ecdsa: sign returns 0");
    f += check(siglen > 0 && siglen <= sizeof(sig),
               "fsdir_sign_ecdsa: siglen is plausible");

    /* Oracle: decode the same DER into a fresh ecc_key; verify independently */
    if (ret == 0 && siglen > 0 && der_len > 0) {
        idx = 0;
        if (wc_ecc_init(&oracle_ecc) == 0) {
            if (wc_EccPrivateKeyDecode(der, &idx, &oracle_ecc,
                                       (word32)der_len) == 0) {
                stat = 0;
                ret  = wc_ecc_verify_hash(sig, (word32)siglen,
                                          hash, (word32)sizeof(hash),
                                          &stat, &oracle_ecc);
                f += check(ret == 0 && stat == 1,
                           "fsdir_sign_ecdsa: oracle wc_ecc_verify_hash confirms signature");
            } else {
                f++;
                printf("FAIL: fsdir_sign_ecdsa: oracle ecc_key DER import failed\n");
            }
            wc_ecc_free(&oracle_ecc);
        }
    }

    memset(der, 0, sizeof(der));
    wp11_keystore_free(ks);
    return f;
}

/* -------------------------------------------------------------------------
 * Test 2: ECDSA verify
 *
 * External raw wc_ecc_sign_hash generates a signature; the fsdir backend
 * verifies it (positive).  Then a tampered signature must be rejected
 * (negative).
 * ---------------------------------------------------------------------- */
static int test_fsdir_verify_ecdsa(const char *tmpdir)
{
    char                    path[256];
    wp11_keystore_t        *ks    = NULL;
    const wp11_key_entry_t *entry;
    wp11_key_handle_t       h;
    uint8_t                 sig[SIG_BUF_SZ];
    word32                  wlen  = sizeof(sig);
    uint8_t                 der[DER_BUF_SZ];
    size_t                  der_len = 0;
    ecc_key                 ext_ecc;
    WC_RNG                  ext_rng;
    word32                  idx;
    int                     ret;
    int                     f = 0;
    static const uint8_t hash[32] = {
        0xca, 0xfe, 0xba, 0xbe, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40,
        0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0
    };

    snprintf(path, sizeof(path), "%s/ec_verify.p11k", tmpdir);

    ret = setup_ec_keystore(path, &ks, der, &der_len);
    f += check(ret == WP11_KEYSTORE_OK,
               "fsdir_verify_ecdsa: keystore setup succeeds");
    if (ret != WP11_KEYSTORE_OK || ks == NULL) return f;

    entry = wp11_keystore_get(ks, 0);
    f += check(entry != NULL,
               "fsdir_verify_ecdsa: wp11_keystore_get returns entry");
    if (entry == NULL) { wp11_keystore_free(ks); return f; }

    make_fsdir_handle(entry, &h);

    /* External signer: import the same DER into a fresh ecc_key */
    if (der_len > 0 && wc_InitRng(&ext_rng) == 0) {
        idx = 0;
        if (wc_ecc_init(&ext_ecc) == 0) {
            if (wc_EccPrivateKeyDecode(der, &idx, &ext_ecc,
                                       (word32)der_len) == 0) {
                ret = wc_ecc_sign_hash(hash, (word32)sizeof(hash),
                                       sig, &wlen, &ext_rng, &ext_ecc);
                f += check(ret == 0,
                           "fsdir_verify_ecdsa: external sign succeeds");

                if (ret == 0) {
                    /* Positive: fsdir_verify must accept the valid signature */
                    ret = wp11_backend_fsdir_ops.verify(
                              &h, TEST_CKM_ECDSA,
                              hash, sizeof(hash),
                              sig, (size_t)wlen);
                    f += check(ret == 0,
                               "fsdir_verify_ecdsa: accepts external signature");

                    /* Negative: flip a bit in the signature; must be rejected */
                    sig[wlen - 1u] ^= 0x01u;
                    ret = wp11_backend_fsdir_ops.verify(
                              &h, TEST_CKM_ECDSA,
                              hash, sizeof(hash),
                              sig, (size_t)wlen);
                    f += check(ret != 0,
                               "fsdir_verify_ecdsa: rejects tampered signature");
                }
            } else {
                f++;
                printf("FAIL: fsdir_verify_ecdsa: external ecc_key DER import failed\n");
            }
            wc_ecc_free(&ext_ecc);
        }
        wc_FreeRng(&ext_rng);
    }

    memset(der, 0, sizeof(der));
    wp11_keystore_free(ks);
    return f;
}

/* -------------------------------------------------------------------------
 * Test 3: ECDSA_SHA256 sign
 *
 * Sign a message with TEST_CKM_ECDSA_SHA256 (fsdir hashes internally).
 * Oracle: compute SHA-256 independently with wc_Sha256*, then verify the
 * resulting digest against the signature with wc_ecc_verify_hash.
 * ---------------------------------------------------------------------- */
static int test_fsdir_sign_ecdsa_sha256(const char *tmpdir)
{
    char                    path[256];
    wp11_keystore_t        *ks     = NULL;
    const wp11_key_entry_t *entry;
    wp11_key_handle_t       h;
    uint8_t                 sig[SIG_BUF_SZ];
    size_t                  siglen = sizeof(sig);
    uint8_t                 der[DER_BUF_SZ];
    size_t                  der_len = 0;
    ecc_key                 oracle_ecc;
    wc_Sha256               sha;
    uint8_t                 digest[WC_SHA256_DIGEST_SIZE];
    word32                  idx;
    int                     stat;
    int                     ret;
    int                     f = 0;
    /* 32-byte message: fsdir backend will SHA-256 this before signing */
    static const uint8_t msg[32] = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f,
        0x72, 0x6c, 0x64, 0x20, 0x66, 0x72, 0x6f, 0x6d,
        0x20, 0x77, 0x6f, 0x6c, 0x66, 0x50, 0x31, 0x31,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };

    snprintf(path, sizeof(path), "%s/ec_sha256.p11k", tmpdir);

    ret = setup_ec_keystore(path, &ks, der, &der_len);
    f += check(ret == WP11_KEYSTORE_OK,
               "fsdir_sign_ecdsa_sha256: keystore setup succeeds");
    if (ret != WP11_KEYSTORE_OK || ks == NULL) return f;

    entry = wp11_keystore_get(ks, 0);
    f += check(entry != NULL,
               "fsdir_sign_ecdsa_sha256: wp11_keystore_get returns entry");
    if (entry == NULL) { wp11_keystore_free(ks); return f; }

    make_fsdir_handle(entry, &h);

    ret = wp11_backend_fsdir_ops.sign(&h, TEST_CKM_ECDSA_SHA256,
                                      msg, sizeof(msg),
                                      sig, &siglen);
    f += check(ret == 0,    "fsdir_sign_ecdsa_sha256: sign returns 0");
    f += check(siglen > 0 && siglen <= sizeof(sig),
               "fsdir_sign_ecdsa_sha256: siglen is plausible");

    /* Oracle: SHA-256(msg) independently, then wc_ecc_verify_hash on the digest */
    if (ret == 0 && siglen > 0 && der_len > 0) {
        if (wc_InitSha256(&sha) == 0) {
            ret = wc_Sha256Update(&sha, msg, (word32)sizeof(msg));
            if (ret == 0) ret = wc_Sha256Final(&sha, digest);
            wc_Sha256Free(&sha);

            if (ret == 0) {
                idx = 0;
                if (wc_ecc_init(&oracle_ecc) == 0) {
                    if (wc_EccPrivateKeyDecode(der, &idx, &oracle_ecc,
                                               (word32)der_len) == 0) {
                        stat = 0;
                        ret  = wc_ecc_verify_hash(sig, (word32)siglen,
                                                  digest, WC_SHA256_DIGEST_SIZE,
                                                  &stat, &oracle_ecc);
                        f += check(ret == 0 && stat == 1,
                                   "fsdir_sign_ecdsa_sha256: oracle confirms SHA256+ECDSA signature");
                    } else {
                        f++;
                        printf("FAIL: fsdir_sign_ecdsa_sha256: oracle ecc_key DER import failed\n");
                    }
                    wc_ecc_free(&oracle_ecc);
                }
            }
        }
    }

    memset(der, 0, sizeof(der));
    wp11_keystore_free(ks);
    return f;
}

/* -------------------------------------------------------------------------
 * Test 4: RSA PKCS#1 v1.5 sign
 *
 * Sign a 20-byte hash with TEST_CKM_RSA_PKCS.
 * Oracle: wc_RsaSSL_Verify on the signature with a fresh RsaKey from the
 * same DER; verify the recovered bytes equal the original hash.
 * ---------------------------------------------------------------------- */
static int test_fsdir_sign_rsa(const char *tmpdir)
{
    char                    path[256];
    wp11_keystore_t        *ks     = NULL;
    const wp11_key_entry_t *entry;
    wp11_key_handle_t       h;
    uint8_t                 sig[CT_BUF_SZ];
    size_t                  siglen = sizeof(sig);
    uint8_t                 der[DER_BUF_SZ];
    size_t                  der_len = 0;
    RsaKey                  oracle_rsa;
    word32                  idx;
    uint8_t                 out[CT_BUF_SZ];
    int                     ret;
    int                     f = 0;
    /* 20-byte SHA-1-size hash (typical PKCS#1 v1.5 prehash input length) */
    static const uint8_t hash[20] = {
        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
        0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
        0xaf, 0xd8, 0x07, 0x09
    };

    snprintf(path, sizeof(path), "%s/rsa_sign.p11k", tmpdir);

    ret = setup_rsa_keystore(path, &ks, der, &der_len);
    f += check(ret == WP11_KEYSTORE_OK,
               "fsdir_sign_rsa: keystore setup succeeds");
    if (ret != WP11_KEYSTORE_OK || ks == NULL) return f;

    entry = wp11_keystore_get(ks, 0);
    f += check(entry != NULL,
               "fsdir_sign_rsa: wp11_keystore_get returns entry");
    if (entry == NULL) { wp11_keystore_free(ks); return f; }

    make_fsdir_handle(entry, &h);

    ret = wp11_backend_fsdir_ops.sign(&h, TEST_CKM_RSA_PKCS,
                                      hash, sizeof(hash),
                                      sig, &siglen);
    f += check(ret == 0,       "fsdir_sign_rsa: sign returns 0");
    f += check(siglen == 256u, "fsdir_sign_rsa: siglen is 256 bytes (RSA-2048)");

    /* Oracle: fresh RsaKey from same DER; wc_RsaSSL_Verify recovers the hash */
    if (ret == 0 && siglen == 256u && der_len > 0) {
        idx = 0;
        if (wc_InitRsaKey(&oracle_rsa, NULL) == 0) {
            if (wc_RsaPrivateKeyDecode(der, &idx, &oracle_rsa,
                                       (word32)der_len) == 0) {
                ret = wc_RsaSSL_Verify(sig, (word32)siglen,
                                       out, (word32)sizeof(out),
                                       &oracle_rsa);
                f += check(ret == (int)sizeof(hash) &&
                           memcmp(out, hash, sizeof(hash)) == 0,
                           "fsdir_sign_rsa: oracle wc_RsaSSL_Verify recovers hash");
            } else {
                f++;
                printf("FAIL: fsdir_sign_rsa: oracle RsaKey DER import failed\n");
            }
            wc_FreeRsaKey(&oracle_rsa);
        }
    }

    memset(der, 0, sizeof(der));
    wp11_keystore_free(ks);
    return f;
}

/* -------------------------------------------------------------------------
 * Test 5: RSA PKCS#1 v1.5 decrypt
 *
 * Oracle encrypts 32 bytes with wc_RsaPublicEncrypt (public key extracted
 * from the private DER).  The fsdir backend decrypts.  The recovered
 * plaintext must equal the original.
 * ---------------------------------------------------------------------- */
static int test_fsdir_decrypt_rsa(const char *tmpdir)
{
    char                    path[256];
    wp11_keystore_t        *ks    = NULL;
    const wp11_key_entry_t *entry;
    wp11_key_handle_t       h;
    uint8_t                 ct[CT_BUF_SZ];
    uint8_t                 pt[CT_BUF_SZ];
    size_t                  ptlen = sizeof(pt);
    uint8_t                 der[DER_BUF_SZ];
    size_t                  der_len = 0;
    RsaKey                  enc_rsa;
    WC_RNG                  enc_rng;
    word32                  idx;
    int                     ct_len;
    int                     ret;
    int                     f = 0;
    static const uint8_t plaintext[32] = {
        0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x20, 0x6b,
        0x65, 0x79, 0x20, 0x6d, 0x61, 0x74, 0x65, 0x72,
        0x69, 0x61, 0x6c, 0x20, 0x74, 0x65, 0x73, 0x74,
        0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x21
    };

    snprintf(path, sizeof(path), "%s/rsa_dec.p11k", tmpdir);

    ret = setup_rsa_keystore(path, &ks, der, &der_len);
    f += check(ret == WP11_KEYSTORE_OK,
               "fsdir_decrypt_rsa: keystore setup succeeds");
    if (ret != WP11_KEYSTORE_OK || ks == NULL) return f;

    entry = wp11_keystore_get(ks, 0);
    f += check(entry != NULL,
               "fsdir_decrypt_rsa: wp11_keystore_get returns entry");
    if (entry == NULL) { wp11_keystore_free(ks); return f; }

    make_fsdir_handle(entry, &h);

    /* Oracle: encrypt the plaintext with the public key from the same DER */
    if (der_len > 0 && wc_InitRng(&enc_rng) == 0) {
        idx = 0;
        if (wc_InitRsaKey(&enc_rsa, NULL) == 0) {
            if (wc_RsaPrivateKeyDecode(der, &idx, &enc_rsa,
                                       (word32)der_len) == 0) {
                ct_len = wc_RsaPublicEncrypt(plaintext, (word32)sizeof(plaintext),
                                             ct, (word32)sizeof(ct),
                                             &enc_rsa, &enc_rng);
                f += check(ct_len > 0,
                           "fsdir_decrypt_rsa: oracle encrypt succeeds");

                if (ct_len > 0) {
                    ret = wp11_backend_fsdir_ops.decrypt(
                              &h, TEST_CKM_RSA_PKCS,
                              ct, (size_t)ct_len,
                              pt, &ptlen);
                    f += check(ret == 0,
                               "fsdir_decrypt_rsa: decrypt returns 0");
                    f += check(ptlen == sizeof(plaintext) &&
                               memcmp(pt, plaintext, sizeof(plaintext)) == 0,
                               "fsdir_decrypt_rsa: recovered plaintext matches original");
                }
            } else {
                f++;
                printf("FAIL: fsdir_decrypt_rsa: oracle RsaKey DER import failed\n");
            }
            wc_FreeRsaKey(&enc_rsa);
        }
        wc_FreeRng(&enc_rng);
    }

    memset(der, 0, sizeof(der));
    wp11_keystore_free(ks);
    return f;
}

/* -------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */

int wp11_test_backend_fsdir(void)
{
    char  tmpdir[] = "/tmp/wp11_fsdir_test_XXXXXX";
    char *tdir;
    int   failures = 0;

    tdir = mkdtemp(tmpdir);
    if (tdir == NULL) {
        printf("FAIL: wp11_test_backend_fsdir: mkdtemp failed\n");
        return 1;
    }

    failures += test_fsdir_sign_ecdsa(tdir);
    failures += test_fsdir_verify_ecdsa(tdir);
    failures += test_fsdir_sign_ecdsa_sha256(tdir);
    failures += test_fsdir_sign_rsa(tdir);
    failures += test_fsdir_decrypt_rsa(tdir);

    return failures;
}

#else /* WOLFP11_CFG_FSDIR_BACKEND not defined */

int wp11_test_backend_fsdir(void)
{
    return 0;
}

#endif /* WOLFP11_CFG_FSDIR_BACKEND */

#else /* WOLFP11_CFG_TEST not defined */

int wp11_test_backend_fsdir(void)
{
    return 0;
}

#endif /* WOLFP11_CFG_TEST */
