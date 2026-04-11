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

/* wp11_test_backend_soft.c -- independent oracle tests for wp11_backend_soft_ops
 *
 * wolfP11-56f: wp11_backend_soft_ops (soft_sign, soft_verify, soft_decrypt)
 * had zero test coverage.  These tests exercise each operation using an
 * INDEPENDENT oracle -- the oracle uses raw wolfCrypt APIs on a fresh key
 * object derived from the same key material, never the same code path.
 *
 * Oracle strategy:
 *   Sign:    wp11_backend_soft_ops.sign -> verify with raw wc_ecc_verify_hash
 *            or wc_RsaSSL_Verify on a key imported from the same DER.
 *   Verify:  Raw wc_ecc_sign_hash / wc_RsaSSL_Sign -> wp11_backend_soft_ops.verify.
 *   Decrypt: Raw wc_RsaPublicEncrypt -> wp11_backend_soft_ops.decrypt.
 *
 * The tests export the private key DER via wp11_soft_key_test_export_priv_der
 * (a WOLFP11_CFG_TEST hook in wp11_backend_soft.c), then import it into a
 * fresh wolfCrypt key object that never passes through the soft backend code.
 * This gives a mathematically equivalent but code-path-independent oracle.
 *
 * Compile with -DWOLFP11_CFG_TEST to enable.
 */

#include "test/wp11_test_backend_soft.h"

#ifdef WOLFP11_CFG_TEST

/* wolfssl header order: options.h must precede all other wolfssl includes or
 * settings.h fires a #warning that -Werror treats as an error. */
#include <wolfssl/options.h>
#include "wolfp11/wp11_backend.h"
#include "wolfp11/wp11_soft_key.h"
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn.h>   /* wc_EccPrivateKeyDecode, wc_RsaPrivateKeyDecode */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* CKM_* mechanism constants -- must match SOFT_CKM_* in wp11_backend_soft.c */
#define TEST_CKM_RSA_PKCS      0x00000001UL
#define TEST_CKM_ECDSA         0x00001041UL
#define TEST_CKM_ECDSA_SHA256  0x00001044UL
#define TEST_CKM_ECDH1_DERIVE  0x00001050UL

/* Maximum DER buffer size: RSA-2048 private key DER is ~1200 bytes;
 * ECC P-256 private key DER is ~120 bytes.  2048 covers both with margin. */
#define DER_BUF_SIZE 2048

static int check(int pass, const char *label)
{
    printf("%s: %s\n", pass ? "PASS" : "FAIL", label);
    return pass ? 0 : 1;
}

/* -------------------------------------------------------------------------
 * make_handle: build a wp11_key_handle_t pointing at the soft key
 * ---------------------------------------------------------------------- */

static void make_handle(wp11_soft_key_t *k, wp11_key_handle_t *h)
{
    h->backend = WP11_BACKEND_SOFT;
    h->id      = 0;
    h->priv    = k;
}

/* -------------------------------------------------------------------------
 * Test 1: ECDSA sign -- independent oracle via raw wolfCrypt verify
 *
 * Sign a 32-byte hash with the soft backend (ECDSA, prehashed).
 * Oracle: import the same private DER into a fresh ecc_key and call
 * wc_ecc_verify_hash directly -- this is an independent code path.
 * ---------------------------------------------------------------------- */

static int test_soft_sign_ecdsa(void)
{
    wp11_soft_key_t   *k    = NULL;
    wp11_key_handle_t  h;
    uint8_t            sig[128];
    size_t             siglen = sizeof(sig);
    uint8_t            der[DER_BUF_SIZE];
    int                der_len;
    ecc_key            oracle_ecc;
    word32             idx;
    int                stat;
    int                ret;
    int                f = 0;
    /* Fixed 32-byte hash: independent of the code under test */
    static const uint8_t hash[32] = {
        0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc
    };

    k = wp11_soft_key_new_ecc_p256();
    f += check(k != NULL, "soft_sign_ecdsa: wp11_soft_key_new_ecc_p256 succeeds");
    if (k == NULL) return f;

    make_handle(k, &h);

    /* Sign with the soft backend */
    ret = wp11_backend_soft_ops.sign(&h, TEST_CKM_ECDSA,
                                     hash, sizeof(hash),
                                     sig, &siglen);
    f += check(ret == 0, "soft_sign_ecdsa: sign returns 0");
    f += check(siglen > 0 && siglen <= sizeof(sig),
               "soft_sign_ecdsa: siglen is plausible");

    /* Export the private key DER for the oracle */
    der_len = wp11_soft_key_test_export_priv_der(k, der, (word32)sizeof(der));
    f += check(der_len > 0, "soft_sign_ecdsa: priv DER export succeeds");

    if (ret == 0 && siglen > 0 && der_len > 0) {
        /* Oracle: decode the DER into a fresh ecc_key (never touched by soft backend) */
        idx = 0;
        if (wc_ecc_init(&oracle_ecc) == 0) {
            if (wc_EccPrivateKeyDecode(der, &idx, &oracle_ecc,
                                       (word32)der_len) == 0) {
                stat = 0;
                /* wc_ecc_verify_hash is the oracle: same maths, different code path */
                ret = wc_ecc_verify_hash(sig, (word32)siglen,
                                         hash, (word32)sizeof(hash),
                                         &stat, &oracle_ecc);
                f += check(ret == 0 && stat == 1,
                           "soft_sign_ecdsa: oracle -- wc_ecc_verify_hash confirms signature");
            } else {
                f++;  /* DER import failure = test failure */
                printf("FAIL: soft_sign_ecdsa: oracle ecc_key DER import failed\n");
            }
            wc_ecc_free(&oracle_ecc);
        }
    }

    /* Secure-zero the exported DER before freeing (key material) */
    (void)memset(der, 0, sizeof(der));
    wp11_soft_key_free(k);
    return f;
}

/* -------------------------------------------------------------------------
 * Test 2: ECDSA verify -- cross-validation with external signature
 *
 * Export the private key DER, sign externally with raw wolfCrypt,
 * then pass the external signature to soft_verify.  The sign path
 * is raw wolfCrypt; the verify path is the soft backend.
 * ---------------------------------------------------------------------- */

static int test_soft_verify_ecdsa(void)
{
    wp11_soft_key_t   *k    = NULL;
    wp11_key_handle_t  h;
    uint8_t            sig[128];
    word32             wlen  = sizeof(sig);
    uint8_t            der[DER_BUF_SIZE];
    int                der_len;
    ecc_key            ext_ecc;
    WC_RNG             ext_rng;
    word32             idx;
    int                ret;
    int                f = 0;
    static const uint8_t hash[32] = {
        0xca, 0xfe, 0xba, 0xbe, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40,
        0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0
    };

    k = wp11_soft_key_new_ecc_p256();
    f += check(k != NULL, "soft_verify_ecdsa: wp11_soft_key_new_ecc_p256 succeeds");
    if (k == NULL) return f;

    make_handle(k, &h);

    /* Export the private key DER */
    der_len = wp11_soft_key_test_export_priv_der(k, der, (word32)sizeof(der));
    f += check(der_len > 0, "soft_verify_ecdsa: priv DER export succeeds");

    if (der_len > 0) {
        /* Import into a fresh ecc_key -- the external signer */
        idx = 0;
        if (wc_ecc_init(&ext_ecc) == 0 && wc_InitRng(&ext_rng) == 0) {
            if (wc_EccPrivateKeyDecode(der, &idx, &ext_ecc, (word32)der_len) == 0) {
                /* External sign (raw wolfCrypt, not soft backend) */
                ret = wc_ecc_sign_hash(hash, (word32)sizeof(hash),
                                       sig, &wlen, &ext_rng, &ext_ecc);
                f += check(ret == 0, "soft_verify_ecdsa: external sign succeeds");

                if (ret == 0) {
                    /* Oracle: soft backend verifies the externally-generated signature */
                    ret = wp11_backend_soft_ops.verify(&h, TEST_CKM_ECDSA,
                                                       hash, sizeof(hash),
                                                       sig, (size_t)wlen);
                    f += check(ret == 0,
                               "soft_verify_ecdsa: soft_verify accepts external signature");

                    /* Negative: tamper one sig byte; verify must reject */
                    sig[0] ^= 0xFFu;
                    ret = wp11_backend_soft_ops.verify(&h, TEST_CKM_ECDSA,
                                                       hash, sizeof(hash),
                                                       sig, (size_t)wlen);
                    f += check(ret != 0,
                               "soft_verify_ecdsa: soft_verify rejects tampered signature");
                }
            } else {
                f++;
                printf("FAIL: soft_verify_ecdsa: external ecc_key DER import failed\n");
            }
            wc_ecc_free(&ext_ecc);
            wc_FreeRng(&ext_rng);
        }
    }

    (void)memset(der, 0, sizeof(der));
    wp11_soft_key_free(k);
    return f;
}

/* -------------------------------------------------------------------------
 * Test 3: ECDSA_SHA256 sign -- oracle verifies the hash was computed correctly
 *
 * Sign a message with ECDSA_SHA256 (soft backend hashes internally).
 * Oracle: compute SHA256 manually, then call wc_ecc_verify_hash directly.
 * This cross-validates the SHA256 hashing step in soft_sign.
 * ---------------------------------------------------------------------- */

static int test_soft_sign_ecdsa_sha256(void)
{
    wp11_soft_key_t   *k    = NULL;
    wp11_key_handle_t  h;
    uint8_t            sig[128];
    size_t             siglen = sizeof(sig);
    uint8_t            der[DER_BUF_SIZE];
    int                der_len;
    ecc_key            oracle_ecc;
    word32             idx;
    wc_Sha256          sha;
    uint8_t            hash[WC_SHA256_DIGEST_SIZE];
    int                stat;
    int                ret;
    int                f = 0;
    /* 64-byte test message: the soft backend will SHA256 it internally */
    static const uint8_t msg[64] = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f,  /* "Hello wo" */
        0x72, 0x6c, 0x64, 0x20, 0x66, 0x72, 0x6f, 0x6d,  /* "rld from" */
        0x20, 0x77, 0x6f, 0x6c, 0x66, 0x50, 0x31, 0x31,  /* " wolfP11" */
        0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65,  /* " test ve" */
        0x63, 0x74, 0x6f, 0x72, 0x20, 0x45, 0x43, 0x44,  /* "ctor ECD" */
        0x53, 0x41, 0x5f, 0x53, 0x48, 0x41, 0x32, 0x35,  /* "SA_SHA25" */
        0x36, 0x20, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00,  /* "6 test\0\0" */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    k = wp11_soft_key_new_ecc_p256();
    f += check(k != NULL, "soft_sign_ecdsa_sha256: key gen succeeds");
    if (k == NULL) return f;

    make_handle(k, &h);

    /* Sign with ECDSA_SHA256 (soft backend hashes msg internally) */
    ret = wp11_backend_soft_ops.sign(&h, TEST_CKM_ECDSA_SHA256,
                                     msg, sizeof(msg),
                                     sig, &siglen);
    f += check(ret == 0, "soft_sign_ecdsa_sha256: sign returns 0");

    der_len = wp11_soft_key_test_export_priv_der(k, der, (word32)sizeof(der));
    f += check(der_len > 0, "soft_sign_ecdsa_sha256: priv DER export succeeds");

    if (ret == 0 && siglen > 0 && der_len > 0) {
        /* Oracle: compute SHA256(msg) independently */
        if (wc_InitSha256(&sha) == 0) {
            (void)wc_Sha256Update(&sha, msg, (word32)sizeof(msg));
            (void)wc_Sha256Final(&sha, hash);
            wc_Sha256Free(&sha);
        }

        /* Import key and verify using the manually-computed hash */
        idx = 0;
        if (wc_ecc_init(&oracle_ecc) == 0) {
            if (wc_EccPrivateKeyDecode(der, &idx, &oracle_ecc,
                                       (word32)der_len) == 0) {
                stat = 0;
                ret = wc_ecc_verify_hash(sig, (word32)siglen,
                                         hash, WC_SHA256_DIGEST_SIZE,
                                         &stat, &oracle_ecc);
                f += check(ret == 0 && stat == 1,
                           "soft_sign_ecdsa_sha256: oracle -- wc_ecc_verify_hash on manual SHA256 digest");
            } else {
                f++;
                printf("FAIL: soft_sign_ecdsa_sha256: oracle key import failed\n");
            }
            wc_ecc_free(&oracle_ecc);
        }
    }

    (void)memset(der, 0, sizeof(der));
    wp11_soft_key_free(k);
    return f;
}

/* -------------------------------------------------------------------------
 * Test 4: RSA sign -- oracle verifies with wc_RsaSSL_Verify on exported key
 * ---------------------------------------------------------------------- */

static int test_soft_sign_rsa(void)
{
    wp11_soft_key_t   *k    = NULL;
    wp11_key_handle_t  h;
    uint8_t            sig[256];    /* RSA-2048 = 256-byte sig */
    size_t             siglen = sizeof(sig);
    uint8_t            der[DER_BUF_SIZE];
    int                der_len;
    RsaKey             oracle_rsa;
    word32             idx;
    uint8_t            ver[256];
    word32             ver_len = (word32)sizeof(ver);
    int                ret;
    int                f = 0;
    /* 32-byte prehashed digest to sign (RSA-PKCS signs raw input as digest) */
    static const uint8_t hash[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
    };

    k = wp11_soft_key_new_rsa2048();
    f += check(k != NULL, "soft_sign_rsa: wp11_soft_key_new_rsa2048 succeeds");
    if (k == NULL) return f;

    make_handle(k, &h);

    ret = wp11_backend_soft_ops.sign(&h, TEST_CKM_RSA_PKCS,
                                     hash, sizeof(hash),
                                     sig, &siglen);
    f += check(ret == 0, "soft_sign_rsa: sign returns 0");
    f += check(siglen == 256, "soft_sign_rsa: RSA-2048 siglen == 256");

    der_len = wp11_soft_key_test_export_priv_der(k, der, (word32)sizeof(der));
    f += check(der_len > 0, "soft_sign_rsa: priv DER export succeeds");

    if (ret == 0 && siglen > 0 && der_len > 0) {
        idx = 0;
        if (wc_InitRsaKey(&oracle_rsa, NULL) == 0) {
            if (wc_RsaPrivateKeyDecode(der, &idx, &oracle_rsa,
                                       (word32)der_len) == 0) {
                /* wc_RsaSSL_Verify is the oracle: public-decrypt sig, compare to hash */
                ret = wc_RsaSSL_Verify(sig, (word32)siglen,
                                       ver, ver_len, &oracle_rsa);
                f += check(ret == (int)sizeof(hash) &&
                           memcmp(ver, hash, sizeof(hash)) == 0,
                           "soft_sign_rsa: oracle -- wc_RsaSSL_Verify confirms RSA signature");
            } else {
                f++;
                printf("FAIL: soft_sign_rsa: oracle RSA key import failed\n");
            }
            wc_FreeRsaKey(&oracle_rsa);
        }
    }

    (void)memset(der, 0, sizeof(der));
    wp11_soft_key_free(k);
    return f;
}

/* -------------------------------------------------------------------------
 * Test 5: RSA decrypt -- oracle encrypts with raw wolfCrypt public key
 *
 * Export the RSA key DER, import into a fresh RsaKey, encrypt a plaintext
 * with the PUBLIC key (raw wolfCrypt), then decrypt with the soft backend.
 * This is a clean cross-validation: different code paths, same maths.
 * ---------------------------------------------------------------------- */

static int test_soft_decrypt_rsa(void)
{
    wp11_soft_key_t   *k    = NULL;
    wp11_key_handle_t  h;
    uint8_t            ct[256];   /* RSA-2048 output */
    int                ct_len;
    uint8_t            pt[256];
    size_t             pt_len = sizeof(pt);
    uint8_t            der[DER_BUF_SIZE];
    int                der_len;
    RsaKey             oracle_rsa;
    WC_RNG             rng;
    word32             idx;
    int                ret;
    int                f = 0;
    /* 16-byte plaintext -- small enough for RSA-2048 PKCS#1 v1.5 */
    static const uint8_t plaintext[16] = {
        0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x06, 0x17,
        0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F
    };

    k = wp11_soft_key_new_rsa2048();
    f += check(k != NULL, "soft_decrypt_rsa: wp11_soft_key_new_rsa2048 succeeds");
    if (k == NULL) return f;

    make_handle(k, &h);

    der_len = wp11_soft_key_test_export_priv_der(k, der, (word32)sizeof(der));
    f += check(der_len > 0, "soft_decrypt_rsa: priv DER export succeeds");

    if (der_len > 0 && wc_InitRng(&rng) == 0) {
        idx = 0;
        if (wc_InitRsaKey(&oracle_rsa, NULL) == 0) {
            if (wc_RsaPrivateKeyDecode(der, &idx, &oracle_rsa,
                                       (word32)der_len) == 0) {
                /* Oracle: encrypt plaintext with the PUBLIC key (raw wolfCrypt) */
                ct_len = wc_RsaPublicEncrypt(plaintext, (word32)sizeof(plaintext),
                                             ct, (word32)sizeof(ct),
                                             &oracle_rsa, &rng);
                f += check(ct_len == 256,
                           "soft_decrypt_rsa: oracle public encrypt produces 256-byte ciphertext");

                if (ct_len == 256) {
                    /* Decrypt with the soft backend -- different code path */
                    ret = wp11_backend_soft_ops.decrypt(&h, TEST_CKM_RSA_PKCS,
                                                        ct, (size_t)ct_len,
                                                        pt, &pt_len);
                    f += check(ret == 0,
                               "soft_decrypt_rsa: soft_decrypt returns 0");
                    f += check(pt_len == sizeof(plaintext) &&
                               memcmp(pt, plaintext, sizeof(plaintext)) == 0,
                               "soft_decrypt_rsa: decrypted plaintext matches original");
                }
            } else {
                f++;
                printf("FAIL: soft_decrypt_rsa: oracle RSA key import failed\n");
            }
            wc_FreeRsaKey(&oracle_rsa);
        }
        wc_FreeRng(&rng);
    }

    (void)memset(der, 0, sizeof(der));
    wp11_soft_key_free(k);
    return f;
}

/* -------------------------------------------------------------------------
 * Test 6: RSA verify -- cross-validation with external signature
 * ---------------------------------------------------------------------- */

static int test_soft_verify_rsa(void)
{
    wp11_soft_key_t   *k    = NULL;
    wp11_key_handle_t  h;
    uint8_t            sig[256];
    int                sig_len;
    uint8_t            der[DER_BUF_SIZE];
    int                der_len;
    RsaKey             oracle_rsa;
    WC_RNG             rng;
    word32             idx;
    int                ret;
    int                f = 0;
    static const uint8_t hash[32] = {
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
        0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
        0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0
    };

    k = wp11_soft_key_new_rsa2048();
    f += check(k != NULL, "soft_verify_rsa: wp11_soft_key_new_rsa2048 succeeds");
    if (k == NULL) return f;

    make_handle(k, &h);

    der_len = wp11_soft_key_test_export_priv_der(k, der, (word32)sizeof(der));
    f += check(der_len > 0, "soft_verify_rsa: priv DER export succeeds");

    if (der_len > 0 && wc_InitRng(&rng) == 0) {
        idx = 0;
        if (wc_InitRsaKey(&oracle_rsa, NULL) == 0) {
            if (wc_RsaPrivateKeyDecode(der, &idx, &oracle_rsa,
                                       (word32)der_len) == 0) {
                /* External sign with raw wolfCrypt (not soft backend) */
                sig_len = wc_RsaSSL_Sign(hash, (word32)sizeof(hash),
                                         sig, (word32)sizeof(sig),
                                         &oracle_rsa, &rng);
                f += check(sig_len == 256,
                           "soft_verify_rsa: external RSA sign produces 256-byte sig");

                if (sig_len == 256) {
                    /* Soft backend verifies the external signature */
                    ret = wp11_backend_soft_ops.verify(&h, TEST_CKM_RSA_PKCS,
                                                       hash, sizeof(hash),
                                                       sig, (size_t)sig_len);
                    f += check(ret == 0,
                               "soft_verify_rsa: soft_verify accepts external RSA signature");

                    /* Negative: flip a byte in sig; must reject */
                    sig[0] ^= 0xFFu;
                    ret = wp11_backend_soft_ops.verify(&h, TEST_CKM_RSA_PKCS,
                                                       hash, sizeof(hash),
                                                       sig, (size_t)sig_len);
                    f += check(ret != 0,
                               "soft_verify_rsa: soft_verify rejects tampered RSA signature");
                }
            } else {
                f++;
                printf("FAIL: soft_verify_rsa: oracle RSA key import failed\n");
            }
            wc_FreeRsaKey(&oracle_rsa);
        }
        wc_FreeRng(&rng);
    }

    (void)memset(der, 0, sizeof(der));
    wp11_soft_key_free(k);
    return f;
}

/* -------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * Test 7: ECDH derive -- ECDH symmetry oracle
 *
 * Generate two P-256 key pairs (A and B).  Export each public key in X9.62
 * format using the test hook.  Derive the shared secret from both sides.
 *
 * Oracle: ECDH symmetry -- A.priv * B.pub must equal B.priv * A.pub.
 * These are two independent code paths (different private keys, different
 * peer inputs), so agreement proves correctness without using code as its
 * own oracle.
 * ---------------------------------------------------------------------- */

static int test_soft_derive_ecdh(void)
{
    wp11_soft_key_t   *kA    = NULL;
    wp11_soft_key_t   *kB    = NULL;
    wp11_key_handle_t  hA;
    wp11_key_handle_t  hB;
    uint8_t            pubA[65];
    uint8_t            pubB[65];
    word32             pubA_len = (word32)sizeof(pubA);
    word32             pubB_len = (word32)sizeof(pubB);
    uint8_t            sharedAB[32];
    uint8_t            sharedBA[32];
    size_t             sharedAB_len = sizeof(sharedAB);
    size_t             sharedBA_len = sizeof(sharedBA);
    int                ret;
    int                f = 0;

    kA = wp11_soft_key_new_ecc_p256();
    f += check(kA != NULL, "soft_derive_ecdh: key A created");
    if (kA == NULL) goto done;

    kB = wp11_soft_key_new_ecc_p256();
    f += check(kB != NULL, "soft_derive_ecdh: key B created");
    if (kB == NULL) goto done;

    make_handle(kA, &hA);
    make_handle(kB, &hB);

    /* Export public keys in X9.62 uncompressed format (04 || X || Y) */
    ret = wp11_soft_key_test_export_pub_x963(kA, pubA, &pubA_len);
    f += check(ret == 0, "soft_derive_ecdh: export pub A succeeds");
    ret = wp11_soft_key_test_export_pub_x963(kB, pubB, &pubB_len);
    f += check(ret == 0, "soft_derive_ecdh: export pub B succeeds");

    f += check(pubA_len == 65u && pubB_len == 65u,
               "soft_derive_ecdh: both public keys are 65 bytes (P-256)");
    f += check(pubA[0] == 0x04u && pubB[0] == 0x04u,
               "soft_derive_ecdh: public keys start with 0x04 (uncompressed)");

    if (ret != 0 || pubA_len != 65u || pubB_len != 65u) goto done;

    /* A derives shared secret using B's public key */
    ret = wp11_backend_soft_ops.derive(&hA, TEST_CKM_ECDH1_DERIVE,
                                       pubB, (size_t)pubB_len,
                                       sharedAB, &sharedAB_len);
    f += check(ret == 0, "soft_derive_ecdh: A derives with B's pub returns 0");

    /* B derives shared secret using A's public key */
    ret = wp11_backend_soft_ops.derive(&hB, TEST_CKM_ECDH1_DERIVE,
                                       pubA, (size_t)pubA_len,
                                       sharedBA, &sharedBA_len);
    f += check(ret == 0, "soft_derive_ecdh: B derives with A's pub returns 0");

    f += check(sharedAB_len == 32u && sharedBA_len == 32u,
               "soft_derive_ecdh: both shared secrets are 32 bytes (P-256 x-coord)");

    /* Oracle: ECDH symmetry -- A.priv * B.pub == B.priv * A.pub */
    f += check(sharedAB_len == sharedBA_len &&
               memcmp(sharedAB, sharedBA, sharedAB_len) == 0,
               "soft_derive_ecdh: ECDH symmetry oracle: A*pubB == B*pubA");

done:
    wp11_soft_key_free(kA);
    wp11_soft_key_free(kB);
    return f;
}

/* -------------------------------------------------------------------------
 * Test 8: P-384 ECDH derive -- symmetry oracle (wolfP11-39t)
 *
 * Mirrors test_soft_derive_ecdh but uses P-384 keys (97-byte public key,
 * 48-byte shared secret).  Exercises the P-384 code path in soft_derive
 * which was previously untested.  Oracle: ECDH symmetry.
 * ---------------------------------------------------------------------- */

static int test_soft_derive_ecdh_p384(void)
{
    wp11_soft_key_t   *kA    = NULL;
    wp11_soft_key_t   *kB    = NULL;
    wp11_key_handle_t  hA;
    wp11_key_handle_t  hB;
    uint8_t            pubA[97];   /* P-384 uncompressed: 04 || X(48) || Y(48) */
    uint8_t            pubB[97];
    word32             pubA_len = (word32)sizeof(pubA);
    word32             pubB_len = (word32)sizeof(pubB);
    uint8_t            sharedAB[48];  /* P-384 x-coordinate: 48 bytes */
    uint8_t            sharedBA[48];
    size_t             sharedAB_len = sizeof(sharedAB);
    size_t             sharedBA_len = sizeof(sharedBA);
    int                ret;
    int                f = 0;

    kA = wp11_soft_key_new_ecc_p384();
    f += check(kA != NULL, "soft_derive_ecdh_p384: key A created");
    if (kA == NULL) goto done;

    kB = wp11_soft_key_new_ecc_p384();
    f += check(kB != NULL, "soft_derive_ecdh_p384: key B created");
    if (kB == NULL) goto done;

    make_handle(kA, &hA);
    make_handle(kB, &hB);

    ret = wp11_soft_key_test_export_pub_x963(kA, pubA, &pubA_len);
    f += check(ret == 0, "soft_derive_ecdh_p384: export pub A succeeds");
    ret = wp11_soft_key_test_export_pub_x963(kB, pubB, &pubB_len);
    f += check(ret == 0, "soft_derive_ecdh_p384: export pub B succeeds");

    f += check(pubA_len == 97u && pubB_len == 97u,
               "soft_derive_ecdh_p384: both public keys are 97 bytes (P-384)");
    f += check(pubA[0] == 0x04u && pubB[0] == 0x04u,
               "soft_derive_ecdh_p384: public keys start with 0x04 (uncompressed)");

    if (ret != 0 || pubA_len != 97u || pubB_len != 97u) goto done;

    ret = wp11_backend_soft_ops.derive(&hA, TEST_CKM_ECDH1_DERIVE,
                                       pubB, (size_t)pubB_len,
                                       sharedAB, &sharedAB_len);
    f += check(ret == 0, "soft_derive_ecdh_p384: A derives with B's pub returns 0");

    ret = wp11_backend_soft_ops.derive(&hB, TEST_CKM_ECDH1_DERIVE,
                                       pubA, (size_t)pubA_len,
                                       sharedBA, &sharedBA_len);
    f += check(ret == 0, "soft_derive_ecdh_p384: B derives with A's pub returns 0");

    f += check(sharedAB_len == 48u && sharedBA_len == 48u,
               "soft_derive_ecdh_p384: both shared secrets are 48 bytes (P-384 x-coord)");

    /* Oracle: ECDH symmetry -- A.priv * B.pub must equal B.priv * A.pub */
    f += check(sharedAB_len == sharedBA_len &&
               memcmp(sharedAB, sharedBA, sharedAB_len) == 0,
               "soft_derive_ecdh_p384: ECDH symmetry oracle: A*pubB == B*pubA");

done:
    wp11_soft_key_free(kA);
    wp11_soft_key_free(kB);
    return f;
}

int wp11_test_backend_soft(void)
{
    int failures = 0;

    failures += test_soft_sign_ecdsa();
    failures += test_soft_verify_ecdsa();
    failures += test_soft_sign_ecdsa_sha256();
    failures += test_soft_sign_rsa();
    failures += test_soft_decrypt_rsa();
    failures += test_soft_verify_rsa();
    failures += test_soft_derive_ecdh();
    failures += test_soft_derive_ecdh_p384();

    return failures;
}

#else /* WOLFP11_CFG_TEST not defined */

int wp11_test_backend_soft(void) { return 0; }

#endif /* WOLFP11_CFG_TEST */
