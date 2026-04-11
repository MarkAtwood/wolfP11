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

/* wp11_backend_keystore.c -- shared sign/verify/decrypt for keystore backends
 *
 * Both the USB flash (WOLFP11_CFG_USB_FLASH_BACKEND) and filesystem-directory
 * (WOLFP11_CFG_FSDIR_BACKEND) backends load private keys from encrypted .p11k
 * keystores and perform the same crypto operations.  This file provides a
 * single implementation used by both; the per-backend files just export their
 * ops struct pointing here.
 *
 * Crypto engine: wolfCrypt.  Key material is decoded from DER on each call
 * into a temporary key object, used for the single operation, then freed and
 * zeroed.  This avoids keeping parsed key state alive longer than necessary.
 *
 * RNG: a function-local WC_RNG is initialized per-call and freed immediately
 * after use, avoiding the need for a mutex around a global RNG.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include "wolfp11/wp11_backend.h"
#include "wolfp11/wp11_keystore.h"
#include "wolfp11/wp11_settings.h"

#if defined(WOLFP11_CFG_USB_FLASH_BACKEND) || defined(WOLFP11_CFG_FSDIR_BACKEND)

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <string.h>

/* CKM_* mechanism values from PKCS#11 spec (raw values; no pkcs11.h needed). */
#define KS_CKM_RSA_PKCS      0x00000001UL  /* RSA PKCS#1 v1.5                */
#define KS_CKM_ECDSA         0x00001041UL  /* ECDSA, caller-supplied hash     */
#define KS_CKM_ECDSA_SHA256  0x00001044UL  /* ECDSA with SHA-256              */

/* -------------------------------------------------------------------------
 * Internal helper: validate handle and return the key entry.
 *
 * Accepts either WP11_BACKEND_USB_FLASH or WP11_BACKEND_FSDIR.
 * The PKCS#11 dispatch layer assigns ops at key-creation time, so this path
 * is only reached from the registered callbacks, but the check is
 * defense-in-depth against future refactors crossing backend types.
 * ---------------------------------------------------------------------- */

static const wp11_key_entry_t *ks_entry(const wp11_key_handle_t *handle)
{
    if (handle == NULL || handle->priv == NULL) return NULL;
#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
    if (handle->backend == WP11_BACKEND_USB_FLASH)
        return (const wp11_key_entry_t *)handle->priv;
#endif
#ifdef WOLFP11_CFG_FSDIR_BACKEND
    if (handle->backend == WP11_BACKEND_FSDIR)
        return (const wp11_key_entry_t *)handle->priv;
#endif
    return NULL;
}

/* -------------------------------------------------------------------------
 * wp11_ks_sign
 *
 * Supports:
 *   KS_CKM_RSA_PKCS      -- RSA PKCS#1 v1.5 sign (prehashed input)
 *   KS_CKM_ECDSA         -- ECDSA raw sign over a caller-supplied digest
 *   KS_CKM_ECDSA_SHA256  -- ECDSA with SHA-256 hash of input
 * ---------------------------------------------------------------------- */

int wp11_ks_sign(const wp11_key_handle_t *handle,
                 uint32_t                 mechanism,
                 const uint8_t           *in,    size_t  inlen,
                 uint8_t                 *sig,   size_t *siglen)
{
    const wp11_key_entry_t *entry;
    word32 idx;
    int    ret;

    if (sig == NULL || siglen == NULL || in == NULL) return -1;

    entry = ks_entry(handle);
    if (entry == NULL) return -1;

    if (mechanism == KS_CKM_RSA_PKCS) {
        RsaKey rsa;
        WC_RNG rng;

        if (entry->key_type != WP11_KEY_TYPE_RSA) return -1;
        if (wc_InitRng(&rng) != 0) return -1;

        idx = 0;
        ret = wc_InitRsaKey(&rsa, NULL);
        if (ret != 0) { wc_FreeRng(&rng); return -1; }

        ret = wc_RsaPrivateKeyDecode(entry->der_bytes, &idx, &rsa,
                                     (word32)entry->der_len);
        if (ret != 0) {
            wc_FreeRsaKey(&rsa);
            wc_FreeRng(&rng);
            return -1;
        }

        /* Guard size_t->word32 narrowing before passing to wolfCrypt.
         * RSA-4096 data is at most 512 bytes so these cannot fire in normal
         * use, but the guard is required for correctness under any caller. */
        if (!WP11_FITS_U32(inlen) || !WP11_FITS_U32(*siglen)) {
            wc_FreeRsaKey(&rsa);
            wc_FreeRng(&rng);
            return -1;
        }
        ret = wc_RsaSSL_Sign(in, (word32)inlen,
                              sig, (word32)*siglen,
                              &rsa, &rng);
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        if (ret < 0) return -1;
        *siglen = (size_t)ret;
        return 0;
    }

    if (mechanism == KS_CKM_ECDSA || mechanism == KS_CKM_ECDSA_SHA256) {
        ecc_key ecc;
        WC_RNG  rng;
        word32  wlen;

        if (entry->key_type != WP11_KEY_TYPE_EC) return -1;
        if (wc_InitRng(&rng) != 0) return -1;

        idx = 0;
        ret = wc_ecc_init(&ecc);
        if (ret != 0) { wc_FreeRng(&rng); return -1; }

        ret = wc_EccPrivateKeyDecode(entry->der_bytes, &idx, &ecc,
                                     (word32)entry->der_len);
        if (ret != 0) {
            wc_ecc_free(&ecc);
            wc_FreeRng(&rng);
            return -1;
        }

        /* Guard all size_t->word32 narrowing casts in this block: inlen is
         * passed to wc_Sha256Update and wc_ecc_sign_hash; *siglen is used as
         * the output buffer length (wlen).  P-256/P-384 values are tiny but
         * a hostile caller could pass SIZE_MAX. */
        if (!WP11_FITS_U32(inlen) || !WP11_FITS_U32(*siglen)) {
            wc_ecc_free(&ecc);
            wc_FreeRng(&rng);
            return -1;
        }

        if (mechanism == KS_CKM_ECDSA_SHA256) {
            wc_Sha256 sha;
            uint8_t   digest[WC_SHA256_DIGEST_SIZE];

            if (wc_InitSha256(&sha) != 0) {
                wc_ecc_free(&ecc);
                wc_FreeRng(&rng);
                return -1;
            }
            ret = wc_Sha256Update(&sha, in, (word32)inlen);
            if (ret == 0) ret = wc_Sha256Final(&sha, digest);
            wc_Sha256Free(&sha);
            if (ret != 0) {
                wc_ecc_free(&ecc);
                wc_FreeRng(&rng);
                return -1;
            }
            wlen = (word32)*siglen;
            ret  = wc_ecc_sign_hash(digest, WC_SHA256_DIGEST_SIZE,
                                    sig, &wlen, &rng, &ecc);
        } else {
            /* KS_CKM_ECDSA: sign the caller-supplied prehashed digest */
            wlen = (word32)*siglen;
            ret  = wc_ecc_sign_hash(in, (word32)inlen,
                                    sig, &wlen, &rng, &ecc);
        }

        wc_ecc_free(&ecc);
        wc_FreeRng(&rng);
        if (ret != 0) return -1;
        *siglen = (size_t)wlen;
        return 0;
    }

    return -1; /* unsupported mechanism */
}

/* -------------------------------------------------------------------------
 * wp11_ks_verify
 *
 * Supports:
 *   KS_CKM_RSA_PKCS      -- RSA PKCS#1 v1.5 verify (prehashed)
 *   KS_CKM_ECDSA         -- ECDSA verify over a caller-supplied digest
 *   KS_CKM_ECDSA_SHA256  -- ECDSA with SHA-256 hash of input
 *
 * Verifying with the private key is valid in PKCS#11 (CKO_PRIVATE_KEY
 * objects support verify for RSA via the raw RSA operation).  The public
 * key is derived from the private DER.
 * ---------------------------------------------------------------------- */

int wp11_ks_verify(const wp11_key_handle_t *handle,
                   uint32_t                 mechanism,
                   const uint8_t           *in,    size_t inlen,
                   const uint8_t           *sig,   size_t siglen)
{
    const wp11_key_entry_t *entry;
    word32 idx;
    int    ret;

    if (in == NULL || sig == NULL) return -1;

    entry = ks_entry(handle);
    if (entry == NULL) return -1;

    if (mechanism == KS_CKM_RSA_PKCS) {
        /* RSA PKCS#1 v1.5 verify: public-decrypt the signature, compare.
         *
         * Buffer size: RSA-4096 produces 512-byte output (4096/8).
         * WP11_KEYSTORE_DER_MAX = 4096 caps the DER key size.
         * wc_RsaSSL_Verify bounds-checks against outlen before writing, so
         * if the key size limit is ever raised this fails cleanly (RSA_BUFFER_E)
         * rather than overflowing. */
        RsaKey  rsa;
        uint8_t out[512];
        word32  outlen = (word32)sizeof(out);

        if (entry->key_type != WP11_KEY_TYPE_RSA) return -1;

        idx = 0;
        ret = wc_InitRsaKey(&rsa, NULL);
        if (ret != 0) return -1;

        ret = wc_RsaPrivateKeyDecode(entry->der_bytes, &idx, &rsa,
                                     (word32)entry->der_len);
        if (ret != 0) { wc_FreeRsaKey(&rsa); return -1; }

        if (!WP11_FITS_U32(siglen)) { wc_FreeRsaKey(&rsa); return -1; }
        ret = wc_RsaSSL_Verify(sig, (word32)siglen, out, outlen, &rsa);
        wc_FreeRsaKey(&rsa);
        if (ret < 0) return -1;
        if ((size_t)ret != inlen || memcmp(out, in, inlen) != 0) return -1;
        return 0;
    }

    if (mechanism == KS_CKM_ECDSA || mechanism == KS_CKM_ECDSA_SHA256) {
        ecc_key ecc;
        int     stat;

        if (entry->key_type != WP11_KEY_TYPE_EC) return -1;

        idx = 0;
        ret = wc_ecc_init(&ecc);
        if (ret != 0) return -1;

        ret = wc_EccPrivateKeyDecode(entry->der_bytes, &idx, &ecc,
                                     (word32)entry->der_len);
        if (ret != 0) { wc_ecc_free(&ecc); return -1; }

        /* Guard size_t->word32 narrowing for inlen (Sha256Update, ecc_verify_hash)
         * and siglen (ecc_verify_hash). */
        if (!WP11_FITS_U32(inlen) || !WP11_FITS_U32(siglen)) {
            wc_ecc_free(&ecc);
            return -1;
        }

        if (mechanism == KS_CKM_ECDSA_SHA256) {
            wc_Sha256 sha;
            uint8_t   digest[WC_SHA256_DIGEST_SIZE];

            if (wc_InitSha256(&sha) != 0) { wc_ecc_free(&ecc); return -1; }
            ret = wc_Sha256Update(&sha, in, (word32)inlen);
            if (ret == 0) ret = wc_Sha256Final(&sha, digest);
            wc_Sha256Free(&sha);
            if (ret != 0) { wc_ecc_free(&ecc); return -1; }

            stat = 0;
            ret  = wc_ecc_verify_hash(sig, (word32)siglen,
                                      digest, WC_SHA256_DIGEST_SIZE,
                                      &stat, &ecc);
        } else {
            stat = 0;
            ret  = wc_ecc_verify_hash(sig, (word32)siglen,
                                      in, (word32)inlen,
                                      &stat, &ecc);
        }

        wc_ecc_free(&ecc);
        if (ret != 0 || stat != 1) return -1;
        return 0;
    }

    return -1;
}

/* -------------------------------------------------------------------------
 * wp11_ks_decrypt
 *
 * Supports:
 *   KS_CKM_RSA_PKCS -- RSA PKCS#1 v1.5 decrypt
 * ---------------------------------------------------------------------- */

int wp11_ks_decrypt(const wp11_key_handle_t *handle,
                    uint32_t                 mechanism,
                    const uint8_t           *ct,    size_t  ctlen,
                    uint8_t                 *pt,    size_t *ptlen)
{
    const wp11_key_entry_t *entry;
    word32 idx;
    int    ret;

    if (ct == NULL || pt == NULL || ptlen == NULL) return -1;

    entry = ks_entry(handle);
    if (entry == NULL) return -1;

    if (mechanism == KS_CKM_RSA_PKCS) {
        RsaKey rsa;
        WC_RNG rng;

        if (entry->key_type != WP11_KEY_TYPE_RSA) return -1;

        /* wolfP11-5l2: wc_RsaPrivateDecrypt uses RSA blinding internally
         * (WC_RSA_BLINDING is on by default in wolfCrypt builds).  Blinding
         * requires an RNG inside the RsaKey struct, set via wc_RsaSetRNG.
         * Without this call the function returns BAD_FUNC_ARG immediately
         * before performing any decryption.  wp11_ks_sign avoids this because
         * wc_RsaSSL_Sign takes an explicit &rng argument; wc_RsaPrivateDecrypt
         * does not, so wc_RsaSetRNG is the only way to supply the RNG. */
        if (wc_InitRng(&rng) != 0) return -1;

        idx = 0;
        ret = wc_InitRsaKey(&rsa, NULL);
        if (ret != 0) { wc_FreeRng(&rng); return -1; }

        ret = wc_RsaPrivateKeyDecode(entry->der_bytes, &idx, &rsa,
                                     (word32)entry->der_len);
        if (ret != 0) {
            wc_FreeRsaKey(&rsa);
            wc_FreeRng(&rng);
            return -1;
        }

        ret = wc_RsaSetRNG(&rsa, &rng);
        if (ret != 0) {
            wc_FreeRsaKey(&rsa);
            wc_FreeRng(&rng);
            return -1;
        }

        /* Guard size_t->word32 narrowing before passing to wolfCrypt.
         * RSA-4096 ciphertext is at most 512 bytes so these cannot fire in
         * normal use, but the guard is required for correctness under any caller. */
        if (!WP11_FITS_U32(ctlen) || !WP11_FITS_U32(*ptlen)) {
            wc_FreeRsaKey(&rsa);
            wc_FreeRng(&rng);
            return -1;
        }
        ret = wc_RsaPrivateDecrypt(ct, (word32)ctlen,
                                   pt, (word32)*ptlen,
                                   &rsa);
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        if (ret < 0) return -1;
        *ptlen = (size_t)ret;
        return 0;
    }

    return -1;
}

#endif /* WOLFP11_CFG_USB_FLASH_BACKEND || WOLFP11_CFG_FSDIR_BACKEND */
