/* wp11_backend_usb_flash.c -- wolfP11 USB flash drive keystore backend
 *
 * Implements sign, verify, and decrypt using private keys loaded from an
 * encrypted .p11k keystore file on a USB flash drive.
 *
 * Each operation receives a wp11_key_handle_t whose priv field points to a
 * wp11_key_entry_t from the loaded keystore.  The entry contains DER-encoded
 * private key material (mlock'd by the keystore layer).
 *
 * Crypto engine: wolfCrypt.  Key material is decoded from DER on each call
 * into a temporary key object, used for the single operation, then freed and
 * zeroed.  This avoids keeping parsed key state alive longer than necessary.
 *
 * RNG: a function-local WC_RNG is initialized per sign call and freed
 * immediately after use.  The overhead is acceptable for a user-facing
 * PKCS#11 operation, and it avoids the need for a mutex around a global RNG.
 */

#define _POSIX_C_SOURCE 200112L

#include "wolfp11/wp11_keystore.h"
#include "wolfp11/wp11_backend.h"
#include "wolfp11/wp11_settings.h"

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/asn.h>   /* wc_RsaPrivateKeyDecode, wc_EccPrivateKeyDecode */
#include <string.h>

/* CKM_* mechanism values from PKCS#11 spec (mirrored from pkcs11.h).
 * We use the raw numeric values to avoid dragging in the full PKCS#11 header
 * in the backend implementation file -- the backend only needs these values. */
#define FLASH_CKM_RSA_PKCS       0x00000001UL  /* RSA PKCS#1 v1.5 */
#define FLASH_CKM_ECDSA          0x00001041UL  /* ECDSA, caller-supplied hash */
#define FLASH_CKM_ECDSA_SHA256   0x00001044UL  /* ECDSA with SHA-256 */

/* -------------------------------------------------------------------------
 * Internal helper: get the key entry from the handle
 * ---------------------------------------------------------------------- */

static const wp11_key_entry_t *flash_entry(const wp11_key_handle_t *handle)
{
    if (handle == NULL || handle->priv == NULL) return NULL;
    return (const wp11_key_entry_t *)handle->priv;
}

/* -------------------------------------------------------------------------
 * flash_sign
 *
 * Supports:
 *   FLASH_CKM_RSA_PKCS    -- RSA PKCS#1 v1.5 sign (prehashed)
 *   FLASH_CKM_ECDSA       -- ECDSA raw sign over a prehashed digest
 *   FLASH_CKM_ECDSA_SHA256 -- ECDSA with SHA-256 hash of input
 * ---------------------------------------------------------------------- */

static int flash_sign(const wp11_key_handle_t *handle,
                      uint32_t                 mechanism,
                      const uint8_t           *in,    size_t  inlen,
                      uint8_t                 *sig,   size_t *siglen)
{
    const wp11_key_entry_t *entry;
    word32 idx;
    int    ret;

    if (sig == NULL || siglen == NULL || in == NULL) return -1;

    entry = flash_entry(handle);
    if (entry == NULL) return -1;

    if (mechanism == FLASH_CKM_RSA_PKCS) {
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

        /* size_t -> word32 casts: RSA-4096 inputs/outputs are at most 512 bytes;
         * SHA-256 hash inputs are 32 bytes; both are far below UINT32_MAX.
         * The keystore enforces WP11_KEYSTORE_DER_MAX = 4096, so no key
         * that could produce values near UINT32_MAX can be loaded. */
        ret = wc_RsaSSL_Sign(in, (word32)inlen,
                              sig, (word32)*siglen,
                              &rsa, &rng);
        wc_FreeRsaKey(&rsa);
        wc_FreeRng(&rng);
        if (ret < 0) return -1;
        *siglen = (size_t)ret;
        return 0;
    }

    if (mechanism == FLASH_CKM_ECDSA || mechanism == FLASH_CKM_ECDSA_SHA256) {
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

        if (mechanism == FLASH_CKM_ECDSA_SHA256) {
            /* Hash the input with SHA-256, then sign the digest */
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
            /* FLASH_CKM_ECDSA: sign the caller-supplied prehashed digest */
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
 * flash_verify
 *
 * Supports:
 *   FLASH_CKM_RSA_PKCS    -- RSA PKCS#1 v1.5 verify (prehashed)
 *   FLASH_CKM_ECDSA       -- ECDSA verify over a prehashed digest
 *   FLASH_CKM_ECDSA_SHA256 -- ECDSA with SHA-256 hash of input
 *
 * Note: verifying with the private key is unusual but valid in PKCS#11
 * (CKO_PRIVATE_KEY objects support verify for RSA via raw RSA operation).
 * We derive the public key from the private DER for verification.
 * ---------------------------------------------------------------------- */

static int flash_verify(const wp11_key_handle_t *handle,
                        uint32_t                 mechanism,
                        const uint8_t           *in,    size_t inlen,
                        const uint8_t           *sig,   size_t siglen)
{
    const wp11_key_entry_t *entry;
    word32 idx;
    int    ret;

    if (in == NULL || sig == NULL) return -1;

    entry = flash_entry(handle);
    if (entry == NULL) return -1;

    if (mechanism == FLASH_CKM_RSA_PKCS) {
        /* RSA PKCS#1 v1.5 verify: public-decrypt the signature into out[],
         * then compare to the expected input digest.
         *
         * Buffer size: RSA-4096 produces a 512-byte (4096/8) output.
         * WP11_KEYSTORE_DER_MAX = 4096 bytes caps the DER key size, which
         * limits keys to RSA-4096.  If larger keys are added, this buffer
         * must grow and WP11_KEYSTORE_DER_MAX must be raised in lock-step.
         *
         * wc_RsaSSL_Verify bounds-checks the output against outlen before
         * writing (returns RSA_BUFFER_E if it would overflow), so this is
         * safe even if the key size limit is ever raised and the buffer is
         * not updated -- the operation fails cleanly rather than overflowing. */
        RsaKey  rsa;
        uint8_t out[512];  /* RSA-4096 max: 4096/8 = 512 bytes */
        word32  outlen = (word32)sizeof(out);

        if (entry->key_type != WP11_KEY_TYPE_RSA) return -1;

        idx = 0;
        ret = wc_InitRsaKey(&rsa, NULL);
        if (ret != 0) return -1;

        ret = wc_RsaPrivateKeyDecode(entry->der_bytes, &idx, &rsa,
                                     (word32)entry->der_len);
        if (ret != 0) { wc_FreeRsaKey(&rsa); return -1; }

        ret = wc_RsaSSL_Verify(sig, (word32)siglen, out, outlen, &rsa);
        wc_FreeRsaKey(&rsa);
        if (ret < 0) return -1;
        if ((size_t)ret != inlen || memcmp(out, in, inlen) != 0) return -1;
        return 0;
    }

    if (mechanism == FLASH_CKM_ECDSA || mechanism == FLASH_CKM_ECDSA_SHA256) {
        ecc_key ecc;
        int     stat;

        if (entry->key_type != WP11_KEY_TYPE_EC) return -1;

        idx = 0;
        ret = wc_ecc_init(&ecc);
        if (ret != 0) return -1;

        ret = wc_EccPrivateKeyDecode(entry->der_bytes, &idx, &ecc,
                                     (word32)entry->der_len);
        if (ret != 0) { wc_ecc_free(&ecc); return -1; }

        if (mechanism == FLASH_CKM_ECDSA_SHA256) {
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
 * flash_decrypt
 *
 * Supports:
 *   FLASH_CKM_RSA_PKCS -- RSA PKCS#1 v1.5 decrypt
 * ---------------------------------------------------------------------- */

static int flash_decrypt(const wp11_key_handle_t *handle,
                         uint32_t                 mechanism,
                         const uint8_t           *ct,    size_t  ctlen,
                         uint8_t                 *pt,    size_t *ptlen)
{
    const wp11_key_entry_t *entry;
    word32 idx;
    int    ret;

    if (ct == NULL || pt == NULL || ptlen == NULL) return -1;

    entry = flash_entry(handle);
    if (entry == NULL) return -1;

    if (mechanism == FLASH_CKM_RSA_PKCS) {
        RsaKey rsa;
        WC_RNG rng;

        if (entry->key_type != WP11_KEY_TYPE_RSA) return -1;

        /* wolfP11-5l2: wc_RsaPrivateDecrypt uses RSA blinding internally
         * (WC_RSA_BLINDING is on by default in wolfCrypt builds).  Blinding
         * requires an RNG inside the RsaKey struct, set via wc_RsaSetRNG.
         * Without this call the function returns BAD_FUNC_ARG immediately
         * before performing any decryption.  flash_sign avoids this because
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

        /* size_t -> word32 cast: RSA-4096 ciphertext is 512 bytes max, and
         * plaintext output is always smaller than the modulus.  Both are far
         * below UINT32_MAX.  WP11_KEYSTORE_DER_MAX = 4096 caps key size. */
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

/* -------------------------------------------------------------------------
 * Exported backend ops table
 * ---------------------------------------------------------------------- */

const wp11_backend_ops_t wp11_backend_flash_ops = {
    WP11_BACKEND_USB_FLASH,
    flash_sign,
    flash_verify,
    flash_decrypt,
    /* derive: flash keys are stored-key-only; no hardware ECDH support. */
    NULL,
    /* wolfP11-be5: free_key_priv is NULL for the flash backend.  key_priv
     * for flash keys points into the wp11_keystore_t entries array, which
     * is owned and freed in bulk by wp11_keystore_free.  Individual per-key
     * free must NOT be called. */
    NULL,
};

#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */
