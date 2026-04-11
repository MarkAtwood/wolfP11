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

/* wp11_backend_soft.c -- wolfCrypt direct software backend
 * No hardware or daemon required. Uses wolfCrypt for all crypto.
 */
/* wolfssl header order: options.h must come first or settings.h fires a
 * #warning that -Werror converts to an error.  Keep it before all project
 * headers that transitively include wolfssl internals (e.g. wp11_soft_key.h
 * under WOLFP11_CFG_TEST pulls in wolfssl/wolfcrypt/types.h). */
#include <wolfssl/options.h>
#include "wolfp11/wp11_backend.h"
#include "wolfp11/wp11_soft_key.h"
#include "wolfp11/wp11_settings.h"
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

/* wolfP11-ghii: wipe a memory region against dead-store elimination.
 * Delegates to wc_ForceZero() which selects the strongest available
 * platform primitive (memset_s on C11, explicit_bzero on Linux/BSD,
 * SecureZeroMemory on Windows) rather than relying on a volatile cast
 * that aggressive LTO can still eliminate.  Used to wipe sensitive
 * material (digests, RSA plaintext) from stack buffers before returning. */
static void soft_zero(void *p, size_t n)
{
    wc_ForceZero(p, n);
}

/* Mechanism values (subset of CKM_* from PKCS#11 2.40 / 3.0) */
#define SOFT_CKM_RSA_PKCS      (0x00000001UL)
#define SOFT_CKM_ECDSA         (0x00001041UL)
#define SOFT_CKM_ECDSA_SHA256  (0x00001044UL)
#define SOFT_CKM_ECDH1_DERIVE  (0x00001050UL)
#define SOFT_CKM_EDDSA         (0x00001057UL)  /* PKCS#11 3.0 EdDSA */

/* -------------------------------------------------------------------------
 * Key type tags
 * ---------------------------------------------------------------------- */

#define WP11_SOFT_KEY_ECC      1
#define WP11_SOFT_KEY_RSA      2
#define WP11_SOFT_KEY_ED25519  3

/* -------------------------------------------------------------------------
 * Soft key structure
 * ---------------------------------------------------------------------- */

/* 'struct wp11_soft_key' is forward-declared in wolfp11/wp11_soft_key.h
 * so that callers can hold an opaque wp11_soft_key_t * without seeing
 * the internal wolfCrypt state. */
struct wp11_soft_key {
    int       key_type;
    ecc_key   ecc;
    RsaKey    rsa;
    ed25519_key ed25519;
    WC_RNG    rng;
    int     initialized;
    /* wolfP11-lbs: ref_count is accessed concurrently from multiple threads
     * (a key object can be shared across PKCS#11 sessions which may be used
     * from different threads).  All inc/dec operations use GCC/clang __atomic
     * builtins so that cross-thread visibility and ordering are guaranteed on
     * weakly-ordered architectures.  The field itself remains plain int
     * because C99 has no _Atomic; the builtins provide the needed barriers. */
    int     ref_count;
};
typedef struct wp11_soft_key wp11_soft_key_t;

/* -------------------------------------------------------------------------
 * Key lifecycle
 * ---------------------------------------------------------------------- */

wp11_soft_key_t *wp11_soft_key_new_ecc_p256(void)
{
    wp11_soft_key_t *k = (wp11_soft_key_t *)calloc(1, sizeof(*k));
    if (k == NULL) {
        return NULL;
    }

    if (wc_InitRng(&k->rng) != 0) {
        free(k);
        return NULL;
    }

    if (wc_ecc_init(&k->ecc) != 0) {
        wc_FreeRng(&k->rng);
        free(k);
        return NULL;
    }

    if (wc_ecc_make_key_ex(&k->rng, 32, &k->ecc, ECC_SECP256R1) != 0) {
        wc_ecc_free(&k->ecc);
        wc_FreeRng(&k->rng);
        free(k);
        return NULL;
    }

    k->key_type = WP11_SOFT_KEY_ECC;
    k->initialized = 1;
    k->ref_count = 1;
    return k;
}

/* wolfP11-39t: P-384 key constructor -- parallel to wp11_soft_key_new_ecc_p256.
 * ECC_SECP384R1 key size is 48 bytes; uncompressed public key is 97 bytes. */
/* wolfP11-z2fo: standardized to the verbose P-256 error-handling style for
 * consistency and reviewability. */
wp11_soft_key_t *wp11_soft_key_new_ecc_p384(void)
{
    wp11_soft_key_t *k = (wp11_soft_key_t *)calloc(1, sizeof(*k));
    if (k == NULL) {
        return NULL;
    }

    if (wc_InitRng(&k->rng) != 0) {
        free(k);
        return NULL;
    }

    if (wc_ecc_init(&k->ecc) != 0) {
        wc_FreeRng(&k->rng);
        free(k);
        return NULL;
    }

    if (wc_ecc_make_key_ex(&k->rng, 48, &k->ecc, ECC_SECP384R1) != 0) {
        wc_ecc_free(&k->ecc);
        wc_FreeRng(&k->rng);
        free(k);
        return NULL;
    }

    k->key_type = WP11_SOFT_KEY_ECC;
    k->initialized = 1;
    k->ref_count = 1;
    return k;
}

wp11_soft_key_t *wp11_soft_key_new_rsa2048(void)
{
    wp11_soft_key_t *k = (wp11_soft_key_t *)calloc(1, sizeof(*k));
    if (k == NULL) {
        return NULL;
    }

    if (wc_InitRng(&k->rng) != 0) {
        free(k);
        return NULL;
    }

    if (wc_InitRsaKey(&k->rsa, NULL) != 0) {
        wc_FreeRng(&k->rng);
        free(k);
        return NULL;
    }

    if (wc_MakeRsaKey(&k->rsa, 2048, 65537, &k->rng) != 0) {
        wc_FreeRsaKey(&k->rsa);
        wc_FreeRng(&k->rng);
        free(k);
        return NULL;
    }

    /* WC_RSA_BLINDING is enabled in this wolfCrypt build (default).
     * wc_RsaPrivateDecrypt does not take an explicit RNG parameter; it uses
     * the RNG stored inside the RsaKey (set via wc_RsaSetRNG).  Without this
     * call, all private decrypt operations fail at runtime with blinding
     * error BAD_FUNC_ARG.  The RNG lifetime is tied to the wp11_soft_key_t
     * struct and is freed in wp11_soft_key_free, so the pointer remains valid
     * for the key's entire lifetime. */
    if (wc_RsaSetRNG(&k->rsa, &k->rng) != 0) {
        wc_FreeRsaKey(&k->rsa);
        wc_FreeRng(&k->rng);
        free(k);
        return NULL;
    }

    k->key_type = WP11_SOFT_KEY_RSA;
    k->initialized = 1;
    k->ref_count = 1;
    return k;
}

/* Allocate and generate a new RSA key of the given bit length.
 * wolfP11-prlc: valid range is [WOLFSSL_MIN_RSA_BITS, 4096]; see
 * wp11_soft_key_new_rsa declaration in wp11_soft_key.h for full rationale.
 * Returns NULL on failure. */
wp11_soft_key_t *wp11_soft_key_new_rsa(int bits)
{
    wp11_soft_key_t *k = (wp11_soft_key_t *)calloc(1, sizeof(*k));
    if (k == NULL) return NULL;

    if (wc_InitRng(&k->rng) != 0) {
        free(k);
        return NULL;
    }

    if (wc_InitRsaKey(&k->rsa, NULL) != 0) {
        wc_FreeRng(&k->rng);
        free(k);
        return NULL;
    }

    if (wc_MakeRsaKey(&k->rsa, bits, 65537, &k->rng) != 0) {
        wc_FreeRsaKey(&k->rsa);
        wc_FreeRng(&k->rng);
        free(k);
        return NULL;
    }

    if (wc_RsaSetRNG(&k->rsa, &k->rng) != 0) {
        wc_FreeRsaKey(&k->rsa);
        wc_FreeRng(&k->rng);
        free(k);
        return NULL;
    }

    k->key_type = WP11_SOFT_KEY_RSA;
    k->initialized = 1;
    k->ref_count = 1;
    return k;
}

wp11_soft_key_t *wp11_soft_key_new_ed25519(void)
{
    wp11_soft_key_t *k = (wp11_soft_key_t *)calloc(1, sizeof(*k));
    if (k == NULL) return NULL;

    if (wc_InitRng(&k->rng) != 0) {
        free(k);
        return NULL;
    }

    if (wc_ed25519_init(&k->ed25519) != 0) {
        wc_FreeRng(&k->rng);
        free(k);
        return NULL;
    }

    /* Ed25519 key size is always exactly 32 bytes, fixed by RFC 8032.
     * wolfCrypt defines ED25519_KEY_SIZE=32 but accepts the literal here;
     * this is not a tuneable parameter -- any other value is invalid per
     * the spec and wc_ed25519_make_key will return an error. */
    if (wc_ed25519_make_key(&k->rng, 32, &k->ed25519) != 0) {
        wc_ed25519_free(&k->ed25519);
        wc_FreeRng(&k->rng);
        free(k);
        return NULL;
    }

    k->key_type = WP11_SOFT_KEY_ED25519;
    k->initialized = 1;
    k->ref_count = 1;
    return k;
}

/* Increment reference count on a shared soft key.  Returns key (for chaining).
 * Used by C_GenerateKeyPair to share one wp11_soft_key_t between the public
 * and private key objects without copying the key material. */
wp11_soft_key_t *wp11_soft_key_ref(wp11_soft_key_t *key)
{
    if (key != NULL) {
        /* wolfP11-ezfx: increment uses RELAXED (ref formed from existing ref;
         * caller's synchronization already establishes happens-before).
         * Decrement (wolfP11-lbs) uses ACQ_REL: RELEASE so prior writes are
         * visible before free; ACQUIRE so the freeing thread sees all stores. */
        __atomic_fetch_add(&key->ref_count, 1, __ATOMIC_RELAXED);
    }
    return key;
}

void wp11_soft_key_free(wp11_soft_key_t *key)
{
    if (key == NULL) {
        return;
    }
    /* ACQ_REL on decrement (wolfP11-lbs):
     * RELEASE -- our last writes to the key are visible to any thread that
     *            subsequently decrements the count to 0 and frees.
     * ACQUIRE -- we see all other threads' final writes before we free.
     * fetch_sub returns the OLD value; if > 1 the key is still live. */
    if (__atomic_fetch_sub(&key->ref_count, 1, __ATOMIC_ACQ_REL) > 1) {
        return; /* still referenced by another key object */
    }
    if (key->initialized) {
        if (key->key_type == WP11_SOFT_KEY_ECC) {
            wc_ecc_free(&key->ecc);
        } else if (key->key_type == WP11_SOFT_KEY_RSA) {
            wc_FreeRsaKey(&key->rsa);
        } else if (key->key_type == WP11_SOFT_KEY_ED25519) {
            wc_ed25519_free(&key->ed25519);
        }
        wc_FreeRng(&key->rng);
    }
    free(key);
}

/* -------------------------------------------------------------------------
 * Sign
 * ---------------------------------------------------------------------- */

static int soft_sign(const wp11_key_handle_t *handle,
                     uint32_t                 mechanism,
                     const uint8_t           *in,    size_t  inlen,
                     uint8_t                 *sig,   size_t *siglen)
{
    wp11_soft_key_t *k;
    word32 wlen;
    int ret;

    if (handle == NULL || handle->priv == NULL ||
        in == NULL || sig == NULL || siglen == NULL) {
        return -1;
    }

    k = (wp11_soft_key_t *)handle->priv;

    if (mechanism == SOFT_CKM_ECDSA) {
        if (k->key_type != WP11_SOFT_KEY_ECC) {
            return -1;
        }
        /* wolfP11-g466: *siglen is size_t (64-bit on LP64); word32 is 32-bit.
         * A value > UINT32_MAX silently truncates, giving wolfCrypt a bogus
         * buffer bound.  Guard mirrors wolfP11-jhb3 used for inlen below. */
        if (!WP11_FITS_U32(*siglen)) return -1;
        wlen = (word32)*siglen;
        ret = wc_ecc_sign_hash(in, (word32)inlen, sig, &wlen, &k->rng, &k->ecc);
        if (ret != 0) {
            return -1;
        }
        *siglen = (size_t)wlen;
        return 0;
    }

    if (mechanism == SOFT_CKM_ECDSA_SHA256) {
        wc_Sha256 sha;
        uint8_t   digest[WC_SHA256_DIGEST_SIZE];

        if (k->key_type != WP11_SOFT_KEY_ECC) {
            return -1;
        }
        if (wc_InitSha256(&sha) != 0) {
            return -1;
        }
        ret = wc_Sha256Update(&sha, in, (word32)inlen);
        if (ret == 0) {
            ret = wc_Sha256Final(&sha, digest);
        }
        wc_Sha256Free(&sha);
        /* wolfP11-rzwt: wc_Sha256Free cleans the Sha256 context struct but
         * does NOT zero the digest[] output buffer -- that's caller-managed.
         * soft_zero() here prevents the hash from being readable in stack
         * memory after the signing call returns. */
        if (ret != 0) {
            soft_zero(digest, sizeof(digest));
            return -1;
        }
        /* wolfP11-g466: same size_t->word32 truncation guard as ECDSA above. */
        if (!WP11_FITS_U32(*siglen)) return -1;
        wlen = (word32)*siglen;
        ret = wc_ecc_sign_hash(digest, WC_SHA256_DIGEST_SIZE,
                               sig, &wlen, &k->rng, &k->ecc);
        soft_zero(digest, sizeof(digest));
        if (ret != 0) {
            return -1;
        }
        *siglen = (size_t)wlen;
        return 0;
    }

    if (mechanism == SOFT_CKM_RSA_PKCS) {
        if (k->key_type != WP11_SOFT_KEY_RSA) {
            return -1;
        }
        /* wolfP11-jhb3: size_t is 64 bits on LP64; word32 is 32 bits.
         * A cast of inlen > UINT32_MAX silently truncates to a small value,
         * turning the input into a short prefix and signing garbage. */
        if (!WP11_FITS_U32(inlen)) return -1;
        /* wolfP11-g466: same truncation risk on the output-buffer bound. */
        if (!WP11_FITS_U32(*siglen)) return -1;
        wlen = (word32)*siglen;
        ret = wc_RsaSSL_Sign(in, (word32)inlen, sig, wlen, &k->rsa, &k->rng);
        if (ret < 0) {
            return -1;
        }
        *siglen = (size_t)ret;
        return 0;
    }

    if (mechanism == SOFT_CKM_EDDSA) {
        if (k->key_type != WP11_SOFT_KEY_ED25519) {
            return -1;
        }
        /* Ed25519 sign takes the full message (not a pre-hash).
         * wc_ed25519_sign_msg hashes internally with SHA-512. */
        if (!WP11_FITS_U32(inlen))   return -1;
        /* wolfP11-g466: same truncation guard for the output-buffer bound. */
        if (!WP11_FITS_U32(*siglen)) return -1;
        wlen = (word32)*siglen;
        ret = wc_ed25519_sign_msg(in, (word32)inlen, sig, &wlen, &k->ed25519);
        if (ret != 0) {
            return -1;
        }
        *siglen = (size_t)wlen;
        return 0;
    }

    return -1;
}

/* -------------------------------------------------------------------------
 * Verify
 * ---------------------------------------------------------------------- */

static int soft_verify(const wp11_key_handle_t *handle,
                       uint32_t                 mechanism,
                       const uint8_t           *in,    size_t inlen,
                       const uint8_t           *sig,   size_t siglen)
{
    wp11_soft_key_t *k;
    int ret;
    int stat;

    if (handle == NULL || handle->priv == NULL || in == NULL || sig == NULL) {
        return -1;
    }

    k = (wp11_soft_key_t *)handle->priv;

    if (mechanism == SOFT_CKM_ECDSA) {
        if (k->key_type != WP11_SOFT_KEY_ECC) {
            return -1;
        }
        /* wolfP11-u1lx: siglen is size_t; wc_ecc_verify_hash takes word32.
         * A truncated siglen makes the function read fewer signature bytes,
         * potentially accepting an invalid signature as valid.  EDDSA has
         * this guard (see below); ECDSA must too. */
        if (!WP11_FITS_U32(siglen)) return -1;
        stat = 0;
        ret = wc_ecc_verify_hash(sig, (word32)siglen,
                                 in,  (word32)inlen,
                                 &stat, &k->ecc);
        if (ret != 0 || stat != 1) {
            return -1;
        }
        return 0;
    }

    if (mechanism == SOFT_CKM_ECDSA_SHA256) {
        wc_Sha256 sha;
        uint8_t   digest[WC_SHA256_DIGEST_SIZE];

        if (k->key_type != WP11_SOFT_KEY_ECC) {
            return -1;
        }
        /* wolfP11-u1lx: same truncation guard as ECDSA above. */
        if (!WP11_FITS_U32(siglen)) return -1;
        if (wc_InitSha256(&sha) != 0) {
            return -1;
        }
        ret = wc_Sha256Update(&sha, in, (word32)inlen);
        if (ret == 0) {
            ret = wc_Sha256Final(&sha, digest);
        }
        wc_Sha256Free(&sha);
        if (ret != 0) {
            soft_zero(digest, sizeof(digest));
            return -1;
        }
        stat = 0;
        ret = wc_ecc_verify_hash(sig, (word32)siglen,
                                 digest, WC_SHA256_DIGEST_SIZE,
                                 &stat, &k->ecc);
        soft_zero(digest, sizeof(digest));
        if (ret != 0 || stat != 1) {
            return -1;
        }
        return 0;
    }

    if (mechanism == SOFT_CKM_RSA_PKCS) {
        /* WP11_RSA4096_BYTES covers RSA-4096: PKCS#1 v1.5 unpadded output max
         * is key_bytes - 11 (mandatory padding) = 512 - 11 = 501 bytes.
         * wc_RsaSSL_Verify writes to this buffer; it does not use an
         * internal buffer or return a pointer into the key structure. */
        uint8_t  out[WP11_RSA4096_BYTES];
        word32   outlen = (word32)sizeof(out);

        if (k->key_type != WP11_SOFT_KEY_RSA) {
            return -1;
        }
        ret = wc_RsaSSL_Verify(sig, (word32)siglen, out, outlen, &k->rsa);
        if (ret < 0) {
            soft_zero(out, sizeof(out));
            return -1;
        }
        if ((size_t)ret != inlen || memcmp(out, in, inlen) != 0) {
            soft_zero(out, sizeof(out));
            return -1;
        }
        soft_zero(out, sizeof(out));
        return 0;
    }

    if (mechanism == SOFT_CKM_EDDSA) {
        if (k->key_type != WP11_SOFT_KEY_ED25519) {
            return -1;
        }
        /* Ed25519 verify takes the full message (not a pre-hash).
         * wc_ed25519_verify_msg hashes internally with SHA-512.
         * stat is set to 1 on a valid signature, 0 on invalid. */
        if (!WP11_FITS_U32(inlen))  return -1;
        if (!WP11_FITS_U32(siglen)) return -1;
        stat = 0;
        ret = wc_ed25519_verify_msg(sig, (word32)siglen,
                                    in,  (word32)inlen,
                                    &stat, &k->ed25519);
        if (ret != 0 || stat != 1) {
            return -1;
        }
        return 0;
    }

    return -1;
}

/* -------------------------------------------------------------------------
 * Decrypt
 * ---------------------------------------------------------------------- */

static int soft_decrypt(const wp11_key_handle_t *handle,
                        uint32_t                 mechanism,
                        const uint8_t           *ct,    size_t  ctlen,
                        uint8_t                 *pt,    size_t *ptlen)
{
    wp11_soft_key_t *k;
    int ret;

    if (handle == NULL || handle->priv == NULL ||
        ct == NULL || pt == NULL || ptlen == NULL) {
        return -1;
    }

    k = (wp11_soft_key_t *)handle->priv;

    if (mechanism == SOFT_CKM_RSA_PKCS) {
        if (k->key_type != WP11_SOFT_KEY_RSA) {
            return -1;
        }
        /* wolfP11-jhb3: guard both operands before the word32 cast. */
        if (!WP11_FITS_U32(ctlen) || !WP11_FITS_U32(*ptlen)) return -1;
        ret = wc_RsaPrivateDecrypt(ct, (word32)ctlen,
                                   pt, (word32)*ptlen,
                                   &k->rsa);
        if (ret < 0) {
            return -1;
        }
        *ptlen = (size_t)ret;
        return 0;
    }

    return -1;
}

/* -------------------------------------------------------------------------
 * Derive (ECDH key agreement)
 * ---------------------------------------------------------------------- */

static int soft_derive(const wp11_key_handle_t *handle,
                       uint32_t                 mechanism,
                       const uint8_t           *peer_pub,    size_t  peer_pub_len,
                       uint8_t                 *shared,      size_t *sharedlen)
{
    wp11_soft_key_t *k;
    ecc_key          peer_ecc;
    word32           wlen;
    int              ret;
    int              peer_init = 0;

    if (handle == NULL || handle->priv == NULL ||
        peer_pub == NULL || shared == NULL || sharedlen == NULL) {
        return -1;
    }

    k = (wp11_soft_key_t *)handle->priv;

    if (mechanism != SOFT_CKM_ECDH1_DERIVE) {
        return -1;
    }
    if (k->key_type != WP11_SOFT_KEY_ECC) {
        return -1;
    }

    /* wc_ecc_set_rng: required before wc_ecc_shared_secret.  Keys imported
     * from DER (wp11_soft_key_new_from_der ECC path) do not call this during
     * import, so we call it here for both generated and imported keys. */
    if (wc_ecc_set_rng(&k->ecc, &k->rng) != 0) {
        return -1;
    }

    if (wc_ecc_init(&peer_ecc) != 0) {
        return -1;
    }
    peer_init = 1;

    /* wolfP11-0br: guard the size_t->word32 narrowing cast.  EC uncompressed
     * points are 65 bytes (P-256) or 97 bytes (P-384), so UINT32_MAX is
     * unreachable in practice, but the guard makes the assumption explicit. */
    if (!WP11_FITS_U32(peer_pub_len)) {
        wc_ecc_free(&peer_ecc);
        return -1;
    }
    ret = wc_ecc_import_x963(peer_pub, (word32)peer_pub_len, &peer_ecc);
    if (ret != 0) {
        wc_ecc_free(&peer_ecc);
        return -1;
    }

    if (!WP11_FITS_U32(*sharedlen)) {
        wc_ecc_free(&peer_ecc);
        return -1;
    }
    wlen = (word32)*sharedlen;
    ret = wc_ecc_shared_secret(&k->ecc, &peer_ecc, shared, &wlen);
    wc_ecc_free(&peer_ecc);
    (void)peer_init;
    if (ret != 0) {
        return -1;
    }
    *sharedlen = (size_t)wlen;
    return 0;
}

/* -------------------------------------------------------------------------
 * Key lifecycle -- backend ops table wrapper
 * ---------------------------------------------------------------------- */

/* wolfP11-be5: wrap wp11_soft_key_free for the ops table.  The ops table
 * uses a void * parameter; this shim handles the cast so call sites in
 * wp11_pkcs11.c do not need to know the concrete key type. */
static void soft_free_key_priv(void *key_priv)
{
    wp11_soft_key_free((wp11_soft_key_t *)key_priv);
}

/* -------------------------------------------------------------------------
 * Backend ops table
 * ---------------------------------------------------------------------- */

const wp11_backend_ops_t wp11_backend_soft_ops = {
    WP11_BACKEND_SOFT,
    soft_sign,
    soft_verify,
    soft_decrypt,
    soft_derive,
    soft_free_key_priv,
};

/* -------------------------------------------------------------------------
 * Load from existing DER (for persistent soft token)
 * ---------------------------------------------------------------------- */

/* Create a soft key from an existing DER-encoded private key.
 * key_type: WP11_KEY_TYPE_EC (1) or WP11_KEY_TYPE_RSA (0).
 * For RSA, wc_RsaSetRNG is called immediately so blinding is operational.
 * Returns NULL on any failure. */
wp11_soft_key_t *wp11_soft_key_new_from_der(const uint8_t *der, size_t derlen,
                                             int key_type)
{
    wp11_soft_key_t *k;
    word32 idx = 0;

    if (der == NULL || derlen == 0) return NULL;
    /* wolfP11-366o: guard the size_t -> word32 narrowing cast applied below
     * in wc_EccPrivateKeyDecode / wc_RsaPrivateKeyDecode.  In practice DER
     * keys are kilobytes; the guard makes the assumption explicit and
     * consistent with the pattern used elsewhere in the codebase. */
    if (derlen > (size_t)UINT32_MAX) return NULL;

    k = (wp11_soft_key_t *)calloc(1, sizeof(*k));
    if (k == NULL) return NULL;

    if (wc_InitRng(&k->rng) != 0) { free(k); return NULL; }

    if (key_type == 1 /* WP11_KEY_TYPE_EC */) {
        if (wc_ecc_init(&k->ecc) != 0) {
            wc_FreeRng(&k->rng); free(k); return NULL;
        }
        if (wc_EccPrivateKeyDecode(der, &idx, &k->ecc, (word32)derlen) != 0) {
            wc_ecc_free(&k->ecc); wc_FreeRng(&k->rng); free(k); return NULL;
        }
        /* wolfP11-r3o0: reject trailing garbage after the parsed key.
         * wc_EccPrivateKeyDecode advances idx to the end of the DER structure
         * it consumed.  If idx < derlen, the buffer contains extra bytes beyond
         * the key -- likely a buffer construction bug in the caller.  Reject
         * to avoid silently accepting malformed input. */
        if (idx != (word32)derlen) {
            wc_ecc_free(&k->ecc); wc_FreeRng(&k->rng); free(k); return NULL;
        }
        k->key_type = WP11_SOFT_KEY_ECC;
    } else /* WP11_KEY_TYPE_RSA */ {
        if (wc_InitRsaKey(&k->rsa, NULL) != 0) {
            wc_FreeRng(&k->rng); free(k); return NULL;
        }
        if (wc_RsaPrivateKeyDecode(der, &idx, &k->rsa, (word32)derlen) != 0) {
            wc_FreeRsaKey(&k->rsa); wc_FreeRng(&k->rng); free(k); return NULL;
        }
        /* wolfP11-r3o0: same trailing-garbage check as the ECC path above. */
        if (idx != (word32)derlen) {
            wc_FreeRsaKey(&k->rsa); wc_FreeRng(&k->rng); free(k); return NULL;
        }
        /* RSA blinding requires the RNG stored in the key (see wolfP11-5l2) */
        if (wc_RsaSetRNG(&k->rsa, &k->rng) != 0) {
            wc_FreeRsaKey(&k->rsa); wc_FreeRng(&k->rng); free(k); return NULL;
        }
        k->key_type = WP11_SOFT_KEY_RSA;
    }

    k->initialized = 1;
    return k;
}

/* Export the private key as DER for keystore save operations.
 * ECC: SEC1 (RFC 5915); RSA: PKCS#1 (RFC 3447).
 * Returns bytes written on success, negative on error. */
int wp11_soft_key_export_priv_der(wp11_soft_key_t *key,
                                   uint8_t *buf, uint32_t buflen)
{
    if (key == NULL || !key->initialized || buf == NULL) return -1;
    if (key->key_type == WP11_SOFT_KEY_ECC) {
        return wc_EccKeyToDer(&key->ecc, buf, buflen);
    }
    if (key->key_type == WP11_SOFT_KEY_RSA) {
        return wc_RsaKeyToDer(&key->rsa, buf, buflen);
    }
    return -1;
}

/* RSA PKCS#1 v1.5 public-key encryption.
 * If out is NULL, writes the required output length to *outlen and returns 0.
 * Otherwise encrypts in[0..inlen) into out[]; *outlen must be >= modulus size.
 * Returns 0 on success, negative on error. */
int wp11_soft_key_rsa_encrypt(wp11_soft_key_t *key,
                               const uint8_t *in, word32 inlen,
                               uint8_t *out, word32 *outlen)
{
    word32 modsz;
    int    ret;

    if (key == NULL || !key->initialized || outlen == NULL) return -1;
    if (key->key_type != WP11_SOFT_KEY_RSA) return -1;

    {
        /* wc_RsaEncryptSize returns int; negative means invalid key. */
        int enc_sz = wc_RsaEncryptSize(&key->rsa);
        if (enc_sz <= 0) return -1;
        modsz = (word32)enc_sz;
    }

    if (out == NULL) {
        *outlen = modsz;
        return 0;
    }

    if (*outlen < modsz) return -1;
    if (in == NULL) return -1;

    ret = wc_RsaPublicEncrypt(in, inlen, out, *outlen, &key->rsa, &key->rng);
    if (ret < 0) return -1;
    *outlen = (word32)ret;
    return 0;
}

/* wolfP11-lf4o: WP11_OAEP_LABEL_MAX is defined in wolfp11/wp11_backend.h.
 * Do not redefine it here.  The value (64 bytes) is a deliberate policy limit:
 * PKCS#11 CK_RSA_PKCS_OAEP_PARAMS does not cap label size; wolfCrypt can
 * handle arbitrarily long labels (cost scales with hash, not label size).
 * 64 bytes covers all realistic uses: 32-byte SHA-256 digest labels, UUIDs
 * (36 chars), and typical application identifiers.  Callers needing larger
 * labels must raise the constant in wp11_backend.h and re-audit stack frames. */

int wp11_soft_key_rsa_oaep_encrypt(wp11_soft_key_t *key,
                                    const uint8_t *in, word32 inlen,
                                    uint8_t *out, word32 *outlen,
                                    int hash_type, int mgf,
                                    const uint8_t *label, word32 label_len)
{
    int     ret;
    int     enc_sz;
    uint8_t label_buf[WP11_OAEP_LABEL_MAX];
    word32  label_copy_len = 0;
    uint8_t *label_ptr     = NULL;

    if (key == NULL || !key->initialized || outlen == NULL) return -1;
    if (key->key_type != WP11_SOFT_KEY_RSA) return -1;

    enc_sz = wc_RsaEncryptSize(&key->rsa);
    if (enc_sz <= 0) return -1;

    if (out == NULL) {
        *outlen = (word32)enc_sz;
        return 0;
    }
    if (*outlen < (word32)enc_sz || in == NULL) return -1;

    if (label != NULL && label_len > 0) {
        if (label_len > WP11_OAEP_LABEL_MAX) return -1;
        memcpy(label_buf, label, label_len);
        label_ptr      = label_buf;
        label_copy_len = label_len;
    }

    ret = wc_RsaPublicEncrypt_ex(in, inlen, out, *outlen, &key->rsa, &key->rng,
                                  WC_RSA_OAEP_PAD, (enum wc_HashType)hash_type,
                                  mgf, label_ptr, label_copy_len);
    if (ret < 0) return -1;
    *outlen = (word32)ret;
    return 0;
}

int wp11_soft_key_rsa_oaep_decrypt(wp11_soft_key_t *key,
                                    const uint8_t *in, word32 inlen,
                                    uint8_t *out, word32 outbuflen, word32 *outlen,
                                    int hash_type, int mgf,
                                    const uint8_t *label, word32 label_len)
{
    int     ret;
    int     enc_sz;
    uint8_t label_buf[WP11_OAEP_LABEL_MAX];
    word32  label_copy_len = 0;
    uint8_t *label_ptr     = NULL;

    if (key == NULL || !key->initialized || outlen == NULL) return -1;
    if (key->key_type != WP11_SOFT_KEY_RSA) return -1;

    enc_sz = wc_RsaEncryptSize(&key->rsa);
    if (enc_sz <= 0) return -1;

    if (out == NULL) {
        /* Size query: worst-case plaintext length is the modulus size */
        *outlen = (word32)enc_sz;
        return 0;
    }
    if (in == NULL) return -1;

    if (label != NULL && label_len > 0) {
        if (label_len > WP11_OAEP_LABEL_MAX) return -1;
        memcpy(label_buf, label, label_len);
        label_ptr      = label_buf;
        label_copy_len = label_len;
    }

    ret = wc_RsaPrivateDecrypt_ex(in, inlen, out, outbuflen, &key->rsa,
                                   WC_RSA_OAEP_PAD, (enum wc_HashType)hash_type,
                                   mgf, label_ptr, label_copy_len);
    if (ret < 0) return -1;
    *outlen = (word32)ret;
    return 0;
}

/* Export RSA public key components (modulus N and public exponent E).
 * Both output buffers must be large enough for the key size (512 bytes
 * covers RSA-4096).  On success the actual sizes are written to nlen, elen.
 * Returns 0 on success, negative on failure or for non-RSA keys. */
#ifdef WC_RSA_PSS
/* Sign a pre-computed digest using RSA-PSS.
 * digest/digest_len: pre-hashed message (caller computes the hash).
 * sig/siglen: output buffer and its size; updated to actual bytes written.
 * If sig is NULL, writes the modulus size to *siglen and returns 0 (size query).
 * Returns 0 on success, -1 on error. */
int wp11_soft_key_rsa_pss_sign(wp11_soft_key_t *key,
                                const uint8_t *digest, word32 digest_len,
                                uint8_t *sig, word32 *siglen,
                                int hash_type, int mgf, int salt_len)
{
    int    ret;
    int    enc_sz;

    if (key == NULL || !key->initialized || siglen == NULL) return -1;
    if (key->key_type != WP11_SOFT_KEY_RSA) return -1;

    enc_sz = wc_RsaEncryptSize(&key->rsa);
    if (enc_sz <= 0) return -1;

    if (sig == NULL) {
        *siglen = (word32)enc_sz;
        return 0;
    }
    if (digest == NULL || *siglen < (word32)enc_sz) return -1;

    ret = wc_RsaPSS_Sign_ex(digest, digest_len, sig, *siglen,
                              (enum wc_HashType)hash_type, mgf,
                              salt_len, &key->rsa, &key->rng);
    if (ret < 0) return -1;
    *siglen = (word32)ret;
    return 0;
}

/* Verify an RSA-PSS signature against a pre-computed digest.
 * sig/siglen: PSS signature.
 * digest/digest_len: message hash to verify against.
 * Returns 0 on success (verified), -1 on failure. */
int wp11_soft_key_rsa_pss_verify(wp11_soft_key_t *key,
                                  const uint8_t *sig, word32 siglen,
                                  const uint8_t *digest, word32 digest_len,
                                  int hash_type, int mgf, int salt_len)
{
    int     ret;
    int     enc_sz;
    uint8_t scratch[WP11_RSA4096_BYTES]; /* RSA-4096 modulus size upper bound */
    word32  scratch_sz;

    if (key == NULL || !key->initialized) return -1;
    if (key->key_type != WP11_SOFT_KEY_RSA) return -1;
    if (sig == NULL || digest == NULL) return -1;

    enc_sz = wc_RsaEncryptSize(&key->rsa);
    if (enc_sz <= 0 || (word32)enc_sz > sizeof(scratch)) return -1;
    scratch_sz = (word32)enc_sz;

    /* wc_RsaPSS_VerifyCheck_ex does not exist; compose manually:
     * Verify_ex decrypts and strips the PSS mask, returning the EM block.
     * CheckPadding_ex then validates the internal hash against digest. */
    ret = wc_RsaPSS_Verify_ex(sig, siglen, scratch, scratch_sz,
                               (enum wc_HashType)hash_type, mgf,
                               salt_len, &key->rsa);
    if (ret >= 0) {
        ret = wc_RsaPSS_CheckPadding_ex(digest, digest_len,
                                         scratch, (word32)ret,
                                         (enum wc_HashType)hash_type,
                                         salt_len, enc_sz * 8);
    }
    memset(scratch, 0, scratch_sz);
    if (ret < 0) return -1;
    return 0;
}
#endif /* WC_RSA_PSS */

int wp11_soft_key_export_rsa_pub(wp11_soft_key_t *key,
                                  uint8_t *n, word32 *nlen,
                                  uint8_t *e, word32 *elen)
{
    if (key == NULL || !key->initialized) return -1;
    if (key->key_type != WP11_SOFT_KEY_RSA) return -1;
    return wc_RsaFlattenPublicKey(&key->rsa, e, elen, n, nlen);
}

#ifdef WOLFP11_CFG_TEST
/* Export the Ed25519 public key as a 32-byte raw key for test oracle
 * cross-validation.  Declared in wolfp11/wp11_soft_key.h under
 * WOLFP11_CFG_TEST.  Only valid for ED25519 keys; returns -1 otherwise.
 * *outlen must be at least 32 on entry; updated to 32 on success. */
int wp11_soft_key_test_export_ed25519_pub(wp11_soft_key_t *key,
                                           uint8_t *out, word32 *outlen)
{
    if (key == NULL || out == NULL || outlen == NULL || !key->initialized) {
        return -1;
    }
    if (key->key_type != WP11_SOFT_KEY_ED25519) {
        return -1;
    }
    return wc_ed25519_export_public(&key->ed25519, out, outlen);
}

/* wolfP11-uf1: export the EC public key in X9.62 uncompressed format for
 * ECDH symmetry oracle tests.  Declared in wolfp11/wp11_soft_key.h under
 * WOLFP11_CFG_TEST.  Only valid for ECC keys; returns -1 for RSA keys.
 * *outlen must be at least 65 (P-256) or 97 (P-384) on entry; updated on
 * success. Returns 0 on success, negative on error. */
int wp11_soft_key_test_export_pub_x963(wp11_soft_key_t *key,
                                        uint8_t *out, word32 *outlen)
{
    if (key == NULL || out == NULL || outlen == NULL || !key->initialized) {
        return -1;
    }
    if (key->key_type != WP11_SOFT_KEY_ECC) {
        return -1;
    }
    return wc_ecc_export_x963(&key->ecc, out, outlen);
}

/* wolfP11-56f: export the private key DER for test oracle cross-validation.
 * Declared in wolfp11/wp11_soft_key.h under WOLFP11_CFG_TEST.
 *
 * Returns bytes written on success (positive), negative on wolfCrypt error.
 * The output format is:
 *   ECC: SEC1 (RFC 5915) DER -- compatible with wc_EccPrivateKeyDecode
 *   RSA: PKCS#1 (RFC 3447) DER -- compatible with wc_RsaPrivateKeyDecode
 *
 * This function MUST NOT be called from production code paths.  It is here
 * only so the test file can obtain an independent wolfCrypt key object from
 * the same key material, enabling sign-then-oracle-verify tests. */
int wp11_soft_key_test_export_priv_der(wp11_soft_key_t *key,
                                       uint8_t *out, word32 outlen)
{
    if (key == NULL || out == NULL || !key->initialized) return -1;

    if (key->key_type == WP11_SOFT_KEY_ECC) {
        return wc_EccKeyToDer(&key->ecc, out, outlen);
    }
    if (key->key_type == WP11_SOFT_KEY_RSA) {
        return wc_RsaKeyToDer(&key->rsa, out, outlen);
    }
    return -1;
}
#endif /* WOLFP11_CFG_TEST */
