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
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <string.h>
#include <stdlib.h>

/* Mechanism values (subset of CKM_* from PKCS#11 2.40) */
#define SOFT_CKM_RSA_PKCS      (0x00000001UL)
#define SOFT_CKM_ECDSA         (0x00001041UL)
#define SOFT_CKM_ECDSA_SHA256  (0x00001044UL)
#define SOFT_CKM_ECDH1_DERIVE  (0x00001050UL)

/* -------------------------------------------------------------------------
 * Key type tags
 * ---------------------------------------------------------------------- */

#define WP11_SOFT_KEY_ECC  1
#define WP11_SOFT_KEY_RSA  2

/* -------------------------------------------------------------------------
 * Soft key structure
 * ---------------------------------------------------------------------- */

/* 'struct wp11_soft_key' is forward-declared in wolfp11/wp11_soft_key.h
 * so that callers can hold an opaque wp11_soft_key_t * without seeing
 * the internal wolfCrypt state. */
struct wp11_soft_key {
    int key_type;
    ecc_key ecc;
    RsaKey  rsa;
    WC_RNG  rng;
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
wp11_soft_key_t *wp11_soft_key_new_ecc_p384(void)
{
    wp11_soft_key_t *k = (wp11_soft_key_t *)calloc(1, sizeof(*k));
    if (k == NULL) return NULL;

    if (wc_InitRng(&k->rng) != 0) { free(k); return NULL; }

    if (wc_ecc_init(&k->ecc) != 0) {
        wc_FreeRng(&k->rng); free(k); return NULL;
    }

    if (wc_ecc_make_key_ex(&k->rng, 48, &k->ecc, ECC_SECP384R1) != 0) {
        wc_ecc_free(&k->ecc); wc_FreeRng(&k->rng); free(k); return NULL;
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
 * Supports any power-of-2 modulus size wolfCrypt accepts (e.g. 1024, 2048).
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

/* Increment reference count on a shared soft key.  Returns key (for chaining).
 * Used by C_GenerateKeyPair to share one wp11_soft_key_t between the public
 * and private key objects without copying the key material. */
wp11_soft_key_t *wp11_soft_key_ref(wp11_soft_key_t *key)
{
    if (key != NULL) {
        /* RELAXED: caller already holds a valid reference so the key is
         * alive; no ordering constraint needed for the increment itself. */
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
        if (ret != 0) {
            return -1;
        }
        wlen = (word32)*siglen;
        ret = wc_ecc_sign_hash(digest, WC_SHA256_DIGEST_SIZE,
                               sig, &wlen, &k->rng, &k->ecc);
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
        wlen = (word32)*siglen;
        ret = wc_RsaSSL_Sign(in, (word32)inlen, sig, wlen, &k->rsa, &k->rng);
        if (ret < 0) {
            return -1;
        }
        *siglen = (size_t)ret;
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
        if (wc_InitSha256(&sha) != 0) {
            return -1;
        }
        ret = wc_Sha256Update(&sha, in, (word32)inlen);
        if (ret == 0) {
            ret = wc_Sha256Final(&sha, digest);
        }
        wc_Sha256Free(&sha);
        if (ret != 0) {
            return -1;
        }
        stat = 0;
        ret = wc_ecc_verify_hash(sig, (word32)siglen,
                                 digest, WC_SHA256_DIGEST_SIZE,
                                 &stat, &k->ecc);
        if (ret != 0 || stat != 1) {
            return -1;
        }
        return 0;
    }

    if (mechanism == SOFT_CKM_RSA_PKCS) {
        /* 512 bytes covers RSA-4096: PKCS#1 v1.5 unpadded output max is
         * key_bytes - 11 (mandatory padding) = 512 - 11 = 501 bytes.
         * wc_RsaSSL_Verify writes to this buffer; it does not use an
         * internal buffer or return a pointer into the key structure. */
        uint8_t  out[512];
        word32   outlen = (word32)sizeof(out);

        if (k->key_type != WP11_SOFT_KEY_RSA) {
            return -1;
        }
        ret = wc_RsaSSL_Verify(sig, (word32)siglen, out, outlen, &k->rsa);
        if (ret < 0) {
            return -1;
        }
        if ((size_t)ret != inlen || memcmp(out, in, inlen) != 0) {
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
    if (peer_pub_len > (size_t)UINT32_MAX) {
        wc_ecc_free(&peer_ecc);
        return -1;
    }
    ret = wc_ecc_import_x963(peer_pub, (word32)peer_pub_len, &peer_ecc);
    if (ret != 0) {
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
        k->key_type = WP11_SOFT_KEY_ECC;
    } else /* WP11_KEY_TYPE_RSA */ {
        if (wc_InitRsaKey(&k->rsa, NULL) != 0) {
            wc_FreeRng(&k->rng); free(k); return NULL;
        }
        if (wc_RsaPrivateKeyDecode(der, &idx, &k->rsa, (word32)derlen) != 0) {
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

    modsz = (word32)wc_RsaEncryptSize(&key->rsa);

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

/* Export RSA public key components (modulus N and public exponent E).
 * Both output buffers must be large enough for the key size (512 bytes
 * covers RSA-4096).  On success the actual sizes are written to nlen, elen.
 * Returns 0 on success, negative on failure or for non-RSA keys. */
int wp11_soft_key_export_rsa_pub(wp11_soft_key_t *key,
                                  uint8_t *n, word32 *nlen,
                                  uint8_t *e, word32 *elen)
{
    if (key == NULL || !key->initialized) return -1;
    if (key->key_type != WP11_SOFT_KEY_RSA) return -1;
    return wc_RsaFlattenPublicKey(&key->rsa, e, elen, n, nlen);
}

#ifdef WOLFP11_CFG_TEST
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
