/* wp11_backend_wolfhsm.c -- wolfP11 wolfHSM server backend
 *
 * Routes PKCS#11 sign, verify, decrypt, and ECDH-derive operations to a
 * wolfHSM server via the wolfHSM client API.  Keys are pre-provisioned on
 * the server and referenced by their server-side key ID (whKeyId).
 *
 * Key lifecycle:
 *   - Keys are provisioned on the wolfHSM server out-of-band (e.g., by the
 *     wolfHSM provisioning CLI, or by a previous C_GenerateKeyPair call that
 *     is not yet implemented in this backend).
 *   - wp11_wolfhsm_alloc_key_priv() creates the per-key struct that stores
 *     the server key ID.  It is called by the PKCS#11 layer when setting up
 *     a slot that uses this backend.
 *   - free_key_priv() frees the local struct.  It does NOT evict the key
 *     from the server, because the key is assumed to be NVM-persistent.
 *
 * RSA padding:
 *   wolfHSM's wh_Client_RsaFunction performs the raw RSA modular
 *   exponentiation (m^e mod n or m^d mod n).  PKCS#1 v1.5 padding must be
 *   applied (for sign) or stripped (for verify/decrypt) by the client.  The
 *   helpers pkcs1_v15_pad_sign, pkcs1_v15_unpad_verify, and
 *   pkcs1_v15_unpad_decrypt implement these operations.
 *
 * ECC operations:
 *   wh_Client_EccSign, wh_Client_EccVerify, and wh_Client_EccSharedSecret
 *   handle the server round-trip directly.  If the key has WH_KEYID_ERASED
 *   they auto-import; since we always set key_id, the server uses the cached
 *   key.  The peer public key for ECDH is always imported temporarily
 *   (key_id == WH_KEYID_ERASED on the peer ecc_key struct).
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include "wolfp11/wp11_backend.h"
#include "wolfp11/wp11_settings.h"
/* wolfP11-fnw: include wp11_keystore.h for WP11_KEY_TYPE_* so the compiler
 * enforces value consistency between backends at build time instead of
 * relying on comments.  The header pulls in only stdint.h and stddef.h. */
#include "wolfp11/wp11_keystore.h"

#ifdef WOLFP11_CFG_WOLFHSM_BACKEND

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include <wolfhsm/wh_client.h>
#include <wolfhsm/wh_client_crypto.h>
#include <wolfhsm/wh_keyid.h>
#include <wolfhsm/wh_error.h>

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* CKM_* mechanism values from PKCS#11 spec.
 * Raw numeric values; no pkcs11.h dependency in the backend. */
#define HSM_CKM_RSA_PKCS      0x00000001UL
#define HSM_CKM_ECDSA         0x00001041UL
#define HSM_CKM_ECDSA_SHA256  0x00001044UL
#define HSM_CKM_ECDH1_DERIVE  0x00001050UL

/* Maximum RSA key size this backend supports.
 * RSA-4096 produces 512-byte signatures and ciphertexts. */
#define HSM_RSA_MAX_BYTES  512u

/* -------------------------------------------------------------------------
 * wolfHSM -> backend error code translation
 *
 * Maps wolfHSM return codes (from wh_error.h) to WP11_BACKEND_ERR_* values.
 * Only codes that arise from server round-trip calls are listed explicitly;
 * local init/arg-validation failures fall through to WP11_BACKEND_ERR_GENERAL.
 * ---------------------------------------------------------------------- */

static int wh_err_to_backend_err(int wh_ret)
{
    switch (wh_ret) {
    case WH_ERROR_NOTREADY:  return WP11_BACKEND_ERR_NOT_READY;
    case WH_ERROR_TIMEOUT:   return WP11_BACKEND_ERR_TIMEOUT;
    case WH_ERROR_NOTFOUND:  return WP11_BACKEND_ERR_KEY_NOT_FOUND;
    case WH_ERROR_USAGE:     return WP11_BACKEND_ERR_USAGE;
    case WH_ERROR_NOTIMPL:   /* FALLTHROUGH */
    case WH_ERROR_NOHANDLER: return WP11_BACKEND_ERR_NOT_IMPL;
    default:                  return WP11_BACKEND_ERR_GENERAL;
    }
}

/* -------------------------------------------------------------------------
 * Factory
 * ---------------------------------------------------------------------- */

/* wolfP11-grz: key_size is caller-supplied and is NOT validated against the
 * actual RSA modulus size on the wolfHSM server.  No round-trip is made here
 * to confirm the key exists or to query its size.
 *
 * Design rationale: a wrong key_size causes pkcs1_v15_pad_sign to pad to the
 * wrong block length.  The server then rejects the RsaFunction call because
 * the input length does not match the key's modulus size.  The failure is
 * immediate and deterministic -- no security breach, no silent corruption.
 * Adding a wh_Client_RsaGetSize round-trip here would add per-key setup
 * latency and wolfHSM API complexity for a provisioning error that already
 * surfaces clearly at first use.  Key-size correctness is the caller's
 * responsibility, enforced by the server's length check. */
wp11_wolfhsm_key_priv_t *wp11_wolfhsm_alloc_key_priv(void    *ctx,
                                                       uint16_t key_id,
                                                       int      key_type,
                                                       uint16_t key_size)
{
    wp11_wolfhsm_key_priv_t *kp;

    if (ctx == NULL) return NULL;

    kp = (wp11_wolfhsm_key_priv_t *)malloc(sizeof(*kp));
    if (kp == NULL) return NULL;

    kp->ctx      = ctx;
    kp->key_id   = key_id;
    kp->key_type = key_type;
    kp->key_size = key_size;
    return kp;
}

/* -------------------------------------------------------------------------
 * Internal helper: get and validate key private state
 * ---------------------------------------------------------------------- */

static const wp11_wolfhsm_key_priv_t *hsm_entry(const wp11_key_handle_t *h)
{
    if (h == NULL || h->priv == NULL) return NULL;
    return (const wp11_wolfhsm_key_priv_t *)h->priv;
}

/* -------------------------------------------------------------------------
 * PKCS#1 v1.5 padding helpers (sign / verify / decrypt paths)
 * ---------------------------------------------------------------------- */

/* Apply block-type 01 (signing) padding.
 * out[0..key_size-1] receives: 00 01 FF...FF 00 in[0..in_len-1]
 * Returns 0 on success, -1 if in_len is too large for key_size. */
static int pkcs1_v15_pad_sign(const uint8_t *in, size_t in_len,
                               uint8_t *out, size_t key_size)
{
    size_t ps_len;

    /* PKCS#1 v1.5 minimum overhead: 00 01 [PS>=8] 00 = 11 bytes */
    if (in_len > key_size - 11u) return -1;

    ps_len = key_size - in_len - 3u;   /* guaranteed >= 8 */

    out[0] = 0x00u;
    out[1] = 0x01u;
    memset(out + 2u, 0xFFu, ps_len);
    out[2u + ps_len] = 0x00u;
    memcpy(out + 3u + ps_len, in, in_len);
    return 0;
}

/* Strip block-type 01 padding from buf[0..buf_len-1].
 * On success sets *msg and *msg_len to the embedded message within buf.
 * Returns 0 on success, -1 on malformed padding.
 *
 * wolfP11-y0n: The caller passes the output of wh_Client_RsaFunction with
 * RSA_PUBLIC_DECRYPT.  That function wraps wc_RsaFunction -> wc_RsaFunctionSync,
 * which calls mp_to_unsigned_bin_len_ct(tmp, out, keyLen).  That function
 * always writes exactly keyLen bytes, left-padding with 0x00 as needed.  As a
 * result, the full PKCS#1 v1.5 block (including the leading 0x00 byte) is
 * always present in buf, and the buf[0] == 0x00 check below is guaranteed to
 * find the expected byte.  This was confirmed by reading wolfssl's rsa.c
 * (wc_RsaFunctionSync, line 2807 in the version current when this was written). */
static int pkcs1_v15_unpad_verify(const uint8_t *buf, size_t buf_len,
                                   const uint8_t **msg, size_t *msg_len)
{
    size_t i;

    if (buf_len < 11u) return -1;
    if (buf[0] != 0x00u || buf[1] != 0x01u) return -1;

    for (i = 2u; i < buf_len && buf[i] == 0xFFu; i++) { /* skip PS */ }

    /* PS must be >= 8 bytes; buf[i] must be 0x00 separator */
    if (i < 10u || i >= buf_len || buf[i] != 0x00u) return -1;

    *msg     = buf + i + 1u;
    *msg_len = buf_len - i - 1u;
    return 0;
}

/* Strip block-type 02 padding from buf[0..buf_len-1] and copy plaintext
 * into pt[0..*ptlen-1].  Updates *ptlen to the actual plaintext length.
 * Returns 0 on success, -1 on malformed padding or insufficient output.
 *
 * wolfP11-y0n: Same guarantee as pkcs1_v15_unpad_verify -- the wolfHSM server
 * calls wc_RsaFunctionSync -> mp_to_unsigned_bin_len_ct(tmp, out, keyLen),
 * which always writes exactly keyLen bytes.  The leading 0x00 byte of the
 * type-02 PKCS#1 block is always present in buf.
 *
 * wolfP11-i3c: The separator search is constant-time -- the loop runs for
 * exactly buf_len-2 iterations regardless of where the 0x00 separator falls.
 * The original early-exit loop leaked the separator index via iteration count,
 * creating a client-side timing channel.  The fix uses branchless multiplicative
 * select to record the first valid separator without exiting early.
 *
 * Scope of fix: this eliminates the local timing channel.  Full Bleichenbacher
 * oracle resistance also requires the RSA private operation itself to be
 * indistinguishable between valid and invalid ciphertexts; that property is
 * provided by the wolfHSM server (wc_RsaFunction uses blinding internally). */
static int pkcs1_v15_unpad_decrypt(const uint8_t *buf, size_t buf_len,
                                    uint8_t *pt, size_t *ptlen)
{
    size_t   i;
    size_t   sep_idx  = buf_len;  /* sentinel: "not found yet" */
    size_t   plain_len;
    unsigned bad      = 0u;

    if (buf_len < 11u) return -1;

    /* buf[0] and buf[1] are public structure -- branch is fine */
    bad |= (unsigned)(buf[0] != 0x00u);
    bad |= (unsigned)(buf[1] != 0x02u);

    /* Scan every byte to find the first 0x00 at index >= 10.
     * Loop count is fixed; no early exit.  Branchless select via
     * multiplicative idiom: sep_idx = hit ? i : sep_idx. */
    for (i = 2u; i < buf_len; i++) {
        unsigned is_zero   = (unsigned)(buf[i] == 0x00u);
        unsigned valid_pos = (unsigned)(i >= 10u);
        unsigned not_found = (unsigned)(sep_idx >= buf_len);
        unsigned hit       = is_zero & valid_pos & not_found;
        sep_idx = (size_t)(hit * i) + (size_t)((1u - hit) * sep_idx);
    }

    bad |= (unsigned)(sep_idx >= buf_len);  /* separator never found */

    if (bad) return -1;

    plain_len = buf_len - sep_idx - 1u;
    if (plain_len > *ptlen) return -1;

    memcpy(pt, buf + sep_idx + 1u, plain_len);
    *ptlen = plain_len;
    return 0;
}

/* -------------------------------------------------------------------------
 * hsm_sign
 *
 * Supports:
 *   HSM_CKM_ECDSA       -- raw ECDSA over a caller-supplied prehashed digest
 *   HSM_CKM_ECDSA_SHA256 -- ECDSA with local SHA-256 hash of input
 *   HSM_CKM_RSA_PKCS    -- RSA PKCS#1 v1.5 sign (local pad + server RSA)
 * ---------------------------------------------------------------------- */

static int hsm_sign(const wp11_key_handle_t *handle,
                    uint32_t                 mechanism,
                    const uint8_t           *in,    size_t  inlen,
                    uint8_t                 *sig,   size_t *siglen)
{
    const wp11_wolfhsm_key_priv_t *kp;
    int ret;

    if (sig == NULL || siglen == NULL || in == NULL) return -1;

    kp = hsm_entry(handle);
    if (kp == NULL) return -1;

    /* ---- ECC (ECDSA raw or with SHA-256) ---- */
    if (mechanism == HSM_CKM_ECDSA || mechanism == HSM_CKM_ECDSA_SHA256) {
        ecc_key        ecc;
        uint16_t       wlen;
        const uint8_t *hash;
        uint16_t       hash_len;
        uint8_t        digest[WC_SHA256_DIGEST_SIZE];

        if (kp->key_type != WP11_KEY_TYPE_EC) return -1;

        ret = wc_ecc_init(&ecc);
        if (ret != 0) return -1;

        ret = wh_Client_EccSetKeyId(&ecc, (whKeyId)kp->key_id);
        if (ret != 0) { wc_ecc_free(&ecc); return -1; }

        if (mechanism == HSM_CKM_ECDSA_SHA256) {
            wc_Sha256 sha;
            if (wc_InitSha256(&sha) != 0) { wc_ecc_free(&ecc); return -1; }
            ret = wc_Sha256Update(&sha, in, (word32)inlen);
            if (ret == 0) ret = wc_Sha256Final(&sha, digest);
            wc_Sha256Free(&sha);
            if (ret != 0) { wc_ecc_free(&ecc); return -1; }
            hash     = digest;
            hash_len = WC_SHA256_DIGEST_SIZE;
        } else {
            /* CKM_ECDSA: caller supplies the prehashed digest */
            if (inlen > (size_t)UINT16_MAX) { wc_ecc_free(&ecc); return -1; }
            hash     = in;
            hash_len = (uint16_t)inlen;
        }

        if (*siglen > (size_t)UINT16_MAX) { wc_ecc_free(&ecc); return -1; }
        wlen = (uint16_t)*siglen;
        ret  = wh_Client_EccSign((whClientContext *)kp->ctx, &ecc,
                                  hash, hash_len, sig, &wlen);
        wc_ecc_free(&ecc);
        if (ret != 0) return wh_err_to_backend_err(ret);
        *siglen = (size_t)wlen;
        return 0;
    }

    /* ---- RSA PKCS#1 v1.5 ---- */
    if (mechanism == HSM_CKM_RSA_PKCS) {
        RsaKey   rsa;
        uint8_t  padded[HSM_RSA_MAX_BYTES];
        uint16_t wlen;
        uint16_t key_bytes; /* modulus size in bytes */

        if (kp->key_type != WP11_KEY_TYPE_RSA) return -1;

        /* key_size is cached in key_priv; 0 means not set (error). */
        if (kp->key_size == 0u || kp->key_size > HSM_RSA_MAX_BYTES) return -1;
        key_bytes = kp->key_size;

        ret = wc_InitRsaKey(&rsa, NULL);
        if (ret != 0) return -1;

        ret = wh_Client_RsaSetKeyId(&rsa, (whNvmId)kp->key_id);
        if (ret != 0) { wc_FreeRsaKey(&rsa); return -1; }

        if (pkcs1_v15_pad_sign(in, inlen, padded, (size_t)key_bytes) != 0) {
            wc_FreeRsaKey(&rsa);
            return -1;
        }

        if (*siglen > (size_t)UINT16_MAX) { wc_FreeRsaKey(&rsa); return -1; }
        wlen = (uint16_t)*siglen;
        ret  = wh_Client_RsaFunction((whClientContext *)kp->ctx, &rsa,
                                      RSA_PRIVATE_ENCRYPT,
                                      padded, key_bytes,
                                      sig, &wlen);
        wc_FreeRsaKey(&rsa);
        /* wolfP11-hsm1: zero padded before returning -- it contains the
         * PKCS#1-padded private input, which is sensitive even though it's
         * not the raw key material. */
        memset(padded, 0, sizeof(padded));
        if (ret != 0) return wh_err_to_backend_err(ret);
        *siglen = (size_t)wlen;
        return 0;
    }

    return WP11_BACKEND_ERR_NOT_IMPL; /* unsupported mechanism */
}

/* -------------------------------------------------------------------------
 * hsm_verify
 *
 * Supports:
 *   HSM_CKM_ECDSA       -- raw ECDSA verify over a prehashed digest
 *   HSM_CKM_ECDSA_SHA256 -- ECDSA with local SHA-256 hash of input
 *   HSM_CKM_RSA_PKCS    -- RSA PKCS#1 v1.5 verify (server RSA + local unpad)
 * ---------------------------------------------------------------------- */

static int hsm_verify(const wp11_key_handle_t *handle,
                      uint32_t                 mechanism,
                      const uint8_t           *in,    size_t inlen,
                      const uint8_t           *sig,   size_t siglen)
{
    const wp11_wolfhsm_key_priv_t *kp;
    int ret;

    if (in == NULL || sig == NULL) return -1;

    kp = hsm_entry(handle);
    if (kp == NULL) return -1;

    /* ---- ECC ---- */
    if (mechanism == HSM_CKM_ECDSA || mechanism == HSM_CKM_ECDSA_SHA256) {
        ecc_key        ecc;
        int            stat;
        const uint8_t *hash;
        uint16_t       hash_len;
        uint8_t        digest[WC_SHA256_DIGEST_SIZE];

        if (kp->key_type != WP11_KEY_TYPE_EC) return -1;

        ret = wc_ecc_init(&ecc);
        if (ret != 0) return -1;

        ret = wh_Client_EccSetKeyId(&ecc, (whKeyId)kp->key_id);
        if (ret != 0) { wc_ecc_free(&ecc); return -1; }

        if (mechanism == HSM_CKM_ECDSA_SHA256) {
            wc_Sha256 sha;
            if (wc_InitSha256(&sha) != 0) { wc_ecc_free(&ecc); return -1; }
            ret = wc_Sha256Update(&sha, in, (word32)inlen);
            if (ret == 0) ret = wc_Sha256Final(&sha, digest);
            wc_Sha256Free(&sha);
            if (ret != 0) { wc_ecc_free(&ecc); return -1; }
            hash     = digest;
            hash_len = WC_SHA256_DIGEST_SIZE;
        } else {
            if (inlen > (size_t)UINT16_MAX) { wc_ecc_free(&ecc); return -1; }
            hash     = in;
            hash_len = (uint16_t)inlen;
        }

        if (siglen > (size_t)UINT16_MAX) { wc_ecc_free(&ecc); return -1; }
        stat = 0;
        ret  = wh_Client_EccVerify((whClientContext *)kp->ctx, &ecc,
                                    sig, (uint16_t)siglen,
                                    hash, hash_len,
                                    &stat);
        wc_ecc_free(&ecc);
        if (ret != 0) return wh_err_to_backend_err(ret);
        if (stat != 1) return WP11_BACKEND_ERR_SIG_INVALID;
        return 0;
    }

    /* ---- RSA PKCS#1 v1.5 ---- */
    if (mechanism == HSM_CKM_RSA_PKCS) {
        RsaKey         rsa;
        uint8_t        out[HSM_RSA_MAX_BYTES];
        uint16_t       wlen;
        const uint8_t *msg;
        size_t         msg_len;

        if (kp->key_type != WP11_KEY_TYPE_RSA) return -1;

        ret = wc_InitRsaKey(&rsa, NULL);
        if (ret != 0) return -1;

        ret = wh_Client_RsaSetKeyId(&rsa, (whNvmId)kp->key_id);
        if (ret != 0) { wc_FreeRsaKey(&rsa); return -1; }

        if (siglen > (size_t)UINT16_MAX) { wc_FreeRsaKey(&rsa); return -1; }
        wlen = (uint16_t)sizeof(out);
        ret  = wh_Client_RsaFunction((whClientContext *)kp->ctx, &rsa,
                                      RSA_PUBLIC_DECRYPT,
                                      sig, (uint16_t)siglen,
                                      out, &wlen);
        wc_FreeRsaKey(&rsa);
        if (ret != 0) return wh_err_to_backend_err(ret);

        /* Strip PKCS#1 v1.5 type-01 padding; compare with expected digest */
        if (pkcs1_v15_unpad_verify(out, (size_t)wlen, &msg, &msg_len) != 0)
            return WP11_BACKEND_ERR_SIG_INVALID;
        if (msg_len != inlen || memcmp(msg, in, inlen) != 0)
            return WP11_BACKEND_ERR_SIG_INVALID;
        return 0;
    }

    return WP11_BACKEND_ERR_NOT_IMPL; /* unsupported mechanism */
}

/* -------------------------------------------------------------------------
 * hsm_decrypt
 *
 * Supports:
 *   HSM_CKM_RSA_PKCS -- RSA PKCS#1 v1.5 decrypt (server RSA + local unpad)
 * ---------------------------------------------------------------------- */

static int hsm_decrypt(const wp11_key_handle_t *handle,
                       uint32_t                 mechanism,
                       const uint8_t           *ct,    size_t  ctlen,
                       uint8_t                 *pt,    size_t *ptlen)
{
    const wp11_wolfhsm_key_priv_t *kp;
    int ret;

    if (ct == NULL || pt == NULL || ptlen == NULL) return -1;

    kp = hsm_entry(handle);
    if (kp == NULL) return -1;

    if (mechanism == HSM_CKM_RSA_PKCS) {
        RsaKey  rsa;
        uint8_t out[HSM_RSA_MAX_BYTES];
        uint16_t wlen;

        if (kp->key_type != WP11_KEY_TYPE_RSA) return -1;

        ret = wc_InitRsaKey(&rsa, NULL);
        if (ret != 0) return -1;

        ret = wh_Client_RsaSetKeyId(&rsa, (whNvmId)kp->key_id);
        if (ret != 0) { wc_FreeRsaKey(&rsa); return -1; }

        if (ctlen > (size_t)UINT16_MAX) { wc_FreeRsaKey(&rsa); return -1; }
        wlen = (uint16_t)sizeof(out);
        ret  = wh_Client_RsaFunction((whClientContext *)kp->ctx, &rsa,
                                      RSA_PRIVATE_DECRYPT,
                                      ct, (uint16_t)ctlen,
                                      out, &wlen);
        wc_FreeRsaKey(&rsa);
        if (ret != 0) return wh_err_to_backend_err(ret);

        /* Strip PKCS#1 v1.5 type-02 padding; copy plaintext */
        ret = pkcs1_v15_unpad_decrypt(out, (size_t)wlen, pt, ptlen);
        memset(out, 0, sizeof(out));  /* zero decrypted block regardless */
        return ret;
    }

    return WP11_BACKEND_ERR_NOT_IMPL; /* unsupported mechanism */
}

/* -------------------------------------------------------------------------
 * hsm_derive
 *
 * Supports:
 *   HSM_CKM_ECDH1_DERIVE -- ECDH key agreement using a server-side ECC key
 *
 * peer_pub: uncompressed EC point (04 || X || Y); P-256 = 65 bytes
 * The peer public key is imported to the server temporarily and evicted
 * by the server after the shared-secret computation.
 * ---------------------------------------------------------------------- */

static int hsm_derive(const wp11_key_handle_t *handle,
                      uint32_t                 mechanism,
                      const uint8_t           *peer_pub,    size_t  peer_pub_len,
                      uint8_t                 *shared,      size_t *sharedlen)
{
    const wp11_wolfhsm_key_priv_t *kp;
    ecc_key  priv_ecc;
    ecc_key  pub_ecc;
    uint16_t wlen;
    int      ret;

    if (peer_pub == NULL || shared == NULL || sharedlen == NULL) return -1;

    kp = hsm_entry(handle);
    if (kp == NULL) return -1;

    if (mechanism != HSM_CKM_ECDH1_DERIVE) return -1;
    if (kp->key_type != WP11_KEY_TYPE_EC) return -1;

    /* Private key: reference the server-cached key by ID */
    ret = wc_ecc_init(&priv_ecc);
    if (ret != 0) return -1;

    ret = wh_Client_EccSetKeyId(&priv_ecc, (whKeyId)kp->key_id);
    if (ret != 0) { wc_ecc_free(&priv_ecc); return -1; }

    /* Peer public key: import from uncompressed x963 point.
     * devCtx remains NULL (WH_KEYID_ERASED) -> wh_Client_EccSharedSecret
     * auto-imports the pub key to the server and evicts it afterwards. */
    ret = wc_ecc_init(&pub_ecc);
    if (ret != 0) { wc_ecc_free(&priv_ecc); return -1; }

    /* wolfP11-0br: guard the size_t->word32 narrowing cast.  EC uncompressed
     * points are 65 bytes (P-256) or 97 bytes (P-384), so UINT32_MAX is
     * unreachable in practice, but the guard makes the assumption explicit. */
    if (peer_pub_len > (size_t)UINT32_MAX) {
        wc_ecc_free(&pub_ecc);
        wc_ecc_free(&priv_ecc);
        return -1;
    }
    ret = wc_ecc_import_x963(peer_pub, (word32)peer_pub_len, &pub_ecc);
    if (ret != 0) {
        wc_ecc_free(&pub_ecc);
        wc_ecc_free(&priv_ecc);
        return -1;
    }

    if (*sharedlen > (size_t)UINT16_MAX) {
        wc_ecc_free(&pub_ecc);
        wc_ecc_free(&priv_ecc);
        return -1;
    }
    wlen = (uint16_t)*sharedlen;
    ret  = wh_Client_EccSharedSecret((whClientContext *)kp->ctx,
                                      &priv_ecc, &pub_ecc,
                                      shared, &wlen);
    wc_ecc_free(&pub_ecc);
    wc_ecc_free(&priv_ecc);
    if (ret != 0) return wh_err_to_backend_err(ret);
    *sharedlen = (size_t)wlen;
    return 0;
}

/* -------------------------------------------------------------------------
 * hsm_free_key_priv
 * ---------------------------------------------------------------------- */

static void hsm_free_key_priv(void *key_priv)
{
    /* The key lives on the wolfHSM server (NVM-persistent).
     * The priv struct only holds a borrowed ctx pointer and a key ID.
     * No key material to zero; just free the allocation. */
    free(key_priv);
}

/* -------------------------------------------------------------------------
 * Exported backend ops table
 * ---------------------------------------------------------------------- */

const wp11_backend_ops_t wp11_backend_wolfhsm_ops = {
    WP11_BACKEND_WOLFHSM,
    hsm_sign,
    hsm_verify,
    hsm_decrypt,
    hsm_derive,
    hsm_free_key_priv,
};

#endif /* WOLFP11_CFG_WOLFHSM_BACKEND */
