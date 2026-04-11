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

/* wp11_test_backend_wolfhsm.c -- independent oracle tests for the wolfHSM backend
 *
 * wolfP11-dbd: direct tests of wp11_backend_wolfhsm_ops using an in-process
 * wolfHSM server with a RAM-backed NVM.
 *
 * Oracle strategy:
 *   Sign:    backend sign -> raw wc_ecc_verify_hash / wc_RsaSSL_Verify oracle
 *   Verify:  raw wc_ecc_sign_hash / wc_RsaSSL_Sign oracle -> backend verify
 *   Decrypt: raw wc_RsaPublicEncrypt oracle -> backend decrypt
 *   ECDH:    backend derive A*pubB == backend derive B*pubA (symmetry oracle)
 *
 * Compile with -DWOLFP11_CFG_TEST and -DWOLFP11_CFG_WOLFHSM_BACKEND.
 * Build with WOLFHSM=1 and WOLFHSM_CFG_ENABLE_SERVER (set by test Makefile rule).
 */

#include "test/wp11_test_backend_wolfhsm.h"

#if defined(WOLFP11_CFG_TEST) && defined(WOLFP11_CFG_WOLFHSM_BACKEND)

/* wolfssl/options.h must come before all other wolfssl headers */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn.h>

/* wolfHSM client headers */
#include <wolfhsm/wh_client.h>
#include <wolfhsm/wh_client_crypto.h>
#include <wolfhsm/wh_error.h>
#include <wolfhsm/wh_keyid.h>
#include <wolfhsm/wh_common.h>

/* wolfHSM server headers (gated by WOLFHSM_CFG_ENABLE_SERVER) */
#include <wolfhsm/wh_server.h>
#include <wolfhsm/wh_nvm.h>
#include <wolfhsm/wh_nvm_flash.h>
#include <wolfhsm/wh_flash_ramsim.h>
#include <wolfhsm/wh_transport_mem.h>

/* wolfP11 backend */
#include "wolfp11/wp11_backend.h"
#include "wolfp11/wp11_keystore.h"  /* WP11_KEY_TYPE_RSA, WP11_KEY_TYPE_EC */

/* Transport headers needed for POSIX builds */
#include "port/posix/posix_transport_shm.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

/* CKM_* mechanism values -- must match HSM_CKM_* in wp11_backend_wolfhsm.c */
#define TEST_CKM_RSA_PKCS      0x00000001UL
#define TEST_CKM_ECDSA         0x00001041UL
#define TEST_CKM_ECDH1_DERIVE  0x00001050UL

/* RSA modulus size used in tests (bytes) */
#define TEST_RSA_KEY_BYTES  256u   /* RSA-2048 */

/* Flash RAM size for NVM backend: 256 KB is ample for a few test keys */
#define TEST_FLASH_SIZE    (256u * 1024u)
#define TEST_FLASH_SECTOR  (64u * 1024u)
#define TEST_FLASH_PAGE    8u

/* In-memory transport buffer sizes */
#define TEST_TRANSPORT_BUF_SIZE  4096u

/* -------------------------------------------------------------------------
 * Test fixture: in-process wolfHSM server + client
 * ---------------------------------------------------------------------- */

typedef struct {
    /* Flash RAM for NVM backend */
    uint8_t              flash_mem[TEST_FLASH_SIZE];
    whFlashRamsimCtx     flash_ctx;
    whFlashRamsimCfg     flash_cfg;
    whNvmContext         nvm;
    whNvmFlashContext    nvm_flash_ctx;
    whNvmFlashConfig     nvm_flash_cfg;

    /* In-memory transport (shared req/resp buffers) */
    uint8_t                     req_buf[TEST_TRANSPORT_BUF_SIZE];
    uint8_t                     resp_buf[TEST_TRANSPORT_BUF_SIZE];
    whTransportMemConfig        transport_cfg;
    whTransportMemServerContext server_transport;
    whTransportMemClientContext client_transport;
    /* Transport callback tables.  Must outlive fixture_init() since the comm
     * config stores a pointer to them; cannot be local to fixture_init(). */
    whTransportServerCb         server_transport_cb;
    whTransportClientCb         client_transport_cb;
    /* Flash callback table -- same lifetime requirement as transport callbacks. */
    whFlashCb                   flash_cb;

    /* Server */
    whServerCryptoContext server_crypto;
    whCommServerConfig    server_comm_cfg;
    whServerConfig        server_cfg;
    whServerContext       server;

    /* Client */
    whCommClientConfig  client_comm_cfg;
    whClientConfig      client_cfg;
    whClientContext     client;

    /* Server background thread */
    pthread_t       server_thread;
    volatile int    server_running;
} wp11_wolfhsm_fixture_t;

/* RNG shared across tests (initialized once) */
static WC_RNG g_test_rng;

static int check(int pass, const char *label)
{
    printf("%s: %s\n", pass ? "PASS" : "FAIL", label);
    return pass ? 0 : 1;
}

/* Server thread: runs wh_Server_HandleRequestMessage in a tight loop until
 * server_running is cleared.  Returns NULL on exit. */
static void *server_thread_fn(void *arg)
{
    wp11_wolfhsm_fixture_t *f = (wp11_wolfhsm_fixture_t *)arg;
    while (f->server_running) {
        int ret = wh_Server_HandleRequestMessage(&f->server);
        if (ret != WH_ERROR_OK && ret != WH_ERROR_NOTREADY) {
            /* Unexpected server error -- stop the thread */
            break;
        }
    }
    return NULL;
}

/* Initialise the fixture: set up NVM, transport, server, client, start thread.
 * Returns 0 on success. */
static int fixture_init(wp11_wolfhsm_fixture_t *f)
{
    whNvmConfig  nvm_cfg;

    memset(f, 0, sizeof(*f));

    /* Initialise callback tables in the fixture (must not be local vars).
     * memset(f,...) above cleared them; assign function pointers now. */
    f->flash_cb            = (whFlashCb)WH_FLASH_RAMSIM_CB;
    f->server_transport_cb = (whTransportServerCb)WH_TRANSPORT_MEM_SERVER_CB;
    f->client_transport_cb = (whTransportClientCb)WH_TRANSPORT_MEM_CLIENT_CB;

    /* Flash RAM configuration */
    f->flash_cfg.memory     = f->flash_mem;
    f->flash_cfg.size       = TEST_FLASH_SIZE;
    f->flash_cfg.sectorSize = TEST_FLASH_SECTOR;
    f->flash_cfg.pageSize   = TEST_FLASH_PAGE;
    f->flash_cfg.erasedByte = 0xFFu;

    /* NVM flash config (wrapper over flash) */
    f->nvm_flash_cfg.cb     = &f->flash_cb;
    f->nvm_flash_cfg.context = &f->flash_ctx;
    f->nvm_flash_cfg.config  = &f->flash_cfg;

    /* NVM context */
    memset(&nvm_cfg, 0, sizeof(nvm_cfg));
    {
        whNvmCb nvm_cb = WH_NVM_FLASH_CB;
        nvm_cfg.cb      = NULL;  /* set below */
        nvm_cfg.context = &f->nvm_flash_ctx;
        nvm_cfg.config  = &f->nvm_flash_cfg;
        /* The whNvmCb is a static const; assign via local copy */
        (void)nvm_cb;
    }

    /* Use WH_NVM_FLASH_CB directly */
    {
        static const whNvmCb s_nvm_flash_cb = WH_NVM_FLASH_CB;
        nvm_cfg.cb = (whNvmCb*)&s_nvm_flash_cb;
    }

    if (wh_Nvm_Init(&f->nvm, &nvm_cfg) != WH_ERROR_OK) return -1;

    /* Transport configuration */
    f->transport_cfg.req      = (whTransportMemCsr*)f->req_buf;
    f->transport_cfg.req_size = TEST_TRANSPORT_BUF_SIZE;
    f->transport_cfg.resp      = (whTransportMemCsr*)f->resp_buf;
    f->transport_cfg.resp_size = TEST_TRANSPORT_BUF_SIZE;

    /* Server communication config */
    f->server_comm_cfg.transport_cb      = &f->server_transport_cb;
    f->server_comm_cfg.transport_context = &f->server_transport;
    f->server_comm_cfg.transport_config  = &f->transport_cfg;
    f->server_comm_cfg.server_id         = 1u;

    /* Server crypto context */
    if (wc_InitRng_ex(f->server_crypto.rng, NULL, INVALID_DEVID) != 0) {
        wh_Nvm_Cleanup(&f->nvm);
        return -1;
    }

    /* Server config */
    f->server_cfg.comm_config = &f->server_comm_cfg;
    f->server_cfg.nvm         = &f->nvm;
    f->server_cfg.crypto      = &f->server_crypto;

    /* Server MUST be initialized before client (MEM transport connect is
     * triggered by client init; server init must run first or connect fails) */
    if (wh_Server_Init(&f->server, &f->server_cfg) != WH_ERROR_OK) {
        wh_Nvm_Cleanup(&f->nvm);
        return -1;
    }
    /* wh_TransportMem_Init ignores the connect callback; explicitly set the
     * server to connected so wh_Server_HandleRequestMessage processes
     * requests instead of returning WH_ERROR_NOTREADY and blocking the
     * client busy-poll indefinitely. */
    wh_Server_SetConnected(&f->server, WH_COMM_CONNECTED);

    /* Client communication config */
    f->client_comm_cfg.transport_cb      = &f->client_transport_cb;
    f->client_comm_cfg.transport_context = &f->client_transport;
    f->client_comm_cfg.transport_config  = &f->transport_cfg;
    f->client_comm_cfg.client_id         = 1u;

    f->client_cfg.comm = &f->client_comm_cfg;
    if (wh_Client_Init(&f->client, &f->client_cfg) != WH_ERROR_OK) {
        wh_Server_Cleanup(&f->server);
        wh_Nvm_Cleanup(&f->nvm);
        return -1;
    }

    /* Start server background thread */
    f->server_running = 1;
    if (pthread_create(&f->server_thread, NULL, server_thread_fn, f) != 0) {
        wh_Client_Cleanup(&f->client);
        wh_Server_Cleanup(&f->server);
        wh_Nvm_Cleanup(&f->nvm);
        return -1;
    }

    return 0;
}

/* Tear down: stop server thread, clean up client, server, NVM. */
static void fixture_cleanup(wp11_wolfhsm_fixture_t *f)
{
    f->server_running = 0;
    pthread_cancel(f->server_thread);
    pthread_join(f->server_thread, NULL);

    wh_Client_Cleanup(&f->client);
    wh_Server_Cleanup(&f->server);
    wh_Nvm_Cleanup(&f->nvm);
    wc_FreeRng(f->server_crypto.rng);
}

/* -------------------------------------------------------------------------
 * make_ec_handle -- build a wp11_key_handle_t for an EC key on the server
 *
 * Generates a fresh P-256 key, imports it to the server cache, and returns
 * the key handle.  The caller must call wp11_wolfhsm_free_key_priv on the
 * returned handle's priv pointer when done.
 *
 * pub_key_out: if non-NULL, the wolfCrypt ecc_key is exported with the public
 *   key set and must be freed by the caller with wc_ecc_free.
 *
 * Returns 0 on success, -1 on error.
 * ---------------------------------------------------------------------- */
static int make_ec_handle(wp11_wolfhsm_fixture_t *f,
                          wp11_key_handle_t      *h,
                          ecc_key                *pub_key_out)
{
    ecc_key  key;
    whKeyId  key_id = WH_KEYID_ERASED;
    wp11_wolfhsm_key_priv_t *kp;
    int ret;

    ret = wc_ecc_init(&key);
    if (ret != 0) return -1;

    ret = wc_ecc_make_key(&g_test_rng, 32, &key);  /* P-256 = 32-byte keys */
    if (ret != 0) { wc_ecc_free(&key); return -1; }

    ret = wh_Client_EccImportKey(&f->client, &key, &key_id,
                                  WH_NVM_FLAGS_USAGE_ANY, 0, NULL);
    if (ret != 0) { wc_ecc_free(&key); return -1; }

    if (pub_key_out != NULL) {
        /* Export the public key in uncompressed x963 format, then import it
         * into a fresh key for oracle use.  wc_ecc_copy does not exist in all
         * wolfSSL builds; round-trip through x963 is always available. */
        byte   x963[65];
        word32 x963_len = sizeof(x963);
        ret = wc_ecc_export_x963(&key, x963, &x963_len);
        if (ret == 0) ret = wc_ecc_init(pub_key_out);
        if (ret == 0) ret = wc_ecc_import_x963(x963, x963_len, pub_key_out);
        if (ret != 0) {
            wc_ecc_free(&key);
            return -1;
        }
    }

    wc_ecc_free(&key);

    kp = wp11_wolfhsm_alloc_key_priv((void *)&f->client, (uint16_t)key_id,
                                      WP11_KEY_TYPE_EC, 0u);
    if (kp == NULL) return -1;

    h->backend = WP11_BACKEND_WOLFHSM;
    h->id      = (uint32_t)key_id;
    h->priv    = kp;
    return 0;
}

/* -------------------------------------------------------------------------
 * make_rsa_handle -- build a wp11_key_handle_t for an RSA-2048 key
 *
 * Generates a fresh RSA-2048 key, imports to server, returns handle.
 * pub_key_out is populated with the public key for oracle use.
 *
 * Returns 0 on success, -1 on error.
 * ---------------------------------------------------------------------- */
static int make_rsa_handle(wp11_wolfhsm_fixture_t *f,
                           wp11_key_handle_t      *h,
                           RsaKey                 *pub_key_out)
{
    RsaKey  key;
    whKeyId key_id = WH_KEYID_ERASED;
    wp11_wolfhsm_key_priv_t *kp;
    int ret;

    ret = wc_InitRsaKey(&key, NULL);
    if (ret != 0) return -1;

    ret = wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &g_test_rng);
    if (ret != 0) { wc_FreeRsaKey(&key); return -1; }

    ret = wh_Client_RsaImportKey(&f->client, &key, &key_id,
                                  WH_NVM_FLAGS_USAGE_ANY, 0, NULL);
    if (ret != 0) { wc_FreeRsaKey(&key); return -1; }

    if (pub_key_out != NULL) {
        /* Export public components into a fresh key for oracle use */
        byte   n_buf[TEST_RSA_KEY_BYTES];
        byte   e_buf[4];
        word32 n_len = sizeof(n_buf);
        word32 e_len = sizeof(e_buf);

        ret = wc_InitRsaKey(pub_key_out, NULL);
        if (ret == 0) {
            ret = wc_RsaFlattenPublicKey(&key, e_buf, &e_len, n_buf, &n_len);
        }
        if (ret == 0) {
            ret = wc_RsaPublicKeyDecodeRaw(n_buf, n_len, e_buf, e_len,
                                           pub_key_out);
        }
        if (ret != 0) {
            wc_FreeRsaKey(&key);
            return -1;
        }
    }

    wc_FreeRsaKey(&key);

    kp = wp11_wolfhsm_alloc_key_priv((void *)&f->client, (uint16_t)key_id,
                                      WP11_KEY_TYPE_RSA,
                                      (uint16_t)TEST_RSA_KEY_BYTES);
    if (kp == NULL) return -1;

    h->backend = WP11_BACKEND_WOLFHSM;
    h->id      = (uint32_t)key_id;
    h->priv    = kp;
    return 0;
}

static void free_handle(wp11_key_handle_t *h)
{
    if (h->priv != NULL) {
        wp11_wolfhsm_key_priv_t *kp     = (wp11_wolfhsm_key_priv_t *)h->priv;
        whClientContext         *ctx    = (whClientContext *)kp->ctx;
        whKeyId                  key_id = kp->key_id;
        /* Free client-side allocation before evicting from server cache. */
        wp11_backend_wolfhsm_ops.free_key_priv(h->priv);
        h->priv = NULL;
        /* Evict the key from the server cache.  Server-imported keys have
         * committed=0, so _GetKeyCacheSlot's committed-slot eviction path
         * will not release them; explicit eviction is required to free the
         * cache slot (especially the single big-cache slot used for RSA). */
        (void)wh_Client_KeyEvict(ctx, key_id);
    }
}

/* -------------------------------------------------------------------------
 * Test 1: ECDSA sign -- oracle: raw wolfCrypt wc_ecc_verify_hash
 * ---------------------------------------------------------------------- */
static int test_hsm_sign_ecdsa_p256(wp11_wolfhsm_fixture_t *f)
{
    wp11_key_handle_t h;
    ecc_key           pub;
    uint8_t           hash[WC_SHA256_DIGEST_SIZE];
    uint8_t           sig[128];
    size_t            sig_len = sizeof(sig);
    int               stat    = 0;
    int               failures = 0;
    int               ret;

    /* Deterministic test hash */
    memset(hash, 0xABu, sizeof(hash));

    ret = make_ec_handle(f, &h, &pub);
    failures += check(ret == 0, "hsm_sign_ecdsa: key created");
    if (ret != 0) goto done_no_pub;

    ret = wp11_backend_wolfhsm_ops.sign(&h, TEST_CKM_ECDSA,
                                         hash, sizeof(hash), sig, &sig_len);
    failures += check(ret == 0, "hsm_sign_ecdsa: sign returns 0");
    failures += check(sig_len > 0 && sig_len <= 72u,
                      "hsm_sign_ecdsa: sig_len in ECDSA range");

    if (ret == 0 && sig_len > 0) {
        /* Oracle: verify with raw wolfCrypt (different code path) */
        ret = wc_ecc_verify_hash(sig, (word32)sig_len,
                                  hash, (word32)sizeof(hash),
                                  &stat, &pub);
        failures += check(ret == 0 && stat == 1,
                          "hsm_sign_ecdsa: oracle wc_ecc_verify_hash accepts sig");
    }

    wc_ecc_free(&pub);
done_no_pub:
    free_handle(&h);
    return failures;
}

/* -------------------------------------------------------------------------
 * Test 2: ECDSA verify -- oracle: raw wolfCrypt wc_ecc_sign_hash
 * ---------------------------------------------------------------------- */
static int test_hsm_verify_ecdsa_p256(wp11_wolfhsm_fixture_t *f)
{
    wp11_key_handle_t h;
    ecc_key           oracle_key;
    uint8_t           hash[WC_SHA256_DIGEST_SIZE];
    uint8_t           sig[128];
    word32            sig_len = sizeof(sig);
    int               failures = 0;
    int               ret;

    memset(hash, 0xCDu, sizeof(hash));

    /* Import a fresh key; we need the private key for oracle signing */
    ret = wc_ecc_init(&oracle_key);
    if (ret != 0) return check(0, "hsm_verify_ecdsa: oracle key init");

    ret = wc_ecc_make_key(&g_test_rng, 32, &oracle_key);
    failures += check(ret == 0, "hsm_verify_ecdsa: oracle key generated");
    if (ret != 0) { wc_ecc_free(&oracle_key); return failures; }

    /* Import to server; build handle */
    {
        whKeyId key_id = WH_KEYID_ERASED;
        wp11_wolfhsm_key_priv_t *kp;

        ret = wh_Client_EccImportKey(&f->client, &oracle_key, &key_id,
                                      WH_NVM_FLAGS_USAGE_ANY, 0, NULL);
        failures += check(ret == 0, "hsm_verify_ecdsa: key imported");
        if (ret != 0) { wc_ecc_free(&oracle_key); return failures; }

        kp = wp11_wolfhsm_alloc_key_priv((void *)&f->client, (uint16_t)key_id,
                                          WP11_KEY_TYPE_EC, 0u);
        failures += check(kp != NULL, "hsm_verify_ecdsa: kp alloc");
        if (kp == NULL) { wc_ecc_free(&oracle_key); return failures; }

        h.backend = WP11_BACKEND_WOLFHSM;
        h.id      = (uint32_t)key_id;
        h.priv    = kp;
    }

    /* Oracle: sign with raw wolfCrypt */
    ret = wc_ecc_sign_hash(hash, (word32)sizeof(hash), sig, &sig_len,
                            &g_test_rng, &oracle_key);
    failures += check(ret == 0, "hsm_verify_ecdsa: oracle sign");

    if (ret == 0) {
        /* Backend verify -- should accept the valid signature */
        ret = wp11_backend_wolfhsm_ops.verify(&h, TEST_CKM_ECDSA,
                                               hash, sizeof(hash),
                                               sig, (size_t)sig_len);
        failures += check(ret == 0, "hsm_verify_ecdsa: backend accepts valid sig");

        /* Corrupt the signature and verify it is rejected */
        sig[0] ^= 0xFFu;
        ret = wp11_backend_wolfhsm_ops.verify(&h, TEST_CKM_ECDSA,
                                               hash, sizeof(hash),
                                               sig, (size_t)sig_len);
        failures += check(ret < 0, "hsm_verify_ecdsa: backend rejects bad sig");
    }

    wc_ecc_free(&oracle_key);
    free_handle(&h);
    return failures;
}

/* -------------------------------------------------------------------------
 * Test 3: RSA PKCS#1 v1.5 decrypt -- oracle: raw wc_RsaPublicEncrypt
 * ---------------------------------------------------------------------- */
static int test_hsm_decrypt_rsa_pkcs1(wp11_wolfhsm_fixture_t *f)
{
    wp11_key_handle_t h;
    RsaKey            pub;
    uint8_t           plaintext[32];
    uint8_t           ciphertext[TEST_RSA_KEY_BYTES];
    uint8_t           recovered[TEST_RSA_KEY_BYTES];
    int               ct_len;
    size_t            pt_len = sizeof(recovered);
    int               failures = 0;
    int               ret;

    memset(plaintext, 0x5Au, sizeof(plaintext));

    ret = make_rsa_handle(f, &h, &pub);
    failures += check(ret == 0, "hsm_decrypt_rsa: key created");
    if (ret != 0) goto done_no_pub;

    /* Oracle: encrypt with raw wolfCrypt public key */
    ct_len = wc_RsaPublicEncrypt(plaintext, sizeof(plaintext),
                                  ciphertext, sizeof(ciphertext),
                                  &pub, &g_test_rng);
    failures += check(ct_len > 0, "hsm_decrypt_rsa: oracle encrypt ok");

    if (ct_len > 0) {
        /* Backend decrypt */
        ret = wp11_backend_wolfhsm_ops.decrypt(&h, TEST_CKM_RSA_PKCS,
                                                ciphertext, (size_t)ct_len,
                                                recovered, &pt_len);
        failures += check(ret == 0, "hsm_decrypt_rsa: backend decrypt ok");
        failures += check(pt_len == sizeof(plaintext),
                          "hsm_decrypt_rsa: recovered len matches");
        failures += check(memcmp(recovered, plaintext, sizeof(plaintext)) == 0,
                          "hsm_decrypt_rsa: recovered plaintext matches");
    }

    wc_FreeRsaKey(&pub);
done_no_pub:
    free_handle(&h);
    return failures;
}

/* -------------------------------------------------------------------------
 * Test 4: ECDH P-256 derive -- symmetry oracle: A*pubB == B*pubA
 * ---------------------------------------------------------------------- */
static int test_hsm_derive_ecdh_p256(wp11_wolfhsm_fixture_t *f)
{
    wp11_key_handle_t ha, hb;
    ecc_key           pub_a, pub_b;
    uint8_t           pub_a_x963[65];  /* uncompressed P-256 public key */
    uint8_t           pub_b_x963[65];
    word32            pub_a_len = sizeof(pub_a_x963);
    word32            pub_b_len = sizeof(pub_b_x963);
    uint8_t           shared_a[32];   /* A derives with B's public key */
    uint8_t           shared_b[32];   /* B derives with A's public key */
    size_t            shared_a_len = sizeof(shared_a);
    size_t            shared_b_len = sizeof(shared_b);
    int               failures = 0;
    int               ret;

    ret  = make_ec_handle(f, &ha, &pub_a);
    ret += make_ec_handle(f, &hb, &pub_b);
    failures += check(ret == 0, "hsm_derive_ecdh: both keys created");
    if (ret != 0) goto done;

    /* Export public keys in uncompressed x963 format */
    ret = wc_ecc_export_x963(&pub_a, pub_a_x963, &pub_a_len);
    failures += check(ret == 0 && pub_a_len == 65u,
                      "hsm_derive_ecdh: export pub_a x963");

    ret = wc_ecc_export_x963(&pub_b, pub_b_x963, &pub_b_len);
    failures += check(ret == 0 && pub_b_len == 65u,
                      "hsm_derive_ecdh: export pub_b x963");

    if (pub_a_len != 65u || pub_b_len != 65u) goto done;

    /* A derives with B's public key */
    ret = wp11_backend_wolfhsm_ops.derive(&ha, TEST_CKM_ECDH1_DERIVE,
                                           pub_b_x963, (size_t)pub_b_len,
                                           shared_a, &shared_a_len);
    failures += check(ret == 0, "hsm_derive_ecdh: A derives with B's pub");
    failures += check(shared_a_len == 32u,
                      "hsm_derive_ecdh: A shared secret is 32 bytes (P-256)");

    /* B derives with A's public key */
    ret = wp11_backend_wolfhsm_ops.derive(&hb, TEST_CKM_ECDH1_DERIVE,
                                           pub_a_x963, (size_t)pub_a_len,
                                           shared_b, &shared_b_len);
    failures += check(ret == 0, "hsm_derive_ecdh: B derives with A's pub");
    failures += check(shared_b_len == 32u,
                      "hsm_derive_ecdh: B shared secret is 32 bytes (P-256)");

    /* Symmetry oracle: both sides must agree */
    if (shared_a_len == 32u && shared_b_len == 32u) {
        failures += check(memcmp(shared_a, shared_b, 32u) == 0,
                          "hsm_derive_ecdh: ECDH symmetry: A*pubB == B*pubA");
    }

done:
    wc_ecc_free(&pub_a);
    wc_ecc_free(&pub_b);
    free_handle(&ha);
    free_handle(&hb);
    return failures;
}

/* -------------------------------------------------------------------------
 * Test 5: WH_ERROR_NOTREADY mapping (deferred -- see wolfP11-8o2)
 *
 * wolfP11-8o2 requires a mock transport to inject WH_ERROR_NOTREADY.
 * This is tracked separately and not implemented here.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * Test 6: server-side key generation -- ECC P-256
 *
 * Exercises wh_Client_EccMakeCacheKey (the server-side equivalent of
 * C_GenerateKeyPair for EC keys) by generating a key on the server and
 * immediately signing and verifying with the oracle path:
 *   sign with backend (server-cached key) -> verify with raw wolfCrypt
 *
 * This confirms that the generated key is usable without ever exporting
 * private material to the client.
 * ---------------------------------------------------------------------- */
static int test_hsm_server_gen_ec_p256(wp11_wolfhsm_fixture_t *f)
{
    whKeyId            key_id = WH_KEYID_ERASED;
    wp11_key_handle_t  h;
    wp11_wolfhsm_key_priv_t *kp;
    ecc_key            pub;
    uint8_t            hash[WC_SHA256_DIGEST_SIZE];
    uint8_t            sig[128];
    size_t             sig_len = sizeof(sig);
    int                stat   = 0;
    int                failures = 0;
    int                ret;

    memset(hash, 0x7Eu, sizeof(hash));

    /* Generate EC P-256 key on the server (key never leaves server) */
    ret = wh_Client_EccMakeCacheKey(&f->client, 32, ECC_SECP256R1,
                                     &key_id, WH_NVM_FLAGS_USAGE_ANY, 0, NULL);
    failures += check(ret == 0, "hsm_gen_ec: EccMakeCacheKey returns 0");
    if (ret != 0) return failures;

    /* Export public key for oracle verification */
    ret = wc_ecc_init(&pub);
    if (ret != 0) {
        (void)wh_Client_KeyEvict(&f->client, key_id);
        return failures + check(0, "hsm_gen_ec: pub key init");
    }
    ret = wh_Client_EccExportKey(&f->client, key_id, &pub, 0, NULL);
    failures += check(ret == 0, "hsm_gen_ec: EccExportKey returns 0");

    /* Build handle using the server-side key ID */
    kp = wp11_wolfhsm_alloc_key_priv((void *)&f->client, (uint16_t)key_id,
                                      WP11_KEY_TYPE_EC, 0u);
    failures += check(kp != NULL, "hsm_gen_ec: kp alloc");
    if (kp == NULL) { wc_ecc_free(&pub); return failures; }

    h.backend = WP11_BACKEND_WOLFHSM;
    h.id      = (uint32_t)key_id;
    h.priv    = kp;

    /* Sign with server-cached generated key */
    ret = wp11_backend_wolfhsm_ops.sign(&h, TEST_CKM_ECDSA,
                                         hash, sizeof(hash), sig, &sig_len);
    failures += check(ret == 0, "hsm_gen_ec: sign with generated key returns 0");
    failures += check(sig_len > 0 && sig_len <= 72u,
                      "hsm_gen_ec: sig_len in ECDSA range");

    if (ret == 0 && sig_len > 0) {
        /* Oracle: verify with raw wolfCrypt using exported public key */
        ret = wc_ecc_verify_hash(sig, (word32)sig_len,
                                  hash, (word32)sizeof(hash),
                                  &stat, &pub);
        failures += check(ret == 0 && stat == 1,
                          "hsm_gen_ec: oracle wc_ecc_verify_hash accepts sig");
    }

    wc_ecc_free(&pub);
    free_handle(&h);
    return failures;
}

/* -------------------------------------------------------------------------
 * Test 7: server-side key generation -- RSA-2048
 *
 * Exercises wh_Client_RsaMakeCacheKey and then tests decrypt via the backend.
 * Oracle: raw wc_RsaPublicEncrypt with exported public key -> backend decrypt.
 * ---------------------------------------------------------------------- */
static int test_hsm_server_gen_rsa2048(wp11_wolfhsm_fixture_t *f)
{
    whKeyId            key_id = WH_KEYID_ERASED;
    wp11_key_handle_t  h;
    wp11_wolfhsm_key_priv_t *kp;
    RsaKey             pub;
    uint8_t            plaintext[32];
    uint8_t            ciphertext[TEST_RSA_KEY_BYTES];
    uint8_t            recovered[TEST_RSA_KEY_BYTES];
    int                ct_len;
    size_t             pt_len = sizeof(recovered);
    int                failures = 0;
    int                ret;

    memset(plaintext, 0xBBu, sizeof(plaintext));

    /* Generate RSA-2048 key on the server */
    ret = wh_Client_RsaMakeCacheKey(&f->client, 2048u, WC_RSA_EXPONENT,
                                     &key_id, WH_NVM_FLAGS_USAGE_ANY, 0, NULL);
    failures += check(ret == 0, "hsm_gen_rsa: RsaMakeCacheKey returns 0");
    if (ret != 0) return failures;

    /* Export public key components for oracle */
    ret = wc_InitRsaKey(&pub, NULL);
    if (ret != 0) {
        (void)wh_Client_KeyEvict(&f->client, key_id);
        return failures + check(0, "hsm_gen_rsa: pub key init");
    }
    ret = wh_Client_RsaExportKey(&f->client, key_id, &pub, 0, NULL);
    failures += check(ret == 0, "hsm_gen_rsa: RsaExportKey returns 0");

    /* Build handle */
    kp = wp11_wolfhsm_alloc_key_priv((void *)&f->client, (uint16_t)key_id,
                                      WP11_KEY_TYPE_RSA,
                                      (uint16_t)TEST_RSA_KEY_BYTES);
    failures += check(kp != NULL, "hsm_gen_rsa: kp alloc");
    if (kp == NULL) { wc_FreeRsaKey(&pub); return failures; }

    h.backend = WP11_BACKEND_WOLFHSM;
    h.id      = (uint32_t)key_id;
    h.priv    = kp;

    /* Oracle: encrypt with exported public key */
    ct_len = wc_RsaPublicEncrypt(plaintext, sizeof(plaintext),
                                  ciphertext, sizeof(ciphertext),
                                  &pub, &g_test_rng);
    failures += check(ct_len > 0, "hsm_gen_rsa: oracle encrypt ok");

    if (ct_len > 0) {
        /* Backend decrypt with server-cached generated key */
        ret = wp11_backend_wolfhsm_ops.decrypt(&h, TEST_CKM_RSA_PKCS,
                                                ciphertext, (size_t)ct_len,
                                                recovered, &pt_len);
        failures += check(ret == 0, "hsm_gen_rsa: backend decrypt ok");
        failures += check(pt_len == sizeof(plaintext),
                          "hsm_gen_rsa: recovered len matches");
        failures += check(memcmp(recovered, plaintext, sizeof(plaintext)) == 0,
                          "hsm_gen_rsa: recovered plaintext matches");
    }

    wc_FreeRsaKey(&pub);
    free_handle(&h);
    return failures;
}

/* -------------------------------------------------------------------------
 * Test 8: C_CreateObject EC import path -- private-only key
 *
 * Simulates what C_CreateObject does for CKK_EC CKO_PRIVATE_KEY on a
 * wolfHSM slot: imports an ECC_PRIVATEKEY_ONLY key (private scalar only,
 * no public key) via wh_Client_EccImportKey.  The key_id returned is then
 * used with the backend sign op.  The oracle verifies the signature using
 * the locally-held public key (which was never sent to the server).
 *
 * Oracle strategy: generate key locally -> extract priv scalar -> import
 * priv-only -> backend sign -> local wc_ecc_verify_hash with local pub key
 * ---------------------------------------------------------------------- */
static int test_hsm_import_ec_private(wp11_wolfhsm_fixture_t *f)
{
    ecc_key                  full_key;   /* locally generated key pair */
    ecc_key                  priv_only;  /* private-scalar-only import copy */
    whKeyId                  key_id = WH_KEYID_ERASED;
    wp11_wolfhsm_key_priv_t *kp;
    wp11_key_handle_t        h;
    uint8_t                  hash[WC_SHA256_DIGEST_SIZE];
    uint8_t                  sig[128];
    size_t                   sig_len = sizeof(sig);
    int                      stat    = 0;
    int                      failures = 0;
    int                      ret;
    /* Private scalar extracted from the full key */
    byte                     priv_buf[32];
    word32                   priv_len = sizeof(priv_buf);

    memset(hash, 0xF1u, sizeof(hash));

    /* Generate a full EC P-256 key pair locally (oracle source) */
    ret = wc_ecc_init(&full_key);
    if (ret != 0) return check(0, "hsm_import_ec: full key init");

    ret = wc_ecc_make_key(&g_test_rng, 32, &full_key);
    failures += check(ret == 0, "hsm_import_ec: key pair generated");
    if (ret != 0) { wc_ecc_free(&full_key); return failures; }

    /* Extract the private scalar from the full key */
    ret = wc_ecc_export_private_only(&full_key, priv_buf, &priv_len);
    failures += check(ret == 0 && priv_len == 32u,
                      "hsm_import_ec: private scalar extracted (32 bytes)");
    if (ret != 0) { wc_ecc_free(&full_key); return failures; }

    /* Build a private-only ecc_key -- mirrors what C_CreateObject does when
     * given CKA_EC_PARAMS + CKA_VALUE with no public key component */
    ret = wc_ecc_init(&priv_only);
    failures += check(ret == 0, "hsm_import_ec: priv_only init");
    if (ret != 0) { wc_ecc_free(&full_key); return failures; }

    ret = wc_ecc_import_private_key_ex(priv_buf, priv_len,
                                        NULL, 0u,
                                        &priv_only, ECC_SECP256R1);
    failures += check(ret == 0, "hsm_import_ec: import private scalar");
    failures += check(priv_only.type == ECC_PRIVATEKEY_ONLY,
                      "hsm_import_ec: key type is ECC_PRIVATEKEY_ONLY");

    if (ret == 0) {
        /* Import private-only key to wolfHSM server */
        ret = wh_Client_EccImportKey(&f->client, &priv_only, &key_id,
                                      WH_NVM_FLAGS_USAGE_ANY, 0, NULL);
        failures += check(ret == 0, "hsm_import_ec: EccImportKey returns 0");
    }
    wc_ecc_free(&priv_only);

    if (ret != 0) { wc_ecc_free(&full_key); return failures; }

    /* Build handle for the server-cached private-only key */
    kp = wp11_wolfhsm_alloc_key_priv((void *)&f->client, (uint16_t)key_id,
                                      WP11_KEY_TYPE_EC, 0u);
    failures += check(kp != NULL, "hsm_import_ec: kp alloc");
    if (kp == NULL) {
        wc_ecc_free(&full_key);
        (void)wh_Client_KeyEvict(&f->client, key_id);
        return failures;
    }

    h.backend = WP11_BACKEND_WOLFHSM;
    h.id      = (uint32_t)key_id;
    h.priv    = kp;

    /* Sign with the server-cached private-only key */
    ret = wp11_backend_wolfhsm_ops.sign(&h, TEST_CKM_ECDSA,
                                         hash, sizeof(hash), sig, &sig_len);
    failures += check(ret == 0, "hsm_import_ec: sign with private-only key");
    failures += check(sig_len > 0 && sig_len <= 72u,
                      "hsm_import_ec: sig_len in ECDSA range");

    if (ret == 0 && sig_len > 0) {
        /* Oracle: verify with the locally-held full key's public component.
         * This is independent -- the server never saw the public key. */
        ret = wc_ecc_verify_hash(sig, (word32)sig_len,
                                  hash, (word32)sizeof(hash),
                                  &stat, &full_key);
        failures += check(ret == 0 && stat == 1,
                          "hsm_import_ec: oracle wc_ecc_verify_hash accepts sig");
    }

    wc_ecc_free(&full_key);
    free_handle(&h);
    return failures;
}

/* -------------------------------------------------------------------------
 * Test 9: C_CreateObject RSA import path -- raw CRT components
 *
 * Simulates what C_CreateObject does for CKK_RSA CKO_PRIVATE_KEY on a
 * wolfHSM slot: reconstructs an RsaKey from the flat CRT components
 * (n, e, d, p, q, dP, dQ, u) using wc_RsaPrivateKeyDecodeRaw, then
 * imports to the server via wh_Client_RsaImportKey.
 *
 * Oracle strategy: raw wc_RsaPublicEncrypt with the same n/e -> backend
 * decrypt -> compare recovered plaintext.
 * ---------------------------------------------------------------------- */
static int test_hsm_import_rsa_private(wp11_wolfhsm_fixture_t *f)
{
    RsaKey                   orig;      /* locally generated key pair */
    RsaKey                   reconstructed; /* built from flat components */
    RsaKey                   pub;       /* oracle: public key only */
    whKeyId                  key_id = WH_KEYID_ERASED;
    wp11_wolfhsm_key_priv_t *kp;
    wp11_key_handle_t        h;
    uint8_t                  plaintext[32];
    uint8_t                  ciphertext[TEST_RSA_KEY_BYTES];
    uint8_t                  recovered[TEST_RSA_KEY_BYTES];
    int                      ct_len;
    size_t                   pt_len = sizeof(recovered);
    int                      failures = 0;
    int                      ret;

    /* CRT component buffers sized for RSA-2048 */
    byte n_buf[TEST_RSA_KEY_BYTES], e_buf[4], d_buf[TEST_RSA_KEY_BYTES];
    byte p_buf[TEST_RSA_KEY_BYTES / 2], q_buf[TEST_RSA_KEY_BYTES / 2];
    byte dp_buf[TEST_RSA_KEY_BYTES / 2], dq_buf[TEST_RSA_KEY_BYTES / 2];
    byte u_buf[TEST_RSA_KEY_BYTES / 2];
    word32 n_len = sizeof(n_buf), e_len = sizeof(e_buf), d_len = sizeof(d_buf);
    word32 p_len = sizeof(p_buf), q_len = sizeof(q_buf);
    word32 dp_len = sizeof(dp_buf), dq_len = sizeof(dq_buf), u_len = sizeof(u_buf);

    memset(plaintext, 0xD5u, sizeof(plaintext));

    /* Generate RSA-2048 key pair locally */
    ret = wc_InitRsaKey(&orig, NULL);
    if (ret != 0) return check(0, "hsm_import_rsa: orig key init");

    ret = wc_MakeRsaKey(&orig, 2048, WC_RSA_EXPONENT, &g_test_rng);
    failures += check(ret == 0, "hsm_import_rsa: key pair generated");
    if (ret != 0) { wc_FreeRsaKey(&orig); return failures; }

    /* Export CRT components -- these simulate PKCS#11 template attributes.
     * wc_RsaExportKey order: e, n, d, p, q (note: n before d) */
    ret = wc_RsaExportKey(&orig,
                          e_buf,  &e_len,
                          n_buf,  &n_len,
                          d_buf,  &d_len,
                          p_buf,  &p_len,
                          q_buf,  &q_len);
    failures += check(ret == 0, "hsm_import_rsa: wc_RsaExportKey");
    if (ret != 0) { wc_FreeRsaKey(&orig); return failures; }

    /* Compute dP = d mod (p-1), dQ = d mod (q-1), u = q^-1 mod p using
     * mp_* APIs -- these are the CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFF
     * values that a PKCS#11 caller would provide in a C_CreateObject template */
    {
        mp_int mp_d, mp_p, mp_q, mp_dp, mp_dq, mp_u, mp_tmp;
        int mp_ret = 0;

        mp_init_multi(&mp_d, &mp_p, &mp_q, &mp_dp, &mp_dq, NULL);
        mp_init_multi(&mp_u, &mp_tmp, NULL, NULL, NULL, NULL);

        mp_read_unsigned_bin(&mp_d, d_buf, (int)d_len);
        mp_read_unsigned_bin(&mp_p, p_buf, (int)p_len);
        mp_read_unsigned_bin(&mp_q, q_buf, (int)q_len);

        /* dP = d mod (p - 1) */
        mp_sub_d(&mp_p, 1, &mp_tmp);
        mp_mod(&mp_d, &mp_tmp, &mp_dp);

        /* dQ = d mod (q - 1) */
        mp_sub_d(&mp_q, 1, &mp_tmp);
        mp_mod(&mp_d, &mp_tmp, &mp_dq);

        /* u = q^-1 mod p */
        mp_ret = mp_invmod(&mp_q, &mp_p, &mp_u);

        dp_len = (word32)sizeof(dp_buf);
        dq_len = (word32)sizeof(dq_buf);
        u_len  = (word32)sizeof(u_buf);
        if (mp_ret == 0) mp_ret = mp_to_unsigned_bin_len(&mp_dp, dp_buf, (int)dp_len);
        if (mp_ret == 0) mp_ret = mp_to_unsigned_bin_len(&mp_dq, dq_buf, (int)dq_len);
        if (mp_ret == 0) mp_ret = mp_to_unsigned_bin_len(&mp_u,  u_buf,  (int)u_len);
        /* Trim leading zeros for a realistic comparison to PKCS#11 values */
        if (mp_ret == 0) dp_len = (word32)mp_unsigned_bin_size(&mp_dp);
        if (mp_ret == 0) dq_len = (word32)mp_unsigned_bin_size(&mp_dq);
        if (mp_ret == 0) u_len  = (word32)mp_unsigned_bin_size(&mp_u);
        if (mp_ret == 0) mp_ret = mp_to_unsigned_bin(&mp_dp, dp_buf);
        if (mp_ret == 0) mp_ret = mp_to_unsigned_bin(&mp_dq, dq_buf);
        if (mp_ret == 0) mp_ret = mp_to_unsigned_bin(&mp_u,  u_buf);

        mp_clear(&mp_d); mp_clear(&mp_p); mp_clear(&mp_q);
        mp_clear(&mp_dp); mp_clear(&mp_dq); mp_clear(&mp_u); mp_clear(&mp_tmp);

        failures += check(mp_ret == 0, "hsm_import_rsa: CRT compute (dP, dQ, u)");
        if (mp_ret != 0) { wc_FreeRsaKey(&orig); return failures; }
    }

    /* Reconstruct RsaKey from flat components -- mirrors C_CreateObject path */
    ret = wc_InitRsaKey(&reconstructed, NULL);
    failures += check(ret == 0, "hsm_import_rsa: reconstructed init");
    if (ret != 0) { wc_FreeRsaKey(&orig); return failures; }

    ret = wc_RsaPrivateKeyDecodeRaw(
        n_buf,  n_len,  e_buf,  e_len,
        d_buf,  d_len,  u_buf,  u_len,
        p_buf,  p_len,  q_buf,  q_len,
        dp_buf, dp_len, dq_buf, dq_len,
        &reconstructed);
    failures += check(ret == 0, "hsm_import_rsa: wc_RsaPrivateKeyDecodeRaw");

    if (ret == 0) {
        ret = wh_Client_RsaImportKey(&f->client, &reconstructed, &key_id,
                                      WH_NVM_FLAGS_USAGE_ANY, 0, NULL);
        failures += check(ret == 0, "hsm_import_rsa: RsaImportKey returns 0");
    }
    wc_FreeRsaKey(&reconstructed);
    if (ret != 0) { wc_FreeRsaKey(&orig); return failures; }

    /* Build oracle: public key only for encryption */
    {
        byte   e2[4];
        word32 e2_len = sizeof(e2);

        ret = wc_InitRsaKey(&pub, NULL);
        failures += check(ret == 0, "hsm_import_rsa: pub init");
        if (ret == 0) {
            ret = wc_RsaFlattenPublicKey(&orig, e2, &e2_len, n_buf, &n_len);
            if (ret == 0)
                ret = wc_RsaPublicKeyDecodeRaw(n_buf, n_len, e2, e2_len, &pub);
            failures += check(ret == 0, "hsm_import_rsa: pub key build");
        }
    }

    if (ret != 0) {
        (void)wh_Client_KeyEvict(&f->client, key_id);
        wc_FreeRsaKey(&orig);
        return failures;
    }

    /* Build handle for the server-cached reconstructed key */
    kp = wp11_wolfhsm_alloc_key_priv((void *)&f->client, (uint16_t)key_id,
                                      WP11_KEY_TYPE_RSA,
                                      (uint16_t)TEST_RSA_KEY_BYTES);
    failures += check(kp != NULL, "hsm_import_rsa: kp alloc");
    if (kp == NULL) {
        wc_FreeRsaKey(&pub);
        wc_FreeRsaKey(&orig);
        (void)wh_Client_KeyEvict(&f->client, key_id);
        return failures;
    }

    h.backend = WP11_BACKEND_WOLFHSM;
    h.id      = (uint32_t)key_id;
    h.priv    = kp;

    /* Oracle: encrypt with public key */
    ct_len = wc_RsaPublicEncrypt(plaintext, sizeof(plaintext),
                                  ciphertext, sizeof(ciphertext),
                                  &pub, &g_test_rng);
    failures += check(ct_len > 0, "hsm_import_rsa: oracle encrypt ok");

    if (ct_len > 0) {
        ret = wp11_backend_wolfhsm_ops.decrypt(&h, TEST_CKM_RSA_PKCS,
                                                ciphertext, (size_t)ct_len,
                                                recovered, &pt_len);
        failures += check(ret == 0, "hsm_import_rsa: backend decrypt ok");
        failures += check(pt_len == sizeof(plaintext),
                          "hsm_import_rsa: recovered len matches");
        failures += check(memcmp(recovered, plaintext, sizeof(plaintext)) == 0,
                          "hsm_import_rsa: recovered plaintext matches");
    }

    wc_FreeRsaKey(&pub);
    wc_FreeRsaKey(&orig);
    free_handle(&h);
    return failures;
}

/* -------------------------------------------------------------------------
 * Mock transport -- used by error-condition tests that do not need a real
 * wolfHSM server.  Send returns WH_ERROR_NOTREADY for the first
 * notready_count calls, then WH_ERROR_OK.  Recv is never expected to be
 * called in these tests (Send fails before a request is delivered).
 * ---------------------------------------------------------------------- */

typedef struct {
    int send_calls;      /* total Send invocations */
    int notready_count;  /* how many calls return WH_ERROR_NOTREADY */
} mock_send_ctx_t;

static int mock_transport_init(void *ctx, const void *cfg,
                               whCommSetConnectedCb cb, void *cb_arg)
{
    (void)ctx; (void)cfg; (void)cb; (void)cb_arg;
    return WH_ERROR_OK;
}

static int mock_transport_send(void *ctx, uint16_t size, const void *data)
{
    mock_send_ctx_t *m = (mock_send_ctx_t *)ctx;
    (void)size; (void)data;
    m->send_calls++;
    if (m->send_calls <= m->notready_count)
        return WH_ERROR_NOTREADY;
    return WH_ERROR_OK;
}

static int mock_transport_recv(void *ctx, uint16_t *size, void *data)
{
    (void)ctx; (void)size; (void)data;
    return WH_ERROR_NOTREADY;  /* should not be reached in NOTREADY tests */
}

static int mock_transport_cleanup(void *ctx)
{
    (void)ctx;
    return WH_ERROR_OK;
}

static const whTransportClientCb mock_transport_cb = {
    mock_transport_init,
    mock_transport_send,
    mock_transport_recv,
    mock_transport_cleanup,
};

/* -------------------------------------------------------------------------
 * Test 9: WH_ERROR_NOTREADY from Send -> WP11_BACKEND_ERR_NOT_READY
 *
 * When the transport's Send returns WH_ERROR_NOTREADY (send buffer full),
 * wh_Client_SendRequest propagates the error immediately to its caller.
 * The wolfP11 backend does not retry; it maps the error and returns.
 *
 * This is the executable specification for wolfP11-zel.  The check is
 * written to document the current (no-retry) behaviour.  When wolfP11-zel
 * is implemented the backend will retry and the sign will succeed; at that
 * point the mock_ctx.notready_count should be raised to a value that the
 * retry loop can exhaust before giving up.
 * ---------------------------------------------------------------------- */
static int test_hsm_error_notready(wp11_wolfhsm_fixture_t *f)
{
    mock_send_ctx_t      mock_ctx;
    whClientContext      mock_client;
    whCommClientConfig   mock_comm_cfg;
    whClientConfig       mock_client_cfg;
    wp11_wolfhsm_key_priv_t *kp;
    wp11_key_handle_t        h;
    uint8_t                  hash[WC_SHA256_DIGEST_SIZE];
    uint8_t                  sig[128];
    size_t                   sig_len = sizeof(sig);
    int                      ret;
    int                      failures = 0;

    (void)f;  /* mock client used; real fixture not needed */

    memset(hash, 0xABu, sizeof(hash));

    /* Mock: the first (and only) Send returns WH_ERROR_NOTREADY */
    memset(&mock_ctx, 0, sizeof(mock_ctx));
    mock_ctx.notready_count = 1;

    memset(&mock_comm_cfg, 0, sizeof(mock_comm_cfg));
    mock_comm_cfg.transport_cb      = &mock_transport_cb;
    mock_comm_cfg.transport_context = &mock_ctx;
    mock_comm_cfg.transport_config  = NULL;
    mock_comm_cfg.client_id         = 2u;

    memset(&mock_client_cfg, 0, sizeof(mock_client_cfg));
    mock_client_cfg.comm = &mock_comm_cfg;

    ret = wh_Client_Init(&mock_client, &mock_client_cfg);
    failures += check(ret == 0, "hsm_error_notready: mock client init");
    if (ret != 0) return failures;

    /* key_id = 1 (not erased); sign dispatches directly without import */
    kp = wp11_wolfhsm_alloc_key_priv((void *)&mock_client, 1u,
                                      WP11_KEY_TYPE_EC, 0u);
    failures += check(kp != NULL, "hsm_error_notready: kp alloc");
    if (kp == NULL) {
        wh_Client_Cleanup(&mock_client);
        return failures;
    }

    memset(&h, 0, sizeof(h));
    h.backend = WP11_BACKEND_WOLFHSM;
    h.id      = 1u;
    h.priv    = kp;

    ret = wp11_backend_wolfhsm_ops.sign(&h, TEST_CKM_ECDSA,
                                         hash, sizeof(hash), sig, &sig_len);

    /* Backend propagates NOTREADY without retry (wolfP11-zel) */
    failures += check(ret == WP11_BACKEND_ERR_NOT_READY,
                      "hsm_notready: sign returns NOT_READY (wolfP11-zel)");
    /* Exactly one Send call: confirms no retry loop in backend */
    failures += check(mock_ctx.send_calls == 1,
                      "hsm_notready: Send called once (no retry)");

    wp11_backend_wolfhsm_ops.free_key_priv(kp);
    wh_Client_Cleanup(&mock_client);
    return failures;
}

/* -------------------------------------------------------------------------
 * Test 10: WH_ERROR_NOTFOUND -> WP11_BACKEND_ERR_KEY_NOT_FOUND
 *
 * Import a key, evict it, then attempt to sign.  The server finds no key
 * for the stale key_id and returns WH_ERROR_NOTFOUND.  The backend must
 * map this to WP11_BACKEND_ERR_KEY_NOT_FOUND.
 * ---------------------------------------------------------------------- */
static int test_hsm_error_key_not_found(wp11_wolfhsm_fixture_t *f)
{
    ecc_key                  key;
    whKeyId                  key_id = WH_KEYID_ERASED;
    wp11_wolfhsm_key_priv_t *kp;
    wp11_key_handle_t        h;
    uint8_t                  hash[WC_SHA256_DIGEST_SIZE];
    uint8_t                  sig[128];
    size_t                   sig_len = sizeof(sig);
    int                      ret;
    int                      failures = 0;

    memset(hash, 0xABu, sizeof(hash));

    /* Import a fresh EC key to the server RAM cache (not committed to NVM) */
    ret = wc_ecc_init(&key);
    if (ret != 0) {
        failures += check(0, "hsm_error_notfound: ecc init");
        return failures;
    }
    ret = wc_ecc_make_key(&g_test_rng, 32, &key);
    if (ret != 0) {
        wc_ecc_free(&key);
        failures += check(0, "hsm_error_notfound: ecc make_key");
        return failures;
    }
    ret = wh_Client_EccImportKey(&f->client, &key, &key_id,
                                  WH_NVM_FLAGS_USAGE_ANY, 0, NULL);
    wc_ecc_free(&key);
    failures += check(ret == 0, "hsm_error_notfound: key import");
    if (ret != 0) return failures;

    /* Evict the key -- key_id is now stale (not in cache, not in NVM) */
    (void)wh_Client_KeyEvict(&f->client, key_id);

    /* Build a handle that references the evicted key_id */
    kp = wp11_wolfhsm_alloc_key_priv((void *)&f->client, (uint16_t)key_id,
                                      WP11_KEY_TYPE_EC, 0u);
    failures += check(kp != NULL, "hsm_error_notfound: kp alloc");
    if (kp == NULL) return failures;

    memset(&h, 0, sizeof(h));
    h.backend = WP11_BACKEND_WOLFHSM;
    h.id      = (uint32_t)key_id;
    h.priv    = kp;

    ret = wp11_backend_wolfhsm_ops.sign(&h, TEST_CKM_ECDSA,
                                         hash, sizeof(hash), sig, &sig_len);

    /* Server returns WH_ERROR_NOTFOUND; backend maps to KEY_NOT_FOUND */
    failures += check(ret == WP11_BACKEND_ERR_KEY_NOT_FOUND,
                      "hsm_error_notfound: sign returns KEY_NOT_FOUND");

    wp11_backend_wolfhsm_ops.free_key_priv(kp);
    return failures;
}

/* -------------------------------------------------------------------------
 * Test 11: Unsupported mechanism -> WP11_BACKEND_ERR_NOT_IMPL
 *
 * The backend rejects unknown CKM_* values before reaching wolfHSM.
 * No server round-trip occurs; return is immediate.
 * ---------------------------------------------------------------------- */
static int test_hsm_error_unsupported_mechanism(wp11_wolfhsm_fixture_t *f)
{
    wp11_wolfhsm_key_priv_t  fake_kp;
    wp11_key_handle_t         h;
    uint8_t                   in[WC_SHA256_DIGEST_SIZE];
    uint8_t                   out[128];
    size_t                    out_len = sizeof(out);
    int                       ret;
    int                       failures = 0;

    memset(in, 0xABu, sizeof(in));

    /* Minimal valid kp -- no wolfHSM call will be made */
    memset(&fake_kp, 0, sizeof(fake_kp));
    fake_kp.ctx      = (void *)&f->client;
    fake_kp.key_id   = 1u;
    fake_kp.key_type = WP11_KEY_TYPE_EC;
    fake_kp.key_size = 0u;

    memset(&h, 0, sizeof(h));
    h.backend = WP11_BACKEND_WOLFHSM;
    h.id      = 1u;
    h.priv    = &fake_kp;

    ret = wp11_backend_wolfhsm_ops.sign(&h, 0xDEADBEEFu,
                                         in, sizeof(in), out, &out_len);
    failures += check(ret == WP11_BACKEND_ERR_NOT_IMPL,
                      "hsm_unsupported_mech: sign returns NOT_IMPL");

    ret = wp11_backend_wolfhsm_ops.verify(&h, 0xDEADBEEFu,
                                           in, sizeof(in), out, out_len);
    failures += check(ret == WP11_BACKEND_ERR_NOT_IMPL,
                      "hsm_unsupported_mech: verify returns NOT_IMPL");

    out_len = sizeof(out);
    ret = wp11_backend_wolfhsm_ops.decrypt(&h, 0xDEADBEEFu,
                                            in, sizeof(in), out, &out_len);
    failures += check(ret == WP11_BACKEND_ERR_NOT_IMPL,
                      "hsm_unsupported_mech: decrypt returns NOT_IMPL");

    return failures;
}

/* -------------------------------------------------------------------------
 * Suite entry point
 * ---------------------------------------------------------------------- */

int wp11_test_backend_wolfhsm(void)
{
    wp11_wolfhsm_fixture_t f;
    int failures = 0;
    int ret;

    /* One-time RNG init for key generation */
    if (wc_InitRng(&g_test_rng) != 0) {
        printf("FAIL: wolfhsm_backend: RNG init\n");
        return 1;
    }

    ret = fixture_init(&f);
    if (ret != 0) {
        printf("FAIL: wolfhsm_backend: fixture_init failed (%d)\n", ret);
        wc_FreeRng(&g_test_rng);
        return 1;
    }

    failures += test_hsm_sign_ecdsa_p256(&f);
    failures += test_hsm_verify_ecdsa_p256(&f);
    failures += test_hsm_decrypt_rsa_pkcs1(&f);
    failures += test_hsm_derive_ecdh_p256(&f);
    failures += test_hsm_server_gen_ec_p256(&f);
    failures += test_hsm_server_gen_rsa2048(&f);
    failures += test_hsm_import_ec_private(&f);
    failures += test_hsm_import_rsa_private(&f);
    failures += test_hsm_error_notready(&f);
    failures += test_hsm_error_key_not_found(&f);
    failures += test_hsm_error_unsupported_mechanism(&f);

    fixture_cleanup(&f);
    wc_FreeRng(&g_test_rng);
    return failures;
}

#else /* !(WOLFP11_CFG_TEST && WOLFP11_CFG_WOLFHSM_BACKEND) */

int wp11_test_backend_wolfhsm(void) { return 0; }

#endif /* WOLFP11_CFG_TEST && WOLFP11_CFG_WOLFHSM_BACKEND */
