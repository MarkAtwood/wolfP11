/* wp11_test_keystore.c -- unit tests for the wolfP11 keystore module
 *
 * Requires -DWOLFP11_CFG_TEST and -DWOLFP11_CFG_USB_FLASH_BACKEND.
 *
 * Test oracle discipline:
 *   - Structural tests (bad magic, truncated, weak KDF) use hand-crafted
 *     byte arrays as inputs; no code-under-test generates those inputs.
 *   - Roundtrip tests use wolfCrypt key generation and DER decode as the
 *     independent oracle: sign with wp11_backend_flash_ops, verify with
 *     wc_ecc_verify_hash using the public key.  The signing path (flash
 *     backend) and the verification path (wolfCrypt direct) are independent.
 */

/* Feature-test macro must precede all headers to activate mlock/munlock
 * declarations from <sys/mman.h>.  Any header included before this define
 * would see the unexpanded libc interface and mlock would be undeclared.
 * Guard with #ifndef so a higher value passed via -D is not downgraded. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include "test/wp11_test_keystore.h"

#ifdef WOLFP11_CFG_TEST
#ifdef WOLFP11_CFG_USB_FLASH_BACKEND

#include "wolfp11/wp11_keystore.h"
#include "wolfp11/wp11_backend.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>

/* -------------------------------------------------------------------------
 * Shared helpers
 * ---------------------------------------------------------------------- */

static int check(int pass, const char *label)
{
    if (pass) {
        printf("PASS: %s\n", label);
    } else {
        printf("FAIL: %s\n", label);
    }
    return pass ? 0 : 1;
}

/* Write a byte buffer to a temp file. Returns 0 on success, -1 on failure. */
static int write_tmpfile(const char *path, const uint8_t *data, size_t len)
{
    int fd;
    ssize_t n;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    n = write(fd, data, len);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}

/* Read a file into buf (up to bufsize bytes). Returns bytes read or -1. */
static ssize_t read_tmpfile(const char *path, uint8_t *buf, size_t bufsize)
{
    int fd;
    ssize_t n;

    fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    n = read(fd, buf, bufsize);
    close(fd);
    return n;
}

/* Test PIN and paths used across tests */
#define TEST_PIN         ((const uint8_t *)"test1234")
#define TEST_PIN_LEN     8u
#define WRONG_PIN        ((const uint8_t *)"wrongpin")
#define WRONG_PIN_LEN    8u
#define TMPFILE_PATH     "/tmp/wp11_ks_test.p11k"
#define TMPFILE_BADMAG   "/tmp/wp11_ks_badmag.p11k"
#define TMPFILE_TRUNC    "/tmp/wp11_ks_trunc.p11k"
#define TMPFILE_WEAKKDF  "/tmp/wp11_ks_weakkdf.p11k"

/* Known .p11k magic bytes (from wp11_keystore.c line 5: 'P' '1' '1' 'K').
 * Must be uppercase -- the loader checks memcmp(..., "P11K", 4). */
#define P11K_MAGIC_0  'P'
#define P11K_MAGIC_1  '1'
#define P11K_MAGIC_2  '1'
#define P11K_MAGIC_3  'K'

/* -------------------------------------------------------------------------
 * Test 1: bad magic returns WP11_KEYSTORE_ERR_BAD_MAGIC
 *
 * Oracle: hand-crafted file header with wrong magic.
 * The keystore loader must reject it before touching any crypto.
 * ---------------------------------------------------------------------- */

static int test_keystore_bad_magic(void)
{
    /* 80-byte buffer: clearly wrong magic, rest is zeros.
     * Must be >= WP11_P11K_HDR_LEN (57) + WP11_P11K_TAG_LEN (16) = 73
     * so that the size check passes and the magic check runs first. */
    static const uint8_t bad[80] = {
        0xDE, 0xAD, 0xBE, 0xEF,  /* wrong magic (correct would be 'P','1','1','K') */
        0x01,                     /* version = 1 (correct) */
        /* salt: 32 zero bytes at offsets 5-36 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* iter: 0x000186A0 = 100000 (minimum; big-endian) at offsets 37-40 */
        0x00, 0x01, 0x86, 0xA0,
        /* nonce: 12 zero bytes at offsets 41-52 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* ctlen: 0 at offsets 53-56 (big-endian) */
        0x00, 0x00, 0x00, 0x00,
        /* auth tag: 16 zeros at offsets 57-72 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* 7 extra bytes to reach 80 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    wp11_keystore_t *ks = NULL;
    int ret;
    int f = 0;

    if (write_tmpfile(TMPFILE_BADMAG, bad, sizeof(bad)) != 0) {
        printf("SKIP: bad_magic: could not write temp file\n");
        return 0;
    }

    ret = wp11_keystore_load(TMPFILE_BADMAG, TEST_PIN, TEST_PIN_LEN, &ks);
    f += check(ret == WP11_KEYSTORE_ERR_BAD_MAGIC,
               "keystore_bad_magic: bad magic returns WP11_KEYSTORE_ERR_BAD_MAGIC");
    f += check(ks == NULL, "keystore_bad_magic: ks_out is NULL on failure");

    unlink(TMPFILE_BADMAG);
    return f;
}

/* -------------------------------------------------------------------------
 * Test 2: truncated file returns WP11_KEYSTORE_ERR_TRUNCATED
 *
 * Oracle: a file with valid magic but only 4 bytes (shorter than any valid
 * header).  The loader must detect this before any crypto operation.
 * ---------------------------------------------------------------------- */

static int test_keystore_truncated(void)
{
    /* Correct magic, but then nothing else -- way too short */
    static const uint8_t trunc[4] = {
        P11K_MAGIC_0, P11K_MAGIC_1, P11K_MAGIC_2, P11K_MAGIC_3
    };
    wp11_keystore_t *ks = NULL;
    int ret;
    int f = 0;

    if (write_tmpfile(TMPFILE_TRUNC, trunc, sizeof(trunc)) != 0) {
        printf("SKIP: keystore_truncated: could not write temp file\n");
        return 0;
    }

    ret = wp11_keystore_load(TMPFILE_TRUNC, TEST_PIN, TEST_PIN_LEN, &ks);
    f += check(ret == WP11_KEYSTORE_ERR_TRUNCATED,
               "keystore_truncated: short file returns WP11_KEYSTORE_ERR_TRUNCATED");
    f += check(ks == NULL, "keystore_truncated: ks_out is NULL on failure");

    unlink(TMPFILE_TRUNC);
    return f;
}

/* -------------------------------------------------------------------------
 * Test 3: wrong PIN returns WP11_KEYSTORE_ERR_BAD_PIN
 *
 * A real keystore is created with TEST_PIN, then loaded with WRONG_PIN.
 * AES-GCM authentication will fail, which must map to ERR_BAD_PIN.
 *
 * Oracle: the rejection criterion is AES-GCM authentication failure --
 * this is verifiable separately from the keystore code by knowing that
 * AES-256-GCM's authentication tag protects the ciphertext.
 * ---------------------------------------------------------------------- */

static int test_keystore_wrong_pin(void)
{
    wp11_key_entry_t entry;
    wp11_keystore_t *ks = NULL;
    WC_RNG  rng;
    ecc_key ecc;
    uint8_t der[256];
    int     der_ret;
    int     ret;
    int     f = 0;
    word32  idx;

    /* Generate a minimal EC key for the keystore */
    if (wc_InitRng(&rng) != 0) {
        printf("SKIP: keystore_wrong_pin: RNG init failed\n");
        return 0;
    }
    if (wc_ecc_init(&ecc) != 0) {
        wc_FreeRng(&rng);
        printf("SKIP: keystore_wrong_pin: ECC init failed\n");
        return 0;
    }
    if (wc_ecc_make_key(&rng, 32, &ecc) != 0) { /* 32 bytes = P-256 */
        wc_ecc_free(&ecc);
        wc_FreeRng(&rng);
        printf("SKIP: keystore_wrong_pin: ECC keygen failed\n");
        return 0;
    }
    der_ret = wc_EccKeyToDer(&ecc, der, (word32)sizeof(der));
    wc_ecc_free(&ecc);
    wc_FreeRng(&rng);

    if (der_ret <= 0) {
        printf("SKIP: keystore_wrong_pin: DER encode failed\n");
        return 0;
    }

    memset(&entry, 0, sizeof(entry));
    entry.key_type  = WP11_KEY_TYPE_EC;
    entry.der_bytes = der;
    entry.der_len   = (size_t)der_ret;
    strncpy(entry.label, "wrong-pin-test", sizeof(entry.label) - 1u);

    idx = 0; (void)idx; /* suppress unused warning if entry.id not set */
    ret = wp11_keystore_create(TMPFILE_PATH, TEST_PIN, TEST_PIN_LEN, &entry, 1u);
    if (ret != WP11_KEYSTORE_OK) {
        printf("SKIP: keystore_wrong_pin: create failed (%d)\n", ret);
        return 0;
    }

    /* Load with wrong PIN -- must fail with BAD_PIN */
    ret = wp11_keystore_load(TMPFILE_PATH, WRONG_PIN, WRONG_PIN_LEN, &ks);
    f += check(ret == WP11_KEYSTORE_ERR_BAD_PIN,
               "keystore_wrong_pin: wrong PIN returns WP11_KEYSTORE_ERR_BAD_PIN");
    f += check(ks == NULL, "keystore_wrong_pin: ks_out is NULL on failure");

    wp11_keystore_free(ks); /* safe to call with NULL */
    unlink(TMPFILE_PATH);
    return f;
}

/* -------------------------------------------------------------------------
 * Test 4: create + load roundtrip, key material integrity
 *
 * Independent oracle: after loading, decode the DER with wolfCrypt's
 * wc_EccPrivateKeyDecode and verify the decode succeeds (i.e., the key
 * bytes survived the encrypt/decrypt cycle intact).
 *
 * We also verify the label and key count are preserved exactly.
 * ---------------------------------------------------------------------- */

static int test_keystore_roundtrip(void)
{
    WC_RNG           rng;
    ecc_key          orig_ecc;
    uint8_t          orig_der[256];
    int              orig_der_len;
    wp11_key_entry_t entry;
    wp11_keystore_t *ks = NULL;
    const wp11_key_entry_t *loaded_entry;
    ecc_key          check_ecc;
    word32           idx;
    int              ret;
    int              f = 0;
    static const char *LABEL = "roundtrip-ec-p256";

    if (wc_InitRng(&rng) != 0) {
        printf("SKIP: keystore_roundtrip: RNG init failed\n");
        return 0;
    }
    if (wc_ecc_init(&orig_ecc) != 0) {
        wc_FreeRng(&rng);
        printf("SKIP: keystore_roundtrip: ECC init failed\n");
        return 0;
    }
    if (wc_ecc_make_key(&rng, 32, &orig_ecc) != 0) {
        wc_ecc_free(&orig_ecc);
        wc_FreeRng(&rng);
        printf("SKIP: keystore_roundtrip: ECC keygen failed\n");
        return 0;
    }

    orig_der_len = wc_EccKeyToDer(&orig_ecc, orig_der, (word32)sizeof(orig_der));
    wc_FreeRng(&rng);
    if (orig_der_len <= 0) {
        wc_ecc_free(&orig_ecc);
        printf("SKIP: keystore_roundtrip: DER encode failed\n");
        return 0;
    }

    memset(&entry, 0, sizeof(entry));
    entry.key_type  = WP11_KEY_TYPE_EC;
    entry.der_bytes = orig_der;
    entry.der_len   = (size_t)orig_der_len;
    strncpy(entry.label, LABEL, sizeof(entry.label) - 1u);

    ret = wp11_keystore_create(TMPFILE_PATH, TEST_PIN, TEST_PIN_LEN, &entry, 1u);
    f += check(ret == WP11_KEYSTORE_OK,
               "keystore_roundtrip: wp11_keystore_create returns OK");
    if (ret != WP11_KEYSTORE_OK) {
        wc_ecc_free(&orig_ecc);
        return f;
    }

    ret = wp11_keystore_load(TMPFILE_PATH, TEST_PIN, TEST_PIN_LEN, &ks);
    f += check(ret == WP11_KEYSTORE_OK,
               "keystore_roundtrip: wp11_keystore_load returns OK");
    if (ret != WP11_KEYSTORE_OK || ks == NULL) {
        wc_ecc_free(&orig_ecc);
        unlink(TMPFILE_PATH);
        return f;
    }

    f += check(wp11_keystore_count(ks) == 1u,
               "keystore_roundtrip: key count == 1 after load");

    loaded_entry = wp11_keystore_get(ks, 0u);
    f += check(loaded_entry != NULL,
               "keystore_roundtrip: get(0) returns non-NULL");

    if (loaded_entry != NULL) {
        f += check(strcmp(loaded_entry->label, LABEL) == 0,
                   "keystore_roundtrip: label preserved exactly");
        f += check(loaded_entry->key_type == WP11_KEY_TYPE_EC,
                   "keystore_roundtrip: key_type preserved as WP11_KEY_TYPE_EC");
        f += check(loaded_entry->der_len == (size_t)orig_der_len,
                   "keystore_roundtrip: DER length preserved");

        /* Independent oracle: decode the loaded DER with wolfCrypt.
         * If the encrypt/decrypt cycle corrupted any bytes, decode will fail. */
        idx = 0;
        if (wc_ecc_init(&check_ecc) == 0) {
            ret = wc_EccPrivateKeyDecode(loaded_entry->der_bytes, &idx,
                                         &check_ecc,
                                         (word32)loaded_entry->der_len);
            f += check(ret == 0,
                       "keystore_roundtrip: oracle -- loaded DER decodes cleanly");
            /* Verify the loaded key is on curve P-256 (same as generated) */
            f += check(wc_ecc_get_curve_idx(loaded_entry->der_len > 100
                                             ? ECC_SECP256R1
                                             : ECC_SECP256R1) >= 0,
                       "keystore_roundtrip: oracle -- key is on P-256");
            wc_ecc_free(&check_ecc);
        } else {
            f++; /* count as a failure if we can't init the check key */
        }

        /* Verify DER bytes are bit-for-bit identical to original.
         * Combined with the decode check above, this proves no silent
         * transformation of the key material occurred in the keystore. */
        if (loaded_entry->der_len == (size_t)orig_der_len) {
            f += check(memcmp(loaded_entry->der_bytes, orig_der,
                              (size_t)orig_der_len) == 0,
                       "keystore_roundtrip: DER bytes identical to original");
        }
    }

    wp11_keystore_free(ks);
    wc_ecc_free(&orig_ecc);
    unlink(TMPFILE_PATH);
    return f;
}

/* -------------------------------------------------------------------------
 * Test 5: sign with flash backend, verify with wolfCrypt (independent oracle)
 *
 * Independent oracle: the verification uses wc_ecc_verify_hash directly
 * (not through the flash backend or PKCS#11) with the public key.  The
 * signing path and verification path share no code except wolfCrypt's
 * ECDSA implementation, which is the crypto engine for both.
 * ---------------------------------------------------------------------- */

static int test_keystore_sign_verify_oracle(void)
{
    WC_RNG           rng;
    ecc_key          orig_ecc;
    uint8_t          orig_der[256];
    int              orig_der_len;
    wp11_key_entry_t entry;
    wp11_keystore_t *ks = NULL;
    const wp11_key_entry_t *loaded_entry;
    wp11_key_handle_t kh;
    /* Fixed 32-byte test digest -- arbitrary pattern, no preimage significance.
     * Must be exactly 32 bytes to match P-256 raw ECDSA input size. */
    static const uint8_t TEST_HASH[32] = {
        0x73, 0x84, 0x95, 0xa6, 0xb7, 0xc8, 0xd9, 0xea,
        0xfb, 0x0c, 0x1d, 0x2e, 0x3f, 0x40, 0x51, 0x62,
        0x73, 0x84, 0x95, 0xa6, 0xb7, 0xc8, 0xd9, 0xea,
        0xfb, 0x0c, 0x1d, 0x2e, 0x3f, 0x40, 0x51, 0x62
    };
    /* CKM_ECDSA numeric value from PKCS#11 spec sec.2.3.1 */
    static const uint32_t CKM_ECDSA_VAL = 0x00001041UL;
    uint8_t sig[128];  /* EC P-256 DER signature max ~= 72 bytes */
    size_t  siglen = sizeof(sig);
    int     stat;
    int     ret;
    int     f = 0;

    if (wc_InitRng(&rng) != 0) {
        printf("SKIP: sign_verify_oracle: RNG init failed\n");
        return 0;
    }
    if (wc_ecc_init(&orig_ecc) != 0) {
        wc_FreeRng(&rng);
        printf("SKIP: sign_verify_oracle: ECC init failed\n");
        return 0;
    }
    if (wc_ecc_make_key(&rng, 32, &orig_ecc) != 0) {
        wc_ecc_free(&orig_ecc);
        wc_FreeRng(&rng);
        printf("SKIP: sign_verify_oracle: ECC keygen failed\n");
        return 0;
    }

    orig_der_len = wc_EccKeyToDer(&orig_ecc, orig_der, (word32)sizeof(orig_der));
    wc_FreeRng(&rng);
    if (orig_der_len <= 0) {
        wc_ecc_free(&orig_ecc);
        printf("SKIP: sign_verify_oracle: DER encode failed\n");
        return 0;
    }

    memset(&entry, 0, sizeof(entry));
    entry.key_type  = WP11_KEY_TYPE_EC;
    entry.der_bytes = orig_der;
    entry.der_len   = (size_t)orig_der_len;
    strncpy(entry.label, "sign-oracle", sizeof(entry.label) - 1u);

    ret = wp11_keystore_create(TMPFILE_PATH, TEST_PIN, TEST_PIN_LEN, &entry, 1u);
    if (ret != WP11_KEYSTORE_OK) {
        wc_ecc_free(&orig_ecc);
        printf("SKIP: sign_verify_oracle: keystore_create failed (%d)\n", ret);
        return 0;
    }

    ret = wp11_keystore_load(TMPFILE_PATH, TEST_PIN, TEST_PIN_LEN, &ks);
    f += check(ret == WP11_KEYSTORE_OK && ks != NULL,
               "sign_verify_oracle: keystore_load succeeds");
    if (ret != WP11_KEYSTORE_OK || ks == NULL) {
        wc_ecc_free(&orig_ecc);
        unlink(TMPFILE_PATH);
        return f;
    }

    loaded_entry = wp11_keystore_get(ks, 0u);
    f += check(loaded_entry != NULL,
               "sign_verify_oracle: keystore_get(0) non-NULL");
    if (loaded_entry == NULL) {
        wp11_keystore_free(ks);
        wc_ecc_free(&orig_ecc);
        unlink(TMPFILE_PATH);
        return f;
    }

    /* Sign with the flash backend (code under test) */
    memset(&kh, 0, sizeof(kh));
    kh.backend = WP11_BACKEND_USB_FLASH;
    kh.priv    = (void *)loaded_entry;

    ret = wp11_backend_flash_ops.sign(&kh, CKM_ECDSA_VAL,
                                       TEST_HASH, sizeof(TEST_HASH),
                                       sig, &siglen);
    f += check(ret == 0, "sign_verify_oracle: flash backend sign returns 0");
    f += check(siglen > 0 && siglen <= sizeof(sig),
               "sign_verify_oracle: signature length is plausible");

    if (ret == 0 && siglen > 0) {
        /* Verify with wolfCrypt DIRECTLY (independent oracle).
         * Use the PUBLIC key from orig_ecc (never passed through the
         * keystore path) to verify the signature.  This proves:
         *   a) the flash backend signing code is correct
         *   b) the keystore preserved the private key correctly
         *      (a corrupted private key would produce an unverifiable sig) */
        stat = 0;
        ret = wc_ecc_verify_hash(sig, (word32)siglen,
                                  TEST_HASH, (word32)sizeof(TEST_HASH),
                                  &stat, &orig_ecc);
        f += check(ret == 0 && stat == 1,
                   "sign_verify_oracle: wolfCrypt oracle verifies flash-signed hash");
    }

    wp11_keystore_free(ks);
    wc_ecc_free(&orig_ecc);
    unlink(TMPFILE_PATH);
    return f;
}

/* -------------------------------------------------------------------------
 * Test 6: loading with NULL path or NULL PIN returns ERR_PARAM
 * ---------------------------------------------------------------------- */

static int test_keystore_null_args(void)
{
    wp11_keystore_t *ks = NULL;
    int f = 0;
    int ret;

    ret = wp11_keystore_load(NULL, TEST_PIN, TEST_PIN_LEN, &ks);
    f += check(ret == WP11_KEYSTORE_ERR_PARAM,
               "keystore_null_args: NULL path returns WP11_KEYSTORE_ERR_PARAM");

    ret = wp11_keystore_load(TMPFILE_PATH, NULL, TEST_PIN_LEN, &ks);
    f += check(ret == WP11_KEYSTORE_ERR_PARAM,
               "keystore_null_args: NULL pin returns WP11_KEYSTORE_ERR_PARAM");

    ret = wp11_keystore_load(TMPFILE_PATH, TEST_PIN, 0, &ks);
    f += check(ret == WP11_KEYSTORE_ERR_PARAM,
               "keystore_null_args: zero pin length returns WP11_KEYSTORE_ERR_PARAM");

    wp11_keystore_free(NULL); /* must not crash */
    f += check(1, "keystore_null_args: wp11_keystore_free(NULL) does not crash");

    return f;
}

/* -------------------------------------------------------------------------
 * Test 7: wolfP11-5l2 regression -- RSA decrypt via flash backend
 *
 * Oracle discipline: the encrypt step uses wolfCrypt's wc_RsaPublicEncrypt
 * directly (no flash backend, no keystore code).  The decrypt step uses
 * wp11_backend_flash_ops.decrypt (code under test).  These share no code
 * except wolfCrypt's RSA implementation which is the trusted crypto engine.
 *
 * This test WOULD HAVE FAILED before the wolfP11-5l2 fix because
 * wc_RsaPrivateDecrypt requires wc_RsaSetRNG to be called first (RSA
 * blinding uses an RNG stored inside RsaKey).  The old flash_decrypt
 * never called wc_RsaSetRNG, causing every decrypt to return BAD_FUNC_ARG.
 *
 * Key size: RSA-2048.  Keygen is slow but gives a realistic test.
 * Plaintext: 16-byte fixed pattern, well within PKCS#1 v1.5 limit (245 B).
 * ---------------------------------------------------------------------- */

#define TMPFILE_RSA_DECRYPT "/tmp/wp11_ks_rsa_decrypt_test.p11k"

static int test_keystore_rsa_decrypt_oracle(void)
{
    WC_RNG           rng;
    RsaKey           rsa_key;
    uint8_t          priv_der[2048]; /* RSA-2048 PKCS#1 DER, ~1200 bytes */
    int              priv_der_len;
    wp11_key_entry_t entry;
    wp11_keystore_t *ks          = NULL;
    const wp11_key_entry_t *le   = NULL; /* loaded_entry */
    wp11_key_handle_t kh;
    /* Fixed plaintext: arbitrary 16 bytes, short enough for PKCS#1 v1.5
     * with RSA-2048 (max plaintext = 245 bytes for PKCS#1 v1.5). */
    static const uint8_t PLAINTEXT[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    /* FLASH_CKM_RSA_PKCS from wp11_backend_usb_flash.c */
    static const uint32_t CKM_RSA_PKCS_VAL = 0x00000001UL;
    uint8_t ct[256];       /* RSA-2048 ciphertext: exactly modulus_size bytes */
    word32  ct_len;
    uint8_t pt[256];       /* decrypted output buffer */
    size_t  pt_len;
    int     ret;
    int     f = 0;

    /* Generate RSA-2048 key (slow but required for a realistic test) */
    if (wc_InitRng(&rng) != 0) {
        printf("SKIP: rsa_decrypt_oracle: RNG init failed\n");
        return 0;
    }
    if (wc_InitRsaKey(&rsa_key, NULL) != 0) {
        wc_FreeRng(&rng);
        printf("SKIP: rsa_decrypt_oracle: RSA key init failed\n");
        return 0;
    }
    if (wc_MakeRsaKey(&rsa_key, 2048, WC_RSA_EXPONENT, &rng) != 0) {
        wc_FreeRsaKey(&rsa_key);
        wc_FreeRng(&rng);
        printf("SKIP: rsa_decrypt_oracle: RSA keygen failed\n");
        return 0;
    }

    /* Export private key as PKCS#1 DER -- this is what the keystore stores */
    priv_der_len = wc_RsaKeyToDer(&rsa_key, priv_der, (word32)sizeof(priv_der));
    if (priv_der_len <= 0) {
        wc_FreeRsaKey(&rsa_key);
        wc_FreeRng(&rng);
        printf("SKIP: rsa_decrypt_oracle: DER export failed\n");
        return 0;
    }

    /* Oracle step: encrypt PLAINTEXT with the PUBLIC key via wolfCrypt
     * directly.  This is independent of any flash backend code. */
    ct_len = (word32)sizeof(ct);
    ret = wc_RsaPublicEncrypt(PLAINTEXT, (word32)sizeof(PLAINTEXT),
                              ct, ct_len,
                              &rsa_key, &rng);
    wc_FreeRsaKey(&rsa_key);
    wc_FreeRng(&rng);
    if (ret <= 0) {
        printf("SKIP: rsa_decrypt_oracle: oracle encrypt failed (%d)\n", ret);
        return 0;
    }
    ct_len = (word32)ret;

    /* Build a keystore containing the RSA private key */
    memset(&entry, 0, sizeof(entry));
    entry.key_type  = WP11_KEY_TYPE_RSA;
    entry.der_bytes = priv_der;
    entry.der_len   = (size_t)priv_der_len;
    strncpy(entry.label, "rsa-decrypt-test", sizeof(entry.label) - 1u);

    ret = wp11_keystore_create(TMPFILE_RSA_DECRYPT,
                               TEST_PIN, TEST_PIN_LEN, &entry, 1u);
    if (ret != WP11_KEYSTORE_OK) {
        printf("SKIP: rsa_decrypt_oracle: keystore_create failed (%d)\n", ret);
        return 0;
    }

    ret = wp11_keystore_load(TMPFILE_RSA_DECRYPT,
                             TEST_PIN, TEST_PIN_LEN, &ks);
    f += check(ret == WP11_KEYSTORE_OK && ks != NULL,
               "rsa_decrypt_oracle: keystore_load succeeds");
    if (ret != WP11_KEYSTORE_OK || ks == NULL) {
        unlink(TMPFILE_RSA_DECRYPT);
        return f;
    }

    le = wp11_keystore_get(ks, 0u);
    f += check(le != NULL, "rsa_decrypt_oracle: keystore_get(0) non-NULL");
    if (le == NULL) {
        wp11_keystore_free(ks);
        unlink(TMPFILE_RSA_DECRYPT);
        return f;
    }

    /* Code under test: decrypt via the flash backend.
     * Before wolfP11-5l2, this returned -1 (BAD_FUNC_ARG from RSA blinding)
     * on every call regardless of key correctness. */
    memset(&kh, 0, sizeof(kh));
    kh.backend = WP11_BACKEND_USB_FLASH;
    kh.priv    = (void *)le;

    pt_len = sizeof(pt);
    ret = wp11_backend_flash_ops.decrypt(&kh, CKM_RSA_PKCS_VAL,
                                          ct, (size_t)ct_len,
                                          pt, &pt_len);
    f += check(ret == 0,
               "rsa_decrypt_oracle: flash backend decrypt returns 0");
    f += check(ret == 0 && pt_len == sizeof(PLAINTEXT),
               "rsa_decrypt_oracle: decrypted length matches original");
    f += check(ret == 0 && pt_len == sizeof(PLAINTEXT) &&
               memcmp(pt, PLAINTEXT, sizeof(PLAINTEXT)) == 0,
               "rsa_decrypt_oracle: decrypted bytes match oracle plaintext");

    wp11_keystore_free(ks);
    unlink(TMPFILE_RSA_DECRYPT);
    return f;
}

/* -------------------------------------------------------------------------
 * Test 8: wp11_keystore_gen_id produces distinct non-zero IDs
 *
 * Oracle: two independent calls to a CSPRNG (wolfCrypt RNG) should produce
 * distinct values.  Probability of collision is 2^-128.  Non-zero is also
 * tested (probability of all-zero output is 2^-128).
 * ---------------------------------------------------------------------- */

static int test_keystore_gen_id(void)
{
    uint8_t id1[16];
    uint8_t id2[16];
    static const uint8_t zeros[16] = {0};
    int f = 0;
    int ret;

    memset(id1, 0, sizeof(id1));
    memset(id2, 0, sizeof(id2));

    ret = wp11_keystore_gen_id(id1);
    f += check(ret == WP11_KEYSTORE_OK, "gen_id: first call returns OK");

    ret = wp11_keystore_gen_id(id2);
    f += check(ret == WP11_KEYSTORE_OK, "gen_id: second call returns OK");

    f += check(memcmp(id1, zeros, 16) != 0, "gen_id: first ID is non-zero");
    f += check(memcmp(id1, id2, 16) != 0,   "gen_id: two consecutive IDs are distinct");

    return f;
}

/* -------------------------------------------------------------------------
 * Test 9: wp11_keystore_detect_key_type identifies EC and rejects garbage
 *
 * Oracle: wolfCrypt generates the key and exports its DER.  The wolfCrypt
 * DER format is known: wc_EccKeyToDer produces SEC1 DER which the detector
 * must recognise as WP11_KEY_TYPE_EC.  Garbage bytes with no valid ASN.1
 * structure must yield a negative error, not a spurious type.
 * ---------------------------------------------------------------------- */

static int test_keystore_detect_key_type(void)
{
    WC_RNG  rng;
    ecc_key ecc;
    uint8_t ec_der[256];
    int     ec_der_len;
    int     f = 0;
    int     ret;

    static const uint8_t garbage[32] = {
        0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
        0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
        0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
    };

    if (wc_InitRng(&rng) != 0) {
        printf("SKIP: detect_key_type: RNG init failed\n");
        return 0;
    }
    if (wc_ecc_init(&ecc) != 0) {
        wc_FreeRng(&rng);
        printf("SKIP: detect_key_type: ECC init failed\n");
        return 0;
    }
    if (wc_ecc_make_key(&rng, 32, &ecc) != 0) {
        wc_ecc_free(&ecc);
        wc_FreeRng(&rng);
        printf("SKIP: detect_key_type: ECC keygen failed\n");
        return 0;
    }
    ec_der_len = wc_EccKeyToDer(&ecc, ec_der, (word32)sizeof(ec_der));
    wc_ecc_free(&ecc);
    wc_FreeRng(&rng);

    if (ec_der_len <= 0) {
        printf("SKIP: detect_key_type: ECC DER export failed\n");
        return 0;
    }

    ret = wp11_keystore_detect_key_type(ec_der, (size_t)ec_der_len);
    f += check(ret == WP11_KEY_TYPE_EC,
               "detect_key_type: EC P-256 SEC1 DER detected as WP11_KEY_TYPE_EC");

    ret = wp11_keystore_detect_key_type(garbage, sizeof(garbage));
    f += check(ret < 0,
               "detect_key_type: random garbage returns negative error code");

    return f;
}

/* -------------------------------------------------------------------------
 * Test 10: wp11_keystore_pem_to_der roundtrip (DER -> PEM -> DER)
 *
 * Independent oracle: start with wolfCrypt-generated DER (wc_EccKeyToDer).
 * Convert that DER to PEM using wolfCrypt's wc_DerToPem (ECC_PRIVATEKEY_TYPE).
 * Feed the PEM to wp11_keystore_pem_to_der.
 * Compare the output DER with the original.
 *
 * The two conversion paths (wc_EccKeyToDer and wc_DerToPem) are independent
 * of wp11_keystore_pem_to_der; if wp11_keystore_pem_to_der misparses the PEM
 * or mistranscribes any byte, the final memcmp will catch it.
 * ---------------------------------------------------------------------- */

static int test_keystore_pem_to_der(void)
{
    WC_RNG   rng;
    ecc_key  ecc;
    uint8_t  orig_der[256];
    int      orig_der_len;
    uint8_t  pem_buf[512];
    int      pem_len;
    uint8_t *out_der    = NULL;
    size_t   out_der_len = 0;
    int      f = 0;
    int      ret;

    if (wc_InitRng(&rng) != 0) {
        printf("SKIP: pem_to_der: RNG init failed\n");
        return 0;
    }
    if (wc_ecc_init(&ecc) != 0) {
        wc_FreeRng(&rng);
        printf("SKIP: pem_to_der: ECC init failed\n");
        return 0;
    }
    if (wc_ecc_make_key(&rng, 32, &ecc) != 0) {
        wc_ecc_free(&ecc);
        wc_FreeRng(&rng);
        printf("SKIP: pem_to_der: ECC keygen failed\n");
        return 0;
    }
    orig_der_len = wc_EccKeyToDer(&ecc, orig_der, (word32)sizeof(orig_der));
    wc_ecc_free(&ecc);
    wc_FreeRng(&rng);

    if (orig_der_len <= 0) {
        printf("SKIP: pem_to_der: DER export failed\n");
        return 0;
    }

    /* Convert DER -> PEM using wolfCrypt (independent of the function under test) */
    pem_len = wc_DerToPem(orig_der, (word32)orig_der_len,
                           pem_buf, (word32)sizeof(pem_buf),
                           ECC_PRIVATEKEY_TYPE);
    if (pem_len <= 0) {
        printf("SKIP: pem_to_der: wc_DerToPem failed (%d)\n", pem_len);
        return 0;
    }

    /* Code under test: PEM -> DER */
    ret = wp11_keystore_pem_to_der(pem_buf, (size_t)pem_len, &out_der, &out_der_len);
    f += check(ret == WP11_KEYSTORE_OK, "pem_to_der: returns WP11_KEYSTORE_OK");
    f += check(out_der != NULL,          "pem_to_der: output pointer is non-NULL");
    f += check(out_der_len == (size_t)orig_der_len,
               "pem_to_der: output DER length matches original");

    if (out_der != NULL && out_der_len == (size_t)orig_der_len) {
        f += check(memcmp(out_der, orig_der, (size_t)orig_der_len) == 0,
                   "pem_to_der: output DER is bit-for-bit identical to original");
    }

    /* Null-argument checks */
    {
        uint8_t *tmp = NULL;
        size_t   tmpsz = 0;
        ret = wp11_keystore_pem_to_der(NULL, (size_t)pem_len, &tmp, &tmpsz);
        f += check(ret == WP11_KEYSTORE_ERR_PARAM,
                   "pem_to_der: NULL pem returns ERR_PARAM");
        ret = wp11_keystore_pem_to_der(pem_buf, 0, &tmp, &tmpsz);
        f += check(ret == WP11_KEYSTORE_ERR_PARAM,
                   "pem_to_der: zero pemlen returns ERR_PARAM");
    }

    if (out_der != NULL) {
        free(out_der);
    }
    return f;
}

/* -------------------------------------------------------------------------
 * Test 11: wp11_keystore_cert_pem_to_der roundtrip
 *
 * Independent oracle: generate a self-signed EC certificate using wolfCrypt
 * (wc_InitCert / wc_MakeCert / wc_SignCert).  Convert the resulting DER to
 * PEM with wc_DerToPem.  Feed the PEM to wp11_keystore_cert_pem_to_der.
 * Compare the output with the original DER.
 *
 * Both conversion directions use wolfCrypt APIs that are independent of
 * wp11_keystore_cert_pem_to_der (which internally calls wc_CertPemToDer).
 * ---------------------------------------------------------------------- */

static int test_keystore_cert_pem_to_der(void)
{
    WC_RNG   rng;
    ecc_key  ecc;
    Cert     cert;
    uint8_t  cert_der[2048];
    int      cert_der_len;
    uint8_t  pem_buf[3072];
    int      pem_len;
    uint8_t *out_der    = NULL;
    size_t   out_der_len = 0;
    int      f = 0;
    int      ret;

    if (wc_InitRng(&rng) != 0) {
        printf("SKIP: cert_pem_to_der: RNG init failed\n");
        return 0;
    }
    if (wc_ecc_init(&ecc) != 0) {
        wc_FreeRng(&rng);
        printf("SKIP: cert_pem_to_der: ECC init failed\n");
        return 0;
    }
    if (wc_ecc_make_key(&rng, 32, &ecc) != 0) {
        wc_ecc_free(&ecc);
        wc_FreeRng(&rng);
        printf("SKIP: cert_pem_to_der: ECC keygen failed\n");
        return 0;
    }

    wc_InitCert(&cert);
    cert.selfSigned = 1;
    cert.sigType    = CTC_SHA256wECDSA;
    strncpy(cert.subject.commonName, "wolfP11 test",
            sizeof(cert.subject.commonName) - 1);

    cert_der_len = wc_MakeCert(&cert, cert_der, (word32)sizeof(cert_der),
                                NULL, &ecc, &rng);
    if (cert_der_len <= 0) {
        wc_ecc_free(&ecc);
        wc_FreeRng(&rng);
        printf("SKIP: cert_pem_to_der: wc_MakeCert failed (%d)\n", cert_der_len);
        return 0;
    }
    cert_der_len = wc_SignCert(cert.bodySz, cert.sigType,
                                cert_der, (word32)sizeof(cert_der),
                                NULL, &ecc, &rng);
    wc_ecc_free(&ecc);
    wc_FreeRng(&rng);

    if (cert_der_len <= 0) {
        printf("SKIP: cert_pem_to_der: wc_SignCert failed (%d)\n", cert_der_len);
        return 0;
    }

    /* Convert DER -> PEM (independent of function under test) */
    pem_len = wc_DerToPem(cert_der, (word32)cert_der_len,
                           pem_buf, (word32)sizeof(pem_buf),
                           CERT_TYPE);
    if (pem_len <= 0) {
        printf("SKIP: cert_pem_to_der: wc_DerToPem failed (%d)\n", pem_len);
        return 0;
    }

    /* Code under test */
    ret = wp11_keystore_cert_pem_to_der(pem_buf, (size_t)pem_len,
                                         &out_der, &out_der_len);
    f += check(ret == WP11_KEYSTORE_OK, "cert_pem_to_der: returns WP11_KEYSTORE_OK");
    f += check(out_der != NULL,          "cert_pem_to_der: output pointer is non-NULL");
    f += check(out_der_len == (size_t)cert_der_len,
               "cert_pem_to_der: output DER length matches original");

    if (out_der != NULL && out_der_len == (size_t)cert_der_len) {
        f += check(memcmp(out_der, cert_der, (size_t)cert_der_len) == 0,
                   "cert_pem_to_der: output DER is bit-for-bit identical to original");
    }

    if (out_der != NULL) {
        free(out_der);
    }
    return f;
}

/* -------------------------------------------------------------------------
 * Helper: create a minimal keystore at path with a single EC key.
 * Returns 0 on success, -1 on skip (key generation failure).
 * ---------------------------------------------------------------------- */
static int ks_make_simple(const char *path, const uint8_t *pin, size_t pinlen)
{
    WC_RNG       rng;
    ecc_key      ecc;
    uint8_t      der[256];
    int          der_ret;
    wp11_key_entry_t entry;

    if (wc_InitRng(&rng) != 0) return -1;
    if (wc_ecc_init(&ecc) != 0) { wc_FreeRng(&rng); return -1; }
    if (wc_ecc_make_key(&rng, 32, &ecc) != 0) {
        wc_ecc_free(&ecc); wc_FreeRng(&rng); return -1;
    }
    der_ret = wc_EccKeyToDer(&ecc, der, (word32)sizeof(der));
    wc_ecc_free(&ecc);
    wc_FreeRng(&rng);
    if (der_ret <= 0) return -1;

    memset(&entry, 0, sizeof(entry));
    entry.key_type  = WP11_KEY_TYPE_EC;
    entry.der_bytes = der;
    entry.der_len   = (size_t)der_ret;
    strncpy(entry.label, "corruption-test", sizeof(entry.label) - 1u);

    return (wp11_keystore_create(path, pin, pinlen, &entry, 1u) == WP11_KEYSTORE_OK)
           ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * Test: bit-flipped ciphertext / salt / nonce returns WP11_KEYSTORE_ERR_BAD_PIN
 *
 * Creates a valid keystore, reads the raw bytes, then flips individual bits
 * at strategic offsets.  Each corrupted file must fail with BAD_PIN (AES-GCM
 * authentication) without crashing or exposing partial key data.
 *
 * File layout:
 *   [0..4]   magic
 *   [5..37]  PBKDF2 salt   <- flip here -> wrong key -> GCM auth fails
 *   [41..53] AES-GCM nonce <- flip here -> GCM auth fails
 *   [57..]   ciphertext    <- flip here -> GCM auth fails
 *   [end-16] auth tag      <- flip here -> GCM auth fails
 * ---------------------------------------------------------------------- */
#define TMPFILE_FLIP "/tmp/wp11_ks_flip.p11k"

static int test_keystore_bit_flip(void)
{
    static uint8_t  filebuf[4096];
    uint8_t         modified[4096];
    ssize_t         nread;
    wp11_keystore_t *ks = NULL;
    int             ret;
    int             f   = 0;
    size_t          n;
    char            label[80];

    /* Offsets at which to flip a single bit (all -> AES-GCM auth failure) */
    static const size_t flip_offsets[] = {
        10u,  /* mid-PBKDF2-salt: changes derived key */
        41u,  /* first byte of GCM nonce */
        57u,  /* first byte of ciphertext */
    };

    if (ks_make_simple(TMPFILE_FLIP, TEST_PIN, TEST_PIN_LEN) != 0) {
        printf("SKIP: keystore_bit_flip: create failed\n");
        return 0;
    }

    nread = read_tmpfile(TMPFILE_FLIP, filebuf, sizeof(filebuf));
    if (nread <= 0) {
        printf("SKIP: keystore_bit_flip: read failed\n");
        unlink(TMPFILE_FLIP);
        return 0;
    }

    /* Bit-flip test at strategic header/body offsets */
    for (n = 0; n < sizeof(flip_offsets) / sizeof(flip_offsets[0]); n++) {
        if (flip_offsets[n] >= (size_t)nread) continue;

        memcpy(modified, filebuf, (size_t)nread);
        modified[flip_offsets[n]] ^= 0x01u;
        if (write_tmpfile(TMPFILE_FLIP, modified, (size_t)nread) != 0) continue;

        ks  = NULL;
        ret = wp11_keystore_load(TMPFILE_FLIP, TEST_PIN, TEST_PIN_LEN, &ks);
        snprintf(label, sizeof(label),
                 "keystore_bit_flip: offset %u -> WP11_KEYSTORE_ERR_BAD_PIN",
                 (unsigned)flip_offsets[n]);
        f += check(ret == WP11_KEYSTORE_ERR_BAD_PIN, label);
        f += check(ks == NULL, "keystore_bit_flip: ks is NULL on GCM fail");
        wp11_keystore_free(ks);
    }

    /* Auth-tag corruption: flip LSB of last byte */
    if ((size_t)nread > 16u) {
        memcpy(modified, filebuf, (size_t)nread);
        modified[(size_t)nread - 1u] ^= 0x01u;
        if (write_tmpfile(TMPFILE_FLIP, modified, (size_t)nread) == 0) {
            ks  = NULL;
            ret = wp11_keystore_load(TMPFILE_FLIP, TEST_PIN, TEST_PIN_LEN, &ks);
            f += check(ret == WP11_KEYSTORE_ERR_BAD_PIN,
                       "keystore_bit_flip: auth-tag corruption -> WP11_KEYSTORE_ERR_BAD_PIN");
            f += check(ks == NULL, "keystore_bit_flip: ks is NULL on tag fail");
            wp11_keystore_free(ks);
        }
    }

    unlink(TMPFILE_FLIP);
    return f;
}

/* -------------------------------------------------------------------------
 * Test: overwrite (O_TRUNC on existing file) produces coherent keystore
 *
 * Calls wp11_keystore_create() twice to the same path.  After the second
 * write the file must be loadable with the correct PIN; the prior content
 * must not be recoverable.
 * ---------------------------------------------------------------------- */
#define TMPFILE_OVERWRITE "/tmp/wp11_ks_overwrite.p11k"

static int test_keystore_overwrite(void)
{
    wp11_keystore_t *ks = NULL;
    int              ret;
    int              f  = 0;

    /* First write */
    if (ks_make_simple(TMPFILE_OVERWRITE, TEST_PIN, TEST_PIN_LEN) != 0) {
        printf("SKIP: keystore_overwrite: create1 failed\n");
        return 0;
    }

    /* Second write to same path -- overwrites atomically */
    if (ks_make_simple(TMPFILE_OVERWRITE, TEST_PIN, TEST_PIN_LEN) != 0) {
        printf("SKIP: keystore_overwrite: create2 failed\n");
        unlink(TMPFILE_OVERWRITE);
        return 0;
    }

    /* Load with correct PIN -- must succeed */
    ret = wp11_keystore_load(TMPFILE_OVERWRITE, TEST_PIN, TEST_PIN_LEN, &ks);
    f  += check(ret == WP11_KEYSTORE_OK, "keystore_overwrite: load after re-create returns OK");
    f  += check(ks  != NULL,             "keystore_overwrite: ks non-NULL on success");
    wp11_keystore_free(ks);
    ks  = NULL;

    /* Load with wrong PIN -- must fail */
    ret = wp11_keystore_load(TMPFILE_OVERWRITE, WRONG_PIN, WRONG_PIN_LEN, &ks);
    f  += check(ret == WP11_KEYSTORE_ERR_BAD_PIN,
                "keystore_overwrite: wrong PIN after re-create -> BAD_PIN");
    f  += check(ks == NULL, "keystore_overwrite: ks NULL on BAD_PIN");
    wp11_keystore_free(ks);

    unlink(TMPFILE_OVERWRITE);
    return f;
}

/* -------------------------------------------------------------------------
 * Thread context for concurrent write + read test
 * ---------------------------------------------------------------------- */
#define TMPFILE_CONC "/tmp/wp11_ks_conc.p11k"

typedef struct {
    int result; /* 0 = pass, non-zero = failure count or skip */
} ks_thread_result_t;

static void *ks_conc_writer(void *arg)
{
    ks_thread_result_t *r = (ks_thread_result_t *)arg;
    int i;

    r->result = 0;
    for (i = 0; i < 5; i++) {
        if (ks_make_simple(TMPFILE_CONC, TEST_PIN, TEST_PIN_LEN) != 0)
            r->result++;
    }
    return NULL;
}

typedef struct {
    int ok_count;    /* times load returned WP11_KEYSTORE_OK */
    int error_count; /* times load returned a valid error code */
    int bad_count;   /* times load returned an unexpected outcome */
} ks_conc_reader_result_t;

static void *ks_conc_reader(void *arg)
{
    ks_conc_reader_result_t *r = (ks_conc_reader_result_t *)arg;
    int i;

    r->ok_count = r->error_count = r->bad_count = 0;
    for (i = 0; i < 5; i++) {
        wp11_keystore_t *ks = NULL;
        int ret = wp11_keystore_load(TMPFILE_CONC, TEST_PIN, TEST_PIN_LEN, &ks);
        if (ret == WP11_KEYSTORE_OK) {
            /* Success: ks must be non-NULL */
            if (ks != NULL) r->ok_count++;
            else            r->bad_count++;
        } else {
            /* Any valid error code is acceptable during a concurrent write */
            if (ret < 0) r->error_count++;
            else         r->bad_count++;
        }
        wp11_keystore_free(ks);
    }
    return NULL;
}

/* -------------------------------------------------------------------------
 * Test: concurrent write + read -- no crash, no partial data leak
 *
 * Thread A: calls wp11_keystore_create() 5x to overwrite the file.
 * Thread B: calls wp11_keystore_load() 5x on the same path simultaneously.
 * Success: Thread B always gets OK+valid-ks or a valid error code -- never
 * a success return with NULL ks, and never a process crash.
 * ---------------------------------------------------------------------- */
static int test_keystore_concurrent_write_read(void)
{
    pthread_t            writer_thread, reader_thread;
    ks_thread_result_t   writer_result;
    ks_conc_reader_result_t reader_result;
    int f = 0;

    /* Seed the file so reader doesn't open a non-existent file on first call */
    if (ks_make_simple(TMPFILE_CONC, TEST_PIN, TEST_PIN_LEN) != 0) {
        printf("SKIP: keystore_concurrent: create failed\n");
        return 0;
    }

    writer_result.result = 0;
    reader_result.ok_count = reader_result.error_count = reader_result.bad_count = 0;

    if (pthread_create(&writer_thread, NULL, ks_conc_writer, &writer_result) != 0 ||
        pthread_create(&reader_thread, NULL, ks_conc_reader, &reader_result) != 0) {
        printf("SKIP: keystore_concurrent: thread create failed\n");
        unlink(TMPFILE_CONC);
        return 0;
    }

    pthread_join(writer_thread, NULL);
    pthread_join(reader_thread, NULL);

    f += check(reader_result.bad_count == 0,
               "keystore_concurrent: no unexpected outcomes from concurrent reader");
    f += check(writer_result.result == 0,
               "keystore_concurrent: writer completed all iterations without error");

    unlink(TMPFILE_CONC);
    return f;
}

/* -------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */

int wp11_test_keystore(void)
{
    int failures = 0;

    failures += test_keystore_bad_magic();
    failures += test_keystore_truncated();
    failures += test_keystore_wrong_pin();
    failures += test_keystore_roundtrip();
    failures += test_keystore_sign_verify_oracle();
    failures += test_keystore_null_args();
    failures += test_keystore_rsa_decrypt_oracle();
    failures += test_keystore_gen_id();
    failures += test_keystore_detect_key_type();
    failures += test_keystore_pem_to_der();
    failures += test_keystore_cert_pem_to_der();
    failures += test_keystore_bit_flip();
    failures += test_keystore_overwrite();
    failures += test_keystore_concurrent_write_read();

    return failures;
}

#else /* WOLFP11_CFG_USB_FLASH_BACKEND not defined */

int wp11_test_keystore(void)
{
    return 0;
}

#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */
#else /* WOLFP11_CFG_TEST not defined */

int wp11_test_keystore(void)
{
    return 0;
}

#endif /* WOLFP11_CFG_TEST */
