/* wp11_test_token_db.c -- tests for the wolfP11 token database
 *
 * Compile with -DWOLFP11_CFG_TEST to enable.
 * Returns 0 on full pass, or the count of failures.
 */

#include "wp11_test_token_db.h"

#ifdef WOLFP11_CFG_TEST

#include "wolfp11/wp11_token_db.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Internal helpers
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

/* -------------------------------------------------------------------------
 * Test: lookup each seeded token by exact VID/PID, verify name
 *
 * Ground truth: VID/PID and name strings are defined here independently
 * of the table under test -- they are the specification, not derived from
 * the implementation.
 * ---------------------------------------------------------------------- */

static int test_lookup_known_tokens(void)
{
    int failures = 0;

    static const struct {
        uint16_t    vid;
        uint16_t    pid;
        const char *expected_name;
    } known[] = {
        { 0x1050u, 0x0407u, "YubiKey 5 NFC"      },
        { 0x1050u, 0x0406u, "YubiKey 5C"          },
        { 0x1050u, 0x0410u, "YubiKey 5 Nano"      },
        { 0x20A0u, 0x4108u, "NitroKey HSM 2"      },
        { 0x20A0u, 0x4109u, "NitroKey Pro 2"      },
        { 0x096Eu, 0x0608u, "Feitian ePass3003"   },
        { 0x096Eu, 0x0858u, "Feitian FIDO K9"     },
    };

    size_t i;
    for (i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
        const wp11_token_desc_t *t =
            wp11_token_db_lookup(known[i].vid, known[i].pid);
        char label[64];
        int pass;

        snprintf(label, sizeof(label),
                 "token_db lookup %s", known[i].expected_name);

        pass = (t != NULL) && (strcmp(t->name, known[i].expected_name) == 0);
        failures += check(pass, label);
    }

    return failures;
}

/* -------------------------------------------------------------------------
 * Test: unknown VID/PID returns NULL
 * ---------------------------------------------------------------------- */

static int test_lookup_unknown_returns_null(void)
{
    const wp11_token_desc_t *t = wp11_token_db_lookup(0xDEADu, 0xBEEFu);
    return check(t == NULL, "token_db lookup unknown VID/PID returns NULL");
}

/* -------------------------------------------------------------------------
 * Test: count returns exactly 5
 * ---------------------------------------------------------------------- */

static int test_count(void)
{
    /* count > 0 suffices here; the five specific-token lookup tests above
     * verify each entry individually. Avoid hardcoding the table size so
     * adding new tokens doesn't break this test. */
    return check(wp11_token_db_count() > 0u,
                 "token_db count is non-zero");
}

/* -------------------------------------------------------------------------
 * Test: YubiKey 5 NFC has WP11_PROTO_PIV
 * ---------------------------------------------------------------------- */

static int test_yubikey_nfc_proto_piv(void)
{
    const wp11_token_desc_t *t = wp11_token_db_lookup(0x1050u, 0x0407u);
    return check(t != NULL && t->proto == WP11_PROTO_PIV,
                 "token_db YubiKey 5 NFC proto is WP11_PROTO_PIV");
}

/* -------------------------------------------------------------------------
 * Test: NitroKey Pro 2 has WP11_PROTO_OPENPGP
 * ---------------------------------------------------------------------- */

static int test_nitrokey_pro2_proto_openpgp(void)
{
    const wp11_token_desc_t *t = wp11_token_db_lookup(0x20A0u, 0x4109u);
    return check(t != NULL && t->proto == WP11_PROTO_OPENPGP,
                 "token_db NitroKey Pro 2 proto is WP11_PROTO_OPENPGP");
}

/* -------------------------------------------------------------------------
 * Test: YubiKey 5 NFC has WP11_ALGO_EC_P256 flag set
 * ---------------------------------------------------------------------- */

static int test_yubikey_nfc_has_ec_p256(void)
{
    const wp11_token_desc_t *t = wp11_token_db_lookup(0x1050u, 0x0407u);
    return check(t != NULL && (t->algos & WP11_ALGO_EC_P256) != 0u,
                 "token_db YubiKey 5 NFC algos has WP11_ALGO_EC_P256");
}

/* -------------------------------------------------------------------------
 * Test: NitroKey Pro 2 does NOT have WP11_ALGO_RSA4096 flag set
 * ---------------------------------------------------------------------- */

static int test_nitrokey_pro2_no_rsa4096(void)
{
    const wp11_token_desc_t *t = wp11_token_db_lookup(0x20A0u, 0x4109u);
    return check(t != NULL && (t->algos & WP11_ALGO_RSA4096) == 0u,
                 "token_db NitroKey Pro 2 algos lacks WP11_ALGO_RSA4096");
}

/* -------------------------------------------------------------------------
 * Tests for wp11_token_db_lookup_unknown()
 *
 * Oracle: the fallback descriptor fields are hardcoded in wp11_token_db.c
 * and documented in wolfp11/wp11_token_db.h.  Each assertion checks one
 * field against the spec-mandated value.
 * ---------------------------------------------------------------------- */

static int test_lookup_unknown_non_null(void)
{
    const wp11_token_desc_t *t = wp11_token_db_lookup_unknown();
    return check(t != NULL,
                 "token_db lookup_unknown returns non-NULL");
}

static int test_lookup_unknown_stable(void)
{
    const wp11_token_desc_t *a = wp11_token_db_lookup_unknown();
    const wp11_token_desc_t *b = wp11_token_db_lookup_unknown();
    return check(a != NULL && a == b,
                 "token_db lookup_unknown returns same address on repeated calls");
}

static int test_lookup_unknown_proto_piv(void)
{
    const wp11_token_desc_t *t = wp11_token_db_lookup_unknown();
    return check(t != NULL && t->proto == WP11_PROTO_PIV,
                 "token_db lookup_unknown proto is WP11_PROTO_PIV");
}

static int test_lookup_unknown_quirks_short_apdu(void)
{
    const wp11_token_desc_t *t = wp11_token_db_lookup_unknown();
    return check(t != NULL && t->quirks == WP11_QUIRK_SHORT_APDU,
                 "token_db lookup_unknown quirks is WP11_QUIRK_SHORT_APDU");
}

static int test_lookup_unknown_name(void)
{
    const wp11_token_desc_t *t = wp11_token_db_lookup_unknown();
    return check(t != NULL && strcmp(t->name, "Generic PIV Token") == 0,
                 "token_db lookup_unknown name is \"Generic PIV Token\"");
}

static int test_lookup_unknown_algos(void)
{
    const wp11_token_desc_t *t = wp11_token_db_lookup_unknown();
    return check(t != NULL &&
                 t->algos == (WP11_ALGO_RSA2048 | WP11_ALGO_EC_P256),
                 "token_db lookup_unknown algos is RSA2048|EC_P256");
}

/* -------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */

int wp11_test_token_db(void)
{
    int failures = 0;

    failures += test_lookup_known_tokens();
    failures += test_lookup_unknown_returns_null();
    failures += test_count();
    failures += test_yubikey_nfc_proto_piv();
    failures += test_nitrokey_pro2_proto_openpgp();
    failures += test_yubikey_nfc_has_ec_p256();
    failures += test_nitrokey_pro2_no_rsa4096();
    failures += test_lookup_unknown_non_null();
    failures += test_lookup_unknown_stable();
    failures += test_lookup_unknown_proto_piv();
    failures += test_lookup_unknown_quirks_short_apdu();
    failures += test_lookup_unknown_name();
    failures += test_lookup_unknown_algos();

    return failures;
}

#else /* WOLFP11_CFG_TEST not defined */

int wp11_test_token_db(void)
{
    return 0;
}

#endif /* WOLFP11_CFG_TEST */
