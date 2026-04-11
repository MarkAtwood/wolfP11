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

/* wp11_cli.c -- wolfP11 command-line tool */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L   /* tcgetattr, tcsetattr, getpass */
#endif

#include "wolfp11/wp11_pkcs11.h"
#include "wolfp11/wp11_settings.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
#include "wolfp11/wp11_keystore.h"
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
/* wolfP11-dfv1: plain memset() can be optimised away by the compiler when
 * the buffer is not subsequently read (dead-store elimination).  cli_zero()
 * uses a volatile write loop that the compiler cannot elide, providing the
 * same guarantee as wc_ForceZero() in the wolfCrypt backends.  The CLI
 * binary links against -lwolfp11 but not -lwolfssl directly, so calling
 * wc_ForceZero() would require adding -lwolfssl to the link line; the
 * volatile loop avoids that dependency while being equally safe.
 * Guarded by WOLFP11_CFG_USB_FLASH_BACKEND because all PIN-handling code
 * is inside that guard; without it the function would be defined but unused
 * and generate a -Wunused-function error. */
static void cli_zero(void *p, size_t n)
{
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) *q++ = 0;
}
#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */

static void print_usage(void)
{
    printf("Usage: wp11 <command> [options]\n");
    printf("\n");
    printf("Commands:\n");
    printf("  list-tokens              List all token slots and their labels\n");
    printf("  list-mechanisms <slot>   List supported mechanisms for a slot\n");
    printf("  list-keys [slot]         List key objects as RFC 7512 PKCS#11 URIs\n");
    printf("  version                  Print library version\n");
    printf("  help                     Print this message\n");
#ifdef WOLFP11_CFG_USB_BACKEND
    printf("  attest <slot> <9a|9c|9d|9e>   Fetch PIV attestation certificate as PEM\n");
#endif
#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
    printf("\n");
    printf("  keystore create --key <file> --label <str> [--key ...] --output <path>\n");
    printf("  keystore import-key <path> --key <file> --label <str>\n");
    printf("  keystore remove-key <path> --label <str> | --id <hexstr>\n");
    printf("  keystore pin-change <path>\n");
    printf("  keystore cert-add <path> --label <str> --cert <file>\n");
    printf("  keystore info <path>\n");
    printf("  keystore list <path>\n");
#endif
}

static int cmd_version(void)
{
    printf("%s\n", WOLFP11_VERSION_STRING);
    return 0;
}

/* Copy a fixed-width PKCS#11 string field (space-padded, not NUL-terminated)
 * into buf and NUL-terminate it, stripping trailing spaces.
 * n is the field width; buf must hold n+1 bytes. */
/* wolfP11-bvx0 + wolfP11-g5j3: validate a decimal slot-ID string.
 * Checks syntax (decimal, no trailing chars) and range [0, WOLFP11_CFG_MAX_SLOTS).
 * Prints its own error and returns -1 on failure; sets *out and returns 0 on
 * success.  Centralises the strtoul pattern that was duplicated in three
 * CLI commands, each missing the upper-bound check. */
static int parse_slot_id(const char *str, CK_SLOT_ID *out)
{
    char          *end = NULL;
    unsigned long  v;
    errno = 0;
    v = strtoul(str, &end, 10);
    if (errno != 0 || end == str || *end != '\0') {
        fprintf(stderr, "invalid slot number: %s\n", str);
        return -1;
    }
    if (v >= (unsigned long)WOLFP11_CFG_MAX_SLOTS) {
        fprintf(stderr, "slot %lu out of range (max %lu)\n",
                v, (unsigned long)(WOLFP11_CFG_MAX_SLOTS - 1u));
        return -1;
    }
    *out = (CK_SLOT_ID)v;
    return 0;
}

static void pkcs11_str(const CK_UTF8CHAR *field, CK_ULONG n, char *buf)
{
    CK_ULONG i;
    memcpy(buf, field, n);
    buf[n] = '\0';
    for (i = n; i > 0 && buf[i - 1] == ' '; i--)
        buf[i - 1] = '\0';
}

/* Derive a short type label from slot ID and slot description.
 * Slot 0 is always the soft token.  Flash keystores use a .p11k filename
 * as their description (set by flash_scan_dir in wp11_pkcs11.c).
 * Everything else is a hardware token. */
static const char *slot_type(CK_SLOT_ID id, const char *desc)
{
    if (id == 0)                       return "soft";
    if (strstr(desc, ".p11k") != NULL) return "flash";
    return "hardware";
}

/* Build a space-separated string of the crypto operations in a mechanism's
 * flag word.  Returns a pointer to a static buffer -- suitable for one use
 * per printf call. */
static const char *mech_ops(CK_FLAGS flags)
{
    static const struct { CK_FLAGS bit; const char *name; } ops[] = {
        { CKF_SIGN,    "sign"    },
        { CKF_VERIFY,  "verify"  },
        { CKF_DECRYPT, "decrypt" },
        { CKF_ENCRYPT, "encrypt" },
        { CKF_DERIVE,  "derive"  },
    };
    static char buf[64];
    int pos = 0;
    size_t i;
    buf[0] = '\0';
    for (i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
        const char *s;
        if (!(flags & ops[i].bit)) continue;
        if (pos > 0 && pos < (int)sizeof(buf) - 1)
            buf[pos++] = ' ';
        for (s = ops[i].name; *s && pos < (int)sizeof(buf) - 1; s++)
            buf[pos++] = *s;
    }
    buf[pos] = '\0';
    return buf;
}

static int cmd_list_tokens(void)
{
    CK_FUNCTION_LIST_PTR fl = NULL;
    CK_RV rv;
    CK_SLOT_ID slots[WOLFP11_CFG_MAX_SLOTS];
    CK_ULONG nslots = WOLFP11_CFG_MAX_SLOTS;
    CK_ULONG i;

    rv = C_GetFunctionList(&fl);
    if (rv != CKR_OK || fl == NULL) {
        fprintf(stderr, "C_GetFunctionList failed: 0x%lx\n", rv);
        return 1;
    }
    rv = fl->C_Initialize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_Initialize failed: 0x%lx\n", rv);
        return 1;
    }
    rv = fl->C_GetSlotList(CK_FALSE, slots, &nslots);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_GetSlotList failed: 0x%lx\n", rv);
        fl->C_Finalize(NULL);
        return 1;
    }

    printf("Slots: %lu\n", nslots);
    printf("  %-4s  %-32s  %-8s  %-7s  %s\n",
           "Slot", "Label", "Type", "Status", "Notes");
    printf("  %-4s  %-32s  %-8s  %-7s\n",
           "----", "--------------------------------",
           "--------", "-------");

    for (i = 0; i < nslots; i++) {
        CK_SLOT_INFO  sinfo;
        CK_TOKEN_INFO tinfo;
        char desc[65];    /* slotDescription: 64 chars + NUL */
        char label[33];   /* token label: 32 chars + NUL */
        const char *type;
        int present;

        rv = fl->C_GetSlotInfo(slots[i], &sinfo);
        if (rv != CKR_OK) {
            printf("  %-4lu  (C_GetSlotInfo error: 0x%lx)\n", slots[i], rv);
            continue;
        }
        pkcs11_str(sinfo.slotDescription, 64, desc);
        type    = slot_type(slots[i], desc);
        present = (sinfo.flags & CKF_TOKEN_PRESENT) != 0;

        if (present) {
            rv = fl->C_GetTokenInfo(slots[i], &tinfo);
            if (rv != CKR_OK) {
                printf("  %-4lu  (C_GetTokenInfo error: 0x%lx)\n",
                       slots[i], rv);
                continue;
            }
            pkcs11_str(tinfo.label, 32, label);
        } else {
            /* No token inserted -- fall back to the slot description */
            strncpy(label, desc, sizeof(label) - 1);
            label[sizeof(label) - 1] = '\0';
        }

        printf("  %-4lu  %-32s  %-8s  %-7s",
               slots[i], label, type,
               present ? "present" : "absent");

        if (present && slots[i] != 0)
            printf("  PIN required");
        printf("\n");
    }

    fl->C_Finalize(NULL);
    return 0;
}

static int cmd_list_mechanisms(CK_SLOT_ID slot)
{
    CK_FUNCTION_LIST_PTR fl = NULL;
    CK_RV rv;
    CK_MECHANISM_TYPE mechs[64];
    CK_ULONG nmechs = 64;
    CK_ULONG i;

    static const struct {
        CK_MECHANISM_TYPE val;
        const char       *name;
    } names[] = {
        { CKM_RSA_PKCS,     "CKM_RSA_PKCS"     },
        { CKM_ECDSA,        "CKM_ECDSA"        },
        { CKM_ECDSA_SHA256, "CKM_ECDSA_SHA256" },
    };

    rv = C_GetFunctionList(&fl);
    if (rv != CKR_OK || fl == NULL) {
        fprintf(stderr, "C_GetFunctionList failed: 0x%lx\n", rv);
        return 1;
    }
    rv = fl->C_Initialize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_Initialize failed: 0x%lx\n", rv);
        return 1;
    }
    rv = fl->C_GetMechanismList(slot, mechs, &nmechs);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_GetMechanismList failed: 0x%lx\n", rv);
        fl->C_Finalize(NULL);
        return 1;
    }

    printf("Mechanisms for slot %lu (%lu total):\n", slot, nmechs);
    printf("  %-22s  %-22s  %s\n", "Mechanism", "Operations", "Key size");
    printf("  %-22s  %-22s  %s\n",
           "----------------------", "----------------------", "--------");

    for (i = 0; i < nmechs; i++) {
        CK_MECHANISM_INFO minfo;
        size_t j;
        const char *mname = "(unknown)";
        char keysz[32]    = "";

        for (j = 0; j < sizeof(names) / sizeof(names[0]); j++) {
            if (names[j].val == mechs[i]) {
                mname = names[j].name;
                break;
            }
        }

        rv = fl->C_GetMechanismInfo(slot, mechs[i], &minfo);
        if (rv == CKR_OK) {
            if (minfo.ulMinKeySize > 0 || minfo.ulMaxKeySize > 0) {
                snprintf(keysz, sizeof(keysz), "%lu-%lu bits",
                         minfo.ulMinKeySize, minfo.ulMaxKeySize);
            }
            printf("  %-22s  %-22s  %s\n",
                   mname, mech_ops(minfo.flags), keysz);
        } else {
            printf("  %-22s  (C_GetMechanismInfo error: 0x%lx)\n",
                   mname, rv);
        }
    }

    fl->C_Finalize(NULL);
    return 0;
}

/* -------------------------------------------------------------------------
 * cmd_list_keys [slot]
 *
 * Enumerates key objects across all slots (or a single slot) and emits one
 * RFC 7512 PKCS#11 URI per key:
 *   pkcs11:token=<label>;id=<pct-encoded>;object=<label>;type=private|public
 * ---------------------------------------------------------------------- */
static int cmd_list_keys(int argc, char *argv[])
{
    CK_FUNCTION_LIST_PTR fl = NULL;
    CK_RV rv;
    CK_SLOT_ID slots[WOLFP11_CFG_MAX_SLOTS];
    CK_ULONG nslots = WOLFP11_CFG_MAX_SLOTS;
    CK_ULONG i;
    CK_SLOT_ID filter_slot = (CK_SLOT_ID)-1;
    int filter_set = 0;
    int found_any = 0;

    if (argc >= 2) {
        if (parse_slot_id(argv[1], &filter_slot) < 0) {
            return 1;
        }
        filter_set = 1;
    }

    rv = C_GetFunctionList(&fl);
    if (rv != CKR_OK || fl == NULL) {
        fprintf(stderr, "C_GetFunctionList failed: 0x%lx\n", rv);
        return 1;
    }
    rv = fl->C_Initialize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_Initialize failed: 0x%lx\n", rv);
        return 1;
    }
    rv = fl->C_GetSlotList(CK_TRUE, slots, &nslots);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_GetSlotList failed: 0x%lx\n", rv);
        fl->C_Finalize(NULL);
        return 1;
    }

    for (i = 0; i < nslots; i++) {
        CK_SLOT_ID        sid = slots[i];
        CK_TOKEN_INFO     tinfo;
        CK_SESSION_HANDLE session;
        CK_OBJECT_HANDLE  objs[64];
        CK_ULONG          nfound;
        CK_ULONG          j;
        char              token_label[33];

        if (filter_set && sid != filter_slot)
            continue;

        rv = fl->C_GetTokenInfo(sid, &tinfo);
        if (rv != CKR_OK) continue;
        pkcs11_str(tinfo.label, 32, token_label);

        rv = fl->C_OpenSession(sid, CKF_SERIAL_SESSION, NULL, NULL, &session);
        if (rv != CKR_OK) {
            fprintf(stderr, "C_OpenSession(%lu) failed: 0x%lx\n", sid, rv);
            continue;
        }

        rv = fl->C_FindObjectsInit(session, NULL, 0);
        if (rv != CKR_OK) {
            fl->C_CloseSession(session);
            continue;
        }

        do {
            nfound = 0;
            rv = fl->C_FindObjects(session, objs, 64, &nfound);
            if (rv != CKR_OK) break;

            for (j = 0; j < nfound; j++) {
                CK_OBJECT_CLASS obj_class = 0;
                CK_ATTRIBUTE    class_attr = { CKA_CLASS, &obj_class,
                                               sizeof(obj_class) };
                CK_BYTE         id_buf[64];
                CK_UTF8CHAR     lbl_buf[33];
                CK_ATTRIBUTE    attrs[2];
                const char     *type_str;
                char            id_pct[64 * 3 + 1];
                char            lbl_str[33];
                CK_ULONG        id_len;
                CK_ULONG        lbl_len;
                CK_ULONG        k;
                int             pos;
                int             written;

                rv = fl->C_GetAttributeValue(session, objs[j],
                                              &class_attr, 1);
                if (rv != CKR_OK) continue;

                if (obj_class == CKO_PRIVATE_KEY)
                    type_str = "private";
                else if (obj_class == CKO_PUBLIC_KEY)
                    type_str = "public";
                else if (obj_class == CKO_SECRET_KEY)
                    type_str = "secret-key";
                else
                    continue;

                memset(id_buf,  0, sizeof(id_buf));
                memset(lbl_buf, 0, sizeof(lbl_buf));
                attrs[0].type       = CKA_ID;
                attrs[0].pValue     = id_buf;
                attrs[0].ulValueLen = sizeof(id_buf);
                attrs[1].type       = CKA_LABEL;
                attrs[1].pValue     = lbl_buf;
                attrs[1].ulValueLen = sizeof(lbl_buf) - 1u;

                rv = fl->C_GetAttributeValue(session, objs[j], attrs, 2);
                if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID)
                    continue;

                id_len  = (attrs[0].ulValueLen == (CK_ULONG)-1) ?
                           0u : attrs[0].ulValueLen;
                lbl_len = (attrs[1].ulValueLen == (CK_ULONG)-1) ?
                           0u : attrs[1].ulValueLen;
                if (lbl_len > 32u) lbl_len = 32u;

                /* Percent-encode CKA_ID for the URI */
                pos = 0;
                for (k = 0; k < id_len; k++) {
                    written = snprintf(id_pct + pos,
                                       sizeof(id_pct) - (size_t)pos,
                                       "%%%02X", id_buf[k]);
                    if (written < 0 || written >= (int)(sizeof(id_pct) - (size_t)pos))
                        break;
                    pos += written;
                }
                id_pct[pos] = '\0';

                /* NUL-terminate and strip trailing spaces from label */
                memcpy(lbl_str, lbl_buf, lbl_len);
                lbl_str[lbl_len] = '\0';
                for (k = lbl_len; k > 0 && lbl_str[k - 1] == ' '; k--)
                    lbl_str[k - 1] = '\0';

                printf("pkcs11:token=%s", token_label);
                if (id_len > 0)
                    printf(";id=%s", id_pct);
                if (lbl_str[0] != '\0')
                    printf(";object=%s", lbl_str);
                printf(";type=%s\n", type_str);
                found_any = 1;
            }
        } while (nfound > 0);

        fl->C_FindObjectsFinal(session);
        fl->C_CloseSession(session);
    }

    fl->C_Finalize(NULL);

    if (!found_any) {
        if (filter_set)
            printf("(no key objects in slot %lu)\n", filter_slot);
        else
            printf("(no key objects found)\n");
    }
    return 0;
}

/* =========================================================================
 * Keystore subcommands (compiled only with WOLFP11_CFG_USB_FLASH_BACKEND)
 * ========================================================================= */

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND

/* Minimum PIN length enforced at creation and PIN-change time. */
#define KS_MIN_PIN_LEN  6

/* Read a PIN from /dev/tty with echo disabled.
 * Returns the length written into buf (not including NUL), or -1 on error.
 * buf is NUL-terminated on success. */
static int read_pin(const char *prompt, char *buf, size_t bufmax)
{
    int            ttyfd;
    struct termios orig, noecho;
    ssize_t        n;
    int            ret = -1;

    ttyfd = open("/dev/tty", O_RDWR);
    if (ttyfd < 0) {
        /* No tty -- fall back to stderr prompt + stdin read (no echo control) */
        fprintf(stderr, "%s", prompt);
        fflush(stderr);
        if (fgets(buf, (int)bufmax, stdin) == NULL) {
            return -1;
        }
        n = (ssize_t)strlen(buf);
        if (n > 0 && buf[n - 1] == '\n') {
            buf[--n] = '\0';
        }
        return (int)n;
    }

    if (write(ttyfd, prompt, strlen(prompt)) < 0) {
        close(ttyfd);
        return -1;
    }

    if (tcgetattr(ttyfd, &orig) != 0) {
        close(ttyfd);
        return -1;
    }
    noecho        = orig;
    noecho.c_lflag &= ~(tcflag_t)(ECHO | ECHOE | ECHOK | ECHONL);
    if (tcsetattr(ttyfd, TCSANOW, &noecho) != 0) {
        close(ttyfd);
        return -1;
    }

    n = read(ttyfd, buf, bufmax - 1u);

    /* Restore echo before any other writes */
    tcsetattr(ttyfd, TCSANOW, &orig);
    if (write(ttyfd, "\n", 1) < 0) { /* newline since echo was off */ }

    if (n > 0) {
        if (buf[n - 1] == '\n') {
            n--;
        }
        buf[n] = '\0';
        ret = (int)n;
    }

    close(ttyfd);
    return ret;
}

/* Read the entire contents of a file into a malloc'd buffer.
 * Returns 0 on success; *data_out and *len_out are set.
 * Returns -1 on error (error message printed to stderr). */
static int read_file(const char *path, uint8_t **data_out, size_t *len_out)
{
    FILE    *f;
    uint8_t *buf;
    size_t   len;
    size_t   nread;

    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "error: cannot open '%s': %s\n", path, strerror(errno));
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "error: cannot seek '%s': %s\n", path, strerror(errno));
        fclose(f);
        return -1;
    }
    {
        long pos = ftell(f);
        if (pos < 0) {
            fprintf(stderr, "error: cannot ftell '%s': %s\n", path, strerror(errno));
            fclose(f);
            return -1;
        }
        len = (size_t)pos;
    }
    rewind(f);

    buf = (uint8_t *)malloc(len + 1u); /* +1 for safe NUL */
    if (buf == NULL) {
        fprintf(stderr, "error: out of memory reading '%s'\n", path);
        fclose(f);
        return -1;
    }

    nread = fread(buf, 1u, len, f);
    fclose(f);

    if (nread != len) {
        fprintf(stderr, "error: short read from '%s'\n", path);
        free(buf);
        return -1;
    }
    buf[len] = '\0'; /* safe NUL for PEM detection */

    *data_out = buf;
    *len_out  = len;
    return 0;
}

/* Detect whether data starts with a PEM header. */
static int is_pem(const uint8_t *data, size_t len)
{
    const char *hdr = "-----BEGIN";
    size_t      hdrlen = 10u;
    return len >= hdrlen && memcmp(data, hdr, hdrlen) == 0;
}

/* wolfP11-dyfa: Validate a CKA_LABEL string from a CLI argument.
 * Rejects empty labels, labels longer than WP11_KEYSTORE_LABEL_MAX, and
 * labels containing control characters (0x00-0x1F, DEL 0x7F).  Binary or
 * control-character labels would produce confusing output in C_GetAttributeValue
 * and could mislead label-based key lookups.
 * Returns 1 if valid, 0 if invalid (error printed to stderr). */
static int is_valid_label(const char *label)
{
    size_t i;
    size_t len = strlen(label);
    if (len == 0u) {
        fprintf(stderr, "error: label cannot be empty\n");
        return 0;
    }
    if (len > WP11_KEYSTORE_LABEL_MAX) {
        fprintf(stderr,
                "error: label too long (max %u chars, got %zu)\n",
                (unsigned)WP11_KEYSTORE_LABEL_MAX, len);
        return 0;
    }
    for (i = 0u; i < len; i++) {
        unsigned char c = (unsigned char)label[i];
        if (c < 0x20u || c == 0x7Fu) {
            fprintf(stderr,
                    "error: label contains control character 0x%02x at "
                    "position %zu\n", (unsigned)c, i);
            return 0;
        }
    }
    return 1;
}

/* Load a key from path, auto-detecting PEM vs DER.
 * On success, *der_out is a malloc'd DER buffer (caller must
 * wp11_zero + free), *key_type is set, and *derlen_out is set.
 * Returns 0 on success, -1 on failure. */
static int load_key_file(const char *path,
                          uint8_t **der_out, size_t *derlen_out,
                          int *key_type)
{
    uint8_t *raw;
    size_t   rawlen;
    uint8_t *der;
    size_t   derlen;
    int      rc;

    if (read_file(path, &raw, &rawlen) != 0) {
        return -1;
    }

    if (is_pem(raw, rawlen)) {
        rc = wp11_keystore_pem_to_der(raw, rawlen, &der, &derlen);
        /* raw PEM data is not sensitive (public file) but zeroize anyway */
        memset(raw, 0, rawlen);
        free(raw);
        if (rc != WP11_KEYSTORE_OK) {
            fprintf(stderr, "error: PEM-to-DER conversion failed (%d)\n", rc);
            return -1;
        }
    } else {
        der    = raw;
        derlen = rawlen;
    }

    rc = wp11_keystore_detect_key_type(der, derlen);
    if (rc < 0) {
        memset(der, 0, derlen);
        free(der);
        fprintf(stderr,
                "error: '%s' does not parse as an RSA or EC private key\n",
                path);
        return -1;
    }

    *der_out    = der;
    *derlen_out = derlen;
    *key_type   = rc;
    return 0;
}

/* Load a certificate from path, auto-detecting PEM vs DER.
 * On success, *der_out is a malloc'd buffer (caller must free).
 * Returns 0 on success, -1 on failure. */
static int load_cert_file(const char *path,
                            uint8_t **der_out, size_t *derlen_out)
{
    uint8_t *raw;
    size_t   rawlen;
    uint8_t *der;
    size_t   derlen;
    int      rc;

    if (read_file(path, &raw, &rawlen) != 0) {
        return -1;
    }

    if (is_pem(raw, rawlen)) {
        rc = wp11_keystore_cert_pem_to_der(raw, rawlen, &der, &derlen);
        free(raw);
        if (rc != WP11_KEYSTORE_OK) {
            fprintf(stderr, "error: certificate PEM-to-DER conversion failed (%d)\n", rc);
            return -1;
        }
    } else {
        der    = raw;
        derlen = rawlen;
    }

    *der_out    = der;
    *derlen_out = derlen;
    return 0;
}

/* Write a new keystore to tmppath then atomically rename over dst.
 * Removes tmppath on failure.
 * Returns 0 on success, -1 on failure (message printed). */
static int keystore_atomic_save(const char             *dst,
                                 const uint8_t          *pin,    size_t pinlen,
                                 const wp11_key_entry_t *entries, size_t nentries)
{
    char tmppath[PATH_MAX];
    int  rc;

    if (snprintf(tmppath, sizeof(tmppath), "%s.tmp", dst) >= (int)sizeof(tmppath)) {
        fprintf(stderr, "error: path too long\n");
        return -1;
    }

    rc = wp11_keystore_create(tmppath, pin, pinlen, entries, nentries);
    if (rc != WP11_KEYSTORE_OK) {
        fprintf(stderr, "error: failed to write keystore (%d)\n", rc);
        remove(tmppath);
        return -1;
    }

    if (rename(tmppath, dst) != 0) {
        fprintf(stderr, "error: rename failed: %s\n", strerror(errno));
        remove(tmppath);
        return -1;
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * wp11 keystore create
 * -------------------------------------------------------------------------
 * --key <file> --label <str>   (may repeat up to MAX_ENTRIES times)
 * --output <path>              (required)
 * Prompts for PIN twice (must match).
 * ---------------------------------------------------------------------- */
static int cmd_keystore_create(int argc, char *argv[])
{
    /* Collect up to MAX_ENTRIES key/label pairs. */
    const char  *key_paths[64];
    const char  *key_labels[64];
    size_t       nkeys = 0;
    const char  *outpath = NULL;
    int          i;

    /* PIN buffers */
    char pin1[128];
    char pin2[128];
    int  plen1, plen2;

    /* Built entries */
    wp11_key_entry_t entries[64];
    size_t           built = 0;
    int              ret   = 1;

    cli_zero(pin1, sizeof(pin1));
    cli_zero(pin2, sizeof(pin2));
    memset(entries, 0, sizeof(entries));

    /* Parse args: argv[0] == "create" */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            if (nkeys >= 64u) {
                fprintf(stderr, "error: too many keys (max 64)\n");
                return 1;
            }
            key_paths[nkeys] = argv[++i];
            key_labels[nkeys] = NULL; /* set when --label is parsed */
            nkeys++;
        } else if (strcmp(argv[i], "--label") == 0 && i + 1 < argc) {
            if (nkeys == 0) {
                fprintf(stderr, "error: --label before --key\n");
                return 1;
            }
            key_labels[nkeys - 1u] = argv[++i];
            if (!is_valid_label(key_labels[nkeys - 1u])) return 1;
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            outpath = argv[++i];
        } else {
            fprintf(stderr, "error: unknown option '%s'\n", argv[i]);
            return 1;
        }
    }

    if (nkeys == 0) {
        fprintf(stderr, "usage: wp11 keystore create --key <file> --label <str> "
                        "[--key ...] --output <path>\n");
        return 1;
    }
    if (outpath == NULL) {
        fprintf(stderr, "error: --output required\n");
        return 1;
    }
    for (i = 0; i < (int)nkeys; i++) {
        if (key_labels[i] == NULL) {
            fprintf(stderr, "error: --key '%s' has no --label\n", key_paths[i]);
            return 1;
        }
    }

    /* PIN input */
    plen1 = read_pin("Enter new PIN: ", pin1, sizeof(pin1));
    if (plen1 < 0) {
        fprintf(stderr, "error: could not read PIN\n");
        return 1;
    }
    if (plen1 < KS_MIN_PIN_LEN) {
        fprintf(stderr, "error: PIN must be at least %d characters\n",
                KS_MIN_PIN_LEN);
        cli_zero(pin1, sizeof(pin1));
        return 1;
    }
    plen2 = read_pin("Confirm PIN: ", pin2, sizeof(pin2));
    if (plen2 < 0 || strcmp(pin1, pin2) != 0) {
        fprintf(stderr, "error: PINs do not match\n");
        cli_zero(pin1, sizeof(pin1));
        cli_zero(pin2, sizeof(pin2));
        return 1;
    }
    cli_zero(pin2, sizeof(pin2));

    /* Load key files and build entries */
    for (i = 0; i < (int)nkeys; i++) {
        uint8_t *der = NULL;
        size_t   derlen = 0;
        int      ktype  = 0;

        if (load_key_file(key_paths[i], &der, &derlen, &ktype) != 0) {
            goto cleanup;
        }

        if (wp11_keystore_gen_id(entries[built].id) != WP11_KEYSTORE_OK) {
            memset(der, 0, derlen);
            free(der);
            fprintf(stderr, "error: failed to generate key ID\n");
            goto cleanup;
        }

        strncpy(entries[built].label, key_labels[i],
                WP11_KEYSTORE_LABEL_MAX);
        entries[built].label[WP11_KEYSTORE_LABEL_MAX] = '\0';
        entries[built].key_type  = ktype;
        entries[built].der_bytes = der;
        entries[built].der_len   = derlen;
        built++;
    }

    if (keystore_atomic_save(outpath,
                              (const uint8_t *)pin1, (size_t)plen1,
                              entries, built) != 0) {
        goto cleanup;
    }

    printf("wrote %s (%zu key%s)\n", outpath, built, built == 1u ? "" : "s");
    ret = 0;

cleanup:
    cli_zero(pin1, sizeof(pin1));
    {
        size_t j;
        for (j = 0; j < built; j++) {
            if (entries[j].der_bytes != NULL) {
                memset(entries[j].der_bytes, 0, entries[j].der_len);
                free(entries[j].der_bytes);
                entries[j].der_bytes = NULL;
            }
        }
    }
    return ret;
}

/* -------------------------------------------------------------------------
 * wp11 keystore import-key <path> --key <file> --label <str>
 * ---------------------------------------------------------------------- */
static int cmd_keystore_import_key(int argc, char *argv[])
{
    const char       *kspath  = NULL;
    const char       *keyfile = NULL;
    const char       *label   = NULL;
    wp11_keystore_t  *ks      = NULL;
    wp11_key_entry_t  entries[64];
    size_t            nentries;
    size_t            i;
    uint8_t          *newder  = NULL;
    size_t            newderlen = 0;
    int               newktype  = 0;
    char              pin[128];
    int               plen;
    int               ret = 1;
    int               rc;

    memset(entries, 0, sizeof(entries));
    cli_zero(pin, sizeof(pin));

    /* argv[0] == "import-key" */
    if (argc < 2) {
        fprintf(stderr, "usage: wp11 keystore import-key <path> "
                        "--key <file> --label <str>\n");
        return 1;
    }
    kspath = argv[1];

    for (i = 2; i < (size_t)argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < (size_t)argc) {
            keyfile = argv[++i];
        } else if (strcmp(argv[i], "--label") == 0 && i + 1 < (size_t)argc) {
            label = argv[++i];
            if (!is_valid_label(label)) return 1;
        } else {
            fprintf(stderr, "error: unknown option '%s'\n", argv[i]);
            return 1;
        }
    }

    if (keyfile == NULL || label == NULL) {
        fprintf(stderr, "error: --key and --label required\n");
        return 1;
    }

    plen = read_pin("PIN: ", pin, sizeof(pin));
    if (plen < 0) {
        fprintf(stderr, "error: could not read PIN\n");
        return 1;
    }

    rc = wp11_keystore_load(kspath, (const uint8_t *)pin, (size_t)plen, &ks);
    if (rc != WP11_KEYSTORE_OK) {
        fprintf(stderr, "error: failed to load '%s' (%d)%s\n", kspath, rc,
                rc == WP11_KEYSTORE_ERR_BAD_PIN ? " -- wrong PIN?" : "");
        goto cleanup;
    }

    nentries = wp11_keystore_count(ks);
    if (nentries >= 64u) {
        fprintf(stderr, "error: keystore already has maximum entries\n");
        goto cleanup;
    }

    /* Copy existing entries (shallow -- der_bytes pointers borrowed) */
    for (i = 0; i < nentries; i++) {
        entries[i] = *wp11_keystore_get(ks, i);
    }

    /* Load new key */
    if (load_key_file(keyfile, &newder, &newderlen, &newktype) != 0) {
        goto cleanup;
    }

    if (wp11_keystore_gen_id(entries[nentries].id) != WP11_KEYSTORE_OK) {
        fprintf(stderr, "error: failed to generate key ID\n");
        goto cleanup;
    }
    strncpy(entries[nentries].label, label, WP11_KEYSTORE_LABEL_MAX);
    entries[nentries].label[WP11_KEYSTORE_LABEL_MAX] = '\0';
    entries[nentries].key_type  = newktype;
    entries[nentries].der_bytes = newder;
    entries[nentries].der_len   = newderlen;

    if (keystore_atomic_save(kspath,
                              (const uint8_t *)pin, (size_t)plen,
                              entries, nentries + 1u) != 0) {
        goto cleanup;
    }

    printf("added '%s' to %s\n", label, kspath);
    ret = 0;

cleanup:
    cli_zero(pin, sizeof(pin));
    if (newder != NULL) {
        memset(newder, 0, newderlen);
        free(newder);
    }
    wp11_keystore_free(ks);
    return ret;
}

/* -------------------------------------------------------------------------
 * wp11 keystore remove-key <path> --label <str> | --id <hexstr>
 * ---------------------------------------------------------------------- */
static int cmd_keystore_remove_key(int argc, char *argv[])
{
    const char       *kspath    = NULL;
    const char       *by_label  = NULL;
    const char       *by_id_hex = NULL;
    wp11_keystore_t  *ks        = NULL;
    wp11_key_entry_t  entries[64];
    size_t            nentries;
    size_t            nout = 0;
    size_t            i;
    char              pin[128];
    int               plen;
    int               ret = 1;
    int               rc;
    int               found = 0;

    memset(entries, 0, sizeof(entries));
    cli_zero(pin, sizeof(pin));

    if (argc < 2) {
        fprintf(stderr, "usage: wp11 keystore remove-key <path> "
                        "--label <str> | --id <hexstr>\n");
        return 1;
    }
    kspath = argv[1];

    for (i = 2; i < (size_t)argc; i++) {
        if (strcmp(argv[i], "--label") == 0 && i + 1 < (size_t)argc) {
            by_label = argv[++i];
        } else if (strcmp(argv[i], "--id") == 0 && i + 1 < (size_t)argc) {
            by_id_hex = argv[++i];
        } else {
            fprintf(stderr, "error: unknown option '%s'\n", argv[i]);
            return 1;
        }
    }

    if (by_label == NULL && by_id_hex == NULL) {
        fprintf(stderr, "error: --label or --id required\n");
        return 1;
    }

    plen = read_pin("PIN: ", pin, sizeof(pin));
    if (plen < 0) {
        fprintf(stderr, "error: could not read PIN\n");
        return 1;
    }

    rc = wp11_keystore_load(kspath, (const uint8_t *)pin, (size_t)plen, &ks);
    if (rc != WP11_KEYSTORE_OK) {
        fprintf(stderr, "error: failed to load '%s' (%d)%s\n", kspath, rc,
                rc == WP11_KEYSTORE_ERR_BAD_PIN ? " -- wrong PIN?" : "");
        goto cleanup;
    }

    nentries = wp11_keystore_count(ks);
    for (i = 0; i < nentries; i++) {
        const wp11_key_entry_t *e = wp11_keystore_get(ks, i);
        int keep = 1;

        if (by_label != NULL && strcmp(e->label, by_label) == 0) {
            keep  = 0;
            found = 1;
        } else if (by_id_hex != NULL) {
            /* Compare hex string against binary ID */
            uint8_t id[16];
            size_t  j;
            int     ok = 1;
            size_t  hexlen = strlen(by_id_hex);

            if (hexlen == 32u) { /* 16 bytes = 32 hex chars */
                for (j = 0; j < 16u; j++) {
                    unsigned int hi, lo;
                    if (sscanf(by_id_hex + j * 2u, "%1x%1x", &hi, &lo) != 2) {
                        ok = 0; break;
                    }
                    id[j] = (uint8_t)((hi << 4) | lo);
                }
                if (ok && memcmp(e->id, id, 16u) == 0) {
                    keep  = 0;
                    found = 1;
                }
            }
        }

        if (keep) {
            entries[nout++] = *e;
        }
    }

    if (!found) {
        fprintf(stderr, "error: no matching key found\n");
        goto cleanup;
    }

    if (keystore_atomic_save(kspath,
                              (const uint8_t *)pin, (size_t)plen,
                              entries, nout) != 0) {
        goto cleanup;
    }

    printf("removed key from %s (%zu remaining)\n", kspath, nout);
    ret = 0;

cleanup:
    cli_zero(pin, sizeof(pin));
    wp11_keystore_free(ks);
    return ret;
}

/* -------------------------------------------------------------------------
 * wp11 keystore pin-change <path>
 * ---------------------------------------------------------------------- */
static int cmd_keystore_pin_change(int argc, char *argv[])
{
    const char       *kspath = NULL;
    wp11_keystore_t  *ks     = NULL;
    wp11_key_entry_t  entries[64];
    size_t            nentries;
    size_t            i;
    char              oldpin[128];
    char              newpin1[128];
    char              newpin2[128];
    int               oldplen, newplen1, newplen2;
    int               ret = 1;
    int               rc;

    memset(entries, 0, sizeof(entries));
    memset(oldpin,  0, sizeof(oldpin));
    cli_zero(newpin1, sizeof(newpin1));
    cli_zero(newpin2, sizeof(newpin2));

    if (argc < 2) {
        fprintf(stderr, "usage: wp11 keystore pin-change <path>\n");
        return 1;
    }
    kspath = argv[1];

    oldplen = read_pin("Current PIN: ", oldpin, sizeof(oldpin));
    if (oldplen < 0) {
        fprintf(stderr, "error: could not read PIN\n");
        cli_zero(oldpin, sizeof(oldpin));
        return 1;
    }

    rc = wp11_keystore_load(kspath, (const uint8_t *)oldpin, (size_t)oldplen,
                             &ks);
    if (rc != WP11_KEYSTORE_OK) {
        fprintf(stderr, "error: failed to load '%s' (%d)%s\n", kspath, rc,
                rc == WP11_KEYSTORE_ERR_BAD_PIN ? " -- wrong PIN?" : "");
        cli_zero(oldpin, sizeof(oldpin));
        return 1;
    }
    cli_zero(oldpin, sizeof(oldpin));

    newplen1 = read_pin("New PIN: ", newpin1, sizeof(newpin1));
    if (newplen1 < 0) {
        fprintf(stderr, "error: could not read new PIN\n");
        goto cleanup;
    }
    if (newplen1 < KS_MIN_PIN_LEN) {
        fprintf(stderr, "error: PIN must be at least %d characters\n",
                KS_MIN_PIN_LEN);
        goto cleanup;
    }
    newplen2 = read_pin("Confirm new PIN: ", newpin2, sizeof(newpin2));
    if (newplen2 < 0 || strcmp(newpin1, newpin2) != 0) {
        fprintf(stderr, "error: PINs do not match\n");
        goto cleanup;
    }
    cli_zero(newpin2, sizeof(newpin2));

    nentries = wp11_keystore_count(ks);
    for (i = 0; i < nentries; i++) {
        entries[i] = *wp11_keystore_get(ks, i);
    }

    if (keystore_atomic_save(kspath,
                              (const uint8_t *)newpin1, (size_t)newplen1,
                              entries, nentries) != 0) {
        goto cleanup;
    }

    printf("PIN changed for %s\n", kspath);
    ret = 0;

cleanup:
    cli_zero(newpin1, sizeof(newpin1));
    cli_zero(newpin2, sizeof(newpin2));
    wp11_keystore_free(ks);
    return ret;
}

/* -------------------------------------------------------------------------
 * wp11 keystore cert-add <path> --label <str> --cert <file>
 * ---------------------------------------------------------------------- */
static int cmd_keystore_cert_add(int argc, char *argv[])
{
    const char       *kspath    = NULL;
    const char       *by_label  = NULL;
    const char       *certfile  = NULL;
    wp11_keystore_t  *ks        = NULL;
    wp11_key_entry_t  entries[64];
    size_t            nentries;
    size_t            i;
    uint8_t          *certder   = NULL;
    size_t            certderlen = 0;
    char              pin[128];
    int               plen;
    int               ret   = 1;
    int               found = 0;
    int               rc;

    memset(entries, 0, sizeof(entries));
    cli_zero(pin, sizeof(pin));

    if (argc < 2) {
        fprintf(stderr, "usage: wp11 keystore cert-add <path> "
                        "--label <str> --cert <file>\n");
        return 1;
    }
    kspath = argv[1];

    for (i = 2; i < (size_t)argc; i++) {
        if (strcmp(argv[i], "--label") == 0 && i + 1 < (size_t)argc) {
            /* wolfP11-yr57: by_label is a LOOKUP argument, not a creation
             * argument.  Do NOT apply is_valid_label() here: a keystore
             * created programmatically (via the C API, not the CLI) may have
             * labels with bytes outside the CLI validator's accepted range.
             * The user must be able to look up and attach a certificate to
             * such keys.  is_valid_label() belongs at creation sites only
             * (cmd_keystore_create, cmd_keystore_import_key). */
            by_label = argv[++i];
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < (size_t)argc) {
            certfile = argv[++i];
        } else {
            fprintf(stderr, "error: unknown option '%s'\n", argv[i]);
            return 1;
        }
    }

    if (by_label == NULL || certfile == NULL) {
        fprintf(stderr, "error: --label and --cert required\n");
        return 1;
    }

    plen = read_pin("PIN: ", pin, sizeof(pin));
    if (plen < 0) {
        fprintf(stderr, "error: could not read PIN\n");
        return 1;
    }

    rc = wp11_keystore_load(kspath, (const uint8_t *)pin, (size_t)plen, &ks);
    if (rc != WP11_KEYSTORE_OK) {
        fprintf(stderr, "error: failed to load '%s' (%d)%s\n", kspath, rc,
                rc == WP11_KEYSTORE_ERR_BAD_PIN ? " -- wrong PIN?" : "");
        goto cleanup;
    }

    if (load_cert_file(certfile, &certder, &certderlen) != 0) {
        goto cleanup;
    }

    nentries = wp11_keystore_count(ks);
    for (i = 0; i < nentries; i++) {
        entries[i] = *wp11_keystore_get(ks, i);
        if (strcmp(entries[i].label, by_label) == 0) {
            entries[i].cert_bytes = certder;
            entries[i].cert_len   = certderlen;
            found = 1;
        }
    }

    if (!found) {
        fprintf(stderr, "error: no key with label '%s' found\n", by_label);
        goto cleanup;
    }

    if (keystore_atomic_save(kspath,
                              (const uint8_t *)pin, (size_t)plen,
                              entries, nentries) != 0) {
        goto cleanup;
    }

    printf("certificate attached to '%s' in %s\n", by_label, kspath);
    ret = 0;

cleanup:
    cli_zero(pin, sizeof(pin));
    if (certder != NULL) {
        free(certder);
    }
    wp11_keystore_free(ks);
    return ret;
}

/* -------------------------------------------------------------------------
 * wp11 keystore info <path>  -- no PIN required
 * ---------------------------------------------------------------------- */

/* File format constants (duplicated from wp11_keystore.c internals; these
 * are stable public-format offsets, safe to reference here). */
#define P11K_MAGIC    "P11K"
#define P11K_OFF_VER  4u
#define P11K_OFF_ITER 37u
#define P11K_HDR_LEN  57u

static int cmd_keystore_info(int argc, char *argv[])
{
    const char *path;
    FILE       *f;
    uint8_t     hdr[P11K_HDR_LEN];
    uint32_t    iter;

    if (argc < 2) {
        fprintf(stderr, "usage: wp11 keystore info <path>\n");
        return 1;
    }
    path = argv[1];

    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "error: cannot open '%s': %s\n", path, strerror(errno));
        return 1;
    }

    if (fread(hdr, 1u, P11K_HDR_LEN, f) != P11K_HDR_LEN) {
        fprintf(stderr, "error: '%s' is too short to be a .p11k file\n", path);
        fclose(f);
        return 1;
    }
    fclose(f);

    if (memcmp(hdr, P11K_MAGIC, 4u) != 0) {
        fprintf(stderr, "error: '%s' does not have the P11K magic header\n",
                path);
        return 1;
    }

    iter = ((uint32_t)hdr[P11K_OFF_ITER]     << 24)
         | ((uint32_t)hdr[P11K_OFF_ITER + 1] << 16)
         | ((uint32_t)hdr[P11K_OFF_ITER + 2] <<  8)
         |  (uint32_t)hdr[P11K_OFF_ITER + 3];

    printf("File:    %s\n", path);
    printf("Magic:   P11K\n");
    printf("Version: %u\n", hdr[P11K_OFF_VER]);
    printf("KDF:     PBKDF2-HMAC-SHA256, %u iterations\n", iter);
    printf("Salt:    ");
    {
        size_t j;
        for (j = 5u; j < 37u; j++) {
            printf("%02x", hdr[j]);
        }
    }
    printf("\n");
    return 0;
}

/* -------------------------------------------------------------------------
 * wp11 keystore list <path>
 * ---------------------------------------------------------------------- */
static int cmd_keystore_list(int argc, char *argv[])
{
    const char      *kspath = NULL;
    wp11_keystore_t *ks     = NULL;
    size_t           nentries;
    size_t           i;
    char             pin[128];
    int              plen;
    int              rc;

    cli_zero(pin, sizeof(pin));

    if (argc < 2) {
        fprintf(stderr, "usage: wp11 keystore list <path>\n");
        return 1;
    }
    kspath = argv[1];

    plen = read_pin("PIN: ", pin, sizeof(pin));
    if (plen < 0) {
        fprintf(stderr, "error: could not read PIN\n");
        return 1;
    }

    rc = wp11_keystore_load(kspath, (const uint8_t *)pin, (size_t)plen, &ks);
    cli_zero(pin, sizeof(pin));
    if (rc != WP11_KEYSTORE_OK) {
        fprintf(stderr, "error: failed to load '%s' (%d)%s\n", kspath, rc,
                rc == WP11_KEYSTORE_ERR_BAD_PIN ? " -- wrong PIN?" : "");
        return 1;
    }

    nentries = wp11_keystore_count(ks);
    printf("Keys: %zu\n", nentries);
    printf("  %-4s  %-32s  %-7s  %-34s  %s\n",
           "#", "Label", "Type", "ID (hex)", "Cert");
    printf("  %-4s  %-32s  %-7s  %-34s  %s\n",
           "----", "--------------------------------", "-------",
           "----------------------------------", "----");

    for (i = 0; i < nentries; i++) {
        const wp11_key_entry_t *e = wp11_keystore_get(ks, i);
        char idhex[33];
        size_t j;

        for (j = 0; j < 16u; j++) {
            snprintf(idhex + j * 2u, 3u, "%02x", e->id[j]);
        }
        idhex[32] = '\0';

        printf("  %-4zu  %-32s  %-7s  %s  %s\n",
               i,
               e->label,
               e->key_type == WP11_KEY_TYPE_EC ? "EC" : "RSA",
               idhex,
               e->cert_bytes != NULL ? "yes" : "no");
    }

    wp11_keystore_free(ks);
    return 0;
}

/* -------------------------------------------------------------------------
 * Dispatcher for 'wp11 keystore <subcommand> ...'
 * ---------------------------------------------------------------------- */
static int cmd_keystore(int argc, char *argv[])
{
    /* argv[0] == "keystore", argv[1] == subcommand */
    if (argc < 2) {
        fprintf(stderr, "usage: wp11 keystore <subcommand> [options]\n");
        fprintf(stderr, "subcommands: create, import-key, remove-key, "
                        "pin-change, cert-add, info, list\n");
        return 1;
    }

    if (strcmp(argv[1], "create") == 0) {
        return cmd_keystore_create(argc - 1, argv + 1);
    }
    if (strcmp(argv[1], "import-key") == 0) {
        return cmd_keystore_import_key(argc - 1, argv + 1);
    }
    if (strcmp(argv[1], "remove-key") == 0) {
        return cmd_keystore_remove_key(argc - 1, argv + 1);
    }
    if (strcmp(argv[1], "pin-change") == 0) {
        return cmd_keystore_pin_change(argc - 1, argv + 1);
    }
    if (strcmp(argv[1], "cert-add") == 0) {
        return cmd_keystore_cert_add(argc - 1, argv + 1);
    }
    if (strcmp(argv[1], "info") == 0) {
        return cmd_keystore_info(argc - 1, argv + 1);
    }
    if (strcmp(argv[1], "list") == 0) {
        return cmd_keystore_list(argc - 1, argv + 1);
    }

    fprintf(stderr, "unknown keystore subcommand: %s\n", argv[1]);
    return 1;
}

#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */

#ifdef WOLFP11_CFG_USB_BACKEND
#include "wolfp11/wp11_proto_piv.h"

/* Base64 alphabet used by PEM encoding */
static const char b64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Write DER certificate to stdout as a PEM block (64 chars per line). */
static int print_pem_cert(const uint8_t *der, size_t derlen)
{
    size_t i;
    int    col = 0;

    printf("-----BEGIN CERTIFICATE-----\n");
    for (i = 0; i < derlen; i += 3) {
        unsigned int b0 = (unsigned int)der[i];
        unsigned int b1 = (i + 1u < derlen) ? (unsigned int)der[i + 1u] : 0u;
        unsigned int b2 = (i + 2u < derlen) ? (unsigned int)der[i + 2u] : 0u;
        unsigned int bits = (b0 << 16) | (b1 << 8) | b2;
        int          n    = (int)(derlen - i);

        putchar(b64_chars[(bits >> 18) & 0x3Fu]);
        putchar(b64_chars[(bits >> 12) & 0x3Fu]);
        putchar((n > 1) ? b64_chars[(bits >> 6) & 0x3Fu] : '=');
        putchar((n > 2) ? b64_chars[bits & 0x3Fu] : '=');
        col += 4;
        if (col >= 64) {
            putchar('\n');
            col = 0;
        }
    }
    if (col > 0) {
        putchar('\n');
    }
    printf("-----END CERTIFICATE-----\n");
    return 0;
}

static int cmd_attest(int argc, char *argv[])
{
    CK_FUNCTION_LIST_PTR fl = NULL;
    CK_RV                rv;
    CK_SLOT_ID           slot_id;
    uint8_t              piv_slot = WP11_PIV_SLOT_AUTH; /* wolfP11-g5j3: init */
    uint8_t              der[WP11_PIV_CERT_MAX_LEN];
    size_t               derlen = sizeof(der);
    int                  rc;

    if (argc < 3) {
        fprintf(stderr, "usage: wp11 attest <slot> <9a|9c|9d|9e>\n");
        return 1;
    }

    if (parse_slot_id(argv[1], &slot_id) < 0) {
        return 1;
    }

    if (strcmp(argv[2], "9a") == 0) {
        piv_slot = WP11_PIV_SLOT_AUTH;
    } else if (strcmp(argv[2], "9c") == 0) {
        piv_slot = WP11_PIV_SLOT_SIGN;
    } else if (strcmp(argv[2], "9d") == 0) {
        piv_slot = WP11_PIV_SLOT_KEYMGMT;
    } else if (strcmp(argv[2], "9e") == 0) {
        piv_slot = WP11_PIV_SLOT_CARDAUTH;
    } else {
        fprintf(stderr, "invalid key slot: %s (expected 9a, 9c, 9d, or 9e)\n",
                argv[2]);
        return 1;
    }

    rv = C_GetFunctionList(&fl);
    if (rv != CKR_OK || fl == NULL) {
        fprintf(stderr, "C_GetFunctionList failed: 0x%lx\n", rv);
        return 1;
    }
    rv = fl->C_Initialize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_Initialize failed: 0x%lx\n", rv);
        return 1;
    }

    rc = wp11_piv_attest_slot(slot_id, piv_slot, der, &derlen);
    fl->C_Finalize(NULL);
    if (rc != 0) {
        fprintf(stderr, "attest failed: %d\n", rc);
        return 1;
    }

    return print_pem_cert(der, derlen);
}

#endif /* WOLFP11_CFG_USB_BACKEND */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage();
        return 1;
    }

    if (strcmp(argv[1], "help") == 0) {
        print_usage();
        return 0;
    }
    if (strcmp(argv[1], "version") == 0) {
        return cmd_version();
    }
    if (strcmp(argv[1], "list-tokens") == 0) {
        return cmd_list_tokens();
    }
    if (strcmp(argv[1], "list-mechanisms") == 0) {
        CK_SLOT_ID slot;
        if (argc < 3) {
            fprintf(stderr, "usage: wp11 list-mechanisms <slot>\n");
            return 1;
        }
        if (parse_slot_id(argv[2], &slot) < 0) {
            return 1;
        }
        return cmd_list_mechanisms(slot);
    }
    if (strcmp(argv[1], "list-keys") == 0) {
        return cmd_list_keys(argc - 1, argv + 1);
    }
#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
    if (strcmp(argv[1], "keystore") == 0) {
        return cmd_keystore(argc - 1, argv + 1);
    }
#endif
#ifdef WOLFP11_CFG_USB_BACKEND
    if (strcmp(argv[1], "attest") == 0) {
        return cmd_attest(argc - 1, argv + 1);
    }
#endif

    fprintf(stderr, "unknown command: %s\n", argv[1]);
    print_usage();
    return 1;
}
