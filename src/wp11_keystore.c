/* wp11_keystore.c -- wolfP11 encrypted keystore implementation
 *
 * .p11k file format (from ~/soft_PKCS11/usb-hsm/src/keystore.rs):
 *
 *   [0..4]    magic: 'P' '1' '1' 'K'     (0x50 0x31 0x31 0x4B)
 *   [4]       version: 0x01
 *   [5..37]   PBKDF2 salt (32 bytes, random)
 *   [37..41]  PBKDF2 iterations (u32 big-endian; minimum WP11_KEYSTORE_MIN_KDF_ITER)
 *   [41..53]  AES-256-GCM nonce (12 bytes, random)
 *   [53..57]  ciphertext length (u32 big-endian)
 *   [57 .. 57+ctlen]     AES-256-GCM ciphertext
 *   [57+ctlen .. +16]    AES-256-GCM authentication tag (16 bytes)
 *
 * Ciphertext decrypts to a CBOR-encoded array of key entries.
 * Each entry is a CBOR map with text keys: "id", "label", "key_type", "der_bytes".
 *
 * CBOR codec: purpose-built minimal encoder/decoder for this exact structure.
 * No external CBOR library: the payload structure is fixed (4 fields per entry),
 * a custom bounded parser is ~200 lines and easier to audit than a general library.
 */
#define _POSIX_C_SOURCE 200112L  /* mlock, munlock */

#include "wolfp11/wp11_keystore.h"
#include "wolfp11/wp11_settings.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/pwdbased.h>    /* wc_PBKDF2 */
#include <wolfssl/wolfcrypt/aes.h>         /* wc_AesGcmEncrypt/Decrypt */
#include <wolfssl/wolfcrypt/random.h>      /* WC_RNG, wc_RNG_GenerateBlock */
#include <wolfssl/wolfcrypt/sha256.h>      /* WC_SHA256 constant for PBKDF2 */
#include <wolfssl/wolfcrypt/rsa.h>         /* wc_RsaPrivateKeyDecode */
#include <wolfssl/wolfcrypt/ecc.h>         /* wc_EccPrivateKeyDecode */
#include <wolfssl/wolfcrypt/asn_public.h>  /* wc_KeyPemToDer, wc_CertPemToDer */

#include <sys/mman.h>   /* mlock, munlock */
#include <sys/stat.h>   /* stat for file size */
#include <fcntl.h>      /* open, O_RDONLY */
#include <unistd.h>     /* read, close, write */
#include <stdlib.h>     /* malloc, free */
#include <string.h>     /* memcmp, memcpy, memset, strlen */
#include <stdint.h>
#include <stddef.h>
#include <errno.h>      /* EINTR */

/* -------------------------------------------------------------------------
 * Secure memory zeroization
 *
 * explicit_bzero requires _DEFAULT_SOURCE / _BSD_SOURCE which conflicts
 * with our strict _POSIX_C_SOURCE=200112L.  Using a volatile cast is the
 * C99-portable idiom that prevents compiler dead-store elimination.
 * The write through a volatile pointer is a side-effect visible to the
 * abstract machine, so the C standard forbids omitting it.
 * ---------------------------------------------------------------------- */

static void wp11_zero(void *p, size_t n)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    size_t i;
    for (i = 0; i < n; i++) {
        vp[i] = 0u;
    }
}

/* -------------------------------------------------------------------------
 * File format constants
 * ---------------------------------------------------------------------- */

#define WP11_P11K_MAGIC         "P11K"
#define WP11_P11K_MAGIC_LEN     4u
#define WP11_P11K_VERSION       0x01u

/* Header field offsets (all big-endian multibyte integers) */
#define WP11_P11K_OFF_MAGIC     0u
#define WP11_P11K_OFF_VERSION   4u
#define WP11_P11K_OFF_SALT      5u
#define WP11_P11K_OFF_ITER      37u
#define WP11_P11K_OFF_NONCE     41u
#define WP11_P11K_OFF_CTLEN     53u
#define WP11_P11K_OFF_CT        57u

#define WP11_P11K_SALT_LEN      32u
#define WP11_P11K_NONCE_LEN     12u
#define WP11_P11K_TAG_LEN       16u
#define WP11_P11K_KEY_LEN       32u   /* AES-256: 32-byte key */
#define WP11_P11K_HDR_LEN       57u   /* bytes before ciphertext */

/* Minimum acceptable PBKDF2 iteration count.
 * Below this, brute-force with commodity hardware is feasible.
 * Matches the minimum enforced by soft_PKCS11. */
#define WP11_KEYSTORE_MIN_KDF_ITER  100000u

/* Default iteration count for newly created keystores.
 * 200000 is NIST SP 800-132 guidance for password-based KDFs in 2024. */
#define WP11_KEYSTORE_KDF_ITERATIONS 200000u

/* Maximum number of key entries per keystore.
 * Prevents excessive memory allocation from a malformed/malicious file. */
#define WP11_KEYSTORE_MAX_ENTRIES    64u

/* Maximum raw CBOR payload size (plaintext after decryption).
 * 64 entries x ~4300 bytes/entry (RSA-4096 DER + overhead) = ~275 KB.
 * We use 512 KB as a safe upper bound. */
#define WP11_KEYSTORE_MAX_CT_LEN     (512u * 1024u)

/* CBOR major types (top 3 bits of initial byte) */
#define CBOR_MAJOR_UINT   0u
#define CBOR_MAJOR_BYTES  2u
#define CBOR_MAJOR_TEXT   3u
#define CBOR_MAJOR_ARRAY  4u
#define CBOR_MAJOR_MAP    5u

/* -------------------------------------------------------------------------
 * Opaque keystore struct
 * ---------------------------------------------------------------------- */

struct wp11_keystore {
    wp11_key_entry_t *entries;    /* heap-alloc'd array, mlock'd */
    size_t            count;
    size_t            mlock_size; /* total mlock'd bytes (entries array) */
};

/* -------------------------------------------------------------------------
 * Big-endian helpers -- no system dependency, no UB via memcpy approach
 * ---------------------------------------------------------------------- */

static uint32_t read_u32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8)
         |  (uint32_t)p[3];
}

static void write_u32be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t) v;
}

/* -------------------------------------------------------------------------
 * Robust read loop -- handles short reads and EINTR
 * ---------------------------------------------------------------------- */

static int read_all(int fd, uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, buf + done, len - done);
        if (n < 0) {
            if (errno == EINTR) {
                continue; /* retry on signal */
            }
            return WP11_KEYSTORE_ERR_IO;
        }
        if (n == 0) {
            return WP11_KEYSTORE_ERR_TRUNCATED; /* unexpected EOF */
        }
        done += (size_t)n;
    }
    return WP11_KEYSTORE_OK;
}

/* Robust write loop -- handles short writes and EINTR */
static int write_all(int fd, const uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, buf + done, len - done);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return WP11_KEYSTORE_ERR_IO;
        }
        if (n == 0) {
            return WP11_KEYSTORE_ERR_IO;
        }
        done += (size_t)n;
    }
    return WP11_KEYSTORE_OK;
}

/* -------------------------------------------------------------------------
 * Minimal CBOR decoder
 *
 * All functions return the number of bytes consumed (>= 1) on success, or
 * a negative WP11_KEYSTORE_ERR_* on failure.  They never read past buflen.
 * ---------------------------------------------------------------------- */

/* Read a CBOR initial byte and extract major type and the length/value.
 * *major_out: 0..7.  *value_out: the integer (array len, byte len, etc.)
 * Returns bytes consumed (1 + 0/1/2/4 for the length), or negative error. */
static int cbor_read_head(const uint8_t *buf, size_t buflen, size_t pos,
                           uint8_t *major_out, uint64_t *value_out)
{
    uint8_t  initial;
    uint8_t  info;
    uint64_t val;

    if (pos >= buflen) {
        return WP11_KEYSTORE_ERR_CBOR;
    }

    initial    = buf[pos];
    *major_out = (uint8_t)(initial >> 5);
    info       = initial & 0x1Fu;

    if (info <= 23u) {
        /* Value is encoded directly in the additional info field. */
        *value_out = (uint64_t)info;
        return 1;
    }
    else if (info == 24u) {
        /* 1-byte value follows. */
        if (pos + 1u >= buflen) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
        *value_out = (uint64_t)buf[pos + 1u];
        return 2;
    }
    else if (info == 25u) {
        /* 2-byte big-endian value follows. */
        if (pos + 2u >= buflen) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
        val  = (uint64_t)buf[pos + 1u] << 8;
        val |= (uint64_t)buf[pos + 2u];
        *value_out = val;
        return 3;
    }
    else if (info == 26u) {
        /* 4-byte big-endian value follows. */
        if (pos + 4u >= buflen) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
        val  = (uint64_t)buf[pos + 1u] << 24;
        val |= (uint64_t)buf[pos + 2u] << 16;
        val |= (uint64_t)buf[pos + 3u] <<  8;
        val |= (uint64_t)buf[pos + 4u];
        *value_out = val;
        return 5;
    }
    else {
        /* info == 27 (8-byte) or 28-31 (reserved/special) -- not used in
         * our fixed schema.  Reject to keep the parser auditable. */
        return WP11_KEYSTORE_ERR_CBOR;
    }
}

/* Read a CBOR text string at pos into dst (NUL-terminated, max dst_len bytes).
 * dst_len must include the NUL terminator (i.e., dst has dst_len bytes).
 * Returns bytes consumed or negative error. */
static int cbor_read_text(const uint8_t *buf, size_t buflen, size_t pos,
                           char *dst, size_t dst_len)
{
    uint8_t  major;
    uint64_t slen;
    int      head;

    head = cbor_read_head(buf, buflen, pos, &major, &slen);
    if (head < 0) {
        return head;
    }
    if (major != CBOR_MAJOR_TEXT) {
        return WP11_KEYSTORE_ERR_CBOR;
    }
    /* slen is the number of UTF-8 bytes; reject if it would overflow size_t
     * or the destination buffer (dst_len - 1 for the NUL terminator). */
    if (slen > (uint64_t)(SIZE_MAX - 1u)) {
        return WP11_KEYSTORE_ERR_CBOR;
    }
    if (slen >= (uint64_t)dst_len) {
        return WP11_KEYSTORE_ERR_CBOR;
    }
    /* Verify the bytes are present in the buffer. */
    if ((size_t)head + (size_t)slen > buflen - pos) {
        return WP11_KEYSTORE_ERR_CBOR;
    }
    memcpy(dst, buf + pos + (size_t)head, (size_t)slen);
    dst[(size_t)slen] = '\0';
    return (int)((size_t)head + (size_t)slen);
}

/* Read a CBOR byte string at pos into *data_out / *data_len_out.
 *
 * wolfP11-2oi: the allocated buffer is mlock()'d BEFORE the memcpy so that
 * private key DER bytes (the only CBOR byte strings in a .p11k file) are
 * never written to a page that the OS is free to swap to disk.  The order
 * is: malloc -> mlock -> memcpy.  Reversing mlock and memcpy would leave a
 * window (the memcpy itself) during which the page is pageable.
 *
 * Returns bytes consumed on success, or a negative WP11_KEYSTORE_ERR_* code.
 * On success: *data_out is heap-alloc'd AND mlock()'d; caller is responsible
 * for wp11_zero + munlock + free in that order. */
static int cbor_read_bytes_alloc(const uint8_t *buf, size_t buflen, size_t pos,
                                  uint8_t **data_out, size_t *data_len_out)
{
    uint8_t  major;
    uint64_t blen;
    int      head;
    uint8_t *data;

    head = cbor_read_head(buf, buflen, pos, &major, &blen);
    if (head < 0) {
        return head;
    }
    if (major != CBOR_MAJOR_BYTES) {
        return WP11_KEYSTORE_ERR_CBOR;
    }
    if (blen > (uint64_t)WP11_KEYSTORE_DER_MAX) {
        return WP11_KEYSTORE_ERR_CBOR;
    }
    /* Verify the bytes are present in the buffer. */
    if ((size_t)head + (size_t)blen > buflen - pos) {
        return WP11_KEYSTORE_ERR_CBOR;
    }

    data = (uint8_t *)malloc((size_t)blen);
    if (data == NULL) {
        return WP11_KEYSTORE_ERR_NOMEM;
    }

    /* mlock before memcpy: page must be pinned before sensitive bytes land
     * in it.  mlock(size=0) is defined as a no-op on Linux; blen=0 is
     * caught above by the WP11_KEYSTORE_DER_MAX check being > 0, but even
     * if a zero-length field slipped through, mlock(ptr, 0) is harmless. */
    if (mlock(data, (size_t)blen) != 0) {
        free(data);
        return WP11_KEYSTORE_ERR_MLOCK;
    }

    memcpy(data, buf + pos + (size_t)head, (size_t)blen);

    *data_out     = data;
    *data_len_out = (size_t)blen;
    return (int)((size_t)head + (size_t)blen);
}

/* Read a CBOR byte string at pos into a fixed-size buffer.
 * Fails if the encoded length != expected_len.
 * Returns bytes consumed or negative error. */
static int cbor_read_bytes_fixed(const uint8_t *buf, size_t buflen, size_t pos,
                                  uint8_t *dst, size_t expected_len)
{
    uint8_t  major;
    uint64_t blen;
    int      head;

    head = cbor_read_head(buf, buflen, pos, &major, &blen);
    if (head < 0) {
        return head;
    }
    if (major != CBOR_MAJOR_BYTES) {
        return WP11_KEYSTORE_ERR_CBOR;
    }
    if ((size_t)blen != expected_len) {
        return WP11_KEYSTORE_ERR_CBOR;
    }
    if ((size_t)head + expected_len > buflen - pos) {
        return WP11_KEYSTORE_ERR_CBOR;
    }
    memcpy(dst, buf + pos + (size_t)head, expected_len);
    return (int)((size_t)head + expected_len);
}

/* Skip a single CBOR item (any type) -- needed when iterating map keys we
 * encounter but have already matched (allows forward-compatible maps). */
static int cbor_skip(const uint8_t *buf, size_t buflen, size_t pos);

static int cbor_skip(const uint8_t *buf, size_t buflen, size_t pos)
{
    uint8_t  major;
    uint64_t val;
    int      head;
    size_t   i;
    int      n;

    head = cbor_read_head(buf, buflen, pos, &major, &val);
    if (head < 0) {
        return head;
    }

    if (major == CBOR_MAJOR_BYTES || major == CBOR_MAJOR_TEXT) {
        /* Payload bytes follow inline. */
        if (val > (uint64_t)(buflen - pos - (size_t)head)) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
        return (int)((size_t)head + (size_t)val);
    }
    else if (major == CBOR_MAJOR_UINT) {
        return head; /* no inline payload */
    }
    else if (major == CBOR_MAJOR_ARRAY) {
        /* Skip val items. */
        size_t cur = pos + (size_t)head;
        for (i = 0; i < (size_t)val; i++) {
            n = cbor_skip(buf, buflen, cur);
            if (n < 0) {
                return n;
            }
            cur += (size_t)n;
        }
        if (cur < pos) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
        return (int)(cur - pos);
    }
    else if (major == CBOR_MAJOR_MAP) {
        /* Skip val key-value pairs (2*val items).
         *
         * Guard against (size_t)val * 2u wrapping on 32-bit targets: if val
         * is large enough that 2*val overflows size_t, the multiplied loop
         * bound would be silently truncated and we'd skip too few items,
         * potentially misaligning the parser.  Reject any count that would
         * overflow SIZE_MAX before the multiply.
         *
         * In practice this cannot be reached with a valid .p11k file: the
         * AES-GCM auth tag protects the CBOR payload, and the plaintext is
         * capped at WP11_KEYSTORE_MAX_CT_LEN bytes, so a legitimate map can
         * have at most a few hundred pairs.  The check is here to make the
         * parser defensible on all targets regardless of those invariants. */
        size_t cur = pos + (size_t)head;
        if (val > (uint64_t)(SIZE_MAX / 2u)) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
        for (i = 0; i < (size_t)val * 2u; i++) {
            n = cbor_skip(buf, buflen, cur);
            if (n < 0) {
                return n;
            }
            cur += (size_t)n;
        }
        if (cur < pos) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
        return (int)(cur - pos);
    }
    else {
        return WP11_KEYSTORE_ERR_CBOR;
    }
}

/* -------------------------------------------------------------------------
 * Minimal CBOR encoder
 * ---------------------------------------------------------------------- */

/* Write CBOR initial byte + length for a major type.
 * Returns bytes written (positive), or -1 on overflow. */
static int cbor_write_head(uint8_t *buf, size_t buflen, size_t pos,
                            uint8_t major, uint64_t value)
{
    uint8_t prefix = (uint8_t)((major & 0x07u) << 5);

    if (value <= 23u) {
        if (pos >= buflen) {
            return -1;
        }
        buf[pos] = prefix | (uint8_t)value;
        return 1;
    }
    else if (value <= 0xFFu) {
        if (pos + 1u >= buflen) {
            return -1;
        }
        buf[pos]     = prefix | 24u;
        buf[pos + 1u] = (uint8_t)value;
        return 2;
    }
    else if (value <= 0xFFFFu) {
        if (pos + 2u >= buflen) {
            return -1;
        }
        buf[pos]      = prefix | 25u;
        buf[pos + 1u] = (uint8_t)(value >> 8);
        buf[pos + 2u] = (uint8_t) value;
        return 3;
    }
    else if (value <= 0xFFFFFFFFu) {
        if (pos + 4u >= buflen) {
            return -1;
        }
        buf[pos]      = prefix | 26u;
        buf[pos + 1u] = (uint8_t)(value >> 24);
        buf[pos + 2u] = (uint8_t)(value >> 16);
        buf[pos + 3u] = (uint8_t)(value >>  8);
        buf[pos + 4u] = (uint8_t) value;
        return 5;
    }
    else {
        /* 8-byte encoding not needed for our payload sizes. */
        return -1;
    }
}

/* Write a CBOR text string. Returns bytes written or -1 on overflow. */
static int cbor_write_text(uint8_t *buf, size_t buflen, size_t pos,
                            const char *str)
{
    size_t slen = strlen(str);
    int    head;

    head = cbor_write_head(buf, buflen, pos, CBOR_MAJOR_TEXT, (uint64_t)slen);
    if (head < 0) {
        return -1;
    }
    if (pos + (size_t)head + slen > buflen) {
        return -1;
    }
    memcpy(buf + pos + (size_t)head, str, slen);
    return (int)((size_t)head + slen);
}

/* Write a CBOR byte string. Returns bytes written or -1 on overflow. */
static int cbor_write_bytes(uint8_t *buf, size_t buflen, size_t pos,
                             const uint8_t *data, size_t len)
{
    int head;

    head = cbor_write_head(buf, buflen, pos, CBOR_MAJOR_BYTES, (uint64_t)len);
    if (head < 0) {
        return -1;
    }
    if (pos + (size_t)head + len > buflen) {
        return -1;
    }
    memcpy(buf + pos + (size_t)head, data, len);
    return (int)((size_t)head + len);
}

/* -------------------------------------------------------------------------
 * CBOR payload decoder
 *
 * Decodes the CBOR array of maps into the entries array.
 * Each map has text keys: "id", "label", "key_type", "der_bytes".
 *
 * Key ordering in the map is not assumed -- we iterate all map pairs and
 * match each key by name.  Unknown keys are skipped (forward compatibility).
 * ---------------------------------------------------------------------- */
static int decode_cbor_payload(const uint8_t    *plain,
                                size_t            plain_len,
                                wp11_key_entry_t *entries,
                                size_t           *count_out)
{
    uint8_t  major;
    uint64_t nentries;
    int      n;
    size_t   pos = 0;
    size_t   i;

    /* Outer structure must be a CBOR array. */
    n = cbor_read_head(plain, plain_len, pos, &major, &nentries);
    if (n < 0) {
        return n;
    }
    if (major != CBOR_MAJOR_ARRAY) {
        return WP11_KEYSTORE_ERR_CBOR;
    }
    if (nentries > WP11_KEYSTORE_MAX_ENTRIES) {
        return WP11_KEYSTORE_ERR_CBOR;
    }
    pos += (size_t)n;

    for (i = 0; i < (size_t)nentries; i++) {
        uint64_t npairs;
        uint8_t  map_major;
        size_t   p;
        int      has_id       = 0;
        int      has_label    = 0;
        int      has_key_type = 0;
        int      has_der      = 0;
        int      has_cert     = 0; /* optional; absence is not an error */
        (void)has_cert;

        /* Each entry is a CBOR map. */
        n = cbor_read_head(plain, plain_len, pos, &map_major, &npairs);
        if (n < 0) {
            return n;
        }
        if (map_major != CBOR_MAJOR_MAP) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
        pos += (size_t)n;

        /* Zero-initialise the entry so partial results don't leak. */
        memset(&entries[i], 0, sizeof(wp11_key_entry_t));

        for (p = 0; p < (size_t)npairs; p++) {
            char key_name[32];

            /* Read map key (must be text). */
            n = cbor_read_text(plain, plain_len, pos,
                               key_name, sizeof(key_name));
            if (n < 0) {
                return n;
            }
            pos += (size_t)n;

            /* Dispatch on key name.  cbor_read_text NUL-terminates key_name,
             * so strcmp is safe and clearer than memcmp with strlen+1 sizes. */
            if (strcmp(key_name, "id") == 0) {
                n = cbor_read_bytes_fixed(plain, plain_len, pos,
                                          entries[i].id, 16u);
                if (n < 0) {
                    return n;
                }
                has_id = 1;
            }
            else if (strcmp(key_name, "label") == 0) {
                n = cbor_read_text(plain, plain_len, pos,
                                   entries[i].label,
                                   WP11_KEYSTORE_LABEL_MAX + 1u);
                if (n < 0) {
                    return n;
                }
                has_label = 1;
            }
            else if (strcmp(key_name, "key_type") == 0) {
                /* key_type is a CBOR unsigned int. */
                uint8_t  kt_major;
                uint64_t kt_val;
                n = cbor_read_head(plain, plain_len, pos, &kt_major, &kt_val);
                if (n < 0) {
                    return n;
                }
                if (kt_major != CBOR_MAJOR_UINT) {
                    return WP11_KEYSTORE_ERR_CBOR;
                }
                if (kt_val != (uint64_t)WP11_KEY_TYPE_RSA &&
                    kt_val != (uint64_t)WP11_KEY_TYPE_EC) {
                    return WP11_KEYSTORE_ERR_CBOR;
                }
                entries[i].key_type = (int)kt_val;
                has_key_type = 1;
            }
            else if (strcmp(key_name, "der_bytes") == 0) {
                n = cbor_read_bytes_alloc(plain, plain_len, pos,
                                          &entries[i].der_bytes,
                                          &entries[i].der_len);
                if (n < 0) {
                    return n;
                }
                has_der = 1;
            }
            else if (strcmp(key_name, "cert_bytes") == 0) {
                /* Certificate is public data -- plain malloc, no mlock. */
                uint8_t  cb_major;
                uint64_t cb_blen;
                int      cb_head;

                cb_head = cbor_read_head(plain, plain_len, pos,
                                         &cb_major, &cb_blen);
                if (cb_head < 0) {
                    return cb_head;
                }
                if (cb_major != CBOR_MAJOR_BYTES) {
                    return WP11_KEYSTORE_ERR_CBOR;
                }
                if (cb_blen > (uint64_t)WP11_KEYSTORE_CERT_MAX) {
                    return WP11_KEYSTORE_ERR_CBOR;
                }
                if ((size_t)cb_head + (size_t)cb_blen > plain_len - pos) {
                    return WP11_KEYSTORE_ERR_CBOR;
                }
                entries[i].cert_bytes = (uint8_t *)malloc((size_t)cb_blen);
                if (entries[i].cert_bytes == NULL) {
                    return WP11_KEYSTORE_ERR_NOMEM;
                }
                memcpy(entries[i].cert_bytes,
                       plain + pos + (size_t)cb_head,
                       (size_t)cb_blen);
                entries[i].cert_len = (size_t)cb_blen;
                n = (int)((size_t)cb_head + (size_t)cb_blen);
                has_cert = 1;
            }
            else {
                /* Unknown key -- skip the value for forward compatibility. */
                n = cbor_skip(plain, plain_len, pos);
                if (n < 0) {
                    return n;
                }
            }
            pos += (size_t)n;
        }

        /* All four required fields must be present. */
        if (!has_id || !has_label || !has_key_type || !has_der) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
    }

    *count_out = (size_t)nentries;
    return WP11_KEYSTORE_OK;
}

/* -------------------------------------------------------------------------
 * CBOR payload encoder
 * ---------------------------------------------------------------------- */
static int encode_cbor_payload(uint8_t                *buf,
                                size_t                  buflen,
                                const wp11_key_entry_t *keys,
                                size_t                  nkeys,
                                size_t                 *encoded_len_out)
{
    size_t pos = 0;
    size_t i;
    int    n;

    /* Outer array of nkeys entries.
     *
     * cbor_write_* return -1 when the output buffer is too small -- this is
     * a CBOR encoding overflow, not an OOM.  ERR_CBOR is the correct code;
     * ERR_NOMEM is reserved for malloc/mlock failures. */
    n = cbor_write_head(buf, buflen, pos, CBOR_MAJOR_ARRAY, (uint64_t)nkeys);
    if (n < 0) {
        return WP11_KEYSTORE_ERR_CBOR;
    }
    pos += (size_t)n;

    for (i = 0; i < nkeys; i++) {
        /* Map with 4 required pairs, plus 1 optional "cert_bytes" pair. */
        n = cbor_write_head(buf, buflen, pos, CBOR_MAJOR_MAP,
                            keys[i].cert_bytes != NULL ? 5u : 4u);
        if (n < 0) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
        pos += (size_t)n;

        /* "id" */
        n = cbor_write_text(buf, buflen, pos, "id");
        if (n < 0) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
        pos += (size_t)n;
        n = cbor_write_bytes(buf, buflen, pos, keys[i].id, 16u);
        if (n < 0) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
        pos += (size_t)n;

        /* "label" */
        n = cbor_write_text(buf, buflen, pos, "label");
        if (n < 0) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
        pos += (size_t)n;
        n = cbor_write_text(buf, buflen, pos, keys[i].label);
        if (n < 0) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
        pos += (size_t)n;

        /* "key_type" */
        n = cbor_write_text(buf, buflen, pos, "key_type");
        if (n < 0) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
        pos += (size_t)n;
        n = cbor_write_head(buf, buflen, pos, CBOR_MAJOR_UINT,
                            (uint64_t)keys[i].key_type);
        if (n < 0) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
        pos += (size_t)n;

        /* "der_bytes" */
        n = cbor_write_text(buf, buflen, pos, "der_bytes");
        if (n < 0) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
        pos += (size_t)n;
        n = cbor_write_bytes(buf, buflen, pos,
                             keys[i].der_bytes, keys[i].der_len);
        if (n < 0) {
            return WP11_KEYSTORE_ERR_CBOR;
        }
        pos += (size_t)n;

        /* "cert_bytes" (optional) */
        if (keys[i].cert_bytes != NULL) {
            n = cbor_write_text(buf, buflen, pos, "cert_bytes");
            if (n < 0) {
                return WP11_KEYSTORE_ERR_CBOR;
            }
            pos += (size_t)n;
            n = cbor_write_bytes(buf, buflen, pos,
                                 keys[i].cert_bytes, keys[i].cert_len);
            if (n < 0) {
                return WP11_KEYSTORE_ERR_CBOR;
            }
            pos += (size_t)n;
        }
    }

    *encoded_len_out = pos;
    return WP11_KEYSTORE_OK;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

int wp11_keystore_load(const char      *path,
                       const uint8_t   *pin,  size_t pinlen,
                       wp11_keystore_t **ks_out)
{
    int              rc           = WP11_KEYSTORE_OK;
    int              fd           = -1;
    uint8_t         *filebuf      = NULL;
    size_t           filelen      = 0;
    uint8_t          aes_key[WP11_P11K_KEY_LEN]; /* derived key -- zeroize always */
    uint8_t         *plain        = NULL;
    size_t           plain_len    = 0;
    /* wolfP11-2oi: track which allocations have been mlock()'d so that the
     * cleanup path can call munlock() before free().  mlock and free must
     * always be paired: freeing an mlock'd page without munlock first leaks
     * the lock limit (RLIMIT_MEMLOCK) and can exhaust it for the process. */
    int              plain_locked   = 0; /* 1 once mlock(plain) succeeds   */
    int              entries_locked = 0; /* 1 once mlock(entries) succeeds */
    wp11_keystore_t *ks           = NULL;
    wp11_key_entry_t *entries     = NULL;
    size_t           entry_alloc_size = 0;
    int              key_zeroed   = 0;
    struct stat      st;
    uint32_t         iter;
    uint32_t         ctlen;
    Aes              aes;
    int              wc_rc;
    size_t           count      = 0;

    memset(aes_key, 0, sizeof(aes_key));
    memset(&aes, 0, sizeof(aes));

    /* Validate parameters. */
    if (path == NULL || pin == NULL || ks_out == NULL) {
        return WP11_KEYSTORE_ERR_PARAM;
    }
    if (pinlen == 0) {
        return WP11_KEYSTORE_ERR_PARAM;
    }
    *ks_out = NULL;

    /* Open file and stat for size. */
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return WP11_KEYSTORE_ERR_IO;
    }
    if (fstat(fd, &st) < 0) {
        close(fd);
        return WP11_KEYSTORE_ERR_IO;
    }
    /* Reject obviously too-small files before allocating anything. */
    if (st.st_size < (off_t)(WP11_P11K_HDR_LEN + WP11_P11K_TAG_LEN)) {
        close(fd);
        return WP11_KEYSTORE_ERR_TRUNCATED;
    }
    /* Sanity upper bound: header + max ciphertext + tag. */
    if ((uint64_t)st.st_size >
        (uint64_t)(WP11_P11K_HDR_LEN + WP11_KEYSTORE_MAX_CT_LEN + WP11_P11K_TAG_LEN)) {
        close(fd);
        return WP11_KEYSTORE_ERR_TRUNCATED;
    }
    filelen = (size_t)st.st_size;

    filebuf = (uint8_t *)malloc(filelen);
    if (filebuf == NULL) {
        close(fd);
        return WP11_KEYSTORE_ERR_NOMEM;
    }

    rc = read_all(fd, filebuf, filelen);
    close(fd);
    fd = -1;
    if (rc != WP11_KEYSTORE_OK) {
        goto cleanup;
    }

    /* Check magic. */
    if (memcmp(filebuf + WP11_P11K_OFF_MAGIC, WP11_P11K_MAGIC, WP11_P11K_MAGIC_LEN) != 0) {
        rc = WP11_KEYSTORE_ERR_BAD_MAGIC;
        goto cleanup;
    }

    /* Check version. */
    if (filebuf[WP11_P11K_OFF_VERSION] != WP11_P11K_VERSION) {
        rc = WP11_KEYSTORE_ERR_BAD_VERSION;
        goto cleanup;
    }

    /* Read and validate PBKDF2 iteration count. */
    iter = read_u32be(filebuf + WP11_P11K_OFF_ITER);
    if (iter < WP11_KEYSTORE_MIN_KDF_ITER) {
        rc = WP11_KEYSTORE_ERR_KDF_WEAK;
        goto cleanup;
    }

    /* Read and validate ciphertext length. */
    ctlen = read_u32be(filebuf + WP11_P11K_OFF_CTLEN);
    if (ctlen > WP11_KEYSTORE_MAX_CT_LEN) {
        rc = WP11_KEYSTORE_ERR_CBOR; /* malformed/too-large payload */
        goto cleanup;
    }
    /* Verify file is large enough to hold: header + ctlen + tag. */
    if (filelen < WP11_P11K_HDR_LEN + (size_t)ctlen + WP11_P11K_TAG_LEN) {
        rc = WP11_KEYSTORE_ERR_TRUNCATED;
        goto cleanup;
    }

    /* Derive AES-256 key from PIN + salt using PBKDF2-HMAC-SHA256. */
    /* wolfP11-44h: iter is uint32_t from the file; wc_PBKDF2 takes int.
     * A value above INT_MAX (2^31-1) casts to negative and the wolfCrypt
     * behaviour is undefined.  Such a value is unrealistic (>2B iterations
     * would take years) but an adversarially crafted file could set it. */
    if (iter > (uint32_t)INT_MAX) {
        rc = WP11_KEYSTORE_ERR_KDF_WEAK;
        goto cleanup;
    }
    wc_rc = wc_PBKDF2(aes_key,
                      pin,    (int)pinlen,
                      filebuf + WP11_P11K_OFF_SALT, (int)WP11_P11K_SALT_LEN,
                      (int)iter,
                      (int)WP11_P11K_KEY_LEN,
                      WC_SHA256);
    if (wc_rc != 0) {
        rc = WP11_KEYSTORE_ERR_CRYPTO;
        /* Fall through to cleanup which will wp11_zero the key. */
        goto cleanup;
    }

    /* Allocate plaintext buffer (same size as ciphertext for GCM). */
    plain_len = (size_t)ctlen;
    if (plain_len == 0) {
        /* Empty payload is technically valid CBOR (empty array) but useless.
         * Treat as malformed to catch truncation bugs. */
        rc = WP11_KEYSTORE_ERR_CBOR;
        goto cleanup;
    }
    plain = (uint8_t *)malloc(plain_len);
    if (plain == NULL) {
        rc = WP11_KEYSTORE_ERR_NOMEM;
        goto cleanup;
    }

    /* wolfP11-2oi: lock the plaintext buffer before AES-GCM writes into it.
     * Order matters: mlock BEFORE the decrypt write so the page is pinned
     * before any sensitive byte lands in it.  If we mlock'd after decrypt,
     * the page could have been faulted in as pageable during the write. */
    if (mlock(plain, plain_len) != 0) {
        rc = WP11_KEYSTORE_ERR_MLOCK;
        goto cleanup;
    }
    plain_locked = 1;

    /* Set AES-GCM key. */
    wc_rc = wc_AesGcmSetKey(&aes, aes_key, WP11_P11K_KEY_LEN);
    if (wc_rc != 0) {
        rc = WP11_KEYSTORE_ERR_CRYPTO;
        goto cleanup;
    }

    /* Decrypt. wc_AesGcmDecrypt returns non-zero if the auth tag doesn't
     * match -- this is the expected signal for a wrong PIN. */
    wc_rc = wc_AesGcmDecrypt(&aes,
                              plain,
                              filebuf + WP11_P11K_OFF_CT, (word32)ctlen,
                              filebuf + WP11_P11K_OFF_NONCE, WP11_P11K_NONCE_LEN,
                              filebuf + WP11_P11K_OFF_CT + ctlen, WP11_P11K_TAG_LEN,
                              NULL, 0);

    /* Immediately zeroize the derived key -- it must not persist beyond this
     * point regardless of decryption success or failure. */
    wp11_zero(aes_key, sizeof(aes_key));
    wp11_zero(&aes, sizeof(aes));
    key_zeroed = 1;

    if (wc_rc != 0) {
        rc = WP11_KEYSTORE_ERR_BAD_PIN;
        goto cleanup;
    }

    /* Decode CBOR payload. */
    entry_alloc_size = WP11_KEYSTORE_MAX_ENTRIES * sizeof(wp11_key_entry_t);
    entries = (wp11_key_entry_t *)malloc(entry_alloc_size);
    if (entries == NULL) {
        rc = WP11_KEYSTORE_ERR_NOMEM;
        goto cleanup;
    }
    memset(entries, 0, entry_alloc_size);

    rc = decode_cbor_payload(plain, plain_len, entries, &count);

    /* Zeroize plaintext immediately after decode, success or failure. */
    wp11_zero(plain, plain_len);
    free(plain);
    plain = NULL;

    if (rc != WP11_KEYSTORE_OK) {
        goto cleanup;
    }

    /* mlock the entries array to protect the label, id, key_type, and
     * der_bytes pointer fields.  The der_bytes buffers themselves were
     * already mlock()'d inside cbor_read_bytes_alloc (wolfP11-2oi) so
     * this call covers only the struct-level fields.
     *
     * No separate "mlock each der_bytes" loop is needed here: that job
     * was moved into cbor_read_bytes_alloc so the window between allocation
     * and lock is closed for each key's DER bytes individually. */
    if (mlock(entries, entry_alloc_size) != 0) {
        rc = WP11_KEYSTORE_ERR_MLOCK;
        goto cleanup;
    }
    entries_locked = 1;

    /* Allocate and populate the keystore handle.
     * On failure, fall through to cleanup which munlocks and frees everything
     * tracked by the plain_locked / entries_locked flags. */
    ks = (wp11_keystore_t *)malloc(sizeof(wp11_keystore_t));
    if (ks == NULL) {
        rc = WP11_KEYSTORE_ERR_NOMEM;
        goto cleanup;
    }

    ks->entries    = entries;
    ks->count      = count;
    ks->mlock_size = entry_alloc_size;
    entries        = NULL; /* transferred ownership */

    *ks_out = ks;
    rc = WP11_KEYSTORE_OK;

cleanup:
    /* Zeroize derived key if not already done (error before decryption). */
    if (!key_zeroed) {
        wp11_zero(aes_key, sizeof(aes_key));
        wp11_zero(&aes, sizeof(aes));
    }

    /* Zeroize, munlock, and free plaintext buffer if still allocated.
     * wolfP11-2oi: plain_locked tracks whether mlock(plain) succeeded;
     * munlock must always pair with mlock to avoid leaking RLIMIT_MEMLOCK. */
    if (plain != NULL) {
        wp11_zero(plain, plain_len);
        if (plain_locked) {
            munlock(plain, plain_len);
        }
        free(plain);
    }

    /* Free file buffer (not sensitive -- encrypted ciphertext). */
    if (filebuf != NULL) {
        free(filebuf);
    }

    /* On error, clean up partially-built entries.
     *
     * wolfP11-2oi: all non-NULL der_bytes were mlock()'d by cbor_read_bytes_alloc,
     * so munlock must precede free for each one.  Iterating MAX_ENTRIES (not
     * count) is intentional: a CBOR parse error can leave der_bytes allocated
     * for entries 0..k while entries k+1.. are NULL-initialized; the NULL
     * check is the guard, not the count.
     *
     * entries_locked tracks whether mlock(entries) itself succeeded. */
    if (rc != WP11_KEYSTORE_OK && entries != NULL) {
        size_t j;
        for (j = 0; j < WP11_KEYSTORE_MAX_ENTRIES; j++) {
            if (entries[j].der_bytes != NULL) {
                wp11_zero(entries[j].der_bytes, entries[j].der_len);
                munlock(entries[j].der_bytes, entries[j].der_len);
                free(entries[j].der_bytes);
                entries[j].der_bytes = NULL;
            }
            if (entries[j].cert_bytes != NULL) {
                wp11_zero(entries[j].cert_bytes, entries[j].cert_len);
                free(entries[j].cert_bytes);
                entries[j].cert_bytes = NULL;
            }
        }
        /* wolfP11-0hx: zeroize the entries array itself (labels, IDs, key_types)
         * before munlock and free.  wp11_keystore_free does the same for the
         * success path.  Must happen AFTER the der_bytes loop above so we do
         * not zero the pointers before we dereference them. */
        wp11_zero(entries, entry_alloc_size);
        if (entries_locked) {
            munlock(entries, entry_alloc_size);
        }
        free(entries);
    }

    return rc;
}

void wp11_keystore_free(wp11_keystore_t *ks)
{
    size_t i;

    if (ks == NULL) {
        return;
    }

    if (ks->entries != NULL) {
        /* Zeroize and munlock each der_bytes allocation first.
         * cert_bytes is public data (not mlock'd); zeroize + free only. */
        for (i = 0; i < WP11_KEYSTORE_MAX_ENTRIES; i++) {
            if (ks->entries[i].der_bytes != NULL) {
                wp11_zero(ks->entries[i].der_bytes, ks->entries[i].der_len);
                munlock(ks->entries[i].der_bytes, ks->entries[i].der_len);
                free(ks->entries[i].der_bytes);
                ks->entries[i].der_bytes = NULL;
            }
            if (ks->entries[i].cert_bytes != NULL) {
                wp11_zero(ks->entries[i].cert_bytes, ks->entries[i].cert_len);
                free(ks->entries[i].cert_bytes);
                ks->entries[i].cert_bytes = NULL;
            }
        }
        /* Zeroize the entries array (contains labels, ids) before munlock. */
        wp11_zero(ks->entries, ks->mlock_size);
        munlock(ks->entries, ks->mlock_size);
        free(ks->entries);
        ks->entries = NULL;
    }

    free(ks);
}

size_t wp11_keystore_count(const wp11_keystore_t *ks)
{
    if (ks == NULL) {
        return 0;
    }
    return ks->count;
}

const wp11_key_entry_t *wp11_keystore_get(const wp11_keystore_t *ks, size_t i)
{
    if (ks == NULL || i >= ks->count) {
        return NULL;
    }
    return &ks->entries[i];
}

int wp11_keystore_create(const char             *path,
                          const uint8_t          *pin,   size_t pinlen,
                          const wp11_key_entry_t *keys,  size_t nkeys)
{
    int      rc         = WP11_KEYSTORE_OK;
    uint8_t *plain      = NULL;
    size_t   plain_len  = 0;
    uint8_t *ct         = NULL;
    uint8_t  salt[WP11_P11K_SALT_LEN];
    uint8_t  nonce[WP11_P11K_NONCE_LEN];
    uint8_t  tag[WP11_P11K_TAG_LEN];
    uint8_t  aes_key[WP11_P11K_KEY_LEN];
    uint8_t  hdr[WP11_P11K_HDR_LEN];
    WC_RNG   rng;
    Aes      aes;
    int      rng_init   = 0;
    int      key_zeroed = 0;
    int      fd         = -1;
    int      wc_rc;

    memset(salt,    0, sizeof(salt));
    memset(nonce,   0, sizeof(nonce));
    memset(tag,     0, sizeof(tag));
    memset(aes_key, 0, sizeof(aes_key));
    memset(&aes,    0, sizeof(aes));
    memset(&rng,    0, sizeof(rng));
    memset(hdr,     0, sizeof(hdr));

    if (path == NULL || pin == NULL) {
        return WP11_KEYSTORE_ERR_PARAM;
    }
    if (keys == NULL && nkeys != 0u) {
        return WP11_KEYSTORE_ERR_PARAM;
    }
    if (pinlen == 0 || nkeys > WP11_KEYSTORE_MAX_ENTRIES) {
        return WP11_KEYSTORE_ERR_PARAM;
    }

    /* Calculate an upper bound for the CBOR buffer.
     * Per entry: map head(1) + 4 required key-value pairs:
     *   "id"(3) + bstr(1+16) + "label"(6) + tstr(1+64) +
     *   "key_type"(9) + uint(1) + "der_bytes"(10) + bstr(3+4096)
     *   = 3+17+6+65+9+1+10+4099 = ~4210 bytes per entry.
     * Plus optional "cert_bytes": text(11) + bstr(3+4096) = ~4110 bytes.
     * Outer array head: 5.  Add 64 bytes slack. */
    /* wolfP11-4pe: check for size_t overflow before multiplying.
     * nkeys is already validated against WP11_KEYSTORE_MAX_ENTRIES (64),
     * but on 32-bit targets (SIZE_MAX = 0xFFFFFFFF) the multiply could
     * still wrap if WP11_KEYSTORE_CERT_MAX is large.  Guard explicitly. */
    {
        size_t per_entry = 4300u + (size_t)WP11_KEYSTORE_CERT_MAX + 16u;
        if (nkeys > 0u && per_entry > (SIZE_MAX - 5u) / nkeys) {
            return WP11_KEYSTORE_ERR_PARAM;
        }
        plain_len = 5u + nkeys * per_entry;
    }

    plain = (uint8_t *)malloc(plain_len);
    if (plain == NULL) {
        return WP11_KEYSTORE_ERR_NOMEM;
    }
    memset(plain, 0, plain_len);

    rc = encode_cbor_payload(plain, plain_len, keys, nkeys, &plain_len);
    if (rc != WP11_KEYSTORE_OK) {
        goto cleanup;
    }

    /* ciphertext is same length as plaintext in AES-GCM. */
    ct = (uint8_t *)malloc(plain_len);
    if (ct == NULL) {
        rc = WP11_KEYSTORE_ERR_NOMEM;
        goto cleanup;
    }

    /* Initialise RNG for salt and nonce generation. */
    wc_rc = wc_InitRng(&rng);
    if (wc_rc != 0) {
        rc = WP11_KEYSTORE_ERR_CRYPTO;
        goto cleanup;
    }
    rng_init = 1;

    wc_rc = wc_RNG_GenerateBlock(&rng, salt, WP11_P11K_SALT_LEN);
    if (wc_rc != 0) {
        rc = WP11_KEYSTORE_ERR_CRYPTO;
        goto cleanup;
    }

    wc_rc = wc_RNG_GenerateBlock(&rng, nonce, WP11_P11K_NONCE_LEN);
    if (wc_rc != 0) {
        rc = WP11_KEYSTORE_ERR_CRYPTO;
        goto cleanup;
    }

    /* Derive key. */
    wc_rc = wc_PBKDF2(aes_key,
                      pin,    (int)pinlen,
                      salt,   (int)WP11_P11K_SALT_LEN,
                      (int)WP11_KEYSTORE_KDF_ITERATIONS,
                      (int)WP11_P11K_KEY_LEN,
                      WC_SHA256);
    if (wc_rc != 0) {
        rc = WP11_KEYSTORE_ERR_CRYPTO;
        goto cleanup;
    }

    /* Encrypt. */
    wc_rc = wc_AesGcmSetKey(&aes, aes_key, WP11_P11K_KEY_LEN);
    if (wc_rc != 0) {
        rc = WP11_KEYSTORE_ERR_CRYPTO;
        goto cleanup;
    }

    wc_rc = wc_AesGcmEncrypt(&aes,
                              ct,
                              plain, (word32)plain_len,
                              nonce, WP11_P11K_NONCE_LEN,
                              tag,   WP11_P11K_TAG_LEN,
                              NULL, 0);

    /* Zeroize derived key immediately after use. */
    wp11_zero(aes_key, sizeof(aes_key));
    wp11_zero(&aes, sizeof(aes));
    key_zeroed = 1;

    if (wc_rc != 0) {
        rc = WP11_KEYSTORE_ERR_CRYPTO;
        goto cleanup;
    }

    /* Build the file header. */
    memcpy(hdr + WP11_P11K_OFF_MAGIC,   WP11_P11K_MAGIC, WP11_P11K_MAGIC_LEN);
    hdr[WP11_P11K_OFF_VERSION] = WP11_P11K_VERSION;
    memcpy(hdr + WP11_P11K_OFF_SALT,  salt,  WP11_P11K_SALT_LEN);
    write_u32be(hdr + WP11_P11K_OFF_ITER,  WP11_KEYSTORE_KDF_ITERATIONS);
    memcpy(hdr + WP11_P11K_OFF_NONCE, nonce, WP11_P11K_NONCE_LEN);
    write_u32be(hdr + WP11_P11K_OFF_CTLEN, (uint32_t)plain_len);

    /* Write file: header, ciphertext, tag. */
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        rc = WP11_KEYSTORE_ERR_IO;
        goto cleanup;
    }

    rc = write_all(fd, hdr, WP11_P11K_HDR_LEN);
    if (rc != WP11_KEYSTORE_OK) {
        goto cleanup;
    }

    rc = write_all(fd, ct, plain_len);
    if (rc != WP11_KEYSTORE_OK) {
        goto cleanup;
    }

    rc = write_all(fd, tag, WP11_P11K_TAG_LEN);
    if (rc != WP11_KEYSTORE_OK) {
        goto cleanup;
    }

    rc = WP11_KEYSTORE_OK;

cleanup:
    if (fd >= 0) {
        close(fd);
    }
    if (rng_init) {
        wc_FreeRng(&rng);
    }
    if (!key_zeroed) {
        wp11_zero(aes_key, sizeof(aes_key));
        wp11_zero(&aes, sizeof(aes));
    }
    if (plain != NULL) {
        wp11_zero(plain, plain_len);
        free(plain);
    }
    if (ct != NULL) {
        free(ct);
    }

    return rc;
}

/* -------------------------------------------------------------------------
 * Provisioning helpers
 * ---------------------------------------------------------------------- */

int wp11_keystore_gen_id(uint8_t id[16])
{
    WC_RNG rng;
    int    wc_rc;
    int    rc = WP11_KEYSTORE_OK;

    memset(&rng, 0, sizeof(rng));
    wc_rc = wc_InitRng(&rng);
    if (wc_rc != 0) {
        return WP11_KEYSTORE_ERR_CRYPTO;
    }
    wc_rc = wc_RNG_GenerateBlock(&rng, id, 16u);
    if (wc_rc != 0) {
        rc = WP11_KEYSTORE_ERR_CRYPTO;
    }
    wc_FreeRng(&rng);
    return rc;
}

int wp11_keystore_detect_key_type(const uint8_t *der, size_t derlen)
{
    ecc_key  ecc;
    RsaKey   rsa;
    word32   idx;
    int      wc_rc;

    if (der == NULL || derlen == 0) {
        return WP11_KEYSTORE_ERR_PARAM;
    }

    /* Try EC first -- SEC1 DER is unambiguous. */
    wc_rc = wc_ecc_init(&ecc);
    if (wc_rc == 0) {
        idx   = 0;
        wc_rc = wc_EccPrivateKeyDecode(der, &idx, &ecc, (word32)derlen);
        wc_ecc_free(&ecc);
        if (wc_rc == 0) {
            return WP11_KEY_TYPE_EC;
        }
    }

    /* Try RSA -- PKCS#1 DER. */
    wc_rc = wc_InitRsaKey(&rsa, NULL);
    if (wc_rc == 0) {
        idx   = 0;
        wc_rc = wc_RsaPrivateKeyDecode(der, &idx, &rsa, (word32)derlen);
        wc_FreeRsaKey(&rsa);
        if (wc_rc == 0) {
            return WP11_KEY_TYPE_RSA;
        }
    }

    return WP11_KEYSTORE_ERR_CBOR; /* reuse as "unrecognised DER" error */
}

int wp11_keystore_pem_to_der(const uint8_t *pem, size_t pemlen,
                              uint8_t **der_out, size_t *derlen_out)
{
    /* Note: the output buffer is NOT mlock'd here.  mlock is critical in
     * the load path (cbor_read_bytes_alloc) where DER bytes live in RAM for
     * the duration of the session.  In the create path the caller passes
     * these bytes to wp11_keystore_create, which encrypts and immediately
     * zeroizes the plaintext.  The window without mlock is the provisioning
     * call itself; the caller is responsible for wp11_zero + free on error
     * and after wp11_keystore_create returns. */
    uint8_t *buf;
    int      n;

    if (pem == NULL || pemlen == 0 || der_out == NULL || derlen_out == NULL) {
        return WP11_KEYSTORE_ERR_PARAM;
    }

    buf = (uint8_t *)malloc(WP11_KEYSTORE_DER_MAX);
    if (buf == NULL) {
        return WP11_KEYSTORE_ERR_NOMEM;
    }

    n = wc_KeyPemToDer(pem, (int)pemlen, buf, (int)WP11_KEYSTORE_DER_MAX, NULL);
    if (n <= 0) {
        wp11_zero(buf, WP11_KEYSTORE_DER_MAX);
        free(buf);
        return WP11_KEYSTORE_ERR_CRYPTO;
    }

    *der_out    = buf;
    *derlen_out = (size_t)n;
    return WP11_KEYSTORE_OK;
}

int wp11_keystore_cert_pem_to_der(const uint8_t *pem, size_t pemlen,
                                   uint8_t **der_out, size_t *derlen_out)
{
    uint8_t *buf;
    int      n;

    if (pem == NULL || der_out == NULL || derlen_out == NULL) {
        return WP11_KEYSTORE_ERR_PARAM;
    }

    buf = (uint8_t *)malloc(WP11_KEYSTORE_CERT_MAX);
    if (buf == NULL) {
        return WP11_KEYSTORE_ERR_NOMEM;
    }

    n = wc_CertPemToDer(pem, (int)pemlen, buf, (int)WP11_KEYSTORE_CERT_MAX,
                         CERT_TYPE);
    if (n <= 0) {
        free(buf);
        return WP11_KEYSTORE_ERR_CRYPTO;
    }

    *der_out    = buf;
    *derlen_out = (size_t)n;
    return WP11_KEYSTORE_OK;
}
