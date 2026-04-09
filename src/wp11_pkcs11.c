/* wp11_pkcs11.c -- wolfP11 PKCS#11 2.40 C_* function implementations */

/* _POSIX_C_SOURCE is required for pthread_cond_t, pthread_mutex_t, and
 * related POSIX thread APIs when building with -std=c99 on Linux/glibc.
 * Must appear before any system header to take effect.
 * Guard with #ifndef so a higher value passed via -D on the command line
 * (e.g. 200809L when building with wolfHSM) is not downgraded. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include "wolfp11/wp11_pkcs11.h"
#include "wolfp11/wp11_settings.h"
#include "wolfp11/wp11_backend.h"
#include "wolfp11/wp11_token_db.h"
#include <wolfssl/options.h>
#include "wolfp11/wp11_soft_key.h"
#include <wolfssl/wolfcrypt/random.h>   /* WC_RNG, wc_InitRng, wc_RNG_GenerateBlock */
#include <wolfssl/wolfcrypt/wc_port.h>  /* wolfSSL_Mutex, wc_InitMutex, etc. */
#include <wolfssl/wolfcrypt/aes.h>      /* Aes, wc_AesInit/SetKey/CbcEncrypt/EcbEncrypt */
#include <wolfssl/wolfcrypt/des3.h>     /* Des, Des3, wc_Des_SetKey/CbcEncrypt/EcbEncrypt */
#include <wolfssl/wolfcrypt/md5.h>      /* wc_Md5, wc_InitMd5/Md5Update/Md5Final */
#include <wolfssl/wolfcrypt/sha.h>      /* wc_Sha, wc_InitSha/ShaUpdate/ShaFinal */
#include <wolfssl/wolfcrypt/sha256.h>   /* wc_Sha256, wc_InitSha256/Sha256Update/Final */
#include <wolfssl/wolfcrypt/sha512.h>   /* wc_Sha384/Sha512 */
#include <wolfssl/wolfcrypt/hmac.h>     /* Hmac, wc_HmacInit/SetKey/Update/Final */
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#ifdef WOLFP11_CFG_USB_BACKEND
#include <libusb-1.0/libusb.h>
#include "wolfp11/wp11_ccid.h"
#include "wolfp11/wp11_proto_piv.h"
#endif

#if defined(WOLFP11_CFG_USB_FLASH_BACKEND) || defined(WOLFP11_CFG_FSDIR_BACKEND)
#include "wolfp11/wp11_keystore.h"
/* wolfCrypt key-parsing headers: used to derive the exact signature length
 * for each keystore key at C_Login time so C_Sign(NULL) can return the right
 * size instead of the hardcoded 512 that triggered wolfP11-3qf. */
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>
/* inotify: watch filesystem events for .p11k files.
 * inotify itself is Linux-only and always available in our
 * target environments (embedded Linux, containers). */
#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#endif /* WOLFP11_CFG_USB_FLASH_BACKEND || WOLFP11_CFG_FSDIR_BACKEND */
#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
#include <sys/mman.h>   /* mlock / munlock for soft-token PIN cache */
#endif

#ifdef WOLFP11_CFG_WOLFHSM_BACKEND
#include <wolfhsm/wh_client.h>
#include <wolfhsm/wh_client_crypto.h>
#include <wolfhsm/wh_comm.h>
#include <wolfhsm/wh_error.h>
#include "port/posix/posix_transport_shm.h"
#include "port/posix/posix_transport_tcp.h"
/* wolfCrypt key-parsing headers: used for key-type detection at C_Login
 * key enumeration time.  Safe to include when USB_FLASH_BACKEND already
 * pulled them in -- header guards make the second include a no-op. */
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>
#include "wolfp11/wp11_keystore.h"  /* WP11_KEY_TYPE_RSA, WP11_KEY_TYPE_EC */
#ifndef WOLFP11_CFG_USB_FLASH_BACKEND
#include <stdio.h>                  /* snprintf for hex key-ID label fallback */
#endif
#endif /* WOLFP11_CFG_WOLFHSM_BACKEND */

/*
 * THREAD SAFETY: Two-lock model.
 *
 * Lock 1: g_lock (wolfSSL_Mutex)
 *   Protects: g_initialized, g_sessions[], g_keys[], g_slots[].
 *   All C_* functions except C_GetFunctionList and C_WaitForSlotEvent
 *   acquire this lock on entry.
 *
 * Lock 2: g_hotplug_mutex (pthread_mutex_t)
 *   Protects: g_hotplug_queue[], g_hotplug_head, g_hotplug_tail.
 *   Used with g_hotplug_cond for C_WaitForSlotEvent blocking.
 *
 * CRITICAL INVARIANT: The hotplug callback acquires g_lock first, then
 * g_hotplug_mutex (via hotplug_push_event). C_WaitForSlotEvent must
 * NEVER hold g_lock while waiting on g_hotplug_cond -- that would deadlock.
 */

/* Forward declarations -- implemented in wp11_backend_soft.c */
typedef struct wp11_soft_key wp11_soft_key_t;
void             wp11_soft_key_free(wp11_soft_key_t *key);
wp11_soft_key_t *wp11_soft_key_ref(wp11_soft_key_t *key);
wp11_soft_key_t *wp11_soft_key_new_ecc_p256(void);
wp11_soft_key_t *wp11_soft_key_new_rsa2048(void);
wp11_soft_key_t *wp11_soft_key_new_from_der(const uint8_t *der, size_t derlen,
                                             int key_type);
int              wp11_soft_key_export_priv_der(wp11_soft_key_t *key,
                                               uint8_t *buf, uint32_t buflen);
/* Export RSA public key components (N = modulus, E = public exponent).
 * word32 is wolfCrypt's unsigned 32-bit type, already defined via random.h. */
int wp11_soft_key_export_rsa_pub(wp11_soft_key_t *key,
                                  uint8_t *n, word32 *nlen,
                                  uint8_t *e, word32 *elen);
#ifdef WOLFP11_CFG_TEST
/* Test-only hook: export EC public key in X9.62 format.
 * Defined in wp11_backend_soft.c under WOLFP11_CFG_TEST. */
int wp11_soft_key_test_export_pub_x963(wp11_soft_key_t *key,
                                        uint8_t *out, word32 *outlen);
#endif

/* -------------------------------------------------------------------------
 * Global lock -- single mutex serializing all C_* calls that touch
 * g_initialized, g_sessions[], g_keys[], or g_slots[].
 * ---------------------------------------------------------------------- */
static wolfSSL_Mutex g_lock;
static int           g_lock_ready = 0;  /* 1 after wc_InitMutex succeeds */

/* Acquire g_lock. On failure returns the given CK_RV error code.
 * Usage: WP11_LOCK(CKR_GENERAL_ERROR); */
#define WP11_LOCK(rv_on_fail) \
    do { \
        if (!g_lock_ready || wc_LockMutex(&g_lock) != 0) { \
            return (rv_on_fail); \
        } \
    } while (0)

/* Release g_lock unconditionally. */
#define WP11_UNLOCK() \
    do { (void)wc_UnLockMutex(&g_lock); } while (0)

/* -------------------------------------------------------------------------
 * Global state
 * ---------------------------------------------------------------------- */

static int g_initialized = 0;

/* -------------------------------------------------------------------------
 * Session model
 * ---------------------------------------------------------------------- */

#define MAX_SESSIONS WOLFP11_CFG_MAX_SESSIONS

/* Maximum template attributes stored per FindObjectsInit call. */
#define FIND_TMPL_MAX_ATTRS    8u
/* Maximum bytes stored per attribute value. Covers all scalar types
 * (CKA_CLASS, CKA_KEY_TYPE: 4-8 bytes), CKA_ID (<=16 bytes),
 * CKA_LABEL (<=32 bytes), CKA_TOKEN (1 byte). */
#define FIND_ATTR_MAX_VAL_LEN 64u

typedef struct {
    CK_ATTRIBUTE_TYPE type;
    CK_ULONG          len;
    uint8_t           val[FIND_ATTR_MAX_VAL_LEN];
} wp11_find_attr_t;

typedef struct {
    int            in_use;
    CK_SLOT_ID     slot_id;
    CK_FLAGS       flags;
    CK_STATE       state;
    int            logged_in;     /* 0=no, 1=CKU_USER, 2=CKU_SO */
    /* Sign operation state */
    int            sign_active;
    CK_MECHANISM_TYPE sign_mech;
    CK_OBJECT_HANDLE  sign_key;   /* 1-based key handle */
    /* Verify operation state */
    int            verify_active;
    CK_MECHANISM_TYPE verify_mech;
    CK_OBJECT_HANDLE  verify_key;
    /* Decrypt operation state */
    int            decrypt_active;
    int            decrypt_oneshot;   /* 1 after C_Decrypt(NULL) size query */
    int            decrypt_multipart; /* 1 after C_DecryptUpdate called */
    CK_MECHANISM_TYPE decrypt_mech;
    CK_OBJECT_HANDLE  decrypt_key;
    /* wolfCrypt context for symmetric decrypt (AES/DES/3DES multi-part) */
    union {
        Aes  aes;
        Des  des;
        Des3 des3;
    } dec_ctx;
    /* Encrypt operation state */
    int               encrypt_active;
    int               encrypt_oneshot;   /* 1 after C_Encrypt(NULL) size query */
    int               encrypt_multipart; /* 1 after C_EncryptUpdate called */
    CK_MECHANISM_TYPE encrypt_mech;
    CK_OBJECT_HANDLE  encrypt_key;
    /* wolfCrypt context for symmetric encrypt (AES/DES/3DES multi-part) */
    union {
        Aes  aes;
        Des  des;
        Des3 des3;
    } enc_ctx;
    /* Digest operation state */
    int               digest_active;
    int               digest_oneshot;   /* 1 after C_Digest(NULL) size query  */
    int               digest_multipart; /* 1 after C_DigestUpdate/DigestKey   */
    CK_MECHANISM_TYPE digest_mech;
    union {
        wc_Md5    md5;
        wc_Sha    sha;
        wc_Sha256 sha256;
        wc_Sha384 sha384;  /* typedef of wc_Sha512 */
        wc_Sha512 sha512;
    } dig_ctx;
    /* Find operation state */
    int              find_active;
    CK_ULONG         find_pos;
    wp11_find_attr_t find_tmpl[FIND_TMPL_MAX_ATTRS];
    CK_ULONG         find_tmpl_count;
} wp11_session_t;

static wp11_session_t g_sessions[MAX_SESSIONS];

/* -------------------------------------------------------------------------
 * Key object model
 * ---------------------------------------------------------------------- */

#define MAX_KEYS 64

/* wolfP11-1am6: sentinel for wp11_key_obj_t.sig_len_max meaning "not yet
 * known; use the 512-byte conservative fallback in C_Sign size queries".
 * A zero here is safe -- C_Sign returns 512 to callers that omit DER parsing
 * or do not set sig_len_max after key load.  Do not set this field to 0 to
 * mean "zero-length signature" -- that is not a valid PKCS#11 output. */
#define WP11_SIG_LEN_UNKNOWN  0u

typedef struct {
    int              in_use;
    CK_SLOT_ID       slot_id;
    CK_OBJECT_CLASS  obj_class;
    CK_KEY_TYPE      key_type;
    /* Backend-specific key state.  Ownership depends on the backend:
     *   Soft token  -- heap-alloc'd wp11_soft_key_t; backend_ops->free_key_priv
     *                 is non-NULL and releases it via wp11_soft_key_free.
     *   Flash token -- pointer into a wp11_key_entry_t inside the slot's
     *                 keystore (NOT individually alloc'd); backend_ops->
     *                 free_key_priv is NULL so callers skip the per-key free;
     *                 wp11_keystore_free handles bulk teardown. */
    void            *key_priv;
    /* wolfP11-3qf: max signature output bytes for this key.
     * Set once when the key object is created; read by C_Sign(pSignature=NULL).
     * 0 means unknown -- callers fall back to a conservative bound. */
    CK_ULONG         sig_len_max;
    char             label[32];
    char             application[64]; /* CKA_APPLICATION bytes for CKO_DATA objects */
    uint8_t          application_len; /* actual bytes stored in application[] */
    /* wolfP11-be5: dispatch table for this key's backend.
     *
     * Also encodes key_priv ownership: if free_key_priv is non-NULL the
     * caller (C_Finalize, C_DestroyObject) invokes it; if NULL the backend
     * owns key_priv in bulk and the caller must not free it individually.
     *
     * NULL backend_ops means the slot was cleared without going through the
     * normal free path (should not happen, but is caught defensively). */
    const wp11_backend_ops_t *backend_ops;
    /* CKA_ID byte array and its length (0 = no ID set).
     * For persistent soft-token keys: 16 random bytes (set by wolfP11-y4w).
     * For PIV hardware keys: 1 byte (slot index 0x01-0x04).
     * All-zeros / id_len == 0 means no ID has been assigned. */
    uint8_t  id[16];
    uint8_t  id_len;
    /* CKA_PRIVATE attribute: CK_TRUE means this object requires login to use.
     * Hardware token keys (PIV) and persistent keystore keys are always private.
     * Session objects generated with CKA_PRIVATE=false in the template are not.
     * C_SignInit, C_VerifyInit, C_DecryptInit skip the login check when false. */
    CK_BBOOL is_private;
    /* CKA_TOKEN: 0 = session object (default -- g_keys[] zero-initialised),
     * 1 = persistent token object.  C_CreateObject with CKA_TOKEN=false leaves
     * this at 0; all other creation paths (PIV, keystore, C_GenerateKeyPair,
     * C_DeriveKey) set it to CK_TRUE so C_GetAttributeValue and
     * key_matches_template reflect the correct value. */
    CK_BBOOL is_token;
    /* CKO_CERTIFICATE objects: malloc'd DER cert bytes and length.
     * NULL / 0 for key objects (CKO_PRIVATE_KEY, CKO_PUBLIC_KEY).
     * Freed by piv_slot_clear_keys when the PIV slot is logged out. */
    uint8_t *cert_der;
    size_t   cert_der_len;
    /* CKO_SECRET_KEY objects from C_DeriveKey and C_GenerateKey:
     * malloc'd key bytes.  Zeroed and freed by C_DestroyObject and C_Finalize.
     * Also used by C_CreateObject (CKO_DATA) to store the object value.
     * NULL / 0 for asymmetric key objects. */
    uint8_t *secret;
    size_t   secret_len;
    /* PKCS#11 sec.9.8 secret-key boolean attributes.
     * Zero-initialised fields give safe defaults for non-secret-key objects.
     * Defaults for C_GenerateKey: sensitive=false, extractable=true.
     * is_extractable is NOT safe to read when zero for keys that were created
     * before this field existed -- use is_local to distinguish. */
    CK_BBOOL          is_sensitive;      /* CKA_SENSITIVE                     */
    CK_BBOOL          is_extractable;    /* CKA_EXTRACTABLE                   */
    CK_BBOOL          always_sensitive;  /* CKA_ALWAYS_SENSITIVE (read-only)  */
    CK_BBOOL          never_extractable; /* CKA_NEVER_EXTRACTABLE (read-only) */
    CK_BBOOL          is_local;          /* CKA_LOCAL: generated on-token     */
    CK_MECHANISM_TYPE key_gen_mech;      /* CKA_KEY_GEN_MECHANISM             */
} wp11_key_obj_t;

static wp11_key_obj_t g_keys[MAX_KEYS];

/* -------------------------------------------------------------------------
 * Slot model
 *
 * Slot 0: always the soft token (wolfCrypt direct). Always present.
 *         usb_vid/pid = 0. Never removed.
 *
 * Slots 1..WOLFP11_CFG_MAX_SLOTS-1: USB hardware token slots.
 *         Dynamically added on USB arrival, cleared on departure.
 *         token_present reflects real-time hotplug state.
 *
 * Slot IDs are indices into g_slots[]. A slot is live when in_use == 1.
 * token_present == 0 means the slot exists but has no token (recently removed).
 * ---------------------------------------------------------------------- */
#define MAX_SLOTS WOLFP11_CFG_MAX_SLOTS

typedef struct {
    int          in_use;        /* 1 = slot exists and is visible to callers */
    int          token_present; /* 1 = token is currently in the slot        */
    uint16_t     usb_vid;       /* 0 for soft token or flash slot            */
    uint16_t     usb_pid;       /* 0 for soft token or flash slot            */
    char         label[33];     /* NUL-terminated token label                */
    wp11_proto_t proto;         /* protocol (PIV, OpenPGP, etc.)             */
#ifdef WOLFP11_CFG_USB_BACKEND
    /* Open CCID context for USB hardware token slots (PIV, OpenPGP).
     * Non-NULL when the slot is logged in via a CCID device.
     * Opened at C_Login, closed at C_Logout and token departure. */
    wp11_ccid_ctx_t *ccid;
#endif
#if defined(WOLFP11_CFG_USB_FLASH_BACKEND) || defined(WOLFP11_CFG_FSDIR_BACKEND)
    /* Full path to the .p11k keystore file for this slot.
     * USB flash slots: set when the .p11k file appears on USB media.
     * FSDIR slots: set when the .p11k file appears in the watched directory.
     * Soft token (slot 0): set at C_Initialize from env/config/default. */
    char             keystore_path[256];
    /* Loaded keystore: non-NULL when the slot is logged in.
     * Owns the mlock'd key material; freed at C_Logout / token departure.
     * Not used for soft-proto slot 0 (DER is imported into wp11_soft_key_t). */
    wp11_keystore_t *keystore;
#endif
#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
    /* Soft-token PIN cache: mlock'd during the logged-in period.
     * Used to re-encrypt the .p11k file when C_GenerateKeyPair adds a key.
     * Only meaningful for proto == WP11_PROTO_SOFT; zeroized at C_Logout. */
    uint8_t          soft_pin[64];
    size_t           soft_pin_len;
#endif
#ifdef WOLFP11_CFG_WOLFHSM_BACKEND
    /* wolfHSM client context for WP11_PROTO_WOLFHSM slots.
     * NULL until C_Login establishes the connection to the wolfHSM server
     * (wolfP11-s5x).  Stored as void* to avoid pulling wolfHSM headers into
     * the PKCS#11 layer; cast to whClientContext* in wolfhsm-specific code. */
    void *hsm_client;
    /* Server address passed to the wolfHSM transport layer at C_Login.
     * Set at C_Initialize from WOLFP11_WOLFHSM_SERVER_ADDR env var or the
     * WOLFP11_CFG_WOLFHSM_SERVER_ADDR compile-time default.  Never changes
     * after C_Initialize. */
    char  hsm_server_addr[256];
#endif
    /* Consecutive failed C_Login (wrong PIN) count for this slot.
     * Reset to 0 on successful C_Login.  Used to set CKF_USER_PIN_COUNT_LOW
     * in C_GetTokenInfo per PKCS#11 2.40 sec.11.5.  Any non-zero value causes
     * CKF_USER_PIN_COUNT_LOW to be reported (conservative: flag after the
     * first failed attempt). */
    int pin_fail_count;
} wp11_slot_t;

static wp11_slot_t g_slots[MAX_SLOTS];

/* -------------------------------------------------------------------------
 * Hotplug event queue
 *
 * Ring buffer of slot-change events for C_WaitForSlotEvent.
 * Producer: hotplug callback (signals g_hotplug_cond).
 * Consumer: C_WaitForSlotEvent.
 * Protected by g_hotplug_mutex.
 * ---------------------------------------------------------------------- */
#define WP11_HOTPLUG_QUEUE_SIZE 64u

typedef struct {
    CK_SLOT_ID slot_id;
    int        arrived;  /* 1 = token arrived, 0 = token departed */
} wp11_hotplug_event_t;

static pthread_mutex_t       g_hotplug_mutex;
static pthread_cond_t        g_hotplug_cond;
static int                   g_hotplug_mutex_ready = 0;
static wp11_hotplug_event_t  g_hotplug_queue[WP11_HOTPLUG_QUEUE_SIZE];
static unsigned int          g_hotplug_head = 0u;    /* index of oldest event */
static unsigned int          g_hotplug_tail = 0u;    /* index of next empty slot */
static unsigned int          g_hotplug_dropped = 0u; /* events dropped due to full queue */

#ifdef WOLFP11_CFG_USB_BACKEND
/* Background thread that drives the libusb event loop so hotplug callbacks fire. */
static pthread_t              g_event_thread;
/* wolfP11-6vz: volatile is insufficient on weakly-ordered architectures
 * (ARM, MIPS): it prevents compiler caching but provides no hardware memory
 * barrier.  A store from the main thread may not be visible to the background
 * thread before the wakeup syscall fires.  We use GCC/clang __atomic builtins
 * (available in C99 mode) with RELEASE/ACQUIRE ordering:
 *   Store(__ATOMIC_RELEASE): visible before libusb_interrupt_event_handler()
 *   Load (__ATOMIC_ACQUIRE): thread sees the store before acting on exit cond.
 * Stores that occur while g_lock is held and before thread creation use
 * RELAXED -- no other thread can observe them at that point. */
static int                    g_event_thread_running = 0;
static libusb_context        *g_usb_ctx = NULL;
static libusb_hotplug_callback_handle g_hotplug_handle;
#endif /* WOLFP11_CFG_USB_BACKEND */

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
/* Maximum number of simultaneously watched subdirectories (= simultaneously
 * mounted USB drives that the inotify thread tracks). */
#define WP11_FLASH_MAX_SUBDIRS 16

/* Per-subdir inotify watch record.  Protected by the inotify thread -- only
 * the inotify thread reads/writes these; no other thread touches them. */
typedef struct {
    int  wd;            /* inotify watch descriptor, -1 = slot is free  */
    char path[256];     /* full path of the watched subdirectory         */
} wp11_flash_watch_t;

static pthread_t          g_flash_thread;
/* Same rationale as g_event_thread_running above (wolfP11-6vz): uses
 * __atomic_store_n/__atomic_load_n rather than volatile. */
static int                g_flash_thread_running = 0;
static int                g_flash_inotify_fd     = -1;
static int                g_flash_root_wd        = -1; /* wd for WATCH_DIR itself */
/* Self-pipe: C_Finalize writes a byte to [1]; thread wakes on [0] and exits.
 * Using a pipe instead of a flag+signal prevents the thread from blocking
 * indefinitely in select() when there are no filesystem events. */
static int                g_flash_wake_pipe[2];
static wp11_flash_watch_t g_flash_watches[WP11_FLASH_MAX_SUBDIRS];
#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */

#ifdef WOLFP11_CFG_FSDIR_BACKEND
static pthread_t g_fsdir_thread;
/* Same rationale as g_event_thread_running (wolfP11-6vz): atomic store/load. */
static int       g_fsdir_thread_running = 0;
static int       g_fsdir_inotify_fd     = -1;
static int       g_fsdir_wd             = -1; /* wd for the watched directory */
/* Self-pipe for clean shutdown: C_Finalize writes to [1]; thread wakes and exits. */
static int       g_fsdir_wake_pipe[2];
/* Resolved watch directory: set from WOLFP11_FSDIR_PATH env var or
 * WOLFP11_CFG_FSDIR_PATH at C_Initialize time. */
static char      g_fsdir_path[256];
#endif /* WOLFP11_CFG_FSDIR_BACKEND */

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

/* Forward declaration -- definition below C_EncryptInit */
static CK_RV validate_mechanism_params(CK_MECHANISM_PTR mech);

/* Returns the block size in bytes for a symmetric cipher mechanism.
 * Returns 0 for non-cipher or unknown mechanisms. */
static CK_ULONG mech_block_size(CK_MECHANISM_TYPE mech)
{
    switch (mech) {
    case CKM_DES_ECB:  case CKM_DES_CBC:
    case CKM_DES3_ECB: case CKM_DES3_CBC:
        return 8;
    case CKM_AES_ECB: case CKM_AES_CBC:
        return 16;
    default:
        return 0;
    }
}

/* Returns 1 if mechanism is a symmetric block cipher with an IV. */
static int mech_has_iv(CK_MECHANISM_TYPE mech)
{
    return (mech == CKM_DES_CBC || mech == CKM_DES3_CBC || mech == CKM_AES_CBC);
}

/* Returns the required CK_KEY_TYPE for a cipher mechanism, or
 * (CK_KEY_TYPE)-1 for non-cipher / unknown mechanisms. */
static CK_KEY_TYPE mech_required_key_type(CK_MECHANISM_TYPE mech)
{
    switch (mech) {
    case CKM_DES_ECB:  case CKM_DES_CBC:  return CKK_DES;
    case CKM_DES3_ECB: case CKM_DES3_CBC: return CKK_DES3;
    case CKM_AES_ECB:  case CKM_AES_CBC:  return CKK_AES;
    default: return (CK_KEY_TYPE)-1;
    }
}

/* Returns the wolfCrypt HMAC type for a PKCS#11 HMAC mechanism.
 * Returns -1 for non-HMAC mechanisms. */
static int mech_hmac_type(CK_MECHANISM_TYPE mech)
{
    switch (mech) {
    case CKM_MD5_HMAC:    return WC_MD5;
    case CKM_SHA_1_HMAC:  return WC_SHA;
    case CKM_SHA256_HMAC: return WC_SHA256;
    case CKM_SHA384_HMAC: return WC_SHA384;
    case CKM_SHA512_HMAC: return WC_SHA512;
    default: return -1;
    }
}

/* Returns the HMAC output size in bytes for an HMAC mechanism, 0 if unknown. */
static CK_ULONG mech_hmac_output_size(CK_MECHANISM_TYPE mech)
{
    switch (mech) {
    case CKM_MD5_HMAC:    return 16;
    case CKM_SHA_1_HMAC:  return 20;
    case CKM_SHA256_HMAC: return 32;
    case CKM_SHA384_HMAC: return 48;
    case CKM_SHA512_HMAC: return 64;
    default: return 0;
    }
}

/* Returns the digest output size in bytes for a digest mechanism, 0 if unknown. */
static CK_ULONG mech_digest_output_size(CK_MECHANISM_TYPE mech)
{
    switch (mech) {
    case CKM_MD5:    return 16;
    case CKM_SHA_1:  return 20;
    case CKM_SHA256: return 32;
    case CKM_SHA384: return 48;
    case CKM_SHA512: return 64;
    default: return 0;
    }
}

/* Pad a string with spaces to exactly len bytes (no NUL terminator) */
static void pad_string(CK_UTF8CHAR *dst, size_t dst_len,
                        const char *src)
{
    size_t src_len = strlen(src);
    size_t copy = src_len < dst_len ? src_len : dst_len;
    memcpy(dst, src, copy);
    if (copy < dst_len) {
        memset(dst + copy, ' ', dst_len - copy);
    }
}

static int session_handle_valid(CK_SESSION_HANDLE h)
{
    if (h == 0 || h > MAX_SESSIONS) {
        return 0;
    }
    return g_sessions[h - 1].in_use;
}

static wp11_session_t *session_get(CK_SESSION_HANDLE h)
{
    if (!session_handle_valid(h)) {
        return NULL;
    }
    return &g_sessions[h - 1];
}

static int key_handle_valid(CK_OBJECT_HANDLE h)
{
    if (h == 0 || h > MAX_KEYS) {
        return 0;
    }
    return g_keys[h - 1].in_use;
}

static wp11_key_obj_t *key_get(CK_OBJECT_HANDLE h)
{
    if (!key_handle_valid(h)) {
        return NULL;
    }
    return &g_keys[h - 1];
}

/* Return 1 if slotID is a valid, in-use slot index. Must be called under g_lock. */
static int slot_valid(CK_SLOT_ID slotID)
{
    if (slotID >= (CK_SLOT_ID)MAX_SLOTS) return 0;
    return g_slots[slotID].in_use;
}

/* Add a new USB token slot. Must be called under g_lock.
 * Returns the new slot ID (>= 1), or (CK_SLOT_ID)-1 if no room.
 * Slot 0 is reserved for the soft token; USB slots start at 1. */
static CK_SLOT_ID slot_add(uint16_t vid, uint16_t pid)
{
    const wp11_token_desc_t *desc;
    CK_SLOT_ID i;

    desc = wp11_token_db_lookup(vid, pid);
    if (desc == NULL) return (CK_SLOT_ID)-1;  /* unknown token */

    /* Search for an existing slot for this VID/PID (re-insertion case) */
    for (i = 1; i < (CK_SLOT_ID)MAX_SLOTS; i++) {
        if (g_slots[i].in_use &&
            g_slots[i].usb_vid == vid &&
            g_slots[i].usb_pid == pid) {
            g_slots[i].token_present = 1;
            return i;
        }
    }

    /* Allocate a new slot */
    for (i = 1; i < (CK_SLOT_ID)MAX_SLOTS; i++) {
        if (!g_slots[i].in_use) {
            g_slots[i].in_use        = 1;
            g_slots[i].token_present = 1;
            g_slots[i].usb_vid       = vid;
            g_slots[i].usb_pid       = pid;
            g_slots[i].proto         = desc->proto;
            strncpy(g_slots[i].label, desc->name,
                    sizeof(g_slots[i].label) - 1u);
            g_slots[i].label[sizeof(g_slots[i].label) - 1u] = '\0';
            return i;
        }
    }

    return (CK_SLOT_ID)-1; /* slot table full */
}

#ifdef WOLFP11_CFG_USB_BACKEND
/* Remove and free all USB hardware token key objects in g_keys[] for slot_id.
 * Calls free_key_priv on each key (frees the wp11_usb_key_priv_t struct).
 * The CCID context itself is NOT closed here -- caller owns CCID lifetime.
 * Called by slot_remove (token departure) and C_Logout. */
static void piv_slot_clear_keys(CK_SLOT_ID slot_id)
{
    int gi;
    for (gi = 0; gi < MAX_KEYS; gi++) {
        if (g_keys[gi].in_use &&
            g_keys[gi].slot_id == slot_id &&
            g_keys[gi].backend_ops == &wp11_backend_usb_ops) {
            if (g_keys[gi].key_priv != NULL &&
                g_keys[gi].backend_ops->free_key_priv != NULL) {
                g_keys[gi].backend_ops->free_key_priv(g_keys[gi].key_priv);
            }
            if (g_keys[gi].cert_der != NULL) {
                free(g_keys[gi].cert_der);
            }
            if (g_keys[gi].secret != NULL) {
                memset(g_keys[gi].secret, 0, g_keys[gi].secret_len);
                free(g_keys[gi].secret);
            }
            memset(&g_keys[gi], 0, sizeof(g_keys[gi]));
        }
    }
}
#endif /* WOLFP11_CFG_USB_BACKEND */

/* Mark a USB token as departed. Must be called under g_lock.
 * Clears token_present and invalidates all sessions on that slot.
 * Returns the slot ID of the departed token, or (CK_SLOT_ID)-1 if not found. */
static CK_SLOT_ID slot_remove(uint16_t vid, uint16_t pid)
{
    CK_SLOT_ID i;
    int j;

    for (i = 1; i < (CK_SLOT_ID)MAX_SLOTS; i++) {
        if (g_slots[i].in_use &&
            g_slots[i].usb_vid == vid &&
            g_slots[i].usb_pid == pid &&
            g_slots[i].token_present) {
            g_slots[i].token_present = 0;

            /* Invalidate all open sessions on this slot so that subsequent
             * C_* calls on those handles return CKR_SESSION_HANDLE_INVALID.
             * Per PKCS#11 2.40 sec.11.16, token removal may invalidate sessions. */
            for (j = 0; j < MAX_SESSIONS; j++) {
                if (g_sessions[j].in_use &&
                    g_sessions[j].slot_id == i) {
                    memset(&g_sessions[j], 0, sizeof(g_sessions[j]));
                }
            }

#ifdef WOLFP11_CFG_USB_BACKEND
            /* Close the CCID context if the token was removed while logged in */
            if (g_slots[i].ccid != NULL) {
                piv_slot_clear_keys(i);
                wp11_ccid_close(g_slots[i].ccid);
                g_slots[i].ccid = NULL;
            }
#endif

            return i;
        }
    }

    return (CK_SLOT_ID)-1;
}

/* Forward declaration: defined after the USB backend section. */
static void hotplug_push_event(CK_SLOT_ID slot_id, int arrived);

#if defined(WOLFP11_CFG_USB_FLASH_BACKEND) || defined(WOLFP11_CFG_FSDIR_BACKEND)

/* Forward declaration: ks_slot_clear_keys is defined in the key-management
 * section below but called here by slot_remove_keystore and
 * slot_remove_flash_dir. */
static void ks_slot_clear_keys(CK_SLOT_ID slot_id);

/* Add (or re-activate) a keystore slot for the given .p11k file path.
 * proto: WP11_PROTO_FLASH or WP11_PROTO_FSDIR.
 * Must be called under g_lock.
 * Returns the slot ID (>= 1), or (CK_SLOT_ID)-1 on failure. */
static CK_SLOT_ID slot_add_keystore(const char *path, wp11_proto_t proto)
{
    const char *name;
    CK_SLOT_ID i;

    /* Reject paths that are too long to store without truncation.
     * Scan helpers build paths in fpath[512] and skip >= 512 chars, but
     * keystore_path[] is only 256 bytes.  Without this guard, a path of
     * 256..511 chars would be silently stored truncated, causing
     * slot_remove_keystore (with the full path) to fail to find the slot. */
    if (strlen(path) >= sizeof(g_slots[0].keystore_path)) {
        return (CK_SLOT_ID)-1;
    }

    /* Re-insertion: if a slot for this path and proto already exists
     * (token_present == 0), re-activate it rather than allocating a new slot.
     * Keeps slot IDs stable across remove/reinsert cycles. */
    for (i = 1; i < (CK_SLOT_ID)MAX_SLOTS; i++) {
        if (g_slots[i].in_use &&
            g_slots[i].proto == proto &&
            strncmp(g_slots[i].keystore_path, path,
                    sizeof(g_slots[i].keystore_path) - 1u) == 0) {
            g_slots[i].token_present = 1;
            return i;
        }
    }

    /* Allocate a new slot */
    for (i = 1; i < (CK_SLOT_ID)MAX_SLOTS; i++) {
        if (!g_slots[i].in_use) {
            g_slots[i].in_use        = 1;
            g_slots[i].token_present = 1;
            g_slots[i].usb_vid       = 0;
            g_slots[i].usb_pid       = 0;
            g_slots[i].proto         = proto;
            strncpy(g_slots[i].keystore_path, path,
                    sizeof(g_slots[i].keystore_path) - 1u);
            g_slots[i].keystore_path[sizeof(g_slots[i].keystore_path) - 1u] = '\0';

            /* Derive a human-readable label from the filename (drop directory). */
            name = strrchr(path, '/');
            name = (name != NULL) ? name + 1 : path;
            strncpy(g_slots[i].label, name, sizeof(g_slots[i].label) - 1u);
            g_slots[i].label[sizeof(g_slots[i].label) - 1u] = '\0';
            return i;
        }
    }

    return (CK_SLOT_ID)-1;  /* slot table full */
}

/* Mark a keystore slot as departed (token removed / file deleted).
 * Must be called under g_lock.
 * Returns the slot ID, or (CK_SLOT_ID)-1 if not found. */
static CK_SLOT_ID slot_remove_keystore(const char *path)
{
    CK_SLOT_ID i;
    int j;

    for (i = 1; i < (CK_SLOT_ID)MAX_SLOTS; i++) {
        if (g_slots[i].in_use &&
            g_slots[i].token_present &&
            strncmp(g_slots[i].keystore_path, path,
                    sizeof(g_slots[i].keystore_path) - 1u) == 0) {
            /* Clear keys BEFORE freeing the keystore so key_priv pointers
             * (into keystore memory) are not left dangling (wolfP11-be5). */
            ks_slot_clear_keys(i);
            if (g_slots[i].keystore != NULL) {
                wp11_keystore_free(g_slots[i].keystore);
                g_slots[i].keystore = NULL;
            }
            g_slots[i].token_present = 0;

            /* Invalidate open sessions */
            for (j = 0; j < MAX_SESSIONS; j++) {
                if (g_sessions[j].in_use && g_sessions[j].slot_id == i) {
                    memset(&g_sessions[j], 0, sizeof(g_sessions[j]));
                }
            }
            return i;
        }
    }

    return (CK_SLOT_ID)-1;
}

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND

/* Remove all flash slots whose path starts with the given directory prefix.
 * Used when an entire mount point disappears (USB drive unplugged while
 * multiple .p11k files were loaded from it).
 * Must be called under g_lock. */
static void slot_remove_flash_dir(const char *dir_path, size_t dir_len)
{
    CK_SLOT_ID i;
    int j;

    for (i = 1; i < (CK_SLOT_ID)MAX_SLOTS; i++) {
        if (!g_slots[i].in_use || !g_slots[i].token_present) continue;
        if (g_slots[i].proto != WP11_PROTO_FLASH) continue;
        /* Check if this slot's path is under dir_path/ */
        if (strncmp(g_slots[i].keystore_path, dir_path, dir_len) != 0) continue;
        if (g_slots[i].keystore_path[dir_len] != '/' &&
            g_slots[i].keystore_path[dir_len] != '\0') continue;

        /* Same clear-then-free ordering as slot_remove_keystore and C_Finalize. */
        ks_slot_clear_keys(i);
        if (g_slots[i].keystore != NULL) {
            wp11_keystore_free(g_slots[i].keystore);
            g_slots[i].keystore = NULL;
        }
        g_slots[i].token_present = 0;

        /* Invalidate open sessions */
        for (j = 0; j < MAX_SESSIONS; j++) {
            if (g_sessions[j].in_use && g_sessions[j].slot_id == i) {
                memset(&g_sessions[j], 0, sizeof(g_sessions[j]));
            }
        }

        /* Push departure event for each removed slot. */
        hotplug_push_event(i, 0);
    }
}

#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */

#endif /* WOLFP11_CFG_USB_FLASH_BACKEND || WOLFP11_CFG_FSDIR_BACKEND */

/* Push a hotplug event to the ring buffer and signal any waiters.
 * Called with g_lock held but NOT g_hotplug_mutex -- acquires it internally.
 * Separate lock for the queue so C_WaitForSlotEvent can wait without holding g_lock. */
static void hotplug_push_event(CK_SLOT_ID slot_id, int arrived)
{
    unsigned int next_tail;

    if (!g_hotplug_mutex_ready) return;

    if (pthread_mutex_lock(&g_hotplug_mutex) != 0) return;
    next_tail = (g_hotplug_tail + 1u) % WP11_HOTPLUG_QUEUE_SIZE;
    if (next_tail != g_hotplug_head) {
        /* Queue not full: enqueue */
        g_hotplug_queue[g_hotplug_tail].slot_id  = slot_id;
        g_hotplug_queue[g_hotplug_tail].arrived  = arrived;
        g_hotplug_tail = next_tail;
        pthread_cond_broadcast(&g_hotplug_cond);
    }
    /* If queue is full, drop the event and count it.  Callers can re-enumerate
     * via C_GetSlotList to recover current state.  g_hotplug_dropped is a
     * diagnostic counter readable in tests via wp11_test_hotplug_dropped(). */
    else {
        g_hotplug_dropped++;
    }
    (void)pthread_mutex_unlock(&g_hotplug_mutex);
}

#ifdef WOLFP11_CFG_USB_BACKEND

/* libusb hotplug callback. Called from the g_event_thread on each USB plug/unplug.
 * Per libusb docs: it is safe to call libusb_hotplug_deregister_callback()
 * from within a callback; we do not, but we are safe to update state here. */
static int LIBUSB_CALL hotplug_cb(libusb_context *ctx,
                                   libusb_device  *dev,
                                   libusb_hotplug_event event,
                                   void           *user_data)
{
    struct libusb_device_descriptor desc;
    int arrived = (event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED);
    CK_SLOT_ID slot_id;

    (void)ctx; (void)user_data;

    if (libusb_get_device_descriptor(dev, &desc) != 0) return 0;

    /* Validate descriptor type before trusting VID/PID -- malformed descriptors
     * can match arbitrary token_db entries.  USB spec requires bDescriptorType
     * == LIBUSB_DT_DEVICE (0x01), bLength == 18, and idVendor != 0 (USB-IF
     * does not assign vendor ID 0). */
    if (desc.bDescriptorType != LIBUSB_DT_DEVICE) return 0;
    if (desc.bLength != LIBUSB_DT_DEVICE_SIZE) return 0;
    if (desc.idVendor == 0u) return 0;

    /* Only process tokens we know about (in the token database).
     * LIBUSB_HOTPLUG_MATCH_ANY was used for the VID/PID filter so we see
     * all USB devices; filter here for known tokens only. */
    if (wp11_token_db_lookup(desc.idVendor, desc.idProduct) == NULL) return 0;

    /* Update slot table under g_lock, then push event (g_lock not held
     * when signaling g_hotplug_cond to avoid any lock-ordering hazard). */
    if (wc_LockMutex(&g_lock) != 0) return 0;

    if (arrived) {
        slot_id = slot_add(desc.idVendor, desc.idProduct);
    } else {
        slot_id = slot_remove(desc.idVendor, desc.idProduct);
    }

    wc_UnLockMutex(&g_lock);

    if (slot_id == (CK_SLOT_ID)-1) return 0;

    /* Push event OUTSIDE g_lock -- hotplug_push_event acquires g_hotplug_mutex
     * internally. This keeps the two lock hierarchies from inverting. */
    hotplug_push_event(slot_id, arrived);

    return 0; /* returning non-zero would de-register the callback */
}

/* Background thread: drains libusb events so hotplug callbacks fire.
 * Runs until g_event_thread_running is set to 0 and libusb is interrupted. */
static void *event_thread_fn(void *arg)
{
    struct timeval tv;
    (void)arg;

    while (__atomic_load_n(&g_event_thread_running, __ATOMIC_ACQUIRE)) {
        tv.tv_sec  = 0;
        tv.tv_usec = 100000; /* 100 ms timeout -- bounds worst-case shutdown latency */
        libusb_handle_events_timeout(g_usb_ctx, &tv);
    }
    return NULL;
}

#endif /* WOLFP11_CFG_USB_BACKEND */

#ifdef WOLFP11_CFG_TEST

#ifdef WOLFP11_CFG_USB_BACKEND

/* Transport function that returns SW 90 00 for any APDU.
 * Used by wp11_test_inject_piv_login.  GET DATA (INS 0xCB) returns success
 * with no payload, so BER-TLV parsing in wp11_piv_get_cert will find no
 * 0x53 tag and skip cert object creation. */
static int piv_mock_ok_transport(void          *ud,
                                  const uint8_t *out, size_t  outlen,
                                  uint8_t       *in,  size_t *inlen)
{
    uint8_t seq;
    (void)ud;

    if (in == NULL || inlen == NULL || *inlen < 12u) return -1;
    if (out == NULL || outlen < 10u)                  return -1;

    seq = out[6];

    memset(in, 0, 12u);
    in[0]  = 0x80u; /* RDR_to_PC_DataBlock */
    in[1]  = 2u;    /* dwLength lo = 2 (SW1 + SW2) */
    in[6]  = seq;
    in[7]  = 0x00u;
    in[10] = 0x90u; /* SW1 */
    in[11] = 0x00u; /* SW2 */
    *inlen = 12u;
    return 0;
}

/* Synthetic cert bytes returned by piv_mock_cert_transport for GET DATA.
 * Not a valid ASN.1 structure -- only the BER-TLV container is real.
 * Tests verify that these exact bytes appear in CKA_VALUE. */
static const uint8_t piv_cert_stub[10] = {
    0x01u, 0x02u, 0x03u, 0x04u, 0x05u,
    0x06u, 0x07u, 0x08u, 0x09u, 0x0Au
};

/* Transport function that returns a synthetic PIV BER-TLV cert object for
 * GET DATA (INS 0xCB) and SW 90 00 for all other APDUs.
 * Response: 53 0E { 70 0A [10 cert bytes] FE 00 } 90 00 (18 bytes APDU). */
static int piv_mock_cert_transport(void          *ud,
                                    const uint8_t *out, size_t  outlen,
                                    uint8_t       *in,  size_t *inlen)
{
    uint8_t seq;
    uint8_t ins;

    (void)ud;

    if (in == NULL || inlen == NULL || *inlen < 28u) return -1;
    if (out == NULL || outlen < 12u)                  return -1;

    seq = out[6];   /* bSeq */
    ins = out[11];  /* INS byte (APDU byte 1, CCID header is 10 bytes) */

    if (ins == 0xCBu) {
        /* GET DATA: return PIV object 53 { 70 { cert_stub } FE 00 } SW */
        memset(in, 0, 28u);
        in[0]  = 0x80u; /* RDR_to_PC_DataBlock */
        in[1]  = 18u;   /* dwLength = 18 */
        in[6]  = seq;
        in[7]  = 0x00u;
        in[10] = 0x53u; /* outer tag */
        in[11] = 0x0Eu; /* outer len = 14: 70 0A [10] FE 00 */
        in[12] = 0x70u; /* cert tag */
        in[13] = 0x0Au; /* cert len = 10 */
        memcpy(&in[14], piv_cert_stub, sizeof(piv_cert_stub));
        in[24] = 0xFEu; /* Error Detection Code tag */
        in[25] = 0x00u; /* EDC length = 0 */
        in[26] = 0x90u; /* SW1 */
        in[27] = 0x00u; /* SW2 */
        *inlen = 28u;
    } else {
        memset(in, 0, 12u);
        in[0]  = 0x80u;
        in[1]  = 2u;
        in[6]  = seq;
        in[7]  = 0x00u;
        in[10] = 0x90u;
        in[11] = 0x00u;
        *inlen = 12u;
    }
    return 0;
}

/* Shared implementation for test PIV login injection.
 * Creates 4 CKO_PRIVATE_KEY objects and attempts cert retrieval for each slot.
 * Cert objects are created only when transport_fn returns valid GET DATA data.
 * Callable from test code without g_lock held. */
static void piv_inject_login_impl(CK_SLOT_ID slot_id,
                                   wp11_ccid_transport_fn transport_fn)
{
    static const struct {
        uint8_t    piv_slot;
        uint8_t    piv_alg;
        uint8_t    key_id;
        CK_ULONG   sig_len_max;
        const char *label;
    } piv_slot_tab[] = {
        { WP11_PIV_SLOT_AUTH,     WP11_PIV_ALG_EC_P256, 0x01, 72u, "PIV Authentication"    },
        { WP11_PIV_SLOT_SIGN,     WP11_PIV_ALG_EC_P256, 0x02, 72u, "PIV Digital Signature" },
        { WP11_PIV_SLOT_KEYMGMT,  WP11_PIV_ALG_EC_P256, 0x03, 72u, "PIV Key Management"    },
        { WP11_PIV_SLOT_CARDAUTH, WP11_PIV_ALG_EC_P256, 0x04, 72u, "PIV Card Authentication" },
    };
    wp11_ccid_ctx_t *ccid = NULL;
    size_t ns;
    int ki;

    if (slot_id >= MAX_SLOTS || !g_slots[slot_id].in_use) return;
    if (g_slots[slot_id].proto != WP11_PROTO_PIV)         return;
    if (g_slots[slot_id].ccid != NULL)                    return;

    if (wp11_ccid_open_mock(transport_fn, NULL, &ccid) != WP11_CCID_OK)
        return;
    if (wp11_piv_select(ccid) != WP11_PIV_OK) {
        wp11_ccid_close(ccid);
        return;
    }
    if (wp11_piv_verify_pin(ccid,
                              (const uint8_t *)"123456", 6u) != WP11_PIV_OK) {
        wp11_ccid_close(ccid);
        return;
    }

    /* Create one CKO_PRIVATE_KEY object per PIV slot */
    for (ns = 0; ns < sizeof(piv_slot_tab)/sizeof(piv_slot_tab[0]); ns++) {
        wp11_usb_key_priv_t *kp;

        for (ki = 0; ki < MAX_KEYS; ki++) {
            if (!g_keys[ki].in_use) break;
        }
        if (ki == MAX_KEYS) {
            piv_slot_clear_keys(slot_id);
            wp11_ccid_close(ccid);
            return;
        }

        kp = (wp11_usb_key_priv_t *)malloc(sizeof(*kp));
        if (kp == NULL) {
            piv_slot_clear_keys(slot_id);
            wp11_ccid_close(ccid);
            return;
        }
        kp->ccid     = ccid;
        kp->piv_slot = piv_slot_tab[ns].piv_slot;
        kp->piv_alg  = piv_slot_tab[ns].piv_alg;

        g_keys[ki].in_use      = 1;
        g_keys[ki].slot_id     = (int)slot_id;
        g_keys[ki].obj_class   = CKO_PRIVATE_KEY;
        g_keys[ki].key_type    = CKK_EC;
        g_keys[ki].sig_len_max = piv_slot_tab[ns].sig_len_max;
        g_keys[ki].key_priv    = kp;
        g_keys[ki].backend_ops = &wp11_backend_usb_ops;
        g_keys[ki].is_private  = CK_TRUE;
        g_keys[ki].is_token    = CK_TRUE;
        memset(g_keys[ki].id, 0, sizeof(g_keys[ki].id));
        g_keys[ki].id[0]       = piv_slot_tab[ns].key_id;
        g_keys[ki].id_len      = 1u;
        strncpy(g_keys[ki].label, piv_slot_tab[ns].label,
                sizeof(g_keys[ki].label) - 1u);
        g_keys[ki].label[sizeof(g_keys[ki].label) - 1u] = '\0';
    }

    /* Attempt certificate retrieval for each PIV slot.
     * Any error (not provisioned, transport error, OOM) is non-fatal. */
    for (ns = 0; ns < sizeof(piv_slot_tab)/sizeof(piv_slot_tab[0]); ns++) {
        uint8_t *der;
        size_t   derlen;
        int      crc;
        int      ci;

        der = (uint8_t *)malloc(WP11_PIV_CERT_MAX_LEN);
        if (der == NULL) break;

        derlen = WP11_PIV_CERT_MAX_LEN;
        crc = wp11_piv_get_cert(ccid, piv_slot_tab[ns].piv_slot, der, &derlen);
        if (crc != WP11_PIV_OK) {
            free(der);
            continue;
        }

        for (ci = 0; ci < MAX_KEYS; ci++) {
            if (!g_keys[ci].in_use) break;
        }
        if (ci == MAX_KEYS) {
            free(der);
            break;
        }

        g_keys[ci].in_use       = 1;
        g_keys[ci].slot_id      = (int)slot_id;
        g_keys[ci].obj_class    = CKO_CERTIFICATE;
        g_keys[ci].key_priv     = NULL;
        g_keys[ci].backend_ops  = &wp11_backend_usb_ops;
        g_keys[ci].is_token     = CK_TRUE;
        memset(g_keys[ci].id, 0, sizeof(g_keys[ci].id));
        g_keys[ci].id[0]        = piv_slot_tab[ns].key_id;
        g_keys[ci].id_len       = 1u;
        g_keys[ci].cert_der     = der;
        g_keys[ci].cert_der_len = derlen;
        strncpy(g_keys[ci].label, piv_slot_tab[ns].label,
                sizeof(g_keys[ci].label) - 1u);
        g_keys[ci].label[sizeof(g_keys[ci].label) - 1u] = '\0';
    }

    g_slots[slot_id].ccid = ccid;

    for (ki = 0; ki < MAX_SESSIONS; ki++) {
        if (g_sessions[ki].in_use && g_sessions[ki].slot_id == slot_id)
            g_sessions[ki].logged_in = 1;
    }
}

/* Simulate a successful PIV C_Login using the always-OK mock transport.
 * Creates 4 CKO_PRIVATE_KEY objects; cert slots are empty with this mock.
 * Acquires g_lock so that concurrent C_Finalize/C_Sign cannot race the
 * g_slots[]/g_keys[] mutations inside piv_inject_login_impl. */
void wp11_test_inject_piv_login(CK_SLOT_ID slot_id)
{
    if (!g_lock_ready || wc_LockMutex(&g_lock) != 0) return;
    piv_inject_login_impl(slot_id, piv_mock_ok_transport);
    (void)wc_UnLockMutex(&g_lock);
}

/* Simulate a successful PIV C_Login using the cert-providing mock transport.
 * Creates 4 CKO_PRIVATE_KEY objects and 4 CKO_CERTIFICATE objects.
 * Acquires g_lock -- see wp11_test_inject_piv_login for rationale. */
void wp11_test_inject_piv_login_with_certs(CK_SLOT_ID slot_id)
{
    if (!g_lock_ready || wc_LockMutex(&g_lock) != 0) return;
    piv_inject_login_impl(slot_id, piv_mock_cert_transport);
    (void)wc_UnLockMutex(&g_lock);
}

#endif /* WOLFP11_CFG_USB_BACKEND */

/* Inject a simulated hotplug event without real USB hardware.
 * Callable from test code.  Acquires g_lock internally.
 * arrived: 1 = token inserted, 0 = token removed. */
void wp11_test_inject_hotplug(uint16_t vid, uint16_t pid, int arrived)
{
    CK_SLOT_ID slot_id;

    if (!g_lock_ready) return;
    if (wc_LockMutex(&g_lock) != 0) return;

    if (arrived) {
        slot_id = slot_add(vid, pid);
    } else {
        slot_id = slot_remove(vid, pid);
    }

    wc_UnLockMutex(&g_lock);

    if (slot_id != (CK_SLOT_ID)-1) {
        hotplug_push_event(slot_id, arrived);
    }
}

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
/* Inject a simulated flash keystore event without real filesystem access.
 * arrived: 1 = .p11k file appeared, 0 = .p11k file removed.
 * Acquires g_lock internally; safe to call from any thread. */
void wp11_test_inject_flash_event(const char *path, int arrived)
{
    CK_SLOT_ID slot_id;

    if (!g_lock_ready) return;
    if (wc_LockMutex(&g_lock) != 0) return;

    if (arrived) {
        slot_id = slot_add_keystore(path, WP11_PROTO_FLASH);
    } else {
        slot_id = slot_remove_keystore(path);
    }

    wc_UnLockMutex(&g_lock);

    if (slot_id != (CK_SLOT_ID)-1) {
        hotplug_push_event(slot_id, arrived);
    }
}
/* Return the number of hotplug events dropped due to queue overflow since
 * the last C_Initialize.  Protected by g_hotplug_mutex. */
unsigned int wp11_test_hotplug_dropped(void)
{
    unsigned int count = 0;
    if (!g_hotplug_mutex_ready) return 0;
    if (pthread_mutex_lock(&g_hotplug_mutex) != 0) return 0;
    count = g_hotplug_dropped;
    (void)pthread_mutex_unlock(&g_hotplug_mutex);
    return count;
}
#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */
#endif /* WOLFP11_CFG_TEST */

#if defined(WOLFP11_CFG_USB_FLASH_BACKEND) || defined(WOLFP11_CFG_FSDIR_BACKEND)

/* -------------------------------------------------------------------------
 * Shared keystore backend utilities
 *
 * These functions are used by both the USB flash and FSDIR backends.
 * They are compiled whenever either backend is enabled.
 * ---------------------------------------------------------------------- */

/* wolfP11-3qf: compute the maximum signature output length for a key entry
 * by parsing its DER encoding once at C_Login time.  The result is cached
 * in wp11_key_obj_t.sig_len_max so that C_Sign(pSignature=NULL) can return
 * a mechanism-correct size instead of the hardcoded 512 that was previously
 * returned for all mechanisms.
 *
 * Return values:
 *   EC key: 8 + 2*curve_bytes  -- tight DER ECDSA upper bound (accounts for
 *           the mandatory 0x00 prefix on r and s when the high bit is set,
 *           plus SEQUENCE tag/length header).  P-256 -> 72, P-384 -> 104.
 *   RSA key: wc_RsaEncryptSize() bytes -- exact signature length (equal to
 *            modulus byte length for PKCS#1 v1.5).
 *   0 on any parsing error -- callers fall back to a conservative bound.
 *
 * Parsing is performed with temporary stack-allocated key objects that are
 * zeroed and freed before this function returns.  Key material in entry->der_bytes
 * is mlock()'d by the keystore layer and remains untouched. */
static CK_ULONG ks_key_sig_len_max(const wp11_key_entry_t *entry)
{
    word32 idx = 0;
    int key_size;

    if (entry == NULL) return 0;

    if (entry->key_type == WP11_KEY_TYPE_EC) {
        ecc_key ecc;
        if (wc_ecc_init(&ecc) != 0) return 0;
        if (wc_EccPrivateKeyDecode(entry->der_bytes, &idx, &ecc,
                                   (word32)entry->der_len) != 0) {
            wc_ecc_free(&ecc);
            return 0;
        }
        key_size = wc_ecc_size(&ecc);
        wc_ecc_free(&ecc);
        if (key_size <= 0) return 0;
        /* DER ECDSA: SEQUENCE(2) + 2xINTEGER(2 + key_size + 1 pad) */
        return (CK_ULONG)(8 + 2 * key_size);
    } else {
        RsaKey rsa;
        if (wc_InitRsaKey(&rsa, NULL) != 0) return 0;
        if (wc_RsaPrivateKeyDecode(entry->der_bytes, &idx, &rsa,
                                   (word32)entry->der_len) != 0) {
            wc_FreeRsaKey(&rsa);
            return 0;
        }
        key_size = wc_RsaEncryptSize(&rsa);
        wc_FreeRsaKey(&rsa);
        if (key_size <= 0) return 0;
        return (CK_ULONG)key_size;
    }
}

/* Check whether a filename has the ".p11k" extension.
 * Shared between the USB flash and FSDIR backends. */
static int has_p11k_extension(const char *name)
{
    size_t n = strlen(name);
    /* Minimum valid name: "a.p11k" = 6 chars */
    return n > 5u && strcmp(name + n - 5u, ".p11k") == 0;
}

#if defined(WOLFP11_CFG_USB_FLASH_BACKEND) || defined(WOLFP11_CFG_FSDIR_BACKEND)

/* -------------------------------------------------------------------------
 * Shared keystore slot key management (USB flash + FSDIR backends)
 *
 * When C_Login succeeds for a keystore slot, wp11_keystore_load() produces a
 * wp11_keystore_t containing one or more wp11_key_entry_t records.  These
 * are exposed as g_keys[] entries so C_FindObjects / C_Sign / C_Verify /
 * C_Decrypt can reach them through the standard PKCS#11 object model.
 *
 * Key ownership: g_keys[].key_priv is a POINTER INTO the keystore's internal
 * entries array -- not a separately alloc'd object.  backend_ops->free_key_priv
 * is NULL for keystore backends, signalling to C_Finalize and C_DestroyObject
 * that the keystore owns the memory (wolfP11-be5).
 * ---------------------------------------------------------------------- */

/* Populate g_keys[] with the private keys from a freshly loaded keystore.
 * ops: &wp11_backend_flash_ops or &wp11_backend_fsdir_ops.
 * Must be called under g_lock immediately after wp11_keystore_load.
 *
 * Returns the number of keys that could NOT be added because g_keys[] is
 * full.  Returns 0 when all keys were added successfully.
 *
 * Caller (C_Login) must check the return value and return CKR_DEVICE_MEMORY
 * if > 0, rather than silently presenting a partial key set to the caller.
 * A PKCS#11 application has no other way to detect a partial load. */
static int ks_slot_populate_keys(CK_SLOT_ID slot_id,
                                  wp11_keystore_t *ks,
                                  const wp11_backend_ops_t *ops)
{
    size_t nkeys;
    size_t ki;
    int    gi;
    int    dropped = 0;
    const wp11_key_entry_t *entry;

    nkeys = wp11_keystore_count(ks);
    for (ki = 0; ki < nkeys; ki++) {
        entry = wp11_keystore_get(ks, ki);
        if (entry == NULL) continue;

        /* Find a free slot in g_keys[].  MAX_KEYS is a hard limit shared
         * across all slots.  Count remaining keys as dropped rather than
         * silently omitting them. */
        for (gi = 0; gi < MAX_KEYS; gi++) {
            if (!g_keys[gi].in_use) break;
        }
        if (gi == MAX_KEYS) {
            dropped++;
            continue;   /* count all remaining, don't break early */
        }

        g_keys[gi].in_use      = 1;
        g_keys[gi].slot_id     = slot_id;
        g_keys[gi].obj_class   = CKO_PRIVATE_KEY;
        g_keys[gi].key_type    = (entry->key_type == WP11_KEY_TYPE_EC)
                                     ? CKK_EC : CKK_RSA;
        /* wolfP11-3qf: compute exact max signature length once at login time. */
        g_keys[gi].sig_len_max = ks_key_sig_len_max(entry);
        /* key_priv points into the keystore entry; keystore owns the memory.
         * ops->free_key_priv == NULL encodes this (wolfP11-be5). */
        g_keys[gi].key_priv    = (void *)entry;
        g_keys[gi].backend_ops = ops;
        g_keys[gi].is_private  = CK_TRUE;
        g_keys[gi].is_token    = CK_TRUE;
        memcpy(g_keys[gi].label, entry->label, sizeof(g_keys[gi].label) - 1u);
        g_keys[gi].label[sizeof(g_keys[gi].label) - 1u] = '\0';
    }
    return dropped;
}

/* Remove all keystore g_keys[] entries belonging to slot_id.
 * key_priv pointers are NOT freed here -- wp11_keystore_free handles bulk
 * cleanup.  Must be called under g_lock BEFORE wp11_keystore_free.
 * Identifies keystore keys by ops->free_key_priv == NULL (wolfP11-be5). */
static void ks_slot_clear_keys(CK_SLOT_ID slot_id)
{
    int gi;
    for (gi = 0; gi < MAX_KEYS; gi++) {
        if (g_keys[gi].in_use &&
            g_keys[gi].slot_id == slot_id &&
            g_keys[gi].backend_ops != NULL &&
            g_keys[gi].backend_ops->free_key_priv == NULL) {
            memset(&g_keys[gi], 0, sizeof(g_keys[gi]));
        }
    }
}

#endif /* WOLFP11_CFG_USB_FLASH_BACKEND || WOLFP11_CFG_FSDIR_BACKEND */

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND

/* -------------------------------------------------------------------------
 * wolfP11-y4w: Soft-token persistent keystore helpers
 *
 * Parallel to ks_slot_populate_keys / ks_slot_clear_keys, but for
 * the soft token (slot 0) with proto == WP11_PROTO_SOFT.
 *
 * Key difference from flash: DER bytes are imported into wolfCrypt key
 * objects (wp11_soft_key_t) rather than referenced from keystore memory.
 * This means the keystore is freed immediately after login; the soft key
 * objects carry the key material from that point on.
 *
 * All helpers must be called under g_lock.
 * ---------------------------------------------------------------------- */

/* Create wp11_soft_key_t objects from a keystore and populate g_keys[].
 * Returns the number of keys that could NOT be added (0 = all OK). */
static int soft_slot_populate_keys(CK_SLOT_ID slot_id, wp11_keystore_t *ks)
{
    size_t                  nkeys = wp11_keystore_count(ks);
    size_t                  ki;
    int                     gi;
    int                     dropped = 0;
    const wp11_key_entry_t *entry;
    wp11_soft_key_t        *sk;

    for (ki = 0; ki < nkeys; ki++) {
        entry = wp11_keystore_get(ks, ki);
        if (entry == NULL) continue;

        for (gi = 0; gi < MAX_KEYS; gi++) {
            if (!g_keys[gi].in_use) break;
        }
        if (gi == MAX_KEYS) { dropped++; continue; }

        sk = wp11_soft_key_new_from_der(entry->der_bytes, entry->der_len,
                                         entry->key_type);
        if (sk == NULL) { dropped++; continue; }

        g_keys[gi].in_use      = 1;
        g_keys[gi].slot_id     = slot_id;
        g_keys[gi].obj_class   = CKO_PRIVATE_KEY;
        g_keys[gi].key_type    = (entry->key_type == WP11_KEY_TYPE_EC)
                                     ? CKK_EC : CKK_RSA;
        g_keys[gi].sig_len_max = ks_key_sig_len_max(entry);
        g_keys[gi].key_priv    = sk;
        g_keys[gi].backend_ops = &wp11_backend_soft_ops;
        g_keys[gi].is_token    = CK_TRUE;
        memcpy(g_keys[gi].id, entry->id, 16u);
        g_keys[gi].id_len = 16u;
        memcpy(g_keys[gi].label, entry->label, sizeof(g_keys[gi].label) - 1u);
        g_keys[gi].label[sizeof(g_keys[gi].label) - 1u] = '\0';
    }
    return dropped;
}

/* Remove and free all soft-token key objects in g_keys[] for slot_id. */
static void soft_slot_clear_keys(CK_SLOT_ID slot_id)
{
    int gi;
    for (gi = 0; gi < MAX_KEYS; gi++) {
        if (g_keys[gi].in_use &&
            g_keys[gi].slot_id == slot_id &&
            g_keys[gi].backend_ops == &wp11_backend_soft_ops) {
            if (g_keys[gi].key_priv != NULL &&
                g_keys[gi].backend_ops->free_key_priv != NULL) {
                g_keys[gi].backend_ops->free_key_priv(g_keys[gi].key_priv);
            }
            if (g_keys[gi].secret != NULL) {
                memset(g_keys[gi].secret, 0, g_keys[gi].secret_len);
                free(g_keys[gi].secret);
            }
            memset(&g_keys[gi], 0, sizeof(g_keys[gi]));
        }
    }
}

/* Re-encrypt and atomically save all soft-token keys for slot_id.
 * Creates the parent directory (~/.wolfp11/) if needed.
 * Must be called under g_lock.  Returns 0 on success, -1 on error. */
static int soft_slot_save(CK_SLOT_ID slot_id)
{
    wp11_key_entry_t *entries  = NULL;
    uint8_t         **der_ptrs = NULL;
    size_t            cap = 0;
    size_t            n   = 0;
    int               gi;
    int               exp;
    int               ret = -1;

    if (g_slots[slot_id].soft_pin_len == 0) return -1;
    if (g_slots[slot_id].keystore_path[0] == '\0') return -1;

    /* Ensure parent directory exists (ignore EEXIST) */
    {
        const char *p = strrchr(g_slots[slot_id].keystore_path, '/');
        if (p != NULL && p != g_slots[slot_id].keystore_path) {
            char dir[256];
            size_t dlen = (size_t)(p - g_slots[slot_id].keystore_path);
            if (dlen < sizeof(dir)) {
                memcpy(dir, g_slots[slot_id].keystore_path, dlen);
                dir[dlen] = '\0';
                mkdir(dir, 0700); /* EEXIST is not an error */
            }
        }
    }

    /* Count soft keys for this slot */
    for (gi = 0; gi < MAX_KEYS; gi++) {
        if (g_keys[gi].in_use &&
            g_keys[gi].slot_id == slot_id &&
            g_keys[gi].backend_ops == &wp11_backend_soft_ops) {
            cap++;
        }
    }

    if (cap == 0) {
        ret = wp11_keystore_create(g_slots[slot_id].keystore_path,
                                    g_slots[slot_id].soft_pin,
                                    g_slots[slot_id].soft_pin_len,
                                    NULL, 0u);
        return (ret == WP11_KEYSTORE_OK) ? 0 : -1;
    }

    entries  = (wp11_key_entry_t *)calloc(cap, sizeof(wp11_key_entry_t));
    der_ptrs = (uint8_t **)calloc(cap, sizeof(uint8_t *));
    if (entries == NULL || der_ptrs == NULL) {
        free(entries); free(der_ptrs); return -1;
    }

    for (gi = 0; gi < MAX_KEYS && n < cap; gi++) {
        if (!g_keys[gi].in_use ||
            g_keys[gi].slot_id != slot_id ||
            g_keys[gi].backend_ops != &wp11_backend_soft_ops) continue;

        der_ptrs[n] = (uint8_t *)malloc(WP11_KEYSTORE_DER_MAX);
        if (der_ptrs[n] == NULL) goto cleanup;

        exp = wp11_soft_key_export_priv_der(
                  (wp11_soft_key_t *)g_keys[gi].key_priv,
                  der_ptrs[n], (uint32_t)WP11_KEYSTORE_DER_MAX);
        if (exp <= 0) {
            free(der_ptrs[n]); der_ptrs[n] = NULL; continue;
        }

        entries[n].der_bytes = der_ptrs[n];
        entries[n].der_len   = (size_t)exp;
        entries[n].key_type  = (g_keys[gi].key_type == CKK_EC)
                                   ? WP11_KEY_TYPE_EC : WP11_KEY_TYPE_RSA;
        memcpy(entries[n].id, g_keys[gi].id, 16u);
        strncpy(entries[n].label, g_keys[gi].label, WP11_KEYSTORE_LABEL_MAX);
        entries[n].label[WP11_KEYSTORE_LABEL_MAX] = '\0';
        n++;
    }

    ret = wp11_keystore_create(g_slots[slot_id].keystore_path,
                                g_slots[slot_id].soft_pin,
                                g_slots[slot_id].soft_pin_len,
                                entries, n);
    ret = (ret == WP11_KEYSTORE_OK) ? 0 : -1;

cleanup:
    {
        size_t ci;
        for (ci = 0; ci < cap; ci++) {
            if (der_ptrs[ci] != NULL) {
                memset(der_ptrs[ci], 0, WP11_KEYSTORE_DER_MAX);
                free(der_ptrs[ci]);
            }
        }
    }
    free(der_ptrs);
    free(entries);
    return ret;
}

/* -------------------------------------------------------------------------
 * inotify flash thread helpers
 *
 * All helpers below are called ONLY from the flash_thread_fn.  They are
 * single-threaded with respect to g_flash_watches[], so no locking is
 * needed for the watch table itself.  When they touch g_slots[], they
 * acquire g_lock; when they push events, they call hotplug_push_event
 * which acquires g_hotplug_mutex internally.
 * ---------------------------------------------------------------------- */

/* Find a free slot in g_flash_watches[].  Returns index, or -1 if full. */
static int flash_watch_alloc(void)
{
    int i;
    for (i = 0; i < WP11_FLASH_MAX_SUBDIRS; i++) {
        if (g_flash_watches[i].wd == -1) return i;
    }
    return -1;
}

/* Look up a watch entry by inotify wd.  Returns index, or -1 if not found. */
static int flash_watch_find_by_wd(int wd)
{
    int i;
    for (i = 0; i < WP11_FLASH_MAX_SUBDIRS; i++) {
        if (g_flash_watches[i].wd == wd) return i;
    }
    return -1;
}

/* Look up a watch entry by path.  Returns index, or -1 if not found. */
static int flash_watch_find_by_path(const char *path)
{
    int i;
    for (i = 0; i < WP11_FLASH_MAX_SUBDIRS; i++) {
        if (g_flash_watches[i].wd != -1 &&
            strcmp(g_flash_watches[i].path, path) == 0) {
            return i;
        }
    }
    return -1;
}

/* Register an inotify watch on dir_path and record it in g_flash_watches[].
 * Idempotent: if a watch already exists for this path, returns immediately. */
static void flash_watch_add_dir(const char *dir_path)
{
    int idx;
    int wd;

    if (flash_watch_find_by_path(dir_path) >= 0) return; /* already watching */

    idx = flash_watch_alloc();
    if (idx < 0) return; /* watch table full */

    /* Watch for files being created, deleted, or renamed in this directory.
     * IN_MOVED_TO catches atomic file replacements (cp then mv).
     * IN_CLOSE_WRITE catches files written in-place. */
    wd = inotify_add_watch(g_flash_inotify_fd, dir_path,
                           (uint32_t)(IN_CREATE | IN_DELETE |
                                      IN_MOVED_TO | IN_MOVED_FROM |
                                      IN_CLOSE_WRITE));
    if (wd < 0) return; /* directory may have disappeared between readdir and here */

    g_flash_watches[idx].wd = wd;
    strncpy(g_flash_watches[idx].path, dir_path,
            sizeof(g_flash_watches[idx].path) - 1u);
    g_flash_watches[idx].path[sizeof(g_flash_watches[idx].path) - 1u] = '\0';
}

/* Remove an inotify watch by index, freeing the slot. */
static void flash_watch_free(int idx)
{
    if (idx < 0 || idx >= WP11_FLASH_MAX_SUBDIRS) return;
    if (g_flash_watches[idx].wd < 0) return;

    inotify_rm_watch(g_flash_inotify_fd, g_flash_watches[idx].wd);
    g_flash_watches[idx].wd = -1;
    g_flash_watches[idx].path[0] = '\0';
}

/* A .p11k file was found (or created).  Update slot table and notify PKCS#11. */
static void flash_file_arrived(const char *fpath)
{
    CK_SLOT_ID slot_id;

    if (wc_LockMutex(&g_lock) != 0) return;
    slot_id = slot_add_keystore(fpath, WP11_PROTO_FLASH);
    wc_UnLockMutex(&g_lock);

    if (slot_id != (CK_SLOT_ID)-1) {
        hotplug_push_event(slot_id, 1);
    }
}

/* A .p11k file was removed.  Update slot table and notify PKCS#11. */
static void flash_file_departed(const char *fpath)
{
    CK_SLOT_ID slot_id;

    if (wc_LockMutex(&g_lock) != 0) return;
    slot_id = slot_remove_keystore(fpath);
    wc_UnLockMutex(&g_lock);

    if (slot_id != (CK_SLOT_ID)-1) {
        hotplug_push_event(slot_id, 0);
    }
}

/* Scan dir_path for .p11k files and call flash_file_arrived for each one.
 * Called when a new mount point is discovered at init time or at runtime. */
static void flash_scan_dir(const char *dir_path)
{
    DIR *dp;
    struct dirent *de;
    struct stat st;
    char fpath[512]; /* subdir path + '/' + filename + NUL */

    dp = opendir(dir_path);
    if (dp == NULL) return;

    while ((de = readdir(dp)) != NULL) {
        if (!has_p11k_extension(de->d_name)) continue;

        /* wolfP11-mh6: this guard is for the LOCAL fpath[512] stack buffer
         * only -- it prevents a buffer overflow in this function.  A separate
         * guard in slot_add_keystore rejects paths that are too long for the
         * slot's keystore_path[256] storage field (>= 256 chars). */
        if (snprintf(fpath, sizeof(fpath), "%s/%s",
                     dir_path, de->d_name) >= (int)sizeof(fpath)) {
            continue; /* path too long for local buffer; skip */
        }

        /* Use stat() rather than d_type: d_type requires _GNU_SOURCE and is
         * also DT_UNKNOWN on many network/FUSE filesystems.  stat() is always
         * correct.  We intentionally skip symlinks (S_ISLNK) -- we only load
         * regular files to avoid TOCTOU races through symlink chains. */
        if (stat(fpath, &st) == 0 && S_ISREG(st.st_mode)) {
            flash_file_arrived(fpath);
        }
    }

    closedir(dp);
}

/* Remove all flash slots under dir_path and their inotify watch.
 * Called when a mount point disappears (USB drive unplugged).
 * slot_remove_flash_dir pushes departure events internally. */
static void flash_dir_departed(const char *dir_path)
{
    int idx;
    size_t dir_len;

    /* Remove all slots under this directory. */
    if (g_lock_ready && wc_LockMutex(&g_lock) == 0) {
        dir_len = strlen(dir_path);
        slot_remove_flash_dir(dir_path, dir_len);
        wc_UnLockMutex(&g_lock);
    }

    /* Remove the inotify watch for this subdirectory. */
    idx = flash_watch_find_by_path(dir_path);
    if (idx >= 0) flash_watch_free(idx);
}

/* -------------------------------------------------------------------------
 * flash_thread_fn -- the inotify event loop
 *
 * Watches WOLFP11_CFG_USB_FLASH_WATCH_DIR (default: /run/media) for new
 * subdirectories (= USB drive mount points via udisks2), then watches each
 * subdirectory for .p11k keystore files.
 *
 * Clean shutdown: C_Finalize writes a byte to g_flash_wake_pipe[1]; the
 * thread wakes from select(), sees the pipe is readable, and exits.
 * ---------------------------------------------------------------------- */
static void *flash_thread_fn(void *arg)
{
    /* inotify event buffer. The kernel guarantees that each read returns
     * one or more complete events; alignment to struct inotify_event is
     * required by the kernel ABI. */
    char     buf[4096];
    int      maxfd;
    int      n;
    int      i;
    fd_set   rfds;
    char     dir_path[256];
    char     fpath[512];
    char     subdir_path[256];
    DIR     *dp;
    struct dirent *de;
    struct stat    st;
    struct inotify_event *ev;
    char    *p;
    int      idx;

    (void)arg;

    /* Initialize all watch slots to unused */
    for (i = 0; i < WP11_FLASH_MAX_SUBDIRS; i++) {
        g_flash_watches[i].wd = -1;
        g_flash_watches[i].path[0] = '\0';
    }

    g_flash_inotify_fd = inotify_init();
    if (g_flash_inotify_fd < 0) {
        /* Non-fatal: flash token detection simply won't work. */
        return NULL;
    }

    /* Watch the root mount directory for new/removed subdirectories.
     * udisks2 creates /run/media/$USER/<label> on mount. */
    g_flash_root_wd = inotify_add_watch(g_flash_inotify_fd,
                                        WOLFP11_CFG_USB_FLASH_WATCH_DIR,
                                        (uint32_t)(IN_CREATE | IN_DELETE |
                                                   IN_MOVED_TO | IN_MOVED_FROM));
    if (g_flash_root_wd < 0) {
        /* Root watch dir does not exist on this system (e.g., no udisks2).
         * Close inotify and exit gracefully -- soft token still works. */
        close(g_flash_inotify_fd);
        g_flash_inotify_fd = -1;
        return NULL;
    }

    /* Enumerate any subdirs already present (USB drives mounted before init).
     * Also enumerate their .p11k files so pre-existing keystores appear
     * as PKCS#11 slots immediately on C_Initialize. */
    dp = opendir(WOLFP11_CFG_USB_FLASH_WATCH_DIR);
    if (dp != NULL) {
        while ((de = readdir(dp)) != NULL) {
            if (de->d_name[0] == '.') continue; /* skip . and .. */

            if (snprintf(dir_path, sizeof(dir_path), "%s/%s",
                         WOLFP11_CFG_USB_FLASH_WATCH_DIR,
                         de->d_name) >= (int)sizeof(dir_path)) {
                continue;
            }

            /* Use stat() -- d_type requires _GNU_SOURCE and is unreliable
             * on some filesystems.  Only follow actual directories. */
            if (stat(dir_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                flash_watch_add_dir(dir_path);
                flash_scan_dir(dir_path);
            }
        }
        closedir(dp);
    }

    /* Also scan for .p11k files directly in the root watch dir itself
     * (some non-udisks2 setups mount USB drives directly at /run/media). */
    flash_scan_dir(WOLFP11_CFG_USB_FLASH_WATCH_DIR);

    maxfd = (g_flash_inotify_fd > g_flash_wake_pipe[0])
            ? g_flash_inotify_fd : g_flash_wake_pipe[0];
    maxfd++;

    while (__atomic_load_n(&g_flash_thread_running, __ATOMIC_ACQUIRE)) {
        FD_ZERO(&rfds);
        FD_SET(g_flash_inotify_fd, &rfds);
        FD_SET(g_flash_wake_pipe[0], &rfds);

        if (select(maxfd, &rfds, NULL, NULL, NULL) < 0) {
            break; /* signal or error; exit cleanly */
        }

        /* Shutdown requested by C_Finalize */
        if (FD_ISSET(g_flash_wake_pipe[0], &rfds)) {
            break;
        }

        if (!FD_ISSET(g_flash_inotify_fd, &rfds)) {
            continue;
        }

        n = (int)read(g_flash_inotify_fd, buf, sizeof(buf));
        if (n <= 0) break;

        p = buf;
        while (p + (int)sizeof(struct inotify_event) <= buf + n) {
            ev = (struct inotify_event *)(void *)p;
            p += (int)sizeof(struct inotify_event) + (int)ev->len;

            /* Skip events with no filename (can happen for IN_Q_OVERFLOW) */
            if (ev->len == 0) continue;

            if (ev->wd == g_flash_root_wd) {
                /* ----- Event in the root watch directory -----
                 * A subdirectory (= mount point) appeared or disappeared. */

                if (snprintf(dir_path, sizeof(dir_path), "%s/%s",
                             WOLFP11_CFG_USB_FLASH_WATCH_DIR,
                             ev->name) >= (int)sizeof(dir_path)) {
                    continue;
                }

                if ((ev->mask & (uint32_t)(IN_CREATE | IN_MOVED_TO)) &&
                    (ev->mask & (uint32_t)IN_ISDIR)) {
                    /* New mount point: start watching it for .p11k files */
                    flash_watch_add_dir(dir_path);
                    flash_scan_dir(dir_path);
                } else if ((ev->mask & (uint32_t)(IN_DELETE | IN_MOVED_FROM)) &&
                           (ev->mask & (uint32_t)IN_ISDIR)) {
                    /* Mount point gone: remove all slots and the watch */
                    flash_dir_departed(dir_path);
                }

            } else {
                /* ----- Event in a watched subdirectory -----
                 * A file was created or deleted in a mount point. */

                if (!has_p11k_extension(ev->name)) continue;

                /* Look up the directory path for this inotify wd */
                idx = flash_watch_find_by_wd(ev->wd);
                if (idx < 0) continue; /* stale watch descriptor; skip */

                strncpy(subdir_path, g_flash_watches[idx].path,
                        sizeof(subdir_path) - 1u);
                subdir_path[sizeof(subdir_path) - 1u] = '\0';

                if (snprintf(fpath, sizeof(fpath), "%s/%s",
                             subdir_path, ev->name) >= (int)sizeof(fpath)) {
                    continue;
                }

                if (ev->mask & (uint32_t)(IN_CREATE | IN_MOVED_TO |
                                          IN_CLOSE_WRITE)) {
                    flash_file_arrived(fpath);
                } else if (ev->mask & (uint32_t)(IN_DELETE | IN_MOVED_FROM)) {
                    flash_file_departed(fpath);
                }
            }
        }
    }

    close(g_flash_inotify_fd);
    g_flash_inotify_fd = -1;

    /* Remove all inotify watches (kernel cleans them when fd is closed,
     * but clear our table for cleanliness). */
    for (i = 0; i < WP11_FLASH_MAX_SUBDIRS; i++) {
        g_flash_watches[i].wd = -1;
    }

    return NULL;
}

#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */

#ifdef WOLFP11_CFG_FSDIR_BACKEND

/* A .p11k file was found (or created) in the watched directory. */
static void fsdir_file_arrived(const char *fpath)
{
    CK_SLOT_ID slot_id;

    if (wc_LockMutex(&g_lock) != 0) return;
    slot_id = slot_add_keystore(fpath, WP11_PROTO_FSDIR);
    wc_UnLockMutex(&g_lock);

    if (slot_id != (CK_SLOT_ID)-1) {
        hotplug_push_event(slot_id, 1);
    }
}

/* A .p11k file was deleted from the watched directory. */
static void fsdir_file_departed(const char *fpath)
{
    CK_SLOT_ID slot_id;

    if (wc_LockMutex(&g_lock) != 0) return;
    slot_id = slot_remove_keystore(fpath);
    wc_UnLockMutex(&g_lock);

    if (slot_id != (CK_SLOT_ID)-1) {
        hotplug_push_event(slot_id, 0);
    }
}

/* Scan dir_path for .p11k files and call fsdir_file_arrived for each one. */
static void fsdir_scan_dir(const char *dir_path)
{
    DIR *dp;
    struct dirent *de;
    struct stat st;
    char fpath[512];

    dp = opendir(dir_path);
    if (dp == NULL) return;

    while ((de = readdir(dp)) != NULL) {
        if (!has_p11k_extension(de->d_name)) continue;

        if (snprintf(fpath, sizeof(fpath), "%s/%s",
                     dir_path, de->d_name) >= (int)sizeof(fpath)) {
            continue; /* path too long for local buffer */
        }

        /* Use stat() -- avoid symlinks (TOCTOU risk) and d_type portability. */
        if (stat(fpath, &st) == 0 && S_ISREG(st.st_mode)) {
            fsdir_file_arrived(fpath);
        }
    }

    closedir(dp);
}

/* -------------------------------------------------------------------------
 * fsdir_thread_fn -- inotify event loop for the filesystem directory backend
 *
 * Watches g_fsdir_path (a single flat directory) for .p11k file
 * create/delete events.  Unlike the USB flash thread, no subdirectory
 * tracking is needed: the path is a configured persistent location, not
 * an auto-mounted USB hierarchy.
 *
 * Clean shutdown: C_Finalize writes a byte to g_fsdir_wake_pipe[1]; the
 * thread wakes from select() and exits.
 * ---------------------------------------------------------------------- */
static void *fsdir_thread_fn(void *arg)
{
    char     buf[4096];
    int      maxfd;
    int      n;
    fd_set   rfds;
    char     fpath[512];
    struct inotify_event *ev;
    char    *p;

    (void)arg;

    /* Nothing to watch if path is empty */
    if (g_fsdir_path[0] == '\0') return NULL;

    g_fsdir_inotify_fd = inotify_init();
    if (g_fsdir_inotify_fd < 0) return NULL;

    /* Watch the configured directory for .p11k file arrivals and departures.
     * IN_CLOSE_WRITE catches files written in-place; IN_MOVED_TO catches
     * atomic replacements (write-to-temp then rename). */
    g_fsdir_wd = inotify_add_watch(g_fsdir_inotify_fd, g_fsdir_path,
                                    (uint32_t)(IN_CREATE | IN_DELETE |
                                               IN_MOVED_TO | IN_MOVED_FROM |
                                               IN_CLOSE_WRITE));
    if (g_fsdir_wd < 0) {
        /* Directory does not exist or is not accessible; exit gracefully.
         * Soft token still works. */
        close(g_fsdir_inotify_fd);
        g_fsdir_inotify_fd = -1;
        return NULL;
    }

    /* Initial scan: pick up any .p11k files already present. */
    fsdir_scan_dir(g_fsdir_path);

    maxfd = (g_fsdir_inotify_fd > g_fsdir_wake_pipe[0])
            ? g_fsdir_inotify_fd : g_fsdir_wake_pipe[0];
    maxfd++;

    while (__atomic_load_n(&g_fsdir_thread_running, __ATOMIC_ACQUIRE)) {
        FD_ZERO(&rfds);
        FD_SET(g_fsdir_inotify_fd, &rfds);
        FD_SET(g_fsdir_wake_pipe[0], &rfds);

        if (select(maxfd, &rfds, NULL, NULL, NULL) < 0) {
            break; /* signal or error; exit cleanly */
        }

        if (FD_ISSET(g_fsdir_wake_pipe[0], &rfds)) {
            break; /* shutdown requested by C_Finalize */
        }

        if (!FD_ISSET(g_fsdir_inotify_fd, &rfds)) {
            continue;
        }

        n = (int)read(g_fsdir_inotify_fd, buf, sizeof(buf));
        if (n <= 0) break;

        p = buf;
        while (p + (int)sizeof(struct inotify_event) <= buf + n) {
            ev = (struct inotify_event *)(void *)p;
            p += (int)sizeof(struct inotify_event) + (int)ev->len;

            if (ev->len == 0) continue;
            if (!has_p11k_extension(ev->name)) continue;

            if (snprintf(fpath, sizeof(fpath), "%s/%s",
                         g_fsdir_path, ev->name) >= (int)sizeof(fpath)) {
                continue;
            }

            if (ev->mask & (uint32_t)(IN_CREATE | IN_MOVED_TO |
                                      IN_CLOSE_WRITE)) {
                fsdir_file_arrived(fpath);
            } else if (ev->mask & (uint32_t)(IN_DELETE | IN_MOVED_FROM)) {
                fsdir_file_departed(fpath);
            }
        }
    }

    close(g_fsdir_inotify_fd);
    g_fsdir_inotify_fd = -1;
    return NULL;
}

#endif /* WOLFP11_CFG_FSDIR_BACKEND */

#endif /* WOLFP11_CFG_USB_FLASH_BACKEND || WOLFP11_CFG_FSDIR_BACKEND */

/* -------------------------------------------------------------------------
 * C_Initialize / C_Finalize
 * ---------------------------------------------------------------------- */

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
    CK_RV rv = CKR_OK;

    /* PKCS#11 2.40 sec.11.4: if pInitArgs is non-NULL, it must be a
     * CK_C_INITIALIZE_ARGS_PTR whose pReserved field is NULL_PTR. */
    if (pInitArgs != NULL_PTR) {
        CK_C_INITIALIZE_ARGS_PTR args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;
        if (args->pReserved != NULL_PTR) {
            return CKR_ARGUMENTS_BAD;
        }
    }

    /* Initialize the mutex before acquiring it. Per PKCS#11 2.40 sec.6.7.2,
     * C_Initialize must be called from a single thread before any concurrent
     * Cryptoki calls, so this init itself has no race. */
    if (!g_lock_ready) {
        if (wc_InitMutex(&g_lock) != 0) {
            return CKR_GENERAL_ERROR;
        }
        g_lock_ready = 1;
    }

    WP11_LOCK(CKR_GENERAL_ERROR);

    if (g_initialized) {
        rv = CKR_CRYPTOKI_ALREADY_INITIALIZED;
        goto cleanup;
    }

    memset(g_sessions, 0, sizeof(g_sessions));
    memset(g_keys,     0, sizeof(g_keys));
    memset(g_slots,    0, sizeof(g_slots));

    /* Slot 0: soft token -- always present, never removed */
    g_slots[0].in_use        = 1;
    g_slots[0].token_present = 1;
    g_slots[0].usb_vid       = 0;
    g_slots[0].usb_pid       = 0;
    /* WP11_PROTO_SOFT is the zero value of wp11_proto_t (by design), so this
     * assignment is technically redundant after memset(g_slots, 0, ...) above,
     * but is kept explicit so the intent is clear to any reader. */
    g_slots[0].proto         = WP11_PROTO_SOFT;
    strncpy(g_slots[0].label, "wolfP11 Soft Token", sizeof(g_slots[0].label) - 1u);
    g_slots[0].label[sizeof(g_slots[0].label) - 1u] = '\0';

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
    /* Resolve the soft-token keystore path for slot 0.
     * Priority: WOLFP11_SOFT_KEYSTORE_PATH env var
     *         > WOLFP11_CFG_SOFT_KEYSTORE_PATH compile-time default
     *         > $HOME/.wolfp11/soft.p11k
     * An empty path means no persistence (in-memory only). */
    {
        const char *sp = getenv("WOLFP11_SOFT_KEYSTORE_PATH");
        if (sp == NULL) {
            sp = WOLFP11_CFG_SOFT_KEYSTORE_PATH;
        }
        if (sp == NULL) {
            const char *home = getenv("HOME");
            if (home != NULL) {
                snprintf(g_slots[0].keystore_path,
                         sizeof(g_slots[0].keystore_path),
                         "%s/.wolfp11/soft.p11k", home);
            }
        } else {
            strncpy(g_slots[0].keystore_path, sp,
                    sizeof(g_slots[0].keystore_path) - 1u);
            g_slots[0].keystore_path[sizeof(g_slots[0].keystore_path) - 1u] = '\0';
        }
    }
#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */

#ifdef WOLFP11_CFG_WOLFHSM_BACKEND
    /* Create a wolfHSM backend slot if a server address is configured.
     * Priority: WOLFP11_WOLFHSM_SERVER_ADDR env var
     *         > WOLFP11_CFG_WOLFHSM_SERVER_ADDR compile-time default
     * An empty or NULL address means no wolfHSM slot is created.
     * token_present is left 0 here -- C_Login (wolfP11-s5x) establishes the
     * server connection and flips token_present to 1 on success. */
    {
        const char *wh_srv = getenv("WOLFP11_WOLFHSM_SERVER_ADDR");
        if (wh_srv == NULL) wh_srv = WOLFP11_CFG_WOLFHSM_SERVER_ADDR;
        if (wh_srv != NULL && wh_srv[0] != '\0') {
            CK_SLOT_ID wh_slot;
            /* Find the first free slot (USB slots also start at 1, but they
             * are added dynamically by the hotplug callback; at C_Initialize
             * time all slots >= 1 are free, so this always picks slot 1). */
            for (wh_slot = 1; wh_slot < (CK_SLOT_ID)MAX_SLOTS; wh_slot++) {
                if (!g_slots[wh_slot].in_use) break;
            }
            if (wh_slot < (CK_SLOT_ID)MAX_SLOTS) {
                const char *wh_lbl = getenv("WOLFP11_WOLFHSM_LABEL");
                if (wh_lbl == NULL) wh_lbl = WOLFP11_CFG_WOLFHSM_LABEL;

                g_slots[wh_slot].in_use        = 1;
                g_slots[wh_slot].token_present = 1;
                g_slots[wh_slot].usb_vid       = 0;
                g_slots[wh_slot].usb_pid       = 0;
                g_slots[wh_slot].proto         = WP11_PROTO_WOLFHSM;
                g_slots[wh_slot].hsm_client    = NULL;

                strncpy(g_slots[wh_slot].hsm_server_addr, wh_srv,
                        sizeof(g_slots[wh_slot].hsm_server_addr) - 1u);
                g_slots[wh_slot].hsm_server_addr[
                    sizeof(g_slots[wh_slot].hsm_server_addr) - 1u] = '\0';

                strncpy(g_slots[wh_slot].label, wh_lbl,
                        sizeof(g_slots[wh_slot].label) - 1u);
                g_slots[wh_slot].label[sizeof(g_slots[wh_slot].label) - 1u] = '\0';
            }
        }
    }
#endif /* WOLFP11_CFG_WOLFHSM_BACKEND */

    /* Initialize the hotplug mutex and condition variable.
     * Done here (not statically) for correct destroy-on-finalize lifecycle.
     *
     * wolfP11-nnv: the two inits are guarded separately.  A short-circuit
     * compound condition (A || B) would silently leak the mutex if A succeeds
     * and B fails, because 'goto cleanup' does not call pthread_mutex_destroy.
     * Separating them lets us destroy exactly what was successfully initialised
     * before returning the error. */
    if (pthread_mutex_init(&g_hotplug_mutex, NULL) != 0) {
        rv = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    if (pthread_cond_init(&g_hotplug_cond, NULL) != 0) {
        /* Mutex was already initialised -- destroy it before returning. */
        pthread_mutex_destroy(&g_hotplug_mutex);
        rv = CKR_GENERAL_ERROR;
        goto cleanup;
    }
    g_hotplug_mutex_ready = 1;
    g_hotplug_head    = 0u;
    g_hotplug_tail    = 0u;
    g_hotplug_dropped = 0u;

#ifdef WOLFP11_CFG_USB_BACKEND
    /* Initialize libusb and register a hotplug callback for ALL USB device
     * arrivals and departures. LIBUSB_HOTPLUG_ENUMERATE causes the callback
     * to fire for devices already attached at registration time, so we get
     * an accurate initial slot list with no separate enumeration step. */
    if (libusb_init(&g_usb_ctx) == 0) {
        int hp_ret = libusb_hotplug_register_callback(
            g_usb_ctx,
            (libusb_hotplug_event)(LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED |
                                   LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT),
            LIBUSB_HOTPLUG_ENUMERATE,
            LIBUSB_HOTPLUG_MATCH_ANY,  /* match any VID */
            LIBUSB_HOTPLUG_MATCH_ANY,  /* match any PID */
            LIBUSB_HOTPLUG_MATCH_ANY,  /* match any device class */
            hotplug_cb, NULL, &g_hotplug_handle);

        if (hp_ret == LIBUSB_SUCCESS) {
            __atomic_store_n(&g_event_thread_running, 1, __ATOMIC_RELAXED); /* under g_lock */
            if (pthread_create(&g_event_thread, NULL,
                               event_thread_fn, NULL) != 0) {
                /* Thread creation failed: hotplug won't work, but soft token still ok */
                __atomic_store_n(&g_event_thread_running, 0, __ATOMIC_RELAXED);
                libusb_hotplug_deregister_callback(g_usb_ctx, g_hotplug_handle);
            }
        }
        /* libusb init succeeded even if hotplug registration failed;
         * we keep g_usb_ctx to free it in C_Finalize. */
    }
    /* Non-fatal: if libusb_init fails, soft token still works.
     * g_usb_ctx remains NULL and is checked in C_Finalize. */
#endif /* WOLFP11_CFG_USB_BACKEND */

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
    /* Start the inotify flash-drive detection thread.
     *
     * The self-pipe is created here (under g_lock) so C_Finalize can
     * reliably write to it without a race.  The thread is created while
     * g_lock is still held so we know g_flash_thread_running is visible
     * to the thread before C_Finalize can observe g_initialized == 1. */
    g_flash_wake_pipe[0] = -1;
    g_flash_wake_pipe[1] = -1;
    if (pipe(g_flash_wake_pipe) == 0) {
        __atomic_store_n(&g_flash_thread_running, 1, __ATOMIC_RELAXED); /* under g_lock */
        if (pthread_create(&g_flash_thread, NULL, flash_thread_fn, NULL) != 0) {
            /* Thread creation failed: close the pipe and continue.
             * Flash token detection won't work but soft token is fine. */
            __atomic_store_n(&g_flash_thread_running, 0, __ATOMIC_RELAXED);
            close(g_flash_wake_pipe[0]);
            close(g_flash_wake_pipe[1]);
            g_flash_wake_pipe[0] = -1;
            g_flash_wake_pipe[1] = -1;
        }
    }
#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */

#ifdef WOLFP11_CFG_FSDIR_BACKEND
    /* Resolve the FSDIR watch path.
     * Priority: WOLFP11_FSDIR_PATH env var
     *         > WOLFP11_CFG_FSDIR_PATH compile-time default */
    {
        const char *fp = getenv("WOLFP11_FSDIR_PATH");
        if (fp == NULL) {
            fp = WOLFP11_CFG_FSDIR_PATH;
        }
        if (fp != NULL) {
            strncpy(g_fsdir_path, fp, sizeof(g_fsdir_path) - 1u);
            g_fsdir_path[sizeof(g_fsdir_path) - 1u] = '\0';
        } else {
            g_fsdir_path[0] = '\0';
        }
    }
    /* Start the FSDIR inotify thread (same pipe+thread pattern as flash). */
    g_fsdir_wake_pipe[0] = -1;
    g_fsdir_wake_pipe[1] = -1;
    if (g_fsdir_path[0] != '\0' && pipe(g_fsdir_wake_pipe) == 0) {
        __atomic_store_n(&g_fsdir_thread_running, 1, __ATOMIC_RELAXED);
        if (pthread_create(&g_fsdir_thread, NULL, fsdir_thread_fn, NULL) != 0) {
            __atomic_store_n(&g_fsdir_thread_running, 0, __ATOMIC_RELAXED);
            close(g_fsdir_wake_pipe[0]);
            close(g_fsdir_wake_pipe[1]);
            g_fsdir_wake_pipe[0] = -1;
            g_fsdir_wake_pipe[1] = -1;
        }
    }
#endif /* WOLFP11_CFG_FSDIR_BACKEND */

    g_initialized = 1;

cleanup:
    WP11_UNLOCK();
    return rv;
}

/* Forward declarations: defined before C_Login, called from C_Finalize. */
#ifdef WOLFP11_CFG_WOLFHSM_BACKEND
static void wolfhsm_slot_disconnect(CK_SLOT_ID slot_id);
static void wolfhsm_slot_clear_keys(CK_SLOT_ID slot_id);
#endif

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
    CK_RV rv = CKR_OK;
    int ki;

    /* PKCS#11 2.40 sec.11.4: pReserved must be NULL_PTR. */
    if (pReserved != NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) {
        rv = CKR_CRYPTOKI_NOT_INITIALIZED;
        goto cleanup;
    }

    g_initialized = 0;

    /* Free all remaining key objects.
     * wolfP11-be5: ownership is encoded in backend_ops->free_key_priv.
     * NULL means the backend owns key_priv in bulk (flash keystore, freed
     * below); non-NULL means call it to release this key's private state. */
    for (ki = 0; ki < MAX_KEYS; ki++) {
        if (g_keys[ki].in_use &&
            g_keys[ki].key_priv != NULL &&
            g_keys[ki].backend_ops != NULL &&
            g_keys[ki].backend_ops->free_key_priv != NULL) {
            g_keys[ki].backend_ops->free_key_priv(g_keys[ki].key_priv);
        }
        /* Derived secret keys (CKO_SECRET_KEY from C_DeriveKey) store
         * key material in secret; zero and free it before clearing. */
        if (g_keys[ki].secret != NULL) {
            memset(g_keys[ki].secret, 0, g_keys[ki].secret_len);
            free(g_keys[ki].secret);
        }
        g_keys[ki].key_priv = NULL;
        g_keys[ki].secret   = NULL;
        g_keys[ki].in_use   = 0;
    }

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
    {
        /* Free any loaded flash keystores.  Must happen AFTER clearing g_keys[]
         * (to remove dangling key_priv pointers) but BEFORE memset(g_slots)
         * (to have valid keystore pointers to free). */
        int si;
        for (si = 1; si < MAX_SLOTS; si++) {
            if (g_slots[si].in_use && g_slots[si].keystore != NULL) {
                wp11_keystore_free(g_slots[si].keystore);
                g_slots[si].keystore = NULL;
            }
        }
    }
#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */

#ifdef WOLFP11_CFG_FSDIR_BACKEND
    {
        /* Free any loaded FSDIR keystores.  Same ordering constraint as flash:
         * AFTER clearing g_keys[] (dangling key_priv pointers removed), BEFORE
         * memset(g_slots) (valid keystore pointers still needed). */
        int si;
        for (si = 1; si < MAX_SLOTS; si++) {
            if (g_slots[si].in_use &&
                g_slots[si].proto == WP11_PROTO_FSDIR &&
                g_slots[si].keystore != NULL) {
                wp11_keystore_free(g_slots[si].keystore);
                g_slots[si].keystore = NULL;
            }
        }
    }
#endif /* WOLFP11_CFG_FSDIR_BACKEND */

#ifdef WOLFP11_CFG_WOLFHSM_BACKEND
    {
        /* Disconnect any active wolfHSM client connections.  Must happen AFTER
         * clearing g_keys[] (to drop key_priv pointers that borrow hsm_client)
         * but BEFORE memset(g_slots) (to have valid hsm_client pointers). */
        int si;
        for (si = 1; si < MAX_SLOTS; si++) {
            if (g_slots[si].in_use && g_slots[si].proto == WP11_PROTO_WOLFHSM) {
                wolfhsm_slot_disconnect((CK_SLOT_ID)si);
            }
        }
    }
#endif /* WOLFP11_CFG_WOLFHSM_BACKEND */

    memset(g_slots, 0, sizeof(g_slots));

cleanup:
    /* wolfP11-bpu: the shutdown sequence is ordered to eliminate the window
     * where hotplug_cb (USB event thread) or flash_file_arrived/departed
     * (inotify thread) could call wc_LockMutex(&g_lock) after the mutex has
     * been destroyed.
     *
     * Correct order:
     *   1. Set g_lock_ready = 0 so WP11_LOCK() in C_* functions fails fast.
     *   2. Release g_lock so any in-flight hotplug_cb / flash thread callback
     *      that is already waiting on the mutex can complete and return.
     *   3. Signal and join every background thread.  After pthread_join
     *      returns, no thread can ever call wc_LockMutex again.
     *   4. THEN destroy g_lock with wc_FreeMutex.  Safe: no live threads.
     *
     * The old code called wc_FreeMutex BEFORE the joins (between steps 2 and 3),
     * which left a window where a hotplug event could fire and call
     * wc_LockMutex on a destroyed mutex -- undefined behaviour per POSIX. */
    g_lock_ready = 0;
    WP11_UNLOCK();
    /* Do NOT call wc_FreeMutex here -- threads are still running. */

#ifdef WOLFP11_CFG_USB_BACKEND
    /* Stop the event thread: set flag, interrupt libusb's blocking wait,
     * then join.  Done OUTSIDE g_lock to avoid deadlock (hotplug_cb acquires
     * g_lock; holding g_lock here while waiting on the thread to exit would
     * deadlock if a hotplug event fires at that moment). */
    if (__atomic_load_n(&g_event_thread_running, __ATOMIC_ACQUIRE)) {
        /* RELEASE store: visible to the thread before libusb wakes it */
        __atomic_store_n(&g_event_thread_running, 0, __ATOMIC_RELEASE);
        if (g_usb_ctx != NULL) {
            libusb_interrupt_event_handler(g_usb_ctx);
        }
        pthread_join(g_event_thread, NULL);
    }
    if (g_usb_ctx != NULL) {
        libusb_hotplug_deregister_callback(g_usb_ctx, g_hotplug_handle);
        libusb_exit(g_usb_ctx);
        g_usb_ctx = NULL;
    }
#endif /* WOLFP11_CFG_USB_BACKEND */

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
    /* Stop the inotify flash thread.  Same ordering rationale as the USB
     * event thread: flash_file_arrived/departed acquire g_lock internally,
     * so we must not hold g_lock during the join. */
    if (__atomic_load_n(&g_flash_thread_running, __ATOMIC_ACQUIRE)) {
        /* RELEASE store: visible to the thread before the pipe write wakes it */
        __atomic_store_n(&g_flash_thread_running, 0, __ATOMIC_RELEASE);
        if (g_flash_wake_pipe[1] >= 0) {
            /* A single byte is enough to wake select(). EINTR/EAGAIN are
             * benign: the pipe has kernel buffer space and the thread will
             * drain it on the next wake cycle. */
            if (write(g_flash_wake_pipe[1], "\0", 1) < 0) {}
        }
        pthread_join(g_flash_thread, NULL);
    }
    /* Close the self-pipe fds */
    if (g_flash_wake_pipe[0] >= 0) {
        close(g_flash_wake_pipe[0]);
        g_flash_wake_pipe[0] = -1;
    }
    if (g_flash_wake_pipe[1] >= 0) {
        close(g_flash_wake_pipe[1]);
        g_flash_wake_pipe[1] = -1;
    }
#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */

#ifdef WOLFP11_CFG_FSDIR_BACKEND
    /* Stop the FSDIR inotify thread.  Same ordering rationale as the flash
     * thread: fsdir_file_arrived/departed acquire g_lock, so no g_lock hold
     * during the join. */
    if (__atomic_load_n(&g_fsdir_thread_running, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&g_fsdir_thread_running, 0, __ATOMIC_RELEASE);
        if (g_fsdir_wake_pipe[1] >= 0) {
            /* Ignore return: thread wakes on the running flag; the write
             * is a best-effort wakeup only (wolfP11-6ci). */
            ssize_t wr_ = write(g_fsdir_wake_pipe[1], "\0", 1);
            (void)wr_;
        }
        pthread_join(g_fsdir_thread, NULL);
    }
    if (g_fsdir_wake_pipe[0] >= 0) {
        close(g_fsdir_wake_pipe[0]);
        g_fsdir_wake_pipe[0] = -1;
    }
    if (g_fsdir_wake_pipe[1] >= 0) {
        close(g_fsdir_wake_pipe[1]);
        g_fsdir_wake_pipe[1] = -1;
    }
#endif /* WOLFP11_CFG_FSDIR_BACKEND */

    /* All background threads have joined.  No thread can call wc_LockMutex
     * any more, so it is now safe to destroy g_lock. */
    wc_FreeMutex(&g_lock);

    /* Destroy pthread resources and wake any C_WaitForSlotEvent callers */
    if (g_hotplug_mutex_ready) {
        g_hotplug_mutex_ready = 0;
        pthread_cond_broadcast(&g_hotplug_cond);
        pthread_cond_destroy(&g_hotplug_cond);
        pthread_mutex_destroy(&g_hotplug_mutex);
    }

    return rv;
}

/* -------------------------------------------------------------------------
 * C_GetInfo
 * ---------------------------------------------------------------------- */

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
    CK_RV rv = CKR_OK;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (pInfo == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    pad_string(pInfo->manufacturerID, sizeof(pInfo->manufacturerID),
               "wolfSSL");
    pInfo->flags = 0;
    pad_string(pInfo->libraryDescription, sizeof(pInfo->libraryDescription),
               "wolfP11 PKCS#11 Library");
    pInfo->libraryVersion.major = 0;
    pInfo->libraryVersion.minor = 1;

cleanup:
    WP11_UNLOCK();
    return rv;
}

/* -------------------------------------------------------------------------
 * C_GetSlotList
 * ---------------------------------------------------------------------- */

#if defined(WOLFP11_CFG_USB_FLASH_BACKEND) || defined(WOLFP11_CFG_FSDIR_BACKEND)
/* Comparator for qsort in C_GetSlotList.
 *
 * Ordering:
 *   Slot 0 (soft / USB token) first.
 *   Keystore slots (keystore_path set): alphabetical by path.
 *   Non-keystore slots (USB hardware): by slot ID.
 *   Non-keystore slots sort before keystore slots.
 *
 * This makes C_GetSlotList output deterministic even if .p11k files are
 * discovered by inotify or readdir in non-alphabetical filesystem order. */
static int slot_id_cmp(const void *a, const void *b)
{
    CK_SLOT_ID sa = *(const CK_SLOT_ID *)a;
    CK_SLOT_ID sb = *(const CK_SLOT_ID *)b;
    int a_ks, b_ks;

    if (sa == 0) return -1;
    if (sb == 0) return  1;

    a_ks = (g_slots[sa].keystore_path[0] != '\0');
    b_ks = (g_slots[sb].keystore_path[0] != '\0');

    if (a_ks && b_ks)
        return strncmp(g_slots[sa].keystore_path, g_slots[sb].keystore_path,
                       sizeof(g_slots[0].keystore_path) - 1u);
    if (a_ks) return  1;   /* keystore slots after non-keystore */
    if (b_ks) return -1;
    return (sa < sb) ? -1 : (sa > sb) ? 1 : 0;
}
#endif /* WOLFP11_CFG_USB_FLASH_BACKEND || WOLFP11_CFG_FSDIR_BACKEND */

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                     CK_ULONG_PTR pulCount)
{
    CK_RV      rv  = CKR_OK;
    CK_ULONG   cnt = 0;
    CK_SLOT_ID ids[MAX_SLOTS];
    int i;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (pulCount == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    /* Collect qualifying slots */
    for (i = 0; i < MAX_SLOTS; i++) {
        if (!g_slots[i].in_use) continue;
        if (tokenPresent && !g_slots[i].token_present) continue;
        ids[cnt++] = (CK_SLOT_ID)i;
    }

    if (pSlotList == NULL_PTR) {
        *pulCount = cnt;
        goto cleanup;
    }

    if (*pulCount < cnt) {
        *pulCount = cnt;
        rv = CKR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

#if defined(WOLFP11_CFG_USB_FLASH_BACKEND) || defined(WOLFP11_CFG_FSDIR_BACKEND)
    /* Sort: slot 0 first, keystore slots alphabetically, others by ID. */
    qsort(ids, (size_t)cnt, sizeof(ids[0]), slot_id_cmp);
#endif

    for (i = 0; i < (int)cnt; i++) {
        pSlotList[i] = ids[i];
    }
    *pulCount = cnt;

cleanup:
    WP11_UNLOCK();
    return rv;
}

/* -------------------------------------------------------------------------
 * C_GetSlotInfo
 * ---------------------------------------------------------------------- */

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    CK_RV rv = CKR_OK;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (!slot_valid(slotID)) { rv = CKR_SLOT_ID_INVALID; goto cleanup; }
    if (pInfo == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    memset(pInfo, 0, sizeof(*pInfo));
    if (slotID == 0) {
        pad_string(pInfo->slotDescription, sizeof(pInfo->slotDescription),
                   "wolfP11 Software Slot");
        pad_string(pInfo->manufacturerID, sizeof(pInfo->manufacturerID),
                   "wolfSSL Inc.");
    } else {
        /* USB slot: use token name from the slot table */
        pad_string(pInfo->slotDescription, sizeof(pInfo->slotDescription),
                   g_slots[slotID].label);
        pad_string(pInfo->manufacturerID, sizeof(pInfo->manufacturerID),
                   "wolfSSL Inc.");
    }
    /* CKF_TOKEN_PRESENT reflects live hotplug state */
    if (g_slots[slotID].token_present) {
        pInfo->flags |= CKF_TOKEN_PRESENT;
    }
    pInfo->hardwareVersion.major = 0;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 0;
    pInfo->firmwareVersion.minor = 1;

cleanup:
    WP11_UNLOCK();
    return rv;
}

/* -------------------------------------------------------------------------
 * C_GetTokenInfo
 * ---------------------------------------------------------------------- */

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    CK_RV rv = CKR_OK;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (!slot_valid(slotID)) { rv = CKR_SLOT_ID_INVALID; goto cleanup; }
    if (!g_slots[slotID].token_present) { rv = CKR_TOKEN_NOT_PRESENT; goto cleanup; }
    if (pInfo == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    memset(pInfo, 0, sizeof(*pInfo));
    pad_string(pInfo->label, sizeof(pInfo->label), g_slots[slotID].label);
    pad_string(pInfo->manufacturerID, sizeof(pInfo->manufacturerID),
               "wolfSSL Inc.");
#ifdef WOLFP11_CFG_WOLFHSM_BACKEND
    if (g_slots[slotID].proto == WP11_PROTO_WOLFHSM)
        pad_string(pInfo->model, sizeof(pInfo->model), "wolfHSM");
    else
#endif
        pad_string(pInfo->model, sizeof(pInfo->model), "Software");
    pad_string(pInfo->serialNumber, sizeof(pInfo->serialNumber),
               "00000000");
    pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_LOGIN_REQUIRED |
                   CKF_USER_PIN_INITIALIZED | CKF_RNG;
    if (g_slots[slotID].pin_fail_count > 0)
        pInfo->flags |= CKF_USER_PIN_COUNT_LOW;
    pInfo->ulMaxSessionCount   = WOLFP11_CFG_MAX_SESSIONS;
    pInfo->ulSessionCount      = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulMaxRwSessionCount = WOLFP11_CFG_MAX_SESSIONS;
    pInfo->ulRwSessionCount    = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulMaxPinLen         = 64;
    pInfo->ulMinPinLen         = 4;
    pInfo->ulTotalPublicMemory  = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory   = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory  = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion.major = 0;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 0;
    pInfo->firmwareVersion.minor = 1;
    memset(pInfo->utcTime, '0', sizeof(pInfo->utcTime));

cleanup:
    WP11_UNLOCK();
    return rv;
}

/* -------------------------------------------------------------------------
 * C_GetMechanismList / C_GetMechanismInfo
 * ---------------------------------------------------------------------- */

static const CK_MECHANISM_TYPE g_mechs[] = {
    CKM_RSA_PKCS,
    CKM_ECDSA,
    CKM_ECDSA_SHA256,
    CKM_ECDH1_DERIVE,
    CKM_DES_KEY_GEN,
    CKM_DES_ECB,
    CKM_DES_CBC,
    CKM_DES3_KEY_GEN,
    CKM_DES3_ECB,
    CKM_DES3_CBC,
    CKM_AES_KEY_GEN,
    CKM_AES_ECB,
    CKM_AES_CBC,
    CKM_MD5,
    CKM_MD5_HMAC,
    CKM_SHA_1,
    CKM_SHA_1_HMAC,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKM_SHA384,
    CKM_SHA384_HMAC,
    CKM_SHA512,
    CKM_SHA512_HMAC,
};
#define NUM_MECHS ((CK_ULONG)(sizeof(g_mechs) / sizeof(g_mechs[0])))

CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
                           CK_MECHANISM_TYPE_PTR pMechanismList,
                           CK_ULONG_PTR pulCount)
{
    CK_RV rv = CKR_OK;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (!slot_valid(slotID)) { rv = CKR_SLOT_ID_INVALID; goto cleanup; }
    if (pulCount == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    if (pMechanismList == NULL_PTR) {
        *pulCount = NUM_MECHS;
        goto cleanup;
    }

    if (*pulCount < NUM_MECHS) {
        *pulCount = NUM_MECHS;
        rv = CKR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    memcpy(pMechanismList, g_mechs, sizeof(g_mechs));
    *pulCount = NUM_MECHS;

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                           CK_MECHANISM_INFO_PTR pInfo)
{
    CK_RV rv = CKR_OK;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (!slot_valid(slotID)) { rv = CKR_SLOT_ID_INVALID; goto cleanup; }
    if (pInfo == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    memset(pInfo, 0, sizeof(*pInfo));

    switch (type) {
    case CKM_RSA_PKCS:
        pInfo->ulMinKeySize = 1024;
        pInfo->ulMaxKeySize = 4096;
        pInfo->flags = CKF_SIGN | CKF_DECRYPT;
        break;
    case CKM_ECDSA:
        pInfo->ulMinKeySize = 256;
        pInfo->ulMaxKeySize = 384;
        pInfo->flags = CKF_SIGN;
        break;
    case CKM_ECDSA_SHA256:
        pInfo->ulMinKeySize = 256;
        pInfo->ulMaxKeySize = 384;
        pInfo->flags = CKF_SIGN;
        break;
    case CKM_ECDH1_DERIVE:
        pInfo->ulMinKeySize = 256;
        pInfo->ulMaxKeySize = 384;
        pInfo->flags = CKF_DERIVE;
        break;
    case CKM_DES_KEY_GEN:
        pInfo->ulMinKeySize = 64;
        pInfo->ulMaxKeySize = 64;
        pInfo->flags = CKF_GENERATE;
        break;
    case CKM_DES_ECB:
    case CKM_DES_CBC:
        pInfo->ulMinKeySize = 64;
        pInfo->ulMaxKeySize = 64;
        pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
        break;
    case CKM_DES3_KEY_GEN:
        pInfo->ulMinKeySize = 192;
        pInfo->ulMaxKeySize = 192;
        pInfo->flags = CKF_GENERATE;
        break;
    case CKM_DES3_ECB:
    case CKM_DES3_CBC:
        pInfo->ulMinKeySize = 128;
        pInfo->ulMaxKeySize = 192;
        pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
        break;
    case CKM_AES_KEY_GEN:
        pInfo->ulMinKeySize = 128;
        pInfo->ulMaxKeySize = 256;
        pInfo->flags = CKF_GENERATE;
        break;
    case CKM_AES_ECB:
    case CKM_AES_CBC:
        pInfo->ulMinKeySize = 128;
        pInfo->ulMaxKeySize = 256;
        pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
        break;
    case CKM_MD5:
        pInfo->ulMinKeySize = 0;
        pInfo->ulMaxKeySize = 0;
        pInfo->flags = CKF_DIGEST;
        break;
    case CKM_MD5_HMAC:
        pInfo->ulMinKeySize = 0;
        pInfo->ulMaxKeySize = 512;
        pInfo->flags = CKF_SIGN | CKF_VERIFY;
        break;
    case CKM_SHA_1:
        pInfo->ulMinKeySize = 0;
        pInfo->ulMaxKeySize = 0;
        pInfo->flags = CKF_DIGEST;
        break;
    case CKM_SHA_1_HMAC:
        pInfo->ulMinKeySize = 0;
        pInfo->ulMaxKeySize = 512;
        pInfo->flags = CKF_SIGN | CKF_VERIFY;
        break;
    case CKM_SHA256:
        pInfo->ulMinKeySize = 0;
        pInfo->ulMaxKeySize = 0;
        pInfo->flags = CKF_DIGEST;
        break;
    case CKM_SHA256_HMAC:
        pInfo->ulMinKeySize = 0;
        pInfo->ulMaxKeySize = 512;
        pInfo->flags = CKF_SIGN | CKF_VERIFY;
        break;
    case CKM_SHA384:
        pInfo->ulMinKeySize = 0;
        pInfo->ulMaxKeySize = 0;
        pInfo->flags = CKF_DIGEST;
        break;
    case CKM_SHA384_HMAC:
        pInfo->ulMinKeySize = 0;
        pInfo->ulMaxKeySize = 512;
        pInfo->flags = CKF_SIGN | CKF_VERIFY;
        break;
    case CKM_SHA512:
        pInfo->ulMinKeySize = 0;
        pInfo->ulMaxKeySize = 0;
        pInfo->flags = CKF_DIGEST;
        break;
    case CKM_SHA512_HMAC:
        pInfo->ulMinKeySize = 0;
        pInfo->ulMaxKeySize = 512;
        pInfo->flags = CKF_SIGN | CKF_VERIFY;
        break;
    default:
        rv = CKR_MECHANISM_INVALID;
        break;
    }

cleanup:
    WP11_UNLOCK();
    return rv;
}

/* -------------------------------------------------------------------------
 * unsupported -- common return for unimplemented C_* functions
 *
 * PKCS#11 2.40 sec.11.4: every C_* function except C_Initialize must return
 * CKR_CRYPTOKI_NOT_INITIALIZED if the library is not initialized.
 * The uninitialized check must precede CKR_FUNCTION_NOT_SUPPORTED.
 * ---------------------------------------------------------------------- */

static CK_RV unsupported(void)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* -------------------------------------------------------------------------
 * C_InitToken -- not supported
 * C_InitPIN -- supported for soft persistent token (wolfP11 extension)
 * C_SetPIN   -- not supported
 * ---------------------------------------------------------------------- */

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin,
                   CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
    (void)slotID; (void)pPin; (void)ulPinLen; (void)pLabel;
    return unsupported();
}

/* C_InitPIN -- soft persistent token only (wolfP11 extension)
 *
 * Per PKCS#11 2.40 sec.11.16, C_InitPIN sets the user PIN and is normally called
 * by an SO-logged-in session.  wolfP11 does not support SO login, so this
 * function works only on uninitialized tokens (no keystore file exists).
 * On an already-initialized token, CKR_USER_NOT_LOGGED_IN is returned because
 * the required SO session state is unavailable.
 *
 * Supported backend: WP11_PROTO_SOFT with flash_path set. */
CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
                 CK_ULONG ulPinLen)
{
    CK_RV          rv = CKR_OK;
    wp11_session_t *s;
#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
    int            kret;
#endif

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (pPin == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }
    if (ulPinLen == 0u) { rv = CKR_PIN_LEN_RANGE; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
    /* Only the soft persistent token (WP11_PROTO_SOFT + flash_path) is
     * supported.  All other backends return CKR_FUNCTION_NOT_SUPPORTED. */
    if (g_slots[s->slot_id].proto == WP11_PROTO_SOFT &&
        g_slots[s->slot_id].keystore_path[0] != '\0') {

        /* wolfP11 extension: C_InitPIN works without SO login ONLY when the
         * token is uninitialized (no keystore file exists).  An initialized
         * token requires SO login, which wolfP11 does not support.
         *
         * Use wp11_keystore_load with a dummy ks_out to probe whether the
         * keystore file exists and is valid. */
        wp11_keystore_t *probe = NULL;
        kret = wp11_keystore_load(g_slots[s->slot_id].keystore_path,
                                   (const uint8_t *)pPin, (size_t)ulPinLen,
                                   &probe);
        if (probe != NULL) wp11_keystore_free(probe);
        if (kret != WP11_KEYSTORE_ERR_IO) {
            /* Either the keystore exists (initialized) or there's a real I/O
             * error.  Either way, SO login would be required to change the PIN,
             * which wolfP11 does not support. */
            rv = (kret == WP11_KEYSTORE_OK || kret == WP11_KEYSTORE_ERR_BAD_PIN)
                 ? CKR_USER_NOT_LOGGED_IN
                 : CKR_FUNCTION_FAILED;
            goto cleanup;
        }

        /* No keystore file -- token is uninitialized.  Create an empty keystore
         * with the given PIN.  NULL/0 entries means no keys. */
        if (ulPinLen > sizeof(g_slots[s->slot_id].soft_pin)) {
            rv = CKR_PIN_LEN_RANGE;
            goto cleanup;
        }
        kret = wp11_keystore_create(g_slots[s->slot_id].keystore_path,
                                     (const uint8_t *)pPin, (size_t)ulPinLen,
                                     NULL, 0);
        if (kret != WP11_KEYSTORE_OK) {
            rv = CKR_FUNCTION_FAILED;
            goto cleanup;
        }
        goto cleanup; /* rv == CKR_OK */
    }
#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */

    rv = CKR_FUNCTION_NOT_SUPPORTED;

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
                CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin,
                CK_ULONG ulNewLen)
{
    (void)hSession; (void)pOldPin; (void)ulOldLen;
    (void)pNewPin;  (void)ulNewLen;
    return unsupported();
}

/* -------------------------------------------------------------------------
 * C_OpenSession / C_CloseSession / C_CloseAllSessions / C_GetSessionInfo
 * ---------------------------------------------------------------------- */

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
                     CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                     CK_SESSION_HANDLE_PTR phSession)
{
    CK_RV rv = CKR_SESSION_COUNT;
    int i;

    (void)pApplication; (void)Notify;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (!slot_valid(slotID)) { rv = CKR_SLOT_ID_INVALID; goto cleanup; }
    if (!g_slots[slotID].token_present) { rv = CKR_TOKEN_NOT_PRESENT; goto cleanup; }
    if (phSession == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }
    if (!(flags & CKF_SERIAL_SESSION)) {
        rv = CKR_SESSION_PARALLEL_NOT_SUPPORTED;
        goto cleanup;
    }

    /* Determine the current login state for this slot so a new session
     * inherits it -- PKCS#11 2.40 sec.11.2.2: sessions opened while a user
     * is already logged in start in the appropriate user-functions state. */
    {
        int slot_login = 0;  /* 0=public, 1=CKU_USER, 2=CKU_SO */
        int j;
        for (j = 0; j < MAX_SESSIONS; j++) {
            if (g_sessions[j].in_use &&
                g_sessions[j].slot_id == slotID &&
                g_sessions[j].logged_in != 0) {
                slot_login = g_sessions[j].logged_in;
                break;
            }
        }

        /* PKCS#11 sec.11.6: SO is logged in -- only R/W sessions may be opened */
        if (slot_login == 2 && !(flags & CKF_RW_SESSION)) {
            rv = CKR_SESSION_READ_WRITE_SO_EXISTS;
            goto cleanup;
        }

        for (i = 0; i < MAX_SESSIONS; i++) {
            if (!g_sessions[i].in_use) {
                memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
                g_sessions[i].in_use    = 1;
                g_sessions[i].slot_id   = slotID;
                g_sessions[i].flags     = flags;
                g_sessions[i].logged_in = slot_login;
                if (slot_login == 1) {
                    /* CKU_USER already logged in */
                    g_sessions[i].state = (flags & CKF_RW_SESSION)
                                          ? CKS_RW_USER_FUNCTIONS
                                          : CKS_RO_USER_FUNCTIONS;
                } else if (slot_login == 2) {
                    /* CKU_SO already logged in */
                    g_sessions[i].state = CKS_RW_SO_FUNCTIONS;
                } else {
                    g_sessions[i].state = (flags & CKF_RW_SESSION)
                                          ? CKS_RW_PUBLIC_SESSION
                                          : CKS_RO_PUBLIC_SESSION;
                }
                *phSession = (CK_SESSION_HANDLE)(i + 1);
                rv = CKR_OK;
                goto cleanup;
            }
        }
    }

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    CK_RV rv = CKR_OK;
    wp11_session_t *s;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }

    memset(s, 0, sizeof(*s));

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    CK_RV rv = CKR_OK;
    int i;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (!slot_valid(slotID)) { rv = CKR_SLOT_ID_INVALID; goto cleanup; }

    for (i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].in_use && g_sessions[i].slot_id == slotID) {
            memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
        }
    }

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession,
                        CK_SESSION_INFO_PTR pInfo)
{
    CK_RV rv = CKR_OK;
    wp11_session_t *s;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (pInfo == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }

    pInfo->slotID        = s->slot_id;
    pInfo->state         = s->state;
    pInfo->flags         = s->flags;
    pInfo->ulDeviceError = 0;

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
                           CK_BYTE_PTR pOperationState,
                           CK_ULONG_PTR pulOperationStateLen)
{
    (void)hSession; (void)pOperationState; (void)pulOperationStateLen;
    return unsupported();
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
                           CK_BYTE_PTR pOperationState,
                           CK_ULONG ulOperationStateLen,
                           CK_OBJECT_HANDLE hEncryptionKey,
                           CK_OBJECT_HANDLE hAuthenticationKey)
{
    (void)hSession; (void)pOperationState; (void)ulOperationStateLen;
    (void)hEncryptionKey; (void)hAuthenticationKey;
    return unsupported();
}

/* -------------------------------------------------------------------------
 * wolfHSM slot connect / disconnect helpers
 *
 * These functions allocate, initialise, and teardown the wolfHSM client
 * context for a WP11_PROTO_WOLFHSM slot.  They are called from C_Login
 * (connect) and C_Logout / C_Finalize (disconnect).
 *
 * Transport is selected at connect time by reading two env vars:
 *   WOLFP11_HSM_SHM_ID  -- POSIX SHM object name (e.g. "/wolfhsm_shm")
 *   WOLFP11_HSM_TCP_ADDR -- "host:port" string  (e.g. "127.0.0.1:23456")
 * SHM is preferred if both are set.  Neither set -> CKR_DEVICE_NOT_FOUND.
 *
 * Must be called under g_lock.
 * ---------------------------------------------------------------------- */

#ifdef WOLFP11_CFG_WOLFHSM_BACKEND

/* SHM request/response buffer sizes.  Must be large enough for wolfHSM's
 * maximum message payload.  4 KiB is sufficient for RSA-4096 operations. */
#define WP11_WOLFHSM_SHM_REQ_SIZE    4096u
#define WP11_WOLFHSM_SHM_RESP_SIZE   4096u

/* Static transport callback tables (file-scope, not stack-allocated, so the
 * pointers in whCommClientConfig remain valid for the lifetime of the slot). */
static const whTransportClientCb g_wolfhsm_shm_cb = POSIX_TRANSPORT_SHM_CLIENT_CB;
static const whTransportClientCb g_wolfhsm_tcp_cb  = PTT_CLIENT_CB;

/* Heap-allocated connection state for one wolfHSM backend slot.
 * Stored in g_slots[i].hsm_client (cast from void*).
 * All fields must remain valid between C_Login and C_Logout. */
typedef struct {
    whClientContext            ctx;
    whCommClientConfig         comm_cfg;
    int                        transport; /* 0=SHM, 1=TCP */
    union {
        struct {
            posixTransportShmContext   ctx;
            posixTransportShmConfig    cfg;
        } shm;
        struct {
            posixTransportTcpClientContext ctx;
            posixTransportTcpConfig        cfg;
        } tcp;
    } t;
    /* Storage for address strings pointed to by transport configs. */
    char addr_buf[256];
    /* For TCP: split storage for ip and port fields */
    char tcp_ip[64];
} wp11_wolfhsm_client_t;

/* Maximum raw DER bytes exported per key during enumeration.
 * RSA-4096 private key PKCS#1 DER <= ~2350 bytes; EC P-384 <= ~185 bytes. */
#define WP11_WOLFHSM_MAX_DER_EXPORT  3072u

/* Remove all g_keys[] entries that belong to a wolfHSM slot.
 * Calls free_key_priv on each key (which frees the wp11_wolfhsm_key_priv_t).
 * Safe to call when keys have already been freed by C_Finalize's generic
 * loop -- in_use == 0 after that loop, so this becomes a no-op. */
static void wolfhsm_slot_clear_keys(CK_SLOT_ID slot_id)
{
    int gi;
    for (gi = 0; gi < MAX_KEYS; gi++) {
        if (!g_keys[gi].in_use) continue;
        if (g_keys[gi].slot_id != slot_id) continue;
        if (g_keys[gi].backend_ops != &wp11_backend_wolfhsm_ops) continue;
        if (g_keys[gi].key_priv != NULL &&
            g_keys[gi].backend_ops->free_key_priv != NULL) {
            g_keys[gi].backend_ops->free_key_priv(g_keys[gi].key_priv);
        }
        memset(&g_keys[gi], 0, sizeof(g_keys[gi]));
    }
}

/* Enumerate pre-provisioned CRYPTO keys on the wolfHSM server and create
 * corresponding g_keys[] entries for the given slot.
 *
 * For each key whose DER can be exported, the key type (RSA / EC) and RSA
 * modulus size are determined by attempting wolfCrypt decode in order:
 * EC first (fast fail), then RSA.  Keys that are NONEXPORTABLE on the server
 * or whose DER cannot be parsed are silently skipped.
 *
 * Must be called under g_lock, immediately after a successful CommInit.
 *
 * Returns the number of keys that could NOT be added because g_keys[] is
 * full (0 = all visible keys added successfully). */
static int wolfhsm_slot_populate_keys(CK_SLOT_ID slot_id, whClientContext *ctx)
{
    whNvmId   start_id = 0u;
    int       dropped  = 0;

    for (;;) {
        int32_t     nvm_rc      = 0;
        whNvmId     out_count   = 0;
        whNvmId     out_id      = 0;
        int32_t     meta_rc     = 0;
        whNvmId     meta_id     = 0;
        whNvmAccess meta_acc    = 0;
        whNvmFlags  meta_flags  = 0;
        whNvmSize   meta_len    = 0;
        uint8_t     nvm_label[WH_NVM_LABEL_LEN];
        uint8_t    *der;
        uint16_t    der_size;
        int         key_type    = -1;
        uint16_t    key_size    = 0u;
        CK_ULONG    sig_len     = 0u;
        int         gi;
        wp11_wolfhsm_key_priv_t *kp;
        int         wret;

        /* Get next NVM object at or after start_id */
        wret = wh_Client_NvmList(ctx, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONE,
                                  start_id, &nvm_rc, &out_count, &out_id);
        if (wret != WH_ERROR_OK || nvm_rc != 0 || out_count == 0) break;

        /* Advance past this ID so the next iteration starts after out_id */
        if (out_id == (whNvmId)0xFFFFu) break;  /* overflow guard */
        start_id = (whNvmId)(out_id + 1u);

        /* Only enumerate crypto keys (skip counters, SHE keys, etc.) */
        if (WH_KEYID_TYPE(out_id) != WH_KEYTYPE_CRYPTO) continue;

        /* Fetch metadata: flags and label */
        memset(nvm_label, 0, sizeof(nvm_label));
        wret = wh_Client_NvmGetMetadata(ctx, out_id, &meta_rc, &meta_id,
                                         &meta_acc, &meta_flags, &meta_len,
                                         (whNvmSize)sizeof(nvm_label),
                                         nvm_label);
        if (wret != WH_ERROR_OK || meta_rc != 0) continue;
        if (meta_len == 0u || meta_len > WP11_WOLFHSM_MAX_DER_EXPORT) continue;

        /* Export raw DER to detect key type and size */
        der = (uint8_t *)malloc(meta_len);
        if (der == NULL) { dropped++; continue; }

        der_size = (uint16_t)meta_len;
        {
            uint8_t exp_label[WH_NVM_LABEL_LEN];
            wret = wh_Client_KeyExport(ctx, out_id, exp_label,
                                        (uint16_t)sizeof(exp_label),
                                        der, &der_size);
        }
        if (wret != WH_ERROR_OK) {
            /* NONEXPORTABLE or server error -- cannot determine type; skip */
            memset(der, 0, meta_len);
            free(der);
            continue;
        }

        /* Try EC decode first (fast unambiguous fail on non-EC DER) */
        {
            ecc_key ecc;
            word32  idx = 0u;
            if (wc_ecc_init(&ecc) == 0) {
                if (wc_EccPrivateKeyDecode(der, &idx, &ecc,
                                           (word32)der_size) == 0) {
                    int csz   = wc_ecc_size(&ecc);
                    key_type  = WP11_KEY_TYPE_EC;
                    key_size  = 0u;
                    sig_len   = (csz > 0) ? (CK_ULONG)(8 + 2 * csz) : 72u;
                }
                wc_ecc_free(&ecc);
            }
        }

        /* Try RSA decode if not EC */
        if (key_type < 0) {
            RsaKey rsa;
            word32 idx = 0u;
            if (wc_InitRsaKey(&rsa, NULL) == 0) {
                if (wc_RsaPrivateKeyDecode(der, &idx, &rsa,
                                           (word32)der_size) == 0) {
                    int sz = wc_RsaEncryptSize(&rsa);
                    if (sz > 0 && sz <= 512) {
                        key_type = WP11_KEY_TYPE_RSA;
                        key_size = (uint16_t)sz;
                        sig_len  = (CK_ULONG)sz;
                    }
                }
                wc_FreeRsaKey(&rsa);
            }
        }

        memset(der, 0, meta_len);
        free(der);

        if (key_type < 0) continue;  /* Unrecognised DER format */

        /* Find a free g_keys[] entry */
        for (gi = 0; gi < MAX_KEYS; gi++) {
            if (!g_keys[gi].in_use) break;
        }
        if (gi >= MAX_KEYS) { dropped++; continue; }

        kp = wp11_wolfhsm_alloc_key_priv((void *)ctx, out_id, key_type, key_size);
        if (kp == NULL) { dropped++; continue; }

        g_keys[gi].in_use      = 1;
        g_keys[gi].slot_id     = slot_id;
        g_keys[gi].obj_class   = CKO_PRIVATE_KEY;
        g_keys[gi].key_type    = (key_type == WP11_KEY_TYPE_EC) ? CKK_EC : CKK_RSA;
        g_keys[gi].sig_len_max = sig_len;
        g_keys[gi].key_priv    = kp;
        g_keys[gi].backend_ops = &wp11_backend_wolfhsm_ops;
        g_keys[gi].is_private  = CK_TRUE;
        g_keys[gi].is_token    = CK_TRUE;

        /* Use the NVM label as the PKCS#11 label if non-empty; else hex ID */
        nvm_label[sizeof(nvm_label) - 1u] = '\0';
        if (nvm_label[0] != '\0') {
            strncpy(g_keys[gi].label, (char *)nvm_label,
                    sizeof(g_keys[gi].label) - 1u);
        } else {
            snprintf(g_keys[gi].label, sizeof(g_keys[gi].label),
                     "%04x", (unsigned)out_id);
        }
        g_keys[gi].label[sizeof(g_keys[gi].label) - 1u] = '\0';

        /* CKA_ID: 2-byte big-endian encoding of the server key ID */
        memset(g_keys[gi].id, 0, sizeof(g_keys[gi].id));
        g_keys[gi].id[0] = (uint8_t)((out_id >> 8) & 0xFFu);
        g_keys[gi].id[1] = (uint8_t)(out_id & 0xFFu);
        g_keys[gi].id_len = 2u;
    }

    return dropped;
}

/* Connect to the wolfHSM server and store the client context in the slot.
 * Returns CKR_OK on success, CKR_DEVICE_NOT_FOUND / CKR_DEVICE_ERROR on
 * failure.  CKR_PIN_INCORRECT is returned if the server rejects the client
 * with WH_ERROR_ACCESS.  pPin/ulPinLen are reserved for future client-auth
 * support and are not used by the current implementation. */
static CK_RV wolfhsm_slot_connect(CK_SLOT_ID slot_id,
                                   CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    const char            *shm_id   = getenv("WOLFP11_HSM_SHM_ID");
    const char            *tcp_addr = getenv("WOLFP11_HSM_TCP_ADDR");
    wp11_wolfhsm_client_t *wh;
    whClientConfig         c_conf;
    int                    wret;

    (void)pPin; (void)ulPinLen;  /* reserved for future client-auth */

    if (g_slots[slot_id].hsm_client != NULL) {
        return CKR_OK;  /* already connected */
    }

    if (shm_id == NULL && tcp_addr == NULL) {
        return CKR_TOKEN_NOT_PRESENT;
    }

    wh = (wp11_wolfhsm_client_t *)calloc(1u, sizeof(*wh));
    if (wh == NULL) return CKR_DEVICE_MEMORY;

    if (shm_id != NULL) {
        /* POSIX SHM transport */
        strncpy(wh->addr_buf, shm_id, sizeof(wh->addr_buf) - 1u);
        wh->addr_buf[sizeof(wh->addr_buf) - 1u] = '\0';

        wh->t.shm.cfg.name      = wh->addr_buf;
        wh->t.shm.cfg.req_size  = WP11_WOLFHSM_SHM_REQ_SIZE;
        wh->t.shm.cfg.resp_size = WP11_WOLFHSM_SHM_RESP_SIZE;
        wh->t.shm.cfg.dma_size  = 0u;

        wh->comm_cfg.transport_cb      = &g_wolfhsm_shm_cb;
        wh->comm_cfg.transport_context = &wh->t.shm.ctx;
        wh->comm_cfg.transport_config  = &wh->t.shm.cfg;
        wh->comm_cfg.client_id         = 1u;
        wh->transport = 0;

    } else {
        /* TCP transport -- parse "host:port" */
        const char *colon;
        long        port_l;
        size_t      ip_len;

        colon = strrchr(tcp_addr, ':');
        if (colon == NULL) { free(wh); return CKR_DEVICE_ERROR; }

        port_l = strtol(colon + 1, NULL, 10);
        if (port_l <= 0 || port_l > 65535) { free(wh); return CKR_DEVICE_ERROR; }

        ip_len = (size_t)(colon - tcp_addr);
        if (ip_len == 0 || ip_len >= sizeof(wh->tcp_ip)) {
            free(wh);
            return CKR_DEVICE_ERROR;
        }
        memcpy(wh->tcp_ip, tcp_addr, ip_len);
        wh->tcp_ip[ip_len] = '\0';

        wh->t.tcp.cfg.server_ip_string = wh->tcp_ip;
        wh->t.tcp.cfg.server_port      = (short)port_l;

        wh->comm_cfg.transport_cb      = &g_wolfhsm_tcp_cb;
        wh->comm_cfg.transport_context = &wh->t.tcp.ctx;
        wh->comm_cfg.transport_config  = &wh->t.tcp.cfg;
        wh->comm_cfg.client_id         = 1u;
        wh->transport = 1;
    }

    memset(&c_conf, 0, sizeof(c_conf));
    c_conf.comm = &wh->comm_cfg;

    wret = wh_Client_Init(&wh->ctx, &c_conf);
    if (wret != WH_ERROR_OK) {
        free(wh);
        return CKR_DEVICE_ERROR;
    }

    wret = wh_Client_CommInit(&wh->ctx, NULL, NULL);
    if (wret != WH_ERROR_OK) {
        wh_Client_Cleanup(&wh->ctx);
        free(wh);
        if (wret == WH_ERROR_ACCESS)  return CKR_PIN_INCORRECT;
        if (wret == WH_ERROR_TIMEOUT) return CKR_TOKEN_NOT_PRESENT;
        return CKR_DEVICE_ERROR;
    }

    g_slots[slot_id].hsm_client = (void *)wh;

    /* Populate g_keys[] with pre-provisioned keys on the server.
     * Returns 0 on success, >0 if any keys couldn't be added (g_keys full). */
    if (wolfhsm_slot_populate_keys(slot_id, &wh->ctx) > 0) {
        wolfhsm_slot_disconnect(slot_id);
        return CKR_DEVICE_MEMORY;
    }

    return CKR_OK;
}

/* Disconnect from the wolfHSM server, free the client context, and clear
 * the slot's hsm_client pointer.  No-op if hsm_client is already NULL. */
static void wolfhsm_slot_disconnect(CK_SLOT_ID slot_id)
{
    wp11_wolfhsm_client_t *wh;

    if (g_slots[slot_id].hsm_client == NULL) return;

    /* Free key objects before closing the connection.  wolfhsm_slot_clear_keys
     * is idempotent: if C_Finalize already ran the generic key-free loop the
     * in_use flags will be 0 and this is a no-op. */
    wolfhsm_slot_clear_keys(slot_id);

    wh = (wp11_wolfhsm_client_t *)g_slots[slot_id].hsm_client;
    wh_Client_CommClose(&wh->ctx);
    wh_Client_Cleanup(&wh->ctx);
    memset(wh, 0, sizeof(*wh));
    free(wh);
    g_slots[slot_id].hsm_client = NULL;
}

#endif /* WOLFP11_CFG_WOLFHSM_BACKEND */

/* -------------------------------------------------------------------------
 * C_Login / C_Logout
 * ---------------------------------------------------------------------- */

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
               CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    CK_RV rv = CKR_OK;
    wp11_session_t *s;
    int i;
    int slot_id_for_count = -1; /* set once we have a valid session+slot */
#if defined(WOLFP11_CFG_USB_FLASH_BACKEND) || defined(WOLFP11_CFG_FSDIR_BACKEND)
    wp11_keystore_t *ks;
    int kret;
#endif

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    slot_id_for_count = (int)s->slot_id;

    /* Check if any session on this slot is already logged in */
    for (i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].in_use &&
            g_sessions[i].slot_id == s->slot_id &&
            g_sessions[i].logged_in != 0) {
            /* logged_in: 1=USER, 2=SO; distinguish same vs different type */
            int cur_type = g_sessions[i].logged_in;
            int req_type = (userType == CKU_SO) ? 2 : 1;
            rv = (cur_type == req_type) ? CKR_USER_ALREADY_LOGGED_IN
                                        : CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
            goto cleanup;
        }
    }

    /* PKCS#11 2.40 sec.11.16: C_Login(CKU_SO) must fail if any read-only session
     * is open on the token, because SO login requires read-write access to all
     * sessions on the slot. */
    if (userType == CKU_SO) {
        for (i = 0; i < MAX_SESSIONS; i++) {
            if (g_sessions[i].in_use &&
                g_sessions[i].slot_id == s->slot_id &&
                !(g_sessions[i].flags & CKF_RW_SESSION)) {
                rv = CKR_SESSION_READ_ONLY_EXISTS;
                goto cleanup;
            }
        }
        /* SO login: verify PIN when a persistent keystore exists.
         * If the keystore file is absent, the token is uninitialized and SO
         * may log in without a PIN (e.g. to call C_InitPIN for first setup). */
#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
        if (g_slots[s->slot_id].proto == WP11_PROTO_SOFT &&
            g_slots[s->slot_id].keystore_path[0] != '\0') {
            struct stat so_st_;
            if (stat(g_slots[s->slot_id].keystore_path, &so_st_) == 0) {
                wp11_keystore_t *so_ks = NULL;
                kret = wp11_keystore_load(g_slots[s->slot_id].keystore_path,
                                           (const uint8_t *)pPin,
                                           (size_t)ulPinLen, &so_ks);
                if (so_ks != NULL) { wp11_keystore_free(so_ks); so_ks = NULL; }
                if (kret == WP11_KEYSTORE_ERR_BAD_PIN) {
                    rv = CKR_PIN_INCORRECT;
                    goto cleanup;
                } else if (kret != WP11_KEYSTORE_OK) {
                    rv = CKR_FUNCTION_FAILED;
                    goto cleanup;
                }
            }
        }
#endif
    }

    if (userType == CKU_USER) {
#ifdef WOLFP11_CFG_USB_BACKEND
        if (g_slots[s->slot_id].proto == WP11_PROTO_PIV) {
            /* PIV hardware token: open CCID, SELECT PIV AID, VERIFY PIN,
             * then create key objects for all four PIV slots (9A/9C/9D/9E). */
            static const struct {
                uint8_t    piv_slot;
                uint8_t    piv_alg;
                uint8_t    key_id;   /* CKA_ID[0] */
                CK_ULONG   sig_len_max;
                const char *label;
            } piv_slot_tab[] = {
                { WP11_PIV_SLOT_AUTH,     WP11_PIV_ALG_EC_P256, 0x01,  72u, "PIV Authentication"    },
                { WP11_PIV_SLOT_SIGN,     WP11_PIV_ALG_EC_P256, 0x02,  72u, "PIV Digital Signature" },
                { WP11_PIV_SLOT_KEYMGMT,  WP11_PIV_ALG_EC_P256, 0x03,  72u, "PIV Key Management"    },
                { WP11_PIV_SLOT_CARDAUTH, WP11_PIV_ALG_EC_P256, 0x04,  72u, "PIV Card Authentication" },
            };
            wp11_ccid_ctx_t    *ccid_new = NULL;
            int                 prc;
            int                 ki;
            size_t              ns;
            wp11_usb_key_priv_t *kp;

            if (pPin == NULL_PTR || ulPinLen == 0) {
                rv = CKR_ARGUMENTS_BAD;
                goto cleanup;
            }

            prc = wp11_ccid_open(g_slots[s->slot_id].usb_vid,
                                  g_slots[s->slot_id].usb_pid, &ccid_new);
            if (prc != WP11_CCID_OK) {
                rv = CKR_DEVICE_ERROR;
                goto cleanup;
            }

            prc = wp11_piv_select(ccid_new);
            if (prc != WP11_PIV_OK) {
                wp11_ccid_close(ccid_new);
                rv = CKR_DEVICE_ERROR;
                goto cleanup;
            }

            prc = wp11_piv_verify_pin(ccid_new,
                                       (const uint8_t *)pPin,
                                       (size_t)ulPinLen);
            if (prc == WP11_PIV_ERR_PIN_BAD ||
                prc == WP11_PIV_ERR_PIN_LOCKED) {
                wp11_ccid_close(ccid_new);
                rv = CKR_PIN_INCORRECT;
                goto cleanup;
            }
            if (prc != WP11_PIV_OK) {
                wp11_ccid_close(ccid_new);
                rv = CKR_FUNCTION_FAILED;
                goto cleanup;
            }

            /* Create one key object per PIV slot */
            for (ns = 0; ns < sizeof(piv_slot_tab)/sizeof(piv_slot_tab[0]); ns++) {
                for (ki = 0; ki < MAX_KEYS; ki++) {
                    if (!g_keys[ki].in_use) break;
                }
                if (ki == MAX_KEYS) {
                    piv_slot_clear_keys(s->slot_id);
                    wp11_ccid_close(ccid_new);
                    rv = CKR_DEVICE_MEMORY;
                    goto cleanup;
                }

                kp = (wp11_usb_key_priv_t *)malloc(sizeof(*kp));
                if (kp == NULL) {
                    piv_slot_clear_keys(s->slot_id);
                    wp11_ccid_close(ccid_new);
                    rv = CKR_DEVICE_MEMORY;
                    goto cleanup;
                }
                kp->ccid     = ccid_new;
                kp->piv_slot = piv_slot_tab[ns].piv_slot;
                kp->piv_alg  = piv_slot_tab[ns].piv_alg;

                g_keys[ki].in_use      = 1;
                g_keys[ki].slot_id     = (int)s->slot_id;
                g_keys[ki].obj_class   = CKO_PRIVATE_KEY;
                g_keys[ki].key_type    = CKK_EC;
                g_keys[ki].sig_len_max = piv_slot_tab[ns].sig_len_max;
                g_keys[ki].key_priv    = kp;
                g_keys[ki].backend_ops = &wp11_backend_usb_ops;
                g_keys[ki].is_token    = CK_TRUE;
                memset(g_keys[ki].id, 0, sizeof(g_keys[ki].id));
                g_keys[ki].id[0]       = piv_slot_tab[ns].key_id;
                g_keys[ki].id_len      = 1u;
                strncpy(g_keys[ki].label, piv_slot_tab[ns].label,
                        sizeof(g_keys[ki].label) - 1u);
                g_keys[ki].label[sizeof(g_keys[ki].label) - 1u] = '\0';
            }

            /* Attempt certificate retrieval for each PIV slot.
             * Cert slots may be empty or unprovisioned -- any error is non-fatal.
             * Cert objects (CKO_CERTIFICATE) share the g_keys[] table and are
             * freed by piv_slot_clear_keys when the token is logged out. */
            for (ns = 0; ns < sizeof(piv_slot_tab)/sizeof(piv_slot_tab[0]); ns++) {
                uint8_t *der;
                size_t   derlen;
                int      crc;
                int      ci;

                der = (uint8_t *)malloc(WP11_PIV_CERT_MAX_LEN);
                if (der == NULL) break;  /* OOM -- skip remaining cert slots */

                derlen = WP11_PIV_CERT_MAX_LEN;
                crc = wp11_piv_get_cert(ccid_new,
                                         piv_slot_tab[ns].piv_slot,
                                         der, &derlen);
                if (crc != WP11_PIV_OK) {
                    free(der);
                    continue;  /* empty slot or transport error -- skip */
                }

                for (ci = 0; ci < MAX_KEYS; ci++) {
                    if (!g_keys[ci].in_use) break;
                }
                if (ci == MAX_KEYS) {
                    free(der);
                    break;  /* table full -- skip remaining cert slots */
                }

                g_keys[ci].in_use       = 1;
                g_keys[ci].slot_id      = (int)s->slot_id;
                g_keys[ci].obj_class    = CKO_CERTIFICATE;
                g_keys[ci].key_priv     = NULL;
                g_keys[ci].backend_ops  = &wp11_backend_usb_ops;
                g_keys[ci].is_token     = CK_TRUE;
                memset(g_keys[ci].id, 0, sizeof(g_keys[ci].id));
                g_keys[ci].id[0]        = piv_slot_tab[ns].key_id;
                g_keys[ci].id_len       = 1u;
                g_keys[ci].cert_der     = der;
                g_keys[ci].cert_der_len = derlen;
                strncpy(g_keys[ci].label, piv_slot_tab[ns].label,
                        sizeof(g_keys[ci].label) - 1u);
                g_keys[ci].label[sizeof(g_keys[ci].label) - 1u] = '\0';
            }

            g_slots[s->slot_id].ccid = ccid_new;
        }
#endif /* WOLFP11_CFG_USB_BACKEND */

#ifdef WOLFP11_CFG_WOLFHSM_BACKEND
        if (g_slots[s->slot_id].proto == WP11_PROTO_WOLFHSM) {
            rv = wolfhsm_slot_connect((CK_SLOT_ID)s->slot_id, pPin, ulPinLen);
            if (rv != CKR_OK) goto cleanup;
        }
#endif /* WOLFP11_CFG_WOLFHSM_BACKEND */

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
        if (g_slots[s->slot_id].keystore_path[0] != '\0') {
            if (pPin == NULL_PTR || ulPinLen == 0) {
                rv = CKR_ARGUMENTS_BAD;
                goto cleanup;
            }
            if (ulPinLen > sizeof(g_slots[s->slot_id].soft_pin)) {
                rv = CKR_PIN_LEN_RANGE;
                goto cleanup;
            }
            ks = NULL;
            if (g_slots[s->slot_id].proto == WP11_PROTO_SOFT) {
                /* Soft persistent token: load if file exists; first use is OK.
                 * A missing file returns WP11_KEYSTORE_ERR_IO -- that means the
                 * token is new and has no keys yet, which is not an error. */
                kret = wp11_keystore_load(g_slots[s->slot_id].keystore_path,
                                           (const uint8_t *)pPin,
                                           (size_t)ulPinLen, &ks);
                if (kret == WP11_KEYSTORE_ERR_IO) {
                    /* No keystore file -- token not initialized.  Return
                     * CKR_USER_PIN_NOT_INITIALIZED per PKCS#11 2.40 sec.11.16.
                     * Call C_InitPIN to create the keystore before logging in. */
                    rv = CKR_USER_PIN_NOT_INITIALIZED;
                    goto cleanup;
                } else if (kret != WP11_KEYSTORE_OK) {
                    rv = (kret == WP11_KEYSTORE_ERR_BAD_PIN)
                             ? CKR_PIN_INCORRECT : CKR_FUNCTION_FAILED;
                    goto cleanup;
                }
                /* Cache PIN (mlock) for re-encryption in C_GenerateKeyPair.
                 * mlock is required for security -- PIN must not reach swap
                 * storage.  Return error if locking fails. */
                if (mlock(g_slots[s->slot_id].soft_pin,
                          sizeof(g_slots[s->slot_id].soft_pin)) != 0) {
                    if (ks != NULL) wp11_keystore_free(ks);
                    rv = CKR_GENERAL_ERROR;
                    goto cleanup;
                }
                memcpy(g_slots[s->slot_id].soft_pin, pPin, (size_t)ulPinLen);
                g_slots[s->slot_id].soft_pin_len = (size_t)ulPinLen;
                if (ks != NULL) {
                    if (soft_slot_populate_keys(s->slot_id, ks) > 0) {
                        soft_slot_clear_keys(s->slot_id);
                        wp11_keystore_free(ks);
                        memset(g_slots[s->slot_id].soft_pin, 0,
                               sizeof(g_slots[s->slot_id].soft_pin));
                        g_slots[s->slot_id].soft_pin_len = 0;
                        rv = CKR_DEVICE_MEMORY;
                        goto cleanup;
                    }
                    wp11_keystore_free(ks);
                }
            } else {
                /* Flash hardware token: authenticate and load all keys.
                 * A wrong PIN causes AES-GCM auth to fail -> ERR_BAD_PIN. */
                kret = wp11_keystore_load(g_slots[s->slot_id].keystore_path,
                                           (const uint8_t *)pPin,
                                           (size_t)ulPinLen, &ks);
                if (kret != WP11_KEYSTORE_OK) {
                    rv = (kret == WP11_KEYSTORE_ERR_BAD_PIN)
                             ? CKR_PIN_INCORRECT : CKR_FUNCTION_FAILED;
                    goto cleanup;
                }
                /* Store keystore in slot and expose keys as PKCS#11 objects.
                 * If the global key table is full, populate returns the number
                 * of keys that could not be added.  Return CKR_DEVICE_MEMORY
                 * rather than silently presenting a partial key set. */
                g_slots[s->slot_id].keystore = ks;
                if (ks_slot_populate_keys(s->slot_id, ks, &wp11_backend_flash_ops) > 0) {
                    ks_slot_clear_keys(s->slot_id);
                    wp11_keystore_free(g_slots[s->slot_id].keystore);
                    g_slots[s->slot_id].keystore = NULL;
                    rv = CKR_DEVICE_MEMORY;
                    goto cleanup;
                }
            }
        } else {
            (void)pPin; (void)ulPinLen;
        }
#else
        (void)pPin; (void)ulPinLen;
#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */

#ifdef WOLFP11_CFG_FSDIR_BACKEND
        if (g_slots[s->slot_id].proto == WP11_PROTO_FSDIR) {
            /* FSDIR slot: authenticate with the .p11k file's PIN. */
            if (pPin == NULL_PTR || ulPinLen == 0) {
                rv = CKR_ARGUMENTS_BAD;
                goto cleanup;
            }
            ks = NULL;
            kret = wp11_keystore_load(g_slots[s->slot_id].keystore_path,
                                       (const uint8_t *)pPin,
                                       (size_t)ulPinLen, &ks);
            if (kret != WP11_KEYSTORE_OK) {
                rv = (kret == WP11_KEYSTORE_ERR_BAD_PIN)
                         ? CKR_PIN_INCORRECT : CKR_FUNCTION_FAILED;
                goto cleanup;
            }
            g_slots[s->slot_id].keystore = ks;
            if (ks_slot_populate_keys(s->slot_id, ks, &wp11_backend_fsdir_ops) > 0) {
                ks_slot_clear_keys(s->slot_id);
                wp11_keystore_free(g_slots[s->slot_id].keystore);
                g_slots[s->slot_id].keystore = NULL;
                rv = CKR_DEVICE_MEMORY;
                goto cleanup;
            }
        }
#endif /* WOLFP11_CFG_FSDIR_BACKEND */

        /* Mark all sessions on this slot as logged in */
        for (i = 0; i < MAX_SESSIONS; i++) {
            if (g_sessions[i].in_use && g_sessions[i].slot_id == s->slot_id) {
                g_sessions[i].logged_in = 1;
                if (g_sessions[i].flags & CKF_RW_SESSION) {
                    g_sessions[i].state = CKS_RW_USER_FUNCTIONS;
                } else {
                    g_sessions[i].state = CKS_RO_USER_FUNCTIONS;
                }
            }
        }
    } else if (userType == CKU_SO) {
        for (i = 0; i < MAX_SESSIONS; i++) {
            if (g_sessions[i].in_use && g_sessions[i].slot_id == s->slot_id) {
                g_sessions[i].logged_in = 2;
                g_sessions[i].state = CKS_RW_SO_FUNCTIONS;
            }
        }
    } else {
        rv = CKR_USER_TYPE_INVALID;
        goto cleanup;
    }

cleanup:
    if (slot_id_for_count >= 0) {
        if (rv == CKR_PIN_INCORRECT)
            g_slots[slot_id_for_count].pin_fail_count++;
        else if (rv == CKR_OK)
            g_slots[slot_id_for_count].pin_fail_count = 0;
    }
    WP11_UNLOCK();
    return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    CK_RV rv = CKR_OK;
    wp11_session_t *s;
    int i;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }

    if (s->logged_in == 0) { rv = CKR_USER_NOT_LOGGED_IN; goto cleanup; }

#ifdef WOLFP11_CFG_USB_BACKEND
    if (g_slots[s->slot_id].proto == WP11_PROTO_PIV &&
        g_slots[s->slot_id].ccid != NULL) {
        /* PIV hardware token: free key objects and close the CCID context.
         * free_key_priv frees the wp11_usb_key_priv_t struct (not the ccid). */
        piv_slot_clear_keys(s->slot_id);
        wp11_ccid_close(g_slots[s->slot_id].ccid);
        g_slots[s->slot_id].ccid = NULL;
    }
#endif /* WOLFP11_CFG_USB_BACKEND */

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
    if (g_slots[s->slot_id].proto == WP11_PROTO_SOFT &&
        g_slots[s->slot_id].keystore_path[0] != '\0') {
        /* Soft persistent token: free wolfCrypt key objects and zeroize
         * the cached PIN.  munlock is best-effort; ignore failure. */
        soft_slot_clear_keys(s->slot_id);
        memset(g_slots[s->slot_id].soft_pin, 0,
               sizeof(g_slots[s->slot_id].soft_pin));
        munlock(g_slots[s->slot_id].soft_pin,
                sizeof(g_slots[s->slot_id].soft_pin));
        g_slots[s->slot_id].soft_pin_len = 0;
    }
#endif /* WOLFP11_CFG_USB_FLASH_BACKEND */

#if defined(WOLFP11_CFG_USB_FLASH_BACKEND) || defined(WOLFP11_CFG_FSDIR_BACKEND)
    if (g_slots[s->slot_id].keystore != NULL) {
        /* Keystore backend (flash or fsdir): clear key objects first, then
         * free the keystore.  ks_slot_clear_keys matches by free_key_priv == NULL
         * so it handles both backends correctly (wolfP11-be5). */
        ks_slot_clear_keys(s->slot_id);
        wp11_keystore_free(g_slots[s->slot_id].keystore);
        g_slots[s->slot_id].keystore = NULL;
    }
#endif /* WOLFP11_CFG_USB_FLASH_BACKEND || WOLFP11_CFG_FSDIR_BACKEND */

#ifdef WOLFP11_CFG_WOLFHSM_BACKEND
    if (g_slots[s->slot_id].proto == WP11_PROTO_WOLFHSM) {
        wolfhsm_slot_disconnect((CK_SLOT_ID)s->slot_id);
    }
#endif /* WOLFP11_CFG_WOLFHSM_BACKEND */

    for (i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].in_use && g_sessions[i].slot_id == s->slot_id) {
            g_sessions[i].logged_in = 0;
            if (g_sessions[i].flags & CKF_RW_SESSION) {
                g_sessions[i].state = CKS_RW_PUBLIC_SESSION;
            } else {
                g_sessions[i].state = CKS_RO_PUBLIC_SESSION;
            }
        }
    }

cleanup:
    WP11_UNLOCK();
    return rv;
}

/* -------------------------------------------------------------------------
 * Object management
 * ---------------------------------------------------------------------- */

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,
                      CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                      CK_OBJECT_HANDLE_PTR phObject)
{
    CK_RV              rv = CKR_OK;
    wp11_session_t    *s;
    CK_ULONG           i;
    int                gi;
    CK_OBJECT_CLASS    obj_class    = (CK_OBJECT_CLASS)-1;
    const char        *label        = "";
    const uint8_t     *app_val      = NULL; /* CKA_APPLICATION bytes */
    CK_ULONG           app_val_len  = 0;
    const uint8_t     *value        = NULL;
    CK_ULONG           value_len    = 0;
    uint8_t           *value_copy   = NULL;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    if (phObject == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }
    if (pTemplate == NULL_PTR && ulCount > 0) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    /* CKA_CLASS is mandatory */
    for (i = 0; i < ulCount; i++) {
        if (pTemplate[i].type == CKA_CLASS && pTemplate[i].pValue != NULL_PTR)
            obj_class = *(const CK_OBJECT_CLASS *)pTemplate[i].pValue;
    }
    if (obj_class == (CK_OBJECT_CLASS)-1) { rv = CKR_TEMPLATE_INCOMPLETE; goto cleanup; }
    if (obj_class != CKO_DATA && obj_class != CKO_SECRET_KEY &&
        obj_class != CKO_PUBLIC_KEY && obj_class != CKO_PRIVATE_KEY) {
        rv = CKR_FUNCTION_NOT_SUPPORTED;
        goto cleanup;
    }

    {
        /* Common parse state for both CKO_DATA and CKO_SECRET_KEY */
        CK_BBOOL is_token_obj  = CK_FALSE;
        CK_BBOOL is_sensitive  = CK_FALSE;  /* PKCS#11 default for imported keys */
        CK_BBOOL is_extractable = CK_TRUE;  /* PKCS#11 default for imported keys */
        CK_KEY_TYPE key_type   = CKK_GENERIC_SECRET;
        CK_BBOOL is_private_obj = CK_FALSE;

        for (i = 0; i < ulCount; i++) {
            if (pTemplate[i].pValue == NULL_PTR) continue;
            switch (pTemplate[i].type) {
            case CKA_CLASS: break;
            case CKA_LABEL:
                label = (const char *)pTemplate[i].pValue;
                break;
            case CKA_VALUE:
                value     = (const uint8_t *)pTemplate[i].pValue;
                value_len = pTemplate[i].ulValueLen;
                break;
            case CKA_TOKEN:
                if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
                    is_token_obj = *(const CK_BBOOL *)pTemplate[i].pValue;
                break;
            case CKA_APPLICATION:
                app_val     = (const uint8_t *)pTemplate[i].pValue;
                app_val_len = pTemplate[i].ulValueLen;
                break;
            case CKA_KEY_TYPE:
                if (pTemplate[i].ulValueLen == sizeof(CK_KEY_TYPE))
                    key_type = *(const CK_KEY_TYPE *)pTemplate[i].pValue;
                break;
            case CKA_SENSITIVE:
                if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
                    is_sensitive = *(const CK_BBOOL *)pTemplate[i].pValue;
                break;
            case CKA_EXTRACTABLE:
                if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
                    is_extractable = *(const CK_BBOOL *)pTemplate[i].pValue;
                break;
            case CKA_PRIVATE:
                if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
                    is_private_obj = *(const CK_BBOOL *)pTemplate[i].pValue;
                break;
            case CKA_ENCRYPT: case CKA_DECRYPT:
            case CKA_SIGN:    case CKA_VERIFY:
            case CKA_MODIFIABLE: case CKA_WRAP: case CKA_UNWRAP:
                break; /* accepted, not stored individually for now */
            default:
                break;
            }
        }

        /* wolfP11-p9e5: validate CKA_APPLICATION length before allocating
         * the key slot.  Silently truncating an over-length value would let
         * two objects with distinct application strings collide on the stored
         * identifier, breaking C_FindObjects equality checks.  Checked here
         * (before in_use = 1) so that cleanup needs no slot teardown. */
        if (app_val != NULL &&
            app_val_len > (CK_ULONG)sizeof(g_keys[0].application)) {
            rv = CKR_ATTRIBUTE_VALUE_INVALID;
            goto cleanup;
        }

        /* Find a free slot */
        for (gi = 0; gi < MAX_KEYS; gi++) {
            if (!g_keys[gi].in_use) break;
        }
        if (gi == MAX_KEYS) { rv = CKR_DEVICE_MEMORY; goto cleanup; }

        if (value != NULL && value_len > 0) {
            value_copy = (uint8_t *)malloc(value_len);
            if (value_copy == NULL) { rv = CKR_DEVICE_MEMORY; goto cleanup; }
            memcpy(value_copy, value, (size_t)value_len);
        }

        g_keys[gi].in_use      = 1;
        g_keys[gi].slot_id     = s->slot_id;
        g_keys[gi].obj_class   = obj_class;
        g_keys[gi].is_private  = is_private_obj;
        g_keys[gi].is_token    = is_token_obj;
        g_keys[gi].secret      = value_copy;
        g_keys[gi].secret_len  = (size_t)value_len;
        g_keys[gi].key_priv    = NULL;
        g_keys[gi].backend_ops = NULL;
        strncpy(g_keys[gi].label, label, sizeof(g_keys[gi].label) - 1u);
        g_keys[gi].label[sizeof(g_keys[gi].label) - 1u] = '\0';

        if (obj_class == CKO_SECRET_KEY ||
            obj_class == CKO_PUBLIC_KEY ||
            obj_class == CKO_PRIVATE_KEY) {
            /* Imported key (is_local=false): always_sensitive and
             * never_extractable are always CK_FALSE per PKCS#11 sec.9.8. */
            g_keys[gi].key_type          = key_type;
            g_keys[gi].is_sensitive      = is_sensitive;
            g_keys[gi].is_extractable    = is_extractable;
            g_keys[gi].always_sensitive  = CK_FALSE;
            g_keys[gi].never_extractable = CK_FALSE;
            g_keys[gi].is_local          = CK_FALSE;
            /* CKA_KEY_GEN_MECHANISM is CK_UNAVAILABLE_INFORMATION for
             * imported keys; the C_GetAttributeValue handler returns that
             * when is_local == CK_FALSE. */
        }

#ifdef WOLFP11_CFG_WOLFHSM_BACKEND
        /* wolfHSM private key import: reconstruct the key from PKCS#11
         * attributes, push it to the wolfHSM server, and retain only the
         * server key_id locally.  Raw key material is zeroed and freed after
         * import so it does not persist in the wolfP11 process. */
        if (obj_class == CKO_PRIVATE_KEY &&
            g_slots[s->slot_id].proto == WP11_PROTO_WOLFHSM) {
            wp11_wolfhsm_client_t   *wh;
            whClientContext         *hctx;
            whKeyId                  wh_key_id   = WH_KEYID_ERASED;
            wp11_wolfhsm_key_priv_t *kp          = NULL;
            int                      wh_key_type;
            uint16_t                 wh_key_size;
            CK_ULONG                 sig_max;
            uint16_t                 wh_label_len;
            int                      wret;

            if (!s->logged_in) { rv = CKR_USER_NOT_LOGGED_IN; goto cleanup; }

            wh = (wp11_wolfhsm_client_t *)g_slots[s->slot_id].hsm_client;
            if (wh == NULL) { rv = CKR_DEVICE_ERROR; goto cleanup; }
            hctx = &wh->ctx;

            {
                size_t llen = strlen(g_keys[gi].label);
                wh_label_len = (uint16_t)(llen < (size_t)(WH_NVM_LABEL_LEN - 1u)
                                          ? llen : (size_t)(WH_NVM_LABEL_LEN - 1u));
            }

            if (key_type == CKK_EC) {
                /* EC private key: CKA_EC_PARAMS (DER OID) + CKA_VALUE (scalar) */
                const uint8_t *ec_params     = NULL;
                CK_ULONG       ec_params_len = 0u;
                ecc_key        ekey;
                int            curve_id;

                for (i = 0; i < ulCount; i++) {
                    if (pTemplate[i].pValue != NULL_PTR &&
                        pTemplate[i].type   == CKA_EC_PARAMS) {
                        ec_params     = (const uint8_t *)pTemplate[i].pValue;
                        ec_params_len = pTemplate[i].ulValueLen;
                    }
                }
                /* CKA_EC_PARAMS is DER-encoded OID: tag(0x06) + length + OID */
                if (ec_params == NULL || ec_params_len < 2u ||
                    ec_params[0] != 0x06u) {
                    rv = CKR_TEMPLATE_INCOMPLETE; goto cleanup;
                }
                if (value == NULL || value_len == 0u) {
                    rv = CKR_TEMPLATE_INCOMPLETE; goto cleanup;
                }

                curve_id = wc_ecc_get_curve_id_from_oid(ec_params + 2u,
                                                          (word32)ec_params[1]);
                if (curve_id < 0) { rv = CKR_ATTRIBUTE_VALUE_INVALID; goto cleanup; }

                if (wc_ecc_init(&ekey) != 0) { rv = CKR_DEVICE_ERROR; goto cleanup; }

                /* Import private scalar only (ECC_PRIVATEKEY_ONLY).
                 * wh_Crypto_EccSerializeKeyDer handles this type via
                 * wc_EccPrivateKeyToDer, and the server signs with the scalar
                 * directly -- the public key is not required for signing. */
                wret = wc_ecc_import_private_key_ex(value, (word32)value_len,
                                                     NULL, 0u,
                                                     &ekey, curve_id);
                if (wret == 0) {
                    wret = wh_Client_EccImportKey(hctx, &ekey, &wh_key_id,
                                                   WH_NVM_FLAGS_USAGE_ANY,
                                                   wh_label_len,
                                                   (uint8_t *)g_keys[gi].label);
                }
                wc_ecc_free(&ekey);
                if (wret != 0) { rv = CKR_DEVICE_ERROR; goto cleanup; }

                wh_key_type = WP11_KEY_TYPE_EC;
                wh_key_size = 0u;
                sig_max     = 72u;  /* DER-encoded ECDSA P-256 max */

            } else if (key_type == CKK_RSA) {
                /* RSA private key: parse CRT components from template */
                const uint8_t *rsa_n  = NULL, *rsa_e  = NULL, *rsa_d  = NULL;
                const uint8_t *rsa_p  = NULL, *rsa_q  = NULL;
                const uint8_t *rsa_dp = NULL, *rsa_dq = NULL, *rsa_u  = NULL;
                CK_ULONG rsa_n_len = 0u, rsa_e_len = 0u, rsa_d_len = 0u;
                CK_ULONG rsa_p_len = 0u, rsa_q_len = 0u;
                CK_ULONG rsa_dp_len = 0u, rsa_dq_len = 0u, rsa_u_len = 0u;
                RsaKey   rkey;
                int      sz;

                for (i = 0; i < ulCount; i++) {
                    if (pTemplate[i].pValue == NULL_PTR) continue;
                    switch (pTemplate[i].type) {
                    case CKA_MODULUS:
                        rsa_n     = (const uint8_t *)pTemplate[i].pValue;
                        rsa_n_len = pTemplate[i].ulValueLen; break;
                    case CKA_PUBLIC_EXPONENT:
                        rsa_e     = (const uint8_t *)pTemplate[i].pValue;
                        rsa_e_len = pTemplate[i].ulValueLen; break;
                    case CKA_PRIVATE_EXPONENT:
                        rsa_d     = (const uint8_t *)pTemplate[i].pValue;
                        rsa_d_len = pTemplate[i].ulValueLen; break;
                    case CKA_PRIME_1:
                        rsa_p     = (const uint8_t *)pTemplate[i].pValue;
                        rsa_p_len = pTemplate[i].ulValueLen; break;
                    case CKA_PRIME_2:
                        rsa_q     = (const uint8_t *)pTemplate[i].pValue;
                        rsa_q_len = pTemplate[i].ulValueLen; break;
                    case CKA_EXPONENT_1:
                        rsa_dp    = (const uint8_t *)pTemplate[i].pValue;
                        rsa_dp_len = pTemplate[i].ulValueLen; break;
                    case CKA_EXPONENT_2:
                        rsa_dq    = (const uint8_t *)pTemplate[i].pValue;
                        rsa_dq_len = pTemplate[i].ulValueLen; break;
                    case CKA_COEFFICIENT:
                        rsa_u     = (const uint8_t *)pTemplate[i].pValue;
                        rsa_u_len = pTemplate[i].ulValueLen; break;
                    default: break;
                    }
                }
                if (rsa_n == NULL || rsa_e == NULL || rsa_d == NULL ||
                    rsa_p == NULL || rsa_q == NULL || rsa_dp == NULL ||
                    rsa_dq == NULL || rsa_u == NULL) {
                    rv = CKR_TEMPLATE_INCOMPLETE; goto cleanup;
                }

                if (wc_InitRsaKey(&rkey, NULL) != 0) { rv = CKR_DEVICE_ERROR; goto cleanup; }

                wret = wc_RsaPrivateKeyDecodeRaw(
                    rsa_n,  (word32)rsa_n_len,
                    rsa_e,  (word32)rsa_e_len,
                    rsa_d,  (word32)rsa_d_len,
                    rsa_u,  (word32)rsa_u_len,
                    rsa_p,  (word32)rsa_p_len,
                    rsa_q,  (word32)rsa_q_len,
                    rsa_dp, (word32)rsa_dp_len,
                    rsa_dq, (word32)rsa_dq_len,
                    &rkey);
                sz = (wret == 0) ? wc_RsaEncryptSize(&rkey) : -1;
                if (wret == 0 && sz > 0) {
                    wret = wh_Client_RsaImportKey(hctx, &rkey, &wh_key_id,
                                                   WH_NVM_FLAGS_USAGE_ANY,
                                                   (uint32_t)wh_label_len,
                                                   (uint8_t *)g_keys[gi].label);
                } else if (wret == 0) {
                    wret = -1; /* bad key size */
                }
                wc_FreeRsaKey(&rkey);
                if (wret != 0) { rv = CKR_DEVICE_ERROR; goto cleanup; }

                wh_key_type = WP11_KEY_TYPE_RSA;
                wh_key_size = (uint16_t)sz;
                sig_max     = (CK_ULONG)sz;

            } else {
                rv = CKR_KEY_TYPE_INCONSISTENT;
                goto cleanup;
            }

            kp = wp11_wolfhsm_alloc_key_priv((void *)hctx, (uint16_t)wh_key_id,
                                              wh_key_type, wh_key_size);
            if (kp == NULL) {
                (void)wh_Client_KeyEvict(hctx, wh_key_id);
                rv = CKR_DEVICE_MEMORY; goto cleanup;
            }

            /* Erase local copy of private key material -- key material must
             * not persist in the wolfP11 process; it is held by the server. */
            if (g_keys[gi].secret != NULL) {
                memset(g_keys[gi].secret, 0, g_keys[gi].secret_len);
                free(g_keys[gi].secret);
                g_keys[gi].secret     = NULL;
                g_keys[gi].secret_len = 0u;
            }

            g_keys[gi].key_priv    = kp;
            g_keys[gi].backend_ops = &wp11_backend_wolfhsm_ops;
            g_keys[gi].sig_len_max = sig_max;
            g_keys[gi].id[0]  = (uint8_t)((wh_key_id >> 8) & 0xFFu);
            g_keys[gi].id[1]  = (uint8_t)(wh_key_id & 0xFFu);
            g_keys[gi].id_len = 2u;
        }
#endif /* WOLFP11_CFG_WOLFHSM_BACKEND */

        if (app_val != NULL && app_val_len > 0u) {
            /* Length already validated before slot allocation (wolfP11-p9e5). */
            memcpy(g_keys[gi].application, app_val, (size_t)app_val_len);
            g_keys[gi].application_len = (uint8_t)app_val_len;
        }

        *phObject  = (CK_OBJECT_HANDLE)((CK_ULONG)gi + 1u);
        value_copy = NULL; /* ownership transferred to g_keys[gi].secret */
    }

cleanup:
    free(value_copy);
    WP11_UNLOCK();
    return rv;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                    CK_OBJECT_HANDLE_PTR phNewObject)
{
    CK_RV           rv = CKR_OK;
    CK_ULONG        i;
    int             gi;
    wp11_key_obj_t *src;
    uint8_t        *secret_copy = NULL;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (session_get(hSession) == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }

    src = key_get(hObject);
    if (src == NULL)         { rv = CKR_OBJECT_HANDLE_INVALID; goto cleanup; }
    if (phNewObject == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }
    if (pTemplate == NULL_PTR && ulCount > 0u) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    /* CKA_CLASS is a read-only attribute: cannot be overridden in copy */
    for (i = 0; i < ulCount; i++) {
        if (pTemplate[i].type == CKA_CLASS) { rv = CKR_ATTRIBUTE_READ_ONLY; goto cleanup; }
    }

    /* Only CKO_DATA copy supported */
    if (src->obj_class != CKO_DATA) { rv = CKR_FUNCTION_NOT_SUPPORTED; goto cleanup; }

    /* Find a free key slot for the new object */
    for (gi = 0; gi < MAX_KEYS; gi++) {
        if (!g_keys[gi].in_use) break;
    }
    if (gi == MAX_KEYS) { rv = CKR_DEVICE_MEMORY; goto cleanup; }

    /* Copy the struct (struct copy shares no pointers that need independent
     * lifetimes except secret).  We deep-copy secret below. */
    g_keys[gi] = *src;

    /* Deep-copy the secret (CKA_VALUE) buffer if present */
    if (src->secret != NULL && src->secret_len > 0) {
        secret_copy = (uint8_t *)malloc(src->secret_len);
        if (secret_copy == NULL) {
            memset(&g_keys[gi], 0, sizeof(g_keys[gi]));
            rv = CKR_HOST_MEMORY; goto cleanup;
        }
        memcpy(secret_copy, src->secret, src->secret_len);
        g_keys[gi].secret = secret_copy;
        secret_copy = NULL; /* ownership transferred */
    }

    /* Apply any template overrides to the copy */
    for (i = 0; i < ulCount; i++) {
        if (pTemplate[i].pValue == NULL_PTR) continue;
        switch (pTemplate[i].type) {
        case CKA_LABEL:
            if (pTemplate[i].ulValueLen < sizeof(g_keys[gi].label)) {
                memcpy(g_keys[gi].label, pTemplate[i].pValue,
                       pTemplate[i].ulValueLen);
                g_keys[gi].label[pTemplate[i].ulValueLen] = '\0';
            }
            break;
        case CKA_VALUE: {
            uint8_t *nv = (uint8_t *)malloc(pTemplate[i].ulValueLen);
            if (nv == NULL) {
                free(g_keys[gi].secret);
                memset(&g_keys[gi], 0, sizeof(g_keys[gi]));
                rv = CKR_HOST_MEMORY; goto cleanup;
            }
            free(g_keys[gi].secret);
            memcpy(nv, pTemplate[i].pValue, pTemplate[i].ulValueLen);
            g_keys[gi].secret     = nv;
            g_keys[gi].secret_len = pTemplate[i].ulValueLen;
            break;
        }
        default:
            break;
        }
    }

    *phNewObject = (CK_OBJECT_HANDLE)((CK_ULONG)gi + 1u);

cleanup:
    free(secret_copy);
    WP11_UNLOCK();
    return rv;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    CK_RV           rv = CKR_OK;
    wp11_session_t *s;
    wp11_key_obj_t *obj;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }

    obj = key_get(hObject);
    if (obj == NULL) { rv = CKR_OBJECT_HANDLE_INVALID; goto cleanup; }
    /* PKCS#11 2.40 sec.11.10: objects are scoped to their token; prevent a session
     * on one slot from destroying an object belonging to another slot. */
    if (obj->slot_id != s->slot_id) { rv = CKR_OBJECT_HANDLE_INVALID; goto cleanup; }

    /* wolfP11-be5: backend_ops->free_key_priv is NULL when the backend owns
     * key_priv in bulk (e.g. flash keystore freed by wp11_keystore_free).
     * Only call the destructor when the ops table provides one; otherwise
     * just NULL the pointer to drop the reference without freeing. */
    if (obj->key_priv != NULL &&
        obj->backend_ops != NULL &&
        obj->backend_ops->free_key_priv != NULL) {
        obj->backend_ops->free_key_priv(obj->key_priv);
    }
    obj->key_priv = NULL;   /* safe to zero regardless of key type */

    /* Derived secret keys (CKO_SECRET_KEY) store key material in secret. */
    if (obj->secret != NULL) {
        memset(obj->secret, 0, obj->secret_len);
        free(obj->secret);
        obj->secret = NULL;
    }

    obj->in_use = 0;

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                       CK_ULONG_PTR pulSize)
{
    CK_RV rv = CKR_OK;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (session_get(hSession) == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    if (key_get(hObject) == NULL)      { rv = CKR_OBJECT_HANDLE_INVALID; goto cleanup; }
    if (pulSize == NULL_PTR)           { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    *pulSize = CK_UNAVAILABLE_INFORMATION;

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,
                           CK_OBJECT_HANDLE hObject,
                           CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    /* wolfP11-4fj: 'worst' tracks the most severe per-attribute error seen
     * while iterating.  Per PKCS#11 2.40 sec.11.7, all template entries are
     * processed regardless of per-attribute errors (so partial results for
     * known attributes are still written), and the function returns the worst
     * error encountered.  Priority order (highest to lowest):
     *   CKR_ATTRIBUTE_TYPE_INVALID > CKR_BUFFER_TOO_SMALL > CKR_OK
     *
     * Prior to this fix the function always returned CKR_OK, causing callers
     * (OpenSSL pkcs11 engine, p11-kit) that check only the return code to
     * silently misinterpret "attribute not found" as "attribute returned". */
    CK_RV rv   = CKR_OK;
    CK_RV worst = CKR_OK;
    wp11_key_obj_t *obj;
    CK_ULONG i;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (session_get(hSession) == NULL) {
        rv = CKR_SESSION_HANDLE_INVALID;
        goto cleanup;
    }
    if (pTemplate == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    obj = key_get(hObject);
    if (obj == NULL) { rv = CKR_OBJECT_HANDLE_INVALID; goto cleanup; }

/* Update the 'worst' error tracker for C_GetAttributeValue.
 * Priority (highest first): TYPE_INVALID > ATTRIBUTE_SENSITIVE > BUFFER_TOO_SMALL > OK */
#define UPDATE_WORST(err)                                                  \
    do {                                                                   \
        CK_RV _ue = (err);                                                 \
        if (_ue == CKR_ATTRIBUTE_TYPE_INVALID) {                           \
            worst = CKR_ATTRIBUTE_TYPE_INVALID;                            \
        } else if (_ue == CKR_ATTRIBUTE_SENSITIVE &&                       \
                   worst != CKR_ATTRIBUTE_TYPE_INVALID) {                  \
            worst = CKR_ATTRIBUTE_SENSITIVE;                               \
        } else if (_ue == CKR_BUFFER_TOO_SMALL &&                         \
                   worst != CKR_ATTRIBUTE_TYPE_INVALID &&                  \
                   worst != CKR_ATTRIBUTE_SENSITIVE) {                     \
            worst = CKR_BUFFER_TOO_SMALL;                                  \
        }                                                                  \
    } while (0)

/* COPY_ATTR: copy 'need' bytes from 'src' into pTemplate[i].pValue when the
 * provided buffer is large enough.  Records CKR_BUFFER_TOO_SMALL if pValue
 * is non-NULL but the buffer is smaller than 'need'.  pValue == NULL_PTR is
 * a size-query and never triggers CKR_BUFFER_TOO_SMALL (sec.11.7). */
#define COPY_ATTR(src, need)                                               \
    do {                                                                   \
        CK_ULONG _need = (CK_ULONG)(need);                                 \
        if (pTemplate[i].pValue != NULL_PTR) {                             \
            if (pTemplate[i].ulValueLen >= _need)                          \
                memcpy(pTemplate[i].pValue, (src), _need);                 \
            else                                                           \
                UPDATE_WORST(CKR_BUFFER_TOO_SMALL);                        \
        }                                                                  \
        pTemplate[i].ulValueLen = _need;                                   \
    } while (0)

/* ATTR_NOT_FOUND: attribute does not exist on this object type.
 * Per PKCS#11 sec.11.7 only ulValueLen is set; pValue is left untouched so
 * callers that reuse the CK_ATTRIBUTE struct for a later query are not
 * left with a dangling NULL pointer. */
#define ATTR_NOT_FOUND()                                                   \
    do {                                                                   \
        pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;             \
        UPDATE_WORST(CKR_ATTRIBUTE_TYPE_INVALID);                          \
    } while (0)

/* ATTR_SENSITIVE: attribute exists but is not permitted to be revealed */
#define ATTR_SENSITIVE()                                                   \
    do {                                                                   \
        pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;             \
        UPDATE_WORST(CKR_ATTRIBUTE_SENSITIVE);                             \
    } while (0)

    for (i = 0; i < ulCount; i++) {
        switch (pTemplate[i].type) {
        case CKA_CLASS:
            COPY_ATTR(&obj->obj_class, sizeof(CK_OBJECT_CLASS));
            break;
        case CKA_KEY_TYPE:
            COPY_ATTR(&obj->key_type, sizeof(CK_KEY_TYPE));
            break;
        case CKA_LABEL:
            COPY_ATTR(obj->label, strlen(obj->label));
            break;
        case CKA_ID:
            if (obj->id_len > 0)
                COPY_ATTR(obj->id, obj->id_len);
            else
                ATTR_NOT_FOUND();
            break;
        case CKA_TOKEN:
            COPY_ATTR(&obj->is_token, sizeof(CK_BBOOL));
            break;
        case CKA_PRIVATE:
            COPY_ATTR(&obj->is_private, sizeof(CK_BBOOL));
            break;
        case CKA_APPLICATION:
            if (obj->obj_class == CKO_DATA)
                COPY_ATTR(obj->application, obj->application_len);
            else
                ATTR_NOT_FOUND();
            break;
        case CKA_VALUE:
            /* PKCS#11 sec.9.8: if key is sensitive or non-extractable, the value
             * cannot be revealed.  Only enforce for locally-generated keys
             * (is_local=CK_TRUE); zero-initialised objects from DeriveKey or
             * PIV/flash paths did not set is_extractable and default to
             * extractable. */
            if (obj->is_local && obj->obj_class == CKO_SECRET_KEY &&
                (obj->is_sensitive || !obj->is_extractable)) {
                ATTR_SENSITIVE();
            } else if (obj->cert_der != NULL) {
                COPY_ATTR(obj->cert_der, obj->cert_der_len);
            } else if (obj->secret != NULL) {
                COPY_ATTR(obj->secret, obj->secret_len);
            } else {
                ATTR_NOT_FOUND();
            }
            break;
        case CKA_CERTIFICATE_TYPE:
            if (obj->obj_class == CKO_CERTIFICATE) {
                static const CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
                COPY_ATTR(&cert_type, sizeof(CK_CERTIFICATE_TYPE));
            } else {
                ATTR_NOT_FOUND();
            }
            break;
        case CKA_SENSITIVE:
            COPY_ATTR(&obj->is_sensitive, sizeof(CK_BBOOL));
            break;
        case CKA_EXTRACTABLE:
            COPY_ATTR(&obj->is_extractable, sizeof(CK_BBOOL));
            break;
        case CKA_ALWAYS_SENSITIVE:
            COPY_ATTR(&obj->always_sensitive, sizeof(CK_BBOOL));
            break;
        case CKA_NEVER_EXTRACTABLE:
            COPY_ATTR(&obj->never_extractable, sizeof(CK_BBOOL));
            break;
        case CKA_LOCAL:
            COPY_ATTR(&obj->is_local, sizeof(CK_BBOOL));
            break;
        case CKA_KEY_GEN_MECHANISM: {
            /* CK_UNAVAILABLE_INFORMATION for imported keys (is_local==false) */
            CK_MECHANISM_TYPE mech = obj->is_local
                                   ? obj->key_gen_mech
                                   : CK_UNAVAILABLE_INFORMATION;
            COPY_ATTR(&mech, sizeof(CK_MECHANISM_TYPE));
            break;
        }
        /* RSA public key components -- exported from the soft key */
        case CKA_MODULUS:
        case CKA_PUBLIC_EXPONENT: {
            wp11_soft_key_t *sk = (wp11_soft_key_t *)obj->key_priv;
            if (sk == NULL ||
                (obj->obj_class != CKO_PUBLIC_KEY &&
                 obj->obj_class != CKO_PRIVATE_KEY)) {
                ATTR_NOT_FOUND();
                break;
            }
            {
                uint8_t  nbuf[512];
                uint8_t  ebuf[32];
                word32   nlen = (word32)sizeof(nbuf);
                word32   elen = (word32)sizeof(ebuf);
                if (wp11_soft_key_export_rsa_pub(sk, nbuf, &nlen,
                                                  ebuf, &elen) != 0) {
                    ATTR_NOT_FOUND();
                    break;
                }
                if (pTemplate[i].type == CKA_MODULUS)
                    COPY_ATTR(nbuf, nlen);
                else
                    COPY_ATTR(ebuf, elen);
            }
            break;
        }
        /* RSA private key components -- always sensitive for private keys */
        case CKA_PRIVATE_EXPONENT:
        case CKA_PRIME_1:
        case CKA_PRIME_2:
        case CKA_EXPONENT_1:
        case CKA_EXPONENT_2:
        case CKA_COEFFICIENT:
            if (obj->obj_class == CKO_PRIVATE_KEY) {
                ATTR_SENSITIVE();
            } else {
                ATTR_NOT_FOUND();
            }
            break;
        default:
            /* wolfP11-4fj: attribute type not supported on this object.
             * Clear pValue and mark ulValueLen = CK_UNAVAILABLE_INFORMATION
             * per sec.11.7.  CKR_ATTRIBUTE_TYPE_INVALID outranks all other
             * per-attribute errors in the 'worst' tracking scheme. */
            ATTR_NOT_FOUND();
            break;
        }
    }

#undef COPY_ATTR
#undef ATTR_NOT_FOUND
#undef ATTR_SENSITIVE
#undef UPDATE_WORST

    rv = worst;

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,
                           CK_OBJECT_HANDLE hObject,
                           CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    CK_RV           rv = CKR_OK;
    CK_ULONG        i;
    wp11_key_obj_t *obj;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (session_get(hSession) == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }

    obj = key_get(hObject);
    if (obj == NULL) { rv = CKR_OBJECT_HANDLE_INVALID; goto cleanup; }

    if (pTemplate == NULL_PTR && ulCount > 0u) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    for (i = 0; i < ulCount; i++) {
        if (pTemplate[i].pValue == NULL_PTR) continue;
        switch (pTemplate[i].type) {
        case CKA_CLASS:
        case CKA_KEY_TYPE:
            /* Always read-only per PKCS#11 2.40 sec.9.8 */
            rv = CKR_ATTRIBUTE_READ_ONLY; goto cleanup;

        case CKA_SENSITIVE:
            /* Latching upward: CK_FALSE->CK_TRUE allowed, reverse is not */
            if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
                CK_BBOOL newval = *(const CK_BBOOL *)pTemplate[i].pValue;
                if (obj->is_sensitive && !newval) {
                    rv = CKR_ATTRIBUTE_READ_ONLY; goto cleanup;
                }
                if (newval) obj->is_sensitive = CK_TRUE;
            }
            break;

        case CKA_EXTRACTABLE:
            /* Latching downward: CK_TRUE->CK_FALSE allowed, reverse is not */
            if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
                CK_BBOOL newval = *(const CK_BBOOL *)pTemplate[i].pValue;
                if (!obj->is_extractable && newval) {
                    rv = CKR_ATTRIBUTE_READ_ONLY; goto cleanup;
                }
                if (!newval) {
                    obj->is_extractable  = CK_FALSE;
                    obj->never_extractable = CK_TRUE;
                }
            }
            break;

        case CKA_LABEL:
            /* Allow label to be updated on any object */
            if (pTemplate[i].ulValueLen <= sizeof(obj->label) - 1u) {
                memcpy(obj->label, pTemplate[i].pValue,
                       pTemplate[i].ulValueLen);
                obj->label[pTemplate[i].ulValueLen] = '\0';
            }
            break;

        default:
            break;
        }
    }

cleanup:
    WP11_UNLOCK();
    return rv;
}

/* -------------------------------------------------------------------------
 * Find objects
 * ---------------------------------------------------------------------- */

/* Returns 1 if obj satisfies all template attributes, 0 otherwise.
 * Unknown or unsupported attribute types produce a non-match (0). */
static int key_matches_template(const wp11_key_obj_t   *obj,
                                 const wp11_find_attr_t *tmpl,
                                 CK_ULONG                count)
{
    CK_ULONG i;
    for (i = 0; i < count; i++) {
        switch (tmpl[i].type) {
        case CKA_CLASS:
            if (tmpl[i].len != sizeof(CK_OBJECT_CLASS) ||
                memcmp(&obj->obj_class, tmpl[i].val, tmpl[i].len) != 0)
                return 0;
            break;
        case CKA_KEY_TYPE:
            if (tmpl[i].len != sizeof(CK_KEY_TYPE) ||
                memcmp(&obj->key_type, tmpl[i].val, tmpl[i].len) != 0)
                return 0;
            break;
        case CKA_LABEL: {
            size_t lbl_len = strlen(obj->label);
            if (tmpl[i].len != (CK_ULONG)lbl_len ||
                memcmp(obj->label, tmpl[i].val, lbl_len) != 0)
                return 0;
            break;
        }
        case CKA_ID:
            if (tmpl[i].len != (CK_ULONG)obj->id_len ||
                (obj->id_len > 0 &&
                 memcmp(obj->id, tmpl[i].val, obj->id_len) != 0))
                return 0;
            break;
        case CKA_TOKEN: {
            CK_BBOOL v;
            if (tmpl[i].len != sizeof(CK_BBOOL)) return 0;
            memcpy(&v, tmpl[i].val, sizeof(CK_BBOOL));
            if ((v ? 1 : 0) != (obj->is_token ? 1 : 0)) return 0;
            break;
        }
        case CKA_APPLICATION:
            if (tmpl[i].len != (CK_ULONG)obj->application_len ||
                (obj->application_len > 0 &&
                 memcmp(obj->application, tmpl[i].val,
                        obj->application_len) != 0))
                return 0;
            break;
        default:
            return 0;
        }
    }
    return 1;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession,
                         CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    CK_RV rv = CKR_OK;
    wp11_session_t *s;
    CK_ULONG i;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }

    /* Validate and deep-copy the template before activating find. */
    if (pTemplate != NULL_PTR && ulCount > 0u) {
        if (ulCount > FIND_TMPL_MAX_ATTRS) {
            rv = CKR_ARGUMENTS_BAD;
            goto cleanup;
        }
        for (i = 0; i < ulCount; i++) {
            if (pTemplate[i].pValue == NULL_PTR ||
                pTemplate[i].ulValueLen > FIND_ATTR_MAX_VAL_LEN) {
                rv = CKR_ARGUMENTS_BAD;
                goto cleanup;
            }
            s->find_tmpl[i].type = pTemplate[i].type;
            s->find_tmpl[i].len  = pTemplate[i].ulValueLen;
            memcpy(s->find_tmpl[i].val, pTemplate[i].pValue,
                   pTemplate[i].ulValueLen);
        }
        s->find_tmpl_count = ulCount;
    } else {
        s->find_tmpl_count = 0u;
    }

    s->find_active = 1;
    s->find_pos    = 0;

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
                     CK_OBJECT_HANDLE_PTR phObject,
                     CK_ULONG ulMaxObjectCount,
                     CK_ULONG_PTR pulObjectCount)
{
    CK_RV rv = CKR_OK;
    wp11_session_t *s;
    CK_ULONG found = 0;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (phObject == NULL_PTR || pulObjectCount == NULL_PTR) {
        rv = CKR_ARGUMENTS_BAD;
        goto cleanup;
    }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    if (!s->find_active) { rv = CKR_OPERATION_NOT_INITIALIZED; goto cleanup; }

    while (s->find_pos < MAX_KEYS && found < ulMaxObjectCount) {
        CK_ULONG idx = s->find_pos;
        s->find_pos++;
        if (g_keys[idx].in_use && g_keys[idx].slot_id == s->slot_id &&
            key_matches_template(&g_keys[idx],
                                 s->find_tmpl, s->find_tmpl_count)) {
            phObject[found] = (CK_OBJECT_HANDLE)(idx + 1);
            found++;
        }
    }

    *pulObjectCount = found;

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    CK_RV rv = CKR_OK;
    wp11_session_t *s;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    if (!s->find_active) { rv = CKR_OPERATION_NOT_INITIALIZED; goto cleanup; }

    s->find_active     = 0;
    s->find_tmpl_count = 0u;

cleanup:
    WP11_UNLOCK();
    return rv;
}

/* -------------------------------------------------------------------------
 * Encrypt -- AES-ECB/CBC, DES-ECB/CBC, 3DES-ECB/CBC
 * ---------------------------------------------------------------------- */

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                     CK_OBJECT_HANDLE hKey)
{
    CK_RV           rv = CKR_OK;
    wp11_session_t *s  = NULL;
    wp11_key_obj_t *obj;
    CK_KEY_TYPE     req_kt;
    const uint8_t  *iv;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (pMechanism == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }

    /* Reject double-init */
    if (s->encrypt_active) { rv = CKR_OPERATION_ACTIVE; goto cleanup; }

    obj = key_get(hKey);
    if (obj == NULL) { rv = CKR_KEY_HANDLE_INVALID; goto cleanup; }
    if (!s->logged_in && obj->is_private) { rv = CKR_USER_NOT_LOGGED_IN; goto cleanup; }

    if (pMechanism->mechanism == CKM_RSA_PKCS) {
        /* RSA PKCS#1 v1.5 public-key encryption */
        if (obj->key_type != CKK_RSA) { rv = CKR_KEY_TYPE_INCONSISTENT; goto cleanup; }
        rv = validate_mechanism_params(pMechanism);
        if (rv != CKR_OK) goto cleanup;
        /* no symmetric context setup needed -- RSA encrypt is oneshot via key_priv */
        s->encrypt_active    = 1;
        s->encrypt_oneshot   = 0;
        s->encrypt_multipart = 0;
        s->encrypt_mech      = pMechanism->mechanism;
        s->encrypt_key       = hKey;
        goto cleanup;
    }

    /* Mechanism validity and key-type consistency check */
    req_kt = mech_required_key_type(pMechanism->mechanism);
    if (req_kt == (CK_KEY_TYPE)-1) {
        /* Mechanism is not a symmetric cipher mechanism.
         * Check if it's a known asymmetric mechanism used with a symmetric
         * key -> CKR_KEY_TYPE_INCONSISTENT; otherwise CKR_MECHANISM_INVALID. */
        if (pMechanism->mechanism == CKM_ECDSA ||
            pMechanism->mechanism == CKM_ECDSA_SHA256) {
            rv = CKR_KEY_TYPE_INCONSISTENT;
        } else {
            rv = CKR_MECHANISM_INVALID;
        }
        goto cleanup;
    }
    if (obj->key_type != req_kt) { rv = CKR_KEY_TYPE_INCONSISTENT; goto cleanup; }

    /* For CBC modes, validate IV parameter */
    iv = NULL;
    if (mech_has_iv(pMechanism->mechanism)) {
        CK_ULONG blksz = mech_block_size(pMechanism->mechanism);
        if (pMechanism->pParameter == NULL_PTR ||
            pMechanism->ulParameterLen != blksz) {
            rv = CKR_MECHANISM_PARAM_INVALID;
            goto cleanup;
        }
        iv = (const uint8_t *)pMechanism->pParameter;
    }

    /* Key material must be present */
    if (obj->secret == NULL || obj->secret_len == 0) {
        rv = CKR_KEY_HANDLE_INVALID;
        goto cleanup;
    }

    /* Initialize wolfCrypt encryption context */
    switch (pMechanism->mechanism) {
    case CKM_AES_ECB:
        wc_AesInit(&s->enc_ctx.aes, NULL, INVALID_DEVID);
        if (wc_AesSetKey(&s->enc_ctx.aes, obj->secret, (word32)obj->secret_len,
                         NULL, AES_ENCRYPTION) != 0) {
            wc_AesFree(&s->enc_ctx.aes);
            rv = CKR_KEY_SIZE_RANGE;
            goto cleanup;
        }
        break;
    case CKM_AES_CBC:
        wc_AesInit(&s->enc_ctx.aes, NULL, INVALID_DEVID);
        if (wc_AesSetKey(&s->enc_ctx.aes, obj->secret, (word32)obj->secret_len,
                         iv, AES_ENCRYPTION) != 0) {
            wc_AesFree(&s->enc_ctx.aes);
            rv = CKR_KEY_SIZE_RANGE;
            goto cleanup;
        }
        break;
    case CKM_DES_ECB:
        wc_Des_SetKey(&s->enc_ctx.des, obj->secret, NULL, DES_ENCRYPTION);
        break;
    case CKM_DES_CBC:
        wc_Des_SetKey(&s->enc_ctx.des, obj->secret, iv, DES_ENCRYPTION);
        break;
    case CKM_DES3_ECB:
        wc_Des3Init(&s->enc_ctx.des3, NULL, INVALID_DEVID);
        wc_Des3_SetKey(&s->enc_ctx.des3, obj->secret, NULL, DES_ENCRYPTION);
        break;
    case CKM_DES3_CBC:
        wc_Des3Init(&s->enc_ctx.des3, NULL, INVALID_DEVID);
        wc_Des3_SetKey(&s->enc_ctx.des3, obj->secret, iv, DES_ENCRYPTION);
        break;
    default:
        rv = CKR_MECHANISM_INVALID;
        goto cleanup;
    }

    s->encrypt_active    = 1;
    s->encrypt_oneshot   = 0;
    s->encrypt_multipart = 0;
    s->encrypt_mech      = pMechanism->mechanism;
    s->encrypt_key       = hKey;

cleanup:
    if (rv != CKR_OK && rv != CKR_OPERATION_ACTIVE && s != NULL)
        s->encrypt_active = 0;
    WP11_UNLOCK();
    return rv;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                 CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
                 CK_ULONG_PTR pulEncryptedDataLen)
{
    CK_RV           rv = CKR_OK;
    wp11_session_t *s;
    CK_ULONG        blksz;
    int             ret;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    if (!s->encrypt_active) { rv = CKR_OPERATION_NOT_INITIALIZED; goto cleanup; }

    /* Mode policing: multi-part mode already started (terminates) */
    if (s->encrypt_multipart) {
        s->encrypt_active = 0;
        rv = CKR_OPERATION_ACTIVE;
        goto cleanup;
    }

    /* Validate required args (after session lookup so we can terminate) */
    if (pData == NULL_PTR || pulEncryptedDataLen == NULL_PTR) {
        s->encrypt_active = 0;
        rv = CKR_ARGUMENTS_BAD;
        goto cleanup;
    }

    /* RSA PKCS#1 v1.5 public-key encryption path */
    if (s->encrypt_mech == CKM_RSA_PKCS) {
        wp11_key_obj_t *eobj = key_get(s->encrypt_key);
        wp11_soft_key_t *skey;
        word32 outw;

        if (eobj == NULL || eobj->key_priv == NULL) {
            s->encrypt_active = 0;
            rv = CKR_KEY_HANDLE_INVALID;
            goto cleanup;
        }
        skey = (wp11_soft_key_t *)eobj->key_priv;

        if (pEncryptedData == NULL_PTR) {
            /* Size query */
            if (wp11_soft_key_rsa_encrypt(skey, NULL, 0, NULL, &outw) != 0) {
                s->encrypt_active = 0;
                rv = CKR_FUNCTION_FAILED;
                goto cleanup;
            }
            *pulEncryptedDataLen = (CK_ULONG)outw;
            s->encrypt_oneshot = 1;
            goto cleanup;
        }

        outw = (word32)*pulEncryptedDataLen;
        if (wp11_soft_key_rsa_encrypt(skey,
                                       pData, (word32)ulDataLen,
                                       pEncryptedData, &outw) != 0) {
            s->encrypt_active = 0;
            rv = CKR_FUNCTION_FAILED;
            goto cleanup;
        }
        *pulEncryptedDataLen = (CK_ULONG)outw;
        s->encrypt_active    = 0;
        s->encrypt_oneshot   = 0;
        s->encrypt_multipart = 0;
        goto cleanup;
    }

    blksz = mech_block_size(s->encrypt_mech);
    if (blksz > 0 && (ulDataLen % blksz) != 0) {
        rv = CKR_DATA_LEN_RANGE;
        s->encrypt_active = 0;
        goto cleanup;
    }

    if (pEncryptedData == NULL_PTR) {
        /* Size query: mark oneshot mode, return required length */
        *pulEncryptedDataLen = ulDataLen;
        s->encrypt_oneshot = 1;
        goto cleanup; /* operation remains active */
    }

    if (*pulEncryptedDataLen < ulDataLen) {
        *pulEncryptedDataLen = ulDataLen;
        rv = CKR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    /* Perform single-shot encryption */
    ret = 0;
    switch (s->encrypt_mech) {
    case CKM_AES_ECB:
        ret = wc_AesEcbEncrypt(&s->enc_ctx.aes, pEncryptedData,
                               pData, (word32)ulDataLen);
        break;
    case CKM_AES_CBC:
        ret = wc_AesCbcEncrypt(&s->enc_ctx.aes, pEncryptedData,
                               pData, (word32)ulDataLen);
        break;
    case CKM_DES_ECB:
        ret = wc_Des_EcbEncrypt(&s->enc_ctx.des, pEncryptedData,
                                pData, (word32)ulDataLen);
        break;
    case CKM_DES_CBC:
        ret = wc_Des_CbcEncrypt(&s->enc_ctx.des, pEncryptedData,
                                pData, (word32)ulDataLen);
        break;
    case CKM_DES3_ECB:
        ret = wc_Des3_EcbEncrypt(&s->enc_ctx.des3, pEncryptedData,
                                  pData, (word32)ulDataLen);
        break;
    case CKM_DES3_CBC:
        ret = wc_Des3_CbcEncrypt(&s->enc_ctx.des3, pEncryptedData,
                                  pData, (word32)ulDataLen);
        break;
    default:
        rv = CKR_MECHANISM_INVALID;
        s->encrypt_active = 0;
        goto cleanup;
    }

    if (ret != 0) {
        rv = CKR_FUNCTION_FAILED;
        s->encrypt_active = 0;
        goto cleanup;
    }

    *pulEncryptedDataLen = ulDataLen;
    s->encrypt_active    = 0;
    s->encrypt_oneshot   = 0;
    s->encrypt_multipart = 0;

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                       CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                       CK_ULONG_PTR pulEncryptedPartLen)
{
    CK_RV           rv = CKR_OK;
    wp11_session_t *s;
    CK_ULONG        blksz;
    int             ret;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    if (!s->encrypt_active) { rv = CKR_OPERATION_NOT_INITIALIZED; goto cleanup; }

    /* Mode policing: single-shot mode already started (terminates) */
    if (s->encrypt_oneshot) {
        s->encrypt_active = 0;
        rv = CKR_OPERATION_ACTIVE;
        goto cleanup;
    }

    /* Validate required args after session lookup so we can terminate */
    if (pPart == NULL_PTR || pulEncryptedPartLen == NULL_PTR) {
        s->encrypt_active = 0;
        rv = CKR_ARGUMENTS_BAD;
        goto cleanup;
    }

    blksz = mech_block_size(s->encrypt_mech);
    if (blksz > 0 && (ulPartLen % blksz) != 0) {
        rv = CKR_DATA_LEN_RANGE;
        s->encrypt_active = 0;
        goto cleanup;
    }

    if (pEncryptedPart == NULL_PTR) {
        rv = CKR_ARGUMENTS_BAD;
        s->encrypt_active = 0;
        goto cleanup;
    }

    if (*pulEncryptedPartLen < ulPartLen) {
        *pulEncryptedPartLen = ulPartLen;
        rv = CKR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    ret = 0;
    switch (s->encrypt_mech) {
    case CKM_AES_ECB:
        ret = wc_AesEcbEncrypt(&s->enc_ctx.aes, pEncryptedPart,
                               pPart, (word32)ulPartLen);
        break;
    case CKM_AES_CBC:
        ret = wc_AesCbcEncrypt(&s->enc_ctx.aes, pEncryptedPart,
                               pPart, (word32)ulPartLen);
        break;
    case CKM_DES_ECB:
        ret = wc_Des_EcbEncrypt(&s->enc_ctx.des, pEncryptedPart,
                                pPart, (word32)ulPartLen);
        break;
    case CKM_DES_CBC:
        ret = wc_Des_CbcEncrypt(&s->enc_ctx.des, pEncryptedPart,
                                pPart, (word32)ulPartLen);
        break;
    case CKM_DES3_ECB:
        ret = wc_Des3_EcbEncrypt(&s->enc_ctx.des3, pEncryptedPart,
                                  pPart, (word32)ulPartLen);
        break;
    case CKM_DES3_CBC:
        ret = wc_Des3_CbcEncrypt(&s->enc_ctx.des3, pEncryptedPart,
                                  pPart, (word32)ulPartLen);
        break;
    default:
        rv = CKR_MECHANISM_INVALID;
        s->encrypt_active = 0;
        goto cleanup;
    }

    if (ret != 0) {
        rv = CKR_FUNCTION_FAILED;
        s->encrypt_active = 0;
        goto cleanup;
    }

    *pulEncryptedPartLen = ulPartLen;
    s->encrypt_multipart = 1;

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pLastEncryptedPart,
                      CK_ULONG_PTR pulLastEncryptedPartLen)
{
    CK_RV           rv = CKR_OK;
    wp11_session_t *s  = NULL; /* init for cleanup guard (wolfP11-v3c -O2) */

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (pLastEncryptedPart == NULL_PTR || pulLastEncryptedPartLen == NULL_PTR) {
        rv = CKR_ARGUMENTS_BAD;
        goto cleanup;
    }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    if (!s->encrypt_active) { rv = CKR_OPERATION_NOT_INITIALIZED; goto cleanup; }

    /* No padding for these modes -- zero bytes in final block */
    *pulLastEncryptedPartLen = 0;
    s->encrypt_active    = 0;
    s->encrypt_oneshot   = 0;
    s->encrypt_multipart = 0;

cleanup:
    if (rv != CKR_OK && rv != CKR_SESSION_HANDLE_INVALID) {
        /* On error, terminate the operation (PKCS#11 sec.11.13) */
        if (s != NULL) s->encrypt_active = 0;
    }
    WP11_UNLOCK();
    return rv;
}

/* Validate pMechanism->pParameter before any mechanism-specific struct cast.
 * NULL with non-zero ulParameterLen or non-NULL with zero ulParameterLen are
 * both invalid per PKCS#11 sec.11.1.  All currently supported mechanisms take no
 * parameter; if any parameter bytes are present, reject with
 * CKR_MECHANISM_PARAM_INVALID so callers that extend this list cannot
 * dereference an unchecked pParameter pointer. */
static CK_RV validate_mechanism_params(CK_MECHANISM_PTR mech)
{
    /* pParameter/ulParameterLen consistency */
    if (mech->pParameter == NULL_PTR && mech->ulParameterLen != 0u)
        return CKR_MECHANISM_PARAM_INVALID;
    if (mech->pParameter != NULL_PTR && mech->ulParameterLen == 0u)
        return CKR_MECHANISM_PARAM_INVALID;
    /* No currently-supported mechanism takes parameters */
    if (mech->ulParameterLen != 0u)
        return CKR_MECHANISM_PARAM_INVALID;
    return CKR_OK;
}

/* Map a WP11_BACKEND_ERR_* code to a CK_RV for sign/decrypt/derive paths.
 * Verify has its own mapping because WP11_BACKEND_ERR_GENERAL should be
 * CKR_SIGNATURE_INVALID on the verify path. */
static CK_RV backend_err_to_rv(int err)
{
    switch (err) {
    case WP11_BACKEND_ERR_NOT_READY:     /* FALLTHROUGH */
    case WP11_BACKEND_ERR_TIMEOUT:       return CKR_DEVICE_ERROR;
    case WP11_BACKEND_ERR_KEY_NOT_FOUND: return CKR_KEY_HANDLE_INVALID;
    case WP11_BACKEND_ERR_USAGE:         return CKR_ACTION_PROHIBITED;
    case WP11_BACKEND_ERR_NOT_IMPL:      return CKR_MECHANISM_INVALID;
    case WP11_BACKEND_ERR_SIG_INVALID:   return CKR_SIGNATURE_INVALID;
    default:                              return CKR_FUNCTION_FAILED;
    }
}

/* -------------------------------------------------------------------------
 * Decrypt
 * ---------------------------------------------------------------------- */

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                     CK_OBJECT_HANDLE hKey)
{
    CK_RV rv = CKR_OK;
    wp11_session_t *s = NULL;
    wp11_key_obj_t *obj;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (pMechanism == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }

    obj = key_get(hKey);
    if (obj == NULL) { rv = CKR_KEY_HANDLE_INVALID; goto cleanup; }
    if (obj->obj_class == CKO_CERTIFICATE) { rv = CKR_KEY_HANDLE_INVALID; goto cleanup; }

    /* Login required only for private objects (CKA_PRIVATE=true). */
    if (!s->logged_in && obj->is_private) {
        rv = CKR_USER_NOT_LOGGED_IN; goto cleanup;
    }

    /* Reject double-init */
    if (s->decrypt_active) { rv = CKR_OPERATION_ACTIVE; goto cleanup; }

    {
        CK_KEY_TYPE req_kt = mech_required_key_type(pMechanism->mechanism);
        if (req_kt != (CK_KEY_TYPE)-1) {
            /* Symmetric cipher */
            if (obj->key_type != req_kt) { rv = CKR_KEY_TYPE_INCONSISTENT; goto cleanup; }
            if (obj->secret == NULL || obj->secret_len == 0) {
                rv = CKR_KEY_HANDLE_INVALID; goto cleanup;
            }

            /* For CBC modes, validate IV */
            if (mech_has_iv(pMechanism->mechanism)) {
                CK_ULONG blksz = mech_block_size(pMechanism->mechanism);
                if (pMechanism->pParameter == NULL_PTR ||
                    pMechanism->ulParameterLen != blksz) {
                    rv = CKR_MECHANISM_PARAM_INVALID; goto cleanup;
                }
            }

            /* Initialize wolfCrypt decryption context */
            {
                const uint8_t *iv = mech_has_iv(pMechanism->mechanism)
                                    ? (const uint8_t *)pMechanism->pParameter
                                    : NULL;
                switch (pMechanism->mechanism) {
                case CKM_AES_ECB:
                    wc_AesInit(&s->dec_ctx.aes, NULL, INVALID_DEVID);
                    if (wc_AesSetKey(&s->dec_ctx.aes, obj->secret,
                                     (word32)obj->secret_len,
                                     NULL, AES_DECRYPTION) != 0) {
                        wc_AesFree(&s->dec_ctx.aes);
                        rv = CKR_KEY_SIZE_RANGE; goto cleanup;
                    }
                    break;
                case CKM_AES_CBC:
                    wc_AesInit(&s->dec_ctx.aes, NULL, INVALID_DEVID);
                    if (wc_AesSetKey(&s->dec_ctx.aes, obj->secret,
                                     (word32)obj->secret_len,
                                     iv, AES_DECRYPTION) != 0) {
                        wc_AesFree(&s->dec_ctx.aes);
                        rv = CKR_KEY_SIZE_RANGE; goto cleanup;
                    }
                    break;
                case CKM_DES_ECB:
                    wc_Des_SetKey(&s->dec_ctx.des, obj->secret, NULL, DES_DECRYPTION);
                    break;
                case CKM_DES_CBC:
                    wc_Des_SetKey(&s->dec_ctx.des, obj->secret, iv, DES_DECRYPTION);
                    break;
                case CKM_DES3_ECB:
                    wc_Des3Init(&s->dec_ctx.des3, NULL, INVALID_DEVID);
                    wc_Des3_SetKey(&s->dec_ctx.des3, obj->secret, NULL, DES_DECRYPTION);
                    break;
                case CKM_DES3_CBC:
                    wc_Des3Init(&s->dec_ctx.des3, NULL, INVALID_DEVID);
                    wc_Des3_SetKey(&s->dec_ctx.des3, obj->secret, iv, DES_DECRYPTION);
                    break;
                default:
                    rv = CKR_MECHANISM_INVALID; goto cleanup;
                }
            }
        } else if (pMechanism->mechanism == CKM_RSA_PKCS) {
            /* RSA path: check key type, then validate mechanism params */
            if (obj->key_type != CKK_RSA) { rv = CKR_KEY_TYPE_INCONSISTENT; goto cleanup; }
            rv = validate_mechanism_params(pMechanism);
            if (rv != CKR_OK) goto cleanup;
        } else {
            /* Check key-type inconsistency for known mechanisms */
            if (pMechanism->mechanism == CKM_ECDSA ||
                pMechanism->mechanism == CKM_ECDSA_SHA256) {
                rv = CKR_KEY_TYPE_INCONSISTENT;
            } else {
                rv = CKR_MECHANISM_INVALID;
            }
            goto cleanup;
        }
    }

    s->decrypt_active    = 1;
    s->decrypt_oneshot   = 0;
    s->decrypt_multipart = 0;
    s->decrypt_mech      = pMechanism->mechanism;
    s->decrypt_key       = hKey;

cleanup:
    if (rv != CKR_OK && rv != CKR_OPERATION_ACTIVE && s != NULL)
        s->decrypt_active = 0;
    WP11_UNLOCK();
    return rv;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
                 CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                 CK_ULONG_PTR pulDataLen)
{
    CK_RV             rv = CKR_OK;
    wp11_session_t   *s;
    wp11_key_obj_t   *obj;
    wp11_key_handle_t kh;
    size_t            outlen;
    int               ret;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    if (!s->decrypt_active) {
        rv = CKR_OPERATION_NOT_INITIALIZED;
        goto cleanup;
    }

    /* Validate required args after session lookup so we can terminate */
    if (pEncryptedData == NULL_PTR || pulDataLen == NULL_PTR) {
        s->decrypt_active = 0;
        rv = CKR_ARGUMENTS_BAD;
        goto cleanup;
    }

    obj = key_get(s->decrypt_key);
    if (obj == NULL) {
        s->decrypt_active = 0;
        rv = CKR_KEY_HANDLE_INVALID;
        goto cleanup;
    }

    /* Mode policing: multi-part already started (terminates) */
    if (s->decrypt_multipart) {
        s->decrypt_active = 0;
        rv = CKR_OPERATION_ACTIVE;
        goto cleanup;
    }

    if (pData == NULL_PTR) {
        /* Size query: return required length without advancing state */
        *pulDataLen = ulEncryptedDataLen;
        s->decrypt_oneshot = 1;
        goto cleanup; /* operation remains active */
    }

    /* Dispatch: symmetric key (backend_ops == NULL) or asymmetric (RSA via backend) */
    if (obj->backend_ops == NULL) {
        /* Symmetric path */
        CK_ULONG blksz = mech_block_size(s->decrypt_mech);
        if (blksz > 0 && (ulEncryptedDataLen % blksz) != 0) {
            rv = CKR_ENCRYPTED_DATA_LEN_RANGE;
            s->decrypt_active = 0;
            goto cleanup;
        }
        if (*pulDataLen < ulEncryptedDataLen) {
            *pulDataLen = ulEncryptedDataLen;
            rv = CKR_BUFFER_TOO_SMALL;
            goto cleanup;
        }
        ret = 0;
        switch (s->decrypt_mech) {
        case CKM_AES_ECB:
            ret = wc_AesEcbDecrypt(&s->dec_ctx.aes, pData,
                                   pEncryptedData, (word32)ulEncryptedDataLen);
            break;
        case CKM_AES_CBC:
            ret = wc_AesCbcDecrypt(&s->dec_ctx.aes, pData,
                                   pEncryptedData, (word32)ulEncryptedDataLen);
            break;
        case CKM_DES_ECB:
            ret = wc_Des_EcbDecrypt(&s->dec_ctx.des, pData,
                                    pEncryptedData, (word32)ulEncryptedDataLen);
            break;
        case CKM_DES_CBC:
            ret = wc_Des_CbcDecrypt(&s->dec_ctx.des, pData,
                                    pEncryptedData, (word32)ulEncryptedDataLen);
            break;
        case CKM_DES3_ECB:
            ret = wc_Des3_EcbDecrypt(&s->dec_ctx.des3, pData,
                                      pEncryptedData, (word32)ulEncryptedDataLen);
            break;
        case CKM_DES3_CBC:
            ret = wc_Des3_CbcDecrypt(&s->dec_ctx.des3, pData,
                                      pEncryptedData, (word32)ulEncryptedDataLen);
            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            s->decrypt_active = 0;
            goto cleanup;
        }
        if (ret != 0) {
            rv = CKR_FUNCTION_FAILED;
            s->decrypt_active = 0;
            goto cleanup;
        }
        *pulDataLen = ulEncryptedDataLen;
        s->decrypt_active    = 0;
        s->decrypt_oneshot   = 0;
        s->decrypt_multipart = 0;
    } else {
        /* Asymmetric path (RSA) -- dispatch through backend ops */
        outlen = (size_t)*pulDataLen;

        memset(&kh, 0, sizeof(kh));
        kh.backend = obj->backend_ops->type;
        kh.priv    = obj->key_priv;

        ret = obj->backend_ops->decrypt(&kh,
                                        (uint32_t)s->decrypt_mech,
                                        pEncryptedData,
                                        (size_t)ulEncryptedDataLen,
                                        pData, &outlen);
        s->decrypt_active = 0;
        if (ret != 0) {
            rv = backend_err_to_rv(ret);
            goto cleanup;
        }
        *pulDataLen = (CK_ULONG)outlen;
    }

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                       CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                       CK_ULONG_PTR pulPartLen)
{
    CK_RV           rv = CKR_OK;
    wp11_session_t *s;
    CK_ULONG        blksz;
    int             ret;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    if (!s->decrypt_active) { rv = CKR_OPERATION_NOT_INITIALIZED; goto cleanup; }

    /* Mode policing: single-shot mode already started (terminates) */
    if (s->decrypt_oneshot) {
        s->decrypt_active = 0;
        rv = CKR_OPERATION_ACTIVE;
        goto cleanup;
    }

    /* Validate required args after session lookup so we can terminate */
    if (pEncryptedPart == NULL_PTR || pulPartLen == NULL_PTR) {
        s->decrypt_active = 0;
        rv = CKR_ARGUMENTS_BAD;
        goto cleanup;
    }

    blksz = mech_block_size(s->decrypt_mech);
    if (blksz > 0 && (ulEncryptedPartLen % blksz) != 0) {
        rv = CKR_DATA_LEN_RANGE;
        s->decrypt_active = 0;
        goto cleanup;
    }

    if (pPart == NULL_PTR) {
        rv = CKR_ARGUMENTS_BAD;
        s->decrypt_active = 0;
        goto cleanup;
    }

    if (*pulPartLen < ulEncryptedPartLen) {
        *pulPartLen = ulEncryptedPartLen;
        rv = CKR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    ret = 0;
    switch (s->decrypt_mech) {
    case CKM_AES_ECB:
        ret = wc_AesEcbDecrypt(&s->dec_ctx.aes, pPart,
                               pEncryptedPart, (word32)ulEncryptedPartLen);
        break;
    case CKM_AES_CBC:
        ret = wc_AesCbcDecrypt(&s->dec_ctx.aes, pPart,
                               pEncryptedPart, (word32)ulEncryptedPartLen);
        break;
    case CKM_DES_ECB:
        ret = wc_Des_EcbDecrypt(&s->dec_ctx.des, pPart,
                                pEncryptedPart, (word32)ulEncryptedPartLen);
        break;
    case CKM_DES_CBC:
        ret = wc_Des_CbcDecrypt(&s->dec_ctx.des, pPart,
                                pEncryptedPart, (word32)ulEncryptedPartLen);
        break;
    case CKM_DES3_ECB:
        ret = wc_Des3_EcbDecrypt(&s->dec_ctx.des3, pPart,
                                  pEncryptedPart, (word32)ulEncryptedPartLen);
        break;
    case CKM_DES3_CBC:
        ret = wc_Des3_CbcDecrypt(&s->dec_ctx.des3, pPart,
                                  pEncryptedPart, (word32)ulEncryptedPartLen);
        break;
    default:
        rv = CKR_MECHANISM_INVALID;
        s->decrypt_active = 0;
        goto cleanup;
    }

    if (ret != 0) {
        rv = CKR_FUNCTION_FAILED;
        s->decrypt_active = 0;
        goto cleanup;
    }

    *pulPartLen = ulEncryptedPartLen;
    s->decrypt_multipart = 1;

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
                      CK_ULONG_PTR pulLastPartLen)
{
    CK_RV           rv = CKR_OK;
    wp11_session_t *s  = NULL; /* init for cleanup guard (wolfP11-v3c -O2) */

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (pLastPart == NULL_PTR || pulLastPartLen == NULL_PTR) {
        rv = CKR_ARGUMENTS_BAD;
        goto cleanup;
    }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    if (!s->decrypt_active) { rv = CKR_OPERATION_NOT_INITIALIZED; goto cleanup; }

    *pulLastPartLen = 0;
    s->decrypt_active    = 0;
    s->decrypt_oneshot   = 0;
    s->decrypt_multipart = 0;

cleanup:
    if (rv != CKR_OK && rv != CKR_SESSION_HANDLE_INVALID) {
        if (s != NULL) s->decrypt_active = 0;
    }
    WP11_UNLOCK();
    return rv;
}

/* -------------------------------------------------------------------------
 * Digest -- MD5, SHA-1, SHA-256, SHA-384, SHA-512
 * ---------------------------------------------------------------------- */

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    CK_RV           rv = CKR_OK;
    wp11_session_t *s  = NULL;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (pMechanism == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }

    if (s->digest_active) { rv = CKR_OPERATION_ACTIVE; goto cleanup; }

    switch (pMechanism->mechanism) {
    case CKM_MD5:
        wc_InitMd5(&s->dig_ctx.md5);
        break;
    case CKM_SHA_1:
        wc_InitSha(&s->dig_ctx.sha);
        break;
    case CKM_SHA256:
        wc_InitSha256(&s->dig_ctx.sha256);
        break;
    case CKM_SHA384:
        wc_InitSha384(&s->dig_ctx.sha384);
        break;
    case CKM_SHA512:
        wc_InitSha512(&s->dig_ctx.sha512);
        break;
    default:
        rv = CKR_MECHANISM_INVALID;
        goto cleanup;
    }

    s->digest_active    = 1;
    s->digest_oneshot   = 0;
    s->digest_multipart = 0;
    s->digest_mech      = pMechanism->mechanism;

cleanup:
    if (rv != CKR_OK && rv != CKR_OPERATION_ACTIVE && s != NULL)
        s->digest_active = 0;
    WP11_UNLOCK();
    return rv;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
                CK_ULONG_PTR pulDigestLen)
{
    CK_RV           rv = CKR_OK;
    wp11_session_t *s;
    CK_ULONG        out_size;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    if (!s->digest_active) { rv = CKR_OPERATION_NOT_INITIALIZED; goto cleanup; }

    /* Mode policing: multipart already started; Digest is not allowed (terminates) */
    if (s->digest_multipart) {
        s->digest_active    = 0;
        s->digest_multipart = 0;
        s->digest_oneshot   = 0;
        rv = CKR_OPERATION_ACTIVE;
        goto cleanup;
    }

    /* Validate required args after session lookup so we can terminate */
    if (pData == NULL_PTR || pulDigestLen == NULL_PTR) {
        s->digest_active = 0;
        rv = CKR_ARGUMENTS_BAD;
        goto cleanup;
    }

    out_size = mech_digest_output_size(s->digest_mech);

    if (pDigest == NULL_PTR) {
        /* Size query: return required length, mark oneshot, stay active */
        *pulDigestLen     = out_size;
        s->digest_oneshot = 1;
        goto cleanup;
    }

    if (*pulDigestLen < out_size) {
        *pulDigestLen = out_size;
        rv = CKR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    /* Feed data then finalize */
    switch (s->digest_mech) {
    case CKM_MD5:
        wc_Md5Update(&s->dig_ctx.md5, pData, (word32)ulDataLen);
        wc_Md5Final(&s->dig_ctx.md5, pDigest);
        break;
    case CKM_SHA_1:
        wc_ShaUpdate(&s->dig_ctx.sha, pData, (word32)ulDataLen);
        wc_ShaFinal(&s->dig_ctx.sha, pDigest);
        break;
    case CKM_SHA256:
        wc_Sha256Update(&s->dig_ctx.sha256, pData, (word32)ulDataLen);
        wc_Sha256Final(&s->dig_ctx.sha256, pDigest);
        break;
    case CKM_SHA384:
        wc_Sha384Update(&s->dig_ctx.sha384, pData, (word32)ulDataLen);
        wc_Sha384Final(&s->dig_ctx.sha384, pDigest);
        break;
    case CKM_SHA512:
        wc_Sha512Update(&s->dig_ctx.sha512, pData, (word32)ulDataLen);
        wc_Sha512Final(&s->dig_ctx.sha512, pDigest);
        break;
    default:
        rv = CKR_MECHANISM_INVALID;
        s->digest_active = 0;
        goto cleanup;
    }

    *pulDigestLen       = out_size;
    s->digest_active    = 0;
    s->digest_oneshot   = 0;
    s->digest_multipart = 0;

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                      CK_ULONG ulPartLen)
{
    CK_RV           rv = CKR_OK;
    wp11_session_t *s;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (pPart == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    if (!s->digest_active) { rv = CKR_OPERATION_NOT_INITIALIZED; goto cleanup; }

    switch (s->digest_mech) {
    case CKM_MD5:    wc_Md5Update(&s->dig_ctx.md5, pPart, (word32)ulPartLen);       break;
    case CKM_SHA_1:  wc_ShaUpdate(&s->dig_ctx.sha, pPart, (word32)ulPartLen);       break;
    case CKM_SHA256: wc_Sha256Update(&s->dig_ctx.sha256, pPart, (word32)ulPartLen); break;
    case CKM_SHA384: wc_Sha384Update(&s->dig_ctx.sha384, pPart, (word32)ulPartLen); break;
    case CKM_SHA512: wc_Sha512Update(&s->dig_ctx.sha512, pPart, (word32)ulPartLen); break;
    default:
        rv = CKR_MECHANISM_INVALID;
        s->digest_active = 0;
        goto cleanup;
    }
    s->digest_multipart = 1;

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    CK_RV           rv  = CKR_OK;
    wp11_session_t *s;
    wp11_key_obj_t *obj;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    if (!s->digest_active) { rv = CKR_OPERATION_NOT_INITIALIZED; goto cleanup; }

    obj = key_get(hKey);
    if (obj == NULL) { rv = CKR_KEY_HANDLE_INVALID; goto cleanup; }
    if (obj->secret == NULL || obj->secret_len == 0) {
        rv = CKR_KEY_INDIGESTIBLE;
        goto cleanup;
    }

    switch (s->digest_mech) {
    case CKM_MD5:
        wc_Md5Update(&s->dig_ctx.md5, obj->secret, (word32)obj->secret_len);
        break;
    case CKM_SHA_1:
        wc_ShaUpdate(&s->dig_ctx.sha, obj->secret, (word32)obj->secret_len);
        break;
    case CKM_SHA256:
        wc_Sha256Update(&s->dig_ctx.sha256, obj->secret, (word32)obj->secret_len);
        break;
    case CKM_SHA384:
        wc_Sha384Update(&s->dig_ctx.sha384, obj->secret, (word32)obj->secret_len);
        break;
    case CKM_SHA512:
        wc_Sha512Update(&s->dig_ctx.sha512, obj->secret, (word32)obj->secret_len);
        break;
    default:
        rv = CKR_MECHANISM_INVALID;
        s->digest_active = 0;
        goto cleanup;
    }
    s->digest_multipart = 1;

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
                     CK_ULONG_PTR pulDigestLen)
{
    CK_RV           rv = CKR_OK;
    wp11_session_t *s;
    CK_ULONG        out_size;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    if (!s->digest_active) { rv = CKR_OPERATION_NOT_INITIALIZED; goto cleanup; }

    /* Mode policing: oneshot mode active; DigestFinal not allowed (terminates) */
    if (s->digest_oneshot) {
        s->digest_active    = 0;
        s->digest_oneshot   = 0;
        s->digest_multipart = 0;
        rv = CKR_OPERATION_ACTIVE;
        goto cleanup;
    }

    /* Validate required pulDigestLen after session lookup so we can terminate */
    if (pulDigestLen == NULL_PTR) {
        s->digest_active = 0;
        rv = CKR_ARGUMENTS_BAD;
        goto cleanup;
    }

    out_size = mech_digest_output_size(s->digest_mech);

    if (pDigest == NULL_PTR) {
        /* Size query: return required length; operation stays active */
        *pulDigestLen = out_size;
        goto cleanup;
    }

    if (*pulDigestLen < out_size) {
        *pulDigestLen = out_size;
        rv = CKR_BUFFER_TOO_SMALL;
        /* PKCS#11 sec.11.15: BUFFER_TOO_SMALL does NOT terminate the operation */
        goto cleanup;
    }

    switch (s->digest_mech) {
    case CKM_MD5:    wc_Md5Final(&s->dig_ctx.md5, pDigest);       break;
    case CKM_SHA_1:  wc_ShaFinal(&s->dig_ctx.sha, pDigest);       break;
    case CKM_SHA256: wc_Sha256Final(&s->dig_ctx.sha256, pDigest); break;
    case CKM_SHA384: wc_Sha384Final(&s->dig_ctx.sha384, pDigest); break;
    case CKM_SHA512: wc_Sha512Final(&s->dig_ctx.sha512, pDigest); break;
    default:
        rv = CKR_MECHANISM_INVALID;
        s->digest_active = 0;
        goto cleanup;
    }

    *pulDigestLen       = out_size;
    s->digest_active    = 0;
    s->digest_oneshot   = 0;
    s->digest_multipart = 0;

cleanup:
    WP11_UNLOCK();
    return rv;
}

/* -------------------------------------------------------------------------
 * Sign
 * ---------------------------------------------------------------------- */

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hKey)
{
    CK_RV rv = CKR_OK;
    wp11_session_t *s = NULL;
    wp11_key_obj_t *obj;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (pMechanism == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }

    obj = key_get(hKey);
    if (obj == NULL) { rv = CKR_KEY_HANDLE_INVALID; goto cleanup; }
    if (obj->obj_class == CKO_CERTIFICATE) { rv = CKR_KEY_HANDLE_INVALID; goto cleanup; }

    /* Login required only for private objects (CKA_PRIVATE=true). */
    if (!s->logged_in && obj->is_private) {
        rv = CKR_USER_NOT_LOGGED_IN; goto cleanup;
    }

    /* Check that mechanism is valid for signing */
    if (pMechanism->mechanism == CKM_RSA_PKCS ||
        pMechanism->mechanism == CKM_ECDSA ||
        pMechanism->mechanism == CKM_ECDSA_SHA256) {
        rv = validate_mechanism_params(pMechanism);
        if (rv != CKR_OK) goto cleanup;
    } else if (mech_hmac_type(pMechanism->mechanism) >= 0) {
        /* HMAC mechanism: key must be a generic secret */
        if (obj->key_type != CKK_GENERIC_SECRET &&
            obj->obj_class != CKO_SECRET_KEY) {
            rv = CKR_KEY_TYPE_INCONSISTENT;
            goto cleanup;
        }
        if (obj->secret == NULL || obj->secret_len == 0) {
            rv = CKR_KEY_HANDLE_INVALID;
            goto cleanup;
        }
    } else {
        rv = CKR_MECHANISM_INVALID;
        goto cleanup;
    }

    s->sign_active = 1;
    s->sign_mech   = pMechanism->mechanism;
    s->sign_key    = hKey;

cleanup:
    if (rv != CKR_OK && s != NULL)
        s->sign_active = 0;
    WP11_UNLOCK();
    return rv;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
              CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
              CK_ULONG_PTR pulSignatureLen)
{
    CK_RV             rv = CKR_OK;
    wp11_session_t   *s;
    wp11_key_obj_t   *obj;
    wp11_key_handle_t kh;
    size_t            siglen;
    int               ret;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (pData == NULL_PTR || pulSignatureLen == NULL_PTR) {
        rv = CKR_ARGUMENTS_BAD;
        goto cleanup;
    }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    if (!s->sign_active) { rv = CKR_OPERATION_NOT_INITIALIZED; goto cleanup; }

    obj = key_get(s->sign_key);
    if (obj == NULL) {
        s->sign_active = 0;
        rv = CKR_KEY_HANDLE_INVALID;
        goto cleanup;
    }

    /* HMAC path -- dispatch without backend_ops */
    if (mech_hmac_type(s->sign_mech) >= 0) {
        CK_ULONG out_size = mech_hmac_output_size(s->sign_mech);
        Hmac     hmac;

        /* wolfP11-tu9w: out_size == 0 means the mechanism ID was not
         * recognised by mech_hmac_output_size.  Propagating a zero length
         * would return 0 to a size-query caller (wrong) and let the HMAC
         * execution path skip the CKR_BUFFER_TOO_SMALL check, producing
         * a silent zero-length MAC. */
        if (out_size == 0u) {
            s->sign_active = 0;
            rv = CKR_MECHANISM_INVALID;
            goto cleanup;
        }

        /* PKCS#11 2.40 sec.11.11: a NULL pSignature is a size query; the
         * operation MUST remain active so the caller can immediately follow
         * with a real C_Sign call.  wolfP11-yn8r reviewed this and confirmed
         * the spec requires sign_active to stay 1 here. */
        if (pSignature == NULL_PTR) {
            *pulSignatureLen = out_size;
            goto cleanup; /* operation remains active */
        }
        if (*pulSignatureLen < out_size) {
            *pulSignatureLen = out_size;
            rv = CKR_BUFFER_TOO_SMALL;
            goto cleanup;
        }

        /* wolfP11-z3c7: zero the struct before wc_HmacInit.  wolfCrypt's
         * wc_HmacFree inspects internal state fields to decide what to wipe;
         * an uninitialised struct risks a garbage-pointer dereference.
         * memset must precede wc_HmacInit, not follow it. */
        memset(&hmac, 0, sizeof(hmac));
        wc_HmacInit(&hmac, NULL, INVALID_DEVID);
        ret = wc_HmacSetKey(&hmac, mech_hmac_type(s->sign_mech),
                            obj->secret, (word32)obj->secret_len);
        if (ret == 0) ret = wc_HmacUpdate(&hmac, pData, (word32)ulDataLen);
        if (ret == 0) ret = wc_HmacFinal(&hmac, pSignature);
        wc_HmacFree(&hmac);

        s->sign_active = 0;
        if (ret != 0) { rv = CKR_FUNCTION_FAILED; goto cleanup; }
        *pulSignatureLen = out_size;
        goto cleanup;
    }

    if (pSignature == NULL_PTR) {
        /* wolfP11-3qf: return the mechanism-correct maximum signature length.
         * PKCS#11 2.40 sec.11.11 says pSignature=NULL is a size-query; the caller
         * expects the exact length (or a tight upper bound) for this key+mechanism,
         * NOT a generic maximum.  Returning 512 for an ECDSA/P-256 key causes
         * callers (e.g., ssh-pkcs11-client) to announce the wrong size to peers.
         *
         * sig_len_max is populated from the DER at C_Login time by
         * ks_key_sig_len_max().  If it is 0 (unknown -- soft key or parse
         * error), fall back to 512 (RSA-4096 max) as a safe conservative bound. */
        *pulSignatureLen = (obj->sig_len_max != WP11_SIG_LEN_UNKNOWN)
                        ? obj->sig_len_max : 512;
        goto cleanup;
    }

    siglen = (size_t)*pulSignatureLen;

    /* wolfP11-be5: dispatch through the ops table; no backend-specific ifdefs. */
    if (obj->backend_ops == NULL) { rv = CKR_FUNCTION_FAILED; goto cleanup; }

    memset(&kh, 0, sizeof(kh));
    kh.backend = obj->backend_ops->type;
    kh.priv    = obj->key_priv;

    ret = obj->backend_ops->sign(&kh,
                                 (uint32_t)s->sign_mech,
                                 pData, (size_t)ulDataLen,
                                 pSignature, &siglen);

    s->sign_active = 0;

    if (ret != 0) {
        rv = backend_err_to_rv(ret);
        goto cleanup;
    }

    *pulSignatureLen = (CK_ULONG)siglen;

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                    CK_ULONG ulPartLen)
{
    (void)hSession; (void)pPart; (void)ulPartLen;
    return unsupported();
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                   CK_ULONG_PTR pulSignatureLen)
{
    (void)hSession; (void)pSignature; (void)pulSignatureLen;
    return unsupported();
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession,
                         CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    (void)hSession; (void)pMechanism; (void)hKey;
    return unsupported();
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                     CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                     CK_ULONG_PTR pulSignatureLen)
{
    (void)hSession; (void)pData; (void)ulDataLen;
    (void)pSignature; (void)pulSignatureLen;
    return unsupported();
}

/* -------------------------------------------------------------------------
 * Verify
 * ---------------------------------------------------------------------- */

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hKey)
{
    CK_RV rv = CKR_OK;
    wp11_session_t *s = NULL;
    wp11_key_obj_t *obj;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (pMechanism == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }

    obj = key_get(hKey);
    if (obj == NULL) { rv = CKR_KEY_HANDLE_INVALID; goto cleanup; }
    if (obj->obj_class == CKO_CERTIFICATE) { rv = CKR_KEY_HANDLE_INVALID; goto cleanup; }

    /* Login required only for private objects (CKA_PRIVATE=true). */
    if (!s->logged_in && obj->is_private) {
        rv = CKR_USER_NOT_LOGGED_IN; goto cleanup;
    }

    if (pMechanism->mechanism == CKM_RSA_PKCS ||
        pMechanism->mechanism == CKM_ECDSA ||
        pMechanism->mechanism == CKM_ECDSA_SHA256) {
        rv = validate_mechanism_params(pMechanism);
        if (rv != CKR_OK) goto cleanup;
    } else if (mech_hmac_type(pMechanism->mechanism) >= 0) {
        if (obj->key_type != CKK_GENERIC_SECRET &&
            obj->obj_class != CKO_SECRET_KEY) {
            rv = CKR_KEY_TYPE_INCONSISTENT;
            goto cleanup;
        }
        if (obj->secret == NULL || obj->secret_len == 0) {
            rv = CKR_KEY_HANDLE_INVALID;
            goto cleanup;
        }
    } else {
        rv = CKR_MECHANISM_INVALID;
        goto cleanup;
    }

    s->verify_active = 1;
    s->verify_mech   = pMechanism->mechanism;
    s->verify_key    = hKey;

cleanup:
    if (rv != CKR_OK && s != NULL)
        s->verify_active = 0;
    WP11_UNLOCK();
    return rv;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                CK_ULONG ulSignatureLen)
{
    CK_RV             rv = CKR_OK;
    wp11_session_t   *s;
    wp11_key_obj_t   *obj;
    wp11_key_handle_t kh;
    int               ret;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (pData == NULL_PTR || pSignature == NULL_PTR) {
        rv = CKR_ARGUMENTS_BAD;
        goto cleanup;
    }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    if (!s->verify_active) {
        rv = CKR_OPERATION_NOT_INITIALIZED;
        goto cleanup;
    }

    /* A zero-length signature is structurally invalid for all supported
     * mechanisms.  Reject early to protect backends from a zero-length
     * buffer and clear the active flag -- per PKCS#11 sec.11.10 the operation
     * is consumed by C_Verify regardless of outcome. */
    if (ulSignatureLen == 0u) {
        s->verify_active = 0;
        rv = CKR_SIGNATURE_LEN_RANGE;
        goto cleanup;
    }

    obj = key_get(s->verify_key);
    if (obj == NULL) {
        s->verify_active = 0;
        rv = CKR_KEY_HANDLE_INVALID;
        goto cleanup;
    }

    /* HMAC verify: compute expected MAC and compare */
    if (mech_hmac_type(s->verify_mech) >= 0) {
        CK_ULONG out_size = mech_hmac_output_size(s->verify_mech);
        uint8_t  computed[64]; /* max HMAC output (SHA-512) */
        Hmac     hmac;

        if (ulSignatureLen != out_size) {
            s->verify_active = 0;
            rv = CKR_SIGNATURE_LEN_RANGE;
            goto cleanup;
        }

        wc_HmacInit(&hmac, NULL, INVALID_DEVID);
        ret = wc_HmacSetKey(&hmac, mech_hmac_type(s->verify_mech),
                            obj->secret, (word32)obj->secret_len);
        if (ret == 0) ret = wc_HmacUpdate(&hmac, pData, (word32)ulDataLen);
        if (ret == 0) ret = wc_HmacFinal(&hmac, computed);
        wc_HmacFree(&hmac);

        s->verify_active = 0;
        if (ret != 0) { rv = CKR_FUNCTION_FAILED; goto cleanup; }

        /* wolfP11-94s: timing-safe HMAC comparison.
         * We accumulate XOR differences into a volatile unsigned char so the
         * compiler cannot short-circuit the loop.  The final branch is on the
         * accumulated value of ALL bytes, not on any individual byte, so only
         * a single branch-prediction bit is observable by a timing attacker --
         * the minimum achievable without a hardware instruction.
         *
         * wc_ConstantCompare (wolfssl/wolfcrypt/misc.h) is WOLFSSL_LOCAL and
         * not accessible from outside the wolfSSL shared library, so we use
         * this pattern instead, which wolfSSL itself uses throughout its code.
         *
         * Using unsigned char (not int) prevents sign-extension bugs where
         * signed overflow of the accumulator could produce false matches. */
        {
            volatile unsigned char neq = 0;
            CK_ULONG              k;
            for (k = 0; k < out_size; k++)
                neq |= (unsigned char)(computed[k] ^ ((const unsigned char *)pSignature)[k]);
            if (neq != 0) { rv = CKR_SIGNATURE_INVALID; goto cleanup; }
        }
        goto cleanup;
    }

    /* For RSA: pre-check signature length before dispatching to backend */
    if (s->verify_mech == CKM_RSA_PKCS &&
        obj->sig_len_max > 0 &&
        ulSignatureLen != obj->sig_len_max) {
        s->verify_active = 0;
        rv = CKR_SIGNATURE_LEN_RANGE;
        goto cleanup;
    }

    /* wolfP11-be5: dispatch through the ops table; no backend-specific ifdefs. */
    if (obj->backend_ops == NULL) { rv = CKR_FUNCTION_FAILED; goto cleanup; }

    memset(&kh, 0, sizeof(kh));
    kh.backend = obj->backend_ops->type;
    kh.priv    = obj->key_priv;

    ret = obj->backend_ops->verify(&kh,
                                   (uint32_t)s->verify_mech,
                                   pData, (size_t)ulDataLen,
                                   pSignature, (size_t)ulSignatureLen);

    s->verify_active = 0;

    if (ret != 0) {
        /* Device and key errors must not be masked as CKR_SIGNATURE_INVALID.
         * WP11_BACKEND_ERR_GENERAL (-1) and WP11_BACKEND_ERR_SIG_INVALID (-7)
         * both map to CKR_SIGNATURE_INVALID -- covers the soft backend (always
         * returns -1) and wolfHSM explicit verification failure. */
        if (ret == WP11_BACKEND_ERR_GENERAL || ret == WP11_BACKEND_ERR_SIG_INVALID)
            rv = CKR_SIGNATURE_INVALID;
        else
            rv = backend_err_to_rv(ret);
        goto cleanup;
    }

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                      CK_ULONG ulPartLen)
{
    (void)hSession; (void)pPart; (void)ulPartLen;
    return unsupported();
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                     CK_ULONG ulSignatureLen)
{
    (void)hSession; (void)pSignature; (void)ulSignatureLen;
    return unsupported();
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
                           CK_MECHANISM_PTR pMechanism,
                           CK_OBJECT_HANDLE hKey)
{
    (void)hSession; (void)pMechanism; (void)hKey;
    return unsupported();
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                       CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
                       CK_ULONG_PTR pulDataLen)
{
    (void)hSession; (void)pSignature; (void)ulSignatureLen;
    (void)pData; (void)pulDataLen;
    return unsupported();
}

/* -------------------------------------------------------------------------
 * Combined operations (not supported)
 * ---------------------------------------------------------------------- */

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                              CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                              CK_ULONG_PTR pulEncryptedPartLen)
{
    (void)hSession; (void)pPart; (void)ulPartLen;
    (void)pEncryptedPart; (void)pulEncryptedPartLen;
    return unsupported();
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pEncryptedPart,
                              CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                              CK_ULONG_PTR pulPartLen)
{
    (void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen;
    (void)pPart; (void)pulPartLen;
    return unsupported();
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                           CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                           CK_ULONG_PTR pulEncryptedPartLen)
{
    (void)hSession; (void)pPart; (void)ulPartLen;
    (void)pEncryptedPart; (void)pulEncryptedPartLen;
    return unsupported();
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
                              CK_BYTE_PTR pEncryptedPart,
                              CK_ULONG ulEncryptedPartLen,
                              CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    (void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen;
    (void)pPart; (void)pulPartLen;
    return unsupported();
}

/* -------------------------------------------------------------------------
 * Key generation
 * ---------------------------------------------------------------------- */

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                     CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                     CK_OBJECT_HANDLE_PTR phKey)
{
    CK_RV           rv = CKR_OK;
    wp11_session_t *s;
    CK_ULONG        i;
    int             gi;
    uint8_t        *key_bytes   = NULL;
    size_t          key_len     = 0;
    CK_KEY_TYPE     key_type    = (CK_KEY_TYPE)0;
    CK_BBOOL        is_sensitive    = CK_FALSE;
    CK_BBOOL        is_extractable  = CK_TRUE;  /* default: extractable */
    CK_BBOOL        is_private      = CK_FALSE;
    CK_BBOOL        is_token_obj    = CK_FALSE;
    const char     *label           = "";
    WC_RNG          rng;
    int             rng_init = 0;
    int             wc_rc;

    memset(&rng, 0, sizeof(rng));

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (pMechanism == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }

    if (pTemplate == NULL_PTR && ulCount > 0u) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }
    if (phKey == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    /* Determine key type and byte length from mechanism */
    switch (pMechanism->mechanism) {
    case CKM_AES_KEY_GEN: {
        CK_ULONG value_len = 0;
        key_type = CKK_AES;
        for (i = 0; i < ulCount; i++) {
            if (pTemplate[i].type == CKA_VALUE_LEN &&
                pTemplate[i].pValue != NULL_PTR &&
                pTemplate[i].ulValueLen == sizeof(CK_ULONG))
                memcpy(&value_len, pTemplate[i].pValue, sizeof(CK_ULONG));
        }
        if (value_len != 16u && value_len != 24u && value_len != 32u) {
            rv = CKR_TEMPLATE_INCOMPLETE; goto cleanup;
        }
        key_len = (size_t)value_len;
        break;
    }
    case CKM_DES_KEY_GEN:
        key_type = CKK_DES;
        key_len  = 8u;
        break;
    case CKM_DES3_KEY_GEN:
        key_type = CKK_DES3;
        key_len  = 24u;
        break;
    default:
        rv = CKR_MECHANISM_INVALID; goto cleanup;
    }

    /* Read optional template attributes */
    for (i = 0; i < ulCount; i++) {
        if (pTemplate[i].pValue == NULL_PTR) continue;
        switch (pTemplate[i].type) {
        case CKA_SENSITIVE:
            if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
                is_sensitive = *(const CK_BBOOL *)pTemplate[i].pValue;
            break;
        case CKA_EXTRACTABLE:
            if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
                is_extractable = *(const CK_BBOOL *)pTemplate[i].pValue;
            break;
        case CKA_PRIVATE:
            if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
                is_private = *(const CK_BBOOL *)pTemplate[i].pValue;
            break;
        case CKA_TOKEN:
            if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
                is_token_obj = *(const CK_BBOOL *)pTemplate[i].pValue;
            break;
        case CKA_LABEL:
            label = (const char *)pTemplate[i].pValue;
            break;
        default:
            break;
        }
    }

    /* Allocate and fill key buffer */
    key_bytes = (uint8_t *)malloc(key_len);
    if (key_bytes == NULL) { rv = CKR_HOST_MEMORY; goto cleanup; }

    wc_rc = wc_InitRng(&rng);
    if (wc_rc != 0) { rv = CKR_GENERAL_ERROR; goto cleanup; }
    rng_init = 1;

    wc_rc = wc_RNG_GenerateBlock(&rng, key_bytes, (word32)key_len);
    if (wc_rc != 0) { rv = CKR_GENERAL_ERROR; goto cleanup; }

    /* Find free key slot */
    for (gi = 0; gi < MAX_KEYS; gi++) {
        if (!g_keys[gi].in_use) break;
    }
    if (gi == MAX_KEYS) { rv = CKR_DEVICE_MEMORY; goto cleanup; }

    g_keys[gi].in_use          = 1;
    g_keys[gi].slot_id         = s->slot_id;
    g_keys[gi].obj_class       = CKO_SECRET_KEY;
    g_keys[gi].key_type        = key_type;
    g_keys[gi].is_private      = is_private;
    g_keys[gi].is_token        = is_token_obj;
    g_keys[gi].is_sensitive    = is_sensitive;
    g_keys[gi].is_extractable  = is_extractable;
    g_keys[gi].always_sensitive   = is_sensitive;      /* sensitive from day 1 */
    g_keys[gi].never_extractable  = (is_extractable ? CK_FALSE : CK_TRUE);
    g_keys[gi].is_local        = CK_TRUE;
    g_keys[gi].key_gen_mech    = pMechanism->mechanism;
    g_keys[gi].secret          = key_bytes;
    g_keys[gi].secret_len      = key_len;
    g_keys[gi].backend_ops     = NULL;
    g_keys[gi].key_priv        = NULL;
    strncpy(g_keys[gi].label, label, sizeof(g_keys[gi].label) - 1u);
    g_keys[gi].label[sizeof(g_keys[gi].label) - 1u] = '\0';

    *phKey    = (CK_OBJECT_HANDLE)((CK_ULONG)gi + 1u);
    key_bytes = NULL; /* ownership transferred to g_keys[gi].secret */

cleanup:
    if (rng_init) wc_FreeRng(&rng);
    free(key_bytes);
    WP11_UNLOCK();
    return rv;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism,
                          CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                          CK_ULONG ulPublicKeyAttributeCount,
                          CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                          CK_ULONG ulPrivateKeyAttributeCount,
                          CK_OBJECT_HANDLE_PTR phPublicKey,
                          CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    CK_RV           rv = CKR_OK;
    wp11_session_t *s;
    wp11_soft_key_t *sk = NULL;
    int              gi;        /* private key slot index */
    int              gi_pub;    /* public key slot index  */
    CK_ULONG         i;
    const char      *label = "";
    CK_BBOOL         key_is_priv = CK_TRUE; /* CKA_PRIVATE default per spec */
    CK_ULONG         modulus_bits = 2048;   /* RSA default modulus size */

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (pMechanism == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }
    if (phPublicKey == NULL_PTR || phPrivateKey == NULL_PTR) {
        rv = CKR_ARGUMENTS_BAD; goto cleanup;
    }
    if (pPublicKeyTemplate == NULL_PTR && ulPublicKeyAttributeCount > 0) {
        rv = CKR_ARGUMENTS_BAD; goto cleanup;
    }
    if (pPrivateKeyTemplate == NULL_PTR && ulPrivateKeyAttributeCount > 0) {
        rv = CKR_ARGUMENTS_BAD; goto cleanup;
    }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }

    /* Parse CKA_MODULUS_BITS from the public key template (RSA only). */
    if (pPublicKeyTemplate != NULL) {
        for (i = 0; i < ulPublicKeyAttributeCount; i++) {
            if (pPublicKeyTemplate[i].type == CKA_MODULUS_BITS &&
                pPublicKeyTemplate[i].pValue != NULL &&
                pPublicKeyTemplate[i].ulValueLen == sizeof(CK_ULONG)) {
                modulus_bits = *(const CK_ULONG *)pPublicKeyTemplate[i].pValue;
            }
        }
    }

    /* Parse CKA_LABEL and CKA_PRIVATE from the private key template.
     * CKA_PRIVATE defaults to CK_TRUE.  Session objects generated with
     * CKA_PRIVATE=false (e.g., pkcs11test conformance suite) are public
     * objects that do not require login per PKCS#11 sec.4.2. */
    if (pPrivateKeyTemplate != NULL) {
        for (i = 0; i < ulPrivateKeyAttributeCount; i++) {
            if (pPrivateKeyTemplate[i].type == CKA_LABEL &&
                pPrivateKeyTemplate[i].pValue != NULL &&
                pPrivateKeyTemplate[i].ulValueLen > 0) {
                label = (const char *)pPrivateKeyTemplate[i].pValue;
            }
            if (pPrivateKeyTemplate[i].type == CKA_PRIVATE &&
                pPrivateKeyTemplate[i].pValue != NULL &&
                pPrivateKeyTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
                key_is_priv = *(const CK_BBOOL *)pPrivateKeyTemplate[i].pValue;
            }
        }
    }

    /* Require login for private keys on hardware tokens and persistent soft
     * tokens.  In-memory soft tokens (no flash_path) allow public session
     * objects without login per PKCS#11 sec.4.2. */
    if (!s->logged_in && key_is_priv) {
        int need_login = (g_slots[s->slot_id].proto == WP11_PROTO_PIV);
#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
        need_login = need_login || (g_slots[s->slot_id].keystore_path[0] != '\0');
#endif
        if (need_login) {
            rv = CKR_USER_NOT_LOGGED_IN; goto cleanup;
        }
    }

#ifdef WOLFP11_CFG_FSDIR_BACKEND
    /* FSDIR slots are read-only: .p11k files are managed externally via the
     * wp11 CLI.  Key generation is not supported on these slots. */
    if (g_slots[s->slot_id].proto == WP11_PROTO_FSDIR) {
        rv = CKR_FUNCTION_NOT_SUPPORTED; goto cleanup;
    }
#endif /* WOLFP11_CFG_FSDIR_BACKEND */

#ifdef WOLFP11_CFG_USB_BACKEND
    if (g_slots[s->slot_id].proto == WP11_PROTO_PIV) {
        /* PIV hardware token: generate key on-device via GENERATE ASYMMETRIC
         * KEY PAIR (INS 0x47).  The private key never leaves the hardware.
         * Target PIV slot is selected by CKA_ID[0] in pPrivateKeyTemplate:
         *   0x01 (or absent) -> 9A Authentication  [default]
         *   0x02             -> 9C Digital Signature
         *   0x03             -> 9D Key Management
         *   0x04             -> 9E Card Authentication */
        wp11_ccid_ctx_t    *piv_ccid;
        uint8_t             piv_alg;
        uint8_t             tgt_piv_slot;
        int                 prc;
        int                 ki_existing = -1;
        wp11_usb_key_priv_t *kp;

        piv_ccid = g_slots[s->slot_id].ccid;
        if (piv_ccid == NULL) { rv = CKR_USER_NOT_LOGGED_IN; goto cleanup; }

        /* Map PKCS#11 mechanism to PIV algorithm reference */
        if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN) {
            piv_alg = WP11_PIV_ALG_EC_P256;
        } else if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN) {
            piv_alg = WP11_PIV_ALG_RSA2048;
        } else {
            rv = CKR_MECHANISM_INVALID; goto cleanup;
        }

        /* Select target PIV slot from CKA_ID in private key template */
        tgt_piv_slot = WP11_PIV_SLOT_AUTH;  /* default: 9A */
        if (pPrivateKeyTemplate != NULL) {
            CK_ULONG ti;
            for (ti = 0; ti < ulPrivateKeyAttributeCount; ti++) {
                if (pPrivateKeyTemplate[ti].type == CKA_ID &&
                    pPrivateKeyTemplate[ti].pValue != NULL &&
                    pPrivateKeyTemplate[ti].ulValueLen >= 1u) {
                    uint8_t kid =
                        ((const uint8_t *)pPrivateKeyTemplate[ti].pValue)[0];
                    if      (kid == 0x02) tgt_piv_slot = WP11_PIV_SLOT_SIGN;
                    else if (kid == 0x03) tgt_piv_slot = WP11_PIV_SLOT_KEYMGMT;
                    else if (kid == 0x04) tgt_piv_slot = WP11_PIV_SLOT_CARDAUTH;
                    else                  tgt_piv_slot = WP11_PIV_SLOT_AUTH;
                    break;
                }
            }
        }

        /* Generate the key on hardware (fire-and-forget: discard public key) */
        prc = wp11_piv_generate_key(piv_ccid, tgt_piv_slot, piv_alg,
                                     NULL, NULL);
        if (prc != WP11_PIV_OK) {
            rv = CKR_DEVICE_ERROR; goto cleanup;
        }

        /* Find the existing key object for the target PIV slot, if any */
        for (gi = 0; gi < MAX_KEYS; gi++) {
            if (g_keys[gi].in_use &&
                g_keys[gi].slot_id == s->slot_id &&
                g_keys[gi].backend_ops == &wp11_backend_usb_ops) {
                kp = (wp11_usb_key_priv_t *)g_keys[gi].key_priv;
                if (kp != NULL && kp->piv_slot == tgt_piv_slot) {
                    ki_existing = gi;
                    break;
                }
            }
        }

        if (ki_existing < 0) {
            /* Create a new key object (no prior key object for target slot) */
            for (gi = 0; gi < MAX_KEYS; gi++) {
                if (!g_keys[gi].in_use) { ki_existing = gi; break; }
            }
            if (ki_existing < 0) { rv = CKR_DEVICE_MEMORY; goto cleanup; }

            kp = (wp11_usb_key_priv_t *)malloc(sizeof(*kp));
            if (kp == NULL) { rv = CKR_DEVICE_MEMORY; goto cleanup; }
            kp->ccid     = piv_ccid;
            kp->piv_slot = tgt_piv_slot;
            g_keys[ki_existing].in_use      = 1;
            g_keys[ki_existing].slot_id     = (int)s->slot_id;
            g_keys[ki_existing].obj_class   = CKO_PRIVATE_KEY;
            g_keys[ki_existing].key_priv    = kp;
            g_keys[ki_existing].backend_ops = &wp11_backend_usb_ops;
            g_keys[ki_existing].is_private  = CK_TRUE;
            g_keys[ki_existing].is_token    = CK_TRUE;
        } else {
            kp = (wp11_usb_key_priv_t *)g_keys[ki_existing].key_priv;
        }

        /* Update algorithm-dependent fields */
        kp->piv_alg = piv_alg;
        if (piv_alg == WP11_PIV_ALG_EC_P256) {
            g_keys[ki_existing].key_type    = CKK_EC;
            g_keys[ki_existing].sig_len_max = 72u;   /* P-256 DER ECDSA max */
        } else if (piv_alg == WP11_PIV_ALG_EC_P384) {
            g_keys[ki_existing].key_type    = CKK_EC;
            g_keys[ki_existing].sig_len_max = 105u;  /* P-384 DER ECDSA max */
        } else {
            g_keys[ki_existing].key_type    = CKK_RSA;
            g_keys[ki_existing].sig_len_max = 256u;  /* RSA-2048 sig = 256 bytes */
        }
        if (label[0] != '\0') {
            strncpy(g_keys[ki_existing].label, label,
                    sizeof(g_keys[ki_existing].label) - 1u);
            g_keys[ki_existing].label[sizeof(g_keys[ki_existing].label) - 1u] = '\0';
        }

        *phPublicKey  = (CK_OBJECT_HANDLE)((CK_ULONG)ki_existing + 1u);
        *phPrivateKey = (CK_OBJECT_HANDLE)((CK_ULONG)ki_existing + 1u);
        goto cleanup;
    }
#endif /* WOLFP11_CFG_USB_BACKEND */

#ifdef WOLFP11_CFG_WOLFHSM_BACKEND
    if (g_slots[s->slot_id].proto == WP11_PROTO_WOLFHSM) {
        wp11_wolfhsm_client_t   *wh;
        whClientContext         *hctx;
        whKeyId                  key_id  = WH_KEYID_ERASED;
        wp11_wolfhsm_key_priv_t *kp_pub  = NULL;
        wp11_wolfhsm_key_priv_t *kp_priv = NULL;
        int                      gi_pub  = -1;
        int                      gi_priv = -1;
        int                      wret;
        CK_KEY_TYPE              ck_key_type;
        CK_ULONG                 sig_max;
        int                      wh_key_type;
        uint16_t                 wh_key_size;
        uint16_t                 wh_label_len;

        if (!s->logged_in) { rv = CKR_USER_NOT_LOGGED_IN; goto cleanup; }

        wh = (wp11_wolfhsm_client_t *)g_slots[s->slot_id].hsm_client;
        if (wh == NULL) { rv = CKR_DEVICE_ERROR; goto cleanup; }
        hctx = &wh->ctx;

        /* Cap label length at the server NVM label size */
        {
            size_t llen = strlen(label);
            wh_label_len = (uint16_t)(llen < (size_t)(WH_NVM_LABEL_LEN - 1u)
                                      ? llen : (size_t)(WH_NVM_LABEL_LEN - 1u));
        }

        if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN) {
            wret = wh_Client_EccMakeCacheKey(hctx, 32, ECC_SECP256R1,
                                             &key_id, WH_NVM_FLAGS_USAGE_ANY,
                                             wh_label_len, (uint8_t *)label);
            ck_key_type = CKK_EC;
            sig_max     = 72u;  /* P-256 DER ECDSA max */
            wh_key_type = WP11_KEY_TYPE_EC;
            wh_key_size = 0u;
        } else if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN) {
            if (modulus_bits < 512u || modulus_bits > 4096u) {
                rv = CKR_ATTRIBUTE_VALUE_INVALID; goto cleanup;
            }
            wret = wh_Client_RsaMakeCacheKey(hctx, (uint32_t)modulus_bits,
                                              (uint32_t)WC_RSA_EXPONENT,
                                              &key_id, WH_NVM_FLAGS_USAGE_ANY,
                                              (uint32_t)wh_label_len,
                                              (uint8_t *)label);
            ck_key_type = CKK_RSA;
            wh_key_size = (uint16_t)(modulus_bits / 8u);
            sig_max     = (CK_ULONG)wh_key_size;
            wh_key_type = WP11_KEY_TYPE_RSA;
        } else {
            rv = CKR_MECHANISM_INVALID; goto cleanup;
        }

        if (wret != WH_ERROR_OK) { rv = CKR_DEVICE_ERROR; goto cleanup; }

        /* Find two free g_keys[] slots (public + private) */
        for (gi = 0; gi < MAX_KEYS; gi++) {
            if (!g_keys[gi].in_use) {
                if (gi_pub < 0) { gi_pub  = gi; }
                else            { gi_priv = gi; break; }
            }
        }
        if (gi_pub < 0 || gi_priv < 0) {
            (void)wh_Client_KeyEvict(hctx, key_id);
            rv = CKR_DEVICE_MEMORY; goto cleanup;
        }

        /* Two separate allocations -- same key_id, freed independently */
        kp_pub  = wp11_wolfhsm_alloc_key_priv((void *)hctx, (uint16_t)key_id,
                                               wh_key_type, wh_key_size);
        kp_priv = wp11_wolfhsm_alloc_key_priv((void *)hctx, (uint16_t)key_id,
                                               wh_key_type, wh_key_size);
        if (kp_pub == NULL || kp_priv == NULL) {
            free(kp_pub);
            free(kp_priv);
            (void)wh_Client_KeyEvict(hctx, key_id);
            rv = CKR_DEVICE_MEMORY; goto cleanup;
        }

        /* Public key slot */
        g_keys[gi_pub].in_use      = 1;
        g_keys[gi_pub].slot_id     = s->slot_id;
        g_keys[gi_pub].obj_class   = CKO_PUBLIC_KEY;
        g_keys[gi_pub].key_type    = ck_key_type;
        g_keys[gi_pub].sig_len_max = sig_max;
        g_keys[gi_pub].key_priv    = kp_pub;
        g_keys[gi_pub].backend_ops = &wp11_backend_wolfhsm_ops;
        g_keys[gi_pub].is_private  = CK_FALSE;
        g_keys[gi_pub].is_token    = CK_TRUE;
        g_keys[gi_pub].is_local    = CK_TRUE;
        strncpy(g_keys[gi_pub].label, label, sizeof(g_keys[gi_pub].label) - 1u);
        g_keys[gi_pub].label[sizeof(g_keys[gi_pub].label) - 1u] = '\0';
        g_keys[gi_pub].id[0]  = (uint8_t)((key_id >> 8) & 0xFFu);
        g_keys[gi_pub].id[1]  = (uint8_t)(key_id & 0xFFu);
        g_keys[gi_pub].id_len = 2u;

        /* Private key slot */
        g_keys[gi_priv].in_use      = 1;
        g_keys[gi_priv].slot_id     = s->slot_id;
        g_keys[gi_priv].obj_class   = CKO_PRIVATE_KEY;
        g_keys[gi_priv].key_type    = ck_key_type;
        g_keys[gi_priv].sig_len_max = sig_max;
        g_keys[gi_priv].key_priv    = kp_priv;
        g_keys[gi_priv].backend_ops = &wp11_backend_wolfhsm_ops;
        g_keys[gi_priv].is_private  = key_is_priv;
        g_keys[gi_priv].is_token    = CK_TRUE;
        g_keys[gi_priv].is_local    = CK_TRUE;
        strncpy(g_keys[gi_priv].label, label, sizeof(g_keys[gi_priv].label) - 1u);
        g_keys[gi_priv].label[sizeof(g_keys[gi_priv].label) - 1u] = '\0';
        g_keys[gi_priv].id[0]  = (uint8_t)((key_id >> 8) & 0xFFu);
        g_keys[gi_priv].id[1]  = (uint8_t)(key_id & 0xFFu);
        g_keys[gi_priv].id_len = 2u;

        *phPublicKey  = (CK_OBJECT_HANDLE)((CK_ULONG)gi_pub  + 1u);
        *phPrivateKey = (CK_OBJECT_HANDLE)((CK_ULONG)gi_priv + 1u);
        goto cleanup;
    }
#endif /* WOLFP11_CFG_WOLFHSM_BACKEND */

    /* Soft token path: wolfP11-y4w, wolfP11-t5u */
    if (g_slots[s->slot_id].proto != WP11_PROTO_SOFT) {
        rv = CKR_FUNCTION_NOT_SUPPORTED; goto cleanup;
    }
    if (pMechanism->mechanism != CKM_EC_KEY_PAIR_GEN &&
        pMechanism->mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN) {
        rv = CKR_MECHANISM_INVALID; goto cleanup;
    }

    /* Claim two free key slots: one for the public key, one for private.
     * Both slots share one wp11_soft_key_t (via ref_count).  Separate
     * slots are required so C_DestroyObject on either handle does not
     * corrupt the other. */
    gi_pub = -1;
    gi     = -1;
    for (i = 0; i < MAX_KEYS; i++) {
        if (!g_keys[i].in_use) {
            if (gi_pub < 0) { gi_pub = (int)i; }
            else            { gi     = (int)i; break; }
        }
    }
    if (gi_pub < 0 || gi < 0) { rv = CKR_DEVICE_MEMORY; goto cleanup; }

    if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN) {
        sk = wp11_soft_key_new_rsa((int)modulus_bits);
    } else {
        sk = wp11_soft_key_new_ecc_p256();
    }
    if (sk == NULL) { rv = CKR_DEVICE_MEMORY; goto cleanup; }

    /* Public key slot (CKA_PRIVATE=false -- never requires login) */
    g_keys[gi_pub].in_use      = 1;
    g_keys[gi_pub].slot_id     = s->slot_id;
    g_keys[gi_pub].obj_class   = CKO_PUBLIC_KEY;
    g_keys[gi_pub].is_private  = CK_FALSE;
    g_keys[gi_pub].is_token    = CK_TRUE;
    g_keys[gi_pub].key_priv    = wp11_soft_key_ref(sk);
    g_keys[gi_pub].backend_ops = &wp11_backend_soft_ops;
    if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN) {
        g_keys[gi_pub].key_type    = CKK_RSA;
        g_keys[gi_pub].sig_len_max = (CK_ULONG)(modulus_bits / 8u);
    } else {
        g_keys[gi_pub].key_type    = CKK_EC;
        g_keys[gi_pub].sig_len_max = 72u;
    }
    strncpy(g_keys[gi_pub].label, label, sizeof(g_keys[gi_pub].label) - 1u);
    g_keys[gi_pub].label[sizeof(g_keys[gi_pub].label) - 1u] = '\0';

    /* Private key slot */
    g_keys[gi].in_use      = 1;
    g_keys[gi].slot_id     = s->slot_id;
    g_keys[gi].obj_class   = CKO_PRIVATE_KEY;
    g_keys[gi].is_private  = key_is_priv;
    g_keys[gi].is_token    = CK_TRUE;
    g_keys[gi].key_priv    = sk;
    g_keys[gi].backend_ops = &wp11_backend_soft_ops;
    if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN) {
        g_keys[gi].key_type    = CKK_RSA;
        g_keys[gi].sig_len_max = (CK_ULONG)(modulus_bits / 8u);
    } else {
        g_keys[gi].key_type    = CKK_EC;
        /* P-256 DER ECDSA max: SEQUENCE(2) + 2 x INTEGER(2 + 32 + 1) = 72 */
        g_keys[gi].sig_len_max = 72u;
    }
    strncpy(g_keys[gi].label, label, sizeof(g_keys[gi].label) - 1u);
    g_keys[gi].label[sizeof(g_keys[gi].label) - 1u] = '\0';

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
    /* Assign a random 16-byte CKA_ID shared between both objects */
    (void)wp11_keystore_gen_id(g_keys[gi].id);
    g_keys[gi].id_len = 16u;
    memcpy(g_keys[gi_pub].id, g_keys[gi].id, 16u);
    g_keys[gi_pub].id_len = 16u;
#endif

    *phPublicKey  = (CK_OBJECT_HANDLE)((CK_ULONG)gi_pub + 1u);
    *phPrivateKey = (CK_OBJECT_HANDLE)((CK_ULONG)gi + 1u);
    sk = NULL; /* ownership transferred to g_keys[gi] */

#ifdef WOLFP11_CFG_USB_FLASH_BACKEND
    /* Persist: re-save all soft keys to the .p11k file.
     * Best-effort: the key is already in g_keys[]; a save failure only
     * means the key won't survive C_Finalize. */
    if (g_slots[s->slot_id].keystore_path[0] != '\0' &&
        g_slots[s->slot_id].soft_pin_len > 0) {
        (void)soft_slot_save(s->slot_id);
    }
#endif

cleanup:
    if (sk != NULL) wp11_soft_key_free(sk);
    WP11_UNLOCK();
    return rv;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                 CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
                 CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
    (void)hSession; (void)pMechanism; (void)hWrappingKey;
    (void)hKey; (void)pWrappedKey; (void)pulWrappedKeyLen;
    return unsupported();
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                   CK_OBJECT_HANDLE hUnwrappingKey,
                   CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen,
                   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
                   CK_OBJECT_HANDLE_PTR phKey)
{
    (void)hSession; (void)pMechanism; (void)hUnwrappingKey;
    (void)pWrappedKey; (void)ulWrappedKeyLen;
    (void)pTemplate; (void)ulAttributeCount; (void)phKey;
    return unsupported();
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                   CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
                   CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
    CK_RV                   rv       = CKR_OK;
    wp11_session_t         *s        = NULL;
    wp11_key_obj_t         *base_obj = NULL;
    CK_ECDH1_DERIVE_PARAMS *params   = NULL;
    uint8_t                 shared[64]; /* 32 for P-256, 48 for P-384 */
    size_t                  sharedlen = sizeof(shared);
    uint8_t                *secret   = NULL;
    wp11_key_handle_t       kh;
    int                     ki;
    int                     rc;

    /* Suppress unused-parameter warnings for template (not yet used) */
    (void)pTemplate;
    (void)ulAttributeCount;

    if (pMechanism == NULL || phKey == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }

    s = session_get(hSession);
    if (s == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }

    if (pMechanism->mechanism != CKM_ECDH1_DERIVE) {
        rv = CKR_MECHANISM_INVALID;
        goto cleanup;
    }

    if (pMechanism->pParameter == NULL ||
        pMechanism->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS)) {
        rv = CKR_MECHANISM_PARAM_INVALID;
        goto cleanup;
    }
    params = (CK_ECDH1_DERIVE_PARAMS *)pMechanism->pParameter;
    if (params->kdf != CKD_NULL) {
        rv = CKR_MECHANISM_PARAM_INVALID;
        goto cleanup;
    }
    if (params->pPublicData == NULL || params->ulPublicDataLen == 0) {
        rv = CKR_MECHANISM_PARAM_INVALID;
        goto cleanup;
    }

    base_obj = key_get(hBaseKey);
    if (base_obj == NULL) { rv = CKR_KEY_HANDLE_INVALID; goto cleanup; }
    if (base_obj->backend_ops == NULL ||
        base_obj->backend_ops->derive == NULL) {
        rv = CKR_KEY_TYPE_INCONSISTENT;
        goto cleanup;
    }

    memset(&kh, 0, sizeof(kh));
    kh.backend = base_obj->backend_ops->type;
    kh.priv    = base_obj->key_priv;

    rc = base_obj->backend_ops->derive(
        &kh,
        (uint32_t)pMechanism->mechanism,
        (const uint8_t *)params->pPublicData, (size_t)params->ulPublicDataLen,
        shared, &sharedlen);
    if (rc != 0) { rv = backend_err_to_rv(rc); goto cleanup; }

    /* Find a free key slot */
    for (ki = 0; ki < MAX_KEYS; ki++) {
        if (!g_keys[ki].in_use) break;
    }
    if (ki >= MAX_KEYS) { rv = CKR_HOST_MEMORY; goto cleanup; }

    secret = (uint8_t *)malloc(sharedlen);
    if (secret == NULL) { rv = CKR_HOST_MEMORY; goto cleanup; }
    memcpy(secret, shared, sharedlen);

    memset(&g_keys[ki], 0, sizeof(g_keys[ki]));
    g_keys[ki].in_use      = 1;
    g_keys[ki].slot_id     = (int)s->slot_id;
    g_keys[ki].obj_class   = CKO_SECRET_KEY;
    g_keys[ki].key_type    = CKK_GENERIC_SECRET;
    g_keys[ki].is_token    = CK_TRUE;
    g_keys[ki].secret      = secret;
    g_keys[ki].secret_len  = sharedlen;
    g_keys[ki].backend_ops = base_obj->backend_ops;
    /* key_priv is NULL: no backend key state for derived secrets */

    *phKey = (CK_OBJECT_HANDLE)(ki + 1);

cleanup:
    memset(shared, 0, sizeof(shared));
    if (rv != CKR_OK && secret != NULL) {
        memset(secret, 0, sharedlen);
        free(secret);
    }
    WP11_UNLOCK();
    return rv;
}

/* -------------------------------------------------------------------------
 * Random
 * ---------------------------------------------------------------------- */

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
                    CK_ULONG ulSeedLen)
{
    CK_RV rv = CKR_OK;

    (void)ulSeedLen;

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (pSeed == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }
    if (session_get(hSession) == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    rv = CKR_RANDOM_SEED_NOT_SUPPORTED;

cleanup:
    WP11_UNLOCK();
    return rv;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData,
                        CK_ULONG ulRandomLen)
{
    CK_RV  rv     = CKR_OK;
    WC_RNG rng;
    int    rng_init = 0;
    int    wc_rc;

    memset(&rng, 0, sizeof(rng));

    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);

    if (!g_initialized) { rv = CKR_CRYPTOKI_NOT_INITIALIZED; goto cleanup; }
    if (RandomData == NULL_PTR) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }
    if (session_get(hSession) == NULL) { rv = CKR_SESSION_HANDLE_INVALID; goto cleanup; }
    /* word32 is 32-bit; reject requests too large to fit. No real caller asks
     * for more than a few KB, but the cast must not silently truncate. */
    if (ulRandomLen > 0xFFFFFFFFUL) { rv = CKR_ARGUMENTS_BAD; goto cleanup; }

    if (ulRandomLen == 0) {
        goto cleanup; /* nothing to do; not an error per PKCS#11 2.40 sec.5.18 */
    }

    wc_rc = wc_InitRng(&rng);
    if (wc_rc != 0) { rv = CKR_GENERAL_ERROR; goto cleanup; }
    rng_init = 1;

    wc_rc = wc_RNG_GenerateBlock(&rng, RandomData, (word32)ulRandomLen);
    if (wc_rc != 0) {
        rv = CKR_GENERAL_ERROR;
    }

cleanup:
    if (rng_init) {
        wc_FreeRng(&rng);
    }
    WP11_UNLOCK();
    return rv;
}

/* -------------------------------------------------------------------------
 * Legacy parallel management
 * ---------------------------------------------------------------------- */

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
    (void)hSession;
    return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
    (void)hSession;
    return CKR_FUNCTION_NOT_PARALLEL;
}

/* -------------------------------------------------------------------------
 * C_WaitForSlotEvent
 * ---------------------------------------------------------------------- */

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
                          CK_VOID_PTR pRserved)
{
    wp11_hotplug_event_t ev;
    int got_event = 0;

    (void)pRserved;

    if (pSlot == NULL_PTR) return CKR_ARGUMENTS_BAD;

    /* Check initialized state without holding g_lock during the wait.
     * C_WaitForSlotEvent must NOT hold g_lock while blocking because the
     * hotplug callback acquires g_lock when updating slot state -- deadlock. */
    WP11_LOCK(CKR_CRYPTOKI_NOT_INITIALIZED);
    if (!g_initialized) { WP11_UNLOCK(); return CKR_CRYPTOKI_NOT_INITIALIZED; }
    WP11_UNLOCK();

    if (!g_hotplug_mutex_ready) {
        /* Hotplug infrastructure not initialized (pre-init or post-finalize). */
        return unsupported();
    }

    if (flags & CKF_DONT_BLOCK) {
        /* Poll: check queue immediately, return CKR_NO_EVENT if empty */
        if (pthread_mutex_lock(&g_hotplug_mutex) != 0)
            return CKR_GENERAL_ERROR;
        if (g_hotplug_head != g_hotplug_tail) {
            ev = g_hotplug_queue[g_hotplug_head];
            g_hotplug_head = (g_hotplug_head + 1u) % WP11_HOTPLUG_QUEUE_SIZE;
            got_event = 1;
        }
        (void)pthread_mutex_unlock(&g_hotplug_mutex);

        if (!got_event) return CKR_NO_EVENT;
    } else {
        /* Blocking: wait until an event is enqueued or library is finalized */
        if (pthread_mutex_lock(&g_hotplug_mutex) != 0)
            return CKR_GENERAL_ERROR;
        while (g_hotplug_head == g_hotplug_tail && g_hotplug_mutex_ready) {
            if (pthread_cond_wait(&g_hotplug_cond, &g_hotplug_mutex) != 0) {
                (void)pthread_mutex_unlock(&g_hotplug_mutex);
                return CKR_GENERAL_ERROR;
            }
        }
        if (g_hotplug_head != g_hotplug_tail) {
            ev = g_hotplug_queue[g_hotplug_head];
            g_hotplug_head = (g_hotplug_head + 1u) % WP11_HOTPLUG_QUEUE_SIZE;
            got_event = 1;
        }
        (void)pthread_mutex_unlock(&g_hotplug_mutex);

        if (!got_event) {
            /* Woken because library is finalizing, not because of a real event */
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
    }

    *pSlot = ev.slot_id;
    return CKR_OK;
}

/* -------------------------------------------------------------------------
 * Function list
 * ---------------------------------------------------------------------- */

static CK_FUNCTION_LIST g_func_list = {
    { 2, 40 },
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken,
    C_InitPIN,
    C_SetPIN,
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    C_GetOperationState,
    C_SetOperationState,
    C_Login,
    C_Logout,
    C_CreateObject,
    C_CopyObject,
    C_DestroyObject,
    C_GetObjectSize,
    C_GetAttributeValue,
    C_SetAttributeValue,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    C_EncryptInit,
    C_Encrypt,
    C_EncryptUpdate,
    C_EncryptFinal,
    C_DecryptInit,
    C_Decrypt,
    C_DecryptUpdate,
    C_DecryptFinal,
    C_DigestInit,
    C_Digest,
    C_DigestUpdate,
    C_DigestKey,
    C_DigestFinal,
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    C_SignRecoverInit,
    C_SignRecover,
    C_VerifyInit,
    C_Verify,
    C_VerifyUpdate,
    C_VerifyFinal,
    C_VerifyRecoverInit,
    C_VerifyRecover,
    C_DigestEncryptUpdate,
    C_DecryptDigestUpdate,
    C_SignEncryptUpdate,
    C_DecryptVerifyUpdate,
    C_GenerateKey,
    C_GenerateKeyPair,
    C_WrapKey,
    C_UnwrapKey,
    C_DeriveKey,
    C_SeedRandom,
    C_GenerateRandom,
    C_GetFunctionStatus,
    C_CancelFunction,
    C_WaitForSlotEvent,
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (ppFunctionList == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }
    *ppFunctionList = &g_func_list;
    return CKR_OK;
}

#ifdef WOLFP11_CFG_USB_BACKEND
/* -------------------------------------------------------------------------
 * wp11_piv_attest_slot -- retrieve YubiKey attestation cert for a PIV slot
 *
 * Acquires g_lock, looks up the slot's open CCID context, calls
 * wp11_piv_attest, and returns.  The slot must have been logged in via
 * C_Login before calling this function.
 * ---------------------------------------------------------------------- */
int wp11_piv_attest_slot(CK_SLOT_ID  slot_id,
                         uint8_t     piv_slot,
                         uint8_t    *der,
                         size_t     *derlen)
{
    wp11_ccid_ctx_t *ccid;
    int              rc;

    if (der == NULL || derlen == NULL) {
        return WP11_PIV_ERR_PARAM;
    }

    if (!g_lock_ready || wc_LockMutex(&g_lock) != 0) {
        return WP11_PIV_ERR_PARAM;
    }

    if (slot_id >= (CK_SLOT_ID)MAX_SLOTS ||
        !g_slots[slot_id].in_use         ||
        g_slots[slot_id].ccid == NULL) {
        (void)wc_UnLockMutex(&g_lock);
        return WP11_PIV_ERR_PARAM;
    }

    ccid = g_slots[slot_id].ccid;
    rc   = wp11_piv_attest(ccid, piv_slot, der, derlen);
    (void)wc_UnLockMutex(&g_lock);
    return rc;
}
#endif /* WOLFP11_CFG_USB_BACKEND */

#ifdef WOLFP11_CFG_TEST
/* -------------------------------------------------------------------------
 * wp11_test_soft_export_pub_x963 -- export EC public key for test oracle
 *
 * Acquires g_lock, looks up the soft-token key object, and delegates to
 * wp11_soft_key_test_export_pub_x963.  Returns 0 on success, -1 on error.
 * Uses CK_ULONG for outlen to avoid word32 in the test file.
 * ---------------------------------------------------------------------- */
int wp11_test_soft_export_pub_x963(CK_OBJECT_HANDLE hKey,
                                    uint8_t *out, CK_ULONG *outlen)
{
    wp11_key_obj_t *obj;
    word32          wlen;
    int             rc;

    if (out == NULL || outlen == NULL) return -1;

    WP11_LOCK(-1);

    obj = key_get(hKey);
    if (obj == NULL || obj->key_priv == NULL ||
        obj->backend_ops != &wp11_backend_soft_ops) {
        WP11_UNLOCK();
        return -1;
    }

    wlen = (word32)*outlen;
    rc = wp11_soft_key_test_export_pub_x963((wp11_soft_key_t *)obj->key_priv,
                                              out, &wlen);
    *outlen = (CK_ULONG)wlen;
    WP11_UNLOCK();
    return rc;
}
#endif /* WOLFP11_CFG_TEST */
