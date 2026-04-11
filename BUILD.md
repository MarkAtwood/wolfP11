# BUILD.md -- Agentic Build Prompt: `wolfP11`

> **Purpose:** This file is a complete agentic build prompt. An autonomous agent
> reading this file should be able to build, test, and validate the `wolfP11`
> project from scratch with no additional human input for the core workflow.
> Read this entire file before writing a single line of code.

---

## What You Are Building

A unified PKCS#11 shared library (`libwolfp11.so`) written in C (C99) that:

1. Communicates directly with USB hardware security tokens (YubiKey, NitroKey,
   etc.) via **libusb** -- no pcscd, no system daemon required
2. Speaks CCID over USB bulk transfers, then ISO 7816 APDUs to the token's PIV
   or OpenPGP card applet
3. Maintains a **table-driven token database**: adding a new PIV-compatible
   token is one row in a C struct array, not a new file
4. Optionally routes operations through a **wolfHSM server** via wolfCrypt's
   device callback (WH_DEV_ID), for targets without USB
5. Exposes a standard **PKCS#11 2.40 C ABI** to every application above it
6. Ships a **patch to wolfProvider** (`~/wolfProvider`) that closes the devId
   gap so OpenSSL 3.x routes through wolfHSM

**Language:** C (C99; C90-compatible guards for embedded targets)
**Target OS:** Linux (primary); portable to any POSIX with libusb support
**Output:** `build/libwolfp11.so` (shared library), `build/wp11` (CLI tool)

**Dependencies:**
- wolfCrypt (wolfSSL) -- crypto engine; must be on include/link path
- libusb-1.0 -- USB hardware token access; required for USB backend
- wolfHSM -- optional HSM backend; enables WH_DEV_ID routing
- OpenSSL 3.x headers -- optional; required only for provider patch

---

## Pre-Flight: Session Setup

Before doing anything else, run these checks:

```bash
bd status 2>/dev/null || (bd init --quiet && bd setup claude)

# Check wolfCrypt is present
ls ~/wolfssl/wolfssl/wolfcrypt/settings.h && echo "wolfcrypt ok" || echo "MISSING: wolfssl checkout"

# Check libusb
pkg-config --modversion libusb-1.0 && echo "libusb ok" || echo "MISSING: libusb-1.0-dev"

# Check wolfProvider is present (for devId patch work)
ls ~/wolfProvider/src/wp_rsa_kmgmt.c && echo "wolfProvider ok" || echo "MISSING: wolfProvider checkout"

# Check C compiler
cc --version
```

If wolfCrypt or libusb is missing, file a blocker issue and stop. Do not
proceed without them. Install commands:

```bash
# Debian/Ubuntu
sudo apt-get install -y libusb-1.0-0-dev pkg-config

# Fedora/RHEL
sudo dnf install -y libusb1-devel pkgconf
```

---

## Beads Issue Decomposition

**Run this block FIRST, before any code.** Create the epic and all child issues.
Use parallel subagents to create issues simultaneously -- do not create them
sequentially.

### Epic

```bash
bd create \
  --title="wolfP11: unified daemon-free PKCS#11 library" \
  --description="Build a C PKCS#11 shared library that talks directly to USB hardware tokens via libusb+CCID, routes to wolfHSM via WH_DEV_ID callback, and patches wolfProvider to close the devId gap. No pcscd dependency." \
  --type=feature \
  --priority=1
```

Save the epic ID. All child issues must depend on it.

### Child Issues

Spawn **8 parallel subagents**, each creating one issue:

**Subagent 1 -- Build scaffold:**
```bash
bd create \
  --title="Scaffold Makefile and directory layout" \
  --description="Create Makefile with targets: all, test, clean, scan. Wire wolfCrypt and libusb via pkg-config. Produce build/libwolfp11.so and build/wp11. Acceptance: make all succeeds producing both artifacts; make clean removes them; no warnings with -Wall -Wextra." \
  --type=task --priority=1 \
  --acceptance="make all exits 0; file build/libwolfp11.so shows ELF shared object; nm -D build/libwolfp11.so shows C_GetFunctionList symbol; no compiler warnings"
```

**Subagent 2 -- Token database:**
```bash
bd create \
  --title="Implement wp11_token_db: USB VID/PID token table" \
  --description="Define wp11_token_desc_t struct and wh_token_db[] table mapping USB VID/PID to protocol, quirks bitmask, and algo bitmask. Populate with YubiKey 5 series, NitroKey HSM 2, NitroKey Pro 2. Implement wp11_token_db_lookup(vid, pid) returning const wp11_token_desc_t*. Acceptance: unit tests confirm correct lookup for known VID/PIDs and NULL for unknown." \
  --type=task --priority=1 \
  --acceptance="lookup tests for all seeded tokens pass; unknown VID/PID returns NULL; struct layout confirmed by offsetof assertions"
```

**Subagent 3 -- CCID transport:**
```bash
bd create \
  --title="Implement wp11_ccid: CCID framing over libusb" \
  --description="Implement CCID PC_to_RDR_XfrBlock and RDR_to_PC_DataBlock framing over libusb bulk endpoints. Implement wp11_ccid_open(vid, pid), wp11_ccid_apdu(ctx, cmd, cmdlen, resp, resplen), wp11_ccid_close(ctx). Handle CCID status bytes and SW1/SW2 propagation. Acceptance: mock-transport unit tests verify correct CCID framing byte-for-byte against known vectors from the USB CCID spec." \
  --type=task --priority=1 \
  --acceptance="CCID framing tests pass against spec vectors; mock transport layer injectable for tests; wp11_ccid_apdu returns correct SW1/SW2 from response"
```

**Subagent 4 -- PIV protocol:**
```bash
bd create \
  --title="Implement wp11_proto_piv: PIV APDU sequences" \
  --description="Implement NIST SP 800-73 PIV applet operations: SELECT AID, GET DATA (cert/key objects), GENERAL AUTHENTICATE (sign, key agreement), VERIFY (PIN). Map PIV slots 9A/9C/9D/9E to PKCS#11 key objects. Acceptance: APDU sequences verified byte-for-byte against NIST SP 800-73 Annex C test vectors." \
  --type=task --priority=1 \
  --acceptance="SELECT AID APDU matches SP 800-73 Annex C; GENERAL AUTHENTICATE request/response APDUs match known vectors; PIN VERIFY APDU correctly formatted; all tests use external vectors, no self-referential round-trips"
```

**Subagent 5 -- OpenPGP card protocol:**
```bash
bd create \
  --title="Implement wp11_proto_openpgp: OpenPGP card APDU sequences" \
  --description="Implement OpenPGP card spec operations: SELECT AID, GET DATA (DOs: application ID, key fingerprints), INTERNAL AUTHENTICATE, COMPUTE DIGITAL SIGNATURE, VERIFY (PW1/PW3). Map SIG/DEC/AUT subkeys to PKCS#11 key objects. Acceptance: APDU sequences verified against OpenPGP card spec test vectors from gnupg.org." \
  --type=task --priority=1 \
  --acceptance="SELECT AID and GET DATA APDUs match spec; COMPUTE DIGITAL SIGNATURE APDU correctly formatted; VERIFY (PW1) APDU matches spec; external vector source cited in test file header"
```

**Subagent 6 -- PKCS#11 C_* layer:**
```bash
bd create \
  --title="Implement wp11_pkcs11: PKCS#11 2.40 C ABI" \
  --description="Implement the PKCS#11 C_* functions: C_GetFunctionList, C_Initialize/Finalize, C_GetInfo, C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, C_OpenSession, C_CloseSession, C_Login, C_Logout, C_FindObjectsInit/FindObjects/FindObjectsFinal, C_SignInit/Sign, C_VerifyInit/Verify, C_DecryptInit/Decrypt. Map errors to CKR_* codes exhaustively. Acceptance: pkcs11-tool --module build/libwolfp11.so --list-slots exits 0." \
  --type=task --priority=1 \
  --acceptance="pkcs11-tool --module build/libwolfp11.so --list-mechanisms exits 0; C_GetFunctionList returns non-null; all exported symbols present per nm -D; no CKR_GENERAL_ERROR catch-all except truly unexpected paths"
```

**Subagent 7 -- wolfHSM backend:**
```bash
bd create \
  --title="Implement wp11_backend_wolfhsm: WH_DEV_ID callback routing" \
  --description="Register a wc_CryptoCb callback under WH_DEV_ID that dispatches crypto operations to a wolfHSM server via the wolfHSM client API. Implement wp11_backend_wolfhsm_init(config) and wp11_backend_wolfhsm_cleanup(). Acceptance: with a wolfHSM server running in loopback (shared-memory transport), a C_Sign call routes through the callback and returns a valid signature verified by wolfCrypt independently." \
  --type=task --priority=1 \
  --acceptance="wc_CryptoCb callback registered and invoked on sign; signature verified by independent wolfCrypt call with same key; no self-referential test: sign and verify must use different code paths"
```

**Subagent 8 -- wolfProvider devId patch:**
```bash
bd create \
  --title="Patch wolfProvider: propagate devId through key init" \
  --description="In ~/wolfProvider: (1) add devId field to WOLFPROV_CTX in include/wolfprovider/internal.h; (2) add OSSL_PARAM to expose devId configuration; (3) change wc_InitRsaKey to wc_InitRsaKey_ex with ctx->devId in wp_rsa_kmgmt.c; (4) change hardcoded INVALID_DEVID to ctx->devId in wp_ecc_kmgmt.c, wp_dh_kmgmt.c, wp_ecx_kmgmt.c. Acceptance: with WH_DEV_ID configured, openssl dgst -provider wolfprovider routes through the registered wc_CryptoCb callback." \
  --type=task --priority=1 \
  --acceptance="WOLFPROV_CTX has devId field; all key init calls use ctx->devId not INVALID_DEVID literal; openssl dgst with wolfprovider invokes wc_CryptoCb callback (verified by callback hit counter in test)"
```

After creating all issues, add dependencies:

```bash
# Implementation issues depend on scaffold
bd dep add <token_db_id>    <scaffold_id>
bd dep add <ccid_id>        <scaffold_id>
bd dep add <piv_id>         <ccid_id>
bd dep add <openpgp_id>     <ccid_id>
bd dep add <pkcs11_id>      <piv_id>
bd dep add <pkcs11_id>      <openpgp_id>
bd dep add <pkcs11_id>      <token_db_id>
bd dep add <wolfhsm_id>     <pkcs11_id>
bd dep add <provider_id>    <scaffold_id>
```

---

## Repository Layout

Create this exact layout. Do not create files not listed here unless they are
generated artifacts (`build/`, `*.o`, `*.d`).

```
wolfp11/
+-- Makefile
+-- wolfp11/                    # public headers
|   +-- wp11_settings.h         # compile-time configuration macros
|   +-- wp11_pkcs11.h           # PKCS#11 C ABI declarations
|   +-- wp11_token_db.h         # token descriptor type + lookup API
|   +-- wp11_ccid.h             # CCID transport API
|   +-- wp11_proto_piv.h        # PIV protocol API
|   +-- wp11_proto_openpgp.h    # OpenPGP card protocol API
|   +-- wp11_backend.h          # backend registration interface
+-- src/
|   +-- wp11_pkcs11.c           # C_* function implementations
|   +-- wp11_token_db.c         # token database table + lookup
|   +-- wp11_ccid.c             # CCID framing via libusb
|   +-- wp11_proto_piv.c        # PIV APDU sequences (SP 800-73)
|   +-- wp11_proto_openpgp.c    # OpenPGP card APDU sequences
|   +-- wp11_backend_wolfhsm.c  # wolfHSM WH_DEV_ID callback backend
|   +-- wp11_backend_soft.c     # wolfCrypt-direct software backend
|   +-- cli/
|       +-- wp11_cli.c          # CLI tool (main entry point)
+-- test/
|   +-- wp11_test.c             # main test driver
|   +-- wp11_test_token_db.c    # VID/PID lookup tests
|   +-- wp11_test_ccid.c        # CCID framing tests (mock transport)
|   +-- wp11_test_piv.c         # PIV APDU tests (known vectors)
|   +-- wp11_test_openpgp.c     # OpenPGP APDU tests (known vectors)
|   +-- wp11_test_pkcs11.c      # PKCS#11 layer tests
|   +-- vectors/
|       +-- piv_apdu.json       # SP 800-73 Annex C APDU vectors
|       +-- openpgp_apdu.json   # OpenPGP card spec APDU vectors
```

---

## Makefile Specification

```makefile
CC      = cc
CFLAGS  = -Wall -Wextra -Werror -std=c99 -fPIC \
          -I. -I$(WOLFSSL_DIR) \
          $(shell pkg-config --cflags libusb-1.0)
LDFLAGS = $(shell pkg-config --libs libusb-1.0)

WOLFSSL_DIR ?= $(HOME)/wolfssl

SRCS = src/wp11_pkcs11.c \
       src/wp11_token_db.c \
       src/wp11_ccid.c \
       src/wp11_proto_piv.c \
       src/wp11_proto_openpgp.c \
       src/wp11_backend_soft.c

# wolfHSM backend is opt-in
ifdef WOLFHSM
SRCS    += src/wp11_backend_wolfhsm.c
CFLAGS  += -DWOLFP11_CFG_WOLFHSM_BACKEND -I$(WOLFHSM_DIR)
LDFLAGS += -L$(WOLFHSM_DIR)/build -lwolfhsm
endif

BUILD   = build
LIB     = $(BUILD)/libwolfp11.so
CLI     = $(BUILD)/wp11
TEST    = $(BUILD)/wp11_test

.PHONY: all test clean scan

all: $(LIB) $(CLI)

$(LIB): $(SRCS)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) -lwolfssl

$(CLI): src/cli/wp11_cli.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD) -lwolfp11 $(LDFLAGS)

$(TEST): test/wp11_test.c test/wp11_test_*.c $(SRCS)
	$(CC) $(CFLAGS) -DWOLFP11_CFG_TEST -o $@ $^ $(LDFLAGS) -lwolfssl

test: $(TEST)
	$(TEST)

clean:
	rm -rf $(BUILD)

scan:
	scan-build $(MAKE) all
```

---

## Module Specifications

### `wolfp11/wp11_settings.h`

Compile-time configuration. All macros use `WOLFP11_CFG_` prefix.
Defaults must be defined here so callers get sane behavior without flags.

```c
/* Maximum number of simultaneously open sessions */
#ifndef WOLFP11_CFG_MAX_SESSIONS
#define WOLFP11_CFG_MAX_SESSIONS  8
#endif

/* Enable USB hardware token backend (requires libusb) */
/* #define WOLFP11_CFG_USB_BACKEND */

/* Enable wolfHSM server backend (requires wolfHSM) */
/* #define WOLFP11_CFG_WOLFHSM_BACKEND */

/* Enable OpenPGP card protocol (depends on USB backend) */
#ifndef WOLFP11_CFG_OPENPGP
#define WOLFP11_CFG_OPENPGP  1
#endif

/* Guard USB-dependent tests */
/* #define WOLFP11_CFG_TEST_USB */
```

---

### `src/wp11_token_db.c` -- Token Database

**Purpose:** Map USB VID/PID to protocol, quirks, and supported algorithms.

**Token descriptor type:**

```c
typedef enum {
    WP11_PROTO_PIV      = 0,
    WP11_PROTO_OPENPGP  = 1,
    WP11_PROTO_PKCS15   = 2,
} wp11_proto_t;

/* Quirk flags -- bitmask */
#define WP11_QUIRK_NONE           0x00000000
#define WP11_QUIRK_NO_PSS         0x00000001  /* RSA-PSS done client-side */
#define WP11_QUIRK_SHORT_APDU     0x00000002  /* max 255-byte APDU, no extended */

/* Algorithm flags -- bitmask */
#define WP11_ALGO_RSA2048         0x00000001
#define WP11_ALGO_RSA4096         0x00000002
#define WP11_ALGO_EC_P256         0x00000010
#define WP11_ALGO_EC_P384         0x00000020
#define WP11_ALGO_ED25519         0x00000100

typedef struct {
    uint16_t        usb_vid;
    uint16_t        usb_pid;
    const char*     name;
    wp11_proto_t    proto;
    uint32_t        quirks;
    uint32_t        algos;
} wp11_token_desc_t;
```

**Initial table (minimum at launch):**

```c
static const wp11_token_desc_t wp11_token_db[] = {
    /* YubiKey 5 NFC */
    { 0x1050, 0x0407, "YubiKey 5 NFC",        WP11_PROTO_PIV,    WP11_QUIRK_NONE,      WP11_ALGO_RSA2048|WP11_ALGO_EC_P256|WP11_ALGO_EC_P384 },
    /* YubiKey 5C */
    { 0x1050, 0x0406, "YubiKey 5C",            WP11_PROTO_PIV,    WP11_QUIRK_NONE,      WP11_ALGO_RSA2048|WP11_ALGO_EC_P256|WP11_ALGO_EC_P384 },
    /* YubiKey 5 Nano */
    { 0x1050, 0x0410, "YubiKey 5 Nano",        WP11_PROTO_PIV,    WP11_QUIRK_NONE,      WP11_ALGO_RSA2048|WP11_ALGO_EC_P256 },
    /* NitroKey HSM 2 */
    { 0x20A0, 0x4108, "NitroKey HSM 2",        WP11_PROTO_PIV,    WP11_QUIRK_NONE,      WP11_ALGO_RSA2048|WP11_ALGO_EC_P256 },
    /* NitroKey Pro 2 */
    { 0x20A0, 0x4109, "NitroKey Pro 2",        WP11_PROTO_OPENPGP,WP11_QUIRK_NONE,      WP11_ALGO_RSA2048|WP11_ALGO_EC_P256 },
};
```

**Public API:**

```c
const wp11_token_desc_t* wp11_token_db_lookup(uint16_t vid, uint16_t pid);
size_t wp11_token_db_count(void);
```

**Testing:** Unit tests must confirm correct lookup for all seeded tokens,
NULL return for an unknown VID/PID, and that the table is sorted by VID then
PID (binary search is acceptable; linear search is also fine for the expected
table size). Verify `wp11_token_db_count()` matches the array literal element
count using a compile-time assert.

---

### `src/wp11_ccid.c` -- CCID Transport

**Purpose:** Frame ISO 7816 APDUs in CCID messages over libusb bulk transfers.

**CCID framing (PC_to_RDR_XfrBlock, big-endian):**

```
[0]      bMessageType:  0x6F
[1..4]   dwLength:      u32 APDU length
[5]      bSlot:         0x00
[6]      bSeq:          sequence number (incrementing)
[7]      bBWI:          0x00
[8..9]   wLevelParameter: 0x0000
[10..]   abData:        APDU bytes
```

**CCID response (RDR_to_PC_DataBlock):**

```
[0]      bMessageType:  0x80
[1..4]   dwLength:      u32 response APDU length
[5]      bSlot:         0x00
[6]      bSeq:          must match request
[7]      bStatus:       0 = ok; non-zero = error
[8]      bError:        error code if bStatus != 0
[9]      bChainParameter: 0x00
[10..]   abData:        response APDU (ends with SW1 SW2)
```

**Public API:**

```c
typedef struct wp11_ccid_ctx wp11_ccid_ctx_t;

int  wp11_ccid_open(uint16_t vid, uint16_t pid, wp11_ccid_ctx_t **ctx_out);
int  wp11_ccid_apdu(wp11_ccid_ctx_t *ctx,
                    const uint8_t *cmd,  size_t cmdlen,
                    uint8_t       *resp, size_t *resplen);
void wp11_ccid_close(wp11_ccid_ctx_t *ctx);
```

**Mock transport:** The implementation must accept an injectable transport
callback so tests can drive the CCID layer without a physical USB device:

```c
typedef int (*wp11_ccid_transport_fn)(void *userdata,
                                      const uint8_t *out, size_t outlen,
                                      uint8_t       *in,  size_t *inlen);

int wp11_ccid_open_mock(wp11_ccid_transport_fn transport,
                        void *userdata,
                        wp11_ccid_ctx_t **ctx_out);
```

**Testing:** Framing tests must verify byte-for-byte against CCID spec Section
6.1 (PC_to_RDR_XfrBlock) and 6.2 (RDR_to_PC_DataBlock). Do not test against a
real device in CI; use the mock transport. Tests must cover: correct bSeq
incrementing, dwLength set to APDU length, bStatus != 0 returns an error code,
response APDU bytes extracted correctly from abData.

---

### `src/wp11_proto_piv.c` -- PIV Protocol

**Purpose:** Implement the NIST SP 800-73 PIV applet APDU sequences.

**PIV AID:** `A0 00 00 03 08 00 00 10 00 01 00`

**PIV slot to key ID mapping (SP 800-73 Table 4b):**

```c
#define WP11_PIV_SLOT_AUTH     0x9A  /* Card Authentication */
#define WP11_PIV_SLOT_SIGN     0x9C  /* Digital Signature */
#define WP11_PIV_SLOT_KEYMGMT  0x9D  /* Key Management */
#define WP11_PIV_SLOT_CARDAUTH 0x9E  /* Card Authentication */
```

**Key operations:**

- **SELECT AID:** `00 A4 04 00 0B [AID bytes]`
- **VERIFY (PIN):** `00 20 00 80 [len] [PIN bytes]` -- SP 800-73 Section 3.2.1
- **GENERAL AUTHENTICATE (sign):** `00 87 [alg] [slot] [len] [dynamic auth template]`
  - alg `0x07` = RSA-2048, `0x11` = EC P-256, `0x14` = EC P-384
  - Dynamic auth template: `7C [len] 82 00 81 [challenge len] [challenge bytes]`
- **GET DATA:** `00 CB 3F FF [len] 5C 03 [tag bytes]` -- retrieves cert or key metadata

**Public API:**

```c
int wp11_piv_select(wp11_ccid_ctx_t *ccid);
int wp11_piv_verify_pin(wp11_ccid_ctx_t *ccid, const uint8_t *pin, size_t pinlen);
int wp11_piv_sign(wp11_ccid_ctx_t *ccid,
                  uint8_t slot, uint8_t alg,
                  const uint8_t *challenge, size_t challengelen,
                  uint8_t *sig, size_t *siglen);
int wp11_piv_get_cert(wp11_ccid_ctx_t *ccid,
                      uint8_t slot,
                      uint8_t *cert, size_t *certlen);
```

**Test vectors:** All APDU sequence tests must use known-answer vectors derived
from NIST SP 800-73-4, Appendix C. Test vector JSON format:

```json
{
  "test": "GENERAL_AUTHENTICATE_P256",
  "slot": "0x9C",
  "alg": "0x11",
  "challenge_hex": "deadbeef...",
  "expected_apdu_hex": "0087119C...",
  "sw1": "0x90", "sw2": "0x00"
}
```

Tests assert the constructed APDU bytes match `expected_apdu_hex` before
transmission. Never test sign-then-verify with the same wolfCrypt path.

---

### `src/wp11_proto_openpgp.c` -- OpenPGP Card Protocol

**Purpose:** Implement OpenPGP card specification APDU sequences.

**OpenPGP AID prefix:** `D2 76 00 01 24 01` (manufacturer and serial follow)

**Data Objects (DOs) used:**

| DO Tag | Content |
|--------|---------|
| `006E` | Application Related Data (ARD) -- capabilities, key fingerprints |
| `007A` | Security Support Template -- signature counter |
| `00C1` | Algorithm attributes: SIG key |
| `00C2` | Algorithm attributes: DEC key |
| `00C3` | Algorithm attributes: AUT key |

**Key operations:**

- **SELECT AID:** `00 A4 04 00 06 [AID prefix]`
- **GET DATA:** `00 CA [tag high] [tag low] 00`
- **VERIFY (PW1 for sign):** `00 20 00 81 [len] [password bytes]`
- **VERIFY (PW1 for other):** `00 20 00 82 [len] [password bytes]`
- **COMPUTE DIGITAL SIGNATURE:** `00 2A 9E 9A [len] [hash bytes]`
- **INTERNAL AUTHENTICATE:** `00 88 00 00 [len] [data bytes]`
- **DECIPHER:** `00 2A 80 86 [len] [ciphertext bytes]`

**Public API:**

```c
int wp11_openpgp_select(wp11_ccid_ctx_t *ccid);
int wp11_openpgp_verify_pw1(wp11_ccid_ctx_t *ccid,
                             const uint8_t *pw, size_t pwlen, int mode);
int wp11_openpgp_sign(wp11_ccid_ctx_t *ccid,
                      const uint8_t *hash, size_t hashlen,
                      uint8_t *sig, size_t *siglen);
int wp11_openpgp_authenticate(wp11_ccid_ctx_t *ccid,
                               const uint8_t *data, size_t datalen,
                               uint8_t *resp, size_t *resplen);
int wp11_openpgp_get_ard(wp11_ccid_ctx_t *ccid,
                          uint8_t *buf, size_t *buflen);
```

**Testing:** Same pattern as PIV. APDU tests use known-answer vectors from the
OpenPGP card specification (gnupg.org). Every test file must include a header
comment citing the specific spec section and version.

---

### `src/wp11_pkcs11.c` -- PKCS#11 C ABI

**Purpose:** Implement the PKCS#11 2.40 C_* functions. This is the integration
layer that sits above the protocol modules and below the application.

**Mandatory exports (minimum viable for pkcs11-tool and p11-kit):**

```
C_GetFunctionList        -- bootstrap; must be present and correct
C_Initialize             -- set up global state
C_Finalize               -- tear down
C_GetInfo                -- library metadata
C_GetSlotList            -- enumerate slots (one per detected token)
C_GetSlotInfo            -- slot metadata
C_GetTokenInfo           -- token metadata (label, flags, etc.)
C_GetMechanismList       -- list supported mechanisms for a slot
C_GetMechanismInfo       -- mechanism metadata
C_OpenSession            -- allocate session handle
C_CloseSession           -- release session
C_CloseAllSessions       -- release all sessions for a slot
C_GetSessionInfo         -- session state
C_Login                  -- authenticate (PIN)
C_Logout                 -- deauthenticate
C_FindObjectsInit        -- begin object search
C_FindObjects            -- enumerate key/cert objects
C_FindObjectsFinal       -- end object search
C_GetAttributeValue      -- read CKA_* attributes from an object
C_SignInit               -- select mechanism and key for signing
C_Sign                   -- produce signature
C_VerifyInit             -- select mechanism and key for verification
C_Verify                 -- check signature
C_DecryptInit            -- select mechanism and key for decryption
C_Decrypt                -- decrypt ciphertext
```

**Error mapping:** Every CKR_* code must be returned precisely. No
`CKR_GENERAL_ERROR` unless a condition genuinely has no more specific code.
Map at minimum:

- `CKR_TOKEN_NOT_PRESENT` -- no USB token detected for this slot
- `CKR_USER_NOT_LOGGED_IN` -- crypto/object op without prior C_Login
- `CKR_USER_ALREADY_LOGGED_IN` -- C_Login when already logged in
- `CKR_PIN_INCORRECT` -- wrong PIN (from token SW `63 Cx`)
- `CKR_PIN_LOCKED` -- PIN locked (from token SW `69 83`)
- `CKR_MECHANISM_INVALID` -- unsupported CKM_* for this token
- `CKR_KEY_TYPE_INCONSISTENT` -- wrong key type for mechanism
- `CKR_DEVICE_REMOVED` -- token unplugged during operation
- `CKR_BUFFER_TOO_SMALL` -- output buffer smaller than required

**Testing:** Use `pkcs11-tool` as the primary external oracle:

```bash
pkcs11-tool --module build/libwolfp11.so --list-slots
pkcs11-tool --module build/libwolfp11.so --list-mechanisms
```

Tests that require a hardware token are guarded by `WOLFP11_CFG_TEST_USB`.
All other tests use the software backend.

---

### `src/wp11_backend_wolfhsm.c` -- wolfHSM Backend

**Purpose:** Register a `wc_CryptoCb` callback under `WH_DEV_ID` that
dispatches crypto operations to a wolfHSM server.

**Integration point:** wolfHSM's `WH_DEV_ID = 0x5748534D`. wolfCrypt calls the
registered callback for any key initialized with this devId. The callback
receives a `wc_CryptoInfo` struct describing the operation; the backend
serializes it as an RPC call to the wolfHSM server.

**Public API:**

```c
typedef struct {
    /* wolfHSM client config -- transport, server address, etc. */
    whClientConfig wolfhsm_config;
} wp11_backend_wolfhsm_cfg_t;

int  wp11_backend_wolfhsm_init(const wp11_backend_wolfhsm_cfg_t *cfg);
void wp11_backend_wolfhsm_cleanup(void);
```

**Testing:** Requires a wolfHSM server running in loopback (shared-memory
transport). Test must:
1. Start a wolfHSM server thread using `wh_transport_mem`
2. Initialize the backend with shared-memory config
3. Perform a C_Sign call through the PKCS#11 layer
4. Verify the resulting signature using wolfCrypt directly (independent path)
5. Assert that the wolfHSM callback was invoked (add a hit counter to the test
   server's handler)

Do NOT verify by signing and then decrypting with the same wolfHSM server
call. Sign -> wolfCrypt verify is the required oracle pattern.

---

### wolfProvider devId fix -- pending upstream

The wolfProvider devId gap fix has been submitted upstream as
`wolfSSL/wolfProvider#390`. No local patch file. Once that PR merges,
update this section with integration instructions.

---

## Test Integrity Rules (CRITICAL)

These rules apply to every test in this project. Violations are build failures.

1. **External oracle for all crypto correctness.** Signature tests use
   `openssl dgst -verify` or independent wolfCrypt verify as the oracle.
   Never sign and verify with the same code path in the same test.

2. **Known-answer vectors for all APDU sequences.** PIV and OpenPGP card
   APDU tests use vectors derived from the relevant specification (SP 800-73
   Annex C, OpenPGP card spec test annex). Test files must cite the source
   spec and section in a header comment.

3. **wolfCrypt primitive correctness is not re-tested here.** wolfCrypt has
   its own NIST CAVP conformance suite. wolfP11 tests validate plumbing
   (APDU framing, callback routing, PKCS#11 error mapping) -- not AES, RSA,
   or ECDSA correctness.

4. **Vector files must be non-empty.** Each test that loads a JSON vector
   file must assert `count > 0` before running. An empty vector file must
   cause a test failure, not a vacuous pass.

5. **Hardware-dependent tests are gated.** Any test requiring a physical USB
   token is compiled only when `WOLFP11_CFG_TEST_USB` is defined. CI runs
   without this flag. Hardware tests require a YubiKey 5 or NitroKey HSM 2
   to be connected and must be documented as such.

6. **No self-referential round-trips for crypto.** The pattern
   `sign(data) -> verify(data, sig)` where both sides call wolfP11 is
   prohibited. It proves only that the code runs without crashing.
