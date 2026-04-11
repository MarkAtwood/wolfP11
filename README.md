# wolfP11

A daemon-free PKCS#11 library for USB hardware tokens and wolfHSM, built on wolfCrypt and libusb.

**License:** GPL-3.0 or commercial (wolfSSL Inc.)
**Version:** 0.1.0
**Language:** C99 (C90-compatible for embedded targets)

---

## What is wolfP11?

wolfP11 is a PKCS#11 2.40 shared library (`libwolfp11.so`) that connects applications to hardware security keys through a single standard interface. It supports three backends:

- **USB hardware tokens** -- YubiKey, NitroKey, Feitian, CAC/PIV cards; communicates directly over libusb with no pcscd or any system daemon required
- **wolfHSM server** -- routes PKCS#11 operations to a wolfHSM server over shared memory or TCP; the private key never leaves the secure enclave
- **USB flash drive keystore** -- encrypted `.p11k` keystore files on removable USB storage, hotplug-detected via inotify; physical possession without dedicated hardware
- **Filesystem directory keystore** -- watches a configured directory for `.p11k` files via inotify; works with tmpfs, LUKS, or any mounted volume; no USB required

Any PKCS#11-aware application -- OpenSSL, GnuTLS, SSH agents, signing tools -- works against any backend with no code changes.

## Why wolfP11 exists

Every PKCS#11 driver for USB hardware tokens available today -- ykcs11, OpenSC, and all vendor middleware -- requires pcscd, a privileged system daemon. On a developer workstation with a full Linux desktop, pcscd is an inconvenience. On a Raspberry Pi running Yocto, in a Docker container, in a Kubernetes sidecar, or on a custom embedded board, pcscd is a hard blocker. Teams end up choosing between a hardware token with an unusable software stack and a software token with no physical key possession. wolfP11 removes that choice.

wolfP11 also solves a fragmentation problem within the wolfSSL ecosystem. A team running wolfHSM on a secure core, YubiKeys on developer workstations, and OpenSSL tooling in CI previously needed three PKCS#11 stacks with three setup procedures. wolfP11 is one library that sits behind all three without requiring application changes.

Finally, wolfP11 closes a gap in wolfProvider. wolfProvider hardcodes `INVALID_DEVID` in all key initialization calls, silently bypassing wolfCrypt's device callback layer and making it impossible to route OpenSSL operations through wolfHSM. The wolfProvider patch included in wolfP11 closes this gap, completing the chain: OpenSSL CLI -> wolfProvider -> wolfCrypt -> wolfHSM server or USB token.

### Why not OpenSC?

OpenSC is the right choice when pcscd is available and token breadth matters. wolfP11 exists for contexts where OpenSC cannot be used:

- **No pcscd dependency** -- wolfP11 is entirely self-contained; OpenSC requires the PC/SC daemon
- **Container and embedded friendly** -- single `.so`, no system services, no root required
- **wolfCrypt is the crypto engine** -- consistent with wolfSSL ecosystem deployments; no OpenSSL dependency in the library itself
- **wolfHSM integration** -- PKCS#11 operations route transparently to a wolfHSM server; no equivalent exists in OpenSC
- **Table-driven token support** -- adding a token that follows PIV or OpenPGP is one row in a table, not a new driver file

---

## Architecture

```
OpenSSL 3.x CLI / application
        |
        v
wolfP11 OpenSSL provider  (requires wolfProvider devId patch; see PR #390)
        |
        v
wolfP11 PKCS#11 layer     (C_* functions -- libwolfp11.so)
        |
        v
   [backend selector]
   +-- wolfHSM server      (wolfHSM client -> WH_DEV_ID callback -> RPC)
   +-- USB hardware token  (libusb -> CCID -> ISO 7816 -> PIV / OpenPGP)
   +-- soft token          (wolfCrypt direct, no hardware)
```

### Module map

| Module | Files | Purpose |
|--------|-------|---------|
| PKCS#11 layer | `wolfp11/wp11_pkcs11.h`, `src/wp11_pkcs11.c` | C_* function implementations |
| Token database | `wolfp11/wp11_token_db.h`, `src/wp11_token_db.c` | VID/PID -> protocol/quirks/algo table |
| CCID transport | `wolfp11/wp11_ccid.h`, `src/wp11_ccid.c` | USB bulk <-> CCID framing via libusb |
| PIV protocol | `wolfp11/wp11_proto_piv.h`, `src/wp11_proto_piv.c` | NIST SP 800-73 APDU sequences |
| OpenPGP protocol | `wolfp11/wp11_proto_openpgp.h`, `src/wp11_proto_openpgp.c` | OpenPGP card APDU sequences |
| Backend interface | `wolfp11/wp11_backend.h` | Sign/verify/decrypt dispatch table |
| Soft token backend | `src/wp11_backend_soft.c` | wolfCrypt direct (no hardware) |
| USB flash keystore | `wolfp11/wp11_keystore.h`, `src/wp11_keystore.c` | AES-256-GCM + PBKDF2 encrypted `.p11k` file format; inotify hotplug |
| USB flash backend | `src/wp11_backend_usb_flash.c` | sign/verify/decrypt against loaded `.p11k` keystore |
| FSDIR backend | `src/wp11_backend_fsdir.c` | sign/verify/decrypt for `.p11k` keystores in a watched directory |
| wolfHSM backend | `wolfp11/wp11_backend.h`, `src/wp11_backend_wolfhsm.c` | wolfHSM client integration |
| Settings | `wolfp11/wp11_settings.h` | Compile-time configuration defaults |
| CLI | `src/cli/wp11_cli.c` | `wp11` command-line tool |

### wolfCrypt integration

wolfCrypt is the crypto engine for all backends. Three things are outside wolfCrypt's scope that wolfP11 supplies:

| Layer | wolfCrypt provides | wolfP11 provides |
|-------|--------------------|------------------|
| Key model | DER/PEM and raw structs (`RsaKey`, `ecc_key`) | PKCS#11 `CKA_*` attribute model; bridging from DER to CK objects |
| Key storage | None | Encrypted `.p11k` keystore on disk (`wp11_keystore.c`) |
| Enclave backends | `devId` callback hook | wolfHSM client (uses the hook); USB CCID transport |

Platform secure enclaves (SGX, TrustZone, Apple Secure Enclave) are not abstracted by wolfCrypt. The wolfHSM devId integration is the current path for hardware security; other enclave targets would need new backends.

---

## Supported Hardware

| Token | USB VID:PID | Protocol | Algorithms |
|-------|-------------|----------|------------|
| YubiKey 5 NFC | 1050:0407 | PIV | RSA-2048, EC P-256, EC P-384 |
| YubiKey 5C | 1050:0406 | PIV | RSA-2048, EC P-256, EC P-384 |
| YubiKey 5 Nano | 1050:0410 | PIV | RSA-2048, EC P-256, EC P-384 |
| NitroKey HSM 2 | 20A0:4108 | PIV | RSA-2048, EC P-256 |
| NitroKey Pro 2 | 20A0:4109 | OpenPGP | RSA-2048, EC P-256 |

Any token following the PIV (NIST SP 800-73) or OpenPGP card specifications can be added with one row in `src/wp11_token_db.c`. See [Adding a new token](#adding-a-new-token) below.

### Token protocols

| Protocol | Specification | Coverage |
|----------|---------------|----------|
| PIV | NIST SP 800-73-4 | YubiKey 5 series, NitroKey HSM 2, CAC/PIV cards, many Feitian tokens |
| OpenPGP card | OpenPGP card spec v3.4 (gnupg.org) | NitroKey Pro 2, Gnuk, Feitian OpenPGP tokens |
| PKCS#15 | ISO 7816-15 | Generic fallback for compliant tokens (planned) |

---

## Build Requirements

| Dependency | Package (Debian/Ubuntu) | Notes |
|------------|------------------------|-------|
| C compiler | `build-essential` | gcc or clang; C99 required |
| wolfCrypt | *(from source)* | `~/wolfssl` -- must be built and installed |
| libusb | `libusb-1.0-0-dev` | Required for USB token support |
| pkg-config | `pkg-config` | Used by Makefile to locate wolfssl and libusb |
| p11-kit headers | `libp11-kit-dev` | Provides standard `<p11-kit/pkcs11.h>` PKCS#11 types |

wolfHSM backend (optional):

| Dependency | Notes |
|------------|-------|
| wolfHSM | `~/wolfHSM` -- build separately; enable with `WOLFHSM=1` |

Install on Debian/Ubuntu:

```sh
sudo apt-get install build-essential libusb-1.0-0-dev pkg-config libp11-kit-dev
```

wolfCrypt must be built from source and installed so that `pkg-config --cflags wolfssl` works:

```sh
cd ~/wolfssl
./autogen.sh
./configure --enable-ecc --enable-rsapss --enable-keygen
make
sudo make install
sudo ldconfig
```

---

## Building

```sh
# Build the shared library and CLI tool
make

# Run the test suite
make test

# Build with wolfHSM backend
make WOLFHSM=1 WOLFHSM_DIR=~/wolfHSM

# Run static analysis (requires clang scan-build)
make scan

# Install to /usr/local (override with PREFIX=/path)
sudo make install
sudo ldconfig

# Uninstall
sudo make uninstall

# Run tests with AddressSanitizer + UBSan
make test-asan

# Run tests with UndefinedBehaviorSanitizer only
make test-ubsan

# Remove build artifacts
make clean
```

Build outputs:

| Output | Description |
|--------|-------------|
| `build/libwolfp11.so` | PKCS#11 shared library -- load this with your application |
| `build/wp11` | Command-line tool for inspecting tokens |
| `build/wp11_test` | Test suite binary |

---

## Using the Library

### As a PKCS#11 module

Any PKCS#11-aware application can load `libwolfp11.so` as a module. The library exports `C_GetFunctionList` as its bootstrap symbol; all other C_* functions are accessible through the returned function list.

**OpenSSL 3.x (via pkcs11-provider or wolfP11 OpenSSL provider):**

```sh
openssl pkeyutl -sign -inkey 'pkcs11:token=YubiKey%205%20NFC;id=%01' \
    -keyform engine -engine pkcs11 -in hash.bin -out sig.bin
```

**ssh-agent / ssh:**

```sh
ssh-add -s /path/to/build/libwolfp11.so
ssh user@host
```

**p11tool (GnuTLS):**

```sh
p11tool --list-tokens --provider /path/to/build/libwolfp11.so
p11tool --list-all --provider /path/to/build/libwolfp11.so
```

**pkcs11-tool (OpenSC suite):**

```sh
pkcs11-tool --module build/libwolfp11.so --list-slots
pkcs11-tool --module build/libwolfp11.so --list-objects --login
```

### Runtime loading

```c
#include <dlfcn.h>
#include <p11-kit/pkcs11.h>

void *h = dlopen("libwolfp11.so", RTLD_NOW);
CK_C_GetFunctionList get_fn_list = dlsym(h, "C_GetFunctionList");

CK_FUNCTION_LIST_PTR fn;
get_fn_list(&fn);

fn->C_Initialize(NULL);
/* use fn->C_OpenSession, fn->C_Sign, etc. */
fn->C_Finalize(NULL);
```

### Static linking

All C_* functions are exported as regular symbols, so static linking works without going through the function list:

```c
#include "wolfp11/wp11_pkcs11.h"

C_Initialize(NULL);
/* ... */
C_Finalize(NULL);
```

---

## CLI Tool

```
wp11 <command> [arguments]

Commands:
  version                    Print the library version string
  list-tokens                List all token slots and their labels
  list-mechanisms <slot>     List supported mechanisms for a slot
  help                       Print this help
```

Examples:

```sh
# Show library version
./build/wp11 version

# List all detected token slots
./build/wp11 list-tokens

# List mechanisms available on slot 0
./build/wp11 list-mechanisms 0
```

---

## Supported Mechanisms

The following mechanisms are implemented and tested in the soft token backend:

| Mechanism | wolfCrypt API |
|-----------|---------------|
| `CKM_RSA_PKCS` | `wc_RsaSSL_Sign` / `wc_RsaSSL_Verify` |
| `CKM_RSA_PKCS_OAEP` | `wc_RsaPublicEncrypt_ex` / `wc_RsaPrivateDecrypt_ex` (`WC_RSA_OAEP_PAD`) |
| `CKM_RSA_PKCS_PSS` | `wc_RsaPSS_Sign` / `wc_RsaPSS_VerifyCheck` |
| `CKM_AES_GCM` | `wc_AesGcmEncrypt` / `wc_AesGcmDecrypt` |
| `CKM_ECDSA` | `wc_ecc_sign_hash` / `wc_ecc_verify_hash` |
| `CKM_ECDSA_SHA256` | hash-then-sign via wolfCrypt |
| `CKM_EDDSA` (Ed25519) | `wc_ed25519_sign_msg` / `wc_ed25519_verify_msg` |
| `C_GenerateKeyPair` (ECC P-256/P-384, RSA, Ed25519) | `wc_ecc_make_key` / `wc_MakeRsaKey` / `wc_ed25519_make_key` |
| `C_DeriveKey` (ECDH P-256/P-384) | `wc_ecc_shared_secret` |

---

## Compile-Time Configuration

All configuration macros use the `WOLFP11_CFG_` prefix. Defaults are in `wolfp11/wp11_settings.h`; override with `-D` on the compiler command line.

| Macro | Default | Description |
|-------|---------|-------------|
| `WOLFP11_CFG_MAX_SESSIONS` | `8` | Maximum simultaneously open sessions [1-256] |
| `WOLFP11_CFG_MAX_SLOTS` | `16` | Maximum slots (soft + USB) [1-256] |
| `WOLFP11_CFG_OPENPGP` | `1` | Enable OpenPGP card protocol |
| `WOLFP11_CFG_USB_BACKEND` | *(undefined)* | Enable USB hardware token backend |
| `WOLFP11_CFG_WOLFHSM_BACKEND` | *(undefined)* | Enable wolfHSM server backend |
| `WOLFP11_CFG_USB_FLASH_BACKEND` | *(undefined)* | Enable USB flash drive keystore backend |
| `WOLFP11_CFG_USB_FLASH_WATCH_DIR` | `"/run/media"` | Directory inotify watches for `.p11k` files (USB flash backend) |
| `WOLFP11_CFG_FSDIR_BACKEND` | *(undefined)* | Enable filesystem directory keystore backend |
| `WOLFP11_CFG_FSDIR_PATH` | `"/var/lib/wolfp11"` | Directory inotify watches for `.p11k` files (FSDIR backend) |
| `WOLFP11_CFG_TEST_USB` | *(undefined)* | Enable hardware-dependent tests |
| `WOLFP11_CFG_TEST_INOTIFY` | *(undefined)* | Enable timing-sensitive inotify arrival/departure tests |

---

## Testing

```sh
make test
```

The test suite covers all modules with mock transports; no hardware is required for the default test run. Hardware-dependent tests are compiled only when `WOLFP11_CFG_TEST_USB` is defined.

Test design rules:

- Tests use independent oracles: known test vectors and cross-validation between backends
- No test uses the code under test as its own oracle
- Mock CCID transport is injectable via `wp11_ccid_open_mock()` -- all APDU tests run against the mock, not a real card

---

## Adding a New Token

If the token follows PIV or OpenPGP, add one row to the table in `src/wp11_token_db.c`:

```c
static const wp11_token_desc_t wp11_token_db[] = {
    /* existing entries ... */

    {
        .usb_vid = 0xABCD,
        .usb_pid = 0x1234,
        .name    = "My Token v2",
        .proto   = WP11_PROTO_PIV,
        .quirks  = WP11_QUIRK_NONE,
        .algos   = WP11_ALGO_RSA2048 | WP11_ALGO_EC_P256,
    },
};
```

**Protocol constants:**

| Constant | Meaning |
|----------|---------|
| `WP11_PROTO_PIV` | NIST SP 800-73 PIV applet |
| `WP11_PROTO_OPENPGP` | OpenPGP card spec v3.4 |
| `WP11_PROTO_PKCS15` | ISO 7816-15 (planned) |

**Quirk flags:**

| Flag | Meaning |
|------|---------|
| `WP11_QUIRK_NONE` | No quirks |
| `WP11_QUIRK_NO_PSS` | Token does not support RSA-PSS; wolfCrypt does PSS padding client-side before sending to token |
| `WP11_QUIRK_SHORT_APDU` | Token only accepts APDUs up to 255 bytes (no extended length) |

**Algorithm flags** (OR together):

| Flag | Meaning |
|------|---------|
| `WP11_ALGO_RSA2048` | RSA 2048-bit |
| `WP11_ALGO_RSA4096` | RSA 4096-bit |
| `WP11_ALGO_EC_P256` | ECDSA / ECDH P-256 |
| `WP11_ALGO_EC_P384` | ECDSA / ECDH P-384 |
| `WP11_ALGO_ED25519` | Ed25519 (where supported) |

If the token has non-standard APDU behavior that is not covered by the quirk flags, add a new quirk constant and a branch in the protocol source (`src/wp11_proto_piv.c` or `src/wp11_proto_openpgp.c`).

---

## Repository Layout

```
wolfP11/
+-- wolfp11/                 Public headers (install alongside .so)
|   +-- wp11_settings.h      Compile-time configuration
|   +-- wp11_pkcs11.h        PKCS#11 C_* entry points
|   +-- wp11_token_db.h      Token descriptor types and lookup API
|   +-- wp11_ccid.h          CCID transport API
|   +-- wp11_proto_piv.h     PIV protocol API
|   +-- wp11_proto_openpgp.h OpenPGP card protocol API
|   +-- wp11_backend.h       Backend dispatch table
|   +-- wp11_keystore.h      Encrypted .p11k keystore API
|   +-- wp11_soft_key.h      Soft key types (test builds only)
+-- src/                     Implementation files
|   +-- wp11_pkcs11.c        PKCS#11 layer
|   +-- wp11_token_db.c      Token database (VID/PID table)
|   +-- wp11_ccid.c          CCID/USB transport
|   +-- wp11_proto_piv.c     PIV APDU sequences
|   +-- wp11_proto_openpgp.c OpenPGP card APDU sequences
|   +-- wp11_backend_soft.c  wolfCrypt soft token backend
|   +-- wp11_keystore.c      Encrypted .p11k keystore (AES-256-GCM, PBKDF2, mlock)
|   +-- wp11_backend_usb_flash.c  USB flash drive keystore backend
|   +-- wp11_backend_fsdir.c      Filesystem directory keystore backend
|   +-- cli/
|       +-- wp11_cli.c       wp11 command-line tool
+-- test/
|   +-- wp11_test.c          Main test driver
|   +-- wp11_test_token_db.c Token database tests
|   +-- wp11_test_ccid.c     CCID transport tests
|   +-- wp11_test_piv.c      PIV protocol tests (mock transport)
|   +-- wp11_test_openpgp.c  OpenPGP card tests (mock transport)
|   +-- wp11_test_pkcs11.c   PKCS#11 layer tests
|   +-- wp11_test_keystore.c Keystore and flash backend tests
|   +-- wp11_test_backend_soft.c  Soft backend unit tests
|   +-- wp11_test_fsdir.c   Filesystem directory backend integration tests
|   +-- vectors/             APDU test reference data (JSON, spec-derived)
+-- Makefile
+-- BUILD.md                 Agentic build specification
+-- PRFAQ.md                 Press release and FAQ
```

---

## Future Plans

### Virtual PIV card (present as a PIV token)

wolfP11 currently drives hardware PIV tokens as a reader. A planned companion feature inverts this: wolfP11 presents itself _as_ a PIV card so that any PIV-aware application can talk to wolfP11's soft or HSM-backed keys without knowing about PKCS#11 at all.

The implementation requires an APDU responder that handles the six PIV commands (SELECT, VERIFY, GET DATA, GENERAL AUTHENTICATE, CHANGE REFERENCE DATA, GENERATE ASYMMETRIC KEY PAIR) and routes crypto operations to the existing soft or wolfHSM backend. The existing `wp11_proto_piv.c` client code serves as both implementation reference and test oracle for the responder.

Applications connect to the virtual card via a Unix socket using the gpg `--card-device` protocol, which avoids any pcscd dependency. USB gadget emulation (presenting as a physical USB CCID device) is a further option for hardware with Linux USB gadget support.

### Virtual OpenPGP Card 3.4 (present as an OpenPGP token)

The same responder architecture applies to OpenPGP card 3.4. wolfP11's keys would appear to gpg, gpg-agent, and any other OpenPGP card client as a hardware OpenPGP card, enabling smartcard-backed gpg signing and decryption with no hardware token required.

OpenPGP is more complex than PIV: the Application Related Data object (DO 006E) is deeply nested BER-TLV that gpg validates strictly before accepting a card, and a persistent signature counter is mandatory per the spec. The remaining commands (PSO:COMPUTE DIGITAL SIGNATURE, INTERNAL AUTHENTICATE, PSO:DECIPHER, PUT DATA, GENERATE ASYMMETRIC KEY PAIR) map straightforwardly onto wolfCrypt operations.

### wolfTPM backend

wolfSSL's wolfTPM library provides a portable TPM 2.0 interface. Adding a wolfTPM backend to wolfP11 would give hardware-backed key storage on any machine with a TPM 2.0 chip — which includes virtually all modern x86 boards and many ARM boards — with no USB token and no separate secure enclave server required.

TPM belongs in wolfP11 rather than wolfHSM because a TPM is a chip on the same board accessible from the main OS via kernel driver. wolfHSM is designed for isolated execution environments (TrustZone secure world, separate MCU); routing wolfP11 through wolfHSM to reach a local TPM would add a layer without adding a security boundary.

Most PKCS#11 mechanisms map cleanly onto wolfTPM: RSA sign/verify (`TPM_ALG_RSASSA`), RSA-PSS (`TPM_ALG_RSAPSS`), ECDSA over P-256/P-384, ECDH, RSA-OAEP, persistent key storage via `TPM2_EvictControl`, and key import. Three gaps are worth noting upfront:

- **Ed25519**: the TPM 2.0 specification does not define Ed25519; `CKM_EDDSA` cannot be satisfied by any TPM command. The wolfTPM backend would document this as unsupported.
- **RSA-OAEP with non-empty label**: wolfTPM's `wolfTPM2_RsaEncrypt` / `wolfTPM2_RsaDecrypt` always send a zero-length label despite the underlying `TPM2_RSA_Encrypt` struct supporting it (the label field is `#if 0`'d in the wrapper). A `wolfTPM2_RsaEncryptLabel` variant would close this gap; this is a one-function addition to wolfTPM.
- **RSA-PSS salt length**: the TPM always uses `sLen = hLen`; `CK_RSA_PKCS_PSS_PARAMS.sLen` cannot be overridden. The backend would reject or document non-standard salt lengths.

### OpenSSL 3.x provider

wolfP11 is designed to sit behind an OpenSSL 3.x provider that routes OpenSSL operations through any wolfP11 backend. The architecture diagram shows this path, but it is currently blocked on [wolfSSL/wolfProvider#390](https://github.com/wolfSSL/wolfProvider/pull/390), which closes the `INVALID_DEVID` gap in wolfProvider. Once that PR merges, completing the provider integration is a priority.

### USB token forwarding over network

wolfP11's daemon-free design makes it a natural forwarding layer: a wolfP11 instance on a machine with a physically attached USB token could expose that token's operations over a Unix or TCP socket to containers, VMs, or remote hosts on the same network. This fills a gap that wolfHSM does not cover — wolfHSM handles remote access to keys stored in a secure enclave, but not forwarding of a USB token's CCID interface.

### Broad key import for USB flash and filesystem directory keystores

The USB flash and filesystem directory backends currently accept private keys in SEC1 DER (ECC) or PKCS#1 DER (RSA) form. The planned target is full parity with the [soft_PKCS11](https://github.com/MarkAtwood/soft_PKCS11) reference implementation, which auto-detects and imports keys from every format a developer or operator is likely to encounter:

**Private key containers:**
- PEM `RSA PRIVATE KEY` (PKCS#1), `EC PRIVATE KEY` (SEC1), `PRIVATE KEY` (PKCS#8 unencrypted)
- PEM `ENCRYPTED PRIVATE KEY` (PKCS#8 encrypted — PBES2/PBKDF2 + AES, and PKCS#12 PBE)
- PKCS#12 / PFX — multi-key files; certificates from CertBags paired to keys by `localKeyID`
- OpenSSH private key format (new `openssh-key-v1` format; passphrase-protected with bcrypt + AES-256-CTR)
- PuTTY PPK v2 (SHA-1-HMAC + AES-256-CBC) and PPK v3 (Argon2 + AES-256-CBC)
- JKS and JCEKS Java keystores (PKCS#8-wrapped private keys)
- OpenPGP secret key packets (armored and binary; RSA and ECDSA primary or subkeys)
- GCP service account JSON (`private_key` field)
- Bare DER — auto-detected as PKCS#1, PKCS#8, or SEC1 by structure

**Certificates:** DER or PEM X.509, stored alongside the key as `CKO_CERTIFICATE` objects. PKCS#12 certificates are paired to their key by `localKeyID` automatically.

**Key algorithms:** RSA (all sizes), EC P-256, EC P-384, Ed25519.

**Post-quantum (planned with wolfCrypt PQC support):** ML-DSA-44/65/87 (`CKM_ML_DSA`) and ML-KEM-512/768/1024 (`CKM_ML_KEM`), matching the PQC key types in the soft_PKCS11 reference.

Format detection is by content (magic bytes, PEM headers, ASN.1 structure), not file extension, so users can import keys without renaming them.

### Full provisioning CLI

The current `wp11` CLI covers inspection (list tokens, list mechanisms). A full provisioning CLI would add: generate key pair, import certificate into a slot, export public key, change PIN, and backup/restore keystore. This would make wolfP11 self-contained for token provisioning without depending on OpenSC tools.

---

## Known Limitations

### wolfProvider — OpenSSL integration blocked on PR #390

wolfProvider hardcodes `INVALID_DEVID` in all key init calls, bypassing wolfCrypt's device callback mechanism. A fix has been submitted upstream as [wolfSSL/wolfProvider#390](https://github.com/wolfSSL/wolfProvider/pull/390). Until that PR merges, the OpenSSL provider layer in the architecture diagram is not functional.

### wolfHSM backend — known limitations

The wolfHSM client API exposes raw RSA modular exponentiation and raw ECDSA. Three features would require wolfHSM upstream additions before wolfP11 can implement them:

| Feature | Status |
|---------|--------|
| RSA-PSS and RSA-OAEP | Not implementable on raw mod-exp; needs wolfHSM native PSS/OAEP support |
| Server-side hash-then-sign | `CKM_ECDSA_SHA256` hashes the message locally before sending digest to server; wolfHSM would need a combined hash-and-sign operation to keep the hash inside the enclave |
| Key enumeration | No API to list key IDs present on the server; keys must be tracked out-of-band after `C_GenerateKeyPair` |

---

## Related Projects

| Project | Role |
|---------|------|
| [wolfSSL / wolfCrypt](https://github.com/wolfSSL/wolfssl) | Crypto engine; all algorithm implementations |
| [wolfProvider](https://github.com/wolfSSL/wolfProvider) | OpenSSL 3.x provider wrapping wolfCrypt; devId routing fix pending [PR #390](https://github.com/wolfSSL/wolfProvider/pull/390) |
| [wolfHSM](https://github.com/wolfSSL/wolfHSM) | HSM server; wolfP11 can route PKCS#11 calls to it via WH_DEV_ID |

---

## Commercial Support and Licensing

wolfSSL Inc. provides commercial support, consulting, integration services, NRE, and porting work for wolfP11 and for the wolfSSL ecosystem (wolfCrypt, wolfHSM, wolfProvider) that underlies it. Commercial licenses for wolfSSL are also available for deployments where the GPL-3.0 copyleft terms are not acceptable.

| Need | Contact |
|------|---------|
| General questions, porting, FIPS | facts@wolfssl.com |
| Commercial licensing | licensing@wolfssl.com |
| Technical support | support@wolfssl.com |
| Phone | +1 (425) 245-8247 |
| Web | https://www.wolfssl.com/contact/ |

---

## License

wolfP11 is copyright (C) 2026 wolfSSL Inc. and is dual-licensed:

**GPL-3.0** — free for open-source use under the GNU General Public License
v3.0. See [https://www.gnu.org/licenses/gpl-3.0.html](https://www.gnu.org/licenses/gpl-3.0.html) or the `LICENSE` file at the root of this repository.

**Commercial** — if the GPL-3.0 copyleft terms are not acceptable for your
deployment (proprietary product, closed-source distribution, OEM embedding),
wolfSSL Inc. sells commercial licenses that remove the copyleft obligation.
Contact [licensing@wolfssl.com](mailto:licensing@wolfssl.com) or
+1 (425) 245-8247.

**wolfSSL / wolfCrypt** (required dependency): the same dual-license applies —
GPL-3.0 for open-source use, or a commercial license from wolfSSL Inc. for
proprietary deployments. Distributing a product that links wolfP11 against
wolfSSL under GPL-3.0 subjects the combined work to GPL-3.0 copyleft.

**FIPS 140-3**: wolfCrypt holds a current FIPS 140-3 certificate (#4718).
FIPS-ready deployments require the separately licensed wolfCrypt FIPS
boundary build; the standard open-source wolfSSL build is not a validated
module.
