# wolfP11

A daemon-free PKCS#11 library for USB hardware tokens and wolfHSM, built on wolfCrypt and libusb.

**License:** GPL-3.0
**Version:** 0.1.0
**Language:** C99 (C90-compatible for embedded targets)

---

## What is wolfP11?

wolfP11 is a PKCS#11 2.40 shared library (`libwolfp11.so`) that connects applications to hardware security keys through a single standard interface. It supports three backends:

- **USB hardware tokens** -- YubiKey, NitroKey, Feitian, CAC/PIV cards; communicates directly over libusb with no pcscd or any system daemon required
- **wolfHSM server** -- routes PKCS#11 operations to a wolfHSM server over shared memory or TCP; the private key never leaves the secure enclave
- **USB flash drive keystore** -- encrypted `.p11k` keystore files on removable USB storage, hotplug-detected via inotify; physical possession without dedicated hardware

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
wolfP11 OpenSSL provider  (patches wolfProvider devId gap)
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
| wolfHSM backend | `wolfp11/wp11_backend.h`, `src/wp11_backend_wolfhsm.c` | wolfHSM client integration |
| Settings | `wolfp11/wp11_settings.h` | Compile-time configuration defaults |
| CLI | `src/cli/wp11_cli.c` | `wp11` command-line tool |

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

## wolfProvider OpenSSL Integration

`provider_patch/wolfprovider_devid.patch` is a unified diff against `~/wolfProvider` that closes the wolfProvider devId gap:

- wolfProvider hardcodes `INVALID_DEVID` in all key init calls, bypassing wolfCrypt's device callback mechanism
- The patch adds `int devId` to `WOLFPROV_CTX`, initializes all key types with the `_ex` variants (`wc_InitRsaKey_ex`, `wc_ecc_init_ex`, `wc_InitDhKey_ex`), and exposes `wolfprovider_devid` as a settable OSSL_PARAM
- With this patch applied, OpenSSL operations through wolfProvider route to whichever wolfCrypt device callback (including wolfHSM's `WH_DEV_ID`) is configured

To apply:

```sh
cd ~/wolfProvider
patch -p1 < ~/wolfP11/provider_patch/wolfprovider_devid.patch
```

**Note:** `wc_curve448_init` has no `_ex` variant in wolfCrypt 5.x. ECX keys (Ed25519, X25519, Ed448, X448) do not inherit `devId` from this patch. A full fix requires upstream wolfCrypt changes or a `WP_ECX_INIT` type change in wolfProvider. See the patch header comment for details.

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
| `WOLFP11_CFG_USB_FLASH_WATCH_DIR` | `"/run/media"` | Directory inotify watches for `.p11k` files |
| `WOLFP11_CFG_TEST_USB` | *(undefined)* | Enable hardware-dependent tests |

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
|   +-- vectors/             APDU test reference data (JSON, spec-derived)
+-- provider_patch/
|   +-- wolfprovider_devid.patch  Patch closing wolfProvider devId gap
+-- Makefile
+-- BUILD.md                 Agentic build specification
+-- PRFAQ.md                 Press release and FAQ
```

---

## Related Projects

| Project | Role |
|---------|------|
| [wolfSSL / wolfCrypt](https://github.com/wolfSSL/wolfssl) | Crypto engine; all algorithm implementations |
| [wolfProvider](https://github.com/wolfSSL/wolfProvider) | OpenSSL 3.x provider wrapping wolfCrypt; wolfP11 patches the devId gap |
| [wolfHSM](https://github.com/wolfSSL/wolfHSM) | HSM server; wolfP11 can route PKCS#11 calls to it via WH_DEV_ID |

---

## License

wolfP11 is released under the **GNU General Public License v3.0** (GPL-3.0).

See [https://www.gnu.org/licenses/gpl-3.0.html](https://www.gnu.org/licenses/gpl-3.0.html) for the full license text.
