# wolfP11 Operations Guide

How to build, provision, and wire wolfP11 into your toolchain. This document
covers out-of-band provisioning steps and `wp11` CLI operations.

The PKCS#11 C API (`C_Sign`, `C_Verify`, `C_Decrypt`, etc.) is documented in
`wolfp11/wp11_pkcs11.h` and is not covered here.

> **Notation:** Operations marked **[*] planned** are not yet implemented; the
> issue ID is the roadmap reference.
>
> **Notation:** `$LIB` = `/usr/local/lib/libwolfp11.so` throughout.

---

## Threat Model

| Threat | Protected? |
|--------|-----------|
| Stolen laptop (USB drive absent) | Yes -- no keys on disk |
| Stolen USB drive (PIN unknown) | Yes -- AES-256-GCM + PBKDF2 (200 000 iterations) |
| Physical theft of both laptop and USB | PIN required to decrypt |
| Root-level memory attack on running machine | No -- keys are in RAM (mlock prevents swap) |
| Attacker with write access to `.p11k` file | Partial -- key material is authenticated; file header is not (DoS risk only; see sec.4) |
| Hardware token lost or stolen | Yes -- private key non-extractable by hardware design |
| Hardware token PIN brute-force | Yes -- token locks after configurable attempt limit |

wolfP11 is not a substitute for a tamper-resistant hardware enclave. The flash
keystore's protection comes from PBKDF2 key-stretching and PIN secrecy. The
USB hardware token backend provides hardware non-extractability in addition.

---

## Quick Reference

| Operation | Tool | Status |
|-----------|------|--------|
| Discover token slots | `wp11 list-tokens` | [x] |
| List supported mechanisms | `wp11 list-mechanisms <slot>` | [x] |
| List keys with PKCS#11 URIs | `wp11 list-keys` | [*] wolfP11-6ln |
| Create a `.p11k` keystore | `wp11 keystore create` | [*] wolfP11-ctv |
| Import a key into a keystore | `wp11 keystore import-key` | [*] wolfP11-ctv |
| Remove a key from a keystore | `wp11 keystore remove-key` | [*] wolfP11-ctv |
| Change keystore PIN | `wp11 keystore pin-change` | [*] wolfP11-ctv |
| Attach certificate to keystore entry | `wp11 keystore cert-add` | [*] wolfP11-ctv |
| Inspect a keystore (no PIN) | `wp11 keystore info` | [*] wolfP11-ctv |
| List keys in a keystore file | `wp11 keystore list` | [*] wolfP11-ctv |
| Get PIV attestation certificate | `wp11 attest <slot>` | [*] wolfP11-p46 |
| Change YubiKey PIV PIN | `ykman piv access change-pin` | external |
| Generate key on YubiKey | `ykman piv keys generate` | external |
| Generate key via PKCS#11 | `C_GenerateKeyPair` | [x] (wolfHSM); [*] wolfP11-ktz (PIV/soft) |
| Import cert to YubiKey | `ykman piv certificates import` | external |
| Sign with pkcs11-tool | `pkcs11-tool --sign` | [x] |
| Load in ssh-agent | `ssh-add -s $LIB` | [x] |
| Apply wolfProvider patch | `patch -p1` | [x] |

---

## 1. Build and Install

### Dependencies

```sh
sudo apt-get install build-essential libusb-1.0-0-dev pkg-config libp11-kit-dev
```

Build wolfCrypt from source first (pkg-config must resolve `wolfssl`).
`--enable-wolfprovider` lowers the minimum RSA key size to 1024 bits, which
is required for full PKCS#11 conformance (RSA-1024 key generation):

```sh
cd ~/wolfssl
./autogen.sh
./configure --enable-ecc --enable-rsapss --enable-keygen --enable-wolfprovider
make
sudo make install
sudo ldconfig
```

If you cannot install system-wide, install to a local prefix and the Makefile
will detect it automatically:

```sh
make install DESTDIR=~/wolfssl-install
# wolfP11's Makefile checks ~/wolfssl-install/usr/local/lib/pkgconfig/wolfssl.pc
# and prefers it over the system wolfssl when present.
```

### Build wolfP11

The USB hardware token backend (`-DWOLFP11_CFG_USB_BACKEND`) is always
compiled in. The USB flash drive keystore backend is opt-in:

```sh
# Soft token + USB hardware token support (YubiKey, NitroKey via CCID)
make

# Also include USB flash drive keystore (.p11k files on removable USB drives)
make USBFLASH=1

# Also include filesystem directory keystore (any mounted volume)
make FSDIR=1

# With wolfHSM backend (opt-in)
make WOLFHSM=1 WOLFHSM_DIR=~/wolfHSM
```

Outputs:

| File | Description |
|------|-------------|
| `build/libwolfp11.so` | PKCS#11 shared library -- load this in your application |
| `build/wp11` | CLI tool |

Install:

```sh
# Installs libwolfp11.so, wp11, and headers under /usr/local (override with PREFIX=)
sudo make install
sudo ldconfig
```

### udev Rules (USB hardware tokens)

Without a udev rule, accessing the USB device requires root. Add rules for
the tokens you use:

```
# /etc/udev/rules.d/70-wolfp11.rules

# YubiKey 5 series (all form factors)
SUBSYSTEM=="usb", ATTR{idVendor}=="1050", ATTR{idProduct}=="0407", \
    MODE="0664", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="1050", ATTR{idProduct}=="0406", \
    MODE="0664", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="1050", ATTR{idProduct}=="0410", \
    MODE="0664", GROUP="plugdev"

# NitroKey HSM 2
SUBSYSTEM=="usb", ATTR{idVendor}=="20a0", ATTR{idProduct}=="4108", \
    MODE="0664", GROUP="plugdev"

# NitroKey Pro 2
SUBSYSTEM=="usb", ATTR{idVendor}=="20a0", ATTR{idProduct}=="4109", \
    MODE="0664", GROUP="plugdev"
```

Apply without rebooting:

```sh
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo usermod -aG plugdev $USER   # log out and back in
```

---

## 2. Inspecting Tokens

### List all slots

```sh
wp11 list-tokens
```

Example output:

```
Slots: 2
  Slot  Label                             Type      Status   Notes
  ----  --------------------------------  --------  -------
  0     wolfP11 Soft Token                soft      present
  1     YubiKey 5 NFC                     hardware  present  PIN required
```

Slot 0 is always the soft token. USB tokens and flash keystores appear as
additional slots.

### List mechanisms on a slot

```sh
wp11 list-mechanisms 1
```

Currently supported mechanisms across all backends:

| Mechanism | Key type | Operations |
|-----------|----------|------------|
| `CKM_RSA_PKCS` | RSA 1024-4096 | sign, decrypt |
| `CKM_ECDSA` | EC P-256/P-384 | sign (prehashed digest input) |
| `CKM_ECDSA_SHA256` | EC P-256/P-384 | sign (raw data input, SHA-256 applied internally) |

### List keys with PKCS#11 URIs

> **[*] Planned (wolfP11-6ln).** Use `pkcs11-tool` as an interim:

```sh
pkcs11-tool --module $LIB --list-objects --login
```

Or `p11tool` (GnuTLS) for RFC 7512 URIs:

```sh
p11tool --list-all --provider $LIB
```

Example output:

```
pkcs11:token=YubiKey%205%20NFC;object=signing;type=private
pkcs11:token=YubiKey%205%20NFC;object=signing;type=public
```

---

## 3. USB Hardware Token (PIV)

This section covers YubiKey 5 series and NitroKey HSM 2. Operations that
require talking to the token directly (PIN changes, key generation,
certificate import) use `ykman`. wolfP11 handles the runtime PKCS#11
operations once the token is provisioned.

### Install ykman

```sh
sudo apt-get install yubikey-manager    # or: pip install yubikey-manager
```

### Check what's on the token

```sh
ykman piv info
```

Shows the PIV applet status: firmware version, PIN/PUK retry counters, and
which of the four key slots (9A/9C/9D/9E) are populated with keys and
certificates.

### Manage the PIV PIN

YubiKey defaults: PIN `123456`, PUK `12345678`. Change both before use.

```sh
# Change PIN (prompted interactively)
ykman piv access change-pin

# Change PUK
ykman piv access change-puk

# Unblock a blocked PIN using the PUK
ykman piv access unblock-pin
```

`C_Login` in wolfP11 uses the PIV PIN. The application passes the PIN as the
`pPin` argument to `C_Login`; wolfP11 sends it to the token via the VERIFY
APDU.

### Generate a key on the token

> **Note:** `C_GenerateKeyPair` is implemented for wolfHSM slots. For PIV
> hardware tokens, key generation must happen on-device -- use `ykman`
> (wolfP11-ktz tracks PKCS#11-driven PIV key generation):

```sh
# Generate EC P-256 key in slot 9A (authentication)
ykman piv keys generate --algorithm ECCP256 9a pubkey.pem

# Generate RSA-2048 key in slot 9C (digital signature)
ykman piv keys generate --algorithm RSA2048 9c pubkey.pem
```

This generates the key on-device; the private key never leaves the YubiKey.
`pubkey.pem` contains the public key for creating a self-signed cert or CSR.

PIV slot assignments:

| Slot | Hex | Intended use |
|------|-----|-------------|
| 9A | `0x9a` | Authentication (TLS client cert, SSH) |
| 9C | `0x9c` | Digital signature (document signing, code signing) |
| 9D | `0x9d` | Key management (ECDH, key decryption) |
| 9E | `0x9e` | Card authentication (physical access, less PIN-protected) |

### Generate a self-signed certificate

The PIV applet (and wolfP11) requires a certificate in the slot alongside the
key. At minimum, create a self-signed cert:

```sh
# Generate a CSR for the public key
openssl req -new -key pubkey.pem -out csr.pem \
    -subj "/CN=My YubiKey Key/O=My Org"

# Self-sign it
openssl x509 -req -days 3650 -in csr.pem \
    -signkey pubkey.pem -out cert.pem
```

For a CA-signed certificate, submit `csr.pem` to your CA. If using PIV
attestation once wolfP11-p46 ships, see [Attestation](#attestation) below.

### Import the certificate

```sh
ykman piv certificates import 9a cert.pem
```

### Attest a key (prove on-device generation) {#attestation}

> **[*] Planned (wolfP11-p46).** Until it ships, use `ykman`:

```sh
ykman piv keys attest 9c attestation.pem
cat attestation.pem
```

`attestation.pem` is a certificate signed by the YubiKey's device attestation
key. Submit it alongside your CSR to a CA or enrollment system that requires
hardware key provenance.

Future `wp11 attest` will emit the same PEM to stdout:

```sh
# planned
wp11 attest 9c > attestation.pem
```

---

## 4. USB Flash Drive Keystore (.p11k)

A `.p11k` file is an encrypted keystore: AES-256-GCM with a key derived from
a PIN via PBKDF2-HMAC-SHA256 (200 000 iterations; minimum 100 000 enforced on
load). Key material is locked into RAM with `mlock` when loaded. wolfP11
watches `/run/media` (configurable) with inotify; dropping a `.p11k` file onto
a mounted USB drive automatically creates a new PKCS#11 slot. Removing the
drive removes the slot and zeroizes the in-memory key material immediately.

**Security note:** The file header (salt, iteration count, nonce) is not
covered by the AES-GCM authentication tag. An attacker with write access to
the file can corrupt these fields causing a denial-of-service (load failure),
but cannot decrypt the key material or change what key material is inside.

All keystore management operations (`wp11 keystore ...`) are **out of band** --
the loaded token is read-only at runtime.

### 4.1 Generating private keys

Generate keys with `openssl` on a trusted machine, then import into the
keystore. The private key file on disk should be deleted immediately after
import.

**EC P-256:**
```sh
openssl ecparam -name prime256v1 -genkey -noout -out private.pem
```

**RSA-2048:**
```sh
openssl genrsa -out private.pem 2048
```

**RSA-4096:**
```sh
openssl genrsa -out private.pem 4096
```

Convert to DER format for import:
```sh
openssl pkey -in private.pem -out private.der -outform DER
```

Delete the plaintext key file after import:
```sh
shred -u private.pem private.der 2>/dev/null; rm -f private.pem private.der
```

### 4.2 Creating a keystore

> **[*] Planned (wolfP11-ctv).** When the CLI ships:
>
> ```sh
> wp11 keystore create \
>   --key private-signing.pem --label signing \
>   --key private-auth.pem    --label auth \
>   --output token.p11k
> ```
>
> You will be prompted to enter and confirm a PIN (minimum 6 characters).
> PBKDF2-HMAC-SHA256 with 200 000 iterations takes approximately 0.5-1 second
> on a modern CPU.

Until the CLI ships, use the C API directly. Compile and run the snippet below:

```c
/* mkp11k.c -- create a .p11k keystore from a DER private key file.
 * Compile: cc mkp11k.c -I/path/to/wolfP11 -L/path/to/build \
 *              -lwolfp11 -lwolfssl -o mkp11k
 * Usage:   ./mkp11k mykey.der mykey.p11k mypin "key label"
 */
#include "wolfp11/wp11_keystore.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <key.der> <out.p11k> <pin> <label>\n",
                argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 1; }
    fseek(f, 0, SEEK_END);
    long dlen = ftell(f);
    rewind(f);
    uint8_t *der = malloc((size_t)dlen);
    fread(der, 1, (size_t)dlen, f);
    fclose(f);

    wp11_key_entry_t entry = {0};
    entry.key_type  = WP11_KEY_TYPE_EC;     /* or WP11_KEY_TYPE_RSA */
    entry.der_bytes = der;
    entry.der_len   = (size_t)dlen;
    strncpy(entry.label, argv[4], sizeof(entry.label) - 1);

    const uint8_t *pin = (const uint8_t *)argv[3];
    int rc = wp11_keystore_create(argv[2], pin, strlen(argv[3]), &entry, 1);
    free(der);
    if (rc != 0) {
        fprintf(stderr, "wp11_keystore_create failed: %d\n", rc);
        return 1;
    }
    printf("wrote %s\n", argv[2]);
    return 0;
}
```

### 4.3 Importing an additional key into an existing keystore

> **[*] Planned (wolfP11-ctv):**
>
> ```sh
> wp11 keystore import-key token.p11k \
>   --key new-key.pem --label "new-label"
> ```
>
> You will be prompted for the existing PIN. The keystore is decrypted, the
> new entry appended, and the file re-encrypted with a fresh nonce. The
> operation is atomic (written to a temp file then renamed).

### 4.4 Removing a key from a keystore

> **[*] Planned (wolfP11-ctv):**
>
> ```sh
> wp11 keystore remove-key token.p11k --label signing
> # or by key ID:
> wp11 keystore remove-key token.p11k --id cafebabe01020304
> ```
>
> The removed key's bytes are zeroized before re-encryption.

### 4.5 Changing the PIN

> **[*] Planned (wolfP11-ctv):**
>
> ```sh
> wp11 keystore pin-change token.p11k
> ```
>
> You will be prompted for the current PIN and then to enter and confirm the
> new PIN. The keystore is re-encrypted with a fresh random salt and nonce.

### 4.6 Attaching a certificate to a key

Once you have a signed certificate from your CA:

> **[*] Planned (wolfP11-ctv):**
>
> ```sh
> wp11 keystore cert-add token.p11k \
>   --label signing \
>   --cert signed-cert.pem
> ```
>
> The certificate DER bytes are stored alongside the key entry. The token
> exposes it as a `CKO_CERTIFICATE` object, which TLS client auth, S/MIME,
> and code-signing tools expect to find next to the private key.

### 4.7 Inspecting a keystore

List the unencrypted header fields (format version, KDF parameters) without
a PIN:

> **[*] Planned (wolfP11-ctv):**
>
> ```sh
> wp11 keystore info token.p11k
> ```

List all objects in the loaded token using `pkcs11-tool` (requires the drive
to be mounted and wolfP11 loaded):

```sh
pkcs11-tool --module $LIB --login --list-objects
```

### 4.8 Exporting a public key

The token must be mounted and logged in.

**SSH `authorized_keys` format** -- for provisioning servers:
```sh
ssh-keygen -D $LIB
```

**DER then PEM** -- for CAs, openssl, web servers:
```sh
pkcs11-tool --module $LIB --login \
  --read-object --type pubkey \
  --label <label> \
  --output-file pubkey.der
openssl pkey -inform DER -pubin -in pubkey.der -out pubkey.pem
```

### 4.9 Copy to a USB drive

```sh
cp token.p11k /media/$USER/MYKEY/
```

wolfP11 detects the file via inotify on `/run/media` (or the directory
configured with `WOLFP11_CFG_USB_FLASH_WATCH_DIR`). A new PKCS#11 slot
appears automatically. Removing the drive removes the slot and zeroizes the
in-memory key material.

Multiple `.p11k` files on one drive are supported -- one slot per file.

To use a different watch directory at build time:

```sh
make USBFLASH=1 CFLAGS='-DWOLFP11_CFG_USB_FLASH_WATCH_DIR=\"/mnt/usb\"'
```

### 4.10 Destroying a keystore

```sh
shred -u token.p11k
```

**Flash storage caveat:** USB drives use flash with wear-leveling firmware.
`shred` overwrites at the filesystem layer, but the flash translation layer
may keep the old data in unmapped blocks that `shred` cannot reach. `shred`
is best-effort on flash. For high-assurance key destruction:

1. Full drive format: `mkfs.vfat /dev/sdX` (replaces the filesystem)
2. Secure erase via `hdparm` if the drive supports ATA Secure Erase
3. Physical destruction of the drive

Do not rely on `shred` alone for high-assurance destruction on USB flash drives.

---

## 5. Filesystem Directory Keystore (FSDIR)

The FSDIR backend watches a single flat directory for `.p11k` keystore files
and creates a PKCS#11 slot for each one it finds. It is the software-only
counterpart to the USB flash backend: no USB drive or dedicated hardware is
required. Physical-presence protection is replaced by filesystem-level access
control.

**Enable at build time:**

```sh
make FSDIR=1
```

**Key differences from the USB flash backend:**

| Property | USB flash | FSDIR |
|----------|-----------|-------|
| Physical presence | Yes -- key on removable drive | No -- key on local filesystem |
| Auto-detection | inotify watch on `/run/media` subdirs | inotify watch on one flat directory |
| Subdirectory scan | Yes (mount-point tree) | No (flat directory only) |
| Key generation | Read-only (import via CLI) | Read-only (import via CLI) |
| Use cases | Removable hardware token alternative | tmpfs, LUKS volume, bind-mount, CI |

### 5.1 Configure the watched directory

The watched directory defaults to `/var/lib/wolfp11`. Override at build time:

```sh
make FSDIR=1 CFLAGS='-DWOLFP11_CFG_FSDIR_PATH=\"/etc/wolfp11/keys\"'
```

Or at runtime (takes precedence over the compile-time default):

```sh
export WOLFP11_FSDIR_PATH=/run/wolfp11/keys
```

### 5.2 Provisioning a FSDIR keystore

`.p11k` files for the FSDIR backend are created with the same `wp11 keystore`
CLI as the USB flash backend. Place the resulting file in the watched directory:

```sh
# Create an empty keystore with a PIN
wp11 keystore create --out /var/lib/wolfp11/my-keys.p11k --pin 'mypin'

# Import an existing EC or RSA private key
wp11 keystore import-key --keystore /var/lib/wolfp11/my-keys.p11k \
    --pin 'mypin' --key ec256.pem --label 'signing-key'
```

wolfP11 picks up the file automatically if it is placed (or moved) into the
watched directory while the library is initialized.

### 5.3 Use cases

**tmpfs (in-memory, survives process restart within the session):**

```sh
mkdir -p /run/wolfp11
mount -t tmpfs tmpfs /run/wolfp11
export WOLFP11_FSDIR_PATH=/run/wolfp11
```

Keys loaded into tmpfs are lost on reboot or unmount. This is useful for
ephemeral signing tasks in containers or CI where keys should not persist.

**LUKS encrypted volume:**

```sh
cryptsetup open /dev/sdb1 wolfp11-keys
mkdir -p /mnt/wolfp11
mount /dev/mapper/wolfp11-keys /mnt/wolfp11
export WOLFP11_FSDIR_PATH=/mnt/wolfp11
```

Closing the LUKS volume makes the keystore files inaccessible, providing
protection analogous to removing a USB drive.

**Bind-mount from a secrets manager:**

```sh
mkdir -p /run/wolfp11
mount --bind /secure/secrets/wolfp11 /run/wolfp11
export WOLFP11_FSDIR_PATH=/run/wolfp11
```

### 5.4 Hot-plug detection

The FSDIR backend uses inotify to watch the directory. When a `.p11k` file
appears (copy, move, or write), a new slot is created automatically and
`C_WaitForSlotEvent` fires. When the file is deleted or moved away, the
slot is marked as token-absent and `C_WaitForSlotEvent` fires again.

### 5.5 Security considerations

- The FSDIR backend provides **no physical-presence guarantee**. Any process
  with read access to the directory can attempt a PIN brute-force attack on
  the `.p11k` file. Use filesystem permissions (`chmod 700` on the directory,
  `chmod 600` on `.p11k` files) and OS-level access controls.
- Keys are **decrypted into mlock'd memory** at `C_Login` time and zeroed at
  `C_Logout` / `C_Finalize`. The plaintext never touches swap.
- For high-assurance use, combine FSDIR with a LUKS volume or tmpfs. The
  `.p11k` file's AES-256-GCM auth tag detects any tampering with the
  ciphertext.

---

## 6. Soft Token

The soft token (slot 0) is always present. It uses wolfCrypt directly -- no
hardware required.

Keys generated or imported into the soft token are **persistent** when a
`.p11k` keystore is configured (set `WOLFP11_SOFT_KEYSTORE_PATH` or use the
flash watch directory). Without a keystore path the soft token is ephemeral --
keys exist only until `C_Finalize`.

The soft token is useful for:

- Development and testing without hardware
- CI pipelines where a physical token is unavailable
- Persistent software-only signing when combined with a `.p11k` keystore

To generate a soft key for testing, use the test-mode key generation
functions (`wp11_soft_key_new_ecc_p256`, `wp11_soft_key_new_rsa2048`) from
`wolfp11/wp11_soft_key.h` -- available when building with `-DWOLFP11_CFG_TEST`.

---

## 7. Using wolfP11 with Common Tools

The PKCS#11 module path in all examples below is `$LIB` =
`/usr/local/lib/libwolfp11.so`. Adjust to your install location.

### pkcs11-tool (OpenSC)

Useful for exploring what wolfP11 exposes without writing code.

```sh
# List all slots
pkcs11-tool --module $LIB --list-slots

# List all objects (login required for private keys)
pkcs11-tool --module $LIB --list-objects --login

# Sign a SHA-256 hash with ECDSA (slot 1, key ID 01)
pkcs11-tool --module $LIB \
    --sign --login --slot 1 --id 01 \
    --mechanism ECDSA \
    --input-file hash.bin --output-file sig.der

# Verify
pkcs11-tool --module $LIB \
    --verify --slot 1 --id 01 \
    --mechanism ECDSA \
    --input-file hash.bin --signature-file sig.der
```

### OpenSSH

**Per-session:**
```sh
ssh -I $LIB user@host
```

**Permanent (`~/.ssh/config`):**
```
Host *
    PKCS11Provider /usr/local/lib/libwolfp11.so
```

**ssh-agent:**
```sh
# Load the module (prompts for PIN if a protected slot is found)
ssh-add -s $LIB

# List loaded keys
ssh-add -l

# Remove
ssh-add -e $LIB
```

The agent will prompt for the PIN once and hold the session open. Removing
the USB drive or flash keystore file invalidates the session; the next
operation returns an error.

**Export public key in authorized_keys format:**
```sh
ssh-keygen -D $LIB
```

### Generating a Certificate Signing Request (CSR)

```sh
openssl req \
  -engine pkcs11 -keyform engine \
  -key "pkcs11:object=<label>;type=private" \
  -new -subj "/CN=your-common-name" \
  -out request.csr.pem
```

With Subject Alternative Names:
```sh
openssl req \
  -engine pkcs11 -keyform engine \
  -key "pkcs11:object=<label>;type=private" \
  -new -subj "/CN=your-common-name" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com" \
  -out request.csr.pem
```

### OpenSSL

**TLS client connection:**
```sh
openssl s_client \
  -engine pkcs11 -keyform engine \
  -key  "pkcs11:object=<label>;type=private" \
  -cert /path/to/client-cert.pem \
  -connect example.com:443
```

**Sign a file:**
```sh
pkcs11-tool --module $LIB --login \
  --sign --mechanism SHA256-RSA-PKCS-PSS \
  --label <label> \
  --input-file data.bin \
  --output-file data.sig
```

**Verify the signature:**
```sh
openssl dgst -sha256 -verify pubkey.pem \
  -sigopt rsa_padding_mode:pss \
  -signature data.sig \
  data.bin
```

Via pkcs11-provider (OpenSSL 3.x):
```sh
openssl pkeyutl -sign \
    -inkey 'pkcs11:object=<label>;type=private' \
    -keyform engine -engine pkcs11 \
    -in hash.bin -out sig.bin
```

### curl

**TLS client authentication** (private key on token, cert in file):
```sh
curl --key "pkcs11:object=<label>;type=private" \
     --cert /path/to/client-cert.pem \
     https://example.com/
```

**Key and certificate both on token:**
```sh
curl --key  "pkcs11:object=<label>;type=private" \
     --cert "pkcs11:object=<label>;type=cert" \
     https://example.com/
```

Requires curl built with OpenSSL and the `pkcs11` engine, or with GnuTLS
and `p11-kit` configured.

### GPG

GPG communicates with PKCS#11 tokens through `gpg-pkcs11-scd`, a drop-in
replacement for `scdaemon`.

Install and configure:
```sh
# Debian/Ubuntu
apt-get install gpg-pkcs11-scd

# Add to ~/.gnupg/scdaemon.conf:
echo "providers wolfp11" >> ~/.gnupg/scdaemon.conf
echo "provider-wolfp11-library $LIB" >> ~/.gnupg/scdaemon.conf
```

Reload the agent:
```sh
gpg-connect-agent "scd serialno" "learn --force" /bye
```

### Firefox / Chrome

Firefox and Chrome load PKCS#11 modules through their security device manager.

**Firefox:**
1. Open Preferences -> Privacy & Security -> Security Devices
2. Click **Load** and browse to `$LIB`
3. The token appears as a security device; Firefox will prompt for the PIN
   when a client certificate is required

**Chrome / Chromium** (Linux):
Chrome uses the system NSS database. Register the module:
```sh
# For your user only
modutil -dbdir sql:$HOME/.pki/nssdb -add "wolfp11" -libfile $LIB

# For all users
modutil -dbdir /etc/pki/nssdb -add "wolfp11" -libfile $LIB
```

### cosign / sigstore

Sign a container image:
```sh
cosign sign \
  --key "pkcs11:object=<label>;type=private" \
  <image-ref>
```

Verify:
```sh
cosign verify \
  --key "pkcs11:object=<label>;type=public" \
  <image-ref>
```

cosign uses the `COSIGN_PKCS11_PIN` environment variable or prompts
interactively.

### p11tool (GnuTLS)

```sh
# List all tokens
p11tool --list-tokens --provider $LIB

# List all objects with RFC 7512 URIs
p11tool --list-all --provider $LIB

# Sign
p11tool --sign --provider $LIB \
    'pkcs11:object=<label>;type=private' < data.bin > sig.bin
```

### PKCS#11 URI format (RFC 7512)

The URI for a private key object named `signing` on token `My Token`:

```
pkcs11:token=My%20Token;object=signing;type=private
```

Percent-encode spaces as `%20`. To target by numeric key ID instead of label:

```
pkcs11:token=My%20Token;id=%01;type=private
```

---

## 8. wolfProvider OpenSSL Integration

The wolfProvider patch closes the devId gap that prevents wolfProvider from
routing OpenSSL operations through wolfHSM or wolfP11 backends.

### Apply the patch

```sh
cd ~/wolfProvider
patch -p1 < ~/wolfP11/provider_patch/wolfprovider_devid.patch
```

Rebuild wolfProvider:

```sh
./autogen.sh
./configure
make
sudo make install
```

### What the patch does

- Adds `int devId` to `WOLFPROV_CTX`
- Exposes `wolfprovider_devid` as a settable `OSSL_PARAM`
- Routes `devId` through RSA, ECC, and DH key initialization (`wc_InitRsaKey_ex`,
  `wc_ecc_init_ex`, `wc_InitDhKey_ex`)

**Known gap:** ECX key types (Ed25519, X25519, Ed448, X448) do not fully
inherit `devId` due to function pointer constraints in `wp_ecx_kmgmt.c`. A
full fix requires upstream wolfCrypt changes. See the patch header for
details.

### Set the devId at runtime

Configure wolfProvider to route operations through wolfHSM by setting
`wolfprovider_devid` to the `WH_DEV_ID` value registered with wolfCrypt's
device callback. The exact OpenSSL configuration syntax depends on the
wolfProvider version; see the wolfProvider documentation for
`OSSL_PROVIDER_set_param` usage.

---

## 9. Container Deployment

Mount the USB flash keystore file into the container; wolfP11 treats its
appearance in the watch directory as a drive insertion:

```sh
docker run \
    -v /path/to/token.p11k:/run/media/token.p11k:ro \
    -v $LIB:$LIB:ro \
    myimage
```

For USB hardware tokens, pass through the USB device:

```sh
docker run \
    --device /dev/bus/usb/001/002 \
    -v $LIB:$LIB:ro \
    myimage
```

Find the correct USB bus/device numbers with `lsusb`:

```sh
lsusb | grep -i yubikey
# Bus 001 Device 002: ID 1050:0407 Yubico.com Yubikey 4/5 U2F+CCID
```

---

## 10. Auditing

wolfP11 does not emit its own audit log. Use system-level logging:

| Application | Where to look |
|-------------|---------------|
| OpenSSH | `/var/log/auth.log` or `journalctl -u ssh` |
| PAM (`pam_pkcs11`) | syslog / `journalctl` |
| Any systemd service | `journalctl -u <service>` |
| Firefox / Chrome | Browser console or OS keychain log |
| curl | `--verbose` flag; TLS handshake details in stderr |

For per-operation audit (every `C_Sign` call), configure logging in the
application using wolfP11, not in wolfP11 itself.

---

## 11. PKCS#11 Conformance Notes

wolfP11 implements the subset of PKCS#11 v2.40 used by real applications.
Known deviations from the spec:

- **Security Officer (SO) role is supported** for session management only.
  `C_Login(CKU_SO)` succeeds on RW-only sessions and blocks opening new RO
  sessions while SO is logged in (`CKR_SESSION_READ_WRITE_SO_EXISTS`). SO
  administrative operations (PIN initialisation, object management with SO
  privileges) are not implemented; applications that only need SO for
  session-level protocol conformance work correctly.

- **Minimum PIN length: 6 characters** for flash keystores, enforced at
  keystore creation time. Hardware tokens enforce their own PIN policy.

- **`CKM_ECDSA` expects a pre-hashed digest** as input, not raw data. Use
  `CKM_ECDSA_SHA256` if you want wolfP11 to apply SHA-256 internally.

- **ECDSA signatures** are returned as DER-encoded
  `SEQUENCE { r INTEGER, s INTEGER }`, per PKCS#11 v2.40 sec.2.3.1.

- **`C_WaitForSlotEvent`** is implemented for flash keystore and FSDIR
  hot-plug detection via inotify. USB hardware token hot-plug support
  depends on the libusb hotplug callback being available on the host.

- **40 of 68 C_* functions** return `CKR_FUNCTION_NOT_SUPPORTED`. The
  implemented subset covers key generation, import, sign, verify, decrypt,
  and object enumeration. Session management edge cases and bulk data
  mechanisms are not implemented.

---

## 12. Compile-Time Configuration Reference

All macros use the `WOLFP11_CFG_` prefix. Override with `-D` on the compiler
command line or via `CFLAGS=` in the make invocation.

| Macro | Default | Description |
|-------|---------|-------------|
| `WOLFP11_CFG_MAX_SESSIONS` | `8` | Maximum simultaneously open sessions [1-256] |
| `WOLFP11_CFG_MAX_SLOTS` | `16` | Maximum slots (soft + USB) [1-256] |
| `WOLFP11_CFG_OPENPGP` | `1` | Enable OpenPGP card protocol |
| `WOLFP11_CFG_USB_BACKEND` | off | Enable USB hardware token backend |
| `WOLFP11_CFG_WOLFHSM_BACKEND` | off | Enable wolfHSM backend |
| `WOLFP11_CFG_USB_FLASH_BACKEND` | off | Enable USB flash drive keystore backend |
| `WOLFP11_CFG_USB_FLASH_WATCH_DIR` | `"/run/media"` | Directory inotify watches for `.p11k` files (USB flash backend) |
| `WOLFP11_CFG_FSDIR_BACKEND` | off | Enable filesystem directory keystore backend |
| `WOLFP11_CFG_FSDIR_PATH` | `"/var/lib/wolfp11"` | Directory inotify watches for `.p11k` files (FSDIR backend) |
| `WOLFP11_CFG_TEST_USB` | off | Enable hardware-dependent tests |
| `WOLFP11_CFG_TEST_INOTIFY` | off | Enable timing-sensitive inotify arrival/departure tests |

Example -- change the USB flash watch directory:

```sh
make USBFLASH=1 CFLAGS='-DWOLFP11_CFG_USB_FLASH_WATCH_DIR=\"/mnt/tokens\"'
```

Example -- change the FSDIR watched directory at build time:

```sh
make FSDIR=1 CFLAGS='-DWOLFP11_CFG_FSDIR_PATH=\"/etc/wolfp11/keys\"'
```
