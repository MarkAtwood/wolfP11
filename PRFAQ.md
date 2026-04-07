# PR/FAQ: wolfP11

---

## Press Release

**FOR IMMEDIATE RELEASE**

### wolfP11 Brings YubiKey, NitroKey, and wolfHSM Under One PKCS#11 Interface -- Without a Daemon

#### The first daemon-free PKCS#11 driver for USB hardware tokens, built on wolfCrypt and designed for embedded Linux, containers, and edge deployments

**SEATTLE, WA -- 2026** -- Today wolfSSL is releasing wolfP11, an open-source PKCS#11 abstraction library that connects hardware USB security tokens directly to the wolfSSL ecosystem -- with no system daemon, no pcscd, and no platform-specific middleware. wolfP11 talks to YubiKey, NitroKey, and a growing table of compatible tokens directly over libusb, speaks PKCS#11 to every application above it, supports encrypted `.p11k` keystore files on USB flash drives as a daemon-free software token alternative, and will optionally route operations through a wolfHSM server when hardware tokens are not present (wolfHSM backend is planned; not yet available in this release). A companion patch to wolfProvider closes the longstanding devId gap that has prevented wolfProvider from routing OpenSSL crypto operations through wolfHSM -- so the entire OpenSSL CLI now works against any wolfP11 backend with no code changes.

Every serious PKCS#11 driver for USB hardware tokens today -- ykcs11, OpenSC, and every vendor middleware -- requires pcscd, a privileged system daemon that manages smartcard readers. On a developer workstation running a full Linux desktop, pcscd is an inconvenience. On a Raspberry Pi running Yocto, in a Docker container, in a Kubernetes sidecar, or on a custom embedded board, pcscd is a hard blocker. Teams building products that need physical key possession end up choosing between a hardware token with an unusable software stack and a software token with no physical possession at all. wolfP11 removes that choice.

Token support in wolfP11 is table-driven. PIV -- the NIST SP 800-73 applet implemented by YubiKey 5, NitroKey HSM 2, US government CAC cards, and most Feitian tokens -- is implemented once as a reusable protocol module. OpenPGP card covers NitroKey Pro 2, Gnuk, and the security community's preferred token family. Adding a new token that follows either protocol is one row in a C struct array: USB vendor ID, product ID, protocol selector, quirk flags, and supported algorithm bitmask. No new source file, no new driver, no new binary.

wolfP11 also resolves a concrete gap in wolfProvider, wolfSSL's OpenSSL 3.x provider. wolfProvider currently hardcodes `INVALID_DEVID` in all key initialization calls, which silently bypasses wolfCrypt's device callback layer and makes it impossible to route OpenSSL operations through a wolfHSM server. wolfP11 patches wolfProvider to propagate a configurable devId through all key init calls, closing the chain: OpenSSL CLI -> wolfProvider -> wolfCrypt (WH_DEV_ID callback) -> wolfHSM client -> wolfHSM server or USB token.

"We kept hitting the same wall," said an embedded security engineer during early testing. "We had a wolfHSM server running on the secure core, a YubiKey for developer workstations, and OpenSSL tooling in CI -- three different PKCS#11 stacks with three different setup procedures, all requiring different daemons or middleware. wolfP11 is the one thing that sits behind all three without requiring us to change any of the applications above it."

wolfP11 is written in C (C99, C90-compatible for embedded targets), requires only wolfCrypt and libusb-1.0, and carries the same license as wolfHSM. The wolfHSM backend is planned for a future release; wolfP11 builds and runs without it today. The OpenSSL provider is also optional; the core library has no OpenSSL dependency. The token database is a static array with no heap allocation required at startup, making it suitable for constrained environments. The project ships with PIV and OpenPGP card protocol implementations, a token discovery tool, a CLI with modern noun-verb subcommand structure, and a test suite validated against external reference vectors for all APDU sequences.

wolfP11 is available now at [repository URL].

---

## Frequently Asked Questions

### External FAQ

**Q: What hardware tokens does wolfP11 support?**

A: At launch, wolfP11 supports any token implementing the PIV applet (NIST SP 800-73) or the OpenPGP card specification. This includes YubiKey 5 series (all form factors), NitroKey HSM 2, NitroKey Pro 2, Gnuk-based tokens, and US government CAC/PIV cards. The token database is a static table in `src/wp11_token_db.c`; adding a new token that follows either protocol is a one-line pull request. The project maintains a supported-hardware list in the repository.

**Q: Does wolfP11 require pcscd or any system daemon?**

A: No. wolfP11 communicates with USB tokens directly via libusb. There is no dependency on pcscd, PC/SC, or any system service. On Linux, udev rules grant unprivileged access to the USB device; on embedded targets, the process needs read/write access to the device node. No background process needs to be running.

**Q: Does it work in Docker containers and Kubernetes?**

A: Yes, and this is one of the primary design targets. Mount the USB device into the container (`--device /dev/bus/usb/...`) and wolfP11 works without any host daemon. The USB flash keystore backend also works in containers -- mount the `.p11k` file into the container and it is treated as a removable keystore. When the wolfHSM backend ships, it will work in containers with no device access at all via TCP transport.

**Q: Does it work with embedded Linux targets like Yocto, Buildroot, or bare-metal RTOS?**

A: Yes. wolfP11 is C99 with C90-compatible paths for embedded targets, has no dynamic allocation requirements at startup, and its only required dependencies (wolfCrypt, libusb) are both well-established on embedded Linux. When the wolfHSM backend ships, it will be the natural choice for deeply embedded targets where USB host support is absent; the same PKCS#11 API will work in both cases.

**Q: What PKCS#11 operations are supported?**

A: wolfP11 covers the operations used by the overwhelming majority of real applications: key generation, key import, sign, verify, encrypt, decrypt, and object enumeration. The full 300-function PKCS#11 specification is not implemented; the functions not implemented are largely session management edge cases and mechanisms not relevant to asymmetric key operations. The specific subset is documented in `wolfp11/wp11_pkcs11.h`.

**Q: What algorithms are supported?**

A: RSA-2048 and RSA-4096 (PKCS#1 v1.5 and PSS signing; OAEP encryption), ECDSA P-256 and P-384, and Ed25519 where the underlying token supports it. Algorithm support is declared per-token in the token database; wolfP11 will not advertise an algorithm for a token that does not implement it. wolfCrypt backs all software-side operations.

**Q: How does it compare to OpenSC?**

A: OpenSC supports more tokens and has decades of deployment history. wolfP11 does not try to match OpenSC on token breadth. wolfP11's differentiation is deployment model: it runs without pcscd, is designed for embedded and container environments, integrates natively with wolfHSM, and carries wolfSSL's support and FIPS posture. For a developer workstation with pcscd available, OpenSC and ykcs11 work fine. For anything outside that context, wolfP11 is the better fit.

**Q: Does it work with OpenSSL and the openssl CLI?**

A: Yes, via the optional wolfProvider patch included in wolfP11. After applying the patch and loading wolfP11 as the devId backend, standard OpenSSL commands work against any wolfP11 backend:

```bash
openssl genpkey -provider wolfprovider -algorithm EC -pkeyopt group:P-256
openssl dgst -provider wolfprovider -sign "pkcs11:label=mykey" -sha256 data.bin
```

No application code changes are required.

**Q: Does it work with SSH, GPG, and other PKCS#11-aware tools?**

A: Yes. wolfP11 exposes a standard PKCS#11 shared library. Any tool that accepts a PKCS#11 module path works: `ssh -I /usr/local/lib/libwolfp11.so`, `gpg-pkcs11-scd`, `cosign --key pkcs11:...`, and curl's `--engine pkcs11` flag all work without modification.

**Q: What is the wolfHSM backend?**

A: wolfHSM is a separate wolfSSL project -- a client-server framework for hardware security modules that runs the crypto engine in a trusted execution environment (TEE) or separate secure core. When wolfP11 is configured with the wolfHSM backend, PKCS#11 calls are serialized as RPC messages and sent to the wolfHSM server over a transport (shared memory, TCP, or a custom port). The wolfHSM server performs the operation and returns the result. wolfP11 acts as the PKCS#11 front door; wolfHSM is the secure back end. **Note: the wolfHSM backend is planned but not yet implemented in this release.** The PKCS#11 interface, soft token, and USB flash keystore backends are available today; wolfHSM integration is a near-term roadmap item.

**Q: What is the USB flash drive keystore?**

A: wolfP11 can load private keys from an encrypted `.p11k` keystore file stored on a USB flash drive. The keystore is encrypted with AES-256-GCM, key-derived from a PIN using PBKDF2-HMAC-SHA256, and the key material is locked into RAM with `mlock` to prevent paging to disk. wolfP11 watches a configurable directory (default: `/run/media`) with inotify and automatically presents a new PKCS#11 slot when a `.p11k` file appears and removes it when the file disappears. This gives physical key possession semantics -- removing the drive removes the key from the running system -- without requiring a hardware token. It is the right choice for environments where a YubiKey is too expensive or too fragile but a software file on a workstation is not trusted enough.

**Q: How do I add support for a new USB token?**

A: If the token implements PIV or OpenPGP card, add one entry to the `wh_token_db[]` array in `src/wp11_token_db.c` with the token's USB VID, PID, protocol selector, quirk flags, and supported algorithm bitmask. If it needs a quirk not yet in the flags enum, add the flag and a branch in the relevant protocol file. If it implements a completely proprietary APDU set, a new protocol module is needed -- but that is the exception for modern tokens, most of which implement PIV or OpenPGP card.

---

### Internal FAQ

**Q: Why not extend OpenSC instead of building something new?**

A: OpenSC is LGPL 2.1 and is architecturally inseparable from pcscd. Its internal APIs assume a PC/SC transport. Removing that dependency would require rewriting the transport layer while preserving driver compatibility for 60+ card drivers -- that is a larger and riskier project than building a focused daemon-free implementation from scratch. wolfP11 uses OpenSC's card drivers as the authoritative reference for APDU sequences (read, not copied), and targets the deployment contexts OpenSC cannot serve.

**Q: Why not extend HashiCorp Vault or OpenBao?**

A: Vault is a server-centric secrets management platform for cloud infrastructure. Its deployment model assumes a running Vault server with a raft or consul backend, mTLS everywhere, and a full network stack. That architecture is incompatible with embedded targets and container sidecars. Vault's PKCS#11 support is Enterprise-only and limited to HSM auto-unseal. wolfP11's deployment model is a shared library loaded in-process, with no network service required. The user experience inspiration comes from Vault's CLI conventions, not its architecture.

**Q: Why is the token database table-driven rather than using a plugin architecture?**

A: The long tail of USB token diversity is mostly illusory. Approximately 80% of tokens in active use implement PIV or OpenPGP card. The remaining 20% are largely legacy proprietary tokens that predate the standard applets. For the 80% case, adding a new token is a compile-time constant -- a row in a struct array. A plugin architecture adds indirection, dynamic loading, symbol resolution, versioning, and a trust boundary problem (what code is in the plugin?) for a problem that does not require it. When a genuinely new protocol is needed, a new protocol module is the right unit of extension, not a plugin per token.

**Q: Why C instead of Rust?**

A: The wolfSSL ecosystem -- wolfCrypt, wolfHSM, and the targets they run on -- is C. wolfP11's primary consumers are C codebases, embedded RTOS environments, and systems where a Rust toolchain is not available. Using C means wolfP11 can be included in a wolfHSM build with no additional toolchain requirements. wolfCrypt already provides the memory safety properties most critical for key material handling (zeroization, mlock). The PKCS#11 C ABI is also natively expressed in C; a Rust implementation would FFI across it anyway.

**Q: What is the wolfProvider devId gap and why does it matter?**

A: wolfProvider is wolfSSL's OpenSSL 3.x provider -- it routes OpenSSL crypto calls into wolfCrypt. wolfCrypt has a device callback mechanism (WC_CRYPTO_CB) that intercepts crypto operations and dispatches them to a registered hardware backend using a device ID (devId). wolfProvider currently hardcodes `INVALID_DEVID` in all key initialization calls, which bypasses this mechanism entirely. The result: wolfProvider cannot route OpenSSL operations through wolfHSM even though wolfCrypt has the infrastructure to do so. The fix is straightforward -- add a `devId` field to `WOLFPROV_CTX`, expose a provider parameter to set it, and change the handful of `INVALID_DEVID` literals to use the configured value. wolfP11 ships this patch because closing the gap is necessary for the "OpenSSL CLI routes through wolfHSM" story and the patch has no wolfP11-specific dependencies.

**Q: Why PIV before OpenPGP card?**

A: PIV is more directly PKCS#11-native. NIST SP 800-73 defines a slot structure (authentication, signing, key management, card authentication) that maps cleanly to PKCS#11 key objects and the `C_Sign`, `C_Decrypt` interface. OpenPGP card uses a different mental model (subkeys with specific roles, keygrip-based addressing) that requires more translation. PIV is also the applet on the tokens most likely to be present in enterprise and government deployments -- the higher-stakes use cases. Implementing PIV first gets to a working, tested, valuable state faster.

**Q: How do we ensure tests are not self-referential?**

A: Two rules enforced in the test suite. First, all APDU sequence tests use known-answer vectors derived from external sources -- NIST SP 800-73 Annex C for PIV, the OpenPGP card test vectors from gnupg.org, and cross-validated against OpenSC's test suite output. Tests assert that the vector set is non-empty before running; an empty vector file is a test failure. Second, signature verification tests use wolfCrypt as an independent verifier for hardware token signatures, and vice versa -- the code paths for production and verification are independent. End-to-end tests for the wolfProvider devId patch verify signatures using `openssl dgst -verify` as an external subprocess oracle.

**Q: What is the migration story for a team currently using OpenSC + pcscd?**

A: wolfP11 exposes the same PKCS#11 C ABI. Replacing OpenSC is a one-line change to the module path in `p11-kit` configuration or wherever the application loads the PKCS#11 library. Keys stored in PIV slots on YubiKey or NitroKey HSM 2 remain accessible -- wolfP11 reads the same slots. Keys stored in OpenSC's PKCS#15 file system on a generic JavaCard token require export and re-import; that is not a wolfP11-specific limitation but a consequence of moving between key storage systems.

**Q: What is the long-term token coverage goal?**

A: Cover every token that a wolfSSL customer is likely to encounter in production. That is: all current YubiKey and NitroKey models (PIV and OpenPGP card), US government CAC/PIV cards, and the Feitian tokens common in enterprise environments. The table-driven design means that as new tokens ship and customers report them, adding support is a pull request with a test vector and a table row. The goal is not parity with OpenSC's 60-driver catalog -- it is depth of support for the tokens that matter to the wolfSSL customer base.
