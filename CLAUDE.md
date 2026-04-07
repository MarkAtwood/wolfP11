# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is wolfP11

wolfP11 is a unified, daemon-free PKCS#11 abstraction layer for the wolfSSL ecosystem. It provides:

- **USB hardware token support** -- YubiKey, NitroKey, Feitian, and others via libusb + CCID, with no pcscd dependency
- **wolfHSM backend** -- routes PKCS#11 operations to a wolfHSM server via the wolfCrypt device callback (WH_DEV_ID)
- **OpenSSL 3.x provider** -- patches the devId gap in wolfProvider so the full OpenSSL CLI routes through wolfHSM or USB tokens
- **Table-driven token database** -- adding a new PIV or OpenPGP card token is one row in a table, not a new driver

The design goal is: one PKCS#11 interface, multiple backends, no system daemon required. Primary targets are embedded Linux, containers, and edge deployments where pcscd is unavailable or undesirable.

## Tech Stack

- Language: C (C99; C90-compatible for embedded targets)
- Crypto library: wolfCrypt (wolfSSL)
- USB access: libusb (for daemon-free hardware token access)
- HSM backend: wolfHSM (optional; via WH_DEV_ID callback)
- OpenSSL integration: OpenSSL 3.x provider API (optional)

## Related Repositories

- `~/wolfssl` -- wolfSSL/wolfCrypt source
- `~/wolfProvider` -- wolfProvider (OpenSSL 3.x provider wrapping wolfCrypt); wolfP11 patches the devId gap here
- `~/soft_PKCS11` -- wolfHSM soft PKCS#11 implementation; architectural reference

## Architecture

```
OpenSSL 3.x CLI / application
        v
wolfP11 OpenSSL provider  (patches wolfProvider devId gap)
        v
wolfP11 PKCS#11 layer     (C_* functions)
        v
   [backend selector]
   +-- wolfHSM server      (wolfHSM client -> WH_DEV_ID callback -> RPC)
   +-- USB hardware token  (libusb -> CCID -> ISO 7816 -> PIV / OpenPGP)
   +-- soft token          (wolfCrypt direct, no hardware)
```

### Module Map

| Module | Files | Purpose |
|--------|-------|---------|
| PKCS#11 layer | `wolfp11/wp11_pkcs11.h`, `src/wp11_pkcs11.c` | C_* function implementations |
| Token database | `src/wp11_token_db.c` | VID/PID/ATR -> (protocol, quirks, algo flags) table |
| CCID transport | `src/wp11_ccid.c` | USB bulk <-> CCID framing via libusb |
| PIV protocol | `src/wp11_proto_piv.c` | NIST SP 800-73 APDU sequences |
| OpenPGP protocol | `src/wp11_proto_openpgp.c` | OpenPGP card APDU sequences |
| wolfHSM backend | `src/wp11_backend_wolfhsm.c` | wolfHSM client integration |
| OpenSSL provider | `src/wp11_provider.c` | OpenSSL 3.x OSSL_PROVIDER implementation |
| CLI | `src/wp11_cli.c` | Human-facing command-line tool |

### Token Database Structure

```c
typedef struct {
    uint16_t        usb_vid;
    uint16_t        usb_pid;
    const char*     name;
    wp11_proto_t    proto;      /* WP11_PROTO_PIV, WP11_PROTO_OPENPGP, WP11_PROTO_PKCS15 */
    uint32_t        quirks;     /* bitmask of known per-token quirks */
    uint32_t        algos;      /* bitmask of supported key types */
} wp11_token_desc_t;
```

Adding a new token that follows an existing protocol is one row. Adding new quirk handling is a flag + a branch in the protocol code.

### wolfProvider devId Gap

wolfProvider (`~/wolfProvider`) hardcodes `INVALID_DEVID` in all key init calls, bypassing wolfCrypt's device callback. wolfP11 patches this by:

1. Adding `devId` to `WOLFPROV_CTX`
2. Initializing keys with `wc_InitRsaKey_ex`, `wc_ecc_init_ex`, etc., using the configured devId
3. Exposing a provider parameter to set the devId at runtime

## Conventions

- Public symbols: `wp11_` prefix (functions/types), `WP11_` prefix (macros/constants)
- Configuration macros: `WOLFP11_CFG_` prefix; defaults in `wolfp11/wp11_settings.h`
- Header guards: `WOLFP11_<MODULE>_H`
- Public headers: `wolfp11/`; implementations: `src/`; tests: `test/wp11_test_<module>.{c,h}`

## Token Protocol Coverage

| Protocol | Spec | Covers |
|----------|------|--------|
| PIV | NIST SP 800-73 | YubiKey 5, NitroKey HSM 2, CAC/PIV cards, many Feitian tokens |
| OpenPGP card | OpenPGP card spec (gnupg.org) | NitroKey Pro 2, Gnuk, many dev/security community tokens |
| PKCS#15 | ISO 7816-15 | Generic fallback for compliant tokens |

## Key Design Rules

- **No pcscd dependency** -- USB access goes directly through libusb
- **PIV first** -- PIV is the most PKCS#11-native applet; implement and stabilize before adding OpenPGP
- **Narrow PKCS#11 surface first** -- sign, verify, key generate, import; not the full 300-function spec
- **Table beats code** -- new tokens that follow existing protocols get a table row, not a new file
- **wolfCrypt is the crypto engine** -- no reimplementing algorithms; delegate to wolfCrypt or the hardware

## Test Structure

- `test/wp11_test.c` -- main test driver
- `test/wp11_test_<module>.c` + `test/wp11_test_<module>.h` -- per-module tests
- Tests must use independent oracles: known test vectors, cross-validation between backends
- Never use the code under test as its own oracle
- Hardware-dependent tests guarded by `WOLFP11_CFG_TEST_USB`

## External Dependencies

- **wolfCrypt** (wolfSSL): crypto engine; must be on include/link path
- **wolfHSM**: optional HSM backend; enables WH_DEV_ID routing
- **libusb-1.0**: required for USB hardware token support
- **OpenSSL 3.x**: optional; required only for the provider integration


<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking -- do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge -- do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
