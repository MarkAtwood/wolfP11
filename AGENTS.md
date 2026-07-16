# Agent Instructions

This project uses **bd** (beads) for issue tracking. Run `bd onboard` to get started.

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work atomically
bd close <id>         # Complete work
```

## Related Repositories

When working on wolfP11, these repos are frequently referenced:

| Path | Purpose |
|------|---------|
| `~/wolfssl` | wolfCrypt source -- crypto primitives, device callback (cryptocb.c) |
| `~/wolfProvider` | wolfProvider source -- OpenSSL 3.x provider; wolfP11 patches the devId gap here |
| `~/soft_PKCS11` | wolfHSM soft PKCS#11 -- architectural reference for PKCS#11 layer |

Never load entire repos into context. Grep for what you need.

## wolfProvider devId Gap

The critical seam to understand: wolfProvider hardcodes `INVALID_DEVID` in all key init calls.
The fix lives in `~/wolfProvider/src/wp_rsa_kmgmt.c`, `wp_ecc_kmgmt.c`, `wp_dh_kmgmt.c`, `wp_ecx_kmgmt.c`
and `include/wolfprovider/internal.h` (`WOLFPROV_CTX` struct).

When working on provider integration, always verify which files have been patched.

## Token Database

`src/wp11_token_db.c` is the authoritative list of supported USB tokens. Each entry maps
VID/PID to a protocol (`WP11_PROTO_PIV`, `WP11_PROTO_OPENPGP`, `WP11_PROTO_PKCS15`) plus
quirk flags and algo capability bitmask. Adding a token that follows an existing protocol
is one row -- do not create new source files for it.

## Protocol Reference Sources

When implementing or debugging APDU sequences, consult:
- PIV: NIST SP 800-73 (nist.gov, free)
- OpenPGP card: OpenPGP card spec (gnupg.org, free)
- USB CCID: USB-IF CCID spec (free)
- OpenSC source (`src/libopensc/card-piv.c`, `card-openpgp.c`) -- best reference implementation;
  study for APDU sequences but do not copy (LGPL 2.1)

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** with file operations to avoid hanging on confirmation prompts.

Shell commands like `cp`, `mv`, and `rm` may be aliased to include `-i` (interactive) mode on some systems, causing the agent to hang indefinitely waiting for y/n input.

**Use these forms instead:**
```bash
# Force overwrite without prompting
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file

# For recursive operations
rm -rf directory            # NOT: rm -r directory
cp -rf source dest          # NOT: cp -r source dest
```

**Other commands that may prompt:**
- `scp` - use `-o BatchMode=yes` for non-interactive
- `ssh` - use `-o BatchMode=yes` to fail instead of prompting
- `apt-get` - use `-y` flag
- `brew` - use `HOMEBREW_NO_AUTO_UPDATE=1` env var

## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` for full workflow context.

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work atomically
bd close <id>         # Complete work
```

**Beads is the only task and planning tool.** Do NOT use:
- TodoWrite / markdown TODO lists
- Scratchpad or audit files (`audit-*.md`, `plan-scratch.md`, or any similar throwaway planning file)
- MEMORY.md or any other markdown file as a knowledge store

The only permitted markdown planning artifact is a crate's `PLAN.md`, which is a permanent
design document checked into the repo — not a scratchpad. Use `bd remember` for persistent
knowledge and `bd create` for all task tracking.

## AI-to-AI PR Replies

When an AI-drafted reply responds to another AI's PR comment (Copilot, Skoll, or any bot reviewer), preface the reply with "AItoAI: ". Replies to human reviewers never carry the prefix.
