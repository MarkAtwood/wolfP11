# Agent Instructions

This project uses **bd** (beads) for issue tracking. Run `bd onboard` to get started.

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work atomically
bd close <id>         # Complete work
bd dolt push          # Push beads data to remote
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
