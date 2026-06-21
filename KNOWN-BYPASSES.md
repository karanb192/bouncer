# Known bypasses

**Bouncer is a regex filter, not a sandbox.** It reads the literal command and
matches dangerous shapes. That stops the ~95% of footguns that are *accidental*
(the agent that panics, the fat-fingered prod command), but an attacker (or an
agent that decides to obfuscate) can hide the dangerous string from the regex.

This file lists, honestly, the classes Bouncer **cannot** catch. Each one is
verified to pass straight through the real hook. Pinned by a test
(`documented bypasses are knowingly NOT blocked`) so we can never quietly claim
coverage we don't have. **A found gap is a one-line PR**, not a gotcha.

| # | Class | Example (passes through) | Why a regex misses it |
|---|---|---|---|
| 1 | Base64 → shell | `echo cm0gLXJmIH4= \| base64 -d \| sh` | the dangerous string only exists *after* decoding at runtime; the bytes on the line are harmless |
| 2 | Variable-split | `R=rm; $R -rf ~` | the token `rm` is assembled from `$R` at runtime; `\brm\b` never appears |
| 3 | `eval` / `printf` | `eval "$(printf 'rm -rf ~')"` | the payload is constructed inside a subshell; the literal command is `eval`, not `rm` |
| 4 | String-split keyword | `psql -c "DR""OP TABLE users"` | the shell concatenates `"DR"` + `"OP"` into `DROP`; the regex sees neither half |
| 5 | Interpreter one-liner | `python3 -c "import os; os.system('rm -rf ~')"` | the destructive call lives inside another language's string, not in shell argv |
| 6 | Indirect tooling | `find . -name .env \| xargs cat` | the secret read happens via `xargs`, not the `cat .env` shape the rule looks for |

## What this means

- **In `claude` mode**, Claude Code still shows you the command before it runs, so
  Bouncer is a *second* net for the obvious stuff, not the only one. Obfuscated
  payloads are exactly the case where you should still be reading.
- **Bouncer's promise is the seatbelt, not the bank vault.** If your threat model
  includes an adversary who will base64 their payload, you want an OS sandbox
  (containers, `seccomp`, restricted users), not a command-string filter.
- **Closing a gap is welcome and easy.** Most of these can be narrowed (e.g. flag
  `base64 -d | sh`, `eval "$(...)"`, or bare interpreter `-c` with `os.system`) at
  the cost of some false-positive risk. If you ship one, add the command to
  `footguns.txt`, move its line out of the pinned-bypass test, and the gauntlet
  proves it.

> Honesty about scope is the feature. A guard that claims to catch everything is
> the one you stop trusting the first time it doesn't.
