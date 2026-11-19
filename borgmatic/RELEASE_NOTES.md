## 2026.11.19.2

**Fix:** `sshExec` now kills and reaps the ssh child on a STDIN-write error. If
the piped-STDIN write (or close) rejected -- a broken pipe or a host refusing
the connection -- before `child.output()` was awaited, the ssh subprocess was
never awaited or killed, leaking an orphaned process and its stdout/stderr
handles. The write/output sequence is now wrapped so any error on that path
sends SIGKILL and awaits the child's exit before rethrowing. The success path is
unchanged, and the passphrase still rides STDIN (never argv). No schema change;
a pure bugfix with no migration needed.

## 2026.11.19.1

Consolidated into the `shrugpw/swamp-extensions` monorepo (full history preserved
from the standalone `swamp-borgmatic` repo).

**New (pub-15):**

- `excludePatterns` support in rendered config, with a newline-injection guard.
- `skipActions` to omit individual borgmatic actions from a run.
- Additional repository `checks` wiring.
- Surfaces the generated borg SSH public key (CEL-reachable for a repo provider
  such as `@shrug/borgwarehouse` to authorize).
- SPDX `license` key added to the manifest.

Carries forward the 2026.08.07.1 security hardening (input-validation charsets on
ssh/sudo/systemd/path fields, shQuoted `ssh_command`, full sensitive-field
redaction of persisted config and command output).
