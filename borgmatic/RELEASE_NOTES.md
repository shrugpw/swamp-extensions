## 2026.11.21.1

**New:** the `backup` method now surfaces the dry-run file list as structured
data. On a dry-run the borg `create` action adds `--list`, and the per-file
output is parsed into two new `backup` resource fields: `files` (the absolute
paths borg would archive) and `fileCount`. Both are null on real backups so
normal runs don't bloat the datastore. A workflow can now assert via CEL (e.g.
`data.latest("<name>","backup").attributes.files`) that no forbidden tenant path
is in the set before the first real append-only backup. The `output` field is
unchanged (still the passphrase-redacted `--stats` tail). Also aligns the
in-source model `version` constant with the manifest (the two had drifted:
manifest `2026.11.19.2` vs in-source `2026.11.19.1`).

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
