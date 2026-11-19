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

**New:** First public release of `@shrug/borgwarehouse`, swamp-native control of
a BorgWarehouse backup-monitor server.

Hybrid transport: an HTTP REST API drives all CRUD, alert, key, compact, and
status-cron operations (it never edits the on-host `repo.json`, which would race
the app's lowdb mutex), while SSH + `podman exec` covers the one API gap -- a
hardened, DESTRUCTIVE `pruneRepo`. Prune carries a full safety envelope: a
caller-asserted `repositoryName` interlock, the passphrase passed over ssh STDIN
(never in argv), a `--dry-run` default that writes only on `confirm`, a mandatory
keep rule and a delete-count floor, and no automatic break-lock, with a
best-effort compact afterward. Every mutation is audited on both success and
failure, and all secrets are vault-backed.
