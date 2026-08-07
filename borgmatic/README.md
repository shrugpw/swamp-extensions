# @shrug/borgmatic

A [swamp](https://github.com/swamp-club/swamp) model for **host-managed
[borgmatic](https://torsion.org/borgmatic/) backups**, driven over SSH. borgmatic
is one cohesive tool on one host, so this is a **single model with many verbs**
(like `@shrug/coolify`) — not a family.

It owns the whole per-client shape we used to hand-roll for every new backup
client: install borgmatic, generate the borg SSH key, render a **version-correct**
config, gate it on `borgmatic config validate`, write it `0600`, enable the
timer, and run/prune/check backups on demand. `status`, `info`, and
`listArchives` snapshot the repo as queryable resources for reports ("which
clients haven't backed up in 24h?").

## Two SSH hops (do not confuse them)

1. **swamp → host** — the transport seam; every method shells `borgmatic …` on
   the target host via SSH. This is the only thing that touches the network from
   swamp's side.
2. **host → repo** — borg's own `ssh_command` using the on-host borg key (e.g.
   `/root/.ssh/borg`). The model *configures* (2) into the rendered config and
   *drives* it through (1).

## Version-aware config rendering (load-bearing)

borgmatic **≥ 2.0** uses the unified `commands:` hook syntax; **1.8–1.9** uses
the legacy `before_backup:` / `after_backup:` lists — and 1.9.14 *rejects*
`commands:` outright. `configure` runs `borgmatic --version` on the host and
renders the matching schema. A backup extension that hard-codes one syntax
breaks on half a real fleet.

## Safety envelope

- **Apply-gate.** `configure` renders → validates against a temp file with
  `borgmatic config validate` → only swaps it into `0600` place on pass. An
  invalid config can never land.
- **Write-kernel audit.** Every mutating verb (`configure`, `initRepo`,
  `backup`, `prune`, `compact`, `check`, `restore`) records an honest `attempt`
  resource on **both** success and failure, then throws-after-persist — a failed
  run is auditable, never silent.
- **Repo address is verbatim.** `repositories[].path` is taken as-is; the model
  never assumes a hostname resolves. (Clients typically point at the borg host's
  Tailscale IP, not an unresolvable DNS name.)
- **Guarded restore.** `restore` is dry-run by default and refuses a real extract
  without `confirm:true`.

## Secrets

`encryptionPassphrase` comes from a vault (e.g. `@webframp/pass`) via a CEL global
argument and is marked `sensitive`. The rendered on-host config necessarily
contains it at mode `0600` (borg needs it — the borgmatic norm). The persisted
`config` resource stores a **redacted** copy plus a sha256 of the real content,
never the resolved secret. Set `encryptionPasscommand` to fetch the passphrase at
run time instead of storing it inline.

## Methods

| Method         | What it does                                                                       |
| -------------- | ---------------------------------------------------------------------------------- |
| `configure`    | Umbrella converge: install (opt), keygen, render (version-aware), validate, write `0600`, enable timer |
| `initRepo`     | `borgmatic repo-create` if absent (idempotent via a `repo-info` pre-check)          |
| `backup`       | `borgmatic create --stats` (ad-hoc); `dryRun` supported                             |
| `prune`        | `borgmatic prune --stats` (enforce retention)                                      |
| `compact`      | `borgmatic compact` (reclaim segment space)                                        |
| `check`        | `borgmatic check` (repo/archive integrity)                                         |
| `listArchives` | snapshot `borgmatic repo-list --json`                                              |
| `info`         | snapshot `borgmatic repo-info --json`                                              |
| `status`       | composed health: config valid? timer active + next run? last-archive age?          |
| `restore`      | **guarded** `borgmatic extract` (dry-run default, `confirm:true` to write)          |

## Example (a client instance)

```yaml
type: "@shrug/borgmatic"
name: my-client
globalArguments:
  host: 203.0.113.10
  sshUser: root
  sourceDirectories:
    - /var/lib/docker/volumes/app-config/_data
  repositories:
    - path: ssh://borgwarehouse@192.0.2.10:2222/./abcd1234
      label: app
  encryptionPassphrase: '${{ vault.get("my-client-borg","passphrase") }}'
  retention: { keepDaily: 7, keepWeekly: 4, keepMonthly: 6 }
  hooks:
    beforeBackup:
      - sqlite3 /var/lib/docker/volumes/app-config/_data/db.sqlite3 "PRAGMA wal_checkpoint(TRUNCATE);"
  schedule: { onCalendar: daily, randomizedDelay: 3h, persistent: true }
```

Then drive it with the verbs:

```bash
# converge the host (install/keygen/render/validate/write/timer)
swamp model @shrug/borgmatic method run configure my-client
# create the repo if absent (idempotent), then back up now
swamp model @shrug/borgmatic method run initRepo my-client
swamp model @shrug/borgmatic method run backup   my-client
# snapshot repo + health for reports
swamp model @shrug/borgmatic method run listArchives my-client
swamp model @shrug/borgmatic method run status       my-client
# query the health resource
swamp data get my-client status --json
```

The v1 manual step is creating the server-side repo slot + registering
`${sshKeyPath}.pub` with the repo provider; a future `@shrug/borgwarehouse`
sibling automates that away, feeding `repositories[].path` by CEL.
