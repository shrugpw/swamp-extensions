# @shrug/borgwarehouse

Swamp-native control of a [BorgWarehouse](https://borgwarehouse.com/)
backup-monitor server. One cohesive server, one model with many verbs (like
`@shrug/borgmatic` and `@shrug/coolify`), not a family.

## Why a hybrid transport

BorgWarehouse keeps every repo slot in `repo.json`, a live lowdb database with an
in-memory cache guarded by an async-mutex. Editing `repo.json` (or
`authorized_keys`) on the host directly races the app's in-memory copy: the next
app write (the per-minute status cron) clobbers it -- the lost-update failure
mode this model exists to avoid. So:

- **HTTP REST API** is the one correct mutator for all CRUD / alert / key /
  compact / status-cron verbs. Bearer-token auth; requires
  `DISABLE_INTEGRATIONS=false` on the server.
- **SSH + `podman exec`** is used for the one API gap: `pruneRepo`.
  BorgWarehouse exposes no prune endpoint, and `borg prune` needs the client
  repo passphrase (client-side repokey encryption; the server never holds it).

## Usage

Define one behavior per BorgWarehouse server. Keep the real host and all secrets
in the behavior YAML / vaults, never in the extension:

```yaml
# behaviors/demo-bw.yaml
type: "@shrug/borgwarehouse"
globalArguments:
  apiBaseUrl: "http://192.0.2.10:3000"
  apiToken: ${{ vault.get("example.com/demo-host/bw-api-token") }}
  cronjobKey: ${{ vault.get("example.com/demo-host/bw-cronjob-key") }}
  sshHost: "192.0.2.10"
  sshUser: rocky
  identityFile: ~/.ssh/bak/id_ed25519
```

```bash
# Read state (no secrets, no mutation)
swamp behavior run demo-bw listRepos
swamp behavior run demo-bw repoStatus --alias demo-1

# Idempotent slot management (HTTP)
swamp behavior run demo-bw setAlert --alias demo-1 --alertSeconds 129600

# A DESTRUCTIVE prune is dry-run by default; a real delete needs the interlock
# plus confirm:true, and the passphrase comes from the client vault.
swamp behavior run demo-bw pruneRepo \
  --alias demo-1 --expectedRepositoryName c055df60 \
  --keep '{"keepDaily":7,"keepWeekly":4,"keepMonthly":6}' \
  --passphrase "$(swamp vault get example.com/demo-host/borg-passphrase)" \
  --dryRun true
```

## Methods

| Method              | Transport | Notes                                                        |
| ------------------- | --------- | ------------------------------------------------------------ |
| `listRepos`         | HTTP      | All repos + computed age / stale / usage. Read-only.         |
| `repoStatus`        | HTTP      | One repo by `slug` (repositoryName) or `alias`. Read-only.   |
| `addRepo`           | HTTP      | Create a slot. Idempotent on the normalized ssh key; 409 re-GET. |
| `authorizeKey`      | HTTP      | Set the repo's authorized key. A rekey requires `confirm:true`. |
| `setAlert`          | HTTP      | Set the alert threshold in seconds (0 disables). No-op when equal. |
| `compactRepo`       | HTTP      | `POST /compact`. A 409 (already running) is benign.          |
| `triggerStatusCron` | HTTP      | On-demand status refresh with `CRONJOB_KEY`. 409 benign.     |
| `breakLock`         | HTTP      | Confirm-gated stale-lock recovery. Never auto-called.        |
| `pruneRepo`         | SSH       | DESTRUCTIVE. Full safety envelope -- see below.              |

## pruneRepo safety envelope

`pruneRepo` deletes archives on a shared production server, so it is hardened:

- **Caller interlock** -- resolve `slug`/`alias` to a `repositoryName`, then
  hard-assert it equals a caller-supplied `expectedRepositoryName` (8-hex)
  before any borg call. A mismatch refuses: no wrong-tenant prune.
- **Passphrase never in argv** -- the passphrase rides in the bash script piped
  over ssh STDIN and is handed to the container via `podman exec -e
  BORG_PASSPHRASE` (name only). It is in no process argv on either hop, and not
  visible in `ps`.
- **No relocated-repo bypass** -- `BORG_RELOCATED_REPO_ACCESS_IS_OK` is never
  set; a relocated/replaced repo fails loudly.
- **Dry-run first** -- `--dry-run` is the default; a real delete needs
  `confirm:true`, at least one keep rule, and a would-delete count within
  `maxDelete` (or `allowLargeDelete:true`).
- **Lock discipline** -- `--lock-wait` waits for an in-flight client backup
  rather than breaking a live lock; `pruneRepo` never breaks a lock itself.
- **Compact after** -- a committing prune only marks segments; `compact` reclaims
  the space and runs best-effort afterward. A compact failure is non-fatal but
  recorded (retry `compactRepo`).

## Secrets (vault-backed, never literal)

- `apiToken` -- the REST Bearer token.
- `cronjobKey` -- the `CRONJOB_KEY` Bearer, used only by `triggerStatusCron`.
- the client repo `passphrase` -- supplied per `pruneRepo` call from the client
  vault via a CEL expression.

No secret is ever persisted into a resource; captured command output is scrubbed
before it lands in an audit record. Every mutation writes an `attempt` audit
resource on both success and failure.

## License

MIT. See LICENSE.txt.
