## 2026.11.21.5

**New:** First release of `@shrug/xen-orchestra` published from this monorepo.
It supersedes the extension's prior standalone-repo home; the registry, not git,
remains the distribution channel.

Over the prior `v2026.11.18.1` (VM/XCP-ng lifecycle, disk provisioning, and
discovery), this release adds a full backup-management surface over the XO REST
API (`/rest/v0`) plus a WebSocket JSON-RPC transport for the operations REST
does not expose:

- **WebSocket JSON-RPC transport** over the built-in Deno `WebSocket`; `npm:ws`
  was dropped to clear the dependency-trust gate. A private-CA XOA is reached by
  trusting the CA at the runtime (`NODE_EXTRA_CA_CERTS` / `DENO_CERT`), not via a
  per-client `caCert`, which the WS transport cannot honor.
- **Backup repository (remote) CRUD + health:** list/get/create/update, a
  `dryRun`-gated forget and reclaim-space, and a health check. The credential URL
  is vaulted and redacted.
- **Task management:** `listTasks`/`getTask` plus `deleteTask`,
  `deleteTasks` (fan-out), and `abortTask`, over a typed `XoHttpError` seam.
- **Backup-archive discovery + file-level restore:** list/get archives and
  mount/unmount a live disk (fail-closed `liveDiskId`).
- **Backup-schedule CRUD:** `listSchedules`/`getSchedule`/`runSchedule` over
  REST; create/update/delete over JSON-RPC.

Reads and the JSON-RPC transport were verified against a live XO (`5.213.4`);
the mutating write paths are covered by tests but not yet exercised against a
live appliance.
