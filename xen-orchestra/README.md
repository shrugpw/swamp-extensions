# @shrug/xen-orchestra

Xen Orchestra (XO) / XCP-NG **VM lifecycle** swamp model. Provisions and
controls a VM on an XCP-NG host through XO's REST API (`/rest/v0`) so the VM is
a first-class swamp resource — created, started, stopped, snapshotted, and
destroyed through model methods rather than by hand. Built to stand up the
always-on `swamp serve` orchestrator VM (design:
`design/serve-orchestrator-vm.md`, Phase 0).

Structural sibling of `@kneel/bugzilla`: plain HTTPS through one injectable
`fetch` seam (`xoRequest`), a vaulted credential, and versioned snapshot
resources. **No curl; TLS verification is always on.**

## Config

| arg | default | notes |
|-----|---------|-------|
| `baseUrl` | `https://localhost:3443` | no trailing slash; REST lives under `/rest/v0`. Point at the hostname the cert is issued for (an SSH-tunnel `localhost` URL fails hostname verification once a real cert is in place). |
| `authToken` | — | sensitive; `vault.get("xo-auth-token","token")`. Sent as the `authenticationToken` cookie. Mint once out of band (see below). |
| `poolId` | `""` | XO pool UUID for `create` (resolve via `listPools`). |
| `caCert` | — | sensitive; PEM of a CA to trust (e.g. FreeIPA) for XOA's cert. Verification stays **on**. Unneeded for a publicly-trusted cert. |
| `requestTimeoutMs` | `120000` | per-request timeout (long create tasks). |

### Minting an auth token

The REST API has an endpoint for it; basic auth is used only here, to bootstrap
the token:

```
curl -u '<xo-user>:<xo-pass>' -X POST \
  https://<xo-host>/rest/v0/users/authentication_tokens \
  -H 'content-type: application/json' \
  -d '{"description":"swamp xen-orchestra","expiresIn":"1 year"}'
```

→ `201` with the token. Or in the XO web UI: user menu → profile →
**Authentication Tokens → New token**. Store it in the vault; the extension
sends it as the `authenticationToken` cookie.

## Methods

| method | REST | notes |
|--------|------|-------|
| `create` | `POST /pools/{poolId}/actions/create_vm?sync=true` | clone a template, inject cloud-init (`cloud_config`/`network_config`), record the `vm` snapshot. `sync=false` polls a task instead. |
| `start` | `POST /vms/{id}/actions/start` | then refresh the `vm` snapshot. |
| `stop` | `POST /vms/{id}/actions/{clean,hard}_shutdown` | `force=true` → hard power-off. |
| `snapshot` | `POST /vms/{id}/actions/snapshot` | body `{name_label}`. |
| `destroy` | `DELETE /vms/{id}` | verifies the VM exists first (Rule 5). |
| `get` | `GET /vms/{id}` | refresh the `vm` live-state snapshot. |
| `listTemplates` / `listPools` / `listSRs` / `listNetworks` | `GET /vm-templates` · `/pools` · `/srs` · `/networks` | resolve UUIDs into an `inventory` snapshot rather than hardcoding. |
| `listVifs` | `GET /vms/{id}` then `GET /vifs/{uuid}` | record a VM's virtual NICs as an `inventory` snapshot (kind `vifs`); `name_label` is the MAC, `raw.$network` the network UUID. |
| `deleteVif` | `DELETE /vifs/{uuid}` | verifies the VIF exists first (Rule 5); resolve the UUID via `listVifs`. |
| `createVdi` | `POST /vdis` body `{srId, virtual_size, name_label}` | create a **blank** VDI on an SR; `sizeGiB` is converted to `virtual_size` **bytes**. Pre-verifies the SR (Rule 5) and rejects an `iso` (read-only) SR; pass `allowedSrTypes: ['ext']` for a stricter rail. Returns the new VDI UUID, recorded under `inventory` (kind `createdVdi`, `items[0].uuid`). **Not idempotent** — no name pre-check, so a re-run creates a *second* disk; persist the returned UUID and do not blindly retry. |

### Provisioning a data disk (createVdi → attachVdi)

`createVdi` is piece 1 of a provision+attach pair. Create the blank disk, then
feed its returned UUID straight into `attachVdi`'s `vdiId` to bind it to a VM as
a non-bootable data disk (e.g. a dedicated `/var/www` disk on an edge VM):

```
createVdi srId=<ext-sr-uuid> sizeGiB=20 nameLabel=www-data
# take the returned VDI UUID, then:
attachVdi vmId=<vm-uuid> vdiId=<new-vdi-uuid> mode=RW bootable=false
```

## Resources

- `vm` — a managed VM's normalized live state (`uuid`, `name_label`,
  `power_state`, `mainIpAddress`, `cpus`, `memory`, `poolId`, `raw`).
- `inventory` — a discovery listing (`kind`, `count`, `items[{uuid,name_label}]`)
  for UUID resolution.

## Rocky Linux 9 bootstrap

`create` passes `cloud_config` (user-data: hostname, SSH keys, packages) and
`network_config` (static IP or DHCP) as cloud-init **content strings**. The
template must have cloud-init installed. Post-boot guest configuration (the
`swamp serve` systemd unit, EnvironmentFile, `dnf`) is handled separately over
SSH via `@adam/cfgmgmt`.

## Testing

```
deno test -A extensions/models/xen_orchestra_test.ts
```

Every method is exercised through a mocked `fetch` seam — no live XO is
touched. A live smoke check (`listTemplates` against a real instance) confirms
auth + connectivity.
