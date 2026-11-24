/**
 * Xen Orchestra (XO) / XCP-NG VM lifecycle model.
 *
 * Provisions and controls a single VM on an XCP-NG host through Xen
 * Orchestra's **REST API** (`/rest/v0`), so the swamp orchestrator VM is a
 * first-class swamp resource — created, started, stopped, snapshotted, and
 * destroyed through model methods rather than by hand. Structural sibling of
 * `@kneel/bugzilla`: plain HTTPS through one injectable `fetch` seam
 * ({@link xoRequest}), a vaulted credential, and versioned snapshot resources.
 *
 * ## Transport & authentication
 *
 * Plain HTTPS via `fetch` — **never** curl, and TLS verification is always on.
 * The XO auth **token** is sent as the `authenticationToken` cookie (the
 * Swagger `token` security scheme; basic auth exists but is used only to mint
 * the token out of band). Resolve it from a swamp vault via CEL, e.g.
 * `--global-arg 'authToken=${{ vault.get("xo-auth-token", "token") }}'`
 * against a `@webframp/pass` vault.
 *
 * A private-CA (e.g. FreeIPA) XOA cert is trusted via the optional
 * {@link GlobalArgs.caCert} PEM (`Deno.createHttpClient({ caCerts })`) —
 * verification stays enabled. A publicly-trusted cert (Let's Encrypt) on XOA
 * needs no `caCert`. Point {@link GlobalArgs.baseUrl} at the hostname the cert
 * is issued for (an SSH-tunnel `localhost` URL will fail hostname
 * verification once a real cert is in place).
 *
 * ## XO REST specifics baked in
 *
 * - Create is pool-scoped: `POST /pools/{poolId}/actions/create_vm`. With
 *   `?sync=true` it returns the new VM's UUID inline; otherwise it returns a
 *   task reference that {@link pollTask} resolves.
 * - Lifecycle actions are `POST /vms/{id}/actions/{start,clean_shutdown,
 *   hard_shutdown,snapshot}`; destroy is `DELETE /vms/{id}`.
 * - Collection GETs (`/vm-templates`, `/pools`, `/srs`, `/networks`) return an
 *   array; with `?fields=` they are objects, else bare URL strings —
 *   {@link normalizeRef} tolerates both so UUIDs are resolved, not hardcoded.
 * - Rocky Linux 9 bootstrap rides `cloud_config`/`network_config` (cloud-init
 *   content strings); the template must have cloud-init installed.
 *
 * @module
 */
import { z } from "npm:zod@4";
// Built-in (Deno-provided) incremental hasher: lets importFromUrl verify a
// multi-GB download's SHA-256 chunk-by-chunk, without buffering it or pulling
// a streaming-digest dependency.
import { createHash } from "node:crypto";

/** Connection, auth, and TLS-trust settings. */
const GlobalArgsSchema = z.object({
  baseUrl: z
    .string()
    .default("https://localhost:3443")
    .describe("XO base URL (no trailing slash); REST lives under /rest/v0"),
  authToken: z
    .string()
    .meta({ sensitive: true })
    .optional()
    .describe(
      "XO authentication token — resolve from a vault via CEL. Sent as the " +
        "`authenticationToken` cookie.",
    ),
  poolId: z
    .string()
    .default("")
    .describe("Default XO pool UUID for create (resolve via listPools)"),
  caCert: z
    .string()
    .meta({ sensitive: true })
    .optional()
    .describe(
      "PEM of a CA to trust (e.g. FreeIPA) for XOA's cert. Verification stays " +
        "ON; unneeded for a publicly-trusted cert.",
    ),
  requestTimeoutMs: z
    .number()
    .int()
    .default(120000)
    .describe("Per-request timeout (long create tasks)"),
});

/** Resolved connection, auth, and TLS-trust settings. */
export type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// ---------------------------------------------------------------------------
// Resource schemas
// ---------------------------------------------------------------------------

/** A normalized VM snapshot (live state lifted from the XO record). */
const VmSchema = z.object({
  uuid: z.string(),
  name_label: z.string().nullable(),
  power_state: z.string().nullable(),
  mainIpAddress: z.string().nullable(),
  cpus: z.number().nullable(),
  memory: z.number().nullable(),
  poolId: z.string().nullable(),
  raw: z.record(z.string(), z.unknown()),
  retrievedAt: z.iso.datetime(),
});

/** A normalized VM snapshot. */
export type Vm = z.infer<typeof VmSchema>;

/** A resolved reference row (template / SR / network / pool). */
const RefSchema = z.object({
  uuid: z.string().nullable(),
  name_label: z.string().nullable(),
  raw: z.record(z.string(), z.unknown()),
});

/** A discovery listing snapshot (templates/pools/srs/networks/servers). */
const InventorySchema = z.object({
  kind: z.string().describe("What was listed, e.g. `templates` or `srs`"),
  count: z.number().int(),
  items: z.array(RefSchema),
  retrievedAt: z.iso.datetime(),
});

/**
 * The outcome record of a `deleteTasks` fan-out. The strict InventorySchema
 * (items are RefSchema) cannot represent the per-id deleted/alreadyGone/failed
 * buckets, so deleteTasks records this dedicated spec. `count` is the bulk
 * delete-all count when XO returns one (else null); in ids-mode it is the
 * number actually deleted.
 */
const TaskDeletionSchema = z.object({
  kind: z.literal("task-deletions"),
  mode: z.enum(["ids", "all"]),
  requested: z.array(z.string()),
  deleted: z.array(z.string()),
  alreadyGone: z.array(z.string()),
  failed: z.array(z.object({ id: z.string(), error: z.string() })),
  count: z.number().int().nullable(),
  retrievedAt: z.iso.datetime(),
});

/**
 * A token minted by createAuthToken. `tokenId` IS the bearer secret, so it is
 * marked `sensitive` — swamp VAULTS that field and persists only a vault
 * reference; the audit fields stay plaintext. Read the secret back via
 * `data.latest("<instance>", "mintedToken-<label>").attributes.tokenId`.
 */
const MintedTokenSchema = z.object({
  // SENSITIVE — swamp vaults this field and persists only a reference.
  tokenId: z.string().meta({ sensitive: true }),
  description: z.string().nullable(),
  clientId: z.string().nullable(),
  userId: z.string().nullable(),
  created: z.union([z.number(), z.string()]).nullable(),
  expiration: z.union([z.number(), z.string()]).nullable(),
  mintedAt: z.string(),
});

/**
 * A created/attached virtual NIC's binding, recorded by `attachVif` so callers
 * can wire to the new interface via CEL (`{uuid, mac, network, attached}`). A
 * dedicated spec (not the `inventory` listing shape) because a single-VIF
 * binding does not conform to {@link InventorySchema}'s `{kind,count,items}`.
 */
const VifSchema = z.object({
  uuid: z.string(),
  mac: z.string().nullable(),
  network: z.string().nullable(),
  attached: z.boolean(),
});

/** A recorded VIF binding. */
export type Vif = z.infer<typeof VifSchema>;

/**
 * A backup SCHEDULE binding (id/jobId/cron/timezone/name/enabled), recorded by
 * getSchedule/createSchedule/updateSchedule. A dedicated spec (like
 * {@link VifSchema}, not the `inventory` listing shape) because a single-schedule
 * record does not conform to {@link InventorySchema}'s `{kind,count,items}`.
 * Every non-id field is `.nullable()` so an unexpected-absent XO field never
 * throws at parse; `raw` keeps full fidelity (schedules carry no known secrets,
 * so no field-stripping like normalizeVm's other_config drop). The XO schedule
 * JSON key names (id/jobId/cron/timezone/enabled/name) are the XO REST/JSON-RPC
 * convention and are NOT verified from a live probe for this ticket.
 */
const ScheduleSchema = z.object({
  id: z.string(),
  jobId: z.string().nullable(),
  cron: z.string().nullable(),
  timezone: z.string().nullable(),
  name: z.string().nullable(),
  enabled: z.boolean().nullable(),
  raw: z.record(z.string(), z.unknown()),
  retrievedAt: z.iso.datetime(),
});

/** A recorded backup-schedule binding. */
export type Schedule = z.infer<typeof ScheduleSchema>;

/**
 * A live-disk mount from a backup archive, recorded by `mountLiveDisk` so the
 * returned `liveDiskId` is durable and the mount can always be released with
 * `unmountLiveDisk` (read the id via
 * `data.latest(name,"liveDisk-<liveDiskId>").attributes.liveDiskId`). A
 * dedicated spec (not the `inventory` listing shape) because a single mount
 * handle is a stateful binding, not a `{kind,count,items}` collection.
 *
 * `mountedAt` and `unmountedAt` are BOTH NULLABLE: the unmount path has no
 * mountedAt source in its args (only {archiveId, liveDiskId}) and
 * ExecuteContext exposes only `writeResource` (no data-store READ seam), so the
 * superseding `unmounted` write cannot carry the original mountedAt forward and
 * re-records `mountedAt:null`. A required mountedAt would make that post-unmount
 * write throw the real zod schema in prod AFTER the server-side unmount already
 * succeeded (a false failure leaving the record stuck at `mounted`).
 */
const LiveDiskSchema = z.object({
  archiveId: z.string(),
  liveDiskId: z.string(),
  status: z.enum(["mounted", "unmounted"]),
  raw: z.record(z.string(), z.unknown()),
  mountedAt: z.string().nullable(),
  unmountedAt: z.string().nullable(),
});

/** A recorded live-disk mount handle. */
export type LiveDisk = z.infer<typeof LiveDiskSchema>;

/**
 * A normalized XO **server** (an XCP-NG host/pool connection XO manages, as
 * opposed to a VM). Registering one here is how a new hypervisor's pool becomes
 * visible to `listPools` and a valid `migrate` target.
 */
const ServerSchema = z.object({
  id: z.string(),
  label: z.string().nullable(),
  host: z.string().nullable(),
  username: z.string().nullable(),
  status: z.string().nullable().describe("connect state, e.g. `connected`"),
  poolId: z.string().nullable(),
  raw: z.record(z.string(), z.unknown()),
  retrievedAt: z.iso.datetime(),
});

/** A normalized XO server connection. */
export type Server = z.infer<typeof ServerSchema>;

/**
 * A normalized XCP-NG network. A VLAN leg is a network whose PIF carries a
 * VLAN tag; a host-internal network has no PIF. Creating these on a fresh host
 * is how guest segments (e.g. a "Services" VLAN) come to exist.
 */
const NetworkSchema = z.object({
  uuid: z.string(),
  name_label: z.string().nullable(),
  mtu: z.number().nullable(),
  poolId: z.string().nullable(),
  pifs: z.array(z.string()).describe("PIF UUIDs (empty = host-internal)"),
  raw: z.record(z.string(), z.unknown()),
  retrievedAt: z.iso.datetime(),
});

/** A normalized XCP-NG network. */
export type Network = z.infer<typeof NetworkSchema>;

const SrSchema = z.object({
  uuid: z.string(),
  name_label: z.string().nullable(),
  name_description: z.string().nullable(),
  SR_type: z.string().nullable(),
  content_type: z.string().nullable(),
  shared: z.boolean().nullable(),
  size: z.number().nullable(),
  physical_usage: z.number().nullable(),
  poolId: z.string().nullable(),
  raw: z.record(z.string(), z.unknown()),
  retrievedAt: z.iso.datetime(),
});

/** A normalized XCP-NG storage repository. */
export type Sr = z.infer<typeof SrSchema>;

/**
 * The XO server's reported version, read over the JSON-RPC transport by the
 * `getServerVersion` proof method (`system.getServerVersion`). A read-only
 * marker that the WebSocket control-plane seam reaches a live xo-server.
 */
const ServerVersionSchema = z.object({
  version: z.string().describe("xo-server version string"),
  retrievedAt: z.iso.datetime(),
});

/** The XO server version snapshot. */
export type ServerVersion = z.infer<typeof ServerVersionSchema>;

/**
 * A normalized XO **backup repository** (a "remote" in XO's UI): where backup
 * chains land — SMB/NFS/S3/local/file. The source `url` embeds a credential
 * (e.g. `smb://user:pass@host/share`), so the persisted `urlRedacted` has its
 * userinfo AND query stripped and is deliberately NOT marked sensitive — the
 * raw secret never reaches this row. Mirrors {@link SrSchema}'s shape; used by
 * get/create/update.
 */
const BackupRepositorySchema = z.object({
  id: z.string(),
  name: z.string().nullable(),
  type: z.string().nullable().describe("smb|nfs|s3|local|file"),
  urlRedacted: z.string().nullable().describe(
    "URL with userinfo+query removed",
  ),
  enabled: z.boolean().nullable(),
  raw: z.record(z.string(), z.unknown()),
  retrievedAt: z.iso.datetime(),
});

/** A normalized XO backup repository (remote). */
export type BackupRepository = z.infer<typeof BackupRepositorySchema>;

/**
 * A listing of backup repositories recorded by listBackupRepositories. A
 * dedicated spec (not {@link InventorySchema}, whose `items` are the strict
 * {@link RefSchema}) so each item is a full redacted {@link BackupRepository}.
 */
const BackupRepositoryListSchema = z.object({
  count: z.number().int(),
  items: z.array(BackupRepositorySchema),
  retrievedAt: z.iso.datetime(),
});

/**
 * The outcome of a backup-repository action (forget / reclaim-space /
 * benchmark, plus the dryRun `*-plan` variants). `taskRef` is set when XO
 * returns an async task reference (the long-running path), otherwise null for
 * an inline result. `raw` is always an object (see {@link rawObject}) so a bare
 * string/null XO response never violates `z.record`.
 */
const BackupRepositoryActionSchema = z.object({
  id: z.string(),
  action: z.string().describe(
    "forget|reclaim-space|benchmark|forget-plan|reclaim-space-plan",
  ),
  status: z.string().nullable().describe("e.g. submitted|planned|done"),
  taskRef: z.string().nullable(),
  raw: z.record(z.string(), z.unknown()),
  retrievedAt: z.iso.datetime(),
});

/**
 * A backup-repository health snapshot. Stored raw (whatever shape XO's
 * `/health` returns) so a brittle normalize is not needed; `raw` is always an
 * object via {@link rawObject}.
 */
const BackupRepositoryHealthSchema = z.object({
  id: z.string(),
  raw: z.record(z.string(), z.unknown()),
  retrievedAt: z.iso.datetime(),
});

// ---------------------------------------------------------------------------
// Pure helpers (exported for tests)
// ---------------------------------------------------------------------------

/**
 * Coerce a value to a string or null.
 *
 * @param v Any raw value.
 * @returns The string form, or null when absent.
 */
export function strOrNull(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  return typeof v === "string" ? v : String(v);
}

/**
 * Coerce a value to a finite number or null.
 *
 * @param v Any raw value.
 * @returns The number, or null when absent/non-numeric.
 */
export function numOrNull(v: unknown): number | null {
  if (v === null || v === undefined) return null;
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? n : null;
}

/**
 * Extract a UUID from a create/task result that may be a bare string or an
 * object carrying `uuid`/`id`/`$id`.
 *
 * @param v The result value.
 * @returns The UUID string, or "" when none is present.
 */
export function extractUuid(v: unknown): string {
  if (typeof v === "string") {
    // A task/href like ".../<uuid>" collapses to its last segment; a bare
    // UUID passes through unchanged.
    return v.includes("/") ? v.split("/").filter(Boolean).pop() ?? "" : v;
  }
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return strOrNull(o.uuid ?? o.id ?? o.$id) ?? "";
  }
  return "";
}

/**
 * Normalize a raw XO VM record into a {@link VmSchema} row, lifting the nested
 * `CPUs.number` / `memory.size` shapes to scalars.
 *
 * @param raw Raw VM object from `GET /vms/{id}`.
 * @returns A flattened VM snapshot.
 */
export function normalizeVm(raw: Record<string, unknown>): Vm {
  const cpuObj = raw.CPUs as Record<string, unknown> | undefined;
  const memObj = raw.memory as Record<string, unknown> | undefined;
  const cpus = cpuObj?.number ?? raw.cpus ?? raw.vCPUs;
  const memory = memObj?.size ??
    (typeof raw.memory === "number" ? raw.memory : undefined);
  // XCP-NG operators sometimes stash secrets in `other_config`/`xenstore_data`
  // (SSH keys, install tokens). Drop them so the swamp data store doesn't
  // inherit XO's secret surface; keep everything else for debugging fidelity.
  const { other_config: _oc, xenstore_data: _xs, ...safeRaw } = raw;
  return {
    uuid: strOrNull(raw.uuid ?? raw.id) ?? "",
    name_label: strOrNull(raw.name_label),
    power_state: strOrNull(raw.power_state),
    mainIpAddress: strOrNull(raw.mainIpAddress),
    cpus: numOrNull(cpus),
    memory: numOrNull(memory),
    poolId: strOrNull(raw.$pool ?? raw.poolId ?? raw.pool),
    raw: safeRaw,
    retrievedAt: new Date().toISOString(),
  };
}

/**
 * Normalize a collection item to a {@link RefSchema}. XO returns collection
 * members as objects (with `?fields=`) or as bare `/rest/v0/<kind>/<uuid>`
 * URL strings (without) — both flatten to `{ uuid, name_label }`.
 *
 * @param raw A collection member (object or URL string).
 * @returns A resolved reference row.
 */
export function normalizeRef(raw: unknown): z.infer<typeof RefSchema> {
  if (typeof raw === "string") {
    return { uuid: extractUuid(raw), name_label: null, raw: { href: raw } };
  }
  const o = (raw ?? {}) as Record<string, unknown>;
  return {
    uuid: strOrNull(o.uuid ?? o.id),
    name_label: strOrNull(o.name_label),
    raw: o,
  };
}

/**
 * Normalize a raw XO backup-schedule record (`GET /schedules/{id}` or the body
 * re-read after a JSON-RPC write) into a {@link ScheduleSchema} row. Lifts the
 * known XO fields to scalars via strOrNull and keeps full `raw` fidelity
 * (schedules carry no known secrets). `retrievedAt` is always stamped so the
 * recorded payload conforms to the declared spec and never throws in prod.
 *
 * @param raw Raw schedule object from XO.
 * @returns A flattened schedule snapshot.
 */
export function normalizeSchedule(raw: Record<string, unknown>): Schedule {
  const r = raw ?? {};
  return {
    id: strOrNull(r.id ?? r.uuid) ?? "",
    jobId: strOrNull(r.jobId ?? r.job ?? r.$job),
    cron: strOrNull(r.cron),
    timezone: strOrNull(r.timezone),
    name: strOrNull(r.name ?? r.name_label),
    enabled: typeof r.enabled === "boolean" ? r.enabled : null,
    raw: r,
    retrievedAt: new Date().toISOString(),
  };
}

/**
 * Normalize a raw XO server record (`GET /servers` / `GET /servers/{id}`) into
 * a {@link ServerSchema} row. The XO server identity is `id` (not `uuid`), and
 * the connection `password` is stripped so it never lands in the swamp data
 * store — same secret-hygiene posture as {@link normalizeVm}.
 *
 * @param raw Raw server object from the servers collection.
 * @returns A flattened server snapshot.
 */
export function normalizeServer(raw: Record<string, unknown>): Server {
  // Never persist the connection password (present on POST bodies, and some XO
  // versions echo it back on the record).
  const { password: _pw, ...safeRaw } = raw;
  return {
    id: strOrNull(raw.id ?? raw.uuid) ?? "",
    label: strOrNull(raw.label ?? raw.name_label),
    host: strOrNull(raw.host),
    username: strOrNull(raw.username),
    status: strOrNull(raw.status),
    poolId: strOrNull(raw.poolId ?? raw.$pool ?? raw.pool),
    raw: safeRaw,
    retrievedAt: new Date().toISOString(),
  };
}

/**
 * Normalize a raw XO network record (`GET /networks` / `GET /networks/{id}`)
 * into a {@link NetworkSchema} row. `PIFs` empty ⇒ host-internal; a populated
 * `PIFs` whose PIF carries a `vlan` tag ⇒ a VLAN leg.
 *
 * @param raw Raw network object.
 * @returns A flattened network snapshot.
 */
export function normalizeNetwork(raw: Record<string, unknown>): Network {
  const pifs = ((raw.PIFs ?? raw.$PIFs ?? []) as unknown[])
    .map(extractUuid)
    .filter((s) => s.length > 0);
  return {
    uuid: strOrNull(raw.uuid ?? raw.id) ?? "",
    name_label: strOrNull(raw.name_label),
    mtu: numOrNull(raw.MTU ?? raw.mtu),
    poolId: strOrNull(raw.$pool ?? raw.poolId ?? raw.pool),
    pifs,
    raw,
    retrievedAt: new Date().toISOString(),
  };
}

/**
 * Normalize a raw XO SR record (`GET /srs` / `GET /srs/{id}`) into an
 * {@link SrSchema} row. XO exposes the XAPI `type` as `SR_type` and
 * `physical_size` as `size`; tolerate either key. `device_config` can carry a
 * write-only credential (SMB/iSCSI) — any `*pass*` key is redacted from the
 * persisted raw, same secret-hygiene posture as {@link normalizeServer}.
 *
 * @param raw Raw SR object.
 * @returns A flattened SR snapshot.
 */
export function normalizeSr(raw: Record<string, unknown>): Sr {
  const dc = raw.device_config as Record<string, unknown> | undefined;
  const safeRaw = dc
    ? {
      ...raw,
      device_config: Object.fromEntries(
        Object.entries(dc).filter(([k]) => !/pass/i.test(k)),
      ),
    }
    : raw;
  return {
    uuid: strOrNull(raw.uuid ?? raw.id) ?? "",
    name_label: strOrNull(raw.name_label),
    name_description: strOrNull(raw.name_description),
    SR_type: strOrNull(raw.SR_type ?? raw.type),
    content_type: strOrNull(raw.content_type),
    shared: typeof raw.shared === "boolean" ? raw.shared : null,
    size: numOrNull(raw.size ?? raw.physical_size),
    physical_usage: numOrNull(raw.physical_usage),
    poolId: strOrNull(raw.$pool ?? raw.poolId ?? raw.pool),
    raw: safeRaw,
    retrievedAt: new Date().toISOString(),
  };
}

/**
 * Redact credentials from a backup-repository (remote) URL before it is logged
 * or persisted. On a successful parse the userinfo (`user:pass`) is cleared and
 * any query string collapses to `?<redacted>`. On a parse FAILURE the fallback
 * still drops the secret: it strips a leading `scheme://`, slices off
 * everything up to and INCLUDING the LAST `@` in the authority (removing
 * `user:pass`), then cuts at the first `/`, `?`, or `#` — so
 * `smb://user:pass@host/share` yields `smb://host`, never `smb://user:pass`.
 *
 * @param url A possibly-credential-bearing remote URL.
 * @returns The URL safe to log/persist (no userinfo, no query value).
 */
export function redactRepoUrl(url: string): string {
  try {
    const u = new URL(url);
    u.username = "";
    u.password = "";
    const q = u.search ? "?<redacted>" : "";
    return `${u.protocol}//${u.host}${u.pathname}${q}`;
  } catch {
    const schemeMatch = url.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//);
    const scheme = schemeMatch ? schemeMatch[0] : "";
    let rest = url.slice(scheme.length);
    const at = rest.lastIndexOf("@");
    if (at >= 0) rest = rest.slice(at + 1);
    const cut = rest.search(/[/?#]/);
    const host = cut >= 0 ? rest.slice(0, cut) : rest;
    return `${scheme}${host}`;
  }
}

/**
 * Coerce an arbitrary XO response into a plain object so it can be stored in a
 * `z.record(z.string(), z.unknown())` field. A non-null, non-array object is
 * returned as-is; anything else (a bare string, null, a number, an array) is
 * wrapped as `{ result: res }`.
 *
 * @param res Any XO response value.
 * @returns An object safe for a `raw` field.
 */
export function rawObject(res: unknown): Record<string, unknown> {
  if (res !== null && typeof res === "object" && !Array.isArray(res)) {
    return res as Record<string, unknown>;
  }
  return { result: res };
}

/**
 * Extract an async task reference from an action response without blocking on
 * it. Returns a task id when `res` is a string containing `tasks/` (via
 * {@link extractUuid}) or an object whose `href`/`id`/`$id` points at a task,
 * else null (an inline result). Lets reclaim-space/benchmark record the async
 * path for a later poll (out of scope here) rather than hanging on it.
 *
 * @param res The raw action response.
 * @returns A task id, or null when the result was inline.
 */
export function extractTaskRef(res: unknown): string | null {
  if (typeof res === "string") {
    return res.includes("tasks/") ? (extractUuid(res) || null) : null;
  }
  if (res && typeof res === "object" && !Array.isArray(res)) {
    const o = res as Record<string, unknown>;
    const ref = o.href ?? o.$id ?? o.id;
    if (typeof ref === "string" && ref.includes("tasks/")) {
      return extractUuid(ref) || null;
    }
  }
  return null;
}

/**
 * Normalize a raw XO backup-repository record into a {@link BackupRepository}
 * row. Tolerates `id`/`uuid`, `name`/`label`/`name_label`, and a boolean
 * `enabled`. The credential-bearing `url` is redacted both in `urlRedacted` and
 * inside the persisted `raw`, and any `*pass*`/`secret`/`password` key (incl.
 * `options.password`) is dropped — same secret-hygiene posture as
 * {@link normalizeSr}/{@link normalizeServer}.
 *
 * @param raw Raw backup-repository object from the REST surface.
 * @returns A flattened, credential-redacted snapshot.
 */
export function normalizeBackupRepository(
  raw: Record<string, unknown>,
): BackupRepository {
  const url = raw.url !== undefined && raw.url !== null
    ? redactRepoUrl(String(raw.url))
    : null;
  // Build a redacted raw: redact the url, drop any secret-bearing key, and
  // scrub a nested options.password if present.
  const safeRaw: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (/pass|secret/i.test(k)) continue;
    if (k === "url") {
      if (url !== null) safeRaw.url = url;
      continue;
    }
    if (k === "options" && v && typeof v === "object" && !Array.isArray(v)) {
      safeRaw.options = Object.fromEntries(
        Object.entries(v as Record<string, unknown>)
          .filter(([ok]) => !/pass|secret/i.test(ok)),
      );
      continue;
    }
    safeRaw[k] = v;
  }
  return {
    id: strOrNull(raw.id ?? raw.uuid) ?? "",
    name: strOrNull(raw.name ?? raw.label ?? raw.name_label),
    type: strOrNull(raw.type),
    urlRedacted: url,
    enabled: typeof raw.enabled === "boolean" ? raw.enabled : null,
    raw: safeRaw,
    retrievedAt: new Date().toISOString(),
  };
}

/**
 * Build a `create_vm` request body from method args, omitting unset fields so
 * XO applies its own defaults (and the template's disks when `vdis` is unset).
 *
 * @param args Create arguments.
 * @returns The JSON body for `POST /pools/{id}/actions/create_vm`.
 */
export function buildCreateBody(
  args: Record<string, unknown>,
): Record<string, unknown> {
  const keys = [
    "name_label",
    "name_description",
    "template",
    "clone",
    "cpus",
    "memory",
    "vifs",
    "vdis",
    "cloud_config",
    "network_config",
    "install",
    "boot",
    "hvmBootFirmware",
    "secureBoot",
    "autoPoweron",
    "copyHostBiosStrings",
  ];
  const body: Record<string, unknown> = {};
  for (const k of keys) {
    if (args[k] !== undefined) body[k] = args[k];
  }
  return body;
}

// ---------------------------------------------------------------------------
// Fetch seam
// ---------------------------------------------------------------------------

/** A minimal `fetch` response the seam consumes. */
export interface FetchResponse {
  ok: boolean;
  status: number;
  statusText: string;
  text(): Promise<string>;
}

/** A `fetch`-compatible function (injected in tests). */
export type FetchLike = (
  input: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    client?: unknown;
    signal?: AbortSignal;
  },
) => Promise<FetchResponse>;

/**
 * Percent-encode a single REST path segment (a VM/pool/task id) so a value
 * containing `/`, `?`, `#`, or `..` cannot redirect the request to a different
 * endpoint than intended — critical for the destructive `destroy` path.
 *
 * @param seg A path segment (e.g. a UUID).
 * @returns The encoded segment.
 */
export function enc(seg: string): string {
  return encodeURIComponent(seg);
}

/**
 * Convert a GiB disk size to bytes for XO's `virtual_size` field. 1 GiB =
 * 1073741824 bytes. A plain JS number suffices: even a multi-PiB disk stays
 * well under Number.MAX_SAFE_INTEGER (2**53 bytes is ~8 PiB), so no BigInt is
 * needed for any realistic VDI.
 *
 * @param gib Size in GiB (a positive integer, by the method's zod schema).
 * @returns The equivalent size in bytes.
 */
export function gibToBytes(gib: number): number {
  return gib * 1024 ** 3;
}

/**
 * Reject an auth token that could inject extra cookies or headers (CR/LF/`;`).
 * The SOLE guard for cookie-header injection via a malformed vaulted token —
 * shared by both request seams (JSON {@link xoRequest} and the binary
 * {@link importVdiToSr}) so it cannot drift between them.
 *
 * @param token The configured XO auth token.
 * @throws When the token contains CR, LF, or `;`.
 */
export function guardAuthToken(token: string): void {
  if (/[\r\n;]/.test(token)) {
    throw new Error("authToken contains illegal characters (CR/LF/;)");
  }
}

/**
 * Strip the query string from a URL before logging or persisting it: presigned
 * S3/Azure/GCS image URLs carry a signature there that doubles as a live
 * download credential. Returns `origin + pathname` (with a `?<redacted>` marker
 * when a query was present), or the pre-`?` substring if it does not parse.
 *
 * @param url A possibly-credential-bearing URL.
 * @returns The URL safe to log/persist.
 */
export function redactUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.search
      ? `${u.origin}${u.pathname}?<redacted>`
      : `${u.origin}${u.pathname}`;
  } catch {
    return url.split(/[?#]/)[0];
  }
}

/**
 * Build the real transport: plain `fetch`, wrapped with a
 * `Deno.createHttpClient({ caCerts })` when a `caCert` is configured so a
 * private-CA XOA cert validates. Never disables verification.
 *
 * @param cfg Connection + TLS-trust config.
 * @returns A {@link FetchLike} over the global `fetch`.
 */
export function makeFetch(cfg: GlobalArgs): FetchLike {
  let client: unknown;
  const g = globalThis as {
    Deno?: { createHttpClient?: (o: unknown) => unknown };
  };
  if (cfg.caCert && g.Deno?.createHttpClient) {
    client = g.Deno.createHttpClient({ caCerts: [cfg.caCert] });
  }
  const f = fetch as unknown as (
    i: string,
    o?: unknown,
  ) => Promise<FetchResponse>;
  return (input, init) => f(input, { ...init, client });
}

/**
 * A typed HTTP error carrying the XO response `status`, so callers can branch
 * on the code (e.g. tolerate a 404 in a batch) without string-parsing the
 * message. Extends Error and preserves the EXACT xoRequest message format, so
 * every existing `instanceof Error` / message-substring assertion still holds.
 */
export class XoHttpError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = "XoHttpError";
  }
}

/**
 * Issue one XO REST request — the sole network seam. Sends the
 * `authenticationToken` cookie when a token is configured, JSON-encodes a
 * body, and raises on a non-2xx status. Returns parsed JSON, or null for an
 * empty body (e.g. a 204 from DELETE).
 *
 * @param cfg Connection + auth.
 * @param method HTTP verb.
 * @param path REST path relative to `/rest/v0`, e.g. `vms/{id}` or
 *   `pools/{id}/actions/create_vm`.
 * @param opts Optional repeatable query params and JSON body.
 * @param doFetch Fetch implementation (defaults to global `fetch`).
 * @returns Parsed JSON body, or null when empty.
 * @throws On any non-2xx HTTP status.
 */
export async function xoRequest(
  cfg: GlobalArgs,
  method: string,
  path: string,
  opts: { query?: Array<[string, string]>; body?: unknown } = {},
  doFetch: FetchLike = fetch as unknown as FetchLike,
): Promise<unknown> {
  const base = cfg.baseUrl.replace(/\/+$/, "");
  const url = new URL(`${base}/rest/v0/${path.replace(/^\/+/, "")}`);
  for (const [k, v] of opts.query ?? []) url.searchParams.append(k, v);

  const headers: Record<string, string> = { "Accept": "application/json" };
  if (cfg.authToken) {
    // Defense-in-depth: a vault entry with a stray newline/`;` must not be
    // able to inject additional cookies or headers.
    guardAuthToken(cfg.authToken);
    headers["Cookie"] = `authenticationToken=${cfg.authToken}`;
  }
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";

  const resp = await doFetch(url.toString(), {
    method,
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    // Bound every request so a hung XO can't hold the per-model lock forever.
    signal: cfg.requestTimeoutMs
      ? AbortSignal.timeout(cfg.requestTimeoutMs)
      : undefined,
  });
  const text = await resp.text();
  if (!resp.ok) {
    throw new XoHttpError(
      resp.status,
      `XO ${method} ${path} failed (HTTP ${resp.status}): ` +
        `${text || resp.statusText}`,
    );
  }
  if (!text.trim()) return null;
  // Actions may return a bare id as plain text (e.g. a new VM UUID) rather
  // than JSON; fall back to the (trimmed) raw string when it isn't valid JSON.
  try {
    return JSON.parse(text);
  } catch {
    return text.trim();
  }
}

/**
 * Block on an XO async task until it resolves, returning its result. Accepts a
 * task id, a `/rest/v0/tasks/<id>` path, or a full URL.
 *
 * @param cfg Connection + auth.
 * @param taskRef The task reference returned by an async action.
 * @param doFetch Fetch implementation.
 * @returns The task's `result` (the new VM UUID for create), or the raw task.
 * @throws When the task resolves to a non-success status.
 */
export async function pollTask(
  cfg: GlobalArgs,
  taskRef: unknown,
  doFetch: FetchLike = fetch as unknown as FetchLike,
): Promise<unknown> {
  const id = extractUuid(taskRef);
  const res = await xoRequest(
    cfg,
    "GET",
    `tasks/${enc(id)}`,
    // XO's task-wait param is a BOOLEAN (`?wait=true` long-polls until the task
    // settles, then returns the task object). The string form `?wait=result` is
    // a newer-XOA-only shortcut that stable XOA rejects with HTTP 422 "invalid
    // boolean value"; `wait=true` is the portable form.
    { query: [["wait", "true"]] },
    doFetch,
  );
  // `?wait=true` returns the settled task, usually a `{ status, result }`
  // envelope but tolerate a bare result too. A present-but-non-success status
  // fails loud; the caller (create) additionally fails closed when no UUID is
  // resolved.
  const o = (res ?? {}) as Record<string, unknown>;
  const status = strOrNull(o.status);
  if (status && status !== "success") {
    throw new Error(
      `XO task ${id} ${status}: ${JSON.stringify(o.result ?? o)}`,
    );
  }
  return o.result ?? o;
}

// ---------------------------------------------------------------------------
// Context types
// ---------------------------------------------------------------------------

/** Minimal logging surface the methods rely on. */
interface MethodLogger {
  debug(message: string, properties?: Record<string, unknown>): void;
  info(message: string, properties?: Record<string, unknown>): void;
  warning(message: string, properties?: Record<string, unknown>): void;
  error(message: string, properties?: Record<string, unknown>): void;
}

/** Minimal shape of the execute context this model relies on. */
interface ExecuteContext {
  globalArgs: GlobalArgs;
  logger: MethodLogger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

/** Return shape for every method's execute function. */
interface ExecuteResult {
  dataHandles: Array<{ name: string }>;
}

// ---------------------------------------------------------------------------
// Shared method internals
// ---------------------------------------------------------------------------

/**
 * GET a VM by UUID and record it as the `vm` resource (single source of truth
 * for its live state). Shared by create/start/stop/snapshot/get.
 *
 * @param cfg Connection + auth.
 * @param id VM UUID.
 * @param doFetch Fetch implementation.
 * @param context Execute context (for `writeResource`).
 * @returns The recorded data handle.
 */
async function snapshotVm(
  cfg: GlobalArgs,
  id: string,
  doFetch: FetchLike,
  context: ExecuteContext,
): Promise<ExecuteResult> {
  const raw = (await xoRequest(cfg, "GET", `vms/${enc(id)}`, {}, doFetch)) as
    | Record<string, unknown>
    | null;
  const vm = normalizeVm(raw ?? { uuid: id });
  const handle = await context.writeResource("vm", `vm:${id}`, vm);
  return { dataHandles: [handle] };
}

/** One scanned VIF: its uuid, its MAC (as `name_label`), and the raw record. */
interface VifRow {
  uuid: string;
  name_label: string | null;
  raw: Record<string, unknown>;
}

/**
 * Scan a VM's virtual NICs: `GET /vms/{id}` (which also serves as the Rule-5
 * verify-before-mutate existence check — it throws HTTP 404 when the VM is
 * absent), then `GET /vifs/{uuid}` per VIF ref. Shared by `listVifs` (fan into
 * an inventory snapshot) and `attachVif` (idempotency scan). `name_label`
 * carries the MAC (upper- or lowercase key); `raw.$network` the network UUID.
 *
 * @param cfg Connection + auth.
 * @param id VM UUID.
 * @param doFetch Fetch implementation.
 * @returns One {@link VifRow} per attached VIF (empty when the VM has none).
 */
async function scanVifs(
  cfg: GlobalArgs,
  id: string,
  doFetch: FetchLike,
): Promise<VifRow[]> {
  const vm = (await xoRequest(cfg, "GET", `vms/${enc(id)}`, {}, doFetch)) as
    | Record<string, unknown>
    | null;
  const refs = (vm?.VIFs ?? vm?.["$VIFs"] ?? []) as unknown[];
  const ids = refs.map(extractUuid).filter((s) => s.length > 0);
  const items: VifRow[] = [];
  for (const vifId of ids) {
    const vif = (await xoRequest(
      cfg,
      "GET",
      `vifs/${enc(vifId)}`,
      {},
      doFetch,
    )) as Record<string, unknown> | null;
    const raw = vif ?? { uuid: vifId };
    items.push({
      uuid: strOrNull(raw.uuid) ?? vifId,
      name_label: strOrNull(raw.MAC) ?? strOrNull(raw.mac),
      raw,
    });
  }
  return items;
}

/** One scanned VBD: its uuid, device position (`name_label`), and raw record. */
interface VbdRow {
  uuid: string;
  name_label: string | null;
  raw: Record<string, unknown>;
}

/**
 * Scan a VM's virtual block devices: `GET /vms/{id}` (also the Rule-5
 * existence check), then `GET /vbds/{uuid}` per VBD ref. `name_label` carries
 * the device position; `raw` holds `bootable`, `VDI`, and the CD/disk type so a
 * caller can tell a boot disk from a cloud-init config drive and pick which VBD
 * to detach. Shared by `listVbds`.
 *
 * @param cfg Connection + auth.
 * @param id VM UUID.
 * @param doFetch Fetch implementation.
 * @returns One {@link VbdRow} per attached VBD (empty when the VM has none).
 */
async function scanVbds(
  cfg: GlobalArgs,
  id: string,
  doFetch: FetchLike,
): Promise<VbdRow[]> {
  const vm = (await xoRequest(cfg, "GET", `vms/${enc(id)}`, {}, doFetch)) as
    | Record<string, unknown>
    | null;
  const refs = (vm?.VBDs ?? vm?.["$VBDs"] ?? []) as unknown[];
  const ids = refs.map(extractUuid).filter((s) => s.length > 0);
  const items: VbdRow[] = [];
  for (const vbdId of ids) {
    const vbd = (await xoRequest(
      cfg,
      "GET",
      `vbds/${enc(vbdId)}`,
      {},
      doFetch,
    )) as Record<string, unknown> | null;
    const raw = vbd ?? { uuid: vbdId };
    items.push({
      uuid: strOrNull(raw.uuid) ?? vbdId,
      name_label: strOrNull(raw.device) ?? strOrNull(raw.userdevice) ??
        strOrNull(raw.position),
      raw,
    });
  }
  return items;
}

/**
 * GET a server by id and record it as the `server` resource. Shared by
 * addServer (and any future connect/disconnect method).
 *
 * @param cfg Connection + auth.
 * @param id XO server id.
 * @param doFetch Fetch implementation.
 * @param context Execute context (for `writeResource`).
 * @returns The recorded data handle.
 */
async function snapshotServer(
  cfg: GlobalArgs,
  id: string,
  doFetch: FetchLike,
  context: ExecuteContext,
): Promise<ExecuteResult> {
  const raw =
    (await xoRequest(cfg, "GET", `servers/${enc(id)}`, {}, doFetch)) as
      | Record<string, unknown>
      | null;
  const server = normalizeServer(raw ?? { id });
  const handle = await context.writeResource("server", `server:${id}`, server);
  return { dataHandles: [handle] };
}

/**
 * GET a network by UUID and record it as the `network` resource. Shared by
 * createNetwork / createInternalNetwork.
 *
 * @param cfg Connection + auth.
 * @param id Network UUID.
 * @param doFetch Fetch implementation.
 * @param context Execute context.
 * @returns The recorded data handle.
 */
async function snapshotNetwork(
  cfg: GlobalArgs,
  id: string,
  doFetch: FetchLike,
  context: ExecuteContext,
): Promise<ExecuteResult> {
  const raw = (await xoRequest(
    cfg,
    "GET",
    `networks/${enc(id)}`,
    {},
    doFetch,
  )) as Record<string, unknown> | null;
  const network = normalizeNetwork(raw ?? { uuid: id });
  const handle = await context.writeResource(
    "network",
    `network:${id}`,
    network,
  );
  return { dataHandles: [handle] };
}

/**
 * GET an SR by UUID and record it as the `sr` resource. Shared by createSR
 * (and any future SR method).
 *
 * @param cfg Connection + auth.
 * @param id SR UUID.
 * @param doFetch Fetch implementation.
 * @param context Execute context.
 * @returns The recorded data handle.
 */
async function snapshotSr(
  cfg: GlobalArgs,
  id: string,
  doFetch: FetchLike,
  context: ExecuteContext,
): Promise<ExecuteResult> {
  const raw = (await xoRequest(cfg, "GET", `srs/${enc(id)}`, {}, doFetch)) as
    | Record<string, unknown>
    | null;
  const sr = normalizeSr(raw ?? { uuid: id });
  const handle = await context.writeResource("sr", `sr:${id}`, sr);
  return { dataHandles: [handle] };
}

/**
 * Resolve the created object's UUID from a pool create-action response, which
 * XO may return inline (`{id}`/bare uuid) or as an async task ref
 * (`{taskId}`) — the latter is polled to completion.
 *
 * @param cfg Connection + auth.
 * @param res The raw POST response.
 * @param doFetch Fetch implementation.
 * @returns The created UUID, or "" when none could be resolved.
 */
async function resolveActionId(
  cfg: GlobalArgs,
  res: unknown,
  doFetch: FetchLike,
): Promise<string> {
  const direct = extractUuid(res);
  if (direct) return direct;
  const o = (res ?? {}) as Record<string, unknown>;
  const taskRef = "taskId" in o ? o.taskId : res;
  if (!extractUuid(taskRef)) return "";
  return extractUuid(await pollTask(cfg, taskRef, doFetch));
}

/**
 * Find an existing network by name within a pool, for idempotent creation.
 *
 * @param cfg Connection + auth.
 * @param poolId Pool UUID to scope the search to.
 * @param name The `name_label` to match.
 * @param doFetch Fetch implementation.
 * @returns The matching network UUID, or "" when none.
 */
async function findNetworkByName(
  cfg: GlobalArgs,
  poolId: string,
  name: string,
  doFetch: FetchLike,
): Promise<string> {
  const res = await xoRequest(
    cfg,
    "GET",
    "networks",
    { query: [["fields", "uuid,name_label,$pool"]] },
    doFetch,
  );
  if (!Array.isArray(res)) return "";
  const match = res
    .map((n) => n as Record<string, unknown>)
    .find((n) => n.name_label === name && strOrNull(n.$pool) === poolId);
  return match ? extractUuid(match) : "";
}

/**
 * True when `actual` (a candidate SR's device_config) matches every non-secret
 * key of the `intended` device_config. Secret keys (`*pass*`) are never
 * compared — XO does not echo them back, and comparing them would force a
 * needless miss. A missing/absent `actual` never matches (fail closed: prefer a
 * loud duplicate-create over silently reusing an unknown-config SR).
 *
 * @param intended The device_config the caller asked to create.
 * @param actual The candidate SR's device_config from `GET /srs/{id}`.
 * @returns Whether the transport/config discriminators all agree.
 */
export function deviceConfigMatches(
  intended: Record<string, string>,
  actual: Record<string, unknown> | undefined,
): boolean {
  if (!actual) return false;
  for (const [k, v] of Object.entries(intended)) {
    if (/pass/i.test(k)) continue;
    if (strOrNull(actual[k]) !== v) return false;
  }
  return true;
}

/**
 * Find an existing SR to reuse for idempotent creation. Matches on
 * `name_label` + `SR_type`, scoped to `poolId` when known (a shared library
 * commonly exists once per pool, so a same-name SR in another pool must NOT be
 * reused). Crucially, `SR_type` alone cannot tell an NFS ISO library from an
 * SMB or local one — all are `SR_type: "iso"` — so each name/type/pool
 * candidate's `device_config` is fetched and its non-secret keys must also
 * match `deviceConfig` before it is treated as the same SR. Never reuses on
 * name alone.
 *
 * @param cfg Connection + auth.
 * @param poolId Pool UUID to scope to, or "" to match across pools.
 * @param name The `name_label` to match.
 * @param srType The `SR_type` to match.
 * @param deviceConfig The intended device_config (transport discriminator).
 * @param doFetch Fetch implementation.
 * @param logger For an ambiguity warning when >1 SR fully matches.
 * @returns The matching SR UUID, or "" when none.
 */
async function findSrByName(
  cfg: GlobalArgs,
  poolId: string,
  name: string,
  srType: string,
  deviceConfig: Record<string, string>,
  doFetch: FetchLike,
  logger: MethodLogger,
): Promise<string> {
  const res = await xoRequest(
    cfg,
    "GET",
    "srs",
    { query: [["fields", "uuid,name_label,SR_type,$pool"]] },
    doFetch,
  );
  if (!Array.isArray(res)) return "";
  const candidates = res
    .map((s) => s as Record<string, unknown>)
    .filter((s) =>
      s.name_label === name &&
      strOrNull(s.SR_type) === srType &&
      (poolId === "" || strOrNull(s.$pool) === poolId)
    );
  const matches: string[] = [];
  for (const c of candidates) {
    const uuid = extractUuid(c);
    if (!uuid) continue;
    const full = (await xoRequest(
      cfg,
      "GET",
      `srs/${enc(uuid)}`,
      { query: [["fields", "uuid,device_config"]] },
      doFetch,
    )) as Record<string, unknown> | null;
    const dc = full?.device_config as Record<string, unknown> | undefined;
    if (deviceConfigMatches(deviceConfig, dc)) matches.push(uuid);
  }
  if (matches.length > 1) {
    logger.warning(
      "Multiple SRs match name {name}/type {type}/device_config; reusing {id}",
      { name, type: srType, id: matches[0] },
    );
  }
  return matches[0] ?? "";
}

/** XAPI SR types whose storage is host-local (not shared pool-wide). */
const LOCAL_SR_TYPES: ReadonlySet<string> = new Set(["ext", "lvm", "file"]);

/**
 * GET a collection and record it as an `inventory` snapshot for UUID
 * resolution.
 *
 * @param cfg Connection + auth.
 * @param kind Inventory label + resource instance name.
 * @param path REST collection path (e.g. `vm-templates`).
 * @param doFetch Fetch implementation.
 * @param context Execute context.
 * @param fields `?fields=` selector (defaults to the identity set). Pass a
 *   richer set for collections whose extra attributes matter (e.g. SR capacity).
 * @returns The recorded data handle.
 */
async function listInventory(
  cfg: GlobalArgs,
  kind: string,
  path: string,
  doFetch: FetchLike,
  context: ExecuteContext,
  fields = "uuid,name_label,name_description,type,$pool",
): Promise<ExecuteResult> {
  const res = await xoRequest(
    cfg,
    "GET",
    path,
    { query: [["fields", fields]] },
    doFetch,
  );
  if (!Array.isArray(res)) {
    // A non-array here means the call failed or the API drifted — surface it
    // rather than silently reporting "0 items" (which reads as "none exist").
    throw new Error(
      `XO GET ${path} did not return a list (got ${typeof res})`,
    );
  }
  const items = res.map(normalizeRef);
  const handle = await context.writeResource("inventory", kind, {
    kind,
    count: items.length,
    items,
    retrievedAt: new Date().toISOString(),
  });
  return { dataHandles: [handle] };
}

// ---------------------------------------------------------------------------
// Image import internals (importFromUrl)
//
// The JSON `xoRequest`/`FetchLike` seam above only reads `text()`, so it cannot
// stream a multi-GB disk in either direction. These helpers add a SECOND,
// binary seam (`StreamFetchLike`) used only by `importFromUrl`: the long
// download and the long upload. Neither is bounded by `requestTimeoutMs` (that
// is sized for quick JSON calls) — like `clone`, a disk transfer runs for many
// minutes by design.
// ---------------------------------------------------------------------------

/** A streaming-capable response: exposes the body stream the JSON seam hides. */
export interface StreamResponse {
  ok: boolean;
  status: number;
  statusText: string;
  body: ReadableStream<Uint8Array> | null;
  text(): Promise<string>;
}

/** A `fetch`-compatible function for binary up/download (injected in tests). */
export type StreamFetchLike = (
  input: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: ReadableStream<Uint8Array> | Uint8Array;
    // Deno/undici require this when the request body is a stream.
    duplex?: "half";
    client?: unknown;
    signal?: AbortSignal;
  },
) => Promise<StreamResponse>;

/**
 * Binary transport, mirroring {@link makeFetch} (same private-CA handling) but
 * returning the real {@link Response} so `.body` is available for streaming.
 */
export function makeStreamFetch(cfg: GlobalArgs): StreamFetchLike {
  let client: unknown;
  const g = globalThis as {
    Deno?: { createHttpClient?: (o: unknown) => unknown };
  };
  if (cfg.caCert && g.Deno?.createHttpClient) {
    client = g.Deno.createHttpClient({ caCerts: [cfg.caCert] });
  }
  const f = fetch as unknown as (
    i: string,
    o?: unknown,
  ) => Promise<StreamResponse>;
  return (input, init) => f(input, { ...init, client });
}

/** The image format a URL names, by extension. `unknown` -> convert via qemu. */
export function inferImageFormat(
  url: string,
): "qcow2" | "vhd" | "raw" | "vmdk" | "unknown" {
  const path = url.toLowerCase().split(/[?#]/)[0];
  if (/\.(qcow2c?|qcow)$/.test(path)) return "qcow2";
  if (/\.vhd$/.test(path)) return "vhd";
  if (/\.(raw|img)$/.test(path)) return "raw";
  if (/\.vmdk$/.test(path)) return "vmdk";
  return "unknown";
}

/**
 * A pass-through stream that throws once more than `max` bytes have flowed — a
 * running cap that catches a missing or dishonest Content-Length, a redirect to
 * something far larger than expected, or a mistyped URL before it fills the
 * exec host's disk.
 */
export function limitStream(
  max: number,
): TransformStream<Uint8Array, Uint8Array> {
  let seen = 0;
  return new TransformStream({
    transform(chunk, ctrl) {
      seen += chunk.byteLength;
      if (seen > max) {
        throw new Error(
          `download exceeded maxBytes=${max} (got > ${seen} bytes)`,
        );
      }
      ctrl.enqueue(chunk);
    },
  });
}

/**
 * Stream a URL to a local file, optionally verifying a hex SHA-256 as it lands
 * (tee: one branch to disk, one to the digest — a single pass, no second read
 * of a multi-GB file) and optionally capping the byte count (`maxBytes`). The
 * file handle is always closed, even on error (a bare `Deno.remove` only
 * unlinks — an fd leak would survive in a long-lived process). URLs are
 * redacted in logs/errors (presigned URLs carry a credential). Not bounded by
 * `requestTimeoutMs`.
 */
export async function downloadToFile(
  net: StreamFetchLike,
  url: string,
  dest: string,
  opts: { sha256?: string; maxBytes?: number; logger?: MethodLogger } = {},
): Promise<void> {
  const safeUrl = redactUrl(url);
  opts.logger?.info("Downloading image {url}", { url: safeUrl });
  const resp = await net(url, { method: "GET" });
  if (!resp.ok || !resp.body) {
    throw new Error(
      `download ${safeUrl} failed (HTTP ${resp.status} ${resp.statusText})`,
    );
  }
  const source = opts.maxBytes !== undefined
    ? resp.body.pipeThrough(limitStream(opts.maxBytes))
    : resp.body;
  const file = await Deno.open(dest, {
    write: true,
    create: true,
    truncate: true,
  });
  try {
    if (opts.sha256) {
      // tee: one branch lands on disk, the other feeds the hash. allSettled
      // (not all) so a fault in one branch still lets the other settle — no
      // detached pipe left writing to the file after we have thrown.
      const [toDisk, toHash] = source.tee();
      const hash = createHash("sha256");
      const results = await Promise.allSettled([
        toDisk.pipeTo(file.writable),
        (async () => {
          for await (const chunk of toHash) hash.update(chunk);
        })(),
      ]);
      const failed = results.find((r) => r.status === "rejected");
      if (failed) throw (failed as PromiseRejectedResult).reason;
      const got = hash.digest("hex");
      if (got.toLowerCase() !== opts.sha256.toLowerCase()) {
        throw new Error(
          `SHA-256 mismatch for ${safeUrl}: expected ${opts.sha256}, got ${got}`,
        );
      }
    } else {
      await source.pipeTo(file.writable);
    }
  } finally {
    // pipeTo closes (and flushes) the writable on success and on abort; this is
    // the safety net for a path that threw before pipeTo ran. Closing an
    // already-closed FsFile throws BadResource — caught.
    try {
      file.close();
    } catch { /* already closed / aborted by pipeTo */ }
  }
}

/**
 * Convert a disk image to the XO wire format via `qemu-img` (a host binary —
 * see the manifest note). VHD out is `vpc` with a dynamic (sparse) subformat so
 * the upload stays small; raw out is a flat image. Throws with stderr on
 * failure. Only reached for non-vhd/raw sources, so vhd/raw inputs never shell
 * out.
 */
export async function qemuConvert(
  src: string,
  srcFmt: string,
  dest: string,
  destFmt: "vhd" | "raw",
  logger?: MethodLogger,
): Promise<void> {
  const g = globalThis as { Deno?: { Command?: unknown } };
  if (!g.Deno?.Command) {
    throw new Error(
      "qemu-img conversion needs Deno.Command (host run permission); " +
        "supply a vhd/raw source URL to avoid conversion",
    );
  }
  const out = destFmt === "vhd" ? "vpc" : "raw";
  const args = [
    "convert",
    "-f",
    srcFmt,
    "-O",
    out,
    ...(destFmt === "vhd" ? ["-o", "subformat=dynamic"] : []),
    src,
    dest,
  ];
  logger?.info("qemu-img {args}", { args: args.join(" ") });
  const cmd = new Deno.Command("qemu-img", { args, stderr: "piped" });
  const { success, stderr } = await cmd.output();
  if (!success) {
    throw new Error(
      `qemu-img convert failed: ${new TextDecoder().decode(stderr)}`,
    );
  }
}

/**
 * Import a prepared VHD/raw file to an SR, creating a new VDI
 * (`POST /rest/v0/srs/<sr>/vdis?name_label=..[&raw]`). The disk bytes are the
 * request body; the response is the new VDI's UUID. The `raw` flag is a bare
 * presence param (absent -> VHD). Not bounded by `requestTimeoutMs`.
 */
export async function importVdiToSr(
  cfg: GlobalArgs,
  net: StreamFetchLike,
  srId: string,
  params: { nameLabel: string; nameDescription?: string; raw: boolean },
  body: Uint8Array | ReadableStream<Uint8Array>,
): Promise<string> {
  const base = cfg.baseUrl.replace(/\/+$/, "");
  const qs = [`name_label=${encodeURIComponent(params.nameLabel)}`];
  if (params.nameDescription) {
    qs.push(`name_description=${encodeURIComponent(params.nameDescription)}`);
  }
  if (params.raw) qs.push("raw"); // bare flag, per XO's documented ?raw form
  const url = `${base}/rest/v0/srs/${enc(srId)}/vdis?${qs.join("&")}`;
  const headers: Record<string, string> = {
    "Content-Type": "application/octet-stream",
    "Accept": "application/json",
  };
  if (cfg.authToken) {
    guardAuthToken(cfg.authToken);
    headers["Cookie"] = `authenticationToken=${cfg.authToken}`;
  }
  // XO's import handler REQUIRES a Content-Length — it rejects a chunked upload
  // with "Trying to import a VDI without a length field". fetch sets the length
  // automatically for a sized body (Uint8Array/Blob) but sends a ReadableStream
  // CHUNKED (and ignores a manual Content-Length header), so importFromUrl
  // passes a buffered Uint8Array. A stream body is still typed here but would be
  // rejected by XO; callers must pass sized bytes.
  const isStream = body instanceof ReadableStream;
  const resp = await net(url, {
    method: "POST",
    headers,
    body,
    ...(isStream ? { duplex: "half" as const } : {}),
  });
  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(
      `XO import VDI to SR ${srId} failed (HTTP ${resp.status}): ` +
        `${text || resp.statusText}`,
    );
  }
  // XO returns the new VDI's identity as JSON (`{ id }` / `{ uuid }`, the shape
  // the live endpoint uses), or a bare/quoted uuid, or a /rest/v0/vdis/<uuid>
  // path. Parse JSON when present, then extract — extractUuid reads .id/.uuid
  // from an object and the last segment from a path.
  const trimmed = text.trim();
  let payload: unknown = trimmed;
  try {
    payload = JSON.parse(trimmed);
  } catch { /* not JSON — treat as a bare/quoted/path string */ }
  const uuid = extractUuid(
    typeof payload === "string" ? payload.replace(/^"|"$/g, "") : payload,
  );
  if (!uuid) {
    // A 2xx with an unparseable body still means XO created the VDI — surface
    // it loudly rather than reporting a phantom success over an orphaned disk.
    throw new Error(
      `XO import to SR ${srId} returned 2xx but no VDI uuid; a VDI may have ` +
        `been created and orphaned. Response: ${text || "<empty body>"}`,
    );
  }
  return uuid;
}

// ---------------------------------------------------------------------------
// WebSocket JSON-RPC transport seam
// ---------------------------------------------------------------------------
//
// XO's authoritative control-plane API (schedule.*, backupNg.*, xo.getAllObjects,
// system.getServerVersion) lives only on xo-server's WebSocket JSON-RPC 2.0
// surface, NOT on the REST API (/rest/v0). {@link xoJsonRpc} is the structural
// sibling of {@link xoRequest}: same {@link GlobalArgs} config, same per-call
// deadline/force-close so a hung call can never hold the per-model lock, same
// injectable transport ({@link RpcConnect}) so unit tests hit no socket.
//
// VERIFY-AT-IMPLEMENT (unverified without a live XO — see pub-21 plan):
//   (1) ws upgrade path: the documented default is `wss://<host>/api/`
//       (historical xo-cli/xo-server). {@link rpcWsUrl} encodes it; confirm
//       against the target xo-server before any write consumer (pub-22/pub-20).
//   (2) auth mechanism: the safe path is a post-connect
//       `session.signInWithToken({ token })` RPC (NOT an upgrade cookie).
//   (3) JSON-RPC frame/id/error shape (id-correlated; error.code/message/data).
//   (4) `system.getServerVersion` exists on the target xo-server.
//
// PRIVATE-CA LIMITATION (resolved — clean path taken): the plan weighed
// `npm:ws` to carry a custom CA for a private-CA (FreeIPA) XOA over ws, since
// Deno's built-in WebSocket has no per-connection CA option. `npm:ws` was
// DROPPED because it fails the extension `dependency-trust` quality gate (and
// that failure would cascade to every ticket stacked on this file). So the
// transport uses ONLY the built-in WebSocket, and {@link makeRpcConnect} THROWS
// a clear error when `cfg.caCert` is set rather than silently ignoring it — a
// private-CA XOA must be reached over REST ({@link xoRequest}) or be given a
// publicly/system-trusted cert. The plan's verify-gate said "if npm:ws isn't
// viable, surface it"; it isn't cleanly viable, so this is the surfaced result.

/** A decoded inbound WebSocket frame: text carries data, binary is opaque. */
export type RpcFrame =
  | { kind: "text"; data: string }
  | { kind: "binary" };

/**
 * The injectable WebSocket seam — the ws analogue of {@link FetchLike}. A real
 * socket is built by {@link makeRpcConnect}; tests inject a fake. `onMessage`
 * delivers a classified {@link RpcFrame} so a non-text frame can reach
 * {@link xoJsonRpc}'s reject path (rather than being silently coerced).
 */
export interface RpcSocket {
  /** Resolves once the socket is open (connect + TLS handshake done). */
  opened: Promise<void>;
  /** Send one text frame. */
  send(data: string): void;
  /** Close the socket (idempotent; releases the per-model lock). */
  close(): void;
  /** Register the inbound-frame callback. */
  onMessage(cb: (frame: RpcFrame) => void): void;
  /** Register the transport-error callback. */
  onError(cb: (err: unknown) => void): void;
  /** Register the socket-closed callback. */
  onClose(cb: () => void): void;
}

/** Build a {@link RpcSocket} from config (injected in tests). */
export type RpcConnect = (cfg: GlobalArgs) => RpcSocket;

/**
 * Derive the ws/wss upgrade URL from the REST `baseUrl` — pure, no I/O.
 * Normalizes trailing slashes exactly like {@link xoRequest}
 * (`baseUrl.replace(/\/+$/, "")`), maps the scheme (`https`->`wss`,
 * `http`->`ws`), and joins the (unverified-default) `/api/` upgrade path.
 *
 * @param baseUrl The XO REST base URL (e.g. `https://xo.example:443`).
 * @returns The `wss://.../api/` (or `ws://.../api/`) URL.
 */
export function rpcWsUrl(baseUrl: string): string {
  const base = baseUrl.replace(/\/+$/, "");
  const ws = base.replace(/^https:/i, "wss:").replace(/^http:/i, "ws:");
  return `${ws}/api/`;
}

/** Wrap a built-in WHATWG `WebSocket` as an {@link RpcSocket}. */
function builtinSocket(url: string): RpcSocket {
  const WsCtor = (globalThis as { WebSocket?: typeof WebSocket }).WebSocket;
  if (!WsCtor) {
    throw new Error("built-in WebSocket unavailable in this runtime");
  }
  const ws = new WsCtor(url);
  let onMsg: (frame: RpcFrame) => void = () => {};
  let onErr: (err: unknown) => void = () => {};
  let onCls: () => void = () => {};
  const opened = new Promise<void>((resolve, reject) => {
    ws.addEventListener("open", () => resolve(), { once: true });
    ws.addEventListener("error", (e) => reject(e), { once: true });
  });
  ws.addEventListener("message", (ev: MessageEvent) => {
    const d = ev.data;
    onMsg(
      typeof d === "string" ? { kind: "text", data: d } : { kind: "binary" },
    );
  });
  ws.addEventListener("error", (e) => onErr(e));
  ws.addEventListener("close", () => onCls());
  return {
    opened,
    send: (data) => ws.send(data),
    close: () => {
      try {
        ws.close();
      } catch { /* already closing/closed */ }
    },
    onMessage: (cb) => (onMsg = cb),
    onError: (cb) => (onErr = cb),
    onClose: (cb) => (onCls = cb),
  };
}

/**
 * Build the real WebSocket transport: {@link rpcWsUrl}, then Deno's built-in
 * WHATWG `WebSocket` behind the seam. The pure URL helper is unit-tested; socket
 * construction is not driven by the test suite (every test injects a fake).
 * Guards the token before it can cross the wire.
 *
 * LIMITATION — private-CA XOA is NOT reachable over WebSocket. Deno's built-in
 * `WebSocket` cannot present a custom CA (no per-connection `caCerts` option,
 * unlike `Deno.createHttpClient` used by the REST {@link xoRequest} seam), so a
 * `cfg.caCert` (private-CA, e.g. FreeIPA XOA) cannot be honored here. Rather
 * than silently ignore it and fail TLS verification opaquely, this THROWS a
 * clear error when `caCert` is set. Use a publicly/system-trusted cert on the
 * XOA to reach it over JSON-RPC, or stay on REST for a private-CA XOA. (The
 * original plan weighed `npm:ws` for the custom-CA path; it was dropped because
 * it fails the extension dependency-trust gate — see the transport-section note.)
 *
 * @param cfg Connection + auth + TLS-trust config.
 * @returns A live {@link RpcSocket}.
 * @throws When `cfg.caCert` is set (private-CA XOA is unsupported over ws).
 */
export function makeRpcConnect(cfg: GlobalArgs): RpcSocket {
  if (cfg.authToken) guardAuthToken(cfg.authToken);
  if (cfg.caCert) {
    throw new Error(
      "xoJsonRpc: private-CA XOA (caCert set) is not supported over " +
        "WebSocket; Deno's built-in WebSocket cannot use a custom CA. Use a " +
        "publicly/system-trusted cert for the XOA, or reach it over REST.",
    );
  }
  return builtinSocket(rpcWsUrl(cfg.baseUrl));
}

/**
 * Format a JSON-RPC error object as `(<code>): <message>` — code+message ONLY,
 * so a thrown message can never carry the token or params.
 */
function rpcErrText(err: { code?: unknown; message?: unknown }): string {
  const code = err.code === undefined || err.code === null
    ? "unknown"
    : err.code;
  const msg = typeof err.message === "string" ? err.message : "no message";
  return `(${code}): ${msg}`;
}

/** Stringify an unknown thrown value for a transport-error message. */
function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Issue one XO JSON-RPC 2.0 call over a WebSocket — the control-plane seam that
 * REST cannot reach. Connect-per-call (swamp methods are stateless and the
 * per-model lock means no socket can be shared): open, sign in with the token
 * (id 1), send the method (id 2), return the unwrapped `result`, and
 * `close()` in `finally` so a hung call never leaks a socket or holds the lock.
 *
 * Correlation & framing: a monotonic integer id per connection starting at 1.
 * A frame whose `id` matches the pending request is the response; a frame with
 * no id (or id null) and no `error` is an XO object-update push -> IGNORE; a
 * frame with a non-matching, non-null id -> ignore; a no-id/null-id frame that
 * DOES carry an `error` is a server-side JSON-RPC parse/protocol error ->
 * TERMINAL "malformed RPC response" (surfacing code+message). Non-text frames,
 * non-JSON text, and a response missing both `result` and `error` -> malformed.
 *
 * Secrecy: the token and params NEVER appear in any thrown message; a logged ws
 * URL would be redacted. The authToken is guarded for CR/LF/`;` before the wire.
 *
 * LIMITATION: a private-CA XOA (`cfg.caCert` set) is NOT reachable over this
 * transport — Deno's built-in WebSocket cannot present a custom CA — so the
 * default {@link makeRpcConnect} THROWS a clear error when `caCert` is set.
 * Reach a private-CA XOA over REST ({@link xoRequest}) or give it a
 * publicly/system-trusted cert. (`npm:ws`, which could carry a custom CA, was
 * dropped for failing the extension dependency-trust gate.)
 *
 * @param cfg Connection + auth + TLS-trust config.
 * @param method The JSON-RPC method (e.g. `system.getServerVersion`).
 * @param params The method params (default `{}`).
 * @param opts `timeoutMs` overrides `cfg.requestTimeoutMs` for the whole call.
 * @param connect Transport factory (defaults to {@link makeRpcConnect}).
 * @returns The unwrapped JSON-RPC `result`.
 * @throws On JSON-RPC error, sign-in failure, timeout, transport error, a
 *   malformed/id-mismatched frame, or a private-CA (`caCert`) config.
 */
export async function xoJsonRpc(
  cfg: GlobalArgs,
  method: string,
  params: Record<string, unknown> = {},
  opts: { timeoutMs?: number } = {},
  connect: RpcConnect = makeRpcConnect,
): Promise<unknown> {
  // `async` (not a bare Promise-returning fn) so a pre-flight throw — a bad
  // token here, or a connect() that throws — surfaces as a rejection, never a
  // synchronous throw at the call site (mirrors the async xoRequest seam).
  if (cfg.authToken) guardAuthToken(cfg.authToken);
  const deadline = opts.timeoutMs ?? cfg.requestTimeoutMs;
  const signInId = 1;
  const callId = 2;
  const socket = connect(cfg);

  return await new Promise<unknown>((resolve, reject) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const done = (fn: () => void) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      // Force-close so a hung call can never leak a socket or hold the lock.
      try {
        socket.close();
      } catch { /* already closing/closed */ }
      fn();
    };
    const fail = (err: Error) => done(() => reject(err));
    const ok = (val: unknown) => done(() => resolve(val));

    if (deadline && deadline > 0) {
      timer = setTimeout(
        () => fail(new Error(`XO RPC ${method} timed out after ${deadline}ms`)),
        deadline,
      );
    }

    socket.onError((err) =>
      fail(new Error(`XO RPC ${method} transport error: ${errText(err)}`))
    );
    socket.onClose(() =>
      fail(new Error(`XO RPC ${method}: connection closed before response`))
    );

    socket.onMessage((frame) => {
      if (settled) return;
      if (frame.kind !== "text") {
        fail(
          new Error(
            `XO RPC ${method}: malformed RPC response (non-text frame)`,
          ),
        );
        return;
      }
      let msg: unknown;
      try {
        msg = JSON.parse(frame.data);
      } catch {
        fail(
          new Error(`XO RPC ${method}: malformed RPC response (non-JSON text)`),
        );
        return;
      }
      if (typeof msg !== "object" || msg === null) {
        fail(new Error(`XO RPC ${method}: malformed RPC response`));
        return;
      }
      const f = msg as { id?: unknown; result?: unknown; error?: unknown };
      const err = (f.error ?? null) as
        | { code?: unknown; message?: unknown }
        | null;
      const hasId = "id" in f && f.id !== null && f.id !== undefined;

      // No id (or id null): an error is a terminal server-side parse/protocol
      // error; otherwise it is an unsolicited notification push -> ignore.
      if (!hasId) {
        if (err) {
          fail(
            new Error(
              `XO RPC ${method}: malformed RPC response ${rpcErrText(err)}`,
            ),
          );
        }
        return;
      }

      if (f.id === signInId) {
        if (err) {
          fail(new Error(`XO RPC sign-in failed ${rpcErrText(err)}`));
          return;
        }
        // Signed in: now send the requested method (never before sign-in).
        try {
          socket.send(
            JSON.stringify({ jsonrpc: "2.0", id: callId, method, params }),
          );
        } catch (e) {
          fail(new Error(`XO RPC ${method} transport error: ${errText(e)}`));
        }
        return;
      }

      if (f.id === callId) {
        if (err) {
          fail(new Error(`XO RPC ${method} failed ${rpcErrText(err)}`));
          return;
        }
        if (!("result" in f)) {
          fail(
            new Error(`XO RPC ${method}: malformed RPC response (no result)`),
          );
          return;
        }
        ok(f.result);
        return;
      }
      // A structured frame bearing a non-null id that correlates to no pending
      // request (sign-in already settled, call id differs) is a protocol
      // violation on the terminal response -> malformed. (Id-less frames were
      // handled above: an error is terminal, anything else is an ignored push.)
      fail(new Error(`XO RPC ${method}: malformed RPC response (id mismatch)`));
    });

    socket.opened
      .then(() => {
        if (settled) return;
        // Auth handshake is the FIRST RPC; the method rides only after it ACKs.
        try {
          socket.send(
            JSON.stringify({
              jsonrpc: "2.0",
              id: signInId,
              method: "session.signInWithToken",
              params: { token: cfg.authToken ?? "" },
            }),
          );
        } catch (e) {
          fail(new Error(`XO RPC sign-in failed: ${errText(e)}`));
        }
      })
      .catch((e) =>
        fail(new Error(`XO RPC ${method}: connection failed: ${errText(e)}`))
      );
  });
}

// ---------------------------------------------------------------------------
// Model definition
// ---------------------------------------------------------------------------

/** Xen Orchestra / XCP-NG VM lifecycle model. */
export const model = {
  type: "@shrug/xen-orchestra",
  version: "2026.11.21.5",
  description:
    "Provision and control a VM on an XCP-NG host via the Xen Orchestra REST " +
    "API: create (from template, with cloud-init), start, stop, snapshot, " +
    "migrate, destroy, plus VM/host/template/pool/SR/network/PIF discovery, " +
    "network creation (VLAN + host-internal), and SR creation (createSR — NFS/" +
    "SMB/ISO/local libraries). Disks: createVdi provisions a blank VDI and " +
    "importFromUrl imports a disk image; attachVdi/detachVdi bind a VDI to a " +
    "VM. Also registers XCP-NG hosts with XO (addServer/listServers) so new " +
    "pools become migrate targets. Backup repositories (remotes): " +
    "listBackupRepositories/getBackupRepository/createBackupRepository/" +
    "updateBackupRepository manage SMB/NFS/S3/local remotes (credential URL is " +
    "redacted before persist/log), forgetBackupRepository (dryRun-gated) and " +
    "reclaimBackupRepositorySpace (dryRun-gated) are the destructive paths, and " +
    "benchmarkBackupRepository/getBackupRepositoryHealth probe a remote. " +
    "Backup-archive discovery and file-level restore via live-disk mount: " +
    "listBackupArchives/getBackupArchive/listBackupJobs/listRestoreLogs are " +
    "safe reads, and mountLiveDisk/unmountLiveDisk manage a stateful live-disk " +
    "handle (the liveDiskId MUST be unmounted to release the mount on XO). " +
    "Backup schedules: listSchedules/getSchedule read over REST, runSchedule " +
    "triggers an immediate backup run (REST, consequential), and createSchedule/" +
    "updateSchedule/deleteSchedule write over the JSON-RPC transport " +
    "(schedule.create/set/delete; deleteSchedule is dryRun-gated, default true).",
  globalArguments: GlobalArgsSchema,
  resources: {
    "vm": {
      description: "A managed VM's normalized live-state snapshot",
      schema: VmSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "server": {
      description:
        "A registered XO server (XCP-NG host/pool connection) live-state snapshot",
      schema: ServerSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "network": {
      description: "A created/managed XCP-NG network's live-state snapshot",
      schema: NetworkSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "sr": {
      description: "A created/managed SR's normalized live-state snapshot",
      schema: SrSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "vif": {
      description:
        "A VIF binding created/attached by attachVif (uuid/mac/network/attached)",
      schema: VifSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "schedule": {
      description:
        "An XO backup schedule binding (id/jobId/cron/timezone/name/enabled) " +
        "recorded by getSchedule/createSchedule/updateSchedule. Read a field " +
        'via data.latest(name,"schedule:<id>").attributes.<field>.',
      schema: ScheduleSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "inventory": {
      description:
        "A discovery listing (templates/pools/srs/networks/backup-archives/" +
        "backup-jobs/restore-logs) for UUID/id resolution",
      schema: InventorySchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "liveDisk": {
      description:
        "A live-disk mount from a backup archive (archiveId/liveDiskId/status) " +
        "created by mountLiveDisk; the liveDiskId MUST be unmounted via " +
        "unmountLiveDisk to release the mount on the XO host. Uniquely named " +
        "per liveDiskId so concurrent/repeat mounts never clobber, and read " +
        'via data.latest(name,"liveDisk-<liveDiskId>").attributes.liveDiskId.',
      schema: LiveDiskSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "mintedToken": {
      description:
        "A token minted by createAuthToken. `tokenId` is vaulted (field-level " +
        "`sensitive`): persisted only as a vault reference; audit fields " +
        "plaintext. Uniquely named per mint (label + timestamp) so re-mints " +
        "never clobber a prior token's vault reference. Read the secret back " +
        'via data.latest(name,"<resourceName>").attributes.tokenId.',
      schema: MintedTokenSchema,
      lifetime: "infinite",
      garbageCollection: 5,
    },
    "taskDeletions": {
      description: "Audit record of a deleteTasks fan-out: per-id outcomes " +
        "(deleted/alreadyGone/failed) plus a count. Uniquely named per run " +
        "(timestamp) so concurrent batches never clobber one another.",
      schema: TaskDeletionSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "serverVersion": {
      description:
        "The XO server version read over the JSON-RPC transport by " +
        "getServerVersion (a read-only control-plane reachability proof)",
      schema: ServerVersionSchema,
      lifetime: "infinite",
      garbageCollection: 5,
    },
    "backupRepository": {
      description:
        "A backup repository (remote) snapshot from get/create/update. The " +
        "`urlRedacted` field has userinfo+query stripped; the raw credential " +
        "is never persisted.",
      schema: BackupRepositorySchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "backupRepositoryList": {
      description: "A listing of backup repositories (remotes) from " +
        "listBackupRepositories; each item is a full redacted repository.",
      schema: BackupRepositoryListSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "backupRepositoryAction": {
      description:
        "The outcome of a forget/reclaim-space/benchmark action (or its dryRun " +
        "plan) on a backup repository, incl. an async taskRef when XO defers.",
      schema: BackupRepositoryActionSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "backupRepositoryHealth": {
      description:
        "A backup-repository health snapshot (raw XO /health payload).",
      schema: BackupRepositoryHealthSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  methods: {
    create: {
      description:
        "Provision a VM from a template (with optional cloud-init) and record " +
        "its snapshot. Default sizing when unset is decided by the template; " +
        "pass cpus/memory/vdis to override. To install a fresh OS from an ISO " +
        "(e.g. OPNsense/BSD/Linux, which have no cloud-init), use a blank " +
        "'Other install media' template plus `install={method:'cdrom', " +
        "repository:<ISO VDI id>}` (resolve the ISO VDI via listVdis) — XO " +
        "attaches the ISO as a boot CD. Uses ?sync=true unless sync=false.",
      arguments: z.object({
        name_label: z.string().describe("VM name"),
        name_description: z.string().optional().describe("VM description"),
        template: z.string().describe(
          "Template UUID (resolve via listTemplates)",
        ),
        poolId: z.string().optional().describe(
          "Pool UUID (defaults to global poolId)",
        ),
        cpus: z.number().int().optional().describe("vCPU count"),
        memory: z.number().optional().describe("RAM in bytes"),
        vifs: z
          .array(
            z.object({
              network: z.string().describe("Network UUID"),
              mac: z.string().optional(),
            }),
          )
          .optional()
          .describe("Virtual NICs (resolve network via listNetworks)"),
        vdis: z
          .array(
            z.object({
              sr: z.string().describe("SR UUID (resolve via listSRs)"),
              size: z.number().describe("Disk size in bytes"),
              name_label: z.string(),
              name_description: z.string().optional(),
            }),
          )
          .optional()
          .describe("Disks to create (omit to use the template's disks)"),
        cloud_config: z.string().optional().describe(
          "cloud-init user-data (content)",
        ),
        network_config: z.string().optional().describe(
          "cloud-init network-config (content)",
        ),
        install: z
          .object({
            method: z
              .enum(["cdrom", "network"])
              .default("cdrom")
              .describe("'cdrom' = boot an ISO; 'network' = PXE"),
            repository: z
              .string()
              .describe(
                "For 'cdrom': the ISO image's VDI UUID (resolve via " +
                  "listVdis). For 'network': ''.",
              ),
          })
          .optional()
          .describe(
            "Boot an OS installer at creation: mount an ISO as a CD " +
              "(method 'cdrom') or PXE-boot (method 'network'). Use for a " +
              "fresh install when the guest OS has no cloud-init image.",
          ),
        boot: z.boolean().default(true).describe("Start the VM after creation"),
        hvmBootFirmware: z.enum(["uefi", "bios"]).optional(),
        secureBoot: z.boolean().optional().describe("Enable UEFI Secure Boot"),
        copyHostBiosStrings: z.boolean().optional().describe(
          "Copy the host's BIOS strings into the VM",
        ),
        autoPoweron: z.boolean().optional().describe("Start on host boot"),
        clone: z.boolean().optional().describe(
          "Fast-clone the template's disks",
        ),
        sync: z.boolean().default(true).describe(
          "Wait inline (?sync=true) vs poll a task",
        ),
      }),
      execute: async (
        args: Record<string, unknown> & { _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const poolId = (args.poolId as string) || cfg.poolId;
        if (!poolId) {
          throw new Error(
            "create requires a poolId (arg or global); resolve one via listPools",
          );
        }
        const body = buildCreateBody(args);
        const sync = args.sync !== false;
        context.logger.info("Creating VM {name} in pool {pool}", {
          name: args.name_label,
          pool: poolId,
        });
        const res = await xoRequest(
          cfg,
          "POST",
          `pools/${enc(poolId)}/actions/create_vm`,
          { query: sync ? [["sync", "true"]] : [], body },
          doFetch,
        );
        const uuid = sync
          ? extractUuid(res)
          : extractUuid(await pollTask(cfg, res, doFetch));
        if (!uuid) {
          throw new Error(
            `create_vm returned no VM UUID: ${JSON.stringify(res)}`,
          );
        }
        context.logger.info("Created VM {uuid}", { uuid });
        return await snapshotVm(cfg, uuid, doFetch, context);
      },
    },
    start: {
      description:
        "Start a VM (`POST /vms/{id}/actions/start`) and refresh its snapshot.",
      arguments: z.object({ id: z.string().describe("VM UUID") }),
      execute: async (
        args: { id: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        context.logger.info("Starting VM {id}", { id: args.id });
        await xoRequest(
          cfg,
          "POST",
          `vms/${enc(args.id)}/actions/start`,
          {},
          doFetch,
        );
        return await snapshotVm(cfg, args.id, doFetch, context);
      },
    },
    stop: {
      description:
        "Stop a VM — clean ACPI shutdown by default, hard power-off when " +
        "force=true — and refresh its snapshot.",
      arguments: z.object({
        id: z.string().describe("VM UUID"),
        force: z.boolean().default(false).describe(
          "Hard power-off instead of ACPI",
        ),
      }),
      execute: async (
        args: { id: string; force: boolean; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const action = args.force ? "hard_shutdown" : "clean_shutdown";
        context.logger.info("Stopping VM {id} ({action})", {
          id: args.id,
          action,
        });
        await xoRequest(
          cfg,
          "POST",
          `vms/${enc(args.id)}/actions/${action}`,
          {},
          doFetch,
        );
        return await snapshotVm(cfg, args.id, doFetch, context);
      },
    },
    snapshot: {
      description:
        "Snapshot a VM (`POST /vms/{id}/actions/snapshot`) and refresh its " +
        "snapshot record.",
      arguments: z.object({
        id: z.string().describe("VM UUID"),
        name_label: z.string().describe("Snapshot name"),
      }),
      execute: async (
        args: { id: string; name_label: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        context.logger.info("Snapshotting VM {id} as {name}", {
          id: args.id,
          name: args.name_label,
        });
        await xoRequest(
          cfg,
          "POST",
          `vms/${enc(args.id)}/actions/snapshot`,
          { body: { name_label: args.name_label } },
          doFetch,
        );
        return await snapshotVm(cfg, args.id, doFetch, context);
      },
    },
    destroy: {
      description:
        "Destroy a VM (`DELETE /vms/{id}`). Verifies the VM exists first " +
        "(Rule 5) and records nothing further.",
      arguments: z.object({ id: z.string().describe("VM UUID") }),
      execute: async (
        args: { id: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Verify before destroy (throws HTTP 404 if it does not exist).
        await xoRequest(cfg, "GET", `vms/${enc(args.id)}`, {}, doFetch);
        context.logger.warning("Destroying VM {id}", { id: args.id });
        await xoRequest(cfg, "DELETE", `vms/${enc(args.id)}`, {}, doFetch);
        return { dataHandles: [] };
      },
    },
    get: {
      description: "Refresh a VM's live-state snapshot (`GET /vms/{id}`).",
      arguments: z.object({ id: z.string().describe("VM UUID") }),
      execute: async (
        args: { id: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        context.logger.info("Fetching VM {id}", { id: args.id });
        return await snapshotVm(cfg, args.id, doFetch, context);
      },
    },
    migrate: {
      description:
        "Migrate a VM to another host (`POST /vms/{id}/actions/migrate`). " +
        "`hostId` is the DESTINATION host UUID (resolve via listHosts), not a " +
        "pool. Cross-pool moves need `srId` (a destination SR for the disks, " +
        "via listSRs) and usually `networkIdByVifId` (map each source VIF to a " +
        "destination network, via listVifs + listNetworks) since the source " +
        "network won't exist on the target pool. NOTE: a cross-pool migration " +
        "reassigns the VM's UUID — the post-migrate re-snapshot is best-effort; " +
        "re-run listVms on the destination to find the moved VM.",
      arguments: z.object({
        id: z.string().describe("VM UUID to migrate"),
        hostId: z.string().describe(
          "Destination host UUID (resolve via listHosts)",
        ),
        srId: z.string().optional().describe(
          "Destination SR for all disks (required cross-pool; via listSRs)",
        ),
        migrationNetworkId: z.string().optional().describe(
          "Network UUID to carry the migration transport",
        ),
        srIdByVdiId: z.record(z.string(), z.string()).optional().describe(
          "Per-VDI SR map { vdiId: srId } (overrides srId per disk)",
        ),
        networkIdByVifId: z.record(z.string(), z.string()).optional().describe(
          "Per-VIF network map { vifId: networkId } (cross-pool VIF remap)",
        ),
        sync: z.boolean().default(true).describe(
          "Wait inline (?sync=true) vs poll a task",
        ),
      }),
      execute: async (
        args: {
          id: string;
          hostId: string;
          srId?: string;
          migrationNetworkId?: string;
          srIdByVdiId?: Record<string, string>;
          networkIdByVifId?: Record<string, string>;
          sync: boolean;
          _fetch?: FetchLike;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Verify the VM exists first (Rule 5) — migrate is disruptive.
        await xoRequest(cfg, "GET", `vms/${enc(args.id)}`, {}, doFetch);
        const body: Record<string, unknown> = { hostId: args.hostId };
        if (args.srId) body.srId = args.srId;
        if (args.migrationNetworkId) {
          body.migrationNetworkId = args.migrationNetworkId;
        }
        if (args.srIdByVdiId) body.srIdByVdiId = args.srIdByVdiId;
        if (args.networkIdByVifId) {
          body.networkIdByVifId = args.networkIdByVifId;
        }
        context.logger.warning("Migrating VM {id} to host {host}", {
          id: args.id,
          host: args.hostId,
        });
        const res = await xoRequest(
          cfg,
          "POST",
          `vms/${enc(args.id)}/actions/migrate`,
          { query: args.sync ? [["sync", "true"]] : [], body },
          doFetch,
        );
        // Async form returns a task ref; block on it so the method only
        // succeeds once the migration itself has.
        if (!args.sync) await pollTask(cfg, res, doFetch);
        // Re-snapshot to capture the new placement. Cross-pool migration
        // reassigns the UUID, so a 404 here is expected, not a failure —
        // record nothing and point the operator at listVms.
        try {
          return await snapshotVm(cfg, args.id, doFetch, context);
        } catch (e) {
          context.logger.warning(
            "Post-migrate snapshot of {id} failed (cross-pool migration " +
              "reassigns the VM uuid — re-run listVms on the destination to " +
              "find it): {err}",
            { id: args.id, err: String(e) },
          );
          return { dataHandles: [] };
        }
      },
    },
    clone: {
      description:
        "Copy a VM (`POST /vms/{id}/actions/clone`) and record the NEW VM's " +
        "snapshot. This is the halted-VM counterpart to `migrate`: `migrate` " +
        "is a live `migrate_send` for running VMs, whereas `clone` works on a " +
        "halted VM and is non-destructive (the source is left intact — a " +
        "rollback). Behaviour follows XO's clone action: pass `srId` to full-" +
        "copy the disks to another SR — when that SR is on a different pool " +
        "than the VM, XO does a cross-pool copy (`remoteCopyVm`), optionally " +
        "compressing the export stream (`compress`). Omit `srId` for a same-SR " +
        "clone: `fast=true` (default) is a fast copy-on-write clone, " +
        "`fast=false` a full copy. Cross-pool copy does NOT remap VIFs — XO " +
        "maps them onto the destination pool's networks by name_label, so " +
        "verify placement with listVifs afterwards. A cross-pool copy mints a " +
        "NEW VM UUID (returned/snapshotted here); the source keeps its UUID. " +
        "WARNING: a cross-pool copy streams the whole disk and can run for many " +
        "minutes — far longer than the default 2-minute `requestTimeoutMs`. " +
        "Raise `requestTimeoutMs` (per-run or on the model) to span the copy " +
        "before calling this; otherwise the client aborts mid-copy while XO " +
        "keeps going, the call reports failure, and a naive retry starts a " +
        "SECOND copy. Prefer `sync=false` together with a raised timeout so a " +
        "single long-poll waits out the whole copy.",
      arguments: z.object({
        id: z.string().describe("Source VM UUID to copy"),
        srId: z.string().optional().describe(
          "Destination SR for all disks (full copy; cross-pool when the SR is " +
            "on another pool). Resolve via listSRs.",
        ),
        nameLabel: z.string().optional().describe(
          "name_label for the new VM (defaults to XO's '<source> (COPY)').",
        ),
        compress: z.enum(["gzip", "zstd"]).optional().describe(
          "Compress the export stream during a cross-pool copy (srId on " +
            "another pool). Ignored for same-pool copies.",
        ),
        fast: z.boolean().default(true).describe(
          "Same-SR only (srId omitted): true = fast CoW clone, false = full " +
            "copy. Ignored when srId is set (an SR copy is always full).",
        ),
        sync: z.boolean().default(true).describe(
          "Wait inline (?sync=true) vs poll a task",
        ),
      }),
      execute: async (
        args: {
          id: string;
          srId?: string;
          nameLabel?: string;
          compress?: "gzip" | "zstd";
          fast: boolean;
          sync: boolean;
          _fetch?: FetchLike;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Verify the source VM exists first (Rule 5).
        await xoRequest(cfg, "GET", `vms/${enc(args.id)}`, {}, doFetch);
        // XO's clone body is a union: the SR-copy shape carries srId/compress,
        // the same-SR shape carries fast. Only send the fields for the chosen
        // branch so XO picks the right code path.
        const body: Record<string, unknown> = {};
        if (args.nameLabel !== undefined) body.name_label = args.nameLabel;
        if (args.srId !== undefined) {
          body.srId = args.srId;
          if (args.compress !== undefined) body.compress = args.compress;
        } else {
          body.fast = args.fast;
        }
        context.logger.warning("Cloning VM {id}{dest}", {
          id: args.id,
          dest: args.srId ? ` to SR ${args.srId}` : "",
        });
        const res = await xoRequest(
          cfg,
          "POST",
          `vms/${enc(args.id)}/actions/clone`,
          { query: args.sync ? [["sync", "true"]] : [], body },
          doFetch,
        );
        // Resolve the NEW VM's uuid. resolveActionId handles both the inline
        // `{ id }` (sync) and the async `{ taskId }` ref (same helper the
        // network-create methods use); a bare extractUuid can't parse a task
        // ref, so don't hand-roll the sync/async split here.
        const uuid = await resolveActionId(cfg, res, doFetch);
        if (!uuid) {
          throw new Error(`clone returned no VM UUID: ${JSON.stringify(res)}`);
        }
        // The copy has already committed server-side by this point. A failure
        // to snapshot the new VM must NOT surface as "clone failed" — that
        // reads as a rollback and invites a retry, which would start a SECOND
        // full copy and orphan the first. So snapshot best-effort (like
        // migrate), but here the new uuid IS known: log it loudly for recovery.
        try {
          context.logger.info("Cloned VM {src} -> {uuid}", {
            src: args.id,
            uuid,
          });
          return await snapshotVm(cfg, uuid, doFetch, context);
        } catch (e) {
          context.logger.warning(
            "clone of {src} SUCCEEDED as new VM {uuid}, but snapshotting it " +
              "failed ({err}). Do NOT retry clone (it would copy again) — run " +
              "`get`/`listVms` against {uuid} to reconcile.",
            { src: args.id, uuid, err: String(e) },
          );
          return { dataHandles: [] };
        }
      },
    },
    createVdi: {
      description:
        "Create a new BLANK VDI (empty virtual disk) on an SR and return its " +
        "UUID — piece 1 of a provision+attach pair: feed the returned UUID " +
        "straight into attachVdi's `vdiId` to stand up a dedicated data disk " +
        "(e.g. a /var/www disk on an edge VM). POSTs `/rest/v0/vdis` with " +
        "`{ srId, virtual_size, name_label }` (XO's VDI-create endpoint; " +
        "`virtual_size` is in BYTES — sizeGiB is converted via gibToBytes) and " +
        "returns XO's `{ id }` as the new VDI UUID. Pre-verifies the SR exists " +
        "(a clean error before the write) and reads its SR_type: an `iso` SR " +
        "is rejected (read-only); pass `allowedSrTypes` to additionally " +
        "restrict to e.g. ['ext']. NOT idempotent: unlike createSR/createNetwork " +
        "there is NO name pre-check, so re-running with the same nameLabel " +
        "creates a SECOND disk — the caller must persist the returned UUID and " +
        "must not blindly retry (same contract as importFromUrl). Records the " +
        "new VDI under inventory `createdVdi` (items[0].uuid) for downstream " +
        "`data.latest(...,'createdVdi')` reads.",
      arguments: z.object({
        srId: z.string().describe(
          "Destination SR UUID (resolve via listSRs). A writable SR; an ISO " +
            "SR is rejected.",
        ),
        sizeGiB: z.number().int().positive().describe(
          "Disk size in GiB, converted to bytes for XO's virtual_size.",
        ),
        nameLabel: z.string().min(1).describe("name_label for the new VDI."),
        nameDescription: z.string().optional().describe(
          "Optional name_description for the new VDI.",
        ),
        allowedSrTypes: z.array(z.string()).optional().describe(
          "When set, require the SR's SR_type to be one of these (e.g. " +
            "['ext']) — a caller-chosen safety rail for a known target. " +
            "Omitted = accept any writable SR. An 'iso' SR is always rejected.",
        ),
      }),
      execute: async (
        args: {
          srId: string;
          sizeGiB: number;
          nameLabel: string;
          nameDescription?: string;
          allowedSrTypes?: string[];
          _fetch?: FetchLike;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Pre-verify the SR exists for a clean error before the write (Rule 5)
        // and to read its SR_type for the guards below.
        const srRaw = (await xoRequest(
          cfg,
          "GET",
          `srs/${enc(args.srId)}`,
          {},
          doFetch,
        )) as Record<string, unknown> | null;
        const srType = strOrNull((srRaw ?? {}).SR_type ?? (srRaw ?? {}).type) ??
          "";
        // An ISO SR is read-only; a blank VDI there is always wrong (XAPI would
        // reject it too, but a pre-check gives a cleaner message).
        if (srType === "iso") {
          throw new Error(
            `SR ${args.srId} is an ISO SR (read-only); cannot create a VDI on it`,
          );
        }
        // Optional caller-supplied allow-list (e.g. ['ext']): no hard-coded
        // ext-only restriction, since XAPI VDI.create works on any writable SR.
        if (
          args.allowedSrTypes && args.allowedSrTypes.length > 0 &&
          !args.allowedSrTypes.includes(srType)
        ) {
          throw new Error(
            `SR ${args.srId} has SR_type '${srType}', not one of the allowed ` +
              `types [${args.allowedSrTypes.join(", ")}]`,
          );
        }
        const sizeBytes = gibToBytes(args.sizeGiB);
        const body: Record<string, unknown> = {
          srId: args.srId,
          virtual_size: sizeBytes,
          name_label: args.nameLabel,
        };
        if (args.nameDescription !== undefined) {
          body.name_description = args.nameDescription;
        }
        context.logger.info(
          "Creating VDI {name} ({gib} GiB) on SR {sr}",
          { name: args.nameLabel, gib: args.sizeGiB, sr: args.srId },
        );
        const res = await xoRequest(cfg, "POST", "vdis", { body }, doFetch);
        const uuid = await resolveActionId(cfg, res, doFetch);
        if (!uuid) {
          throw new Error(
            `createVdi returned no VDI uuid; a VDI may have been created and ` +
              `orphaned on SR ${args.srId}: ${JSON.stringify(res)}`,
          );
        }
        context.logger.info(
          "Created VDI {uuid} ({gib} GiB) on SR {sr}",
          { uuid, gib: args.sizeGiB, sr: args.srId },
        );
        const handle = await context.writeResource(
          "inventory",
          "createdVdi",
          {
            kind: "createdVdi",
            count: 1,
            items: [{
              uuid,
              name_label: args.nameLabel,
              raw: {
                srId: args.srId,
                srType,
                sizeBytes,
                sizeGiB: args.sizeGiB,
              },
            }],
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    importFromUrl: {
      description:
        "Import a disk image from a URL into an SR as a new VDI — the first " +
        "half of standing up a cloud image on a pool that lacks it (e.g. a " +
        "Rocky GenericCloud onto a pool that only has empty templates). " +
        "Streams the URL to disk, converts it to the XO wire format when " +
        "needed, then uploads it to `POST /rest/v0/srs/<sr>/vdis` (XO returns " +
        "the new VDI uuid). Source format comes from the URL extension unless " +
        "`sourceFormat` overrides it; qcow2/vmdk/unknown are converted with " +
        "`qemu-img` (a HOST binary — see the manifest note) to `uploadFormat` " +
        "(default vhd, sparse), while a vhd/raw source uploads as-is with no " +
        "conversion and no host dependency. WARNING: downloads then uploads a " +
        "full disk (often many GB) and runs for many minutes — deliberately " +
        "NOT bounded by requestTimeoutMs (like a cross-pool `clone`). This " +
        "imports a VDI, NOT a bootable VM: pair the new VDI with a VM that " +
        "attaches it (see attachVdi). SHA-256: pass `sha256` to verify the " +
        "download in-flight; OMITTED means NO integrity check (a corrupt or " +
        "tampered image is imported as-is). DISK: writes the image (and, when " +
        "converting, a second copy) to the exec host's temp dir — peak use is " +
        "~2x the image size; set `maxBytes` to cap a runaway download before " +
        "it fills the disk. Source format is trusted from the URL extension " +
        "unless `sourceFormat` overrides it — a .raw/.vhd URL whose bytes are " +
        "actually qcow2 skips conversion and uploads garbage, so set " +
        "`sourceFormat` when the extension may lie. The URL is fetched " +
        "following redirects (operator-supplied; do not point it at untrusted " +
        "input).",
      arguments: z.object({
        url: z.string().url().describe(
          "Image URL (e.g. a Rocky/Alma GenericCloud .qcow2, or a .vhd/.raw).",
        ),
        srId: z.string().describe("Destination SR UUID (resolve via listSRs)."),
        nameLabel: z.string().describe("name_label for the new VDI."),
        nameDescription: z.string().optional().describe(
          "Optional name_description for the new VDI.",
        ),
        sourceFormat: z.enum(["auto", "qcow2", "vhd", "raw", "vmdk"]).default(
          "auto",
        ).describe(
          "Override the source format (default: infer from the URL extension).",
        ),
        uploadFormat: z.enum(["vhd", "raw"]).default("vhd").describe(
          "Wire format to upload when the source needs conversion. vhd " +
            "(default) is sparse/smaller; raw is flat. Ignored when the source " +
            "is already vhd/raw (uploaded as-is).",
        ),
        sha256: z.string().optional().describe(
          "Hex SHA-256 to verify the downloaded image against, in-flight. " +
            "Omitted = no integrity check.",
        ),
        maxBytes: z.number().int().positive().optional().describe(
          "Cap the download size in bytes; aborts once exceeded (guards a " +
            "mistyped URL or a redirect to something huge from filling the " +
            "exec host disk). Omitted = unbounded.",
        ),
        keepWorkDir: z.boolean().default(false).describe(
          "Keep the temp download/convert dir for debugging (default: remove).",
        ),
      }),
      execute: async (
        args: {
          url: string;
          srId: string;
          nameLabel: string;
          nameDescription?: string;
          sourceFormat: "auto" | "qcow2" | "vhd" | "raw" | "vmdk";
          uploadFormat: "vhd" | "raw";
          sha256?: string;
          maxBytes?: number;
          keepWorkDir: boolean;
          _fetch?: FetchLike;
          _netFetch?: StreamFetchLike;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const net = args._netFetch ?? makeStreamFetch(cfg);
        // Verify the destination SR exists before a long transfer (Rule 5-ish).
        await xoRequest(cfg, "GET", `srs/${enc(args.srId)}`, {}, doFetch);

        const srcFmt = args.sourceFormat === "auto"
          ? inferImageFormat(args.url)
          : args.sourceFormat;
        const work = await Deno.makeTempDir({ prefix: "xo-import-" });
        try {
          const srcPath = `${work}/src.${
            srcFmt === "unknown" ? "img" : srcFmt
          }`;
          await downloadToFile(net, args.url, srcPath, {
            sha256: args.sha256,
            maxBytes: args.maxBytes,
            logger: context.logger,
          });

          // vhd/raw upload as-is (pure, no host binary); anything else is
          // converted to uploadFormat via qemu-img.
          let uploadPath = srcPath;
          let wireRaw = srcFmt === "raw";
          if (srcFmt !== "vhd" && srcFmt !== "raw") {
            uploadPath = `${work}/disk.${args.uploadFormat}`;
            await qemuConvert(
              srcPath,
              srcFmt === "unknown" ? "qcow2" : srcFmt,
              uploadPath,
              args.uploadFormat,
              context.logger,
            );
            wireRaw = args.uploadFormat === "raw";
          }

          // XO's import needs a Content-Length, which fetch only sets for a
          // sized (non-stream) body — so read the prepared image into memory
          // and upload that. The default vhd wire format is sparse, so this
          // stays modest; a large raw upload buffers fully in memory.
          const bytes = await Deno.readFile(uploadPath);
          const uuid = await importVdiToSr(
            cfg,
            net,
            args.srId,
            {
              nameLabel: args.nameLabel,
              nameDescription: args.nameDescription,
              raw: wireRaw,
            },
            bytes,
          );
          context.logger.info("Imported VDI {uuid} to SR {sr}", {
            uuid,
            sr: args.srId,
          });
          const handle = await context.writeResource(
            "inventory",
            "importedVdi",
            {
              kind: "importedVdi",
              count: 1,
              items: [{
                uuid,
                name_label: args.nameLabel,
                raw: {
                  srId: args.srId,
                  // redacted: a presigned URL's query carries a credential.
                  sourceUrl: redactUrl(args.url),
                  sourceFormat: srcFmt,
                  wireFormat: wireRaw ? "raw" : "vhd",
                },
              }],
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } finally {
          if (!args.keepWorkDir) {
            await Deno.remove(work, { recursive: true }).catch(() => {});
          }
        }
      },
    },
    attachVdi: {
      description:
        "Attach an existing VDI to a VM as a new VBD (`POST /rest/v0/vbds`) — " +
        "piece 2 of standing up an imported cloud image: after importFromUrl " +
        "lands the disk and `create` makes a diskless VM (with cloud_config), " +
        "attach that VDI as the VM's bootable boot disk, then `start` it. XO " +
        "requires the VM and VDI be in the SAME pool (so import to an SR on " +
        "the VM's pool). For the boot disk pass bootable=true and userdevice " +
        "'0'; mode RW. Returns the new VBD uuid and re-snapshots the VM. " +
        "Detach with detachVdi (which leaves the VDI intact).",
      arguments: z.object({
        vmId: z.string().describe("VM UUID to attach the disk to."),
        vdiId: z.string().describe(
          "VDI UUID to attach (e.g. the one importFromUrl created).",
        ),
        bootable: z.boolean().default(false).describe(
          "Mark the VBD bootable (true for the OS/boot disk).",
        ),
        mode: z.enum(["RW", "RO"]).default("RW").describe("Disk access mode."),
        userdevice: z.string().optional().describe(
          "Device position, e.g. '0' for the boot disk; XO auto-assigns when " +
            "omitted.",
        ),
      }),
      execute: async (
        args: {
          vmId: string;
          vdiId: string;
          bootable: boolean;
          mode: "RW" | "RO";
          userdevice?: string;
          _fetch?: FetchLike;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Verify the VM exists for a clear error before the write (Rule 5); the
        // endpoint also validates the VDI and same-pool, but pre-checking the
        // VM gives a cleaner message than XO's generic 404.
        await xoRequest(cfg, "GET", `vms/${enc(args.vmId)}`, {}, doFetch);
        const body: Record<string, unknown> = {
          VM: args.vmId,
          VDI: args.vdiId,
          bootable: args.bootable,
          mode: args.mode,
        };
        if (args.userdevice !== undefined) body.userdevice = args.userdevice;
        context.logger.warning(
          "Attaching VDI {vdi} to VM {vm} (bootable={boot})",
          { vdi: args.vdiId, vm: args.vmId, boot: args.bootable },
        );
        const res = await xoRequest(cfg, "POST", "vbds", { body }, doFetch) as
          | { id?: string }
          | string
          | null;
        const vbdId = typeof res === "string" ? res : res?.id;
        if (!vbdId) {
          throw new Error(
            `attachVdi returned no VBD id: ${JSON.stringify(res)}`,
          );
        }
        const handle = await context.writeResource(
          "inventory",
          "attachedVbd",
          {
            kind: "attachedVbd",
            count: 1,
            items: [{
              uuid: vbdId,
              name_label: null,
              raw: {
                vmId: args.vmId,
                vdiId: args.vdiId,
                bootable: args.bootable,
                mode: args.mode,
              },
            }],
            retrievedAt: new Date().toISOString(),
          },
        );
        // The VBD is already created server-side by this point. A failure to
        // re-snapshot the VM must NOT surface as "attach failed" — that reads
        // as a rollback and invites a retry, which would create a SECOND VBD
        // for the same VDI (a double-attached RW disk). Snapshot best-effort;
        // the vbdId is already recorded above for reconciliation.
        try {
          const vm = await snapshotVm(cfg, args.vmId, doFetch, context);
          return { dataHandles: [handle, ...vm.dataHandles] };
        } catch (e) {
          context.logger.warning(
            "attachVdi created VBD {vbd} (VDI {vdi} -> VM {vm}) but " +
              "re-snapshotting the VM failed ({err}). Do NOT retry attach (it " +
              "would double-attach) — run `get` against the VM to reconcile.",
            { vbd: vbdId, vdi: args.vdiId, vm: args.vmId, err: String(e) },
          );
          return { dataHandles: [handle] };
        }
      },
    },
    detachVdi: {
      description: "Detach a VDI from a VM by destroying its VBD " +
        "(`DELETE /rest/v0/vbds/{id}`). The VDI itself is NOT deleted — this " +
        "only removes the attachment (the inverse of attachVdi). Find the VBD " +
        "uuid in attachVdi's record or the VM snapshot's VBDs. Verifies the " +
        "VBD exists first (Rule 5).",
      arguments: z.object({
        vbdId: z.string().describe("VBD UUID to destroy (detaches the VDI)."),
      }),
      execute: async (
        args: { vbdId: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Verify before destroy (Rule 5).
        await xoRequest(cfg, "GET", `vbds/${enc(args.vbdId)}`, {}, doFetch);
        context.logger.warning("Detaching VBD {id}", { id: args.vbdId });
        await xoRequest(cfg, "DELETE", `vbds/${enc(args.vbdId)}`, {}, doFetch);
        return { dataHandles: [] };
      },
    },
    getTask: {
      description:
        "Get an XO async task's current state (`GET /tasks/{id}`), recorded as " +
        "an `inventory` snapshot (kind `task`). Use to check the status/" +
        "progress of a long async action — e.g. a cross-pool clone/" +
        "`remoteCopyVm` whose task ref came back from a `sync=false` call — " +
        "WITHOUT blocking and WITHOUT re-issuing the action (which would start a " +
        "SECOND copy). `raw.status` is pending|success|failure; " +
        "`raw.properties.progress` is 0..1. Set `wait=true` to long-poll until " +
        "the task settles before returning (bounded by requestTimeoutMs); the " +
        "default returns the current state immediately.",
      arguments: z.object({
        id: z.string().describe(
          "Task id (e.g. the task ref returned by a prior async action).",
        ),
        wait: z.boolean().default(false).describe(
          "Block until the task settles (?wait=true) vs return current state.",
        ),
      }),
      execute: async (
        args: { id: string; wait: boolean; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const res = await xoRequest(
          cfg,
          "GET",
          `tasks/${enc(args.id)}`,
          { query: args.wait ? [["wait", "true"]] : [] },
          doFetch,
        );
        const item = normalizeRef(res);
        const handle = await context.writeResource("inventory", "task", {
          kind: "task",
          count: 1,
          items: [item],
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    listTemplates: {
      description:
        "List VM templates (`GET /vm-templates`) to resolve a template UUID.",
      arguments: z.object({}),
      execute: async (
        args: { _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        return await listInventory(
          cfg,
          "templates",
          "vm-templates",
          doFetch,
          context,
        );
      },
    },
    listPools: {
      description:
        "List pools (`GET /pools`) to resolve the pool UUID for create.",
      arguments: z.object({}),
      execute: async (
        args: { _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        return await listInventory(cfg, "pools", "pools", doFetch, context);
      },
    },
    listSRs: {
      description:
        "List storage repositories (`GET /srs`) to resolve an SR UUID and read " +
        "capacity — `raw.physical_size`/`raw.physical_usage`/`raw.size` show " +
        "free space for placing a VM's disks.",
      arguments: z.object({}),
      execute: async (
        args: { _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        return await listInventory(
          cfg,
          "srs",
          "srs",
          doFetch,
          context,
          "uuid,name_label,name_description,type,$pool," +
            "physical_size,physical_usage,size,SR_type,content_type,shared",
        );
      },
    },
    listVdis: {
      description:
        "List VDIs (`GET /vdis`) — virtual disks and ISO images — recorded as " +
        "an `inventory` snapshot (kind `vdis`). Primary use: resolve an ISO " +
        "image's VDI UUID to feed `create`'s `install.repository` for a " +
        "boot-from-ISO install. Pass `sr` to scope to one SR (e.g. an ISO SR) " +
        "or `filter` for a raw XO complex-matcher string.",
      arguments: z.object({
        sr: z.string().optional().describe(
          "Scope to VDIs on this SR UUID (e.g. an ISO SR)",
        ),
        filter: z.string().optional().describe(
          "Raw XO complex-matcher filter (e.g. `name_label:opnsense`)",
        ),
      }),
      execute: async (
        args: Record<string, unknown> & { _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const query: Array<[string, string]> = [[
          "fields",
          "uuid,name_label,name_description,size,$SR,VDI_type,type," +
          "is_a_snapshot",
        ]];
        const filters: string[] = [];
        if (args.sr) filters.push(`$SR:${String(args.sr)}`);
        if (args.filter) filters.push(String(args.filter));
        if (filters.length) query.push(["filter", filters.join(" ")]);
        const res = await xoRequest(cfg, "GET", "vdis", { query }, doFetch);
        if (!Array.isArray(res)) {
          throw new Error(
            `XO GET vdis did not return a list (got ${typeof res})`,
          );
        }
        const items = res.map(normalizeRef);
        context.logger.info("XO lists {count} VDI(s)", { count: items.length });
        const handle = await context.writeResource("inventory", "vdis", {
          kind: "vdis",
          count: items.length,
          items,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    listNetworks: {
      description:
        "List networks (`GET /networks`) to resolve a VIF network UUID.",
      arguments: z.object({}),
      execute: async (
        args: { _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        return await listInventory(
          cfg,
          "networks",
          "networks",
          doFetch,
          context,
        );
      },
    },
    listVms: {
      description:
        "List all VMs (`GET /vms`) with identity/placement fields, recorded as " +
        "an `inventory` snapshot (kind `vms`). Use to resolve a VM UUID and read " +
        "its host (`raw.$container`), pool (`raw.$pool`), and power_state before " +
        "a migrate.",
      arguments: z.object({}),
      execute: async (
        args: { _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const res = await xoRequest(
          cfg,
          "GET",
          "vms",
          {
            query: [[
              "fields",
              "uuid,name_label,power_state,mainIpAddress,$container,$pool,memory",
            ]],
          },
          doFetch,
        );
        if (!Array.isArray(res)) {
          throw new Error(
            `XO GET vms did not return a list (got ${typeof res})`,
          );
        }
        const items = res.map(normalizeRef);
        context.logger.info("XO lists {count} VM(s)", { count: items.length });
        const handle = await context.writeResource("inventory", "vms", {
          kind: "vms",
          count: items.length,
          items,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    listHosts: {
      description:
        "List XCP-NG hosts (`GET /hosts`) with placement fields, recorded as an " +
        "`inventory` snapshot (kind `hosts`). Resolve a destination host UUID " +
        "here — `migrate` targets a host (`hostId`), not a pool. `raw.$pool` " +
        "ties each host to its pool.",
      arguments: z.object({}),
      execute: async (
        args: { _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const res = await xoRequest(
          cfg,
          "GET",
          "hosts",
          {
            query: [[
              "fields",
              "uuid,name_label,power_state,address,$pool",
            ]],
          },
          doFetch,
        );
        if (!Array.isArray(res)) {
          throw new Error(
            `XO GET hosts did not return a list (got ${typeof res})`,
          );
        }
        const items = res.map(normalizeRef);
        context.logger.info("XO lists {count} host(s)", {
          count: items.length,
        });
        const handle = await context.writeResource("inventory", "hosts", {
          kind: "hosts",
          count: items.length,
          items,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    createNetwork: {
      description: "Create a VLAN-backed network on a pool " +
        "(`POST /pools/{id}/actions/create_network`) — a VLAN tag on an uplink " +
        "PIF (resolve via listPifs). Idempotent by name within the pool. " +
        "Records the network snapshot.",
      arguments: z.object({
        name: z.string().describe("Network name (name_label)"),
        pif: z.string().describe(
          "Uplink PIF UUID to carry the VLAN (resolve via listPifs)",
        ),
        vlan: z.number().int().min(0).max(4094).describe("VLAN tag (0–4094)"),
        poolId: z.string().optional().describe(
          "Pool UUID (defaults to global poolId)",
        ),
        description: z.string().optional(),
        mtu: z.number().int().optional().describe("MTU (default 1500)"),
      }),
      execute: async (
        args: {
          name: string;
          pif: string;
          vlan: number;
          poolId?: string;
          description?: string;
          mtu?: number;
          _fetch?: FetchLike;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const poolId = args.poolId || cfg.poolId;
        if (!poolId) {
          throw new Error(
            "createNetwork requires a poolId (arg or global); resolve via listPools",
          );
        }
        let id = await findNetworkByName(cfg, poolId, args.name, doFetch);
        if (id) {
          context.logger.info(
            "Network {name} already exists as {id} in pool {pool}; reusing",
            { name: args.name, id, pool: poolId },
          );
        } else {
          const body: Record<string, unknown> = {
            name: args.name,
            pif: args.pif,
            vlan: args.vlan,
          };
          if (args.description !== undefined) {
            body.description = args.description;
          }
          if (args.mtu !== undefined) body.mtu = args.mtu;
          context.logger.info(
            "Creating VLAN {vlan} network {name} on pif {pif}",
            { vlan: args.vlan, name: args.name, pif: args.pif },
          );
          const res = await xoRequest(
            cfg,
            "POST",
            `pools/${enc(poolId)}/actions/create_network`,
            { query: [["sync", "true"]], body },
            doFetch,
          );
          id = await resolveActionId(cfg, res, doFetch);
          if (!id) {
            throw new Error(
              `create_network returned no network id: ${JSON.stringify(res)}`,
            );
          }
        }
        return await snapshotNetwork(cfg, id, doFetch, context);
      },
    },
    createInternalNetwork: {
      description: "Create a host-internal network (no PIF) on a pool " +
        "(`POST /pools/{id}/actions/create_internal_network`). Idempotent by " +
        "name within the pool. Records the network snapshot.",
      arguments: z.object({
        name: z.string().describe("Network name (name_label)"),
        poolId: z.string().optional().describe(
          "Pool UUID (defaults to global poolId)",
        ),
        description: z.string().optional(),
        mtu: z.number().int().optional().describe("MTU (default 1500)"),
      }),
      execute: async (
        args: {
          name: string;
          poolId?: string;
          description?: string;
          mtu?: number;
          _fetch?: FetchLike;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const poolId = args.poolId || cfg.poolId;
        if (!poolId) {
          throw new Error(
            "createInternalNetwork requires a poolId (arg or global)",
          );
        }
        let id = await findNetworkByName(cfg, poolId, args.name, doFetch);
        if (id) {
          context.logger.info(
            "Network {name} already exists as {id}; reusing",
            { name: args.name, id },
          );
        } else {
          const body: Record<string, unknown> = { name: args.name };
          if (args.description !== undefined) {
            body.description = args.description;
          }
          if (args.mtu !== undefined) body.mtu = args.mtu;
          context.logger.info("Creating internal network {name}", {
            name: args.name,
          });
          const res = await xoRequest(
            cfg,
            "POST",
            `pools/${enc(poolId)}/actions/create_internal_network`,
            { query: [["sync", "true"]], body },
            doFetch,
          );
          id = await resolveActionId(cfg, res, doFetch);
          if (!id) {
            throw new Error(
              `create_internal_network returned no id: ${JSON.stringify(res)}`,
            );
          }
        }
        return await snapshotNetwork(cfg, id, doFetch, context);
      },
    },
    createSR: {
      description:
        "Create a storage repository on a host (`POST /srs`) and record its " +
        "snapshot. `device_config` is passed AS-IS to XAPI; its keys depend on " +
        "`SR_type`. Recipes: NFS VHD SR -> SR_type 'nfs', device_config " +
        "{server, serverpath}; NFS ISO library -> SR_type 'iso', device_config " +
        "{location:'<server>:/<path>', type:'nfs_iso'}; SMB/CIFS ISO -> SR_type " +
        "'iso', device_config {location:'\\\\\\\\<server>\\\\<share>', " +
        "type:'cifs', username, password}; local dir ISO -> SR_type 'iso', " +
        "device_config {location:'/<path>', legacy_mode:'true'}. `content_type` " +
        "is auto-set to 'iso' for SR_type 'iso' and `shared` is computed by XO " +
        "(local vs network-backed). XOSTOR (SR_type 'linstor') is not supported " +
        "(XO returns 501). Idempotent within the host's pool by name_label + " +
        "SR_type AND a device_config transport match (so an NFS ISO library is " +
        "never confused with a same-named SMB/local one). Resolve `hostId` via " +
        "listHosts. NOTE: for host-local SR types (ext/lvm/local iso) reuse is " +
        "pool-scoped, not host-scoped — verify host attachment yourself. " +
        "`device_config`/`sm_config` may carry a credential (SMB/iSCSI): they " +
        "are marked sensitive and the recorded snapshot redacts `*pass*` keys, " +
        "but avoid passing a plaintext secret via `--input` (use a vault CEL in " +
        "a workflow step input).",
      arguments: z.object({
        hostId: z.string().describe(
          "Host UUID to create the SR on (resolve via listHosts)",
        ),
        name_label: z.string().describe("SR name (name_label)"),
        SR_type: z.string().describe(
          "XAPI SR type: nfs, smb, iso, ext, lvm, iscsi, hba, ... (not linstor)",
        ),
        device_config: z.record(z.string(), z.string())
          .meta({ sensitive: true })
          .describe(
            "XAPI device-config; keys depend on SR_type (see method " +
              "description). May contain a credential — resolve via a vault CEL.",
          ),
        name_description: z.string().optional().describe("SR description"),
        sm_config: z.record(z.string(), z.string()).optional()
          .meta({ sensitive: true })
          .describe("XAPI sm-config (rarely needed); may carry a credential"),
        size: z.number().optional().describe(
          "Physical size in bytes (for SR types that pre-size, e.g. lvm/iscsi; " +
            "omit for nfs/smb/iso)",
        ),
      }),
      execute: async (
        args: {
          hostId: string;
          name_label: string;
          SR_type: string;
          device_config: Record<string, string>;
          name_description?: string;
          sm_config?: Record<string, string>;
          size?: number;
          _fetch?: FetchLike;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Resolve the host's pool so the idempotency probe is pool-scoped (an
        // ISO library commonly exists once per pool). Best-effort: on failure
        // fall back to a name+type-only match rather than block creation.
        let poolId = "";
        try {
          const host = (await xoRequest(
            cfg,
            "GET",
            `hosts/${enc(args.hostId)}`,
            { query: [["fields", "$pool"]] },
            doFetch,
          )) as Record<string, unknown> | null;
          poolId = strOrNull(host?.$pool) ?? "";
        } catch (e) {
          // A failed host lookup (e.g. a wrong/typo'd hostId that 404s) must not
          // be silent: without a pool the idempotency probe widens to all pools,
          // so surface it. The create below still verifies the host via XAPI.
          context.logger.warning(
            "Host {host} lookup failed ({err}); SR reuse probe is UNSCOPED " +
              "(matches across all pools by name+type+device_config)",
            {
              host: args.hostId,
              err: e instanceof Error ? e.message : String(e),
            },
          );
          poolId = "";
        }
        let id = await findSrByName(
          cfg,
          poolId,
          args.name_label,
          args.SR_type,
          args.device_config,
          doFetch,
          context.logger,
        );
        if (id) {
          context.logger.info(
            "SR {name} ({type}) already exists as {id}; reusing",
            { name: args.name_label, type: args.SR_type, id },
          );
          const localIso = args.SR_type === "iso" &&
            String(args.device_config.legacy_mode) === "true";
          if (LOCAL_SR_TYPES.has(args.SR_type) || localIso) {
            context.logger.warning(
              "Reusing host-local SR {id} by pool scope; host attachment to " +
                "{host} is NOT verified",
              { id, host: args.hostId },
            );
          }
        } else {
          const body: Record<string, unknown> = {
            hostId: args.hostId,
            name_label: args.name_label,
            SR_type: args.SR_type,
            device_config: args.device_config,
          };
          if (args.name_description !== undefined) {
            body.name_description = args.name_description;
          }
          if (args.sm_config !== undefined) body.sm_config = args.sm_config;
          if (args.size !== undefined) body.size = args.size;
          context.logger.info(
            "Creating {type} SR {name} on host {host}",
            { type: args.SR_type, name: args.name_label, host: args.hostId },
          );
          const res = await xoRequest(cfg, "POST", "srs", { body }, doFetch);
          id = await resolveActionId(cfg, res, doFetch);
          if (!id) {
            throw new Error(`create SR returned no id: ${JSON.stringify(res)}`);
          }
        }
        return await snapshotSr(cfg, id, doFetch, context);
      },
    },
    listPifs: {
      description:
        "List physical interfaces (`GET /pifs`) with VLAN/device/host fields, " +
        "recorded as an `inventory` snapshot (kind `pifs`). Use to tell an " +
        "internal bridge (a network with no PIF) from a VLAN-on-PIF, and to " +
        "find a host's uplink PIF — `raw.vlan` is the tag (-1 = untagged), " +
        "`raw.$network` ties the PIF to its network, `raw.device` is e.g. eth0.",
      arguments: z.object({}),
      execute: async (
        args: { _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const res = await xoRequest(
          cfg,
          "GET",
          "pifs",
          {
            query: [[
              "fields",
              "uuid,device,vlan,management,$network,$host,$pool,ip,mode",
            ]],
          },
          doFetch,
        );
        if (!Array.isArray(res)) {
          throw new Error(
            `XO GET pifs did not return a list (got ${typeof res})`,
          );
        }
        const items = res.map(normalizeRef);
        context.logger.info("XO lists {count} PIF(s)", { count: items.length });
        const handle = await context.writeResource("inventory", "pifs", {
          kind: "pifs",
          count: items.length,
          items,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    listServers: {
      description:
        "List XO servers (`GET /servers`) — the XCP-NG host/pool connections XO " +
        "manages — recorded as an `inventory` snapshot (kind `servers`). Use to " +
        "find a server id or confirm a host is registered before/after addServer.",
      arguments: z.object({}),
      execute: async (
        args: { _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const res = await xoRequest(
          cfg,
          "GET",
          "servers",
          { query: [["fields", "id,label,host,username,status,poolId"]] },
          doFetch,
        );
        if (!Array.isArray(res)) {
          throw new Error(
            `XO GET servers did not return a list (got ${typeof res})`,
          );
        }
        // Map to the shared RefSchema shape (id -> uuid, label -> name_label);
        // the full server object stays in `raw` (host/status/poolId).
        const items = res.map((s) => {
          const o = (s ?? {}) as Record<string, unknown>;
          return {
            uuid: strOrNull(o.id ?? o.uuid),
            name_label: strOrNull(o.label ?? o.name_label),
            raw: o,
          };
        });
        context.logger.info("XO has {count} server(s)", {
          count: items.length,
        });
        const handle = await context.writeResource("inventory", "servers", {
          kind: "servers",
          count: items.length,
          items,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    listAuthTokens: {
      description:
        "SECURITY/IR, read-only: enumerate XO authentication tokens for the " +
        "connected (admin) user (`GET /users/me/authentication_tokens`) and " +
        "the full user list (`GET /users`), recorded as `inventory` snapshots " +
        "(kinds `authTokens`, `users`). Hunt for attacker-minted/harvested " +
        "tokens or rogue accounts (e.g. VSA-2026-062 REST token theft): any " +
        "token or user you did not create is a red flag. Never writes to XO.",
      arguments: z.object({}),
      execute: async (
        args: { _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const handles: Array<{ name: string }> = [];

        // (1) Connected user's tokens — the exact surface the VSA-2026-062
        // exploit reads. A persistent attacker-minted token shows here with
        // its created/expiration timestamps.
        const tokRes = await xoRequest(
          cfg,
          "GET",
          "users/me/authentication_tokens",
          {},
          doFetch,
        );
        const tokArr = Array.isArray(tokRes) ? tokRes : [];
        const tokens = tokArr.map((t) => {
          const o = (t ?? {}) as Record<string, unknown>;
          // The token `id` IS the bearer secret — NEVER persist it. Keep a
          // masked id plus non-secret metadata (enough to spot an anomalous /
          // unexpected token during the hunt); drop the raw object.
          const rawId = strOrNull(o.id ?? o.uuid);
          // Reveal partial ends only for long ids (real XO token ids are ~43
          // chars); fully mask anything short so the two slices can't
          // reconstruct the whole secret.
          const masked = rawId
            ? (rawId.length >= 16
              ? `${rawId.slice(0, 4)}...(${rawId.length})...${rawId.slice(-4)}`
              : `***(${rawId.length})***`)
            : null;
          const client = o.client as Record<string, unknown> | undefined;
          return {
            uuid: masked,
            name_label: strOrNull(
              o.description ?? (client ? strOrNull(client.id) : null) ??
                (o.created_at != null ? String(o.created_at) : null),
            ),
            raw: {
              created_at: o.created_at ?? o.created ?? null,
              expiration: o.expiration ?? null,
              description: o.description ?? null,
              client: client ?? null,
              user_id: o.user_id ?? null,
              last_uses: o.last_uses ?? null,
            },
          };
        });
        context.logger.info(
          "XO user 'me' has {count} authentication token(s)",
          { count: tokens.length },
        );
        handles.push(
          await context.writeResource("inventory", "authTokens", {
            kind: "authTokens",
            count: tokens.length,
            items: tokens,
            retrievedAt: new Date().toISOString(),
          }),
        );

        // (2) Full user list — a rogue/unexpected account is the other half of
        // a post-exploit footprint. Best-effort: a users 403/404 must not
        // suppress the token snapshot above.
        try {
          const usrRes = await xoRequest(cfg, "GET", "users", {
            query: [["fields", "id,email,permission,groups"]],
          }, doFetch);
          const usrArr = Array.isArray(usrRes) ? usrRes : [];
          const users = usrArr.map((u) => {
            const o = (u ?? {}) as Record<string, unknown>;
            // Persist only the fields needed to spot a rogue account; `id` is a
            // user UUID (not a secret). Avoid blanket `raw: o` over-collection.
            return {
              uuid: strOrNull(o.id ?? o.uuid),
              name_label: strOrNull(o.email ?? o.name_label),
              raw: {
                email: o.email ?? null,
                permission: o.permission ?? null,
                groups: o.groups ?? null,
              },
            };
          });
          context.logger.info("XO has {count} user account(s)", {
            count: users.length,
          });
          handles.push(
            await context.writeResource("inventory", "users", {
              kind: "users",
              count: users.length,
              items: users,
              retrievedAt: new Date().toISOString(),
            }),
          );
        } catch (e) {
          context.logger.info(
            "XO GET users failed (continuing with token snapshot): {err}",
            { err: e instanceof Error ? e.message : String(e) },
          );
        }

        return { dataHandles: handles };
      },
    },
    createAuthToken: {
      description:
        "SECURITY/IR write (dryRun-gated): mint a new XO authentication token " +
        "(`POST /users/authentication_tokens`) for the connected user — e.g. to " +
        "re-mint the swamp integration token after suspected token exposure " +
        "(VSA-2026-062) so the old token can then be revoked. dryRun (default " +
        "true) records a plan and does NOT call XO. With dryRun=false it mints " +
        "the token, logs the secret ONCE for you to store in vault " +
        "`xoa-hel/api-key`, and records only MASKED metadata to the datastore " +
        "(the raw token id is the bearer secret and is never persisted). " +
        "Revocation is out of scope — REST v0 has no token DELETE (see work " +
        "item xo-revoke-auth-token).",
      arguments: z.object({
        description: z.string().default("").describe(
          "Human label stored on the token (e.g. 'swamp'); shown in XO's token list.",
        ),
        expiresIn: z.union([z.string(), z.number()]).optional().describe(
          "Token lifetime: a duration string XO accepts (e.g. '30 days', '1 hour') or milliseconds as a number. Omit for XO's default.",
        ),
        clientId: z.string().default("").describe(
          "Optional client.id to tag the token with (XO groups tokens by client).",
        ),
        force: z.boolean().default(false).describe(
          "Mint even if a token with the same description+clientId already exists. Default false refuses to create a duplicate (XO has no REST revoke, so duplicates strand unrevocably).",
        ),
        dryRun: z.boolean().default(true).describe(
          "Default true: record the planned POST without creating anything. Set false to actually mint the token.",
        ),
      }),
      execute: async (
        args: {
          description: string;
          expiresIn?: string | number;
          clientId: string;
          force: boolean;
          dryRun: boolean;
          _fetch?: FetchLike;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const body: Record<string, unknown> = {};
        if (args.description) body.description = args.description;
        if (args.expiresIn !== undefined) body.expiresIn = args.expiresIn;
        if (args.clientId) body.client = { id: args.clientId };

        if (args.dryRun) {
          context.logger.info(
            "DRY-RUN createAuthToken: would POST /users/authentication_tokens " +
              "({desc}{exp}); no token minted. Re-run with dryRun=false to mint.",
            {
              desc: args.description
                ? `description="${args.description}"`
                : "no description",
              exp: args.expiresIn !== undefined
                ? `, expiresIn=${args.expiresIn}`
                : "",
            },
          );
          const handle = await context.writeResource(
            "inventory",
            "authTokenPlan",
            {
              kind: "authTokenPlan",
              count: 1,
              items: [{
                uuid: null,
                name_label: "planned POST /users/authentication_tokens",
                raw: body,
              }],
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        }

        // Idempotency: a bare POST mints a NEW token every call, and XO has no
        // REST DELETE -- a retry (incl. swamp's own method retries) would
        // strand an unrevocable duplicate. Refuse if a token with the same
        // description+clientId already exists, unless force.
        if (!args.force) {
          const existing = await xoRequest(
            cfg,
            "GET",
            "users/me/authentication_tokens",
            {},
            doFetch,
          );
          // Fail CLOSED: unwrap a possible envelope, and if we still can't read
          // a list, refuse to mint rather than silently proceeding.
          const list = Array.isArray(existing) ? existing : (
            (existing as Record<string, unknown> | null)?.data ??
              (existing as Record<string, unknown> | null)?.items
          );
          if (!Array.isArray(list)) {
            throw new Error(
              "createAuthToken: could not read the existing-token list to " +
                "check for duplicates (unexpected XO response shape). Refusing " +
                "to mint (fail-closed); pass force=true to override.",
            );
          }
          const dupe = list.some((e) => {
            const o = (e ?? {}) as Record<string, unknown>;
            const ec = o.client as Record<string, unknown> | undefined;
            return (strOrNull(o.description) ?? "") === args.description &&
              (strOrNull(ec?.id) ?? "") === args.clientId;
          });
          if (dupe) {
            throw new Error(
              `createAuthToken: a token with description="${args.description}" ` +
                `and clientId="${args.clientId}" already exists. Refusing to ` +
                `mint a duplicate (XO has no REST revoke, so it would strand ` +
                `unrevocably). Revoke the existing token first, or pass ` +
                `force=true to mint anyway.`,
            );
          }
        }

        const res = await xoRequest(
          cfg,
          "POST",
          "users/authentication_tokens",
          { body },
          doFetch,
        );
        // XO returns the new token NESTED as {token:{id,created_at,...}} on this
        // XOA (verified against the live swagger); tolerate a flat object or a
        // bare string too.
        const asObj = (res ?? {}) as Record<string, unknown>;
        const unwrapped = (res && typeof res === "object" && "token" in asObj)
          ? asObj.token
          : (typeof res === "string" ? { id: res } : res);
        // Null/non-object guard: {token:null}, null, or a scalar response must
        // fall through to the graceful error below, not throw a raw TypeError
        // on `.id` after the token has already been minted.
        const created = (unwrapped && typeof unwrapped === "object")
          ? (unwrapped as Record<string, unknown>)
          : {};
        const secret = strOrNull(created.id ?? created.token);
        if (!secret) {
          throw new Error(
            "createAuthToken: XO returned no token id (the mint may have " +
              "succeeded) -- inspect XO's token list manually before retrying.",
          );
        }
        const label = (args.description || args.clientId || "default")
          .replace(/[^A-Za-z0-9._-]+/g, "-").slice(0, 60);
        // Unique per mint so a deliberate force=true re-mint with the same
        // label never clobbers the prior (still-live, unrevocable) token's
        // vault reference.
        const mintedAt = new Date().toISOString();
        const resourceName = `mintedToken-${label}-${Date.now()}`;
        const client = created.client as Record<string, unknown> | undefined;
        // The token id is the bearer secret -> write it into the `mintedToken`
        // resource's `sensitive` field. swamp VAULTS it and persists only a
        // reference; it is never logged or stored plaintext. Read it back via
        // data.latest("<instance>","<resourceName>").attributes.tokenId.
        const handle = await context.writeResource(
          "mintedToken",
          resourceName,
          {
            tokenId: secret,
            description: strOrNull(created.description ?? args.description),
            clientId: strOrNull(client?.id ?? (args.clientId || null)),
            userId: strOrNull(created.user_id),
            created: (created.created_at ?? created.created ?? null) as
              | number
              | string
              | null,
            expiration: (created.expiration ?? null) as number | string | null,
            mintedAt,
          },
        );
        context.logger.info(
          "createAuthToken MINTED + VAULTED a token. The secret is vaulted, " +
            "not logged. Read it via CEL: " +
            'data.latest("<instance>","{name}").attributes.tokenId ' +
            "(e.g. repoint vault xoa-hel/api-key).",
          { name: resourceName },
        );
        return { dataHandles: [handle] };
      },
    },
    addServer: {
      description:
        "Register an XCP-NG host with XO (`POST /servers`) and connect it " +
        "(`POST /servers/{id}/actions/connect`), then snapshot the server. " +
        "Idempotent: if a server for the same `host` is already registered, " +
        "reuses it instead of adding a duplicate. After this, the host's pool " +
        "appears in listPools and is a valid `migrate` target.",
      arguments: z.object({
        host: z.string().describe(
          "XCP-NG host address XO connects to (IP or FQDN, no scheme)",
        ),
        label: z.string().describe("Human label for the server in XO"),
        username: z.string().default("root").describe(
          "XCP-NG account (usually root)",
        ),
        password: z
          .string()
          .meta({ sensitive: true })
          .describe(
            "XCP-NG account password — resolve from a vault via CEL. Never " +
              "persisted to the data store.",
          ),
        allowUnauthorized: z.boolean().default(false).describe(
          "Accept a self-signed/pinned host cert (XCP-NG installs a " +
            "self-signed cert by default — set true unless the host has a " +
            "publicly-trusted cert)",
        ),
        connect: z.boolean().default(true).describe(
          "Connect the server after registering",
        ),
        sync: z.boolean().default(true).describe(
          "Wait inline on the connect action (?sync=true)",
        ),
      }),
      execute: async (
        args: {
          host: string;
          label: string;
          username: string;
          password: string;
          allowUnauthorized: boolean;
          connect: boolean;
          sync: boolean;
          _fetch?: FetchLike;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Idempotency (Rule 5-adjacent): reuse an existing registration for
        // this host rather than creating a duplicate connection.
        const list = await xoRequest(
          cfg,
          "GET",
          "servers",
          { query: [["fields", "id,host,label,username,status,poolId"]] },
          doFetch,
        );
        const found = Array.isArray(list)
          ? list.map((s) => normalizeServer(s as Record<string, unknown>))
            .find((s) => s.host === args.host)
          : undefined;
        let id = found?.id ?? "";
        if (id) {
          context.logger.info(
            "Host {host} already registered as server {id}; reusing",
            { host: args.host, id },
          );
        } else {
          context.logger.info("Registering XCP-NG host {host} with XO", {
            host: args.host,
          });
          const res = await xoRequest(
            cfg,
            "POST",
            "servers",
            {
              body: {
                host: args.host,
                label: args.label,
                username: args.username,
                password: args.password,
                allowUnauthorized: args.allowUnauthorized,
              },
            },
            doFetch,
          );
          id = extractUuid(res);
          if (!id) {
            throw new Error(
              `addServer returned no server id: ${JSON.stringify(res)}`,
            );
          }
        }
        if (args.connect) {
          context.logger.info("Connecting server {id}", { id });
          await xoRequest(
            cfg,
            "POST",
            `servers/${enc(id)}/actions/connect`,
            { query: args.sync ? [["sync", "true"]] : [] },
            doFetch,
          );
        }
        return await snapshotServer(cfg, id, doFetch, context);
      },
    },
    listVifs: {
      description:
        "List a VM's virtual NICs (`GET /vms/{id}` then `GET /vifs/{uuid}` per " +
        "VIF), recorded as an `inventory` snapshot (kind `vifs`). `name_label` " +
        "is the MAC; `raw.$network` is the network UUID — use to resolve which " +
        "VIF to keep/prune.",
      arguments: z.object({ id: z.string().describe("VM UUID") }),
      execute: async (
        args: { id: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const items = await scanVifs(cfg, args.id, doFetch);
        context.logger.info("VM {id} has {count} VIF(s)", {
          id: args.id,
          count: items.length,
        });
        const handle = await context.writeResource("inventory", "vifs", {
          kind: "vifs",
          count: items.length,
          items,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    listVbds: {
      description:
        "List a VM's virtual block devices (`GET /vms/{id}` then `GET " +
        "/vbds/{uuid}` per VBD), recorded as an `inventory` snapshot (kind " +
        "`vbds`). `name_label` is the device position; `raw.bootable`, " +
        "`raw.VDI`, and `raw.is_cd_drive`/`raw.type` distinguish a boot disk " +
        "from a cloud-init config drive — use to pick which VBD to detachVdi " +
        "(e.g. to swap a scratch disk off device 0 for an imported image).",
      arguments: z.object({ id: z.string().describe("VM UUID") }),
      execute: async (
        args: { id: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const items = await scanVbds(cfg, args.id, doFetch);
        context.logger.info("VM {id} has {count} VBD(s)", {
          id: args.id,
          count: items.length,
        });
        const handle = await context.writeResource("inventory", "vbds", {
          kind: "vbds",
          count: items.length,
          items,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    deleteVif: {
      description:
        "Delete a virtual NIC by VIF UUID (`DELETE /vifs/{uuid}`). Verifies the " +
        "VIF exists first (Rule 5). Resolve the UUID via listVifs.",
      arguments: z.object({ vif: z.string().describe("VIF UUID") }),
      execute: async (
        args: { vif: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Verify before delete (throws HTTP 404 if it does not exist).
        await xoRequest(cfg, "GET", `vifs/${enc(args.vif)}`, {}, doFetch);
        context.logger.warning("Deleting VIF {vif}", { vif: args.vif });
        await xoRequest(cfg, "DELETE", `vifs/${enc(args.vif)}`, {}, doFetch);
        return { dataHandles: [] };
      },
    },
    attachVif: {
      description:
        "Attach a new virtual NIC to a VM on a named network, optionally with " +
        "an explicit MAC (`POST /vifs` with {vmId, networkId, MAC?}). Verifies " +
        "the VM exists first (Rule 5). Idempotent by MAC: if a VIF already " +
        "carries the requested MAC, no-op and return it (re-running the " +
        "jump-host edge must not stack NICs). Records a `vif` resource " +
        "{uuid,mac,network,attached}. Endpoint/body confirmed live against XO " +
        "(the older `POST /vms/{id}/vifs` route does not exist).",
      arguments: z.object({
        id: z.string().describe("VM UUID"),
        network: z.string().describe(
          "Network UUID to attach to (resolve via listNetworks)",
        ),
        mac: z
          .string()
          .optional()
          .describe(
            "Explicit MAC (aa:bb:cc:dd:ee:ff); omit to let XO auto-assign",
          ),
        allowedIpv4: z
          .array(z.string())
          .optional()
          .describe("Antispoof: permitted source IPv4 addresses"),
        allowedIpv6: z
          .array(z.string())
          .optional()
          .describe("Antispoof: permitted source IPv6 addresses"),
        attached: z
          .boolean()
          .default(true)
          .describe("Plug the VIF immediately"),
      }),
      execute: async (
        args: {
          id: string;
          network: string;
          mac?: string;
          allowedIpv4?: string[];
          allowedIpv6?: string[];
          attached?: boolean;
          _fetch?: FetchLike;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        // Validate the MAC BEFORE any network call so a malformed value can
        // never reach XO or trigger a fetch.
        if (
          args.mac !== undefined &&
          !/^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(args.mac)
        ) {
          throw new Error(
            `attachVif: invalid MAC "${args.mac}" (expected aa:bb:cc:dd:ee:ff)`,
          );
        }
        const doFetch = args._fetch ?? makeFetch(cfg);
        const attached = args.attached ?? true;

        // Rule 5 verify-before + idempotency scan in one pass (GET vms/{id}
        // 404s if the VM is absent, then GET vifs/{uuid} per existing VIF).
        const existing = await scanVifs(cfg, args.id, doFetch);
        if (args.mac) {
          const want = args.mac.toLowerCase();
          const hit = existing.find((v) =>
            (v.name_label ?? "").toLowerCase() === want
          );
          if (hit) {
            // Resolve the existing VIF's network the same way the resource
            // does, so idempotency is judged against the real binding.
            const hitNetwork = strOrNull(
              hit.raw["$network"] ?? hit.raw.network,
            );
            // Only a MATCHING network is a safe no-op. A VIF that already
            // carries the requested MAC but lives on a DIFFERENT network is a
            // conflict — fail loud instead of silently returning the stale
            // binding. (A null/unknown network can't prove a conflict, so it
            // still no-ops.)
            if (hitNetwork !== null && hitNetwork !== args.network) {
              throw new Error(
                `attachVif: a VIF with MAC ${args.mac} already exists on ` +
                  `network ${hitNetwork}, but attach was requested on network ` +
                  `${args.network}; refusing to return the stale binding`,
              );
            }
            context.logger.info(
              "VM {id} already has a VIF with MAC {mac}; no-op",
              { id: args.id, mac: args.mac },
            );
            const data: Vif = {
              uuid: hit.uuid,
              mac: hit.name_label,
              network: hitNetwork ?? args.network,
              attached: typeof hit.raw.attached === "boolean"
                ? hit.raw.attached
                : attached,
            };
            const handle = await context.writeResource(
              "vif",
              `vif:${hit.uuid}`,
              data,
            );
            return { dataHandles: [handle] };
          }
        }

        // Confirmed XO REST create shape (POST /rest/v0/vifs): the VM and
        // network are body keys `vmId`/`networkId` (NOT a path segment), the
        // MAC key is `MAC`, and antispoof lists are `ipv4_allowed`/
        // `ipv6_allowed` (the XAPI VIF_create field names). See vif.controller
        // createVif in @xen-orchestra/rest-api.
        const body: Record<string, unknown> = {
          vmId: args.id,
          networkId: args.network,
        };
        if (args.mac) body.MAC = args.mac;
        if (args.allowedIpv4) body.ipv4_allowed = args.allowedIpv4;
        if (args.allowedIpv6) body.ipv6_allowed = args.allowedIpv6;
        // The "plug immediately" flag is `currently_attached` — the XAPI
        // VIF_create field. When true against a running VM, XO also calls
        // VIF.plug; a halted VM plugs it on next boot.
        body.currently_attached = attached;
        context.logger.info("Attaching VIF to VM {id} on network {network}", {
          id: args.id,
          network: args.network,
        });
        const created = await xoRequest(
          cfg,
          "POST",
          `vifs`,
          { body },
          doFetch,
        );
        const vifId = extractUuid(created);
        if (!vifId) {
          throw new Error(
            "attachVif: create returned no VIF UUID to re-read",
          );
        }
        // Re-read the created VIF for its authoritative MAC/network/attached.
        const raw = (await xoRequest(
          cfg,
          "GET",
          `vifs/${enc(vifId)}`,
          {},
          doFetch,
        )) as Record<string, unknown> | null ?? { uuid: vifId };
        const data: Vif = {
          uuid: strOrNull(raw.uuid) ?? vifId,
          mac: strOrNull(raw.MAC ?? raw.mac) ?? args.mac ?? null,
          network: strOrNull(raw["$network"] ?? raw.network) ?? args.network,
          attached: typeof raw.attached === "boolean" ? raw.attached : attached,
        };
        const handle = await context.writeResource(
          "vif",
          `vif:${data.uuid}`,
          data,
        );
        return { dataHandles: [handle] };
      },
    },
    setVm: {
      description:
        "Edit a HALTED VM's CPU count and/or memory (`PATCH /vms/{id}` with " +
        "{CPUs?, memory?}). At least one of cpus/memory is required. Verifies " +
        "the VM exists and is `halted` first (Rule 5) — fails closed with zero " +
        "mutation otherwise, since XO rejects live CPU/mem edits. Re-snapshots " +
        "the VM on success.",
      arguments: z.object({
        id: z.string().describe("VM UUID"),
        cpus: z.number().int().optional().describe("New vCPU count"),
        memory: z.number().optional().describe("New RAM in bytes"),
      }),
      execute: async (
        args: {
          id: string;
          cpus?: number;
          memory?: number;
          _fetch?: FetchLike;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        // Fail closed if neither field is set (nothing to change).
        if (args.cpus === undefined && args.memory === undefined) {
          throw new Error(
            "setVm: at least one of cpus/memory must be provided",
          );
        }
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Rule 5 verify-before: existence + power-state gate (404s if absent).
        const raw = (await xoRequest(
          cfg,
          "GET",
          `vms/${enc(args.id)}`,
          {},
          doFetch,
        )) as Record<string, unknown> | null;
        const power = strOrNull(raw?.power_state);
        // XO refuses CPU/mem edits on a running VM; guard case-insensitively
        // (live XO reports "Halted", the spec writes it "halted").
        if ((power ?? "").toLowerCase() !== "halted") {
          throw new Error(
            `setVm: VM ${args.id} is ${power ?? "unknown"} (not halted); ` +
              "refusing CPU/memory edit — halt the VM first",
          );
        }
        const body: Record<string, unknown> = {};
        if (args.cpus !== undefined) body.CPUs = args.cpus;
        if (args.memory !== undefined) body.memory = args.memory;
        context.logger.info("Editing VM {id} ({fields})", {
          id: args.id,
          fields: Object.keys(body).join(","),
        });
        await xoRequest(cfg, "PATCH", `vms/${enc(args.id)}`, { body }, doFetch);
        return await snapshotVm(cfg, args.id, doFetch, context);
      },
    },
    getServerVersion: {
      description:
        "Read the XO server version over the WebSocket JSON-RPC transport " +
        "(`system.getServerVersion`) and record a `serverVersion` resource. A " +
        "read-only proof that the control-plane seam reaches a live xo-server; " +
        "writes nothing to XO.",
      arguments: z.object({}),
      execute: async (
        args: { _connect?: RpcConnect },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const connect = args._connect ?? makeRpcConnect;
        context.logger.info("Reading XO server version over JSON-RPC");
        const result = await xoJsonRpc(
          cfg,
          "system.getServerVersion",
          {},
          {},
          connect,
        );
        // xo-server returns a version string or a { version } object; tolerate
        // both and fall back to a stringified payload for an unexpected shape.
        const version = typeof result === "string"
          ? result
          : (typeof result === "object" && result !== null &&
              typeof (result as { version?: unknown }).version === "string")
          ? (result as { version: string }).version
          : JSON.stringify(result);
        const payload = ServerVersionSchema.parse({
          version,
          retrievedAt: new Date().toISOString(),
        });
        context.logger.info("XO server version {version}", {
          version: payload.version,
        });
        const handle = await context.writeResource(
          "serverVersion",
          "serverVersion",
          payload,
        );
        return { dataHandles: [handle] };
      },
    },
    listBackupRepositories: {
      description:
        "List XO backup repositories (remotes) (`GET /backup-repositories`) " +
        "and record them as a `backupRepositoryList` snapshot. Read-only; each " +
        "item's url is redacted (userinfo + query stripped). Use to resolve a " +
        "repository id before get/update/forget/reclaim/benchmark/health.",
      arguments: z.object({}),
      execute: async (
        args: { _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const res = await xoRequest(
          cfg,
          "GET",
          "backup-repositories",
          { query: [["fields", "id,name,type,url,enabled"]] },
          doFetch,
        );
        // Tolerate a bare array OR an envelope ({data}/{items}); on any other
        // shape record an empty list rather than throwing (the .map guard).
        const env = (res ?? null) as
          | { data?: unknown; items?: unknown }
          | null;
        const unwrapped = Array.isArray(res) ? res : (env?.data ?? env?.items);
        const items = Array.isArray(unwrapped)
          ? unwrapped.map((r) =>
            normalizeBackupRepository(r as Record<string, unknown>)
          )
          : [];
        context.logger.info("XO has {count} backup repository(ies)", {
          count: items.length,
        });
        const handle = await context.writeResource(
          "backupRepositoryList",
          "backupRepositories",
          {
            count: items.length,
            items,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    getBackupRepository: {
      description: "Fetch one backup repository (remote) by id " +
        "(`GET /backup-repositories/{id}`) and record a `backupRepository` " +
        "snapshot. Read-only; the url is redacted before persist.",
      arguments: z.object({
        id: z.string().describe(
          "Backup-repository id (resolve via listBackupRepositories).",
        ),
      }),
      execute: async (
        args: { id: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const res = await xoRequest(
          cfg,
          "GET",
          `backup-repositories/${enc(args.id)}`,
          {},
          doFetch,
        );
        if (!res || typeof res !== "object" || Array.isArray(res)) {
          throw new Error(
            `backup repository ${args.id} not found or empty response`,
          );
        }
        const repo = normalizeBackupRepository(res as Record<string, unknown>);
        context.logger.info("Fetched backup repository {id}", { id: args.id });
        const handle = await context.writeResource(
          "backupRepository",
          `backupRepository:${repo.id || args.id}`,
          repo,
        );
        return { dataHandles: [handle] };
      },
    },
    createBackupRepository: {
      description: "Register a backup repository (remote) with XO " +
        "(`POST /backup-repositories`) and record its snapshot. The `url` " +
        "embeds the credential (e.g. smb://user:<pass>@host/share) and is the " +
        "ONLY place the secret leaves the vault — it is never logged or " +
        "persisted (only a redacted form is). Idempotent on `name`: if a " +
        "remote with the same name exists and `force` is false it is reused " +
        "(no POST); set force=true to create anyway.",
      arguments: z.object({
        name: z.string().min(1),
        type: z.string().optional().describe(
          "smb|nfs|s3|local|file; omit to let the url scheme decide.",
        ),
        url: z.string().min(1).meta({ sensitive: true }).describe(
          "Remote URL embedding credentials, e.g. " +
            "smb://DOMAIN\\\\user:<pass>@host/share. Resolve from a vault via " +
            "CEL; never logged or persisted (only a redacted form is).",
        ),
        options: z.string().optional().describe(
          "Extra mount options (non-secret).",
        ),
        enabled: z.boolean().default(true),
        force: z.boolean().default(false).describe(
          "Create even if a remote with the same name already exists.",
        ),
      }),
      execute: async (
        args: {
          name: string;
          type?: string;
          url: string;
          options?: string;
          enabled: boolean;
          force: boolean;
          _fetch?: FetchLike;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Idempotency: reuse an existing same-name remote unless force.
        if (!args.force) {
          const list = await xoRequest(
            cfg,
            "GET",
            "backup-repositories",
            { query: [["fields", "id,name"]] },
            doFetch,
          );
          const env = (list ?? null) as
            | { data?: unknown; items?: unknown }
            | null;
          const unwrapped = Array.isArray(list)
            ? list
            : (env?.data ?? env?.items);
          const found = Array.isArray(unwrapped)
            ? unwrapped
              .map((r) => (r ?? {}) as Record<string, unknown>)
              .find((r) => strOrNull(r.name) === args.name)
            : undefined;
          if (found) {
            const existingId = strOrNull(found.id ?? found.uuid) ?? "";
            context.logger.info(
              "Backup repository {name} already exists as {id}; reusing",
              { name: args.name, id: existingId },
            );
            const cur = await xoRequest(
              cfg,
              "GET",
              `backup-repositories/${enc(existingId)}`,
              {},
              doFetch,
            );
            const repo = normalizeBackupRepository(
              (cur ?? found) as Record<string, unknown>,
            );
            const handle = await context.writeResource(
              "backupRepository",
              `backupRepository:${repo.id || existingId}`,
              repo,
            );
            return { dataHandles: [handle] };
          }
        }
        const body: Record<string, unknown> = {
          name: args.name,
          url: args.url,
          enabled: args.enabled,
        };
        if (args.type !== undefined) body.type = args.type;
        if (args.options !== undefined) body.options = args.options;
        // Log only a redacted view — NEVER args.url.
        context.logger.info(
          "Creating backup repository {name} ({url})",
          { name: args.name, url: redactRepoUrl(args.url) },
        );
        const res = await xoRequest(
          cfg,
          "POST",
          "backup-repositories",
          { body },
          doFetch,
        );
        const id = await resolveActionId(cfg, res, doFetch);
        if (!id) {
          // Do NOT stringify args.url into the error — it carries the secret.
          throw new Error(
            `createBackupRepository returned no id; a remote named ` +
              `'${args.name}' may have been created and orphaned`,
          );
        }
        const cur = await xoRequest(
          cfg,
          "GET",
          `backup-repositories/${enc(id)}`,
          {},
          doFetch,
        );
        const repo = normalizeBackupRepository(
          (cur ?? { id }) as Record<string, unknown>,
        );
        context.logger.info("Created backup repository {id}", { id });
        const handle = await context.writeResource(
          "backupRepository",
          `backupRepository:${id}`,
          repo,
        );
        return { dataHandles: [handle] };
      },
    },
    updateBackupRepository: {
      description: "Update a backup repository (remote) in place " +
        "(`PATCH /backup-repositories/{id}`) to a target state and record the " +
        "refreshed snapshot. Pre-verifies the repo exists (Rule 5). Only the " +
        "fields you pass change; a new `url` embeds the credential and is never " +
        "logged or persisted (only a redacted form is). Idempotent.",
      arguments: z.object({
        id: z.string(),
        name: z.string().optional(),
        url: z.string().optional().meta({ sensitive: true }).describe(
          "New remote URL embedding credentials; omit to leave unchanged.",
        ),
        options: z.string().optional(),
        enabled: z.boolean().optional(),
      }),
      execute: async (
        args: {
          id: string;
          name?: string;
          url?: string;
          options?: string;
          enabled?: boolean;
          _fetch?: FetchLike;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Rule-5 pre-verify: a clean 404 before any PATCH.
        const cur = await xoRequest(
          cfg,
          "GET",
          `backup-repositories/${enc(args.id)}`,
          {},
          doFetch,
        );
        if (!cur || typeof cur !== "object" || Array.isArray(cur)) {
          throw new Error(
            `backup repository ${args.id} not found; refusing to PATCH`,
          );
        }
        const body: Record<string, unknown> = {};
        if (args.name !== undefined) body.name = args.name;
        if (args.url !== undefined) body.url = args.url;
        if (args.options !== undefined) body.options = args.options;
        if (args.enabled !== undefined) body.enabled = args.enabled;
        if (Object.keys(body).length === 0) {
          throw new Error("updateBackupRepository: no fields to update");
        }
        context.logger.info("Updating backup repository {id}{url}", {
          id: args.id,
          url: args.url !== undefined ? ` (${redactRepoUrl(args.url)})` : "",
        });
        await xoRequest(
          cfg,
          "PATCH",
          `backup-repositories/${enc(args.id)}`,
          { body },
          doFetch,
        );
        const after = await xoRequest(
          cfg,
          "GET",
          `backup-repositories/${enc(args.id)}`,
          {},
          doFetch,
        );
        const repo = normalizeBackupRepository(
          (after ?? cur) as Record<string, unknown>,
        );
        const handle = await context.writeResource(
          "backupRepository",
          `backupRepository:${repo.id || args.id}`,
          repo,
        );
        return { dataHandles: [handle] };
      },
    },
    forgetBackupRepository: {
      description:
        "DESTRUCTIVE: removes the backup repository from XO (forget); backup " +
        "chains stored on the remote become unreferenced. XO has no DELETE " +
        "verb for a remote — this POSTs `.../actions/forget`. dryRun-gated " +
        "(default true): a dry run pre-verifies and records a plan WITHOUT " +
        "forgetting; set dryRun=false to actually forget. Always GETs the repo " +
        "first for a clean 404 (Rule 5).",
      arguments: z.object({
        id: z.string().describe(
          "Backup-repository id to forget. VERIFY this id with " +
            "getBackupRepository first.",
        ),
        dryRun: z.boolean().default(true).describe(
          "Default true: pre-verify and record the plan WITHOUT forgetting. " +
            "Set false to actually forget the remote.",
        ),
      }),
      execute: async (
        args: { id: string; dryRun: boolean; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const cur = await xoRequest(
          cfg,
          "GET",
          `backup-repositories/${enc(args.id)}`,
          {},
          doFetch,
        );
        if (!cur || typeof cur !== "object" || Array.isArray(cur)) {
          throw new Error(
            `backup repository ${args.id} not found; refusing to forget`,
          );
        }
        const name = strOrNull((cur as Record<string, unknown>).name);
        // Defense-in-depth: only an EXPLICIT dryRun=false forgets. An unset
        // dryRun stays in the safe plan-only path (matches the schema default).
        const dryRun = args.dryRun !== false;
        if (dryRun) {
          context.logger.info(
            "[dryRun] would forget backup repository {id} ({name})",
            { id: args.id, name },
          );
          const handle = await context.writeResource(
            "backupRepositoryAction",
            `forget:${args.id}`,
            {
              id: args.id,
              action: "forget-plan",
              status: "planned",
              taskRef: null,
              raw: {
                plannedPath: `backup-repositories/${args.id}/actions/forget`,
              },
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        }
        context.logger.warning("Forgetting backup repository {id} ({name})", {
          id: args.id,
          name,
        });
        const res = await xoRequest(
          cfg,
          "POST",
          `backup-repositories/${enc(args.id)}/actions/forget`,
          { body: {} },
          doFetch,
        );
        const handle = await context.writeResource(
          "backupRepositoryAction",
          `forget:${args.id}`,
          {
            id: args.id,
            action: "forget",
            status: "done",
            taskRef: extractTaskRef(res),
            raw: rawObject(res),
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    reclaimBackupRepositorySpace: {
      description:
        "DESTRUCTIVE: reclaims space by deleting unreferenced data on the " +
        "remote (GC/merge). dryRun-gated (default true). XO may run this " +
        "SYNCHRONOUSLY — the request is bounded by the model's requestTimeoutMs " +
        "(xoRequest applies AbortSignal.timeout) so a low timeout ABORTS a long " +
        "run; raise requestTimeoutMs for large remotes — or XO may return an " +
        "async task reference, which is recorded (taskRef) without blocking. " +
        "Pre-verifies the repo (Rule 5); does not poll the task.",
      arguments: z.object({
        id: z.string().describe(
          "Backup-repository id. VERIFY with getBackupRepository first.",
        ),
        dryRun: z.boolean().default(true),
      }),
      execute: async (
        args: { id: string; dryRun: boolean; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const cur = await xoRequest(
          cfg,
          "GET",
          `backup-repositories/${enc(args.id)}`,
          {},
          doFetch,
        );
        if (!cur || typeof cur !== "object" || Array.isArray(cur)) {
          throw new Error(
            `backup repository ${args.id} not found; refusing to reclaim space`,
          );
        }
        // Defense-in-depth: only an EXPLICIT dryRun=false reclaims (matches the
        // schema default); an unset dryRun stays plan-only.
        const dryRun = args.dryRun !== false;
        if (dryRun) {
          context.logger.info(
            "[dryRun] would reclaim space on backup repository {id}",
            { id: args.id },
          );
          const handle = await context.writeResource(
            "backupRepositoryAction",
            `reclaim:${args.id}`,
            {
              id: args.id,
              action: "reclaim-space-plan",
              status: "planned",
              taskRef: null,
              raw: {
                plannedPath:
                  `backup-repositories/${args.id}/actions/reclaim-space`,
              },
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        }
        context.logger.warning("Reclaiming space on backup repository {id}", {
          id: args.id,
        });
        const res = await xoRequest(
          cfg,
          "POST",
          `backup-repositories/${enc(args.id)}/actions/reclaim-space`,
          { body: {} },
          doFetch,
        );
        const taskRef = extractTaskRef(res);
        const handle = await context.writeResource(
          "backupRepositoryAction",
          `reclaim:${args.id}`,
          {
            id: args.id,
            action: "reclaim-space",
            status: taskRef ? "submitted" : "done",
            taskRef,
            raw: rawObject(res),
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    benchmarkBackupRepository: {
      description:
        "Writes temporary benchmark data to the remote to measure read/write " +
        "throughput (`POST .../actions/benchmark`). Not dryRun-gated " +
        "(reversible) but pre-verified (Rule 5). XO may run SYNCHRONOUSLY " +
        "(bounded by requestTimeoutMs via xoRequest AbortSignal.timeout — raise " +
        "it for a slow remote so a long run is not aborted) or return an async " +
        "task reference, which is recorded (taskRef) without blocking. Not " +
        "idempotent (each run writes fresh test data); does not poll.",
      arguments: z.object({
        id: z.string().describe(
          "Backup-repository id. VERIFY with getBackupRepository first.",
        ),
      }),
      execute: async (
        args: { id: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const cur = await xoRequest(
          cfg,
          "GET",
          `backup-repositories/${enc(args.id)}`,
          {},
          doFetch,
        );
        if (!cur || typeof cur !== "object" || Array.isArray(cur)) {
          throw new Error(
            `backup repository ${args.id} not found; refusing to benchmark`,
          );
        }
        context.logger.info("Benchmarking backup repository {id}", {
          id: args.id,
        });
        const res = await xoRequest(
          cfg,
          "POST",
          `backup-repositories/${enc(args.id)}/actions/benchmark`,
          { body: {} },
          doFetch,
        );
        const taskRef = extractTaskRef(res);
        const handle = await context.writeResource(
          "backupRepositoryAction",
          `benchmark:${args.id}`,
          {
            id: args.id,
            action: "benchmark",
            status: taskRef ? "submitted" : "done",
            taskRef,
            raw: rawObject(res),
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    getBackupRepositoryHealth: {
      description: "Read a backup repository's health " +
        "(`GET /backup-repositories/{id}/health`) and record a " +
        "`backupRepositoryHealth` snapshot (raw payload). Read-only.",
      arguments: z.object({
        id: z.string(),
      }),
      execute: async (
        args: { id: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const res = await xoRequest(
          cfg,
          "GET",
          `backup-repositories/${enc(args.id)}/health`,
          {},
          doFetch,
        );
        context.logger.info("Fetched health for backup repository {id}", {
          id: args.id,
        });
        const handle = await context.writeResource(
          "backupRepositoryHealth",
          `health:${args.id}`,
          {
            id: args.id,
            raw: rawObject(res),
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    listTasks: {
      description:
        "List XO async tasks (`GET /tasks`), recorded as an `inventory` " +
        "snapshot (kind `tasks`). Use to resolve task ids for " +
        "getTask/abortTask/deleteTask(s). Pass `filter` for a raw XO " +
        "complex-matcher string (e.g. `status:pending`).",
      arguments: z.object({
        filter: z.string().optional().describe(
          "Raw XO complex-matcher filter (e.g. `status:pending`).",
        ),
      }),
      execute: async (
        args: Record<string, unknown> & { _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const query: Array<[string, string]> = [];
        if (args.filter) query.push(["filter", String(args.filter)]);
        const res = await xoRequest(cfg, "GET", "tasks", { query }, doFetch);
        if (!Array.isArray(res)) {
          throw new Error(
            `XO GET tasks did not return a list (got ${typeof res})`,
          );
        }
        const items = res.map(normalizeRef);
        context.logger.info("XO lists {count} task(s)", {
          count: items.length,
        });
        const handle = await context.writeResource("inventory", "tasks", {
          kind: "tasks",
          count: items.length,
          items,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    deleteTask: {
      description:
        "Delete an XO async task by id (`DELETE /tasks/{id}`). Verifies the " +
        "task exists first (Rule 5) and records nothing. Resolve the id via " +
        "listTasks. For bulk cleanup use deleteTasks.",
      arguments: z.object({
        id: z.string().describe("Task id to delete (resolve via listTasks)."),
      }),
      execute: async (
        args: { id: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Verify before destroy (throws HTTP 404 if it does not exist).
        await xoRequest(cfg, "GET", `tasks/${enc(args.id)}`, {}, doFetch);
        context.logger.warning("Deleting XO task {id}", { id: args.id });
        await xoRequest(cfg, "DELETE", `tasks/${enc(args.id)}`, {}, doFetch);
        return { dataHandles: [] };
      },
    },
    deleteTasks: {
      description:
        "Delete MANY XO tasks in ONE fan-out (Rule 6: one lock acquisition). " +
        "Provide EXACTLY ONE of: a non-empty `ids[]` (delete those tasks) OR " +
        "`all=true` (delete every task). A bare run with neither (or both) is " +
        "rejected, so delete-all is opt-in only. In ids-mode each id is " +
        "deleted independently; a 404 is tolerated as already-gone, any other " +
        "error stops the batch and rethrows AFTER recording the partial " +
        "summary (fail-loud, never a silent partial wipe). Records a " +
        "`taskDeletions` audit (deleted/alreadyGone/failed + count).",
      arguments: z.object({
        ids: z.array(z.string()).optional().describe(
          "Task ids to delete (resolve via listTasks). Mutually exclusive " +
            "with all=true.",
        ),
        all: z.boolean().default(false).describe(
          "Delete EVERY task (bulk `DELETE /tasks`). Mutually exclusive with " +
            "a non-empty ids[].",
        ),
      }).superRefine((v, ctx) => {
        const hasIds = (v.ids?.length ?? 0) > 0;
        if (hasIds === v.all) {
          ctx.addIssue({
            code: "custom",
            message: "Provide exactly one of: a non-empty ids[] OR all=true",
          });
        }
      }),
      execute: async (
        args: { ids?: string[]; all: boolean; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const retrievedAt = new Date().toISOString();
        const deleted: string[] = [];
        const alreadyGone: string[] = [];
        const failed: Array<{ id: string; error: string }> = [];
        let mode: "ids" | "all";
        let count: number | null;
        let rethrow: unknown = undefined;

        if (args.all) {
          mode = "all";
          context.logger.warning("Deleting ALL XO tasks");
          const res = await xoRequest(cfg, "DELETE", "tasks", {}, doFetch);
          count = numOrNull((res as { count?: unknown } | null)?.count);
        } else {
          mode = "ids";
          const ids = args.ids ?? [];
          context.logger.warning("Deleting {count} XO task(s)", {
            count: ids.length,
          });
          for (const id of ids) {
            try {
              await xoRequest(cfg, "DELETE", `tasks/${enc(id)}`, {}, doFetch);
              deleted.push(id);
            } catch (e) {
              // Typed status branch: tolerate a raced 404 as already-gone;
              // any other error stops the batch and is rethrown below.
              if (e instanceof XoHttpError && e.status === 404) {
                alreadyGone.push(id);
              } else {
                failed.push({ id, error: String(e) });
                rethrow = e;
                break;
              }
            }
          }
          count = deleted.length;
        }

        const handle = await context.writeResource(
          "taskDeletions",
          `task-deletions:${retrievedAt}`,
          {
            kind: "task-deletions",
            mode,
            requested: args.ids ?? [],
            deleted,
            alreadyGone,
            failed,
            count,
            retrievedAt,
          },
        );
        // Summary is persisted before surfacing the failure to the caller.
        if (rethrow !== undefined) throw rethrow;
        return { dataHandles: [handle] };
      },
    },
    abortTask: {
      description:
        "Abort a RUNNING XO task (`POST /tasks/{id}/actions/abort`); stops it " +
        "but does NOT delete it (use deleteTask for that). Verifies the task " +
        "exists first, then short-circuits to a logged no-op if it is already " +
        "settled (any status other than `pending`), so re-aborting is safe. " +
        "Records the post-abort snapshot as an `inventory` task (kind " +
        "`task`). Resolve the id via listTasks. No bulk abort: abort targets " +
        "one running task at a time.",
      arguments: z.object({
        id: z.string().describe("Task id to abort (resolve via listTasks)."),
      }),
      execute: async (
        args: { id: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Verify existence (throws HTTP 404 if it does not exist).
        const cur = await xoRequest(
          cfg,
          "GET",
          `tasks/${enc(args.id)}`,
          {},
          doFetch,
        );
        const status = (cur as { status?: unknown } | null)?.status;
        // Anything other than `pending` is terminal; aborting it is undefined,
        // so skip the POST and record the current snapshot (safe idempotency).
        if (status && status !== "pending") {
          context.logger.warning(
            "XO task {id} not pending (status={status}); abort is a no-op",
            { id: args.id, status },
          );
          const item = normalizeRef(cur);
          const handle = await context.writeResource("inventory", "task", {
            kind: "task",
            count: 1,
            items: [item],
            retrievedAt: new Date().toISOString(),
          });
          return { dataHandles: [handle] };
        }
        context.logger.warning("Aborting XO task {id}", { id: args.id });
        await xoRequest(
          cfg,
          "POST",
          `tasks/${enc(args.id)}/actions/abort`,
          {},
          doFetch,
        );
        const after = await xoRequest(
          cfg,
          "GET",
          `tasks/${enc(args.id)}`,
          {},
          doFetch,
        );
        const item = normalizeRef(after);
        const handle = await context.writeResource("inventory", "task", {
          kind: "task",
          count: 1,
          items: [item],
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    listBackupArchives: {
      description:
        "List backup archives (`GET /backup-archives`), recorded as an " +
        "`inventory` snapshot (kind `backupArchives`). Resolve an archive id " +
        "here (`raw.id`) to feed getBackupArchive/mountLiveDisk. An optional " +
        "`filter` is passed as the raw XO complex-matcher `?filter=` query " +
        "(a no-op if the server ignores it). No `?fields=` projection is sent " +
        "so full objects are returned. NOTE: this is the real `/backup-archives` " +
        "endpoint, not the deprecated `/backup/jobs`.",
      arguments: z.object({
        filter: z.string().optional().describe(
          "raw XO complex-matcher filter (optional; no-op if unsupported)",
        ),
      }),
      execute: async (
        args: { filter?: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const res = await xoRequest(
          cfg,
          "GET",
          "backup-archives",
          { query: args.filter ? [["filter", args.filter]] : [] },
          doFetch,
        );
        if (!Array.isArray(res)) {
          throw new Error(
            `XO GET backup-archives did not return a list (got ${typeof res})`,
          );
        }
        const items = res.map(normalizeRef);
        context.logger.info("XO lists {count} backup archive(s)", {
          count: items.length,
        });
        const handle = await context.writeResource(
          "inventory",
          "backupArchives",
          {
            kind: "backupArchives",
            count: items.length,
            items,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    getBackupArchive: {
      description:
        "Get a single backup archive (`GET /backup-archives/{id}`), recorded as " +
        "a one-item `inventory` snapshot (kind `backupArchive`, count 1). A " +
        "missing id yields XO 404 (clear error). Read `raw.<field>` via CEL for " +
        "archive details not lifted onto `uuid`/`name_label`.",
      arguments: z.object({
        id: z.string().describe(
          "backup archive id (from listBackupArchives raw.id)",
        ),
      }),
      execute: async (
        args: { id: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const res = await xoRequest(
          cfg,
          "GET",
          `backup-archives/${enc(args.id)}`,
          {},
          doFetch,
        );
        if (res == null) {
          throw new Error(
            `XO GET backup-archives/${args.id} returned empty`,
          );
        }
        const item = normalizeRef(res);
        context.logger.info("XO read backup archive {id}", { id: args.id });
        const handle = await context.writeResource(
          "inventory",
          "backupArchive",
          {
            kind: "backupArchive",
            count: 1,
            items: [item],
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    listBackupJobs: {
      description:
        "List backup jobs (`GET /backup-jobs` - the REAL endpoint; the " +
        "deprecated `/backup/jobs` is NOT used), recorded as an `inventory` " +
        "snapshot (kind `backupJobs`). No `?fields=` projection is sent. Read " +
        "`raw.<field>` via CEL for job details.",
      arguments: z.object({}),
      execute: async (
        args: { _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const res = await xoRequest(cfg, "GET", "backup-jobs", {}, doFetch);
        if (!Array.isArray(res)) {
          throw new Error(
            `XO GET backup-jobs did not return a list (got ${typeof res})`,
          );
        }
        const items = res.map(normalizeRef);
        context.logger.info("XO lists {count} backup job(s)", {
          count: items.length,
        });
        const handle = await context.writeResource("inventory", "backupJobs", {
          kind: "backupJobs",
          count: items.length,
          items,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    listRestoreLogs: {
      description:
        "List restore logs (`GET /restore-logs` - the REAL endpoint; the " +
        "deprecated `/restore/logs` and `/backup/logs` are NOT used), recorded " +
        "as an `inventory` snapshot (kind `restoreLogs`). A read-only audit " +
        "surface - never mutating. No `?fields=` projection is sent.",
      arguments: z.object({}),
      execute: async (
        args: { _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const res = await xoRequest(cfg, "GET", "restore-logs", {}, doFetch);
        if (!Array.isArray(res)) {
          throw new Error(
            `XO GET restore-logs did not return a list (got ${typeof res})`,
          );
        }
        const items = res.map(normalizeRef);
        context.logger.info("XO lists {count} restore log(s)", {
          count: items.length,
        });
        const handle = await context.writeResource("inventory", "restoreLogs", {
          kind: "restoreLogs",
          count: items.length,
          items,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    listSchedules: {
      description:
        "List XO backup schedules (`GET /schedules`) and record them as an " +
        "`inventory` snapshot (kind `schedules`). Read-only; each item is a " +
        "`normalizeRef` row (extra fields land in `raw`). Use to resolve a " +
        "schedule id before get/run/update/delete.",
      arguments: z.object({}),
      execute: async (
        args: { _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const res = await xoRequest(
          cfg,
          "GET",
          "schedules",
          { query: [["fields", "id,name,jobId,cron,timezone,enabled"]] },
          doFetch,
        );
        if (!Array.isArray(res)) {
          throw new Error(
            `XO GET schedules did not return a list (got ${typeof res})`,
          );
        }
        const items = res.map(normalizeRef);
        context.logger.info("XO lists {count} backup schedule(s)", {
          count: items.length,
        });
        const handle = await context.writeResource("inventory", "schedules", {
          kind: "schedules",
          count: items.length,
          items,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    getSchedule: {
      description:
        "Fetch one backup schedule by id (`GET /schedules/{id}`) and record a " +
        "`schedule` snapshot (id/jobId/cron/timezone/name/enabled + full `raw`). " +
        "Read-only.",
      arguments: z.object({
        id: z.string().describe("Schedule id (resolve via listSchedules)."),
      }),
      execute: async (
        args: { id: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const res = await xoRequest(
          cfg,
          "GET",
          `schedules/${enc(args.id)}`,
          {},
          doFetch,
        );
        if (!res || typeof res !== "object" || Array.isArray(res)) {
          throw new Error(
            `schedule ${args.id} not found or empty response`,
          );
        }
        const schedule = normalizeSchedule(res as Record<string, unknown>);
        context.logger.info("Fetched backup schedule {id}", { id: args.id });
        const handle = await context.writeResource(
          "schedule",
          `schedule:${args.id}`,
          schedule,
        );
        return { dataHandles: [handle] };
      },
    },
    runSchedule: {
      description:
        "CONSEQUENTIAL: triggers an IMMEDIATE backup run for a schedule " +
        "(`POST /schedules/{id}/actions/run`). Verifies the schedule exists " +
        "first (Rule 5), then launches the run and records a run-ack as an " +
        "`inventory` snapshot (kind `scheduleRun`). NOT idempotent: each call " +
        "starts a new run - never auto-retry.",
      arguments: z.object({
        id: z.string().describe(
          "Schedule id to run now (resolve via listSchedules).",
        ),
      }),
      execute: async (
        args: { id: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Rule 5: verify the schedule exists before the mutation (clean 404).
        await xoRequest(
          cfg,
          "GET",
          `schedules/${enc(args.id)}`,
          {},
          doFetch,
        );
        context.logger.warning("Triggering backup run for schedule {id}", {
          id: args.id,
        });
        const res = await xoRequest(
          cfg,
          "POST",
          `schedules/${enc(args.id)}/actions/run`,
          {},
          doFetch,
        );
        const handle = await context.writeResource("inventory", "scheduleRun", {
          kind: "scheduleRun",
          count: 1,
          items: [{
            uuid: extractUuid(res) || null,
            name_label: `run of schedule ${args.id}`,
            raw: { scheduleId: args.id, result: res },
          }],
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    createSchedule: {
      description: "Create a backup schedule over the JSON-RPC transport " +
        "(`schedule.create`) and record the resulting `schedule` snapshot. XO's " +
        "REST has no schedule-create verb, so this writes over JSON-RPC then " +
        "RE-READS over REST (`GET /schedules/{id}`) so the recorded shape is " +
        "deterministic. NOT naturally idempotent (each call mints a NEW " +
        "schedule); list first, and a duplicate is recoverable via " +
        "deleteSchedule.",
      arguments: z.object({
        jobId: z.string().describe(
          "Backup job id this schedule drives (resolve via listBackupJobs).",
        ),
        cron: z.string().describe("Cron expression, e.g. '0 2 * * *'."),
        timezone: z.string().optional().describe("IANA tz, e.g. 'UTC'."),
        name: z.string().optional().describe("Human-readable schedule name."),
        enabled: z.boolean().optional().describe(
          "Whether the schedule is active.",
        ),
      }),
      execute: async (
        args: {
          jobId: string;
          cron: string;
          timezone?: string;
          name?: string;
          enabled?: boolean;
          _connect?: RpcConnect;
          _fetch?: FetchLike;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        const params: Record<string, unknown> = {
          jobId: args.jobId,
          cron: args.cron,
        };
        if (args.timezone !== undefined) params.timezone = args.timezone;
        if (args.name !== undefined) params.name = args.name;
        if (args.enabled !== undefined) params.enabled = args.enabled;
        context.logger.warning("Creating backup schedule for job {jobId}", {
          jobId: args.jobId,
        });
        // JSON-RPC errors carry only code+message (never token/params) and are
        // left to propagate (swamp records the failure + method-summary report).
        const result = await xoJsonRpc(
          cfg,
          "schedule.create",
          params,
          {},
          args._connect ?? makeRpcConnect,
        );
        const id = extractUuid(result);
        if (!id) {
          throw new Error(
            `schedule.create returned no id: ${JSON.stringify(result)}`,
          );
        }
        // Re-read the canonical state over REST so the recorded shape does not
        // depend on whether schedule.create returns an id or a full object.
        const res = await xoRequest(
          cfg,
          "GET",
          `schedules/${enc(id)}`,
          {},
          doFetch,
        );
        const schedule = normalizeSchedule(
          (res && typeof res === "object" && !Array.isArray(res))
            ? res as Record<string, unknown>
            : { id },
        );
        const handle = await context.writeResource(
          "schedule",
          `schedule:${id}`,
          schedule,
        );
        return { dataHandles: [handle] };
      },
    },
    updateSchedule: {
      description: "Update a backup schedule over the JSON-RPC transport " +
        "(`schedule.set`) and record the refreshed `schedule` snapshot. " +
        "REST-pre-reads the schedule first (Rule 5: a missing id 404s BEFORE " +
        "any write), sets ONLY the provided fields (an empty set is a " +
        "server-side no-op), then RE-READS over REST. Setting the same values " +
        "is idempotent (safe to retry).",
      arguments: z.object({
        id: z.string().describe(
          "Schedule id to update (resolve via listSchedules).",
        ),
        cron: z.string().optional().describe("New cron expression."),
        timezone: z.string().optional().describe("New IANA timezone."),
        name: z.string().optional().describe("New schedule name."),
        enabled: z.boolean().optional().describe(
          "Enable/disable the schedule.",
        ),
      }),
      execute: async (
        args: {
          id: string;
          cron?: string;
          timezone?: string;
          name?: string;
          enabled?: boolean;
          _connect?: RpcConnect;
          _fetch?: FetchLike;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Rule 5: pre-read so a missing id fails cleanly BEFORE any write.
        await xoRequest(
          cfg,
          "GET",
          `schedules/${enc(args.id)}`,
          {},
          doFetch,
        );
        const params: Record<string, unknown> = { id: args.id };
        if (args.cron !== undefined) params.cron = args.cron;
        if (args.timezone !== undefined) params.timezone = args.timezone;
        if (args.name !== undefined) params.name = args.name;
        if (args.enabled !== undefined) params.enabled = args.enabled;
        context.logger.warning("Updating backup schedule {id}", {
          id: args.id,
        });
        await xoJsonRpc(
          cfg,
          "schedule.set",
          params,
          {},
          args._connect ?? makeRpcConnect,
        );
        // Re-read over REST so the recorded shape is the authoritative state.
        const res = await xoRequest(
          cfg,
          "GET",
          `schedules/${enc(args.id)}`,
          {},
          doFetch,
        );
        const schedule = normalizeSchedule(
          (res && typeof res === "object" && !Array.isArray(res))
            ? res as Record<string, unknown>
            : { id: args.id },
        );
        const handle = await context.writeResource(
          "schedule",
          `schedule:${args.id}`,
          schedule,
        );
        return { dataHandles: [handle] };
      },
    },
    deleteSchedule: {
      description:
        "DESTRUCTIVE: delete a backup schedule over the JSON-RPC transport " +
        "(`schedule.delete`). dryRun-gated (default true): a dry run pre-verifies " +
        "and records a plan WITHOUT deleting; set dryRun=false to actually " +
        "delete. Always REST-pre-reads the schedule first (Rule 5) so a delete " +
        "never fires against a non-existent/typo'd id.",
      arguments: z.object({
        id: z.string().describe(
          "Schedule id to delete. VERIFY first via listSchedules.",
        ),
        dryRun: z.boolean().default(true).describe(
          "Default true: record the planned delete WITHOUT calling XO. Set " +
            "false to actually delete.",
        ),
      }),
      execute: async (
        args: {
          id: string;
          dryRun: boolean;
          _connect?: RpcConnect;
          _fetch?: FetchLike;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Rule 5: verify-before-destroy. 404s cleanly if the id is absent.
        await xoRequest(
          cfg,
          "GET",
          `schedules/${enc(args.id)}`,
          {},
          doFetch,
        );
        // Defense-in-depth: only an EXPLICIT dryRun=false deletes.
        const dryRun = args.dryRun !== false;
        if (dryRun) {
          context.logger.info(
            "[dryRun] would delete backup schedule {id}",
            { id: args.id },
          );
          const handle = await context.writeResource(
            "inventory",
            "scheduleDeletePlan",
            {
              kind: "scheduleDeletePlan",
              count: 1,
              items: [{
                uuid: args.id,
                name_label: `planned schedule.delete ${args.id}`,
                raw: { id: args.id },
              }],
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        }
        context.logger.warning("Deleting backup schedule {id}", {
          id: args.id,
        });
        await xoJsonRpc(
          cfg,
          "schedule.delete",
          { id: args.id },
          {},
          args._connect ?? makeRpcConnect,
        );
        return { dataHandles: [] };
      },
    },
    mountLiveDisk: {
      description: "Mount a backup archive for file-level restore " +
        "(`POST /backup-archives/{id}/actions/mount_live_disk`), standing up a " +
        "live mount (loopback/NBD device) on the XO host and recording the " +
        "returned `liveDiskId` into a durable `liveDisk` resource " +
        "(`liveDisk-<liveDiskId>`, status `mounted`). NOT idempotent: each call " +
        "mounts a NEW live disk, and the mount MUST be released with " +
        "unmountLiveDisk or it LEAKS a device on XO. Verifies the archive " +
        "exists first (Rule 5). Fails closed on a task-envelope response or a " +
        "missing id so a liveDiskId it cannot later unmount is never recorded.",
      arguments: z.object({
        archiveId: z.string().describe(
          "backup archive id to mount for file-level restore",
        ),
      }),
      execute: async (
        args: { archiveId: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        // Rule 5: verify the archive exists before the mutation (clean error).
        await xoRequest(
          cfg,
          "GET",
          `backup-archives/${enc(args.archiveId)}`,
          {},
          doFetch,
        );
        context.logger.warning(
          "Mounting live disk for archive {id} (creates a live mount that " +
            "MUST be unmounted)",
          { id: args.archiveId },
        );
        const res = await xoRequest(
          cfg,
          "POST",
          `backup-archives/${enc(args.archiveId)}/actions/mount_live_disk`,
          {},
          doFetch,
        ) as { id?: string; liveDiskId?: string } | string | null;
        // Fail closed on a plausible-but-WRONG id, not only a missing one. A
        // value containing a `/tasks/` href is an async-task envelope, NOT a
        // direct liveDiskId: extractUuid-ing it would silently store the TASK
        // uuid as the liveDiskId, the later unmount would 404, and the real
        // mount would leak. Reject it and point at pollTask as the verify path.
        const rawRef = typeof res === "string"
          ? res
          : (res?.liveDiskId ?? res?.id);
        const refStr = String(rawRef ?? "");
        if (
          refStr.includes("/tasks/") || refStr.includes("/rest/v0/tasks")
        ) {
          throw new Error(
            "mount_live_disk returned a task envelope, not a direct " +
              `liveDiskId: ${JSON.stringify(res)} -- resolve via pollTask ` +
              "first (verify-at-implement)",
          );
        }
        const liveDiskId = extractUuid(rawRef);
        if (!liveDiskId) {
          throw new Error(
            `mountLiveDisk returned no liveDiskId: ${JSON.stringify(res)}`,
          );
        }
        // Record durably BEFORE returning: a unique name per liveDiskId so
        // concurrent/repeat mounts never clobber, and so an operator can always
        // find and unmount an orphaned mount even if the caller crashes.
        const data: LiveDisk = {
          archiveId: args.archiveId,
          liveDiskId,
          status: "mounted",
          raw: (typeof res === "object" && res) ? res : { value: res },
          mountedAt: new Date().toISOString(),
          unmountedAt: null,
        };
        const handle = await context.writeResource(
          "liveDisk",
          `liveDisk-${liveDiskId}`,
          data,
        );
        return { dataHandles: [handle] };
      },
    },
    unmountLiveDisk: {
      description: "Release a live-disk mount " +
        "(`POST /backup-archives/{id}/live_disks/{liveDiskId}/actions/" +
        "unmount`), superseding the `liveDisk-<liveDiskId>` record with status " +
        "`unmounted`. The GOAL (unmounted) is idempotent, but a genuine failure " +
        "(e.g. a real 404/409 on an unknown id) is NOT swallowed - masking a " +
        "real failure is worse than a loud double-unmount error. mountedAt is " +
        "re-recorded null (no read seam to recover the original).",
      arguments: z.object({
        archiveId: z.string().describe(
          "the archive the live disk was mounted from",
        ),
        liveDiskId: z.string().describe(
          "the liveDiskId returned by mountLiveDisk (read via " +
            'data.latest(name,"liveDisk-<id>").attributes.liveDiskId)',
        ),
      }),
      execute: async (
        args: { archiveId: string; liveDiskId: string; _fetch?: FetchLike },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const doFetch = args._fetch ?? makeFetch(cfg);
        context.logger.warning(
          "Unmounting live disk {ld} from archive {a}",
          { ld: args.liveDiskId, a: args.archiveId },
        );
        await xoRequest(
          cfg,
          "POST",
          `backup-archives/${enc(args.archiveId)}/live_disks/${
            enc(args.liveDiskId)
          }/actions/unmount`,
          {},
          doFetch,
        );
        // Record release AFTER the server-side unmount succeeds. mountedAt is
        // null here (schema allows null) so this superseding write satisfies
        // LiveDiskSchema and will NOT throw in prod after a successful unmount;
        // it re-records under the same name, transitioning mounted->unmounted.
        const data: LiveDisk = {
          archiveId: args.archiveId,
          liveDiskId: args.liveDiskId,
          status: "unmounted",
          raw: {},
          mountedAt: null,
          unmountedAt: new Date().toISOString(),
        };
        const handle = await context.writeResource(
          "liveDisk",
          `liveDisk-${args.liveDiskId}`,
          data,
        );
        return { dataHandles: [handle] };
      },
    },
  },
};
