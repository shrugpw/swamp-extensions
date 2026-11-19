/**
 * `@shrug/borgwarehouse` -- swamp-native control of a
 * [BorgWarehouse](https://borgwarehouse.com/) backup-monitor server
 * (e.g. backup.example.internal, v3.6.3). One cohesive server -> one model with many verbs,
 * like `@shrug/borgmatic` and `@shrug/coolify` -- not a family.
 *
 * ## Why a HYBRID transport (do not confuse the two seams)
 * BorgWarehouse stores every repo slot in `repo.json`, a live lowdb database with
 * an in-memory cache guarded by an async-mutex (`withRepoListLock`). A direct
 * on-host edit of `repo.json` (or `authorized_keys`) races the app's in-memory
 * copy: the next app write (the status cron, every minute) clobbers it -- the
 * 2026-09-09 lost-update incident. So every CRUD/alert/key/compact/status/cron
 * mutation goes through the **HTTP REST API** (the one correct mutator), NEVER by
 * editing on-host files.
 *
 *   1. **HTTP seam** ({@link httpFetch}) -- all REST verbs. Bearer-token auth.
 *      This is the ONLY transport the read/CRUD/alert/compact/cron verbs use.
 *   2. **SSH seam** ({@link sshExec}) -- the ONE API gap: `pruneRepo`. BorgWarehouse
 *      exposes no prune endpoint, and `borg prune` needs the client repo
 *      passphrase (client-side repokey encryption; the server never holds it). So
 *      prune runs direct-local inside the container over SSH + `podman exec`.
 *
 * ## pruneRepo -- the one genuinely new, DESTRUCTIVE primitive
 * It deletes archives on a shared production server, so it carries a full safety
 * envelope hardened after plan-review:
 *   - **F1 caller-asserted interlock:** resolve slug/alias -> repositoryName, then
 *     HARD-ASSERT it `===` a caller-supplied `expectedRepositoryName` (8-hex)
 *     before any borg call. A mismatch refuses -- no wrong-tenant prune.
 *   - **F2 passphrase never in argv:** the passphrase travels in the bash script
 *     piped over ssh STDIN (`export BORG_PASSPHRASE=...`), and is handed to the
 *     container via `podman exec -e BORG_PASSPHRASE` (name only). It is in NO
 *     process argv on either hop (not ssh's, not podman's/borg's) and not in `ps`.
 *   - **F3** no `BORG_RELOCATED_REPO_ACCESS_IS_OK` -- a relocated/replaced repo
 *     must fail loudly, never be auto-accepted.
 *   - **F4 dry-run-first:** `--dry-run` is the DEFAULT; a real delete needs
 *     `confirm:true`; >=1 keep rule is mandatory; a committing prune whose
 *     would-delete count exceeds `maxDelete` is refused without
 *     `allowLargeDelete:true`.
 *   - **F8** `--lock-wait 1800` (waits for an in-flight client backup, fails
 *     clean if it can't acquire); NEVER auto break-lock; after a committing prune,
 *     `compact` is best-effort -- a compact failure is NON-FATAL but RECORDED
 *     ("prune committed, compact pending -> retry compactRepo").
 *
 * ## Secrets (vault-backed, never literal)
 *   - `apiToken` -- the BorgWarehouse REST Bearer token (needs
 *     `DISABLE_INTEGRATIONS=false` on the server).
 *   - `cronjobKey` -- the `CRONJOB_KEY` Bearer used only by `triggerStatusCron`.
 *   - the client repo `passphrase` -- supplied per `pruneRepo` call from the
 *     client's vault via a CEL global/arg.
 * None of these is ever persisted into a resource; captured command output is
 * scrubbed by {@link redactSecrets} before it lands in an audit record.
 *
 * @module
 */
import { z } from "npm:zod@4.4.3";

// ===========================================================================
// Input-validation charsets. Values that get spliced into an ssh script (which
// the remote sshd re-joins into a shell command) or a `podman exec ... borg ...`
// argv MUST reject shell/newline metacharacters.
// ===========================================================================
const REPO_NAME_RE = /^[a-f0-9]{8}$/; // BorgWarehouse repositoryName (8-hex)
const CONTAINER_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/; // podman container/pod name
const SAFE_PATH_RE = /^\/[a-zA-Z0-9_./-]+$/; // absolute path, no metacharacters
const POSIX_USER_RE = /^[a-zA-Z0-9_][a-zA-Z0-9_-]*$/;

// ===========================================================================
// Global arguments -- the connection seam(s) + server identity. The per-repo
// desired state is supplied as METHOD arguments (one server, many repos).
// ===========================================================================

const GlobalArgsSchema = z.object({
  // --- HTTP seam (REST API; used by every verb except pruneRepo) ---
  apiBaseUrl: z
    .string()
    .regex(/^https?:\/\/[^\s]+$/, "apiBaseUrl must be an http(s) URL")
    .describe(
      "BorgWarehouse base URL, scheme+host+port only, e.g. " +
        "http://192.0.2.10:3000 -- the /api/v1 prefix is added by the model. " +
        "Keep the real host in the behavior YAML, not hard-coded here.",
    ),
  apiToken: z
    .string()
    .optional()
    .meta({ sensitive: true })
    .describe(
      "REST Bearer token (users.json tokens[]). Resolve from a vault via CEL, " +
        "never hard-code. Requires DISABLE_INTEGRATIONS=false on the server.",
    ),
  cronjobKey: z
    .string()
    .optional()
    .meta({ sensitive: true })
    .describe(
      "CRONJOB_KEY Bearer, used ONLY by triggerStatusCron. Resolve from a " +
        "vault via CEL (a copy of the server's key -- do not read the env file).",
    ),

  // --- SSH seam (pruneRepo ONLY) ---
  sshHost: z
    .string()
    .optional()
    .describe(
      "Host for the SSH+podman-exec prune hop (e.g. the backup host's mgmt IP)",
    ),
  sshUser: z
    .string()
    .regex(POSIX_USER_RE, "sshUser must be a valid POSIX username")
    .default("rocky")
    .describe("SSH username on the BorgWarehouse host"),
  sshPort: z.number().int().positive().default(22).describe("SSH port"),
  identityFile: z
    .string()
    .optional()
    .describe(
      "Private key path; presented with IdentitiesOnly so only this key is " +
        "offered. Omit to use the SSH agent / ssh config.",
    ),
  proxyJump: z
    .string()
    .optional()
    .describe(
      "Optional ssh -J jump host (the dom0 bastion), e.g. user@bastion. " +
        "Omit when the local ssh config already supplies ProxyJump.",
    ),

  // --- container identity (pruneRepo / breakLock podman path) ---
  containerName: z
    .string()
    .regex(CONTAINER_RE, "containerName must be a valid podman name")
    .default("borgwarehouse")
    .describe("The BorgWarehouse podman container to `podman exec` into"),
  borgBaseDir: z
    .string()
    .regex(SAFE_PATH_RE, "borgBaseDir must be an absolute path, no metachars")
    .default("/home/borgwarehouse")
    .describe("BORG_BASE_DIR inside the container (owns the borg cache)"),
  repoBasePath: z
    .string()
    .regex(SAFE_PATH_RE, "repoBasePath must be an absolute path, no metachars")
    .default("/home/borgwarehouse/repos")
    .describe("Directory holding the repos inside the container"),
  sudo: z
    .boolean()
    .default(true)
    .describe(
      "Run `podman exec` under `sudo -n --preserve-env=BORG_PASSPHRASE` " +
        "(passwordless sudo on the host). Set false if swamp's ssh user can " +
        "run podman directly.",
    ),
});

/** Resolved connection/server settings. */
export type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// ===========================================================================
// HTTP transport seam -- the REST mutator. Injected in tests so every verb is
// exercised with zero live hosts.
// ===========================================================================

/** A single HTTP request issued against the BorgWarehouse REST API. */
export interface HttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

/** The response, body read as text (JSON is parsed by the caller). */
export interface HttpResult {
  status: number;
  body: string;
}

/** The one HTTP seam: perform `req` and return status + text body. */
export type HttpRunner = (req: HttpRequest) => Promise<HttpResult>;

/** Default HTTP seam: a plain `fetch`. */
export const httpFetch: HttpRunner = async (req) => {
  const resp = await fetch(req.url, {
    method: req.method,
    headers: req.headers,
    body: req.body,
  });
  return { status: resp.status, body: await resp.text() };
};

/** Build a full `/api/v1` URL from the base and a leading-slash path. */
export function apiUrl(cfg: GlobalArgs, path: string): string {
  const base = cfg.apiBaseUrl.replace(/\/+$/, "");
  return `${base}/api/v1${path}`;
}

/** The server descriptor used in audit records + resource names (host only). */
export function serverDesc(cfg: GlobalArgs): string {
  try {
    return new URL(cfg.apiBaseUrl).host;
  } catch {
    return cfg.apiBaseUrl;
  }
}

/** A request issued against the API with a chosen Bearer token. */
async function apiRequest(
  run: HttpRunner,
  cfg: GlobalArgs,
  method: string,
  path: string,
  opts: { token?: string; body?: unknown } = {},
): Promise<HttpResult> {
  const headers: Record<string, string> = { "Accept": "application/json" };
  if (opts.token) headers["Authorization"] = `Bearer ${opts.token}`;
  let body: string | undefined;
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }
  return await run({ method, url: apiUrl(cfg, path), headers, body });
}

/** True when the REST call failed in a way we should surface (not 2xx). */
export function httpFailed(res: HttpResult): boolean {
  return res.status < 200 || res.status >= 300;
}

// ===========================================================================
// SSH transport seam -- pruneRepo ONLY. Mirrors the @shrug/borgmatic seam: a
// bash script piped to `bash -s` over ssh STDIN (the passphrase rides here,
// NEVER in argv).
// ===========================================================================

/** Result of running a script on the host. */
export interface ExecResult {
  stdout: string;
  stderr: string;
  code: number;
}

/** The SSH seam: run `script` on the host over ssh, return stdout/stderr/code. */
export type TargetRunner = (
  cfg: GlobalArgs,
  script: string,
) => Promise<ExecResult>;

/** Default SSH seam: pipe `script` to `bash -s` on the host over SSH. */
export const sshExec: TargetRunner = async (cfg, script) => {
  if (!cfg.sshHost) {
    throw new Error("sshHost is required for the SSH (pruneRepo) transport");
  }
  const args: string[] = [
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=15",
    "-p",
    String(cfg.sshPort),
  ];
  if (cfg.proxyJump) args.push("-J", cfg.proxyJump);
  if (cfg.identityFile) {
    // Scope auth to this one key so a loaded agent with many keys doesn't trip
    // the server's MaxAuthTries before this key is offered.
    args.push("-o", "IdentitiesOnly=yes", "-i", cfg.identityFile);
  }
  args.push(`${cfg.sshUser}@${cfg.sshHost}`, "bash", "-s");

  // Every argv element derives from regex-validated GlobalArgs (sshUser,
  // containerName, paths) or fixed literals; the passphrase rides the piped
  // STDIN script, never argv. See the SSH transport note in the README.
  // swamp-quality-ignore deno-command
  const command = new Deno.Command("ssh", {
    args,
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  });
  const child = command.spawn();
  const writer = child.stdin.getWriter();
  await writer.write(new TextEncoder().encode(script));
  await writer.close();
  const { code, stdout, stderr } = await child.output();
  return {
    stdout: new TextDecoder().decode(stdout),
    stderr: new TextDecoder().decode(stderr),
    code,
  };
};

/** SSH exit 255 means the transport itself failed (host unreachable, auth). */
export function transportFailed(res: ExecResult): boolean {
  return res.code === 255;
}

// ===========================================================================
// Small string helpers.
// ===========================================================================

/** Single-quote a value for safe interpolation into a POSIX shell script. */
export function shQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/**
 * Normalize an SSH public key to `<type> <base64-body>` -- dropping the optional
 * trailing comment and collapsing whitespace -- so two keys that differ only by
 * comment/formatting compare equal. This is the IDEMPOTENCY key for addRepo and
 * the rekey-detection basis for authorizeKey (F5/F6). Returns "" for an
 * empty/unset key.
 */
export function normalizeSshPublicKey(key: string | undefined | null): string {
  if (!key) return "";
  const parts = key.trim().split(/\s+/);
  if (parts.length < 2) return key.trim();
  return `${parts[0]} ${parts[1]}`;
}

/** The markers BorgWarehouse's prune output is scanned for. */
const WOULD_PRUNE_RE = /^\s*Would prune:/;
const PRUNING_RE = /^\s*Pruning archive:/;

/**
 * Count the archives a `borg prune --list --dry-run` run WOULD delete, by
 * counting "Would prune:" lines. Used by the F4 delete-count safety floor.
 */
export function countWouldPrune(output: string): number {
  let n = 0;
  for (const line of output.split("\n")) if (WOULD_PRUNE_RE.test(line)) n++;
  return n;
}

/** Count the archives a committing `borg prune --list` run actually deleted. */
export function countPruned(output: string): number {
  let n = 0;
  for (const line of output.split("\n")) if (PRUNING_RE.test(line)) n++;
  return n;
}

/**
 * Redact anything that looks like a secret from text that may be persisted into
 * an audit resource: a `BORG_PASSPHRASE=...` assignment, an `Authorization:
 * Bearer ...` header, or a bare `passphrase`/`token` label. Line-scoped (the `m`
 * flag keeps `.`/`$` within one line) so there is no tail-leak window.
 */
export function redactSecrets(text: string): string {
  return text
    .replace(/^(.*\bBORG_PASSPHRASE\s*=\s*).*$/gim, "$1<redacted>")
    .replace(/^(.*\b[Aa]uthorization:\s*Bearer\s+).*$/gim, "$1<redacted>")
    .replace(
      /^(.*\b(?:passphrase|token|cronjob_?key)\s*[:=]\s*).*$/gim,
      "$1<redacted>",
    );
}

// ===========================================================================
// API response types + resolution.
// ===========================================================================

/** A BorgWarehouse repository slot as returned by the REST API. */
export interface BwRepo {
  id: number;
  alias: string;
  repositoryName: string;
  status?: boolean;
  lastSave?: number;
  alert?: number;
  storageSize?: number;
  storageUsed?: number;
  sshPublicKey?: string;
  comment?: string;
  appendOnlyMode?: boolean;
  archived?: boolean;
  [k: string]: unknown;
}

/** The REST list endpoint wraps repos as `{ repoList: [...] }` or a bare array. */
export function parseRepoList(body: string): BwRepo[] {
  if (!body.trim()) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return [];
  }
  if (Array.isArray(parsed)) return parsed as BwRepo[];
  const obj = parsed as { repoList?: unknown; repositories?: unknown };
  const list = obj.repoList ?? obj.repositories;
  return Array.isArray(list) ? (list as BwRepo[]) : [];
}

/** The path segment (slug) the REST API addresses a repo by: its 8-hex name. */
export function repoSlug(repo: BwRepo): string {
  return repo.repositoryName;
}

/** Selector for resolving one repo out of the list. */
export interface RepoSelector {
  slug?: string;
  alias?: string;
}

/** Resolve exactly one repo from the list by slug (repositoryName) or alias. */
export function resolveRepo(
  repos: BwRepo[],
  sel: RepoSelector,
): BwRepo | undefined {
  if (sel.slug) {
    const bySlug = repos.find((r) => r.repositoryName === sel.slug);
    if (bySlug) return bySlug;
  }
  if (sel.alias) {
    const byAlias = repos.find((r) => r.alias === sel.alias);
    if (byAlias) return byAlias;
  }
  return undefined;
}

/** Match a repo by NORMALIZED ssh public key (the addRepo idempotency key). */
export function findRepoByKey(
  repos: BwRepo[],
  key: string,
): BwRepo | undefined {
  const want = normalizeSshPublicKey(key);
  if (!want) return undefined;
  return repos.find((r) => normalizeSshPublicKey(r.sshPublicKey) === want);
}

/** Seconds since this repo last saved, or null when it never has. */
export function ageSeconds(
  repo: BwRepo,
  nowMs: number = Date.now(),
): number | null {
  if (!repo.lastSave) return null;
  return Math.floor(nowMs / 1000) - repo.lastSave;
}

/** BorgWarehouse "stale": alert enabled (alert>0) and age past the threshold. */
export function isStale(repo: BwRepo, nowMs: number = Date.now()): boolean {
  const a = repo.alert ?? 0;
  if (a <= 0) return false; // alert disabled -> always "green"
  const age = ageSeconds(repo, nowMs);
  return age !== null && age > a;
}

/** Percent of the quota used (0..100+), or null when size is unknown. */
export function storageUsedPct(repo: BwRepo): number | null {
  if (!repo.storageSize || repo.storageSize <= 0) return null;
  const used = repo.storageUsed ?? 0;
  return (used / repo.storageSize) * 100;
}

// ===========================================================================
// pruneRepo -- the SSH + podman-exec script. The passphrase travels in the
// script body (ssh STDIN) and is passed to the container by NAME only.
// ===========================================================================

/** A retention policy. At least one keep rule is MANDATORY (F4). */
export interface KeepPolicy {
  keepHourly?: number;
  keepDaily?: number;
  keepWeekly?: number;
  keepMonthly?: number;
  keepYearly?: number;
}

/** Render the `--keep-*` flags; throws if NO keep rule is set (F4 guard). */
export function keepFlags(keep: KeepPolicy): string[] {
  const out: string[] = [];
  const add = (flag: string, v?: number) => {
    if (v !== undefined) {
      if (!Number.isInteger(v) || v < 0) {
        throw new Error(`${flag} must be a non-negative integer`);
      }
      out.push(flag, String(v));
    }
  };
  add("--keep-hourly", keep.keepHourly);
  add("--keep-daily", keep.keepDaily);
  add("--keep-weekly", keep.keepWeekly);
  add("--keep-monthly", keep.keepMonthly);
  add("--keep-yearly", keep.keepYearly);
  if (out.length === 0) {
    throw new Error(
      "pruneRepo requires at least one keep rule (an empty retention would " +
        "delete ALL archives)",
    );
  }
  return out;
}

/** Inputs needed to build one borg-prune invocation. */
export interface PruneScriptInput {
  repositoryName: string;
  passphrase: string;
  keep: KeepPolicy;
  dryRun: boolean;
  lockWaitSeconds: number;
}

/**
 * Build the bash script run over ssh STDIN. The passphrase is exported in the
 * script body (stdin, never argv) and handed to the container via
 * `podman exec -e BORG_PASSPHRASE` (NAME only). No
 * `BORG_RELOCATED_REPO_ACCESS_IS_OK` (F3). `--lock-wait` waits for an in-flight
 * client backup rather than breaking a live lock (F8).
 */
export function buildPruneScript(
  cfg: GlobalArgs,
  input: PruneScriptInput,
): string {
  if (!REPO_NAME_RE.test(input.repositoryName)) {
    throw new Error(
      `repositoryName ${JSON.stringify(input.repositoryName)} is not 8-hex`,
    );
  }
  if (!Number.isInteger(input.lockWaitSeconds) || input.lockWaitSeconds < 0) {
    throw new Error("lockWaitSeconds must be a non-negative integer");
  }
  const repoPath = `${
    cfg.repoBasePath.replace(/\/+$/, "")
  }/${input.repositoryName}`;

  const podman: string[] = [];
  if (cfg.sudo) {
    podman.push("sudo", "-n", "--preserve-env=BORG_PASSPHRASE");
  }
  podman.push(
    "podman",
    "exec",
    "-e",
    "BORG_PASSPHRASE", // NAME ONLY -- value inherited from the exported env
    "-e",
    `BORG_BASE_DIR=${shQuote(cfg.borgBaseDir)}`,
    shQuote(cfg.containerName),
    "borg",
    "prune",
    "--lock-wait",
    String(input.lockWaitSeconds),
    "--list",
    "--stats",
    ...keepFlags(input.keep),
  );
  if (input.dryRun) podman.push("--dry-run");
  podman.push(shQuote(repoPath));

  return [
    "set -u",
    // Passphrase assignment: in the script body (ssh STDIN), NEVER an argv.
    `export BORG_PASSPHRASE=${shQuote(input.passphrase)}`,
    podman.join(" "),
    "rc=$?",
    "unset BORG_PASSPHRASE",
    "exit $rc",
  ].join("\n") + "\n";
}

// ===========================================================================
// Write-kernel -- an `attempt` audit resource on BOTH success and failure.
// ===========================================================================

const AttemptSchema = z.object({
  method: z.string().describe("Model method name, e.g. pruneRepo"),
  request: z
    .record(z.string(), z.unknown())
    .describe("Sanitized method arguments (NEVER secrets)"),
  success: z.boolean(),
  exitCode: z.number().int().nullable(),
  error: z.string().nullable(),
  target: z.string().describe("Server descriptor (API host)"),
  attemptedAt: z.iso.datetime(),
});

interface Logger {
  debug: (message: string, properties?: Record<string, unknown>) => void;
  info: (message: string, properties?: Record<string, unknown>) => void;
  warning: (message: string, properties?: Record<string, unknown>) => void;
  error: (message: string, properties?: Record<string, unknown>) => void;
}

interface ExecuteContext {
  globalArgs: GlobalArgs;
  logger: Logger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

interface CheckContext {
  globalArgs: GlobalArgs;
  logger?: Logger;
}

interface ExecuteResult {
  dataHandles: Array<{ name: string }>;
}

/** The outcome of a mutation for the write-kernel. */
interface Outcome {
  ok: boolean;
  exitCode: number | null;
  error?: string;
}

/**
 * Run one mutation, persisting an `attempt` audit resource on BOTH paths, then
 * throwing-after-persist on failure. The caller writes the state/result resource
 * only on success, after this resolves.
 */
async function recordAttempt(
  context: ExecuteContext,
  method: string,
  request: Record<string, unknown>,
  instanceKey: string,
  fn: () => Promise<Outcome>,
): Promise<{ handle: { name: string } }> {
  const cfg = context.globalArgs;
  const base = {
    method,
    request,
    target: serverDesc(cfg),
    attemptedAt: new Date().toISOString(),
  };
  const instance = `${instanceKey}-attempt-${method}`;
  context.logger.info("{method} on {target}", { method, target: base.target });

  let outcome: Outcome;
  try {
    outcome = await fn();
  } catch (e) {
    await context.writeResource("attempt", instance, {
      ...base,
      success: false,
      exitCode: null,
      error: redactSecrets(e instanceof Error ? e.message : String(e)),
    });
    context.logger.error("{method} failed on {target}: {error}", {
      method,
      target: base.target,
      error: e instanceof Error ? e.message : String(e),
    });
    throw e;
  }

  if (!outcome.ok) {
    const err = outcome.error ?? `exit ${outcome.exitCode}`;
    await context.writeResource("attempt", instance, {
      ...base,
      success: false,
      exitCode: outcome.exitCode,
      error: redactSecrets(err),
    });
    context.logger.error("{method} failed on {target}: {error}", {
      method,
      target: base.target,
      error: err,
    });
    throw new Error(`${method} failed on ${serverDesc(cfg)}: ${err}`);
  }

  const handle = await context.writeResource("attempt", instance, {
    ...base,
    success: true,
    exitCode: outcome.exitCode,
    error: null,
  });
  return { handle };
}

// ===========================================================================
// Resource schemas.
// ===========================================================================

const RepoViewSchema = z.object({
  id: z.number(),
  alias: z.string(),
  repositoryName: z.string(),
  status: z.boolean().nullable(),
  alert: z.number().nullable(),
  lastSave: z.number().nullable(),
  ageSeconds: z.number().nullable(),
  stale: z.boolean(),
  storageSize: z.number().nullable(),
  storageUsed: z.number().nullable(),
  storageUsedPct: z.number().nullable(),
  appendOnlyMode: z.boolean().nullable(),
});

const ReposSchema = z.object({
  target: z.string(),
  count: z.number(),
  staleCount: z.number(),
  repos: z.array(RepoViewSchema),
  at: z.iso.datetime(),
});

const RepoStatusSchema = z.object({
  target: z.string(),
  repo: RepoViewSchema,
  at: z.iso.datetime(),
});

const RepoSlotSchema = z.object({
  target: z.string(),
  op: z.string().describe("addRepo | authorizeKey | setAlert"),
  id: z.number(),
  alias: z.string(),
  repositoryName: z.string(),
  path: z.string().describe("borg ssh:// repo path clients back up to"),
  changed: z.boolean().describe("false = idempotent no-op"),
  alert: z.number().nullable(),
  appendOnlyMode: z.boolean().nullable(),
  at: z.iso.datetime(),
});

const OpSchema = z.object({
  target: z.string(),
  op: z
    .string()
    .describe("compactRepo | pruneRepo | breakLock | triggerStatusCron"),
  repositoryName: z.string().nullable(),
  dryRun: z.boolean().nullable(),
  skipped: z.boolean().describe(
    "true = benign no-op (e.g. 409 already-running)",
  ),
  deletedCount: z
    .number()
    .nullable()
    .describe("archives pruned (or would-prune on dry-run)"),
  compactStatus: z
    .string()
    .nullable()
    .describe(
      "ok | pending-retry | skipped | null -- post-prune compact outcome",
    ),
  output: z.string().describe("Captured command output, secrets redacted"),
  notes: z.array(z.string()),
  at: z.iso.datetime(),
});

// ===========================================================================
// Method helpers.
// ===========================================================================

/** Map a repo to its persisted view (computed age/stale/pct). */
function repoView(repo: BwRepo, nowMs = Date.now()) {
  return {
    id: repo.id,
    alias: repo.alias,
    repositoryName: repo.repositoryName,
    status: repo.status ?? null,
    alert: repo.alert ?? null,
    lastSave: repo.lastSave ?? null,
    ageSeconds: ageSeconds(repo, nowMs),
    stale: isStale(repo, nowMs),
    storageSize: repo.storageSize ?? null,
    storageUsed: repo.storageUsed ?? null,
    storageUsedPct: storageUsedPct(repo),
    appendOnlyMode: repo.appendOnlyMode ?? null,
  };
}

/** The borg ssh:// path a client backs up to for a given repo. */
function repoClientPath(cfg: GlobalArgs, repositoryName: string): string {
  const host = serverDesc(cfg).replace(/:\d+$/, "");
  return `ssh://${cfg.containerName}@${host}:2222/./${repositoryName}`;
}

/** GET the repo list or throw with a clear message. */
async function getRepoList(
  run: HttpRunner,
  cfg: GlobalArgs,
): Promise<BwRepo[]> {
  const res = await apiRequest(run, cfg, "GET", "/repositories", {
    token: cfg.apiToken,
  });
  if (httpFailed(res)) {
    throw new Error(
      `GET /repositories failed on ${serverDesc(cfg)} ` +
        `(HTTP ${res.status}): ${redactSecrets(res.body).slice(0, 300)}`,
    );
  }
  return parseRepoList(res.body);
}

/** Resource instance key for a repo (alias preferred, else name) @ server. */
function slotKey(
  cfg: GlobalArgs,
  repo: { alias?: string; repositoryName: string },
): string {
  return `${repo.alias || repo.repositoryName}@${serverDesc(cfg)}`;
}

// ===========================================================================
// Model.
// ===========================================================================

export const model = {
  type: "@shrug/borgwarehouse",
  version: "2026.11.19.1",
  description:
    "Swamp-native control of a BorgWarehouse backup-monitor server. HTTP REST " +
    "for all CRUD/alert/key/compact/status-cron (never races the app's lowdb " +
    "mutex); SSH+podman-exec only for the one API gap, a hardened DESTRUCTIVE " +
    "pruneRepo (caller-asserted repo interlock, passphrase off-argv, dry-run " +
    "default, delete-count floor). Every mutation is audited on success and " +
    "failure; all secrets are vault-backed.",
  globalArguments: GlobalArgsSchema,
  resources: {
    "repos": {
      description: "Snapshot of all repos (with computed age/stale/usage).",
      schema: ReposSchema,
      lifetime: "30d",
      garbageCollection: 30,
    },
    "repoStatus": {
      description: "Snapshot of one repo's status.",
      schema: RepoStatusSchema,
      lifetime: "30d",
      garbageCollection: 50,
    },
    "slot": {
      description:
        "Result of a repo-slot mutation (addRepo/authorizeKey/setAlert).",
      schema: RepoSlotSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "op": {
      description:
        "Record of a compact/prune/break-lock/cron operation (output redacted).",
      schema: OpSchema,
      lifetime: "infinite",
      garbageCollection: 200,
    },
    "attempt": {
      description:
        "Audit of a mutation attempt (sanitized args + result/error). Written " +
        "on both success and failure.",
      schema: AttemptSchema,
      lifetime: "infinite",
      garbageCollection: 200,
    },
  },
  methods: {
    // --- reads ---------------------------------------------------------------
    listRepos: {
      description:
        "GET all repositories into the `repos` resource, with computed " +
        "ageSeconds/stale/storageUsedPct per repo. Read-only.",
      arguments: z.object({
        _http: z.any().optional().describe(
          "Test-only: inject an HttpRunner seam",
        ),
      }),
      execute: async (
        args: { _http?: HttpRunner },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const run: HttpRunner = args._http ?? httpFetch;
        const repos = await getRepoList(run, cfg);
        const now = Date.now();
        const views = repos.map((r) => repoView(r, now));
        const handle = await context.writeResource(
          "repos",
          `all@${serverDesc(cfg)}`,
          {
            target: serverDesc(cfg),
            count: views.length,
            staleCount: views.filter((v) => v.stale).length,
            repos: views,
            at: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    repoStatus: {
      description:
        "GET one repository (by slug=repositoryName or alias) into the " +
        "`repoStatus` resource. Read-only.",
      arguments: z.object({
        slug: z.string().optional().describe("repositoryName (8-hex)"),
        alias: z.string().optional().describe("Human alias"),
        _http: z.any().optional().describe(
          "Test-only: inject an HttpRunner seam",
        ),
      }),
      execute: async (
        args: { slug?: string; alias?: string; _http?: HttpRunner },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const run: HttpRunner = args._http ?? httpFetch;
        if (!args.slug && !args.alias) {
          throw new Error("repoStatus requires slug or alias");
        }
        const repos = await getRepoList(run, cfg);
        const repo = resolveRepo(repos, { slug: args.slug, alias: args.alias });
        if (!repo) {
          throw new Error(
            `repo not found (slug=${args.slug ?? "-"}, alias=${
              args.alias ?? "-"
            })`,
          );
        }
        const handle = await context.writeResource(
          "repoStatus",
          slotKey(cfg, repo),
          {
            target: serverDesc(cfg),
            repo: repoView(repo),
            at: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    // --- CRUD / alert / key --------------------------------------------------
    addRepo: {
      description:
        "Create a repo slot (POST /repositories), IDEMPOTENT on the NORMALIZED " +
        "sshPublicKey: if a repo already has this key, return it without a POST. " +
        "A 409 duplicate-key backstop re-GETs and returns the existing repo " +
        "rather than throwing. Audits the attempt.",
      arguments: z.object({
        alias: z.string().describe("Human alias for the repo"),
        sshPublicKey: z.string().describe(
          "Client public key (globally unique in BW)",
        ),
        storageSizeGb: z.number().int().positive().describe("Quota in GB"),
        alert: z.number().int().nonnegative().default(129600).describe(
          "Alert threshold seconds (0=disabled). Default 1.5d.",
        ),
        appendOnlyMode: z.boolean().default(true).describe(
          "Force append-only serve",
        ),
        comment: z.string().default("").describe("Optional comment"),
        _http: z.any().optional().describe(
          "Test-only: inject an HttpRunner seam",
        ),
      }),
      execute: async (
        args: {
          alias: string;
          sshPublicKey: string;
          storageSizeGb: number;
          alert: number;
          appendOnlyMode: boolean;
          comment: string;
          _http?: HttpRunner;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const run: HttpRunner = args._http ?? httpFetch;

        let repo: BwRepo | undefined;
        let changed = false;
        const key = slotKey(cfg, {
          alias: args.alias,
          repositoryName: "pending",
        });

        const { handle: attemptHandle } = await recordAttempt(
          context,
          "addRepo",
          {
            alias: args.alias,
            storageSizeGb: args.storageSizeGb,
            alert: args.alert,
          },
          key,
          async (): Promise<Outcome> => {
            const existing = findRepoByKey(
              await getRepoList(run, cfg),
              args.sshPublicKey,
            );
            if (existing) {
              repo = existing; // idempotent no-op
              return { ok: true, exitCode: 0 };
            }
            const res = await apiRequest(run, cfg, "POST", "/repositories", {
              token: cfg.apiToken,
              body: {
                alias: args.alias,
                sshPublicKey: args.sshPublicKey,
                size: args.storageSizeGb,
                comment: args.comment,
                alert: args.alert,
                appendOnlyMode: args.appendOnlyMode,
              },
            });
            if (res.status === 409) {
              // Duplicate-key backstop: another request created it -- re-GET.
              repo = findRepoByKey(
                await getRepoList(run, cfg),
                args.sshPublicKey,
              );
              if (!repo) {
                return {
                  ok: false,
                  exitCode: 409,
                  error:
                    "409 duplicate key but no matching repo found on re-GET",
                };
              }
              return { ok: true, exitCode: 409 };
            }
            if (httpFailed(res)) {
              return {
                ok: false,
                exitCode: res.status,
                error: `POST /repositories HTTP ${res.status}: ${
                  redactSecrets(res.body).slice(0, 300)
                }`,
              };
            }
            // Re-GET to resolve the freshly-created repo's repositoryName/id.
            repo = findRepoByKey(
              await getRepoList(run, cfg),
              args.sshPublicKey,
            );
            changed = true;
            if (!repo) {
              return {
                ok: false,
                exitCode: res.status,
                error: "repo created but not found on re-GET",
              };
            }
            return { ok: true, exitCode: res.status };
          },
        );

        const r = repo as BwRepo;
        const handle = await context.writeResource("slot", slotKey(cfg, r), {
          target: serverDesc(cfg),
          op: "addRepo",
          id: r.id,
          alias: r.alias,
          repositoryName: r.repositoryName,
          path: repoClientPath(cfg, r.repositoryName),
          changed,
          alert: r.alert ?? null,
          appendOnlyMode: r.appendOnlyMode ?? null,
          at: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, handle] };
      },
    },
    authorizeKey: {
      description:
        "Set a repo's authorized client key (PATCH). First-time set (current " +
        "key empty) is allowed; a REKEY (current key non-empty AND differs) " +
        "REQUIRES confirm:true -- it would revoke the current tenant's access " +
        "(F6). No-op when the key + appendOnly already match.",
      arguments: z.object({
        slug: z.string().optional().describe("repositoryName (8-hex)"),
        alias: z.string().optional().describe("Human alias"),
        sshPublicKey: z.string().describe("The client public key to authorize"),
        appendOnly: z.boolean().default(true).describe(
          "Force append-only serve",
        ),
        confirm: z.boolean().default(false).describe(
          "Required to REKEY (replace a different existing key)",
        ),
        _http: z.any().optional().describe(
          "Test-only: inject an HttpRunner seam",
        ),
      }),
      execute: async (
        args: {
          slug?: string;
          alias?: string;
          sshPublicKey: string;
          appendOnly: boolean;
          confirm: boolean;
          _http?: HttpRunner;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const run: HttpRunner = args._http ?? httpFetch;
        if (!args.slug && !args.alias) {
          throw new Error("authorizeKey requires slug or alias");
        }

        let repo: BwRepo | undefined;
        let changed = false;
        const want = normalizeSshPublicKey(args.sshPublicKey);

        const { handle: attemptHandle } = await recordAttempt(
          context,
          "authorizeKey",
          {
            slug: args.slug ?? null,
            alias: args.alias ?? null,
            appendOnly: args.appendOnly,
          },
          `${args.alias || args.slug}@${serverDesc(cfg)}`,
          async (): Promise<Outcome> => {
            const repos = await getRepoList(run, cfg);
            repo = resolveRepo(repos, { slug: args.slug, alias: args.alias });
            if (!repo) {
              return { ok: false, exitCode: null, error: "repo not found" };
            }
            const current = normalizeSshPublicKey(repo.sshPublicKey);
            const sameKey = current === want;
            const sameMode = (repo.appendOnlyMode ?? true) === args.appendOnly;
            if (sameKey && sameMode) return { ok: true, exitCode: 0 }; // no-op
            // REKEY gate (F6): replacing a DIFFERENT non-empty key needs confirm.
            if (current && !sameKey && !args.confirm) {
              return {
                ok: false,
                exitCode: null,
                error:
                  "refusing to REKEY (replace an existing different key) " +
                  "without confirm:true -- this revokes the current client's " +
                  "access",
              };
            }
            const merged = {
              ...repo,
              sshPublicKey: args.sshPublicKey,
              appendOnlyMode: args.appendOnly,
            };
            const res = await apiRequest(
              run,
              cfg,
              "PATCH",
              `/repositories/${repoSlug(repo)}`,
              { token: cfg.apiToken, body: merged },
            );
            if (res.status === 409) {
              return {
                ok: false,
                exitCode: 409,
                error:
                  "409 -- this key is already authorized on another repo " +
                  "(BorgWarehouse enforces 1 key : 1 repo)",
              };
            }
            if (httpFailed(res)) {
              return {
                ok: false,
                exitCode: res.status,
                error: `PATCH HTTP ${res.status}: ${
                  redactSecrets(res.body).slice(0, 300)
                }`,
              };
            }
            changed = true;
            return { ok: true, exitCode: res.status };
          },
        );

        const r = repo as BwRepo;
        const handle = await context.writeResource("slot", slotKey(cfg, r), {
          target: serverDesc(cfg),
          op: "authorizeKey",
          id: r.id,
          alias: r.alias,
          repositoryName: r.repositoryName,
          path: repoClientPath(cfg, r.repositoryName),
          changed,
          alert: r.alert ?? null,
          appendOnlyMode: changed
            ? args.appendOnly
            : (r.appendOnlyMode ?? null),
          at: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, handle] };
      },
    },
    setAlert: {
      description:
        "Set a repo's alert threshold in SECONDS (PATCH). 0 disables the alert. " +
        "No-op when the threshold already equals the requested value. Audits.",
      arguments: z.object({
        slug: z.string().optional().describe("repositoryName (8-hex)"),
        alias: z.string().optional().describe("Human alias"),
        alertSeconds: z.number().int().nonnegative().describe(
          "Alert threshold seconds (0=off)",
        ),
        _http: z.any().optional().describe(
          "Test-only: inject an HttpRunner seam",
        ),
      }),
      execute: async (
        args: {
          slug?: string;
          alias?: string;
          alertSeconds: number;
          _http?: HttpRunner;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const run: HttpRunner = args._http ?? httpFetch;
        if (!args.slug && !args.alias) {
          throw new Error("setAlert requires slug or alias");
        }

        let repo: BwRepo | undefined;
        let changed = false;

        const { handle: attemptHandle } = await recordAttempt(
          context,
          "setAlert",
          {
            slug: args.slug ?? null,
            alias: args.alias ?? null,
            alertSeconds: args.alertSeconds,
          },
          `${args.alias || args.slug}@${serverDesc(cfg)}`,
          async (): Promise<Outcome> => {
            const repos = await getRepoList(run, cfg);
            repo = resolveRepo(repos, { slug: args.slug, alias: args.alias });
            if (!repo) {
              return { ok: false, exitCode: null, error: "repo not found" };
            }
            if ((repo.alert ?? 0) === args.alertSeconds) {
              return { ok: true, exitCode: 0 }; // no-op
            }
            const merged = { ...repo, alert: args.alertSeconds };
            const res = await apiRequest(
              run,
              cfg,
              "PATCH",
              `/repositories/${repoSlug(repo)}`,
              { token: cfg.apiToken, body: merged },
            );
            if (httpFailed(res)) {
              return {
                ok: false,
                exitCode: res.status,
                error: `PATCH HTTP ${res.status}: ${
                  redactSecrets(res.body).slice(0, 300)
                }`,
              };
            }
            changed = true;
            return { ok: true, exitCode: res.status };
          },
        );

        const r = repo as BwRepo;
        const handle = await context.writeResource("slot", slotKey(cfg, r), {
          target: serverDesc(cfg),
          op: "setAlert",
          id: r.id,
          alias: r.alias,
          repositoryName: r.repositoryName,
          path: repoClientPath(cfg, r.repositoryName),
          changed,
          alert: changed ? args.alertSeconds : (r.alert ?? null),
          appendOnlyMode: r.appendOnlyMode ?? null,
          at: new Date().toISOString(),
        });
        return { dataHandles: [attemptHandle, handle] };
      },
    },
    // --- compact / cron ------------------------------------------------------
    compactRepo: {
      description:
        "POST /repositories/{slug}/compact to reclaim segment space. A 409 " +
        "(already-running) is NON-FATAL and recorded as skipped. compact needs " +
        "no passphrase and is not subject to append-only. Audits.",
      arguments: z.object({
        slug: z.string().optional().describe("repositoryName (8-hex)"),
        alias: z.string().optional().describe("Human alias"),
        _http: z.any().optional().describe(
          "Test-only: inject an HttpRunner seam",
        ),
      }),
      execute: async (
        args: { slug?: string; alias?: string; _http?: HttpRunner },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const run: HttpRunner = args._http ?? httpFetch;
        if (!args.slug && !args.alias) {
          throw new Error("compactRepo requires slug or alias");
        }

        let repo: BwRepo | undefined;
        let skipped = false;
        let output = "";

        const { handle: attemptHandle } = await recordAttempt(
          context,
          "compactRepo",
          { slug: args.slug ?? null, alias: args.alias ?? null },
          `${args.alias || args.slug}@${serverDesc(cfg)}`,
          async (): Promise<Outcome> => {
            const repos = await getRepoList(run, cfg);
            repo = resolveRepo(repos, { slug: args.slug, alias: args.alias });
            if (!repo) {
              return { ok: false, exitCode: null, error: "repo not found" };
            }
            const res = await apiRequest(
              run,
              cfg,
              "POST",
              `/repositories/${repoSlug(repo)}/compact`,
              { token: cfg.apiToken },
            );
            output = redactSecrets(res.body).slice(0, 2000);
            if (res.status === 409) {
              skipped = true; // already running -> benign
              return { ok: true, exitCode: 409 };
            }
            if (httpFailed(res)) {
              return {
                ok: false,
                exitCode: res.status,
                error: `compact HTTP ${res.status}: ${output.slice(0, 300)}`,
              };
            }
            return { ok: true, exitCode: res.status };
          },
        );

        const r = repo as BwRepo;
        const handle = await context.writeResource(
          "op",
          `${slotKey(cfg, r)}-compact`,
          {
            target: serverDesc(cfg),
            op: "compactRepo",
            repositoryName: r.repositoryName,
            dryRun: null,
            skipped,
            deletedCount: null,
            compactStatus: skipped ? "skipped" : "ok",
            output,
            notes: skipped ? ["compact already running (409) -- skipped"] : [],
            at: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, handle] };
      },
    },
    triggerStatusCron: {
      description:
        "POST /cron/status (and optionally /cron/storage) with the CRONJOB_KEY " +
        "Bearer to force a status refresh on demand. A 409 (already-running) is " +
        "benign and recorded as skipped (F7). NOT routine -- the per-minute timer " +
        "owns the steady cadence. Audits.",
      arguments: z.object({
        alsoStorage: z.boolean().default(false).describe(
          "Also POST /cron/storage",
        ),
        _http: z.any().optional().describe(
          "Test-only: inject an HttpRunner seam",
        ),
      }),
      execute: async (
        args: { alsoStorage: boolean; _http?: HttpRunner },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const run: HttpRunner = args._http ?? httpFetch;
        if (!cfg.cronjobKey) {
          throw new Error(
            "triggerStatusCron requires cronjobKey (vault-backed)",
          );
        }

        const notes: string[] = [];
        let skipped = false;

        const { handle: attemptHandle } = await recordAttempt(
          context,
          "triggerStatusCron",
          { alsoStorage: args.alsoStorage },
          `cron@${serverDesc(cfg)}`,
          async (): Promise<Outcome> => {
            const paths = [
              "/cron/status",
              ...(args.alsoStorage ? ["/cron/storage"] : []),
            ];
            for (const p of paths) {
              const res = await apiRequest(run, cfg, "POST", p, {
                token: cfg.cronjobKey,
              });
              if (res.status === 409) {
                skipped = true;
                notes.push(`${p}: already running (409) -- skipped`);
                continue;
              }
              if (httpFailed(res)) {
                return {
                  ok: false,
                  exitCode: res.status,
                  error: `POST ${p} HTTP ${res.status}: ${
                    redactSecrets(res.body).slice(0, 200)
                  }`,
                };
              }
              notes.push(`${p}: ok`);
            }
            return { ok: true, exitCode: 200 };
          },
        );

        const handle = await context.writeResource(
          "op",
          `cron@${serverDesc(cfg)}`,
          {
            target: serverDesc(cfg),
            op: "triggerStatusCron",
            repositoryName: null,
            dryRun: null,
            skipped,
            deletedCount: null,
            compactStatus: null,
            output: "",
            notes,
            at: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, handle] };
      },
    },
    // --- break-lock (confirm-gated stale-lock recovery) ----------------------
    breakLock: {
      description:
        "Explicit stale-lock recovery: POST /repositories/{slug}/break-lock. " +
        "NEVER auto-called by pruneRepo (F8); confirm:true REQUIRED. Use only " +
        "after a crashed client left a lock behind. Audits.",
      arguments: z.object({
        slug: z.string().optional().describe("repositoryName (8-hex)"),
        alias: z.string().optional().describe("Human alias"),
        confirm: z.boolean().default(false).describe(
          "Must be true to break a lock",
        ),
        _http: z.any().optional().describe(
          "Test-only: inject an HttpRunner seam",
        ),
      }),
      execute: async (
        args: {
          slug?: string;
          alias?: string;
          confirm: boolean;
          _http?: HttpRunner;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const run: HttpRunner = args._http ?? httpFetch;
        if (!args.slug && !args.alias) {
          throw new Error("breakLock requires slug or alias");
        }
        if (!args.confirm) {
          throw new Error(
            "Refusing breakLock without confirm:true -- breaking a LIVE lock " +
              "can corrupt an in-progress backup",
          );
        }

        let repo: BwRepo | undefined;
        let output = "";

        const { handle: attemptHandle } = await recordAttempt(
          context,
          "breakLock",
          { slug: args.slug ?? null, alias: args.alias ?? null },
          `${args.alias || args.slug}@${serverDesc(cfg)}`,
          async (): Promise<Outcome> => {
            const repos = await getRepoList(run, cfg);
            repo = resolveRepo(repos, { slug: args.slug, alias: args.alias });
            if (!repo) {
              return { ok: false, exitCode: null, error: "repo not found" };
            }
            const res = await apiRequest(
              run,
              cfg,
              "POST",
              `/repositories/${repoSlug(repo)}/break-lock`,
              { token: cfg.apiToken },
            );
            output = redactSecrets(res.body).slice(0, 2000);
            if (httpFailed(res)) {
              return {
                ok: false,
                exitCode: res.status,
                error: `break-lock HTTP ${res.status}: ${output.slice(0, 300)}`,
              };
            }
            return { ok: true, exitCode: res.status };
          },
        );

        const r = repo as BwRepo;
        const handle = await context.writeResource(
          "op",
          `${slotKey(cfg, r)}-breaklock`,
          {
            target: serverDesc(cfg),
            op: "breakLock",
            repositoryName: r.repositoryName,
            dryRun: null,
            skipped: false,
            deletedCount: null,
            compactStatus: null,
            output,
            notes: [],
            at: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, handle] };
      },
    },
    // --- pruneRepo (DESTRUCTIVE; SSH + podman-exec) --------------------------
    pruneRepo: {
      description:
        "DESTRUCTIVE: enforce retention on a repo via borg prune inside the " +
        "container (SSH + podman-exec). Full safety envelope: resolve " +
        "slug/alias -> repositoryName and HARD-ASSERT it === expectedRepositoryName " +
        "(F1); passphrase over ssh STDIN + `-e BORG_PASSPHRASE` (never argv, F2); " +
        "no RELOCATED-repo flag (F3); --dry-run DEFAULT, confirm:true + a " +
        "mandatory keep rule + a delete-count floor for a real delete (F4); " +
        "--lock-wait, never auto break-lock, best-effort compact after (F8).",
      arguments: z.object({
        slug: z.string().optional().describe("repositoryName (8-hex)"),
        alias: z.string().optional().describe("Human alias"),
        expectedRepositoryName: z
          .string()
          .regex(
            REPO_NAME_RE,
            "expectedRepositoryName must be 8 lowercase hex chars",
          )
          .describe(
            "The 8-hex repo the caller INTENDS to prune (F1 interlock)",
          ),
        passphrase: z
          .string()
          .meta({ sensitive: true })
          .describe(
            "Client repo passphrase -- resolve from the client vault via CEL",
          ),
        keep: z
          .object({
            keepHourly: z.number().int().nonnegative().optional(),
            keepDaily: z.number().int().nonnegative().optional(),
            keepWeekly: z.number().int().nonnegative().optional(),
            keepMonthly: z.number().int().nonnegative().optional(),
            keepYearly: z.number().int().nonnegative().optional(),
          })
          .describe("Retention -- at least one keep rule is MANDATORY (F4)"),
        dryRun: z.boolean().default(true).describe(
          "Dry-run by default; false to actually delete",
        ),
        confirm: z.boolean().default(false).describe(
          "Must be true for a real (non-dry-run) delete",
        ),
        lockWaitSeconds: z.number().int().nonnegative().default(1800).describe(
          "borg --lock-wait",
        ),
        maxDelete: z.number().int().positive().default(10).describe(
          "Delete-count floor: a committing prune deleting more than this is " +
            "refused unless allowLargeDelete=true (F4)",
        ),
        allowLargeDelete: z.boolean().default(false).describe(
          "Override the maxDelete floor",
        ),
        compactAfter: z.boolean().default(true).describe(
          "POST /compact after a committing prune",
        ),
        _run: z.any().optional().describe(
          "Test-only: inject a TargetRunner (SSH) seam",
        ),
        _http: z.any().optional().describe(
          "Test-only: inject an HttpRunner seam",
        ),
      }),
      execute: async (
        args: {
          slug?: string;
          alias?: string;
          expectedRepositoryName: string;
          passphrase: string;
          keep: KeepPolicy;
          dryRun: boolean;
          confirm: boolean;
          lockWaitSeconds: number;
          maxDelete: number;
          allowLargeDelete: boolean;
          compactAfter: boolean;
          _run?: TargetRunner;
          _http?: HttpRunner;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const run: TargetRunner = args._run ?? sshExec;
        const http: HttpRunner = args._http ?? httpFetch;
        if (!args.slug && !args.alias) {
          throw new Error("pruneRepo requires slug or alias");
        }
        // Fail fast on the obvious gates BEFORE any borg call.
        if (!args.dryRun && !args.confirm) {
          throw new Error(
            "Refusing a non-dry-run pruneRepo without confirm:true (prune " +
              "permanently deletes archives)",
          );
        }
        // keepFlags throws if no keep rule is set (F4) -- surface it early too.
        keepFlags(args.keep);

        const notes: string[] = [];
        let repositoryName = "";
        let deletedCount: number | null = null;
        let compactStatus: string | null = null;
        let output = "";
        const committing = !args.dryRun && args.confirm;

        const { handle: attemptHandle } = await recordAttempt(
          context,
          "pruneRepo",
          {
            // NEVER the passphrase.
            slug: args.slug ?? null,
            alias: args.alias ?? null,
            expectedRepositoryName: args.expectedRepositoryName,
            keep: args.keep,
            dryRun: args.dryRun,
            confirm: args.confirm,
            committing,
          },
          `${args.alias || args.slug}@${serverDesc(cfg)}`,
          async (): Promise<Outcome> => {
            // 1. resolve the repo via the API and HARD-ASSERT the interlock (F1).
            const repos = await getRepoList(http, cfg);
            const repo = resolveRepo(repos, {
              slug: args.slug,
              alias: args.alias,
            });
            if (!repo) {
              return { ok: false, exitCode: null, error: "repo not found" };
            }
            repositoryName = repo.repositoryName;
            if (repositoryName !== args.expectedRepositoryName) {
              return {
                ok: false,
                exitCode: null,
                error: `INTERLOCK MISMATCH (F1): resolved repositoryName ` +
                  `${
                    JSON.stringify(repositoryName)
                  } != expectedRepositoryName ` +
                  `${
                    JSON.stringify(args.expectedRepositoryName)
                  } -- refusing to prune`,
              };
            }
            if (repo.archived === true) {
              return {
                ok: false,
                exitCode: null,
                error: "repo is archived -- refusing to prune",
              };
            }

            // 2. On a committing run, dry-run FIRST to enforce the floor (F4).
            if (committing) {
              const dryScript = buildPruneScript(cfg, {
                repositoryName,
                passphrase: args.passphrase,
                keep: args.keep,
                dryRun: true,
                lockWaitSeconds: args.lockWaitSeconds,
              });
              const dry = await run(cfg, dryScript);
              if (transportFailed(dry)) {
                return {
                  ok: false,
                  exitCode: dry.code,
                  error: `SSH transport failed: ${dry.stderr.trim()}`,
                };
              }
              // borg writes --list output (incl. "Would prune:") to STDERR, so
              // scan STDOUT+STDERR together; exit 1 is a non-fatal WARNING.
              const dryOut = dry.stdout + "\n" + dry.stderr;
              if (dry.code >= 2) {
                output = redactSecrets(dryOut).slice(-2000);
                return {
                  ok: false,
                  exitCode: dry.code,
                  error: `preflight dry-run exit ${dry.code}: ${
                    output.slice(-300)
                  }`,
                };
              }
              if (dry.code === 1) {
                notes.push(
                  "preflight dry-run exit 1 (borg WARNING, non-fatal)",
                );
              }
              const wouldDelete = countWouldPrune(dryOut);
              if (wouldDelete > args.maxDelete && !args.allowLargeDelete) {
                return {
                  ok: false,
                  exitCode: null,
                  error: `DELETE-COUNT FLOOR (F4): preflight would delete ` +
                    `${wouldDelete} archives (> maxDelete=${args.maxDelete}); ` +
                    `set allowLargeDelete:true to proceed`,
                };
              }
              notes.push(
                `preflight dry-run: would delete ${wouldDelete} archive(s)`,
              );
            }

            // 3. the real prune (committing) or the reported dry-run.
            const script = buildPruneScript(cfg, {
              repositoryName,
              passphrase: args.passphrase,
              keep: args.keep,
              dryRun: args.dryRun,
              lockWaitSeconds: args.lockWaitSeconds,
            });
            const res = await run(cfg, script);
            if (transportFailed(res)) {
              return {
                ok: false,
                exitCode: res.code,
                error: `SSH transport failed: ${res.stderr.trim()}`,
              };
            }
            // borg writes --list output to STDERR; scan both streams. Exit 1 is
            // a non-fatal WARNING -- record it, reserve hard-fail for code >= 2.
            const resOut = res.stdout + "\n" + res.stderr;
            output = redactSecrets(resOut).slice(-3000);
            if (res.code >= 2) {
              return {
                ok: false,
                exitCode: res.code,
                error: `borg prune exit ${res.code}: ${output.slice(-400)}`,
              };
            }
            if (res.code === 1) {
              notes.push(
                `borg prune exit 1 (WARNING, non-fatal): ${output.slice(-300)}`,
              );
            }
            deletedCount = args.dryRun
              ? countWouldPrune(resOut)
              : countPruned(resOut);

            // 4. compact after a committing prune -- NON-FATAL but RECORDED (F8).
            if (committing && args.compactAfter) {
              const cres = await apiRequest(
                http,
                cfg,
                "POST",
                `/repositories/${repositoryName}/compact`,
                { token: cfg.apiToken },
              );
              if (cres.status === 409) {
                compactStatus = "skipped";
                notes.push("compact already running (409) -- skipped");
              } else if (httpFailed(cres)) {
                compactStatus = "pending-retry";
                notes.push(
                  `prune committed, compact FAILED (HTTP ${cres.status}) -- ` +
                    `retry compactRepo to reclaim space`,
                );
              } else {
                compactStatus = "ok";
              }
            }
            return { ok: true, exitCode: res.code };
          },
        );

        const handle = await context.writeResource(
          "op",
          `${args.alias || repositoryName || "prune"}@${serverDesc(cfg)}-prune`,
          {
            target: serverDesc(cfg),
            op: "pruneRepo",
            repositoryName: repositoryName || null,
            dryRun: args.dryRun,
            skipped: false,
            deletedCount,
            compactStatus,
            output,
            notes,
            at: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, handle] };
      },
    },
  },
  checks: {
    "apiReachable": {
      description:
        "Verify the BorgWarehouse REST API answers (GET /repositories) before a " +
        "mutating verb runs.",
      labels: ["live"],
      appliesTo: [
        "addRepo",
        "authorizeKey",
        "setAlert",
        "compactRepo",
        "breakLock",
      ],
      execute: async (
        context: CheckContext,
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        const cfg = context.globalArgs;
        try {
          const res = await apiRequest(httpFetch, cfg, "GET", "/repositories", {
            token: cfg.apiToken,
          });
          if (httpFailed(res)) {
            return {
              pass: false,
              errors: [
                `BorgWarehouse API ${
                  serverDesc(cfg)
                } returned HTTP ${res.status}`,
              ],
            };
          }
          context.logger?.info("{target} API reachable", {
            target: serverDesc(cfg),
          });
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `BorgWarehouse API ${serverDesc(cfg)} unreachable: ${
                e instanceof Error ? e.message : String(e)
              }`,
            ],
          };
        }
      },
    },
  },
};
