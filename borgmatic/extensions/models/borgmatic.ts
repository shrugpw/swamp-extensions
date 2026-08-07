/**
 * `@shrug/borgmatic` — a host agent for [borgmatic](https://torsion.org/borgmatic/)
 * backups, driven over SSH.
 *
 * One cohesive tool on one host → one model with many verbs (like
 * `@shrug/coolify`), not a family. The model owns the whole per-client shape we
 * used to hand-roll: install borgmatic, generate the borg SSH key, render a
 * version-correct config, gate it on `borgmatic config validate`, write it
 * `0600`, enable the timer, and run/prune/check backups on demand. `status`,
 * `info`, and `listArchives` snapshot the repo as queryable resources for
 * reports ("which clients haven't backed up in 24h?").
 *
 * ## Two SSH hops (do not confuse them)
 *   1. **swamp → host** — the transport seam ({@link sshExec}); every method
 *      shells `borgmatic …` on the target host via this. This is the ONLY thing
 *      that touches the network from swamp's side.
 *   2. **host → repo** — borg's own `ssh_command` using the on-host borg key
 *      (e.g. `/root/.ssh/borg`). The model *configures* (2) into the rendered
 *      config and *drives* it through (1).
 *
 * ## Version-aware rendering (load-bearing, not polish)
 * borgmatic **≥ 2.0** uses the unified `commands:` hook syntax; **1.8–1.9** uses
 * legacy `before_backup:` / `after_backup:` lists. 1.9.14 *rejects*
 * `commands:` outright. So {@link renderBorgmaticConfig} branches on the version
 * detected live via `borgmatic --version`. See {@link parseBorgmaticVersion}.
 *
 * ## Safety envelope
 *   - **Apply-gate:** `configure` renders → `borgmatic config validate` on the
 *     host against a temp file → only swaps it into `0600` place on pass. An
 *     invalid config can never land (the exact gotcha hit during the live build).
 *   - **Write-kernel (from `@shrug/freeipa`/`@shrug/freeradius`):** every mutating
 *     verb records an honest `attempt` audit resource on BOTH success and
 *     failure, then throws-after-persist — a failed run is auditable, never
 *     silent.
 *   - **Repo address is verbatim.** `repositories[].path` is taken as-is; the
 *     model never assumes a hostname resolves. A client uses the borg host's
 *     Tailscale IP (`192.0.2.10`), NOT `borg.example.internal` (which does not
 *     resolve on clients).
 *
 * ## Secrets
 * `encryptionPassphrase` comes from `@webframp/pass` via a CEL global arg,
 * `z.meta({ sensitive: true })`. The rendered on-host config necessarily
 * contains it at mode `0600` (borg needs it — the borgmatic norm). The persisted
 * `config` resource stores a **redacted** copy plus a sha256 of the real content,
 * never the resolved secret. Hardening option: set `encryptionPasscommand` to
 * fetch the passphrase at run time instead of storing it inline.
 *
 * @module
 */
import { z } from "npm:zod@4";

// ===========================================================================
// Global arguments — connection seam + the DESIRED STATE of this backup config.
// ===========================================================================

/** One borg repository the backup targets (local disk or ssh:// offsite). */
const RepositorySchema = z.object({
  path: z
    .string()
    .describe(
      "Repository address, taken VERBATIM (e.g. " +
        "ssh://borgwarehouse@192.0.2.10:2222/./abcd1234 or /mnt/backups/repo). " +
        "Use a reachable address — the model never assumes a hostname resolves.",
    ),
  label: z
    .string()
    .optional()
    .describe("Optional human label for this repository"),
});

/** Native borgmatic database dump hook (consistent-restore-safe). */
const DatabaseHookSchema = z.object({
  type: z
    .enum(["sqlite", "postgresql", "mysql"])
    .describe("Database engine — selects the borgmatic *_databases hook key"),
  name: z
    .string()
    .describe("Database name (postgresql/mysql) or a label (sqlite)"),
  path: z
    .string()
    .optional()
    .describe("Path to the database file (sqlite)"),
  hostname: z.string().optional().describe("DB host (postgresql/mysql)"),
  username: z.string().optional().describe("DB user (postgresql/mysql)"),
  password: z
    .string()
    .optional()
    .meta({ sensitive: true })
    .describe("DB password (postgresql/mysql) — resolve from a vault via CEL"),
});

/** before/after shell hooks + optional native database dump hooks. */
const HooksSchema = z.object({
  beforeBackup: z
    .array(z.string())
    .optional()
    .describe(
      "Raw shell commands to run before a create (e.g. a SQLite WAL " +
        "checkpoint). Rendered version-aware: `commands:` on borgmatic ≥2.0, " +
        "`before_backup:` on 1.8–1.9.",
    ),
  afterBackup: z
    .array(z.string())
    .optional()
    .describe("Raw shell commands to run after a create"),
  databases: z
    .array(DatabaseHookSchema)
    .optional()
    .describe(
      "Native borgmatic database dump hooks (sqlite/postgresql/mysql). " +
        "Preferred over beforeBackup for databases — borgmatic dumps a " +
        "consistent snapshot. Rendered as top-level *_databases keys.",
    ),
});

/** Retention policy → borgmatic keep_* knobs. */
const RetentionSchema = z.object({
  keepHourly: z.number().int().nonnegative().optional(),
  keepDaily: z.number().int().nonnegative().default(7),
  keepWeekly: z.number().int().nonnegative().default(4),
  keepMonthly: z.number().int().nonnegative().default(6),
  keepYearly: z.number().int().nonnegative().optional(),
});

// Input-validation charsets. These values get spliced into ssh argv (which the
// remote sshd re-joins into a shell command), shell scripts, systemd drop-ins,
// or borg's `ssh_command` — so they must reject shell/newline metacharacters.
const POSIX_USER_RE = /^[a-zA-Z0-9_][a-zA-Z0-9_-]*$/;
const SAFE_PATH_RE = /^\/?[a-zA-Z0-9_./-]+$/;
const CALENDAR_RE = /^[A-Za-z0-9 *,:/.~+-]+$/;
const DURATION_RE = /^[A-Za-z0-9 ]+$/;

/** Timer schedule for the packaged `borgmatic.timer` (systemd drop-in). */
const ScheduleSchema = z.object({
  onCalendar: z
    .string()
    .regex(CALENDAR_RE, "onCalendar must be a systemd calendar spec")
    .default("daily")
    .describe("systemd OnCalendar= expression"),
  randomizedDelay: z
    .string()
    .regex(DURATION_RE, "randomizedDelay must be a systemd duration spec")
    .default("3h")
    .describe("systemd RandomizedDelaySec="),
  persistent: z
    .boolean()
    .default(true)
    .describe("systemd Persistent= (run a missed timer at next boot)"),
});

/** Connection seam + desired backup state. */
const GlobalArgsSchema = z.object({
  // --- connection (the swamp→host seam) ---
  host: z.string().describe("Target host management IP or hostname"),
  sshUser: z
    .string()
    .regex(POSIX_USER_RE, "sshUser must be a valid POSIX username")
    .default("root")
    .describe("SSH username on the host"),
  sshPort: z.number().int().positive().default(22).describe("SSH port"),
  identityFile: z
    .string()
    .optional()
    .describe(
      "Path to a private key; presented with IdentitiesOnly so only this key " +
        "is offered. Omit to use the SSH agent/ssh config.",
    ),
  become: z
    .boolean()
    .default(false)
    .describe("Escalate on the host via passwordless sudo (sudo -n)"),
  becomeUser: z
    .string()
    .regex(POSIX_USER_RE, "becomeUser must be a valid POSIX username")
    .default("root")
    .describe("User to sudo to when become=true"),

  // --- config identity ---
  configDir: z
    .string()
    .regex(
      SAFE_PATH_RE,
      "configDir must be a path with no shell metacharacters",
    )
    .default("/etc/borgmatic")
    .describe("Directory the borgmatic config lives in"),
  configName: z
    .string()
    .regex(
      /^[a-zA-Z0-9_.-]+$/,
      "configName must be alphanumeric with _.- only (no path traversal)",
    )
    .default("config")
    .describe("Config basename → <configDir>/<configName>.yaml"),
  borgmaticBin: z
    .string()
    .default("borgmatic")
    .describe(
      "borgmatic executable on the host (name in PATH or absolute path)",
    ),

  // --- what & where ---
  sourceDirectories: z
    .array(z.string())
    .default([])
    .describe("Directories to back up (borgmatic source_directories)"),
  repositories: z
    .array(RepositorySchema)
    .default([])
    .describe("One or more borg repositories (local and/or offsite)"),
  sshKeyPath: z
    .string()
    .default("/root/.ssh/borg")
    .describe("On-host private key borg uses for the host→repo hop"),

  // --- secrets ---
  encryptionPassphrase: z
    .string()
    .optional()
    .meta({ sensitive: true })
    .describe(
      "borg repo passphrase — resolve from a vault via CEL, never hard-code. " +
        "Rendered inline in the 0600 config unless encryptionPasscommand is set.",
    ),
  encryptionPasscommand: z
    .string()
    .optional()
    .describe(
      "Hardening alternative to an inline passphrase: a shell command borgmatic " +
        "runs to fetch the passphrase at run time (encryption_passcommand). " +
        "When set, the passphrase is NOT written to the config file.",
    ),

  // --- policy ---
  compression: z
    .string()
    .default("lz4")
    .describe("borg compression (e.g. lz4, zstd, none)"),
  retention: RetentionSchema.default({
    keepDaily: 7,
    keepWeekly: 4,
    keepMonthly: 6,
  }),
  hooks: HooksSchema.default({}),

  // --- lifecycle toggles ---
  ensureInstalled: z
    .boolean()
    .default(true)
    .describe("Install borgbackup+borgmatic+sqlite3 if absent (apt/dnf)"),
  schedule: ScheduleSchema.optional().describe(
    "When set, enable+start borgmatic.timer with these settings (systemd drop-in)",
  ),
});

/** Resolved connection/desired-state settings. */
export type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

/** Result of running a script in the target host. */
export interface ExecResult {
  stdout: string;
  stderr: string;
  code: number;
}

// ===========================================================================
// Transport seam — run a bash script on the host over SSH (with optional sudo).
// ===========================================================================

/**
 * The one transport seam: run a bash `script` on the host. Injected in tests so
 * the domain logic is exercised with zero live hosts, and swappable for
 * `@swamp/ssh` when `context.runModel` ships. Mirrors the vyos/freeradius seam.
 */
export type TargetRunner = (
  cfg: GlobalArgs,
  script: string,
) => Promise<ExecResult>;

/** The remote argv the SSH script is piped to (honours become/sudo). */
export function remoteShellArgv(cfg: GlobalArgs): string[] {
  if (!cfg.become) return ["bash", "-s"];
  // `-n` fails loudly instead of hanging if passwordless sudo is not set up.
  const u = cfg.becomeUser && cfg.becomeUser !== "root"
    ? ["-u", cfg.becomeUser]
    : [];
  return ["sudo", "-n", ...u, "bash", "-s"];
}

/** Default seam: pipe `script` to `bash -s` on the host over SSH. */
export const sshExec: TargetRunner = async (cfg, script) => {
  const args: string[] = [
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=15",
    "-p",
    String(cfg.sshPort),
  ];
  if (cfg.identityFile) {
    // Scope auth to this one key (IdentitiesOnly) so a loaded agent with many
    // keys doesn't trip the server's MaxAuthTries before this key is offered.
    args.push("-o", "IdentitiesOnly=yes", "-i", cfg.identityFile);
  }
  args.push(`${cfg.sshUser}@${cfg.host}`, ...remoteShellArgv(cfg));

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

/** A short, CEL-friendly descriptor of the configured target. */
export function targetDesc(cfg: GlobalArgs): string {
  return `${cfg.sshUser}@${cfg.host}:${cfg.sshPort}`;
}

/** Absolute path of the rendered config on the host. */
export function configPath(cfg: GlobalArgs): string {
  return `${cfg.configDir.replace(/\/+$/, "")}/${cfg.configName}.yaml`;
}

/**
 * Unique resource instance name for a given model instance. Includes the host
 * so two borgmatic instances with the same `configName` on different hosts
 * don't collide (CRITICAL finding from adversarial review MEDIUM-2).
 */
export function resourceInstanceName(cfg: GlobalArgs): string {
  return `${cfg.configName}@${cfg.host}`;
}

// ===========================================================================
// Small string helpers.
// ===========================================================================

/** Single-quote a value for safe interpolation into a POSIX shell script. */
export function shQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** UTF-8 string → standard base64 (for embedding file bodies in scripts). */
export function strToBase64(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

/** Standard base64 → UTF-8 string. */
export function base64ToStr(b64: string): string {
  const bin = atob(b64.replace(/\s+/g, ""));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

/** sha256 hex of a string (content fingerprint for the config resource). */
export async function sha256Hex(s: string): Promise<string> {
  const data = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Placeholder written in place of the passphrase in the persisted resource. */
export const PASSPHRASE_REDACTED = "<redacted>";

// ===========================================================================
// Version detection + version-aware config rendering.
// ===========================================================================

/** A parsed borgmatic version. */
export interface BorgmaticVersion {
  major: number;
  minor: number;
  raw: string;
}

/**
 * Parse `borgmatic --version` output (e.g. `borgmatic 1.9.14` or `2.0.3`) into
 * major/minor. Throws if no `<major>.<minor>` can be found, so a garbled probe
 * never silently renders the wrong hook syntax.
 */
export function parseBorgmaticVersion(stdout: string): BorgmaticVersion {
  const m = stdout.match(/(\d+)\.(\d+)(?:\.\d+)?/);
  if (!m) {
    throw new Error(
      `could not parse borgmatic version from: ${
        JSON.stringify(stdout.trim())
      }`,
    );
  }
  return { major: Number(m[1]), minor: Number(m[2]), raw: m[0] };
}

/** True when the version uses the borgmatic ≥2.0 unified `commands:` syntax. */
export function usesCommandsSyntax(v: BorgmaticVersion): boolean {
  return v.major >= 2;
}

/** Map a database hook type to its borgmatic top-level config key. */
export function databasesKey(type: "sqlite" | "postgresql" | "mysql"): string {
  switch (type) {
    case "sqlite":
      return "sqlite_databases";
    case "postgresql":
      return "postgresql_databases";
    case "mysql":
      return "mariadb_databases";
  }
}

/** YAML-quote a scalar as a double-quoted string (escape `\` and `"`). */
function yamlDq(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/**
 * Render a borgmatic **flat** config, version-aware on the hook syntax.
 *
 * The passphrase is written inline (borgmatic norm) unless
 * `encryptionPasscommand` is set. Ported from `roles/borgmatic/config.yaml.j2`
 * and a real-world template, generalized. Output is fed to the apply-gate
 * (`borgmatic config validate`) before it is allowed to land, so a rendering
 * mistake is caught on the host rather than shipped.
 *
 * @param cfg Desired state.
 * @param version Detected borgmatic version (selects the hook syntax).
 */
export function renderBorgmaticConfig(
  cfg: GlobalArgs,
  version: BorgmaticVersion,
): string {
  if (cfg.sourceDirectories.length === 0) {
    throw new Error("configure requires at least one sourceDirectory");
  }
  if (cfg.repositories.length === 0) {
    throw new Error("configure requires at least one repository");
  }
  if (!cfg.encryptionPassphrase && !cfg.encryptionPasscommand) {
    throw new Error(
      "configure requires encryptionPassphrase or encryptionPasscommand",
    );
  }

  const L: string[] = [];
  L.push(
    "# Managed by swamp (@shrug/borgmatic). Do not edit by hand — the source of",
    "# truth is the swamp model that renders this file.",
    "source_directories:",
  );
  for (const d of cfg.sourceDirectories) L.push(`    - ${yamlDq(d)}`);
  L.push("", "repositories:");
  for (const r of cfg.repositories) {
    L.push(`    - path: ${yamlDq(r.path)}`);
    if (r.label) L.push(`      label: ${yamlDq(r.label)}`);
  }
  L.push("");
  if (cfg.encryptionPasscommand) {
    L.push(`encryption_passcommand: ${yamlDq(cfg.encryptionPasscommand)}`);
  } else {
    L.push(
      `encryption_passphrase: ${yamlDq(cfg.encryptionPassphrase as string)}`,
    );
  }
  L.push(
    `ssh_command: ${
      yamlDq(
        // shQuote the key path: borg shlex-splits this string, so a crafted
        // path (e.g. `k' -o ProxyCommand=...`) must not break out into extra
        // ssh options. shQuote makes it a single, inert token.
        `ssh -i ${shQuote(cfg.sshKeyPath)} -o StrictHostKeyChecking=accept-new`,
      )
    }`,
    `compression: ${yamlDq(cfg.compression)}`,
    "",
  );

  // Retention.
  const r = cfg.retention;
  if (r.keepHourly !== undefined) L.push(`keep_hourly: ${r.keepHourly}`);
  L.push(`keep_daily: ${r.keepDaily}`);
  L.push(`keep_weekly: ${r.keepWeekly}`);
  L.push(`keep_monthly: ${r.keepMonthly}`);
  if (r.keepYearly !== undefined) L.push(`keep_yearly: ${r.keepYearly}`);

  // Native database dump hooks (top-level *_databases keys; version-stable).
  const dbs = cfg.hooks.databases ?? [];
  for (const db of dbs) {
    L.push("", `${databasesKey(db.type)}:`);
    L.push(`    - name: ${yamlDq(db.name)}`);
    if (db.path) L.push(`      path: ${yamlDq(db.path)}`);
    if (db.hostname) L.push(`      hostname: ${yamlDq(db.hostname)}`);
    if (db.username) L.push(`      username: ${yamlDq(db.username)}`);
    if (db.password) L.push(`      password: ${yamlDq(db.password)}`);
  }

  // before/after shell hooks — the ONE version-branched section.
  const before = cfg.hooks.beforeBackup ?? [];
  const after = cfg.hooks.afterBackup ?? [];
  if (before.length || after.length) {
    L.push("");
    if (usesCommandsSyntax(version)) {
      // borgmatic ≥ 2.0 unified commands: syntax.
      L.push("commands:");
      if (before.length) {
        L.push(
          "    - before: action",
          "      when:",
          "          - create",
          "      run:",
        );
        for (const c of before) L.push(`          - ${yamlDq(c)}`);
      }
      if (after.length) {
        L.push(
          "    - after: action",
          "      when:",
          "          - create",
          "      run:",
        );
        for (const c of after) L.push(`          - ${yamlDq(c)}`);
      }
    } else {
      // borgmatic 1.8–1.9 legacy lists (1.9.14 REJECTS commands:).
      if (before.length) {
        L.push(
          "# borgmatic 1.9.x legacy hook (the 2.0 `commands:` syntax is not " +
            "supported here).",
          "before_backup:",
        );
        for (const c of before) L.push(`    - ${yamlDq(c)}`);
      }
      if (after.length) {
        L.push("after_backup:");
        for (const c of after) L.push(`    - ${yamlDq(c)}`);
      }
    }
  }

  return L.join("\n") + "\n";
}

/**
 * Redact every sensitive value from a rendered config before persisting it.
 * Covers the inline `encryption_passphrase` AND any DB-hook `password` (both are
 * `sensitive: true` in the schema). Matched per-line to end-of-line — preserving
 * indentation — so quoting/escaping can't leave a partial-leak window.
 */
export function redactConfig(rendered: string): string {
  return rendered.replace(
    /^(\s*(?:encryption_passphrase|password):\s*).*$/gim,
    `$1${yamlDq(PASSPHRASE_REDACTED)}`,
  );
}

// ===========================================================================
// Host-side bash scripts (build here, run via the seam).
// ===========================================================================

/** Marker prefix the scripts print for machine parsing. */
const M = "SWAMP_BORG_";

/**
 * Idempotent install of borgbackup + borgmatic + sqlite3. Skips if the binary
 * is already present. Best-effort across apt (Debian) and dnf
 * (EL — borgmatic may require EPEL/pip; the caller can set ensureInstalled=false
 * and manage install separately if the distro repo lacks it).
 */
export function buildInstallScript(cfg: GlobalArgs): string {
  const bin = shQuote(cfg.borgmaticBin);
  return [
    "set -u",
    `if command -v ${bin} >/dev/null 2>&1; then echo ${M}INSTALL_SKIP; exit 0; fi`,
    "if command -v apt-get >/dev/null 2>&1; then",
    "  export DEBIAN_FRONTEND=noninteractive",
    "  apt-get update -qq && apt-get install -y borgbackup borgmatic sqlite3",
    "elif command -v dnf >/dev/null 2>&1; then",
    "  dnf install -y borgbackup borgmatic sqlite",
    "else",
    `  echo ${M}INSTALL_NO_PKGMGR >&2; exit 43`,
    "fi",
    `echo ${M}INSTALL_DONE`,
  ].join("\n") + "\n";
}

/** `borgmatic --version` (used to detect the hook syntax). */
export function buildVersionScript(cfg: GlobalArgs): string {
  return `${shQuote(cfg.borgmaticBin)} --version\n`;
}

/**
 * The converge script: idempotent keygen, then write the rendered config to a
 * temp file, `borgmatic config validate` it (apply-gate), and only `mv` it into
 * `0600` place on pass; on failure, remove the temp and exit non-zero WITHOUT
 * touching the live config. Optionally install+enable the systemd timer drop-in.
 *
 * The rendered config is embedded base64 so its content (passphrase, quotes,
 * newlines) never has to survive shell quoting.
 */
export function buildConfigureScript(
  cfg: GlobalArgs,
  renderedConfig: string,
): string {
  const bin = shQuote(cfg.borgmaticBin);
  const cfgPath = shQuote(configPath(cfg));
  const cfgDir = shQuote(cfg.configDir.replace(/\/+$/, ""));
  const keyPath = shQuote(cfg.sshKeyPath);
  const b64 = shQuote(strToBase64(renderedConfig));
  const keyComment = shQuote(`borg@${cfg.host}`);

  const lines: string[] = [
    "set -u",
    "umask 077",
    // --- idempotent borg keygen (host→repo key) ---
    `KEYP=${keyPath}`,
    `if [ ! -f "$KEYP" ]; then`,
    `  mkdir -p "$(dirname "$KEYP")" && chmod 700 "$(dirname "$KEYP")"`,
    `  ssh-keygen -t ed25519 -f "$KEYP" -N "" -C ${keyComment} \\`,
    `    || { echo ${M}KEYGEN_FAIL >&2; exit 44; }`,
    `  echo ${M}KEYGEN_DONE`,
    `else`,
    `  echo ${M}KEYGEN_SKIP`,
    `fi`,
    // --- render → validate → swap ---
    `mkdir -p ${cfgDir} || { echo ${M}MKDIR_FAIL >&2; exit 45; }`,
    `TMP="$(mktemp)" || { echo ${M}MKTEMP_FAIL >&2; exit 46; }`,
    `printf '%s' ${b64} | base64 -d > "$TMP" \\`,
    `  || { echo ${M}DECODE_FAIL >&2; rm -f "$TMP"; exit 47; }`,
    `chmod 0600 "$TMP"`,
    `if ! ${bin} -c "$TMP" config validate; then`,
    `  echo ${M}VALIDATE_FAIL >&2; rm -f "$TMP"; exit 48`,
    `fi`,
    `echo ${M}VALIDATE_OK`,
    `mv -f "$TMP" ${cfgPath} || { echo ${M}SWAP_FAIL >&2; rm -f "$TMP"; exit 49; }`,
    `echo ${M}CONFIG_OK`,
  ];

  // --- optional systemd timer drop-in ---
  if (cfg.schedule) {
    const s = cfg.schedule;
    const dropin = [
      "[Timer]",
      `OnCalendar=${s.onCalendar}`,
      `RandomizedDelaySec=${s.randomizedDelay}`,
      `Persistent=${s.persistent ? "true" : "false"}`,
      "",
    ].join("\n");
    lines.push(
      "mkdir -p /etc/systemd/system/borgmatic.timer.d",
      `printf '%s' ${shQuote(strToBase64(dropin))} | base64 -d \\`,
      "  > /etc/systemd/system/borgmatic.timer.d/swamp-override.conf \\",
      `  || { echo ${M}DROPIN_FAIL >&2; exit 50; }`,
      "systemctl daemon-reload",
      `systemctl enable --now borgmatic.timer \\`,
      `  || { echo ${M}TIMER_FAIL >&2; exit 51; }`,
      `echo ${M}TIMER_OK`,
    );
  }

  return lines.join("\n") + "\n";
}

/** Run a borgmatic action against the managed config: `borgmatic -c <cfg> …`. */
export function buildActionScript(cfg: GlobalArgs, action: string[]): string {
  const parts = [shQuote(cfg.borgmaticBin), "-c", shQuote(configPath(cfg))]
    .concat(action.map(shQuote));
  return `set -u\n${parts.join(" ")}\n`;
}

/**
 * `initRepo` script: idempotent `repo-create`, guarded by `repo-info` (skip if
 * the repo already exists). Emits a marker so the caller can distinguish
 * created-vs-already-present.
 */
export function buildInitRepoScript(
  cfg: GlobalArgs,
  encryption: string,
): string {
  const bin = shQuote(cfg.borgmaticBin);
  const c = shQuote(configPath(cfg));
  return [
    "set -u",
    `if ${bin} -c ${c} repo-info >/dev/null 2>&1; then`,
    `  echo ${M}REPO_EXISTS; exit 0`,
    `fi`,
    `${bin} -c ${c} repo-create --encryption ${shQuote(encryption)} \\`,
    `  || { echo ${M}REPO_CREATE_FAIL >&2; exit 52; }`,
    `echo ${M}REPO_CREATED`,
  ].join("\n") + "\n";
}

/** Composite health-probe script for `status` (never mutates). */
export function buildStatusScript(cfg: GlobalArgs): string {
  const bin = shQuote(cfg.borgmaticBin);
  const c = shQuote(configPath(cfg));
  const p = shQuote(configPath(cfg));
  return [
    "set +e",
    `if [ -f ${p} ]; then echo ${M}ST_CONFIG_PRESENT=1; else echo ${M}ST_CONFIG_PRESENT=0; fi`,
    `${bin} -c ${c} config validate >/dev/null 2>&1; echo ${M}ST_VALIDATE=$?`,
    `echo ${M}ST_TIMER_ACTIVE=$(systemctl is-active borgmatic.timer 2>/dev/null)`,
    `echo ${M}ST_TIMER_ENABLED=$(systemctl is-enabled borgmatic.timer 2>/dev/null)`,
    `echo ${M}ST_NEXT=$(systemctl show borgmatic.timer -p NextElapseUSecRealtime --value 2>/dev/null)`,
    `echo ${M}ST_LAST_B64=$(${bin} -c ${c} repo-list --json --last 1 2>/dev/null | base64 -w0)`,
  ].join("\n") + "\n";
}

/** Parse `KEY=VALUE` marker lines out of status stdout. */
export function parseMarkers(stdout: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of stdout.split("\n")) {
    const m = line.match(new RegExp(`^${M}([A-Z0-9_]+)=(.*)$`));
    if (m) out[m[1]] = m[2];
  }
  return out;
}

/**
 * Extract the newest archive's ISO time from `borgmatic repo-list --json`
 * output (borg's list JSON: `[{"archives":[{"name","time"}...]}]` or the bare
 * `{"archives":[…]}` shape). Returns null when there are no archives.
 */
/**
 * Parse a borg archive timestamp to epoch ms. borg's `repo-list --json` `time`
 * field is a NAIVE ISO string (no timezone); servers conventionally run UTC, so
 * a bare timestamp is interpreted as UTC (appending `Z`) rather than the swamp
 * host's local zone — otherwise the age comes out shifted by the tz offset
 * (which produced a spurious *negative* age during an early bring-up).
 */
export function borgTimeToMs(t: string): number {
  const hasTz = /([zZ]|[+-]\d{2}:?\d{2})$/.test(t.trim());
  return new Date(hasTz ? t : `${t}Z`).getTime();
}

export function newestArchiveTime(listJson: string): string | null {
  if (!listJson.trim()) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(listJson);
  } catch {
    return null;
  }
  const roots = Array.isArray(parsed) ? parsed : [parsed];
  let newest: string | null = null;
  for (const root of roots) {
    const archives = (root as { archives?: Array<{ time?: string }> })
      ?.archives;
    if (!Array.isArray(archives)) continue;
    for (const a of archives) {
      if (a.time && (newest === null || a.time > newest)) newest = a.time;
    }
  }
  return newest;
}

// ===========================================================================
// Write-kernel — an `attempt` audit resource on BOTH success and failure.
// ===========================================================================

/** An honest record of one mutation attempt — persisted on success AND failure. */
const AttemptSchema = z.object({
  method: z.string().describe("Model method name, e.g. configure"),
  request: z
    .record(z.string(), z.unknown())
    .describe("Sanitized method arguments (no secrets)"),
  success: z.boolean(),
  exitCode: z.number().int().nullable(),
  error: z.string().nullable(),
  target: z.string().describe("Configured target descriptor (user@host:port)"),
  attemptedAt: z.iso.datetime(),
});

/** Minimal logger surface the model relies on from its context. */
interface Logger {
  debug: (message: string, properties?: Record<string, unknown>) => void;
  info: (message: string, properties?: Record<string, unknown>) => void;
  warning: (message: string, properties?: Record<string, unknown>) => void;
  error: (message: string, properties?: Record<string, unknown>) => void;
}

/** Minimal execute context this model relies on. */
interface ExecuteContext {
  globalArgs: GlobalArgs;
  logger: Logger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

/** Minimal pre-flight check context. */
interface CheckContext {
  globalArgs: GlobalArgs;
  logger?: Logger;
}

/** Return shape for every method's execute function. */
interface ExecuteResult {
  dataHandles: Array<{ name: string }>;
}

/** The outcome of a host action for the write-kernel. */
interface Outcome {
  res: ExecResult;
  ok: boolean;
  error?: string;
}

/**
 * Run one mutation, persisting an `attempt` audit resource on BOTH paths, then
 * throwing-after-persist on failure. The state/result resource is written by the
 * caller only on success, after this resolves. Returns the attempt handle plus
 * the raw {@link ExecResult} for the caller to parse.
 */
async function recordAttempt(
  context: ExecuteContext,
  method: string,
  request: Record<string, unknown>,
  fn: () => Promise<Outcome>,
): Promise<{ res: ExecResult; handle: { name: string } }> {
  const cfg = context.globalArgs;
  const base = {
    method,
    request,
    target: targetDesc(cfg),
    attemptedAt: new Date().toISOString(),
  };
  const instance = `${resourceInstanceName(cfg)}-attempt-${method}`;
  context.logger.info("{method} on {target}", { method, target: base.target });

  let outcome: Outcome;
  try {
    outcome = await fn();
  } catch (e) {
    const handle = await context.writeResource("attempt", instance, {
      ...base,
      success: false,
      exitCode: null,
      error: e instanceof Error ? e.message : String(e),
    });
    context.logger.error("{method} failed on {target}: {error}", {
      method,
      target: base.target,
      error: e instanceof Error ? e.message : String(e),
    });
    void handle;
    throw e;
  }

  if (!outcome.ok) {
    const err = outcome.error ?? `exit ${outcome.res.code}`;
    await context.writeResource("attempt", instance, {
      ...base,
      success: false,
      exitCode: outcome.res.code,
      error: err,
    });
    context.logger.error("{method} failed on {target}: {error}", {
      method,
      target: base.target,
      error: err,
    });
    throw new Error(`${method} failed on ${targetDesc(cfg)}: ${err}`);
  }

  const handle = await context.writeResource("attempt", instance, {
    ...base,
    success: true,
    exitCode: outcome.res.code,
    error: null,
  });
  return { res: outcome.res, handle };
}

/** Turn a raw exec result into an Outcome, mapping transport failures. */
function toOutcome(res: ExecResult): Outcome {
  if (transportFailed(res)) {
    return {
      res,
      ok: false,
      error: `SSH transport failed: ${
        res.stderr.trim() || "connection failed"
      }`,
    };
  }
  if (res.code !== 0) {
    // Redact anything that looks like an inline passphrase before persisting —
    // borgmatic config-validate failures can echo config lines including the
    // passphrase. Never leak secrets into the attempt resource.
    const safeStderr = redactPassphraseLeaks(
      res.stderr.trim() || res.stdout.trim() || "(no output)",
    );
    return {
      res,
      ok: false,
      error: `exit ${res.code}: ${safeStderr.slice(-600)}`,
    };
  }
  return { res, ok: true };
}

/**
 * Redact anything that looks like a passphrase or secret from text that may be
 * persisted into an audit resource. Matches `encryption_passphrase: "..."`,
 * `password: "..."`, and bare quoted strings after a `passphrase:` label.
 */
export function redactPassphraseLeaks(text: string): string {
  // Redact from the key label to end-of-line rather than matching a quoted
  // value: yamlDq escapes an embedded `"` as `\"`, so a `"[^"]*"` match would
  // stop at that fake boundary and leak the tail. Line-scoped redaction (the
  // `m` flag keeps `.`/`$` within one line) has no such window.
  return text.replace(
    /^(.*\b(?:encryption_passphrase|password|passphrase)\s*[:=]\s*).*$/gim,
    "$1<redacted>",
  );
}

// ===========================================================================
// Resource schemas.
// ===========================================================================

const ConfigSchema = z.object({
  target: z.string(),
  configPath: z.string(),
  borgmaticVersion: z.string(),
  hookStyle: z.enum(["commands", "before_backup", "none"]),
  sourceDirectories: z.array(z.string()),
  repositories: z.array(RepositorySchema),
  validated: z.boolean(),
  contentSha256: z.string(),
  renderedConfig: z
    .string()
    .describe(
      "Rendered config with the passphrase REDACTED (never the secret)",
    ),
  timerEnabled: z.boolean(),
  appliedAt: z.iso.datetime(),
});

const RepoInitSchema = z.object({
  target: z.string(),
  repositories: z.array(RepositorySchema),
  created: z.boolean().describe(
    "false = repo already existed (idempotent skip)",
  ),
  output: z.string(),
  at: z.iso.datetime(),
});

const BackupSchema = z.object({
  target: z.string(),
  repositories: z.array(RepositorySchema),
  dryRun: z.boolean(),
  archiveName: z.string().nullable(),
  output: z.string().describe("Tail of borgmatic create --stats output"),
  at: z.iso.datetime(),
});

const RepoListSchema = z.object({
  target: z.string(),
  raw: z.unknown().describe("Parsed `borgmatic repo-list --json` output"),
  archiveCount: z.number(),
  newestArchiveTime: z.string().nullable(),
  at: z.iso.datetime(),
});

const RepoInfoSchema = z.object({
  target: z.string(),
  raw: z.unknown().describe("Parsed `borgmatic repo-info --json` output"),
  at: z.iso.datetime(),
});

const OpSchema = z.object({
  target: z.string(),
  op: z.string().describe("prune | compact | check | restore"),
  output: z.string(),
  at: z.iso.datetime(),
});

const StatusSchema = z.object({
  target: z.string(),
  configPresent: z.boolean(),
  configValid: z.boolean(),
  timerActive: z.boolean(),
  timerEnabled: z.boolean(),
  timerState: z.string(),
  newestArchiveTime: z.string().nullable(),
  lastArchiveAgeHours: z.number().nullable(),
  healthy: z
    .boolean()
    .describe("config valid + timer active + a recent-enough archive"),
  reasons: z.array(z.string()),
  at: z.iso.datetime(),
});

// ===========================================================================
// Method helpers.
// ===========================================================================

/** Run the seam, throwing on transport failure with a clear message. */
async function runOrThrow(
  run: TargetRunner,
  cfg: GlobalArgs,
  script: string,
): Promise<ExecResult> {
  const res = await run(cfg, script);
  if (transportFailed(res)) {
    throw new Error(
      `SSH to ${targetDesc(cfg)} failed: ${
        res.stderr.trim() || "connection failed"
      }`,
    );
  }
  return res;
}

/** Detect the borgmatic version on the host (installing first if requested). */
async function detectVersion(
  run: TargetRunner,
  cfg: GlobalArgs,
): Promise<BorgmaticVersion> {
  const res = await runOrThrow(run, cfg, buildVersionScript(cfg));
  if (res.code !== 0) {
    throw new Error(
      `'${cfg.borgmaticBin} --version' failed on ${targetDesc(cfg)} ` +
        `(exit ${res.code}): ${res.stderr.trim() || res.stdout.trim()}. ` +
        `Is borgmatic installed? (set ensureInstalled=true)`,
    );
  }
  return parseBorgmaticVersion(res.stdout);
}

// ===========================================================================
// Model.
// ===========================================================================

/**
 * `@shrug/borgmatic` — host-managed borg backups over SSH. One model, many verbs:
 * `configure` (install/keygen/render/validate/write/timer), `initRepo`,
 * `backup`, `prune`, `compact`, `check`, `listArchives`, `info`, `status`, and a
 * guarded `restore`. Every mutation is audited (write-kernel) and the config is
 * gated on `borgmatic config validate`.
 *
 * The transport seam ({@link sshExec}) is injectable via the (test-only) `_run`
 * method argument so the whole model is exercisable with no live host.
 */
export const model = {
  type: "@shrug/borgmatic",
  version: "2026.08.07.1",
  description:
    "Host agent for borgmatic backups over SSH. Version-aware config rendering " +
    "(commands: on ≥2.0, before_backup: on 1.8–1.9), apply-gated on `borgmatic " +
    "config validate`, with install/keygen/timer convergence, on-demand " +
    "backup/prune/compact/check, and queryable listArchives/info/status. Every " +
    "mutation is audited on both success and failure.",
  globalArguments: GlobalArgsSchema,
  resources: {
    "config": {
      description:
        "The rendered+validated borgmatic config on the host (passphrase redacted).",
      schema: ConfigSchema,
      lifetime: "infinite",
      garbageCollection: 30,
    },
    "repoInit": {
      description:
        "Result of a repo-create (or idempotent already-exists skip).",
      schema: RepoInitSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "backup": {
      description: "Record of a borgmatic create (archive name + stats tail).",
      schema: BackupSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "archives": {
      description: "Snapshot of repo-list (archives + newest time).",
      schema: RepoListSchema,
      lifetime: "30d",
      garbageCollection: 30,
    },
    "repoInfo": {
      description: "Snapshot of repo-info (repo size, encryption, cache).",
      schema: RepoInfoSchema,
      lifetime: "30d",
      garbageCollection: 30,
    },
    "op": {
      description: "Record of a prune/compact/check/restore operation.",
      schema: OpSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "status": {
      description:
        "Composed health: config valid? timer active + next run? last-archive age?",
      schema: StatusSchema,
      lifetime: "30d",
      garbageCollection: 50,
    },
    "attempt": {
      description:
        "Audit record of a mutation attempt (args + result/error + timestamp). Written on both success and failure.",
      schema: AttemptSchema,
      lifetime: "infinite",
      garbageCollection: 200,
    },
  },
  methods: {
    configure: {
      description:
        "Umbrella converge: (optionally) install borgmatic, ensure the borg SSH " +
        "key exists, render a version-aware config, gate it on `borgmatic config " +
        "validate`, write it 0600, and (if `schedule` is set) enable the " +
        "borgmatic.timer. Writes a `config` resource; audits the attempt.",
      arguments: z.object({
        _run: z
          .any()
          .optional()
          .describe("Test-only: inject a TargetRunner seam"),
      }),
      execute: async (
        args: { _run?: TargetRunner },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const run: TargetRunner = args._run ?? sshExec;

        let renderedForResource = "";
        let renderedReal = "";
        let version: BorgmaticVersion = { major: 0, minor: 0, raw: "0.0" };
        let hookStyle: "commands" | "before_backup" | "none" = "none";

        const { res, handle: attemptHandle } = await recordAttempt(
          context,
          "configure",
          { configPath: configPath(cfg), ensureInstalled: cfg.ensureInstalled },
          async () => {
            // 1. install (idempotent) if requested.
            if (cfg.ensureInstalled) {
              const inst = await runOrThrow(run, cfg, buildInstallScript(cfg));
              if (inst.code !== 0) {
                return {
                  res: inst,
                  ok: false,
                  error: `install failed: ${
                    redactPassphraseLeaks(inst.stderr.trim())
                  }`,
                };
              }
            }
            // 2. detect version → select hook syntax.
            version = await detectVersion(run, cfg);
            const hooks = cfg.hooks;
            hookStyle =
              (hooks.beforeBackup?.length || hooks.afterBackup?.length)
                ? (usesCommandsSyntax(version) ? "commands" : "before_backup")
                : "none";
            // 3. render (version-aware) and converge (keygen+validate+write+timer).
            const rendered = renderBorgmaticConfig(cfg, version);
            renderedReal = rendered; // same string the apply-gate validated
            renderedForResource = redactConfig(rendered);
            const conf = await runOrThrow(
              run,
              cfg,
              buildConfigureScript(cfg, rendered),
            );
            return toOutcome(conf);
          },
        );

        const contentSha256 = await sha256Hex(renderedReal);
        const confHandle = await context.writeResource(
          "config",
          resourceInstanceName(cfg),
          {
            target: targetDesc(cfg),
            configPath: configPath(cfg),
            borgmaticVersion: version.raw,
            hookStyle,
            sourceDirectories: cfg.sourceDirectories,
            repositories: cfg.repositories,
            validated: /VALIDATE_OK/.test(res.stdout),
            contentSha256,
            renderedConfig: renderedForResource,
            timerEnabled: cfg.schedule ? /TIMER_OK/.test(res.stdout) : false,
            appliedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, confHandle] };
      },
    },
    initRepo: {
      description:
        "Create the borg repository if it does not already exist (idempotent via " +
        "a repo-info pre-check). v1: the server-side repo slot + key registration " +
        "must already exist (manual). Fails loudly on an auth error.",
      arguments: z.object({
        encryption: z
          .string()
          .default("repokey-blake2")
          .describe("borg encryption mode for repo-create"),
        _run: z.any().optional().describe(
          "Test-only: inject a TargetRunner seam",
        ),
      }),
      execute: async (
        args: { encryption: string; _run?: TargetRunner },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const run: TargetRunner = args._run ?? sshExec;
        const { res, handle: attemptHandle } = await recordAttempt(
          context,
          "initRepo",
          { encryption: args.encryption },
          async () => {
            const r = await runOrThrow(
              run,
              cfg,
              buildInitRepoScript(cfg, args.encryption),
            );
            const oc = toOutcome(r);
            if (!oc.ok) {
              oc.error = `${oc.error}\n` +
                `HINT: did you create the server-side repo slot and register ` +
                `${cfg.sshKeyPath}.pub with the repo provider (BorgWarehouse)?`;
            }
            return oc;
          },
        );
        const created = /REPO_CREATED/.test(res.stdout);
        const handle = await context.writeResource(
          "repoInit",
          resourceInstanceName(cfg),
          {
            target: targetDesc(cfg),
            repositories: cfg.repositories,
            created,
            output: redactPassphraseLeaks(res.stdout + res.stderr).slice(-2000),
            at: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, handle] };
      },
    },
    backup: {
      description:
        "Run `borgmatic create --stats` now (ad-hoc backup). Records the archive " +
        "name + stats tail and audits the attempt.",
      arguments: z.object({
        dryRun: z.boolean().default(false).describe("Pass --dry-run"),
        _run: z.any().optional().describe(
          "Test-only: inject a TargetRunner seam",
        ),
      }),
      execute: async (
        args: { dryRun: boolean; _run?: TargetRunner },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const run: TargetRunner = args._run ?? sshExec;
        const action = ["create", "--stats", "--verbosity", "1"];
        if (args.dryRun) action.push("--dry-run");
        const { res, handle: attemptHandle } = await recordAttempt(
          context,
          "backup",
          { dryRun: args.dryRun },
          async () =>
            toOutcome(
              await runOrThrow(run, cfg, buildActionScript(cfg, action)),
            ),
        );
        const combined = res.stdout + "\n" + res.stderr;
        const m = combined.match(/Archive name:\s*(\S+)/);
        const handle = await context.writeResource(
          "backup",
          resourceInstanceName(cfg),
          {
            target: targetDesc(cfg),
            repositories: cfg.repositories,
            dryRun: args.dryRun,
            archiveName: m ? m[1] : null,
            output: redactPassphraseLeaks(combined).slice(-3000),
            at: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, handle] };
      },
    },
    prune: {
      description:
        "Enforce retention: `borgmatic prune --stats`. Audits the attempt.",
      arguments: z.object({
        _run: z.any().optional().describe(
          "Test-only: inject a TargetRunner seam",
        ),
      }),
      execute: (args: { _run?: TargetRunner }, context: ExecuteContext) =>
        runOp(context, args._run, "prune", ["prune", "--stats"]),
    },
    compact: {
      description:
        "Reclaim segment space: `borgmatic compact`. Audits the attempt.",
      arguments: z.object({
        _run: z.any().optional().describe(
          "Test-only: inject a TargetRunner seam",
        ),
      }),
      execute: (args: { _run?: TargetRunner }, context: ExecuteContext) =>
        runOp(context, args._run, "compact", ["compact"]),
    },
    check: {
      description:
        "Verify repo/archive integrity: `borgmatic check`. Audits the attempt.",
      arguments: z.object({
        _run: z.any().optional().describe(
          "Test-only: inject a TargetRunner seam",
        ),
      }),
      execute: (args: { _run?: TargetRunner }, context: ExecuteContext) =>
        runOp(context, args._run, "check", ["check"]),
    },
    listArchives: {
      description:
        "Snapshot `borgmatic repo-list --json` into the `archives` resource.",
      arguments: z.object({
        _run: z.any().optional().describe(
          "Test-only: inject a TargetRunner seam",
        ),
      }),
      execute: async (
        args: { _run?: TargetRunner },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const run: TargetRunner = args._run ?? sshExec;
        const res = await runOrThrow(
          run,
          cfg,
          buildActionScript(cfg, ["repo-list", "--json"]),
        );
        if (res.code !== 0) {
          throw new Error(
            `listArchives failed on ${targetDesc(cfg)} (exit ${res.code}): ` +
              (res.stderr.trim() || res.stdout.trim()),
          );
        }
        let raw: unknown = null;
        try {
          raw = JSON.parse(res.stdout);
        } catch { /* leave raw null; store below */ }
        const newest = newestArchiveTime(res.stdout);
        const count = (() => {
          const roots = Array.isArray(raw) ? raw : [raw];
          let n = 0;
          for (const r of roots) {
            const a = (r as { archives?: unknown[] })?.archives;
            if (Array.isArray(a)) n += a.length;
          }
          return n;
        })();
        const handle = await context.writeResource(
          "archives",
          resourceInstanceName(cfg),
          {
            target: targetDesc(cfg),
            raw,
            archiveCount: count,
            newestArchiveTime: newest,
            at: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    info: {
      description:
        "Snapshot `borgmatic repo-info --json` into the `repoInfo` resource.",
      arguments: z.object({
        _run: z.any().optional().describe(
          "Test-only: inject a TargetRunner seam",
        ),
      }),
      execute: async (
        args: { _run?: TargetRunner },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const run: TargetRunner = args._run ?? sshExec;
        const res = await runOrThrow(
          run,
          cfg,
          buildActionScript(cfg, ["repo-info", "--json"]),
        );
        if (res.code !== 0) {
          throw new Error(
            `info failed on ${targetDesc(cfg)} (exit ${res.code}): ` +
              (res.stderr.trim() || res.stdout.trim()),
          );
        }
        let raw: unknown = null;
        try {
          raw = JSON.parse(res.stdout);
        } catch { /* leave raw null */ }
        const handle = await context.writeResource(
          "repoInfo",
          resourceInstanceName(cfg),
          {
            target: targetDesc(cfg),
            raw,
            at: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    status: {
      description:
        "Composed health probe (read-only): config present+valid? timer " +
        "active/enabled + next run? newest-archive age vs keepDaily? → a single " +
        "`status` resource ideal for a 'who hasn't backed up in 24h' report.",
      arguments: z.object({
        _run: z.any().optional().describe(
          "Test-only: inject a TargetRunner seam",
        ),
      }),
      execute: async (
        args: { _run?: TargetRunner },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const run: TargetRunner = args._run ?? sshExec;
        const res = await runOrThrow(run, cfg, buildStatusScript(cfg));
        const mk = parseMarkers(res.stdout);
        const configPresent = mk.ST_CONFIG_PRESENT === "1";
        const configValid = mk.ST_VALIDATE === "0";
        const timerState = mk.ST_TIMER_ACTIVE ?? "unknown";
        const timerActive = timerState === "active";
        const timerEnabled = mk.ST_TIMER_ENABLED === "enabled";
        const lastJson = mk.ST_LAST_B64 ? base64ToStr(mk.ST_LAST_B64) : "";
        const newest = newestArchiveTime(lastJson);
        const ageHours = newest
          ? (Date.now() - borgTimeToMs(newest)) / 3_600_000
          : null;
        // Expect a backup within one daily cycle + grace; if keepDaily=0, no
        // daily retention is configured so skip the age check entirely.
        const maxAgeHours = cfg.retention.keepDaily > 0
          ? cfg.retention.keepDaily * 24 + 2
          : Infinity;
        const reasons: string[] = [];
        if (!configPresent) reasons.push("config file absent");
        if (!configValid) reasons.push("config invalid");
        if (!timerActive) reasons.push(`timer not active (${timerState})`);
        if (newest === null) reasons.push("no archives found");
        else if (ageHours !== null && ageHours > maxAgeHours) {
          reasons.push(`last archive ${ageHours.toFixed(1)}h old`);
        }
        const healthy = configPresent && configValid && timerActive &&
          newest !== null && (ageHours ?? Infinity) <= maxAgeHours;
        const handle = await context.writeResource(
          "status",
          resourceInstanceName(cfg),
          {
            target: targetDesc(cfg),
            configPresent,
            configValid,
            timerActive,
            timerEnabled,
            timerState,
            newestArchiveTime: newest,
            lastArchiveAgeHours: ageHours,
            healthy,
            reasons,
            at: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    restore: {
      description:
        "GUARDED restore: `borgmatic extract` of an archive. Destructive to the " +
        "target path — gated behind confirm:true and dry-run by default. Audits " +
        "the attempt.",
      arguments: z.object({
        archive: z
          .string()
          .default("latest")
          .describe("Archive name to extract (default: latest)"),
        paths: z
          .array(z.string())
          .optional()
          .describe("Restrict to these paths within the archive"),
        destination: z
          .string()
          .optional()
          .describe("Extract into this directory (borgmatic --destination)"),
        dryRun: z
          .boolean()
          .default(true)
          .describe("Dry-run by default; set false to actually write files"),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true to run a non-dry-run restore"),
        _run: z.any().optional().describe(
          "Test-only: inject a TargetRunner seam",
        ),
      }),
      execute: async (
        args: {
          archive: string;
          paths?: string[];
          destination?: string;
          dryRun: boolean;
          confirm: boolean;
          _run?: TargetRunner;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const run: TargetRunner = args._run ?? sshExec;
        if (!args.dryRun && !args.confirm) {
          throw new Error(
            "Refusing a non-dry-run restore without confirm:true " +
              "(extract overwrites files at the target path)",
          );
        }
        const action = ["extract", "--archive", args.archive];
        if (args.destination) action.push("--destination", args.destination);
        for (const p of args.paths ?? []) action.push("--path", p);
        if (args.dryRun) action.push("--dry-run");
        const { res, handle: attemptHandle } = await recordAttempt(
          context,
          "restore",
          {
            archive: args.archive,
            dryRun: args.dryRun,
            paths: args.paths ?? [],
            destination: args.destination ?? null,
          },
          async () =>
            toOutcome(
              await runOrThrow(run, cfg, buildActionScript(cfg, action)),
            ),
        );
        const handle = await context.writeResource(
          "op",
          `${resourceInstanceName(cfg)}-restore`,
          {
            target: targetDesc(cfg),
            op: "restore",
            output: redactPassphraseLeaks(res.stdout + res.stderr).slice(-3000),
            at: new Date().toISOString(),
          },
        );
        return { dataHandles: [attemptHandle, handle] };
      },
    },
  },
  checks: {
    "reachable": {
      description:
        "Verify the host answers over SSH before a mutating verb runs (a plain " +
        "`true` over the transport; exit 255 = unreachable/auth failure).",
      labels: ["live"],
      appliesTo: [
        "configure",
        "initRepo",
        "backup",
        "prune",
        "compact",
        "check",
        "restore",
      ],
      execute: async (
        context: CheckContext,
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        const cfg = context.globalArgs;
        const res = await sshExec(cfg, "true\n");
        if (transportFailed(res)) {
          return {
            pass: false,
            errors: [
              `Host ${targetDesc(cfg)} is not reachable over SSH: ${
                res.stderr.trim() || "connection failed"
              }`,
            ],
          };
        }
        context.logger?.info("{target} reachable over SSH", {
          target: targetDesc(cfg),
        });
        return { pass: true };
      },
    },
  },
};

/**
 * Shared execute body for the simple operational verbs (prune/compact/check):
 * run one borgmatic action under the write-kernel and record an `op` resource.
 */
async function runOp(
  context: ExecuteContext,
  runArg: TargetRunner | undefined,
  op: string,
  action: string[],
): Promise<ExecuteResult> {
  const cfg = context.globalArgs;
  const run: TargetRunner = runArg ?? sshExec;
  const { res, handle: attemptHandle } = await recordAttempt(
    context,
    op,
    {},
    async () =>
      toOutcome(await runOrThrow(run, cfg, buildActionScript(cfg, action))),
  );
  const handle = await context.writeResource(
    "op",
    `${resourceInstanceName(cfg)}-${op}`,
    {
      target: targetDesc(cfg),
      op,
      output: redactPassphraseLeaks(res.stdout + res.stderr).slice(-3000),
      at: new Date().toISOString(),
    },
  );
  return { dataHandles: [attemptHandle, handle] };
}
