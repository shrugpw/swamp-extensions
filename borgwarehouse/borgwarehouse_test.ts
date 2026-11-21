/**
 * Unit tests for @shrug/borgwarehouse -- pure helpers plus every method wired
 * against injected HTTP and SSH seams. No live host is ever touched. The
 * plan-review safety gates (F1-F8) each have a dedicated regression test.
 */
import {
  assertEquals,
  assertMatch,
  assertNotMatch,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1";
import {
  ageSeconds,
  apiUrl,
  buildPruneScript,
  type BwRepo,
  countPruned,
  countWouldPrune,
  findRepoByKey,
  type GlobalArgs,
  type HttpRequest,
  type HttpResult,
  type HttpRunner,
  isStale,
  keepFlags,
  model,
  normalizeSshPublicKey,
  parseRepoList,
  redactSecrets,
  resolveRepo,
  serverDesc,
  shQuote,
  sshExec,
  storageUsedPct,
  type TargetRunner,
} from "./borgwarehouse.ts";

// Schema handle for validation-rejection tests.
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

/** A scripted HTTP runner: match on a url substring (+optional method). */
function scriptedHttp(
  rules: Array<{ match: string; method?: string; result: Partial<HttpResult> }>,
): { run: HttpRunner; calls: HttpRequest[] } {
  const calls: HttpRequest[] = [];
  const run: HttpRunner = (req) => {
    calls.push(req);
    for (const r of rules) {
      if (req.url.includes(r.match) && (!r.method || r.method === req.method)) {
        return Promise.resolve({
          status: r.result.status ?? 200,
          body: r.result.body ?? "",
        });
      }
    }
    return Promise.resolve({ status: 200, body: "" });
  };
  return { run, calls };
}

/** A scripted SSH runner: canned result per piped-script substring match. */
function scriptedSsh(
  rules: Array<
    {
      match: string;
      result: Partial<{ stdout: string; stderr: string; code: number }>;
    }
  >,
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

const PP = "pphr4se-SECRET-do-not-leak";
const API_TOKEN = "api-TOKEN-xyz";
const CRON_KEY = "cron-KEY-abc";

const KEY_A =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEKEYAAA client-a@host";
const KEY_B =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEKEYBBB client-b@host";

function repoA(over: Partial<BwRepo> = {}): BwRepo {
  return {
    id: 1,
    alias: "demo-1",
    repositoryName: "c055df60",
    status: true,
    lastSave: Math.floor(Date.now() / 1000) - 3600,
    alert: 129600,
    storageSize: 100,
    storageUsed: 10,
    sshPublicKey: KEY_A,
    appendOnlyMode: true,
    archived: false,
    ...over,
  };
}

function repoOther(over: Partial<BwRepo> = {}): BwRepo {
  return {
    id: 2,
    alias: "other-1",
    repositoryName: "ae166862",
    sshPublicKey: KEY_B,
    alert: 129600,
    appendOnlyMode: true,
    ...over,
  };
}

const baseCfg: GlobalArgs = {
  apiBaseUrl: "http://192.0.2.10:3000",
  apiToken: API_TOKEN,
  cronjobKey: CRON_KEY,
  sshHost: "192.0.2.10",
  sshUser: "rocky",
  sshPort: 22,
  containerName: "borgwarehouse",
  borgBaseDir: "/home/borgwarehouse",
  repoBasePath: "/home/borgwarehouse/repos",
  sudo: true,
};

// --- pure helpers -----------------------------------------------------------

Deno.test("shQuote neutralizes shell metacharacters", () => {
  assertEquals(shQuote("a'b"), "'a'\\''b'");
  assertEquals(shQuote("x; rm -rf /"), "'x; rm -rf /'");
});

Deno.test("normalizeSshPublicKey drops comment + collapses whitespace (F5)", () => {
  assertEquals(
    normalizeSshPublicKey("ssh-ed25519   AAAABODY   comment here"),
    "ssh-ed25519 AAAABODY",
  );
  // comment-only difference -> equal
  assertEquals(
    normalizeSshPublicKey("ssh-ed25519 AAAABODY alice@a"),
    normalizeSshPublicKey("ssh-ed25519 AAAABODY bob@b\n"),
  );
  assertEquals(normalizeSshPublicKey(""), "");
  assertEquals(normalizeSshPublicKey(undefined), "");
});

Deno.test("apiUrl builds the /api/v1 path", () => {
  assertEquals(
    apiUrl(baseCfg, "/repositories"),
    "http://192.0.2.10:3000/api/v1/repositories",
  );
  assertEquals(
    apiUrl(
      { ...baseCfg, apiBaseUrl: "http://192.0.2.10:3000/" },
      "/cron/status",
    ),
    "http://192.0.2.10:3000/api/v1/cron/status",
  );
});

Deno.test("serverDesc is host:port", () => {
  assertEquals(serverDesc(baseCfg), "192.0.2.10:3000");
});

Deno.test("parseRepoList handles bare array and {repoList}", () => {
  assertEquals(parseRepoList(JSON.stringify([repoA()])).length, 1);
  assertEquals(
    parseRepoList(JSON.stringify({ repoList: [repoA()] })).length,
    1,
  );
  assertEquals(parseRepoList("").length, 0);
  assertEquals(parseRepoList("not json").length, 0);
});

Deno.test("resolveRepo / findRepoByKey select by slug/alias/key", () => {
  const repos = [repoA(), repoOther()];
  assertEquals(resolveRepo(repos, { slug: "c055df60" })?.id, 1);
  assertEquals(resolveRepo(repos, { alias: "other-1" })?.id, 2);
  assertEquals(resolveRepo(repos, { slug: "nope" }), undefined);
  // normalized-key match ignores the comment.
  assertEquals(
    findRepoByKey(
      repos,
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEKEYAAA other-comment",
    )?.id,
    1,
  );
  assertEquals(findRepoByKey(repos, "ssh-ed25519 NOSUCHBODY x")?.id, undefined);
});

Deno.test("ageSeconds / isStale / storageUsedPct", () => {
  const now = Date.now();
  const fresh = repoA({ lastSave: Math.floor(now / 1000) - 100, alert: 1000 });
  assertEquals(isStale(fresh, now), false);
  const stale = repoA({ lastSave: Math.floor(now / 1000) - 5000, alert: 1000 });
  assertEquals(isStale(stale, now), true);
  // alert=0 disables the alert -> never stale.
  assertEquals(isStale(repoA({ alert: 0, lastSave: 1 }), now), false);
  assertEquals(ageSeconds(repoA({ lastSave: undefined }), now), null);
  assertEquals(
    storageUsedPct(repoA({ storageSize: 100, storageUsed: 25 })),
    25,
  );
  assertEquals(storageUsedPct(repoA({ storageSize: 0 })), null);
});

Deno.test("countWouldPrune / countPruned parse borg output", () => {
  const dry = "Keeping archive: a\nWould prune:  b\nWould prune:  c\n";
  assertEquals(countWouldPrune(dry), 2);
  const real = "Keeping archive: a\nPruning archive: b\nPruning archive: c\n";
  assertEquals(countPruned(real), 2);
});

Deno.test("keepFlags renders flags and REFUSES empty retention (F4)", () => {
  assertEquals(keepFlags({ keepDaily: 7, keepWeekly: 4 }), [
    "--keep-daily",
    "7",
    "--keep-weekly",
    "4",
  ]);
  assertThrows(() => keepFlags({}), Error, "at least one keep rule");
});

Deno.test("redactSecrets hides passphrase/bearer/token lines", () => {
  const t = [
    "export BORG_PASSPHRASE='topsecret'",
    "Authorization: Bearer abc123",
    "passphrase: hunter2",
    "normal line",
  ].join("\n");
  const r = redactSecrets(t);
  assertNotMatch(r, /topsecret/);
  assertNotMatch(r, /abc123/);
  assertNotMatch(r, /hunter2/);
  assertMatch(r, /normal line/);
});

// --- buildPruneScript: the F2/F3/F8 transport guarantees -------------------

Deno.test("buildPruneScript: passphrase off-argv, no RELOCATED, lock-wait, dry-run", () => {
  const s = buildPruneScript(baseCfg, {
    repositoryName: "c055df60",
    passphrase: PP,
    keep: { keepDaily: 7 },
    dryRun: true,
    lockWaitSeconds: 1800,
  });
  const lines = s.split("\n");
  // F2: the passphrase value appears on EXACTLY ONE line -- the export (stdin).
  const withPp = lines.filter((l) => l.includes(PP));
  assertEquals(withPp.length, 1);
  assertMatch(withPp[0], /^export BORG_PASSPHRASE=/);
  // F2: the podman/borg argv line passes the NAME only, not the value.
  const podman = lines.find((l) => l.includes("podman exec"))!;
  assertMatch(podman, /-e BORG_PASSPHRASE\b/);
  assertNotMatch(podman, new RegExp(PP));
  assertMatch(podman, /--preserve-env=BORG_PASSPHRASE/);
  // F3: never auto-accept a relocated/replaced repo.
  assertNotMatch(s, /BORG_RELOCATED_REPO_ACCESS_IS_OK/);
  // F8 + flags.
  assertMatch(podman, /--lock-wait 1800/);
  assertMatch(podman, /--keep-daily 7/);
  assertMatch(podman, /--dry-run/);
  assertMatch(podman, /'\/home\/borgwarehouse\/repos\/c055df60'/);
});

Deno.test("buildPruneScript: rejects a non-8-hex repositoryName", () => {
  assertThrows(
    () =>
      buildPruneScript(baseCfg, {
        repositoryName: "../etc",
        passphrase: PP,
        keep: { keepDaily: 1 },
        dryRun: true,
        lockWaitSeconds: 1800,
      }),
    Error,
    "8-hex",
  );
});

Deno.test("buildPruneScript: committing run omits --dry-run", () => {
  const s = buildPruneScript(baseCfg, {
    repositoryName: "c055df60",
    passphrase: PP,
    keep: { keepDaily: 7 },
    dryRun: false,
    lockWaitSeconds: 1800,
  });
  assertNotMatch(
    s.split("\n").find((l) => l.includes("podman exec"))!,
    /--dry-run/,
  );
});

// --- reads ------------------------------------------------------------------

Deno.test("listRepos: snapshots repos with computed stale/age", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const nowS = Math.floor(Date.now() / 1000);
  const list = [
    repoA({ lastSave: nowS - 100, alert: 1000 }), // fresh
    repoOther({ lastSave: nowS - 9999, alert: 1000 }), // stale
  ];
  const { run } = scriptedHttp([
    {
      match: "/repositories",
      method: "GET",
      result: { body: JSON.stringify(list) },
    },
  ]);
  await callExec(model.methods.listRepos.execute, { _http: run }, context);
  const r = writes.find((w) => w.spec === "repos");
  assertEquals(r?.data.count, 2);
  assertEquals(r?.data.staleCount, 1);
});

Deno.test("repoStatus: resolves one repo by alias", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run } = scriptedHttp([
    {
      match: "/repositories",
      method: "GET",
      result: { body: JSON.stringify([repoA()]) },
    },
  ]);
  await callExec(model.methods.repoStatus.execute, {
    alias: "demo-1",
    _http: run,
  }, context);
  const r = writes.find((w) => w.spec === "repoStatus");
  assertEquals(
    (r?.data.repo as { repositoryName: string }).repositoryName,
    "c055df60",
  );
});

// --- addRepo (F5 idempotency + 409 re-GET) ----------------------------------

Deno.test("addRepo: idempotent no-op on normalized key (no POST)", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run, calls } = scriptedHttp([
    {
      match: "/repositories",
      method: "GET",
      result: { body: JSON.stringify([repoA()]) },
    },
  ]);
  await callExec(model.methods.addRepo.execute, {
    alias: "demo-1",
    // same key, different comment -> normalized-equal -> no-op
    sshPublicKey:
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEKEYAAA different@comment",
    storageSizeGb: 100,
    alert: 129600,
    appendOnlyMode: true,
    comment: "",
    _http: run,
  }, context);
  const slot = writes.find((w) => w.spec === "slot");
  assertEquals(slot?.data.changed, false);
  assertEquals(slot?.data.repositoryName, "c055df60");
  assertEquals(calls.some((c) => c.method === "POST"), false);
  assertEquals(writes.find((w) => w.spec === "attempt")?.data.success, true);
});

Deno.test("addRepo: creates when key absent (POST then re-GET)", async () => {
  const { context, writes } = fakeContext(baseCfg);
  let getCount = 0;
  const calls: HttpRequest[] = [];
  const run: HttpRunner = (req) => {
    calls.push(req);
    if (req.method === "GET") {
      getCount++;
      const body = getCount === 1 ? [repoOther()] : [repoOther(), repoA()];
      return Promise.resolve({ status: 200, body: JSON.stringify(body) });
    }
    return Promise.resolve({ status: 201, body: "{}" }); // POST create
  };
  await callExec(model.methods.addRepo.execute, {
    alias: "demo-1",
    sshPublicKey: KEY_A,
    storageSizeGb: 100,
    alert: 129600,
    appendOnlyMode: true,
    comment: "",
    _http: run,
  }, context);
  const slot = writes.find((w) => w.spec === "slot");
  assertEquals(slot?.data.changed, true);
  assertEquals(slot?.data.repositoryName, "c055df60");
  assertEquals(calls.some((c) => c.method === "POST"), true);
  // Regression: the POST body must carry the quota as `storageSize` (GB), the
  // field BorgWarehouse's API expects. An earlier `size:` was dropped by the API
  // -> HTTP 400 "Storage Size must be a positive integer".
  const post = calls.find((c) => c.method === "POST");
  const postBody = JSON.parse(post!.body ?? "{}");
  assertEquals(postBody.storageSize, 100);
  assertEquals(postBody.size, undefined);
});

Deno.test("addRepo: 409 duplicate-key backstop re-GETs the existing repo", async () => {
  const { context, writes } = fakeContext(baseCfg);
  let getCount = 0;
  const run: HttpRunner = (req) => {
    if (req.method === "GET") {
      getCount++;
      const body = getCount === 1 ? [repoOther()] : [repoOther(), repoA()];
      return Promise.resolve({ status: 200, body: JSON.stringify(body) });
    }
    return Promise.resolve({ status: 409, body: "duplicate key" });
  };
  await callExec(model.methods.addRepo.execute, {
    alias: "demo-1",
    sshPublicKey: KEY_A,
    storageSizeGb: 100,
    alert: 129600,
    appendOnlyMode: true,
    comment: "",
    _http: run,
  }, context);
  const slot = writes.find((w) => w.spec === "slot");
  assertEquals(slot?.data.repositoryName, "c055df60");
  assertEquals(writes.find((w) => w.spec === "attempt")?.data.success, true);
});

// --- authorizeKey (F6 rekey gate) -------------------------------------------

Deno.test("authorizeKey: first-time set on an empty key (no confirm needed)", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run, calls } = scriptedHttp([
    { match: "/compact", result: { status: 200 } },
    {
      match: "/repositories",
      method: "GET",
      result: { body: JSON.stringify([repoA({ sshPublicKey: "" })]) },
    },
    {
      match: "/repositories",
      method: "PATCH",
      result: { status: 200, body: "{}" },
    },
  ]);
  await callExec(model.methods.authorizeKey.execute, {
    slug: "c055df60",
    sshPublicKey: KEY_A,
    appendOnly: true,
    confirm: false,
    _http: run,
  }, context);
  assertEquals(writes.find((w) => w.spec === "slot")?.data.changed, true);
  assertEquals(calls.some((c) => c.method === "PATCH"), true);
});

Deno.test("authorizeKey: no-op when key + mode already match", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run, calls } = scriptedHttp([
    {
      match: "/repositories",
      method: "GET",
      result: { body: JSON.stringify([repoA()]) },
    },
  ]);
  await callExec(model.methods.authorizeKey.execute, {
    slug: "c055df60",
    sshPublicKey: KEY_A,
    appendOnly: true,
    confirm: false,
    _http: run,
  }, context);
  assertEquals(writes.find((w) => w.spec === "slot")?.data.changed, false);
  assertEquals(calls.some((c) => c.method === "PATCH"), false);
});

Deno.test("authorizeKey: REFUSES a rekey without confirm (F6)", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run, calls } = scriptedHttp([
    {
      match: "/repositories",
      method: "GET",
      result: { body: JSON.stringify([repoA({ sshPublicKey: KEY_A })]) },
    },
    { match: "/repositories", method: "PATCH", result: { status: 200 } },
  ]);
  await assertRejects(
    () =>
      callExec(model.methods.authorizeKey.execute, {
        slug: "c055df60",
        sshPublicKey: KEY_B, // different key -> rekey
        appendOnly: true,
        confirm: false,
        _http: run,
      }, context),
    Error,
    "REKEY",
  );
  assertEquals(writes.find((w) => w.spec === "attempt")?.data.success, false);
  assertEquals(calls.some((c) => c.method === "PATCH"), false);
});

Deno.test("authorizeKey: a rekey WITH confirm proceeds", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run, calls } = scriptedHttp([
    {
      match: "/repositories",
      method: "GET",
      result: { body: JSON.stringify([repoA({ sshPublicKey: KEY_A })]) },
    },
    {
      match: "/repositories",
      method: "PATCH",
      result: { status: 200, body: "{}" },
    },
  ]);
  await callExec(model.methods.authorizeKey.execute, {
    slug: "c055df60",
    sshPublicKey: KEY_B,
    appendOnly: true,
    confirm: true,
    _http: run,
  }, context);
  assertEquals(writes.find((w) => w.spec === "slot")?.data.changed, true);
  assertEquals(calls.some((c) => c.method === "PATCH"), true);
});

// --- setAlert ---------------------------------------------------------------

Deno.test("setAlert: changes then no-ops", async () => {
  // change
  {
    const { context, writes } = fakeContext(baseCfg);
    const { run, calls } = scriptedHttp([
      {
        match: "/repositories",
        method: "GET",
        result: { body: JSON.stringify([repoA({ alert: 129600 })]) },
      },
      {
        match: "/repositories",
        method: "PATCH",
        result: { status: 200, body: "{}" },
      },
    ]);
    await callExec(model.methods.setAlert.execute, {
      slug: "c055df60",
      alertSeconds: 604800,
      _http: run,
    }, context);
    assertEquals(writes.find((w) => w.spec === "slot")?.data.changed, true);
    assertEquals(writes.find((w) => w.spec === "slot")?.data.alert, 604800);
    assertEquals(calls.some((c) => c.method === "PATCH"), true);
  }
  // no-op
  {
    const { context, writes } = fakeContext(baseCfg);
    const { run, calls } = scriptedHttp([
      {
        match: "/repositories",
        method: "GET",
        result: { body: JSON.stringify([repoA({ alert: 129600 })]) },
      },
    ]);
    await callExec(model.methods.setAlert.execute, {
      slug: "c055df60",
      alertSeconds: 129600,
      _http: run,
    }, context);
    assertEquals(writes.find((w) => w.spec === "slot")?.data.changed, false);
    assertEquals(calls.some((c) => c.method === "PATCH"), false);
  }
});

// --- compact (F7 409 benign) ------------------------------------------------

Deno.test("compactRepo: ok then 409-benign-skipped", async () => {
  // ok
  {
    const { context, writes } = fakeContext(baseCfg);
    const { run } = scriptedHttp([
      {
        match: "/compact",
        method: "POST",
        result: { status: 200, body: "ok" },
      },
      {
        match: "/repositories",
        method: "GET",
        result: { body: JSON.stringify([repoA()]) },
      },
    ]);
    await callExec(model.methods.compactRepo.execute, {
      slug: "c055df60",
      _http: run,
    }, context);
    const op = writes.find((w) => w.spec === "op");
    assertEquals(op?.data.skipped, false);
    assertEquals(op?.data.compactStatus, "ok");
  }
  // 409 benign
  {
    const { context, writes } = fakeContext(baseCfg);
    const { run } = scriptedHttp([
      {
        match: "/compact",
        method: "POST",
        result: { status: 409, body: "already running" },
      },
      {
        match: "/repositories",
        method: "GET",
        result: { body: JSON.stringify([repoA()]) },
      },
    ]);
    await callExec(model.methods.compactRepo.execute, {
      slug: "c055df60",
      _http: run,
    }, context);
    assertEquals(writes.find((w) => w.spec === "op")?.data.skipped, true);
    assertEquals(writes.find((w) => w.spec === "attempt")?.data.success, true);
  }
});

// --- triggerStatusCron (CRONJOB_KEY, F7) ------------------------------------

Deno.test("triggerStatusCron: uses CRONJOB_KEY bearer, 409 benign", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run, calls } = scriptedHttp([
    {
      match: "/cron/status",
      method: "POST",
      result: { status: 409, body: "running" },
    },
  ]);
  await callExec(model.methods.triggerStatusCron.execute, {
    alsoStorage: false,
    _http: run,
  }, context);
  // the cron bearer, NOT the api token.
  assertEquals(calls[0].headers["Authorization"], `Bearer ${CRON_KEY}`);
  assertEquals(writes.find((w) => w.spec === "op")?.data.skipped, true);
  assertEquals(writes.find((w) => w.spec === "attempt")?.data.success, true);
});

Deno.test("triggerStatusCron: requires cronjobKey", async () => {
  const { context } = fakeContext({ ...baseCfg, cronjobKey: undefined });
  const { run } = scriptedHttp([]);
  await assertRejects(
    () =>
      callExec(model.methods.triggerStatusCron.execute, {
        alsoStorage: false,
        _http: run,
      }, context),
    Error,
    "cronjobKey",
  );
});

// --- breakLock (F8 confirm-gated) -------------------------------------------

Deno.test("breakLock: REFUSES without confirm", async () => {
  const { context } = fakeContext(baseCfg);
  const { run } = scriptedHttp([]);
  await assertRejects(
    () =>
      callExec(model.methods.breakLock.execute, {
        slug: "c055df60",
        confirm: false,
        _http: run,
      }, context),
    Error,
    "confirm:true",
  );
});

Deno.test("breakLock: proceeds with confirm", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run, calls } = scriptedHttp([
    {
      match: "/break-lock",
      method: "POST",
      result: { status: 200, body: "ok" },
    },
    {
      match: "/repositories",
      method: "GET",
      result: { body: JSON.stringify([repoA()]) },
    },
  ]);
  await callExec(model.methods.breakLock.execute, {
    slug: "c055df60",
    confirm: true,
    _http: run,
  }, context);
  assertEquals(writes.find((w) => w.spec === "op")?.data.op, "breakLock");
  assertEquals(calls.some((c) => c.url.includes("/break-lock")), true);
});

// --- pruneRepo (F1/F2/F4/F8) ------------------------------------------------

Deno.test("pruneRepo: dry-run reports would-delete, no secret leaks (F2)", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const http = scriptedHttp([
    {
      match: "/repositories",
      method: "GET",
      result: { body: JSON.stringify([repoA()]) },
    },
  ]);
  const ssh = scriptedSsh([
    {
      match: "borg",
      result: { stdout: "Would prune:  a\nWould prune:  b\n", code: 0 },
    },
  ]);
  await callExec(model.methods.pruneRepo.execute, {
    slug: "c055df60",
    expectedRepositoryName: "c055df60",
    passphrase: PP,
    keep: { keepDaily: 7 },
    dryRun: true,
    confirm: false,
    lockWaitSeconds: 1800,
    maxDelete: 10,
    allowLargeDelete: false,
    compactAfter: true,
    _run: ssh.run,
    _http: http.run,
  }, context);
  const op = writes.find((w) => w.spec === "op");
  assertEquals(op?.data.deletedCount, 2);
  assertEquals(op?.data.dryRun, true);
  assertEquals(writes.find((w) => w.spec === "attempt")?.data.success, true);
  // F2: passphrase never on a podman/borg argv line in any ssh script.
  for (const script of ssh.calls) {
    const podman = script.split("\n").find((l) => l.includes("podman exec"));
    if (podman) assertNotMatch(podman, new RegExp(PP));
  }
  // passphrase + api token never persisted into any resource.
  const dump = JSON.stringify(writes);
  assertNotMatch(dump, new RegExp(PP));
  assertNotMatch(dump, new RegExp(API_TOKEN));
  // passphrase never appears in any HTTP request.
  assertEquals(http.calls.some((c) => JSON.stringify(c).includes(PP)), false);
});

Deno.test("pruneRepo: REFUSES expectedRepositoryName mismatch (F1)", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const http = scriptedHttp([
    {
      match: "/repositories",
      method: "GET",
      result: { body: JSON.stringify([repoA()]) },
    },
  ]);
  const ssh = scriptedSsh([{ match: "borg", result: { stdout: "", code: 0 } }]);
  await assertRejects(
    () =>
      callExec(model.methods.pruneRepo.execute, {
        slug: "c055df60",
        expectedRepositoryName: "deadbeef", // resolved will be c055df60
        passphrase: PP,
        keep: { keepDaily: 7 },
        dryRun: true,
        confirm: false,
        lockWaitSeconds: 1800,
        maxDelete: 10,
        allowLargeDelete: false,
        compactAfter: true,
        _run: ssh.run,
        _http: http.run,
      }, context),
    Error,
    "INTERLOCK MISMATCH",
  );
  assertEquals(writes.find((w) => w.spec === "attempt")?.data.success, false);
  assertEquals(ssh.calls.length, 0); // never reached borg
});

Deno.test("pruneRepo: REFUSES a non-dry-run without confirm (F4)", async () => {
  const { context } = fakeContext(baseCfg);
  const http = scriptedHttp([{
    match: "/repositories",
    result: { body: JSON.stringify([repoA()]) },
  }]);
  const ssh = scriptedSsh([]);
  await assertRejects(
    () =>
      callExec(model.methods.pruneRepo.execute, {
        slug: "c055df60",
        expectedRepositoryName: "c055df60",
        passphrase: PP,
        keep: { keepDaily: 7 },
        dryRun: false,
        confirm: false,
        lockWaitSeconds: 1800,
        maxDelete: 10,
        allowLargeDelete: false,
        compactAfter: true,
        _run: ssh.run,
        _http: http.run,
      }, context),
    Error,
    "confirm:true",
  );
  assertEquals(ssh.calls.length, 0);
});

Deno.test("pruneRepo: REFUSES an empty keep policy (F4)", async () => {
  const { context } = fakeContext(baseCfg);
  const http = scriptedHttp([{
    match: "/repositories",
    result: { body: JSON.stringify([repoA()]) },
  }]);
  const ssh = scriptedSsh([]);
  await assertRejects(
    () =>
      callExec(model.methods.pruneRepo.execute, {
        slug: "c055df60",
        expectedRepositoryName: "c055df60",
        passphrase: PP,
        keep: {},
        dryRun: true,
        confirm: false,
        lockWaitSeconds: 1800,
        maxDelete: 10,
        allowLargeDelete: false,
        compactAfter: true,
        _run: ssh.run,
        _http: http.run,
      }, context),
    Error,
    "keep rule",
  );
});

Deno.test("pruneRepo: REFUSES over-threshold delete without override (F4)", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const http = scriptedHttp([
    {
      match: "/repositories",
      method: "GET",
      result: { body: JSON.stringify([repoA()]) },
    },
  ]);
  // the committing preflight dry-run would delete 3 archives.
  const ssh = scriptedSsh([
    {
      match: "borg",
      result: {
        stdout: "Would prune:  a\nWould prune:  b\nWould prune:  c\n",
        code: 0,
      },
    },
  ]);
  await assertRejects(
    () =>
      callExec(model.methods.pruneRepo.execute, {
        slug: "c055df60",
        expectedRepositoryName: "c055df60",
        passphrase: PP,
        keep: { keepDaily: 1 },
        dryRun: false,
        confirm: true,
        lockWaitSeconds: 1800,
        maxDelete: 1,
        allowLargeDelete: false,
        compactAfter: true,
        _run: ssh.run,
        _http: http.run,
      }, context),
    Error,
    "DELETE-COUNT FLOOR",
  );
  assertEquals(writes.find((w) => w.spec === "attempt")?.data.success, false);
  // only the preflight dry-run ran -- every ssh script carried --dry-run.
  for (const s of ssh.calls) assertMatch(s, /--dry-run/);
});

Deno.test("pruneRepo: committing run deletes then compacts (F8 ok)", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const http = scriptedHttp([
    { match: "/compact", method: "POST", result: { status: 200, body: "ok" } },
    {
      match: "/repositories",
      method: "GET",
      result: { body: JSON.stringify([repoA()]) },
    },
  ]);
  // preflight dry-run -> 2 would-prune (under maxDelete); real prune -> 2 pruned.
  let calln = 0;
  const ssh: { run: TargetRunner; calls: string[] } = {
    calls: [],
    run: (_c, script) => {
      ssh.calls.push(script);
      calln++;
      if (script.includes("--dry-run")) {
        return Promise.resolve({
          stdout: "Would prune:  a\nWould prune:  b\n",
          stderr: "",
          code: 0,
        });
      }
      return Promise.resolve({
        stdout: "Pruning archive: a\nPruning archive: b\n",
        stderr: "",
        code: 0,
      });
    },
  };
  await callExec(model.methods.pruneRepo.execute, {
    slug: "c055df60",
    expectedRepositoryName: "c055df60",
    passphrase: PP,
    keep: { keepDaily: 7 },
    dryRun: false,
    confirm: true,
    lockWaitSeconds: 1800,
    maxDelete: 10,
    allowLargeDelete: false,
    compactAfter: true,
    _run: ssh.run,
    _http: http.run,
  }, context);
  const op = writes.find((w) => w.spec === "op");
  assertEquals(op?.data.deletedCount, 2);
  assertEquals(op?.data.compactStatus, "ok");
  assertEquals(writes.find((w) => w.spec === "attempt")?.data.success, true);
  assertEquals(calln, 2); // preflight + real
});

Deno.test("pruneRepo: compact failure after a committed prune is NON-FATAL but recorded (F8)", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const http = scriptedHttp([
    {
      match: "/compact",
      method: "POST",
      result: { status: 500, body: "boom" },
    },
    {
      match: "/repositories",
      method: "GET",
      result: { body: JSON.stringify([repoA()]) },
    },
  ]);
  const ssh: { run: TargetRunner; calls: string[] } = {
    calls: [],
    run: (_c, script) => {
      ssh.calls.push(script);
      if (script.includes("--dry-run")) {
        return Promise.resolve({
          stdout: "Would prune:  a\n",
          stderr: "",
          code: 0,
        });
      }
      return Promise.resolve({
        stdout: "Pruning archive: a\n",
        stderr: "",
        code: 0,
      });
    },
  };
  await callExec(model.methods.pruneRepo.execute, {
    slug: "c055df60",
    expectedRepositoryName: "c055df60",
    passphrase: PP,
    keep: { keepDaily: 7 },
    dryRun: false,
    confirm: true,
    lockWaitSeconds: 1800,
    maxDelete: 10,
    allowLargeDelete: false,
    compactAfter: true,
    _run: ssh.run,
    _http: http.run,
  }, context);
  const op = writes.find((w) => w.spec === "op");
  assertEquals(op?.data.compactStatus, "pending-retry");
  assertMatch((op?.data.notes as string[]).join(" "), /compact FAILED/);
  // the prune itself still succeeded (non-fatal compact).
  assertEquals(writes.find((w) => w.spec === "attempt")?.data.success, true);
});

// borg writes its --list output ("Would prune:" / "Pruning archive:") to
// STDERR, not STDOUT. These regressions pin the count to STDOUT+STDERR so the
// F4 delete-count floor cannot be silently bypassed by a 0 count.
Deno.test("pruneRepo: F4 floor FIRES when would-prune is on STDERR", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const http = scriptedHttp([
    {
      match: "/repositories",
      method: "GET",
      result: { body: JSON.stringify([repoA()]) },
    },
  ]);
  // 3 would-prune lines, but delivered on STDERR with an empty STDOUT. Before
  // the fix countWouldPrune(stdout) == 0 and the floor never fired.
  const ssh = scriptedSsh([
    {
      match: "borg",
      result: {
        stdout: "",
        stderr: "Would prune:  a\nWould prune:  b\nWould prune:  c\n",
        code: 0,
      },
    },
  ]);
  await assertRejects(
    () =>
      callExec(model.methods.pruneRepo.execute, {
        slug: "c055df60",
        expectedRepositoryName: "c055df60",
        passphrase: PP,
        keep: { keepDaily: 1 },
        dryRun: false,
        confirm: true,
        lockWaitSeconds: 1800,
        maxDelete: 1,
        allowLargeDelete: false,
        compactAfter: true,
        _run: ssh.run,
        _http: http.run,
      }, context),
    Error,
    "DELETE-COUNT FLOOR",
  );
  assertEquals(writes.find((w) => w.spec === "attempt")?.data.success, false);
  for (const s of ssh.calls) assertMatch(s, /--dry-run/);
});

Deno.test("pruneRepo: deletedCount counts STDERR Pruning-archive lines", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const http = scriptedHttp([
    { match: "/compact", method: "POST", result: { status: 200, body: "ok" } },
    {
      match: "/repositories",
      method: "GET",
      result: { body: JSON.stringify([repoA()]) },
    },
  ]);
  // Both the preflight count and the committing count must read STDERR.
  const ssh: { run: TargetRunner; calls: string[] } = {
    calls: [],
    run: (_c, script) => {
      ssh.calls.push(script);
      if (script.includes("--dry-run")) {
        return Promise.resolve({
          stdout: "",
          stderr: "Would prune:  a\nWould prune:  b\n",
          code: 0,
        });
      }
      return Promise.resolve({
        stdout: "",
        stderr: "Pruning archive: a\nPruning archive: b\n",
        code: 0,
      });
    },
  };
  await callExec(model.methods.pruneRepo.execute, {
    slug: "c055df60",
    expectedRepositoryName: "c055df60",
    passphrase: PP,
    keep: { keepDaily: 7 },
    dryRun: false,
    confirm: true,
    lockWaitSeconds: 1800,
    maxDelete: 10,
    allowLargeDelete: false,
    compactAfter: true,
    _run: ssh.run,
    _http: http.run,
  }, context);
  const op = writes.find((w) => w.spec === "op");
  assertEquals(op?.data.deletedCount, 2);
  assertEquals(writes.find((w) => w.spec === "attempt")?.data.success, true);
});

Deno.test("pruneRepo: borg exit 1 is a non-fatal WARNING, not a failure", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const http = scriptedHttp([
    { match: "/compact", method: "POST", result: { status: 200, body: "ok" } },
    {
      match: "/repositories",
      method: "GET",
      result: { body: JSON.stringify([repoA()]) },
    },
  ]);
  const ssh: { run: TargetRunner; calls: string[] } = {
    calls: [],
    run: (_c, script) => {
      ssh.calls.push(script);
      if (script.includes("--dry-run")) {
        return Promise.resolve({
          stdout: "",
          stderr: "Would prune:  a\n",
          code: 0,
        });
      }
      // borg emits exit 1 on a non-fatal warning (e.g. a lingering lock note).
      return Promise.resolve({
        stdout: "",
        stderr: "Pruning archive: a\nwarning: something non-fatal\n",
        code: 1,
      });
    },
  };
  await callExec(model.methods.pruneRepo.execute, {
    slug: "c055df60",
    expectedRepositoryName: "c055df60",
    passphrase: PP,
    keep: { keepDaily: 7 },
    dryRun: false,
    confirm: true,
    lockWaitSeconds: 1800,
    maxDelete: 10,
    allowLargeDelete: false,
    compactAfter: true,
    _run: ssh.run,
    _http: http.run,
  }, context);
  const op = writes.find((w) => w.spec === "op");
  // non-fatal: the attempt succeeds, the warning is recorded, count is kept.
  assertEquals(writes.find((w) => w.spec === "attempt")?.data.success, true);
  assertEquals(op?.data.deletedCount, 1);
  assertMatch((op?.data.notes as string[]).join(" "), /WARNING, non-fatal/);
  assertEquals(op?.data.compactStatus, "ok");
});

// --- write-kernel audits failure too ----------------------------------------

Deno.test("write-kernel: a failed REST mutation records a failed attempt + throws", async () => {
  const { context, writes } = fakeContext(baseCfg);
  const { run } = scriptedHttp([
    {
      match: "/repositories",
      method: "GET",
      result: { body: JSON.stringify([repoA({ alert: 1 })]) },
    },
    {
      match: "/repositories",
      method: "PATCH",
      result: { status: 500, body: "server error" },
    },
  ]);
  await assertRejects(
    () =>
      callExec(model.methods.setAlert.execute, {
        slug: "c055df60",
        alertSeconds: 99,
        _http: run,
      }, context),
    Error,
    "setAlert failed",
  );
  const att = writes.find((w) => w.spec === "attempt");
  assertEquals(att?.data.success, false);
  assertEquals(att?.data.exitCode, 500);
  assertEquals(writes.some((w) => w.spec === "slot"), false); // no slot on failure
});

// --- schema rejection (adversarial) -----------------------------------------

Deno.test("schema rejects injection in container/path/user fields", () => {
  assertThrows(() =>
    GARGS.parse({ apiBaseUrl: "http://h:3000", containerName: "bw; reboot" })
  );
  assertThrows(() =>
    GARGS.parse({ apiBaseUrl: "http://h:3000", borgBaseDir: "/home/$(reboot)" })
  );
  assertThrows(() =>
    GARGS.parse({ apiBaseUrl: "http://h:3000", repoBasePath: "relative/path" })
  );
  assertThrows(() =>
    GARGS.parse({ apiBaseUrl: "http://h:3000", sshUser: "root; rm -rf /" })
  );
  assertThrows(() => GARGS.parse({ apiBaseUrl: "not-a-url" }));
});

Deno.test("schema accepts legitimate values + applies defaults", () => {
  const ok = GARGS.parse({
    apiBaseUrl: "http://192.0.2.10:3000",
  }) as GlobalArgs;
  assertEquals(ok.sshUser, "rocky");
  assertEquals(ok.containerName, "borgwarehouse");
  assertEquals(ok.sudo, true);
  assertEquals(ok.repoBasePath, "/home/borgwarehouse/repos");
});

Deno.test("pruneRepo args: expectedRepositoryName must be 8-hex", () => {
  // deno-lint-ignore no-explicit-any
  const PARGS = (model.methods.pruneRepo as any).arguments as {
    parse: (o: unknown) => unknown;
  };
  assertThrows(() =>
    PARGS.parse({
      expectedRepositoryName: "NOThex!!",
      passphrase: "x",
      keep: { keepDaily: 1 },
    })
  );
  const ok = PARGS.parse({
    expectedRepositoryName: "c055df60",
    passphrase: "x",
    keep: { keepDaily: 1 },
  });
  assertEquals((ok as { dryRun: boolean }).dryRun, true); // dry by default
});

// --- model shape ------------------------------------------------------------

Deno.test("model shape: type, verbs, check coverage", () => {
  assertEquals(model.type, "@shrug/borgwarehouse");
  for (
    const v of [
      "listRepos",
      "repoStatus",
      "addRepo",
      "authorizeKey",
      "setAlert",
      "compactRepo",
      "triggerStatusCron",
      "breakLock",
      "pruneRepo",
    ]
  ) {
    // deno-lint-ignore no-explicit-any
    assertEquals(typeof (model.methods as any)[v]?.execute, "function");
  }
  assertEquals(model.checks.apiReachable.appliesTo.includes("addRepo"), true);
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
