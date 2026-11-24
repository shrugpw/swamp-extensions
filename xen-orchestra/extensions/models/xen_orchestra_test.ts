/**
 * Unit tests for the `@shrug/xen-orchestra` model.
 *
 * Two layers:
 *  - Pure value-shaping helpers (string/number coercion, UUID extraction from
 *    strings/objects/hrefs, VM normalization of the nested CPUs/memory shapes,
 *    collection-item normalization, and create-body assembly).
 *  - Method paths driven through a mocked `fetch` seam ({@link FetchLike}) so
 *    no network is hit — asserting the `authenticationToken` cookie is sent
 *    only with a token, that POST bodies are JSON-encoded, that HTTP errors
 *    raise, that create resolves the UUID and snapshots the VM, that stop maps
 *    force→hard_shutdown, that destroy verifies-then-deletes, and that
 *    discovery fans a collection into an inventory snapshot.
 *
 * Run with: `deno test -A extensions/models/xen_orchestra_test.ts`
 *
 * @module
 */
import { assertEquals, assertRejects, assertThrows } from "jsr:@std/assert@1";
import {
  buildCreateBody,
  deviceConfigMatches,
  downloadToFile,
  enc,
  extractTaskRef,
  extractUuid,
  type FetchLike,
  type FetchResponse,
  gibToBytes,
  guardAuthToken,
  importVdiToSr,
  inferImageFormat,
  makeFetch,
  makeStreamFetch,
  model,
  normalizeBackupRepository,
  normalizeNetwork,
  normalizeRef,
  normalizeSchedule,
  normalizeServer,
  normalizeSr,
  normalizeVm,
  numOrNull,
  pollTask,
  rawObject,
  redactRepoUrl,
  redactUrl,
  type RpcConnect,
  type RpcFrame,
  type RpcSocket,
  rpcWsUrl,
  type StreamFetchLike,
  type StreamResponse,
  strOrNull,
  XoHttpError,
  xoJsonRpc,
  xoRequest,
} from "./xen_orchestra.ts";

/** Connection config type, derived from the seam so no `any` is needed. */
type Cfg = Parameters<typeof xoRequest>[0];

/** Config with a token (cookie expected on the wire). */
const CFG = {
  baseUrl: "https://xo.example:443",
  authToken: "TOK",
  poolId: "pool-1",
  requestTimeoutMs: 120000,
} as unknown as Cfg;

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

Deno.test("strOrNull() coerces or nulls", () => {
  assertEquals(strOrNull("x"), "x");
  assertEquals(strOrNull(7), "7");
  assertEquals(strOrNull(undefined), null);
  assertEquals(strOrNull(null), null);
});

Deno.test("numOrNull() coerces finite numbers only", () => {
  assertEquals(numOrNull(4), 4);
  assertEquals(numOrNull("8"), 8);
  assertEquals(numOrNull("nope"), null);
  assertEquals(numOrNull(undefined), null);
});

Deno.test("extractUuid() handles strings, hrefs, and objects", () => {
  assertEquals(extractUuid("abc-123"), "abc-123");
  assertEquals(extractUuid("/rest/v0/tasks/task-9/"), "task-9");
  assertEquals(extractUuid({ uuid: "u1" }), "u1");
  assertEquals(extractUuid({ id: "i1" }), "i1");
  assertEquals(extractUuid(42), "");
});

Deno.test("normalizeVm() lifts nested CPUs/memory to scalars", () => {
  const vm = normalizeVm({
    uuid: "vm-1",
    name_label: "orchestrator",
    power_state: "Running",
    mainIpAddress: "192.0.2.5",
    CPUs: { number: 2 },
    memory: { size: 4294967296 },
    $pool: "pool-1",
  });
  assertEquals(vm.uuid, "vm-1");
  assertEquals(vm.name_label, "orchestrator");
  assertEquals(vm.power_state, "Running");
  assertEquals(vm.mainIpAddress, "192.0.2.5");
  assertEquals(vm.cpus, 2);
  assertEquals(vm.memory, 4294967296);
  assertEquals(vm.poolId, "pool-1");
  assertEquals((vm.raw as { name_label: string }).name_label, "orchestrator");
  assertEquals(typeof vm.retrievedAt, "string");
});

Deno.test("normalizeVm() tolerates a missing record (id-only)", () => {
  const vm = normalizeVm({ uuid: "vm-x" });
  assertEquals(vm.uuid, "vm-x");
  assertEquals(vm.name_label, null);
  assertEquals(vm.cpus, null);
  assertEquals(typeof vm.retrievedAt, "string");
});

Deno.test("normalizeRef() flattens objects and href strings", () => {
  assertEquals(normalizeRef({ uuid: "t1", name_label: "Rocky 9" }), {
    uuid: "t1",
    name_label: "Rocky 9",
    raw: { uuid: "t1", name_label: "Rocky 9" },
  });
  assertEquals(normalizeRef("/rest/v0/vm-templates/t2"), {
    uuid: "t2",
    name_label: null,
    raw: { href: "/rest/v0/vm-templates/t2" },
  });
});

Deno.test("buildCreateBody() keeps known fields, drops unset ones", () => {
  const body = buildCreateBody({
    name_label: "vm",
    template: "tmpl-1",
    cpus: 2,
    memory: 4294967296,
    boot: true,
    cloud_config: "#cloud-config",
    bogus: "dropped",
    poolId: "not-a-body-field",
  });
  assertEquals(body, {
    name_label: "vm",
    template: "tmpl-1",
    cpus: 2,
    memory: 4294967296,
    boot: true,
    cloud_config: "#cloud-config",
  });
});

// ---------------------------------------------------------------------------
// Mocked fetch seam
// ---------------------------------------------------------------------------

/** A recorded fetch call. */
interface FetchRec {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
}

/** A route: match a call and return a canned response. */
interface Route {
  match: (url: string, method: string) => boolean;
  status?: number;
  body?: unknown;
}

/** Build a routing fake {@link FetchLike}, recording every call. */
function router(routes: Route[]): { f: FetchLike; calls: FetchRec[] } {
  const calls: FetchRec[] = [];
  const f: FetchLike = (url, init) => {
    const method = init?.method ?? "GET";
    calls.push({ url, method, headers: init?.headers, body: init?.body });
    const r = routes.find((rt) => rt.match(url, method));
    const status = r?.status ?? (r ? 200 : 599);
    const text = r === undefined
      ? `no route for ${method} ${url}`
      : r.body === undefined
      ? ""
      : typeof r.body === "string"
      ? r.body
      : JSON.stringify(r.body);
    const resp: FetchResponse = {
      ok: status >= 200 && status < 300,
      status,
      statusText: "",
      text: () => Promise.resolve(text),
    };
    return Promise.resolve(resp);
  };
  return { f, calls };
}

/** Single-response fake (most helper-level tests). */
function once(
  body: unknown,
  opts: { status?: number } = {},
): { f: FetchLike; calls: FetchRec[] } {
  return router([{ match: () => true, status: opts.status ?? 200, body }]);
}

Deno.test("xoRequest: sends the auth cookie only when a token is set", async () => {
  const withTok = once({ ok: 1 });
  await xoRequest(CFG, "GET", "vms/vm-1", {}, withTok.f);
  assertEquals(
    withTok.calls[0].headers?.["Cookie"],
    "authenticationToken=TOK",
  );

  const noTok = once({ ok: 1 });
  const anon = { ...(CFG as object), authToken: undefined } as unknown as Cfg;
  await xoRequest(anon, "GET", "vms/vm-1", {}, noTok.f);
  assertEquals("Cookie" in (noTok.calls[0].headers ?? {}), false);
});

Deno.test("xoRequest: JSON-encodes a body and sets content-type", async () => {
  const { f, calls } = once({ ok: 1 });
  await xoRequest(
    CFG,
    "POST",
    "vms/vm-1/actions/snapshot",
    { body: { name_label: "snap" } },
    f,
  );
  assertEquals(calls[0].method, "POST");
  assertEquals(calls[0].headers?.["Content-Type"], "application/json");
  assertEquals(calls[0].body, JSON.stringify({ name_label: "snap" }));
});

Deno.test("xoRequest: appends query params and returns null on empty body", async () => {
  const { f, calls } = router([{ match: () => true, status: 204, body: "" }]);
  const out = await xoRequest(
    CFG,
    "GET",
    "vm-templates",
    { query: [["fields", "uuid,name_label"]] },
    f,
  );
  assertEquals(out, null);
  assertEquals(calls[0].url.includes("fields=uuid%2Cname_label"), true);
});

Deno.test("xoRequest: raises on a non-2xx status", async () => {
  const { f } = once({ error: "nope" }, { status: 401 });
  await assertRejects(
    () => xoRequest(CFG, "GET", "vms/vm-1", {}, f),
    Error,
    "HTTP 401",
  );
});

Deno.test("pollTask: returns result on success, throws otherwise", async () => {
  const ok = once({ status: "success", result: "vm-new" });
  assertEquals(await pollTask(CFG, "/rest/v0/tasks/t1", ok.f), "vm-new");
  // Must wait with the BOOLEAN form: stable XOA rejects `?wait=result` (HTTP
  // 422 "invalid boolean value") — regression guard for that live failure.
  assertEquals(ok.calls[0].url.includes("wait=true"), true);
  assertEquals(ok.calls[0].url.includes("wait=result"), false);

  const bad = once({ status: "failure", result: "boom" });
  await assertRejects(
    () => pollTask(CFG, "t2", bad.f),
    Error,
    "failure",
  );
});

// ---------------------------------------------------------------------------
// Method paths (injected fetch)
// ---------------------------------------------------------------------------

/** A recorded `writeResource` call. */
interface WriteCall {
  spec: string;
  name: string;
  data: Record<string, unknown>;
}

/**
 * Cast a loose argument literal to a method's inferred execute-arg type. The
 * single unavoidable `any` (method arg unions carry a private `_fetch`) is
 * localized here so the test bodies stay lint-clean.
 */
function asArgs<T>(o: Record<string, unknown>): T {
  // deno-lint-ignore no-explicit-any
  return o as any as T;
}

/** Stub ExecuteContext: no-op logger, recording writeResource, token config. */
function stubContext(cfg: Cfg = CFG) {
  const writes: WriteCall[] = [];
  const logs: Array<
    { level: string; msg: string; params?: Record<string, unknown> }
  > = [];
  const rec =
    (level: string) => (msg: string, params?: Record<string, unknown>) => {
      // Capture the structured params too: swamp's real logger interpolates
      // them into the rendered line, so a "secret stays out of logs" test must
      // see a secret passed as a param, not only one in the template string.
      logs.push({ level, msg, params });
    };
  const context = {
    globalArgs: cfg,
    logger: {
      debug: rec("debug"),
      info: rec("info"),
      warning: rec("warning"),
      error: rec("error"),
    },
    writeResource: (
      spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      writes.push({ spec, name, data });
      return Promise.resolve({ name });
    },
    // deno-lint-ignore no-explicit-any
  } as any;
  return { context, writes, logs };
}

Deno.test("create: posts create_vm (sync), resolves UUID, snapshots the VM", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "POST" && u.includes("/actions/create_vm"),
      body: "vm-new", // XO returns the new UUID as a JSON string
    },
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-new"),
      body: {
        uuid: "vm-new",
        name_label: "orchestrator",
        power_state: "Halted",
      },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.create.execute(
    asArgs({
      name_label: "orchestrator",
      template: "tmpl-1",
      cpus: 2,
      memory: 4294967296,
      boot: true,
      _fetch: f,
    }),
    context,
  );
  // create_vm carried ?sync=true and the pool from config.
  assertEquals(calls[0].url.includes("/pools/pool-1/actions/create_vm"), true);
  assertEquals(calls[0].url.includes("sync=true"), true);
  assertEquals(JSON.parse(calls[0].body ?? "{}").template, "tmpl-1");
  // recorded the vm resource from the follow-up GET.
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "vm");
  assertEquals(writes[0].name, "vm:vm-new");
  assertEquals(writes[0].data.power_state, "Halted");
});

Deno.test("create: requires a poolId", async () => {
  const { f } = once({});
  const noPool = { ...(CFG as object), poolId: "" } as unknown as Cfg;
  const { context } = stubContext(noPool);
  await assertRejects(
    () =>
      model.methods.create.execute(
        asArgs({ name_label: "x", template: "t", _fetch: f }),
        context,
      ),
    Error,
    "poolId",
  );
});

Deno.test("start: posts start then re-snapshots the VM", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "POST" && u.includes("/actions/start"),
      body: true,
    },
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-1"),
      body: { uuid: "vm-1", power_state: "Running" },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.start.execute(
    asArgs({ id: "vm-1", _fetch: f }),
    context,
  );
  assertEquals(calls[0].url.endsWith("/vms/vm-1/actions/start"), true);
  assertEquals(writes[0].data.power_state, "Running");
});

Deno.test("stop: force maps to hard_shutdown, default to clean_shutdown", async () => {
  const routes: Route[] = [
    { match: (u, m) => m === "POST" && u.includes("/actions/"), body: true },
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-1"),
      body: { uuid: "vm-1" },
    },
  ];
  const hard = router(routes);
  const ctxHard = stubContext();
  await model.methods.stop.execute(
    asArgs({ id: "vm-1", force: true, _fetch: hard.f }),
    ctxHard.context,
  );
  assertEquals(hard.calls[0].url.endsWith("/actions/hard_shutdown"), true);

  const clean = router(routes);
  const ctxClean = stubContext();
  await model.methods.stop.execute(
    asArgs({ id: "vm-1", force: false, _fetch: clean.f }),
    ctxClean.context,
  );
  assertEquals(clean.calls[0].url.endsWith("/actions/clean_shutdown"), true);
});

Deno.test("snapshot: posts the snapshot name then re-snapshots the VM", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "POST" && u.includes("/actions/snapshot"),
      body: "snap-1",
    },
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-1"),
      body: { uuid: "vm-1" },
    },
  ]);
  const { context } = stubContext();
  await model.methods.snapshot.execute(
    asArgs({ id: "vm-1", name_label: "pre-upgrade", _fetch: f }),
    context,
  );
  assertEquals(JSON.parse(calls[0].body ?? "{}").name_label, "pre-upgrade");
});

Deno.test("destroy: verifies (GET) then deletes, recording nothing", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-1"),
      body: { uuid: "vm-1" },
    },
    {
      match: (u, m) => m === "DELETE" && u.endsWith("/vms/vm-1"),
      status: 204,
      body: "",
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.destroy.execute(
    asArgs({ id: "vm-1", _fetch: f }),
    context,
  );
  assertEquals(calls.map((c) => c.method), ["GET", "DELETE"]);
  assertEquals(writes.length, 0);
  assertEquals(res.dataHandles.length, 0);
});

Deno.test("listTemplates: fans a collection into one inventory snapshot", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/vm-templates"),
      body: [
        { uuid: "t1", name_label: "Rocky 9" },
        { uuid: "t2", name_label: "Debian 12" },
      ],
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listTemplates.execute(
    asArgs({ _fetch: f }),
    context,
  );
  assertEquals(calls[0].url.includes("fields="), true);
  assertEquals(writes[0].spec, "inventory");
  assertEquals(writes[0].name, "templates");
  assertEquals(writes[0].data.count, 2);
  assertEquals(
    (writes[0].data.items as Array<{ uuid: string }>)[0].uuid,
    "t1",
  );
});

// ---------------------------------------------------------------------------
// Hardening (review follow-ups)
// ---------------------------------------------------------------------------

Deno.test("destroy: percent-encodes the id in both GET and DELETE paths", async () => {
  const { f, calls } = router([
    { match: (_u, m) => m === "GET", body: { uuid: "x" } },
    { match: (_u, m) => m === "DELETE", status: 204, body: "" },
  ]);
  const { context } = stubContext();
  // A crafted id with a slash must not traverse to a different endpoint.
  await model.methods.destroy.execute(
    asArgs({ id: "a/b", _fetch: f }),
    context,
  );
  assertEquals(calls[0].url.includes("/vms/a%2Fb"), true);
  assertEquals(calls[1].url.includes("/vms/a%2Fb"), true);
  assertEquals(calls[0].url.includes("/vms/a/b"), false);
});

Deno.test("enc() percent-encodes path-unsafe characters", () => {
  assertEquals(enc("a/b"), "a%2Fb");
  assertEquals(enc("vm-1"), "vm-1");
});

// ---------------------------------------------------------------------------
// Blank VDI provisioning (createVdi + gibToBytes)
// ---------------------------------------------------------------------------

Deno.test("gibToBytes() converts GiB to exact bytes", () => {
  assertEquals(gibToBytes(1), 1073741824);
  assertEquals(gibToBytes(1024), 1099511627776); // 1 TiB, still < 2**53
  assertEquals(gibToBytes(10), 10737418240); // XO doc example (10 GiB)
});

Deno.test("createVdi: verifies SR, POSTs /vdis in bytes, records createdVdi", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.endsWith("/srs/sr-1"),
      body: { uuid: "sr-1", SR_type: "ext", name_label: "local-ext" },
    },
    {
      match: (u, m) => m === "POST" && u.endsWith("/vdis"),
      body: { id: "vdi-new" }, // XO returns { id } + a Location header
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.createVdi.execute(
    asArgs({
      srId: "sr-1",
      sizeGiB: 20,
      nameLabel: "www-data",
      nameDescription: "var/www disk",
      _fetch: f,
    }),
    context,
  );
  // GET-verify the SR, then POST the create.
  assertEquals(calls.map((c) => c.method), ["GET", "POST"]);
  assertEquals(calls[1].url.endsWith("/vdis"), true);
  const sent = JSON.parse(calls[1].body ?? "{}");
  assertEquals(sent.srId, "sr-1");
  // virtual_size is in BYTES (not a `size` field, not GiB).
  assertEquals(sent.virtual_size, 20 * 1024 ** 3);
  assertEquals("size" in sent, false);
  assertEquals(sent.name_label, "www-data");
  assertEquals(sent.name_description, "var/www disk");
  // Records the new VDI under inventory 'createdVdi' with its uuid.
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "inventory");
  assertEquals(writes[0].name, "createdVdi");
  const item = (writes[0].data.items as Array<Record<string, unknown>>)[0];
  assertEquals(item.uuid, "vdi-new");
  assertEquals(
    (item.raw as Record<string, unknown>).sizeBytes,
    20 * 1024 ** 3,
  );
  assertEquals(res.dataHandles.length, 1);
});

Deno.test("createVdi: an ISO SR is rejected and never POSTs", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.endsWith("/srs/iso-1"),
      body: { uuid: "iso-1", SR_type: "iso" },
    },
    { match: (_u, m) => m === "POST", body: { id: "nope" } },
  ]);
  const { context, writes } = stubContext();
  await assertRejects(
    () =>
      model.methods.createVdi.execute(
        asArgs({ srId: "iso-1", sizeGiB: 1, nameLabel: "x", _fetch: f }),
        context,
      ),
    Error,
    "ISO SR",
  );
  assertEquals(calls.map((c) => c.method), ["GET"]); // no POST
  assertEquals(writes.length, 0);
});

Deno.test("createVdi: allowedSrTypes mismatch throws before the POST", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.endsWith("/srs/sr-2"),
      body: { uuid: "sr-2", SR_type: "lvm" },
    },
    { match: (_u, m) => m === "POST", body: { id: "nope" } },
  ]);
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.createVdi.execute(
        asArgs({
          srId: "sr-2",
          sizeGiB: 1,
          nameLabel: "x",
          allowedSrTypes: ["ext"],
          _fetch: f,
        }),
        context,
      ),
    Error,
    "not one of the allowed",
  );
  assertEquals(calls.map((c) => c.method), ["GET"]); // no POST
});

Deno.test("createVdi: a 404 on the SR pre-verify never POSTs", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/srs/"),
      status: 404,
      body: { error: "no such SR" },
    },
    { match: (_u, m) => m === "POST", body: { id: "nope" } },
  ]);
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.createVdi.execute(
        asArgs({ srId: "ghost", sizeGiB: 1, nameLabel: "x", _fetch: f }),
        context,
      ),
    Error,
    "HTTP 404",
  );
  assertEquals(calls.map((c) => c.method), ["GET"]); // no POST
});

Deno.test("createVdi: a create response with no uuid throws orphaned-disk", async () => {
  const { f } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/srs/"),
      body: { uuid: "sr-1", SR_type: "ext" },
    },
    { match: (_u, m) => m === "POST", body: {} }, // 2xx, but no id/uuid
  ]);
  const { context, writes } = stubContext();
  await assertRejects(
    () =>
      model.methods.createVdi.execute(
        asArgs({ srId: "sr-1", sizeGiB: 1, nameLabel: "x", _fetch: f }),
        context,
      ),
    Error,
    "orphaned",
  );
  assertEquals(writes.length, 0);
});

Deno.test("createVdi: percent-encodes the srId in the pre-verify GET path", async () => {
  const { f, calls } = router([
    { match: (_u, m) => m === "GET", body: { uuid: "x", SR_type: "ext" } },
    { match: (_u, m) => m === "POST", body: { id: "vdi-9" } },
  ]);
  const { context } = stubContext();
  await model.methods.createVdi.execute(
    asArgs({ srId: "a/b", sizeGiB: 1, nameLabel: "x", _fetch: f }),
    context,
  );
  assertEquals(calls[0].url.includes("/srs/a%2Fb"), true);
  assertEquals(calls[0].url.includes("/srs/a/b"), false);
});

Deno.test("listTemplates: raises when the response is not a list", async () => {
  const { f } = once({ error: "nope" }); // object, not an array
  const { context } = stubContext();
  await assertRejects(
    () => model.methods.listTemplates.execute(asArgs({ _fetch: f }), context),
    Error,
    "did not return a list",
  );
});

Deno.test("xoRequest: trims a plain-text body so no stray newline enters the UUID", async () => {
  const { f } = once("vm-new\n"); // XO plain-text id with a trailing newline
  const out = await xoRequest(CFG, "POST", "pools/p/actions/create_vm", {}, f);
  assertEquals(out, "vm-new");
});

Deno.test("xoRequest: rejects a token carrying CRLF/;", async () => {
  const { f } = once({});
  const bad = {
    ...(CFG as object),
    authToken: "tok\r\nX-Injected: y",
  } as unknown as Cfg;
  await assertRejects(
    () => xoRequest(bad, "GET", "vms/1", {}, f),
    Error,
    "illegal characters",
  );
});

Deno.test("normalizeVm: drops other_config/xenstore_data from persisted raw", () => {
  const vm = normalizeVm({
    uuid: "v",
    name_label: "n",
    other_config: { secret: "x" },
    xenstore_data: { k: "v" },
  });
  assertEquals("other_config" in vm.raw, false);
  assertEquals("xenstore_data" in vm.raw, false);
  assertEquals((vm.raw as { name_label: string }).name_label, "n");
});

Deno.test("buildCreateBody: passes the newly-exposed create fields", () => {
  const body = buildCreateBody({
    name_label: "vm",
    template: "t",
    name_description: "d",
    secureBoot: true,
    copyHostBiosStrings: true,
  });
  assertEquals(body.name_description, "d");
  assertEquals(body.secureBoot, true);
  assertEquals(body.copyHostBiosStrings, true);
});

Deno.test("makeFetch: trusts caCert via Deno.createHttpClient, never disables verification", async () => {
  const g = globalThis as unknown as {
    Deno: Record<string, unknown>;
    fetch: (
      u: string,
      init?: Record<string, unknown>,
    ) => Promise<FetchResponse>;
  };
  const hadCreate = "createHttpClient" in g.Deno;
  const origDesc = Object.getOwnPropertyDescriptor(g.Deno, "createHttpClient");
  const origFetch = g.fetch;
  const sentinel = { __client: true };
  let createArg: unknown;
  let fetchInit: Record<string, unknown> | undefined;
  Object.defineProperty(g.Deno, "createHttpClient", {
    value: (o: unknown) => {
      createArg = o;
      return sentinel;
    },
    configurable: true,
    writable: true,
  });
  g.fetch = (_u, init) => {
    fetchInit = init;
    return Promise.resolve({
      ok: true,
      status: 200,
      statusText: "",
      text: () => Promise.resolve("{}"),
    });
  };
  try {
    const withCa = makeFetch(
      { ...(CFG as object), caCert: "PEM" } as unknown as Cfg,
    );
    await withCa("https://xo/x", { method: "GET" });
    assertEquals(createArg, { caCerts: ["PEM"] });
    assertEquals(fetchInit?.["client"], sentinel);
    // No verification-disabling option is ever attached.
    assertEquals("rejectUnauthorized" in (fetchInit ?? {}), false);

    createArg = undefined;
    fetchInit = undefined;
    const noCa = makeFetch(CFG);
    await noCa("https://xo/x", {});
    assertEquals(createArg, undefined); // not called without a caCert
    assertEquals(fetchInit?.["client"], undefined);
  } finally {
    if (hadCreate && origDesc) {
      Object.defineProperty(g.Deno, "createHttpClient", origDesc);
    } else {
      delete g.Deno.createHttpClient;
    }
    g.fetch = origFetch;
  }
});

// ---------------------------------------------------------------------------
// VIF discovery + pruning (listVifs / deleteVif)
// ---------------------------------------------------------------------------

Deno.test("listVifs: GETs the VM then each VIF, snapshotting MAC + network", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/vms/vm-1"),
      body: { uuid: "vm-1", VIFs: ["vif-a", "vif-b"] },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/vifs/vif-a"),
      body: { uuid: "vif-a", MAC: "ce:99:99:0a:e4:43", $network: "net-1" },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/vifs/vif-b"),
      body: { uuid: "vif-b", MAC: "5a:66:6c:3a:52:53", $network: "net-1" },
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.listVifs.execute(
    asArgs({ id: "vm-1", _fetch: f }),
    context,
  );
  // One VM GET, then one GET per VIF ref.
  assertEquals(calls.map((c) => c.method), ["GET", "GET", "GET"]);
  assertEquals(writes[0].spec, "inventory");
  assertEquals(writes[0].name, "vifs");
  assertEquals(writes[0].data.kind, "vifs");
  assertEquals(writes[0].data.count, 2);
  const items = writes[0].data.items as Array<
    { uuid: string; name_label: string | null; raw: Record<string, unknown> }
  >;
  assertEquals(items.map((i) => i.uuid), ["vif-a", "vif-b"]);
  // name_label carries the MAC; raw.$network resolves which network to prune.
  assertEquals(items[0].name_label, "ce:99:99:0a:e4:43");
  assertEquals(items[0].raw["$network"], "net-1");
  assertEquals(res.dataHandles.length, 1);
});

Deno.test("listVifs: reads the $VIFs fallback, lowercase mac, and a missing VIF body", async () => {
  const { f } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/vms/vm-2"),
      // No plain `VIFs` key — the record only carries the `$VIFs` alias.
      body: { uuid: "vm-2", "$VIFs": ["vif-c", "vif-d"] },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/vifs/vif-c"),
      body: { uuid: "vif-c", mac: "aa:bb:cc:dd:ee:ff" }, // lowercase `mac`
    },
    {
      match: (u, m) => m === "GET" && u.includes("/vifs/vif-d"),
      status: 204,
      body: "", // empty body ⇒ xoRequest returns null
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listVifs.execute(
    asArgs({ id: "vm-2", _fetch: f }),
    context,
  );
  const items = writes[0].data.items as Array<
    { uuid: string; name_label: string | null }
  >;
  assertEquals(writes[0].data.count, 2);
  assertEquals(items[0].name_label, "aa:bb:cc:dd:ee:ff"); // lowercase mac lifted
  // A missing VIF body still records the ref by its id, with a null MAC.
  assertEquals(items[1].uuid, "vif-d");
  assertEquals(items[1].name_label, null);
});

Deno.test("listVifs: a VM with no VIFs records an empty inventory", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/vms/vm-3"),
      body: { uuid: "vm-3" },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listVifs.execute(
    asArgs({ id: "vm-3", _fetch: f }),
    context,
  );
  assertEquals(calls.length, 1); // only the VM GET; no per-VIF calls
  assertEquals(writes[0].data.count, 0);
  assertEquals((writes[0].data.items as unknown[]).length, 0);
});

Deno.test("listVifs: percent-encodes the VM id and each VIF uuid", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/vms/"),
      // An object ref preserves the slash through extractUuid, so enc() is the
      // only thing standing between it and a path traversal.
      body: { uuid: "x", VIFs: [{ uuid: "a/b" }] },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/vifs/"),
      body: { uuid: "a/b", MAC: "00:11:22:33:44:55" },
    },
  ]);
  const { context } = stubContext();
  await model.methods.listVifs.execute(
    asArgs({ id: "v/m", _fetch: f }),
    context,
  );
  assertEquals(calls[0].url.includes("/vms/v%2Fm"), true);
  assertEquals(calls[1].url.includes("/vifs/a%2Fb"), true);
  assertEquals(calls[1].url.includes("/vifs/a/b"), false);
});

Deno.test("deleteVif: verifies (GET) then deletes, recording nothing", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/vifs/vif-1"),
      body: { uuid: "vif-1" },
    },
    {
      match: (u, m) => m === "DELETE" && u.includes("/vifs/vif-1"),
      status: 204,
      body: "",
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.deleteVif.execute(
    asArgs({ vif: "vif-1", _fetch: f }),
    context,
  );
  assertEquals(calls.map((c) => c.method), ["GET", "DELETE"]);
  assertEquals(writes.length, 0);
  assertEquals(res.dataHandles.length, 0);
});

Deno.test("deleteVif: a missing VIF (404 on verify) never issues the DELETE", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/vifs/"),
      status: 404,
      body: { error: "not found" },
    },
    { match: (_u, m) => m === "DELETE", status: 204, body: "" },
  ]);
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.deleteVif.execute(
        asArgs({ vif: "gone", _fetch: f }),
        context,
      ),
    Error,
    "HTTP 404",
  );
  assertEquals(calls.map((c) => c.method), ["GET"]); // DELETE never reached
});

Deno.test("deleteVif: percent-encodes the VIF id in both GET and DELETE paths", async () => {
  const { f, calls } = router([
    { match: (_u, m) => m === "GET", body: { uuid: "x" } },
    { match: (_u, m) => m === "DELETE", status: 204, body: "" },
  ]);
  const { context } = stubContext();
  // A crafted id with a slash must not traverse to a different endpoint.
  await model.methods.deleteVif.execute(
    asArgs({ vif: "a/b", _fetch: f }),
    context,
  );
  assertEquals(calls[0].url.includes("/vifs/a%2Fb"), true);
  assertEquals(calls[1].url.includes("/vifs/a%2Fb"), true);
  assertEquals(calls[0].url.includes("/vifs/a/b"), false);
});

// ---------------------------------------------------------------------------
// Server registration (addServer / listServers)
// ---------------------------------------------------------------------------

Deno.test("normalizeServer() maps id/host, strips the password", () => {
  const s = normalizeServer({
    id: "srv-1",
    label: "alpha",
    host: "192.0.2.5",
    username: "root",
    password: "s3cret",
    status: "connected",
    poolId: "pool-f",
  });
  assertEquals(s.id, "srv-1");
  assertEquals(s.host, "192.0.2.5");
  assertEquals(s.status, "connected");
  assertEquals(s.poolId, "pool-f");
  // The password must never survive into the recorded snapshot.
  assertEquals("password" in s.raw, false);
  assertEquals(s.raw.label, "alpha");
});

Deno.test("addServer: registers a new host, connects, snapshots the server", async () => {
  const { f, calls } = router([
    // Idempotency probe: no servers yet.
    { match: (u, m) => m === "GET" && /\/servers\?/.test(u), body: [] },
    // POST /servers -> { id }
    {
      match: (u, m) => m === "POST" && /\/servers$/.test(u.split("?")[0]),
      body: { id: "srv-new" },
    },
    // connect action
    {
      match: (u, m) =>
        m === "POST" && u.includes("/servers/srv-new/actions/connect"),
      status: 204,
      body: "",
    },
    // final snapshot GET /servers/{id}
    {
      match: (u, m) => m === "GET" && u.includes("/servers/srv-new"),
      body: { id: "srv-new", host: "10.0.0.9", status: "connected" },
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.addServer.execute(
    asArgs({
      host: "10.0.0.9",
      label: "alpha",
      username: "root",
      password: "pw",
      allowUnauthorized: true,
      connect: true,
      sync: true,
      _fetch: f,
    }),
    context,
  );
  // GET probe, POST create, POST connect, GET snapshot.
  assertEquals(calls.map((c) => c.method), ["GET", "POST", "POST", "GET"]);
  // The create body carried the credentials + allowUnauthorized.
  const created = JSON.parse(calls[1].body ?? "{}");
  assertEquals(created.host, "10.0.0.9");
  assertEquals(created.allowUnauthorized, true);
  assertEquals(created.password, "pw");
  // connect used ?sync=true.
  assertEquals(calls[2].url.includes("sync=true"), true);
  // Recorded a server resource with the password stripped.
  assertEquals(writes[0].spec, "server");
  assertEquals(writes[0].name, "server:srv-new");
  assertEquals("password" in (writes[0].data.raw as object), false);
  assertEquals(res.dataHandles[0].name, "server:srv-new");
});

Deno.test("addServer: reuses an already-registered host (no duplicate POST)", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && /\/servers\?/.test(u),
      body: [{ id: "srv-existing", host: "10.0.0.9" }],
    },
    {
      match: (u, m) =>
        m === "POST" && u.includes("/servers/srv-existing/actions/connect"),
      status: 204,
      body: "",
    },
    {
      match: (u, m) => m === "GET" && u.includes("/servers/srv-existing"),
      body: { id: "srv-existing", host: "10.0.0.9", status: "connected" },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.addServer.execute(
    asArgs({
      host: "10.0.0.9",
      label: "alpha",
      username: "root",
      password: "pw",
      allowUnauthorized: true,
      connect: true,
      sync: true,
      _fetch: f,
    }),
    context,
  );
  // No POST /servers create — probe, connect, snapshot only.
  assertEquals(calls.map((c) => c.method), ["GET", "POST", "GET"]);
  assertEquals(calls[1].url.includes("/actions/connect"), true);
  assertEquals(writes[0].name, "server:srv-existing");
});

Deno.test("addServer: connect=false registers without connecting", async () => {
  const { f, calls } = router([
    { match: (u, m) => m === "GET" && /\/servers\?/.test(u), body: [] },
    {
      match: (u, m) => m === "POST" && /\/servers$/.test(u.split("?")[0]),
      body: { id: "srv-new" },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/servers/srv-new"),
      body: { id: "srv-new" },
    },
  ]);
  const { context } = stubContext();
  await model.methods.addServer.execute(
    asArgs({
      host: "10.0.0.9",
      label: "alpha",
      username: "root",
      password: "pw",
      allowUnauthorized: false,
      connect: false,
      sync: true,
      _fetch: f,
    }),
    context,
  );
  // No connect action issued.
  assertEquals(calls.some((c) => c.url.includes("/actions/connect")), false);
  assertEquals(calls.map((c) => c.method), ["GET", "POST", "GET"]);
});

Deno.test("listServers: records an inventory snapshot (id->uuid, label->name_label)", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/servers"),
      body: [
        { id: "srv-1", label: "beta", host: "10.0.0.1", status: "connected" },
        { id: "srv-2", label: "alpha", host: "10.0.0.9", status: "connected" },
      ],
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listServers.execute(asArgs({ _fetch: f }), context);
  assertEquals(calls[0].url.includes("fields=id%2Clabel%2Chost"), true);
  const data = writes[0].data as {
    kind: string;
    count: number;
    items: Array<{ uuid: string | null; name_label: string | null }>;
  };
  assertEquals(data.kind, "servers");
  assertEquals(data.count, 2);
  assertEquals(data.items[1].uuid, "srv-2");
  assertEquals(data.items[1].name_label, "alpha");
});

Deno.test("listServers: a non-array response fails loud", async () => {
  const { f } = once({ error: "boom" }, { status: 200 });
  const { context } = stubContext();
  await assertRejects(
    () => model.methods.listServers.execute(asArgs({ _fetch: f }), context),
    Error,
    "did not return a list",
  );
});

// ---------------------------------------------------------------------------
// VM/host discovery + migrate
// ---------------------------------------------------------------------------

Deno.test("listVms: fans /vms into a vms inventory with placement fields", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/vms"),
      body: [
        {
          uuid: "vm-a",
          name_label: "coolify-worker2",
          power_state: "Halted",
          $container: "host-beta",
          $pool: "pool-beta",
        },
        { uuid: "vm-b", name_label: "swamp-serve-01", power_state: "Running" },
      ],
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listVms.execute(asArgs({ _fetch: f }), context);
  assertEquals(calls[0].url.includes("fields=uuid%2Cname_label"), true);
  const data = writes[0].data as {
    kind: string;
    count: number;
    items: Array<{ uuid: string | null; raw: Record<string, unknown> }>;
  };
  assertEquals(data.kind, "vms");
  assertEquals(data.count, 2);
  assertEquals(data.items[0].uuid, "vm-a");
  // Placement fields survive in raw for the migrate step to resolve.
  assertEquals(data.items[0].raw.$container, "host-beta");
  assertEquals(data.items[0].raw.$pool, "pool-beta");
});

Deno.test("listHosts: fans /hosts into a hosts inventory", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/hosts"),
      body: [
        { uuid: "host-f", name_label: "alpha", $pool: "pool-alpha" },
      ],
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listHosts.execute(asArgs({ _fetch: f }), context);
  assertEquals(calls[0].url.includes("/hosts?"), true);
  const data = writes[0].data as { kind: string; count: number };
  assertEquals(data.kind, "hosts");
  assertEquals(data.count, 1);
});

Deno.test("listHosts: a non-array response fails loud", async () => {
  const { f } = once({ oops: true }, { status: 200 });
  const { context } = stubContext();
  await assertRejects(
    () => model.methods.listHosts.execute(asArgs({ _fetch: f }), context),
    Error,
    "did not return a list",
  );
});

Deno.test("migrate: verifies, posts migrate with mappings, re-snapshots", async () => {
  const { f, calls } = router([
    // verify GET
    {
      match: (u, m) => m === "GET" && /\/vms\/vm-a$/.test(u.split("?")[0]),
      body: { uuid: "vm-a" },
    },
    // migrate action -> 204
    {
      match: (u, m) => m === "POST" && u.includes("/vms/vm-a/actions/migrate"),
      status: 204,
      body: "",
    },
    // post-migrate snapshot GET
    {
      match: (u, m) => m === "GET" && u.includes("/vms/vm-a"),
      body: { uuid: "vm-a", $container: "host-f" },
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.migrate.execute(
    asArgs({
      id: "vm-a",
      hostId: "host-f",
      srId: "sr-f",
      networkIdByVifId: { "vif-1": "net-f" },
      sync: true,
      _fetch: f,
    }),
    context,
  );
  // verify GET, POST migrate, snapshot GET.
  assertEquals(calls.map((c) => c.method), ["GET", "POST", "GET"]);
  const body = JSON.parse(calls[1].body ?? "{}");
  assertEquals(body.hostId, "host-f");
  assertEquals(body.srId, "sr-f");
  assertEquals(body.networkIdByVifId, { "vif-1": "net-f" });
  assertEquals(calls[1].url.includes("sync=true"), true);
  // Optional fields not supplied are omitted from the body.
  assertEquals("migrationNetworkId" in body, false);
  assertEquals(writes[0].name, "vm:vm-a");
  assertEquals(res.dataHandles[0].name, "vm:vm-a");
});

Deno.test("migrate: a missing VM (404 on verify) never issues the POST", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/vms/gone"),
      status: 404,
      body: { error: "not found" },
    },
    { match: (_u, m) => m === "POST", status: 204, body: "" },
  ]);
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.migrate.execute(
        asArgs({ id: "gone", hostId: "host-f", sync: true, _fetch: f }),
        context,
      ),
    Error,
    "HTTP 404",
  );
  assertEquals(calls.map((c) => c.method), ["GET"]); // POST never reached
});

Deno.test("migrate: a post-migrate snapshot 404 (uuid reassigned) still succeeds", async () => {
  let seenPost = false;
  const { f } = router([
    {
      match: (u, m) => {
        // The verify GET (pre-POST) succeeds; the post-migrate GET 404s.
        if (m === "GET" && u.includes("/vms/vm-a")) return true;
        return false;
      },
      // handled below by dynamic status via two routes
    },
  ]);
  // Build a stateful fake: GET ok before POST, GET 404 after POST.
  const calls: string[] = [];
  const ff: FetchLike = (_url, init) => {
    const method = init?.method ?? "GET";
    calls.push(method);
    let status = 200;
    let text = "{}";
    if (method === "POST") {
      seenPost = true;
      status = 204;
      text = "";
    } else if (method === "GET" && seenPost) {
      status = 404;
      text = JSON.stringify({ error: "not found" });
    } else {
      text = JSON.stringify({ uuid: "vm-a" });
    }
    return Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      statusText: "",
      text: () => Promise.resolve(text),
    });
  };
  void f;
  const { context, writes } = stubContext();
  const res = await model.methods.migrate.execute(
    asArgs({ id: "vm-a", hostId: "host-f", sync: true, _fetch: ff }),
    context,
  );
  // GET(verify), POST(migrate), GET(snapshot->404) — method still resolves.
  assertEquals(calls, ["GET", "POST", "GET"]);
  assertEquals(writes.length, 0);
  assertEquals(res.dataHandles.length, 0);
});

Deno.test("listPifs: fans /pifs into a pifs inventory with vlan/device", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/pifs"),
      body: [
        { uuid: "pif-wan", device: "eth0", vlan: -1, $network: "net-wan" },
        { uuid: "pif-svc", device: "eth0", vlan: 40, $network: "net-svc" },
      ],
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listPifs.execute(asArgs({ _fetch: f }), context);
  assertEquals(calls[0].url.includes("fields=uuid%2Cdevice%2Cvlan"), true);
  const data = writes[0].data as {
    kind: string;
    count: number;
    items: Array<{ uuid: string | null; raw: Record<string, unknown> }>;
  };
  assertEquals(data.kind, "pifs");
  assertEquals(data.count, 2);
  // vlan tag survives in raw so recon can tell internal vs VLAN-on-PIF.
  assertEquals(data.items[0].raw.vlan, -1);
  assertEquals(data.items[1].raw.vlan, 40);
});

Deno.test("listSRs: requests capacity fields for placement decisions", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/srs"),
      body: [{
        uuid: "sr-1",
        name_label: "NVME",
        physical_size: 100,
        physical_usage: 10,
      }],
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listSRs.execute(asArgs({ _fetch: f }), context);
  assertEquals(calls[0].url.includes("physical_size"), true);
  const data = writes[0].data as {
    items: Array<{ raw: Record<string, unknown> }>;
  };
  assertEquals(data.items[0].raw.physical_size, 100);
});

// ---------------------------------------------------------------------------
// Network creation
// ---------------------------------------------------------------------------

Deno.test("normalizeNetwork() lifts PIFs + $pool, flags internal vs VLAN", () => {
  const internal = normalizeNetwork({
    uuid: "n1",
    name_label: "int",
    PIFs: [],
  });
  assertEquals(internal.pifs, []);
  const vlan = normalizeNetwork({
    uuid: "n2",
    name_label: "Services",
    MTU: 1500,
    $pool: "pool-f",
    PIFs: ["/rest/v0/pifs/pif-svc"],
  });
  assertEquals(vlan.pifs, ["pif-svc"]);
  assertEquals(vlan.poolId, "pool-f");
  assertEquals(vlan.mtu, 1500);
});

Deno.test("createNetwork: creates a VLAN network then snapshots it", async () => {
  const { f, calls } = router([
    // idempotency probe: no matching network
    { match: (u, m) => m === "GET" && /\/networks\?/.test(u), body: [] },
    // create_network -> { id }
    {
      match: (u, m) => m === "POST" && u.includes("/actions/create_network"),
      body: { id: "net-new" },
    },
    // snapshot GET
    {
      match: (u, m) => m === "GET" && u.includes("/networks/net-new"),
      body: { uuid: "net-new", name_label: "Services", $pool: "pool-f" },
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.createNetwork.execute(
    asArgs({
      name: "Services",
      pif: "pif-eth0",
      vlan: 10,
      poolId: "pool-f",
      _fetch: f,
    }),
    context,
  );
  assertEquals(calls.map((c) => c.method), ["GET", "POST", "GET"]);
  const body = JSON.parse(calls[1].body ?? "{}");
  assertEquals(body, { name: "Services", pif: "pif-eth0", vlan: 10 });
  assertEquals(
    calls[1].url.includes("/pools/pool-f/actions/create_network"),
    true,
  );
  assertEquals(writes[0].name, "network:net-new");
  assertEquals(res.dataHandles[0].name, "network:net-new");
});

Deno.test("createNetwork: reuses an existing same-name network in the pool", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && /\/networks\?/.test(u),
      body: [{ uuid: "net-existing", name_label: "Services", $pool: "pool-f" }],
    },
    {
      match: (u, m) => m === "GET" && u.includes("/networks/net-existing"),
      body: { uuid: "net-existing", name_label: "Services" },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.createNetwork.execute(
    asArgs({
      name: "Services",
      pif: "pif-eth0",
      vlan: 10,
      poolId: "pool-f",
      _fetch: f,
    }),
    context,
  );
  // No POST create — probe + snapshot only.
  assertEquals(calls.map((c) => c.method), ["GET", "GET"]);
  assertEquals(writes[0].name, "network:net-existing");
});

Deno.test("createNetwork: a different pool does not match (name collision across pools)", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && /\/networks\?/.test(u),
      body: [{
        uuid: "net-other",
        name_label: "Services",
        $pool: "pool-OTHER",
      }],
    },
    {
      match: (u, m) => m === "POST" && u.includes("/actions/create_network"),
      body: { id: "net-new" },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/networks/net-new"),
      body: { uuid: "net-new" },
    },
  ]);
  const { context } = stubContext();
  await model.methods.createNetwork.execute(
    asArgs({
      name: "Services",
      pif: "pif-eth0",
      vlan: 10,
      poolId: "pool-f",
      _fetch: f,
    }),
    context,
  );
  // Same name in a DIFFERENT pool must not be reused → POST happens.
  assertEquals(calls.map((c) => c.method), ["GET", "POST", "GET"]);
});

Deno.test("createNetwork: requires a poolId", async () => {
  const { f } = once({});
  const anon = { ...(CFG as object), poolId: "" } as unknown as Cfg;
  const { context } = stubContext(anon);
  await assertRejects(
    () =>
      model.methods.createNetwork.execute(
        asArgs({ name: "x", pif: "p", vlan: 1, _fetch: f }),
        context,
      ),
    Error,
    "requires a poolId",
  );
});

Deno.test("createInternalNetwork: posts create_internal_network with just a name", async () => {
  const { f, calls } = router([
    { match: (u, m) => m === "GET" && /\/networks\?/.test(u), body: [] },
    {
      match: (u, m) =>
        m === "POST" && u.includes("/actions/create_internal_network"),
      body: { id: "net-int" },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/networks/net-int"),
      body: { uuid: "net-int" },
    },
  ]);
  const { context } = stubContext();
  await model.methods.createInternalNetwork.execute(
    asArgs({ name: "isolated", poolId: "pool-f", _fetch: f }),
    context,
  );
  const body = JSON.parse(calls[1].body ?? "{}");
  assertEquals(body, { name: "isolated" });
});

Deno.test("createNetwork: resolves an async task ref (taskId -> poll -> id)", async () => {
  const { f, calls } = router([
    { match: (u, m) => m === "GET" && /\/networks\?/.test(u), body: [] },
    {
      match: (u, m) => m === "POST" && u.includes("/actions/create_network"),
      body: { taskId: "task-1" }, // async: XO returns a task ref, not {id}
    },
    {
      match: (u, m) => m === "GET" && u.includes("/tasks/task-1"),
      body: { status: "success", result: "net-async" },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/networks/net-async"),
      body: { uuid: "net-async" },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.createNetwork.execute(
    asArgs({
      name: "Services",
      pif: "p",
      vlan: 10,
      poolId: "pool-f",
      _fetch: f,
    }),
    context,
  );
  // POST used ?sync=true; the task was polled to the created network id.
  assertEquals(calls[1].url.includes("sync=true"), true);
  assertEquals(writes[0].name, "network:net-async");
});

// ---------------------------------------------------------------------------
// SR creation (createSR)
// ---------------------------------------------------------------------------

Deno.test("createSR: creates an NFS ISO SR (POST /srs) then snapshots it", async () => {
  const { f, calls } = router([
    // host -> pool resolution for idempotency scoping
    {
      match: (u, m) => m === "GET" && /\/hosts\/host-bc\?/.test(u),
      body: { $pool: "pool-bc" },
    },
    // idempotency probe: no matching SR
    { match: (u, m) => m === "GET" && /\/srs\?/.test(u), body: [] },
    // POST /srs -> { id }
    {
      match: (u, m) => m === "POST" && /\/srs$/.test(u.split("?")[0]),
      body: { id: "sr-new" },
    },
    // snapshot GET
    {
      match: (u, m) => m === "GET" && u.includes("/srs/sr-new"),
      body: {
        uuid: "sr-new",
        name_label: "ISOs",
        SR_type: "iso",
        content_type: "iso",
        $pool: "pool-bc",
      },
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.createSR.execute(
    asArgs({
      hostId: "host-bc",
      name_label: "ISOs",
      SR_type: "iso",
      device_config: { location: "192.0.2.5:/export/isos", type: "nfs_iso" },
      name_description: "NFS ISO library",
      _fetch: f,
    }),
    context,
  );
  assertEquals(calls.map((c) => c.method), ["GET", "GET", "POST", "GET"]);
  // POST hit the /srs collection, not a pool action.
  assertEquals(calls[2].url.split("?")[0].endsWith("/srs"), true);
  const body = JSON.parse(calls[2].body ?? "{}");
  assertEquals(body, {
    hostId: "host-bc",
    name_label: "ISOs",
    SR_type: "iso",
    device_config: { location: "192.0.2.5:/export/isos", type: "nfs_iso" },
    name_description: "NFS ISO library",
  });
  assertEquals(writes[0].name, "sr:sr-new");
  assertEquals(res.dataHandles[0].name, "sr:sr-new");
});

Deno.test("createSR: reuses an existing same-name+type SR when device_config matches (no POST)", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && /\/hosts\/host-bc\?/.test(u),
      body: { $pool: "pool-bc" },
    },
    {
      match: (u, m) => m === "GET" && /\/srs\?/.test(u),
      body: [{
        uuid: "sr-existing",
        name_label: "ISOs",
        SR_type: "iso",
        $pool: "pool-bc",
      }],
    },
    // both the device_config match-probe and the final snapshot GET this path
    {
      match: (u, m) => m === "GET" && u.includes("/srs/sr-existing"),
      body: {
        uuid: "sr-existing",
        name_label: "ISOs",
        SR_type: "iso",
        device_config: { location: "192.0.2.5:/export/isos", type: "nfs_iso" },
      },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.createSR.execute(
    asArgs({
      hostId: "host-bc",
      name_label: "ISOs",
      SR_type: "iso",
      device_config: { location: "192.0.2.5:/export/isos", type: "nfs_iso" },
      _fetch: f,
    }),
    context,
  );
  // No POST — host probe + srs list + device_config match-probe + snapshot.
  assertEquals(calls.map((c) => c.method), ["GET", "GET", "GET", "GET"]);
  assertEquals(writes[0].name, "sr:sr-existing");
});

Deno.test("createSR: a same-name ISO SR of a DIFFERENT transport is NOT reused (device_config mismatch -> POST)", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && /\/hosts\/host-bc\?/.test(u),
      body: { $pool: "pool-bc" },
    },
    {
      match: (u, m) => m === "GET" && /\/srs\?/.test(u),
      body: [{
        uuid: "sr-smb",
        name_label: "ISOs",
        SR_type: "iso",
        $pool: "pool-bc",
      }],
    },
    // candidate is an SMB ISO library — same name+type, DIFFERENT transport
    {
      match: (u, m) => m === "GET" && u.includes("/srs/sr-smb"),
      body: {
        uuid: "sr-smb",
        device_config: { location: "\\\\nas\\isos", type: "cifs" },
      },
    },
    {
      match: (u, m) => m === "POST" && /\/srs$/.test(u.split("?")[0]),
      body: { id: "sr-nfs-new" },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/srs/sr-nfs-new"),
      body: { uuid: "sr-nfs-new" },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.createSR.execute(
    asArgs({
      hostId: "host-bc",
      name_label: "ISOs",
      SR_type: "iso",
      device_config: { location: "192.0.2.5:/export/isos", type: "nfs_iso" },
      _fetch: f,
    }),
    context,
  );
  // SMB candidate rejected on device_config -> a real NFS SR is created.
  assertEquals(calls.map((c) => c.method), [
    "GET",
    "GET",
    "GET",
    "POST",
    "GET",
  ]);
  assertEquals(writes[0].name, "sr:sr-nfs-new");
});

Deno.test("createSR: forwards sm_config and size in the POST body", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && /\/hosts\/host-bc\?/.test(u),
      body: { $pool: "pool-bc" },
    },
    { match: (u, m) => m === "GET" && /\/srs\?/.test(u), body: [] },
    {
      match: (u, m) => m === "POST" && /\/srs$/.test(u.split("?")[0]),
      body: { id: "sr-lvm" },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/srs/sr-lvm"),
      body: { uuid: "sr-lvm" },
    },
  ]);
  const { context } = stubContext();
  await model.methods.createSR.execute(
    asArgs({
      hostId: "host-bc",
      name_label: "block",
      SR_type: "lvm",
      device_config: { device: "/dev/sdb" },
      sm_config: { foo: "bar" },
      size: 1073741824,
      _fetch: f,
    }),
    context,
  );
  const body = JSON.parse(calls[2].body ?? "{}");
  assertEquals(body.sm_config, { foo: "bar" });
  assertEquals(body.size, 1073741824);
  assertEquals(body.SR_type, "lvm");
});

Deno.test("createSR: same name+type in a DIFFERENT pool is not reused (POST happens)", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && /\/hosts\/host-bc\?/.test(u),
      body: { $pool: "pool-bc" },
    },
    {
      match: (u, m) => m === "GET" && /\/srs\?/.test(u),
      body: [{
        uuid: "sr-other",
        name_label: "ISOs",
        SR_type: "iso",
        $pool: "pool-OTHER",
      }],
    },
    {
      match: (u, m) => m === "POST" && /\/srs$/.test(u.split("?")[0]),
      body: { id: "sr-new" },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/srs/sr-new"),
      body: { uuid: "sr-new" },
    },
  ]);
  const { context } = stubContext();
  await model.methods.createSR.execute(
    asArgs({
      hostId: "host-bc",
      name_label: "ISOs",
      SR_type: "iso",
      device_config: { location: "192.0.2.5:/export/isos", type: "nfs_iso" },
      _fetch: f,
    }),
    context,
  );
  assertEquals(calls.map((c) => c.method), ["GET", "GET", "POST", "GET"]);
});

Deno.test("createSR: resolves an async task ref (taskId -> poll -> id)", async () => {
  const { f } = router([
    {
      match: (u, m) => m === "GET" && /\/hosts\/host-bc\?/.test(u),
      body: { $pool: "pool-bc" },
    },
    { match: (u, m) => m === "GET" && /\/srs\?/.test(u), body: [] },
    {
      match: (u, m) => m === "POST" && /\/srs$/.test(u.split("?")[0]),
      body: { taskId: "task-sr" },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/tasks/task-sr"),
      body: { status: "success", result: "sr-async" },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/srs/sr-async"),
      body: { uuid: "sr-async" },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.createSR.execute(
    asArgs({
      hostId: "host-bc",
      name_label: "ISOs",
      SR_type: "iso",
      device_config: { location: "192.0.2.5:/export/isos", type: "nfs_iso" },
      _fetch: f,
    }),
    context,
  );
  assertEquals(writes[0].name, "sr:sr-async");
});

Deno.test("createSR: a failed host lookup falls back to name+type match (best-effort pool)", async () => {
  const { f, calls } = router([
    // host lookup fails (404) -> poolId falls back to ""
    {
      match: (u, m) => m === "GET" && /\/hosts\/host-bc\?/.test(u),
      status: 404,
      body: { error: "no host" },
    },
    // with poolId "" a name+type+device_config match anywhere is reused
    {
      match: (u, m) => m === "GET" && /\/srs\?/.test(u),
      body: [{
        uuid: "sr-anywhere",
        name_label: "ISOs",
        SR_type: "iso",
        $pool: "pool-somewhere",
      }],
    },
    {
      match: (u, m) => m === "GET" && u.includes("/srs/sr-anywhere"),
      body: {
        uuid: "sr-anywhere",
        device_config: { location: "192.0.2.5:/export/isos", type: "nfs_iso" },
      },
    },
  ]);
  const { context, writes, logs } = stubContext();
  await model.methods.createSR.execute(
    asArgs({
      hostId: "host-bc",
      name_label: "ISOs",
      SR_type: "iso",
      device_config: { location: "192.0.2.5:/export/isos", type: "nfs_iso" },
      _fetch: f,
    }),
    context,
  );
  // Fell back to reuse, but the failed host lookup was surfaced as a warning
  // (not silently swallowed) — host GET, srs list, dc match-probe, snapshot.
  assertEquals(calls.map((c) => c.method), ["GET", "GET", "GET", "GET"]);
  assertEquals(writes[0].name, "sr:sr-anywhere");
  assertEquals(logs.some((l) => l.level === "warning"), true);
});

Deno.test("createSR: warns when reusing a host-local SR (pool scope can't verify host attachment)", async () => {
  const { f } = router([
    {
      match: (u, m) => m === "GET" && /\/hosts\/host-bc\?/.test(u),
      body: { $pool: "pool-bc" },
    },
    {
      match: (u, m) => m === "GET" && /\/srs\?/.test(u),
      body: [{
        uuid: "sr-ext",
        name_label: "local",
        SR_type: "ext",
        $pool: "pool-bc",
      }],
    },
    {
      match: (u, m) => m === "GET" && u.includes("/srs/sr-ext"),
      body: { uuid: "sr-ext", device_config: { device: "/dev/sdb" } },
    },
  ]);
  const { context, logs } = stubContext();
  await model.methods.createSR.execute(
    asArgs({
      hostId: "host-bc",
      name_label: "local",
      SR_type: "ext",
      device_config: { device: "/dev/sdb" },
      _fetch: f,
    }),
    context,
  );
  assertEquals(
    logs.some((l) => l.level === "warning" && /host-local/.test(l.msg)),
    true,
  );
});

Deno.test("createSR: warns on multiple ambiguous device_config matches", async () => {
  const { f } = router([
    {
      match: (u, m) => m === "GET" && /\/hosts\/host-bc\?/.test(u),
      body: { $pool: "pool-bc" },
    },
    {
      match: (u, m) => m === "GET" && /\/srs\?/.test(u),
      body: [
        { uuid: "sr-a", name_label: "ISOs", SR_type: "iso", $pool: "pool-bc" },
        { uuid: "sr-b", name_label: "ISOs", SR_type: "iso", $pool: "pool-bc" },
      ],
    },
    {
      match: (u, m) => m === "GET" && u.includes("/srs/sr-a"),
      body: {
        uuid: "sr-a",
        device_config: { location: "192.0.2.5:/export/isos", type: "nfs_iso" },
      },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/srs/sr-b"),
      body: {
        uuid: "sr-b",
        device_config: { location: "192.0.2.5:/export/isos", type: "nfs_iso" },
      },
    },
  ]);
  const { context, logs } = stubContext();
  await model.methods.createSR.execute(
    asArgs({
      hostId: "host-bc",
      name_label: "ISOs",
      SR_type: "iso",
      device_config: { location: "192.0.2.5:/export/isos", type: "nfs_iso" },
      _fetch: f,
    }),
    context,
  );
  assertEquals(
    logs.some((l) => l.level === "warning" && /Multiple SRs/.test(l.msg)),
    true,
  );
});

Deno.test("deviceConfigMatches: compares non-secret keys, ignores *pass*, fails on absent", () => {
  const intended = {
    location: "192.0.2.5:/export/isos",
    type: "nfs_iso",
    password: "shouldbeignored",
  };
  // full non-secret match (password not compared) -> true
  assertEquals(
    deviceConfigMatches(intended, {
      location: "192.0.2.5:/export/isos",
      type: "nfs_iso",
    }),
    true,
  );
  // transport differs -> false
  assertEquals(
    deviceConfigMatches(intended, {
      location: "192.0.2.5:/export/isos",
      type: "cifs",
    }),
    false,
  );
  // absent device_config -> false (fail closed)
  assertEquals(deviceConfigMatches(intended, undefined), false);
});

Deno.test("normalizeSr: redacts device_config credentials from persisted raw", () => {
  const sr = normalizeSr({
    uuid: "sr-smb",
    name_label: "SMB ISOs",
    type: "iso",
    content_type: "iso",
    shared: true,
    physical_size: 1000,
    physical_usage: 10,
    $pool: "pool-bc",
    device_config: {
      location: "\\\\nas\\isos",
      type: "cifs",
      username: "svc",
      password: "hunter2",
      cifspassword: "hunter3",
      chappassword: "hunter4",
    },
  });
  assertEquals(sr.SR_type, "iso");
  assertEquals(sr.size, 1000);
  const dc = sr.raw.device_config as Record<string, unknown>;
  // Every *pass* key is stripped.
  assertEquals("password" in dc, false);
  assertEquals("cifspassword" in dc, false);
  assertEquals("chappassword" in dc, false);
  // Non-secret keys survive for debugging fidelity.
  assertEquals(dc.username, "svc");
  assertEquals(dc.type, "cifs");
});

// ---------------------------------------------------------------------------
// Boot-from-ISO install (create + listVdis)
// ---------------------------------------------------------------------------

Deno.test("buildCreateBody: passes the install (boot-from-ISO) block", () => {
  const body = buildCreateBody({
    name_label: "opnsense-alpha",
    template: "other-install-media",
    install: { method: "cdrom", repository: "iso-vdi-1" },
  });
  assertEquals(body.install, { method: "cdrom", repository: "iso-vdi-1" });
});

Deno.test("create: mounts an install ISO in the create_vm body", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "POST" && u.includes("/actions/create_vm"),
      body: "vm-fw",
    },
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-fw"),
      body: {
        uuid: "vm-fw",
        name_label: "opnsense-alpha",
        power_state: "Halted",
      },
    },
  ]);
  const { context } = stubContext();
  await model.methods.create.execute(
    asArgs({
      name_label: "opnsense-alpha",
      template: "other-install-media",
      install: { method: "cdrom", repository: "iso-vdi-1" },
      _fetch: f,
    }),
    context,
  );
  const sent = JSON.parse(calls[0].body ?? "{}");
  assertEquals(sent.install, { method: "cdrom", repository: "iso-vdi-1" });
});

Deno.test("listVdis: GETs /vdis, applies the sr filter, snapshots them", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/vdis"),
      body: [
        { uuid: "iso-1", name_label: "OPNsense-25.1.iso", "$SR": "iso-sr" },
      ],
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.listVdis.execute(
    asArgs({ sr: "iso-sr", _fetch: f }),
    context,
  );
  // Scoped by an XO complex-matcher on $SR.
  assertEquals(calls[0].url.includes("filter=%24SR%3Aiso-sr"), true);
  assertEquals(writes[0].spec, "inventory");
  assertEquals(writes[0].name, "vdis");
  assertEquals(writes[0].data.kind, "vdis");
  assertEquals(writes[0].data.count, 1);
  const items = writes[0].data.items as Array<
    { uuid: string; raw: Record<string, unknown> }
  >;
  assertEquals(items[0].uuid, "iso-1");
  assertEquals(items[0].raw["$SR"], "iso-sr");
  assertEquals(res.dataHandles.length, 1);
});

Deno.test("listVdis: with no filters, GETs the bare collection", async () => {
  const { f, calls } = router([
    { match: (u, m) => m === "GET" && u.includes("/vdis"), body: [] },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listVdis.execute(asArgs({ _fetch: f }), context);
  assertEquals(calls[0].url.includes("filter="), false);
  assertEquals(calls[0].url.includes("fields="), true);
  assertEquals(writes[0].data.count, 0);
});

Deno.test("clone: SR-copy branch verifies source, forwards srId+compress (fast suppressed), snapshots the NEW vm", async () => {
  const { f, calls } = router([
    // Rule 5: source existence check.
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-src"),
      body: { uuid: "vm-src" },
    },
    // The clone action returns the new VM's UUID as `{ id }`.
    {
      match: (u, m) => m === "POST" && u.includes("/vms/vm-src/actions/clone"),
      body: { id: "vm-copy" },
    },
    // snapshotVm GETs the new UUID.
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-copy"),
      body: {
        uuid: "vm-copy",
        name_label: "worker2 (COPY)",
        power_state: "Halted",
      },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.clone.execute(
    asArgs({
      id: "vm-src",
      srId: "sr-alpha",
      nameLabel: "worker2 (COPY)",
      compress: "zstd",
      fast: true, // must be ignored once srId is set
      sync: true,
      _fetch: f,
    }),
    context,
  );
  // Source verified before the clone POST.
  assertEquals(calls[0].method, "GET");
  assertEquals(calls[0].url.endsWith("/vms/vm-src"), true);
  // Clone carried ?sync=true and the SR-copy body (srId+compress+name_label),
  // and did NOT leak `fast` into the SR-copy branch.
  assertEquals(calls[1].url.includes("/vms/vm-src/actions/clone"), true);
  assertEquals(calls[1].url.includes("sync=true"), true);
  const body = JSON.parse(calls[1].body ?? "{}");
  assertEquals(body.srId, "sr-alpha");
  assertEquals(body.compress, "zstd");
  assertEquals(body.name_label, "worker2 (COPY)");
  assertEquals("fast" in body, false);
  // Recorded the NEW vm from the follow-up GET, not the source.
  assertEquals(writes.length, 1);
  assertEquals(writes[0].name, "vm:vm-copy");
  assertEquals(writes[0].data.power_state, "Halted");
});

Deno.test("clone: same-SR clone omits srId and sends fast", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-src"),
      body: { uuid: "vm-src" },
    },
    {
      match: (u, m) => m === "POST" && u.includes("/vms/vm-src/actions/clone"),
      body: "vm-fast", // XO may return a bare UUID string
    },
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-fast"),
      body: { uuid: "vm-fast" },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.clone.execute(
    asArgs({ id: "vm-src", fast: false, sync: true, _fetch: f }),
    context,
  );
  const body = JSON.parse(calls[1].body ?? "{}");
  assertEquals("srId" in body, false);
  assertEquals("compress" in body, false);
  assertEquals(body.fast, false);
  assertEquals(writes[0].name, "vm:vm-fast");
});

Deno.test("clone: throws when the action returns no new UUID", async () => {
  const { f } = router([
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-src"),
      body: { uuid: "vm-src" },
    },
    { match: (u, m) => m === "POST" && u.includes("/actions/clone"), body: {} },
  ]);
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.clone.execute(
        asArgs({ id: "vm-src", srId: "sr-x", sync: true, _fetch: f }),
        context,
      ),
    Error,
    "no VM UUID",
  );
});

Deno.test("clone: async (sync=false) resolves the taskId to the NEW vm uuid", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-src"),
      body: { uuid: "vm-src" },
    },
    // async form: XO returns a task ref, not {id}.
    {
      match: (u, m) => m === "POST" && u.includes("/vms/vm-src/actions/clone"),
      body: { taskId: "task-9" },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/tasks/task-9"),
      body: { status: "success", result: "vm-async" },
    },
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-async"),
      body: { uuid: "vm-async", power_state: "Halted" },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.clone.execute(
    asArgs({ id: "vm-src", srId: "sr-alpha", sync: false, _fetch: f }),
    context,
  );
  // No inline sync; the task was polled through to the NEW uuid.
  assertEquals(calls[1].url.includes("sync=true"), false);
  assertEquals(writes.length, 1);
  assertEquals(writes[0].name, "vm:vm-async");
});

Deno.test("clone: a snapshot failure AFTER a successful copy does not throw (no duplicate-retry trap)", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-src"),
      body: { uuid: "vm-src" },
    },
    {
      match: (u, m) => m === "POST" && u.includes("/actions/clone"),
      body: { id: "vm-copy" },
    },
    // The copy committed, but snapshotting the new VM fails (e.g. transient GET).
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-copy"),
      status: 500,
      body: { message: "boom" },
    },
  ]);
  const { context, writes } = stubContext();
  // Must resolve, not reject: the copy already happened, so a throw here would
  // read as failure and tempt a duplicating retry.
  const res = await model.methods.clone.execute(
    asArgs({ id: "vm-src", srId: "sr-alpha", sync: true, _fetch: f }),
    context,
  );
  assertEquals(res.dataHandles.length, 0);
  assertEquals(writes.length, 0);
  // The clone POST did fire (the copy is real); only the snapshot GET failed.
  assertEquals(calls[1].url.includes("/actions/clone"), true);
});

Deno.test("clone: a missing source VM (404 on verify) never issues the clone POST", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/gone"),
      status: 404,
      body: { message: "no such VM" },
    },
  ]);
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.clone.execute(
        asArgs({ id: "gone", srId: "sr-alpha", sync: true, _fetch: f }),
        context,
      ),
    Error,
  );
  // Only the Rule-5 verify GET happened — no clone POST.
  assertEquals(calls.length, 1);
  assertEquals(calls[0].method, "GET");
});

Deno.test("getTask: default GETs current state (no wait) and records a task snapshot", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/tasks/task-9"),
      body: {
        id: "task-9",
        status: "pending",
        properties: { name: "remoteCopyVm", progress: 0.42 },
      },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.getTask.execute(
    asArgs({ id: "task-9", wait: false, _fetch: f }),
    context,
  );
  // Non-blocking: no wait param at all.
  assertEquals(calls[0].url.includes("wait="), false);
  // Recorded as an inventory/task snapshot with the raw task in items[0].
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "inventory");
  assertEquals(writes[0].name, "task");
  assertEquals(writes[0].data.kind, "task");
  const items = writes[0].data.items as Array<Record<string, unknown>>;
  assertEquals(items[0].uuid, "task-9");
  const raw = items[0].raw as Record<string, unknown>;
  assertEquals(raw.status, "pending");
  assertEquals(
    (raw.properties as Record<string, unknown>).progress,
    0.42,
  );
});

Deno.test("getTask: wait=true long-polls with the boolean form", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/tasks/task-9"),
      body: { id: "task-9", status: "success", result: "vm-async" },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.getTask.execute(
    asArgs({ id: "task-9", wait: true, _fetch: f }),
    context,
  );
  assertEquals(calls[0].url.includes("wait=true"), true);
  assertEquals(calls[0].url.includes("wait=result"), false);
  const items = writes[0].data.items as Array<Record<string, unknown>>;
  assertEquals(items[0].uuid, "task-9");
  assertEquals((items[0].raw as Record<string, unknown>).status, "success");
});

Deno.test("getTask: percent-encodes the task id", async () => {
  const { f, calls } = router([
    { match: (_u, m) => m === "GET", body: { id: "t/9", status: "success" } },
  ]);
  const { context } = stubContext();
  await model.methods.getTask.execute(
    asArgs({ id: "t/9", wait: false, _fetch: f }),
    context,
  );
  assertEquals(calls[0].url.includes("/tasks/t%2F9"), true);
});

// ---------------------------------------------------------------------------
// VIF attach (attachVif)
// ---------------------------------------------------------------------------

Deno.test("attachVif: verifies the VM, POSTs the VIF with the MAC, records a vif resource", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && /\/vms\/vm-1$/.test(u.split("?")[0]),
      body: { uuid: "vm-1", VIFs: [] },
    },
    {
      // Confirmed endpoint: POST /rest/v0/vifs (not /vms/{id}/vifs).
      match: (u, m) => m === "POST" && /\/vifs$/.test(u.split("?")[0]),
      body: { id: "vif-new" },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/vifs/vif-new"),
      body: {
        uuid: "vif-new",
        MAC: "00:50:56:00:7c:40",
        "$network": "net-wan",
        attached: true,
      },
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.attachVif.execute(
    asArgs({
      id: "vm-1",
      network: "net-wan",
      mac: "00:50:56:00:7c:40",
      attached: true,
      _fetch: f,
    }),
    context,
  );
  // verify GET (scan, no existing VIFs), create POST, re-read GET.
  assertEquals(calls.map((c) => c.method), ["GET", "POST", "GET"]);
  // The POST hit the standalone /vifs route with the VM/network as body keys.
  assertEquals(/\/rest\/v0\/vifs$/.test(calls[1].url.split("?")[0]), true);
  const body = JSON.parse(calls[1].body ?? "{}");
  assertEquals(body.vmId, "vm-1");
  assertEquals(body.networkId, "net-wan");
  assertEquals(body.MAC, "00:50:56:00:7c:40");
  // Recorded a dedicated `vif` binding resource {uuid,mac,network,attached}.
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "vif");
  assertEquals(writes[0].name, "vif:vif-new");
  assertEquals(writes[0].data.uuid, "vif-new");
  assertEquals(writes[0].data.mac, "00:50:56:00:7c:40");
  assertEquals(writes[0].data.network, "net-wan");
  assertEquals(writes[0].data.attached, true);
  assertEquals(res.dataHandles[0].name, "vif:vif-new");
});

Deno.test("attachVif: rejects a malformed MAC before any fetch", async () => {
  const { f, calls } = once({});
  const { context, writes } = stubContext();
  await assertRejects(
    () =>
      model.methods.attachVif.execute(
        asArgs({ id: "vm-1", network: "net-wan", mac: "nope", _fetch: f }),
        context,
      ),
    Error,
    "invalid MAC",
  );
  // No network call and no resource write on a validation failure.
  assertEquals(calls.length, 0);
  assertEquals(writes.length, 0);
});

Deno.test("attachVif: idempotent no-op when the MAC is already present (no POST)", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && /\/vms\/vm-1$/.test(u.split("?")[0]),
      body: { uuid: "vm-1", VIFs: ["vif-x"] },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/vifs/vif-x"),
      body: {
        uuid: "vif-x",
        MAC: "00:50:56:00:7C:40", // uppercase — must match case-insensitively
        "$network": "net-wan",
        attached: true,
      },
    },
    // A POST route exists but must never be reached.
    {
      match: (u, m) => m === "POST" && u.includes("/vifs"),
      body: { uuid: "x" },
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.attachVif.execute(
    asArgs({
      id: "vm-1",
      network: "net-wan",
      mac: "00:50:56:00:7c:40",
      _fetch: f,
    }),
    context,
  );
  // Only the scan (VM GET + VIF GET); the create POST is NOT issued.
  assertEquals(calls.map((c) => c.method), ["GET", "GET"]);
  assertEquals(calls.some((c) => c.method === "POST"), false);
  // Returned the existing VIF as the recorded binding.
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "vif");
  assertEquals(writes[0].name, "vif:vif-x");
  assertEquals(writes[0].data.uuid, "vif-x");
  assertEquals(writes[0].data.network, "net-wan");
  assertEquals(res.dataHandles[0].name, "vif:vif-x");
});

Deno.test("attachVif: MAC hit on a DIFFERENT network throws and never POSTs", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && /\/vms\/vm-1$/.test(u.split("?")[0]),
      body: { uuid: "vm-1", VIFs: ["vif-x"] },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/vifs/vif-x"),
      body: {
        uuid: "vif-x",
        MAC: "00:50:56:00:7c:40",
        "$network": "net-lan", // same MAC, but a DIFFERENT network
        attached: true,
      },
    },
    // A POST route exists but must never be reached on the conflict.
    {
      match: (u, m) => m === "POST" && u.includes("/vifs"),
      body: { uuid: "x" },
    },
  ]);
  const { context, writes } = stubContext();
  await assertRejects(
    () =>
      model.methods.attachVif.execute(
        asArgs({
          id: "vm-1",
          network: "net-wan",
          mac: "00:50:56:00:7c:40",
          _fetch: f,
        }),
        context,
      ),
    Error,
    "already exists on network net-lan",
  );
  // Only the scan ran; no create POST, no resource write on the conflict.
  assertEquals(calls.map((c) => c.method), ["GET", "GET"]);
  assertEquals(calls.some((c) => c.method === "POST"), false);
  assertEquals(writes.length, 0);
});

Deno.test("attachVif: the attached flag reaches the create body (attached=false)", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && /\/vms\/vm-1$/.test(u.split("?")[0]),
      body: { uuid: "vm-1", VIFs: [] },
    },
    {
      match: (u, m) => m === "POST" && /\/vifs$/.test(u.split("?")[0]),
      body: { id: "vif-new" },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/vifs/vif-new"),
      body: {
        uuid: "vif-new",
        MAC: "00:50:56:00:7c:40",
        "$network": "net-wan",
        attached: false,
      },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.attachVif.execute(
    asArgs({
      id: "vm-1",
      network: "net-wan",
      mac: "00:50:56:00:7c:40",
      attached: false,
      _fetch: f,
    }),
    context,
  );
  // The create body carried the explicit currently_attached=false flag.
  const body = JSON.parse(calls[1].body ?? "{}");
  assertEquals(body.currently_attached, false);
  assertEquals(body.networkId, "net-wan");
  assertEquals(writes[0].data.attached, false);
});

Deno.test("attachVif: a missing VM (404 on verify) never issues the create POST", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/vms/gone"),
      status: 404,
      body: { error: "not found" },
    },
    { match: (_u, m) => m === "POST", body: { uuid: "x" } },
  ]);
  const { context, writes } = stubContext();
  await assertRejects(
    () =>
      model.methods.attachVif.execute(
        asArgs({
          id: "gone",
          network: "net-wan",
          mac: "00:50:56:00:7c:40",
          _fetch: f,
        }),
        context,
      ),
    Error,
    "HTTP 404",
  );
  assertEquals(calls.map((c) => c.method), ["GET"]); // POST never reached
  assertEquals(writes.length, 0);
});

Deno.test("attachVif: percent-encodes the VM id and the re-read VIF id", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/vms/v%2Fm"),
      body: { uuid: "v/m", VIFs: [] },
    },
    {
      match: (u, m) => m === "POST" && /\/vifs$/.test(u.split("?")[0]),
      body: { id: "a/b" },
    },
    {
      match: (u, m) => m === "GET" && u.includes("/vifs/a%2Fb"),
      body: { uuid: "a/b", MAC: "00:50:56:00:7c:40", attached: true },
    },
  ]);
  const { context } = stubContext();
  await model.methods.attachVif.execute(
    asArgs({
      id: "v/m",
      network: "net-wan",
      mac: "00:50:56:00:7c:40",
      _fetch: f,
    }),
    context,
  );
  // The VM id is percent-encoded in the verify GET path; the standalone /vifs
  // create carries the (raw) VM id in the JSON body, not the path.
  assertEquals(calls[0].url.includes("/vms/v%2Fm"), true);
  assertEquals(/\/rest\/v0\/vifs$/.test(calls[1].url.split("?")[0]), true);
  assertEquals(JSON.parse(calls[1].body ?? "{}").vmId, "v/m");
  // The VIF id returned by create is percent-encoded in the re-read GET path.
  assertEquals(calls[2].url.includes("/vifs/a%2Fb"), true);
  assertEquals(calls[2].url.includes("/vifs/a/b"), false);
});

// ---------------------------------------------------------------------------
// VM CPU/memory edit (setVm)
// ---------------------------------------------------------------------------

Deno.test("setVm: PATCHes only the provided field (cpus) and re-snapshots", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/vms/vm-1"),
      body: { uuid: "vm-1", power_state: "Halted", CPUs: { number: 4 } },
    },
    { match: (u, m) => m === "PATCH" && u.includes("/vms/vm-1"), body: "" },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.setVm.execute(
    asArgs({ id: "vm-1", cpus: 4, _fetch: f }),
    context,
  );
  // verify GET, PATCH, snapshot GET.
  assertEquals(calls.map((c) => c.method), ["GET", "PATCH", "GET"]);
  const body = JSON.parse(calls[1].body ?? "{}");
  assertEquals(body.CPUs, 4);
  assertEquals("memory" in body, false); // only the provided field
  // Re-snapshotted the VM into the `vm` resource.
  assertEquals(writes[0].spec, "vm");
  assertEquals(writes[0].name, "vm:vm-1");
  assertEquals(res.dataHandles[0].name, "vm:vm-1");
});

Deno.test("setVm: PATCH carries only memory when only memory is set", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/vms/vm-1"),
      body: { uuid: "vm-1", power_state: "halted" }, // lowercase tolerated
    },
    { match: (u, m) => m === "PATCH" && u.includes("/vms/vm-1"), body: "" },
  ]);
  const { context } = stubContext();
  await model.methods.setVm.execute(
    asArgs({ id: "vm-1", memory: 8589934592, _fetch: f }),
    context,
  );
  const body = JSON.parse(calls[1].body ?? "{}");
  assertEquals(body.memory, 8589934592);
  assertEquals("CPUs" in body, false);
});

Deno.test("setVm: refuses a running VM with zero mutation", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/vms/vm-1"),
      body: { uuid: "vm-1", power_state: "Running" },
    },
    { match: (_u, m) => m === "PATCH", body: "" },
  ]);
  const { context, writes } = stubContext();
  await assertRejects(
    () =>
      model.methods.setVm.execute(
        asArgs({ id: "vm-1", cpus: 4, _fetch: f }),
        context,
      ),
    Error,
    "not halted",
  );
  assertEquals(calls.map((c) => c.method), ["GET"]); // PATCH never reached
  assertEquals(writes.length, 0);
});

Deno.test("setVm: rejects when neither cpus nor memory is provided (no fetch)", async () => {
  const { f, calls } = once({});
  const { context, writes } = stubContext();
  await assertRejects(
    () =>
      model.methods.setVm.execute(
        asArgs({ id: "vm-1", _fetch: f }),
        context,
      ),
    Error,
    "at least one",
  );
  assertEquals(calls.length, 0);
  assertEquals(writes.length, 0);
});

// ---------------------------------------------------------------------------
// importFromUrl: format inference, VDI import seam, and the no-conversion path
// ---------------------------------------------------------------------------

Deno.test("inferImageFormat() maps extensions (and query strings) to formats", () => {
  assertEquals(inferImageFormat("https://x/Rocky-10.qcow2"), "qcow2");
  assertEquals(inferImageFormat("https://x/img.qcow2c?sig=abc"), "qcow2");
  assertEquals(inferImageFormat("https://x/disk.VHD"), "vhd");
  assertEquals(inferImageFormat("https://x/disk.raw"), "raw");
  assertEquals(inferImageFormat("https://x/cloud.img"), "raw");
  assertEquals(inferImageFormat("https://x/vm.vmdk"), "vmdk");
  assertEquals(inferImageFormat("https://x/no-extension"), "unknown");
});

/** Bytes -> a one-shot ReadableStream, for stubbing the binary seam. */
function bytesStream(b: Uint8Array): ReadableStream<Uint8Array> {
  return ReadableStream.from([b]);
}

/** A recorded binary-seam call (body drained to a byte count). */
interface StreamRec {
  url: string;
  method: string;
  headers?: Record<string, string>;
  bodyBytes: number;
}

/**
 * A {@link StreamFetchLike} stub: GETs return `download` bytes as a stream;
 * everything else (the upload POST) drains the request body and returns
 * `uploadText` (the new VDI uuid) with `uploadStatus`.
 */
function streamStub(opts: {
  download?: Uint8Array;
  uploadText?: string;
  uploadStatus?: number;
}): { f: StreamFetchLike; calls: StreamRec[] } {
  const calls: StreamRec[] = [];
  const f: StreamFetchLike = async (url, init) => {
    const method = init?.method ?? "GET";
    let bodyBytes = 0;
    if (init?.body instanceof ReadableStream) {
      for await (const chunk of init.body) bodyBytes += chunk.byteLength;
    } else if (init?.body) {
      bodyBytes = (init.body as Uint8Array).byteLength;
    }
    calls.push({ url, method, headers: init?.headers, bodyBytes });
    const isGet = method === "GET";
    const status = isGet ? 200 : (opts.uploadStatus ?? 200);
    const resp: StreamResponse = {
      ok: status >= 200 && status < 300,
      status,
      statusText: "",
      body: isGet
        ? bytesStream(opts.download ?? new Uint8Array([1, 2, 3]))
        : null,
      text: () => Promise.resolve(isGet ? "" : (opts.uploadText ?? "vdi-new")),
    };
    return resp;
  };
  return { f, calls };
}

Deno.test("makeStreamFetch() builds a transport function", () => {
  assertEquals(typeof makeStreamFetch(CFG), "function");
});

Deno.test("importVdiToSr: POSTs disk bytes, adds the raw flag only for raw, returns the uuid", async () => {
  const raw = streamStub({ uploadText: "vdi-raw" });
  const uuid = await importVdiToSr(
    CFG,
    raw.f,
    "sr-1",
    { nameLabel: "my disk", nameDescription: "d", raw: true },
    bytesStream(new Uint8Array([9, 9, 9, 9])),
  );
  assertEquals(uuid, "vdi-raw");
  const up = raw.calls[0];
  assertEquals(up.method, "POST");
  assertEquals(up.url.includes("/srs/sr-1/vdis?"), true);
  assertEquals(up.url.includes("name_label=my%20disk"), true);
  assertEquals(up.url.includes("name_description=d"), true);
  assertEquals(/[?&]raw(&|$)/.test(up.url), true); // bare flag, not raw=
  assertEquals(up.headers?.["Cookie"], "authenticationToken=TOK");
  assertEquals(up.headers?.["Content-Type"], "application/octet-stream");
  assertEquals(up.bodyBytes, 4);

  const vhd = streamStub({ uploadText: "vdi-vhd" });
  await importVdiToSr(
    CFG,
    vhd.f,
    "sr-1",
    { nameLabel: "v", raw: false },
    bytesStream(new Uint8Array([1])),
  );
  assertEquals(/[?&]raw(&|$)/.test(vhd.calls[0].url), false); // no raw flag -> VHD
});

Deno.test("importVdiToSr: raises on a non-2xx upload", async () => {
  const bad = streamStub({ uploadStatus: 500, uploadText: "boom" });
  await assertRejects(
    () =>
      importVdiToSr(
        CFG,
        bad.f,
        "sr-1",
        { nameLabel: "v", raw: false },
        bytesStream(new Uint8Array([1])),
      ),
    Error,
    "HTTP 500",
  );
});

Deno.test("importFromUrl: vhd source uploads as-is (no conversion), records the VDI", async () => {
  // JSON seam: the SR existence check.
  const { f: jsonF } = once({ uuid: "sr-1" });
  // Binary seam: download a few bytes, capture the upload, return the uuid.
  const { f: netF, calls } = streamStub({
    download: new Uint8Array([7, 7, 7, 7, 7]),
    uploadText: "vdi-9",
  });
  const { context, writes } = stubContext();
  await model.methods.importFromUrl.execute(
    asArgs({
      url: "https://mirror/Rocky-10-GenericCloud.vhd",
      srId: "sr-1",
      nameLabel: "rocky10-genericcloud",
      // asArgs bypasses zod, so pass the values zod would default (sourceFormat
      // auto -> inferred "vhd" from the URL, so no qemu-img conversion fires).
      sourceFormat: "auto",
      uploadFormat: "vhd",
      keepWorkDir: false,
      _fetch: jsonF,
      _netFetch: netF,
    }),
    context,
  );
  const get = calls.find((c) => c.method === "GET");
  const post = calls.find((c) => c.method === "POST");
  assertEquals(get?.url, "https://mirror/Rocky-10-GenericCloud.vhd");
  assertEquals(post?.url.includes("/srs/sr-1/vdis?"), true);
  assertEquals(/[?&]raw(&|$)/.test(post?.url ?? ""), false); // vhd -> no raw flag
  assertEquals(post?.bodyBytes, 5); // uploaded the downloaded bytes verbatim
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "inventory");
  const vdiItem = (writes[0].data.items as Array<Record<string, unknown>>)[0];
  assertEquals(vdiItem.uuid, "vdi-9");
  assertEquals((vdiItem.raw as Record<string, unknown>).wireFormat, "vhd");
});

Deno.test("importVdiToSr: parses XO's { id } object response (live shape)", async () => {
  const { f } = streamStub({ uploadText: '{"id":"853b53a6-04e0-4d08"}' });
  const uuid = await importVdiToSr(
    CFG,
    f,
    "sr-1",
    { nameLabel: "v", raw: false },
    bytesStream(new Uint8Array([1])),
  );
  assertEquals(uuid, "853b53a6-04e0-4d08");
});

// ---------------------------------------------------------------------------
// attachVdi / detachVdi (piece 2: VDI -> bootable VM via VBD)
// ---------------------------------------------------------------------------

Deno.test("attachVdi: POSTs a VBD (VM+VDI+bootable), returns the id, snapshots the VM", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "POST" && u.endsWith("/vbds"),
      body: { id: "vbd-1" },
    },
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-1"),
      body: { uuid: "vm-1", name_label: "rocky" },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.attachVdi.execute(
    asArgs({
      vmId: "vm-1",
      vdiId: "vdi-9",
      bootable: true,
      mode: "RW",
      userdevice: "0",
      _fetch: f,
    }),
    context,
  );
  const post = calls.find((c) => c.method === "POST");
  assertEquals(post?.url.endsWith("/vbds"), true);
  const body = JSON.parse(post?.body ?? "{}");
  assertEquals(body.VM, "vm-1");
  assertEquals(body.VDI, "vdi-9");
  assertEquals(body.bootable, true);
  assertEquals(body.mode, "RW");
  assertEquals(body.userdevice, "0");
  // Records the VBD and re-snapshots the VM.
  assertEquals(writes.map((w) => w.spec), ["inventory", "vm"]);
  assertEquals(
    (writes[0].data.items as Array<Record<string, unknown>>)[0].uuid,
    "vbd-1",
  );
});

Deno.test("attachVdi: raises when XO returns no VBD id", async () => {
  const { f } = router([
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-1"),
      body: { uuid: "vm-1" },
    },
    { match: (u, m) => m === "POST" && u.endsWith("/vbds"), body: {} },
  ]);
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.attachVdi.execute(
        asArgs({
          vmId: "vm-1",
          vdiId: "vdi-9",
          bootable: false,
          mode: "RW",
          _fetch: f,
        }),
        context,
      ),
    Error,
    "no VBD id",
  );
});

Deno.test("detachVdi: verifies the VBD then DELETEs it", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.endsWith("/vbds/vbd-1"),
      body: { uuid: "vbd-1" },
    },
    {
      match: (u, m) => m === "DELETE" && u.endsWith("/vbds/vbd-1"),
      status: 204,
      body: "",
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.detachVdi.execute(
    asArgs({ vbdId: "vbd-1", _fetch: f }),
    context,
  );
  assertEquals(calls.map((c) => c.method), ["GET", "DELETE"]);
  assertEquals(writes.length, 0);
});

// ---------------------------------------------------------------------------
// Review-driven hardening: guardAuthToken, redactUrl, maxBytes cap,
// empty-uuid guard, and attachVdi's best-effort post-write snapshot.
// ---------------------------------------------------------------------------

Deno.test("guardAuthToken() throws on CR/LF/semicolon, passes a clean token", () => {
  for (const bad of ["a\nb", "a\rb", "a;b"]) {
    assertThrows(() => guardAuthToken(bad), Error, "illegal characters");
  }
  guardAuthToken("TOK-clean_123"); // no throw
});

Deno.test("redactUrl() strips a credential-bearing query, keeps origin+path", () => {
  assertEquals(
    redactUrl(
      "https://bucket.s3.amazonaws.com/img.qcow2?X-Amz-Signature=deadbeef",
    ),
    "https://bucket.s3.amazonaws.com/img.qcow2?<redacted>",
  );
  assertEquals(
    redactUrl("https://mirror.example.org/Rocky-10.qcow2"),
    "https://mirror.example.org/Rocky-10.qcow2",
  );
  // Non-URL input: at least drop anything after ? or #.
  assertEquals(redactUrl("not a url?secret=1"), "not a url");
});

Deno.test("importVdiToSr: guards the auth token on the binary seam too", async () => {
  const { f } = streamStub({ uploadText: "vdi-x" });
  const badCfg = {
    ...(CFG as object),
    authToken: "tok\ninject",
  } as unknown as Cfg;
  await assertRejects(
    () =>
      importVdiToSr(
        badCfg,
        f,
        "sr-1",
        { nameLabel: "v", raw: false },
        bytesStream(new Uint8Array([1])),
      ),
    Error,
    "illegal characters",
  );
});

Deno.test("importVdiToSr: a 2xx with no parseable uuid throws (orphan guard)", async () => {
  const { f } = streamStub({ uploadText: "", uploadStatus: 200 });
  await assertRejects(
    () =>
      importVdiToSr(
        CFG,
        f,
        "sr-1",
        { nameLabel: "v", raw: false },
        bytesStream(new Uint8Array([1])),
      ),
    Error,
    "no VDI uuid",
  );
});

Deno.test("downloadToFile: maxBytes aborts an over-cap download", async () => {
  const { f } = streamStub({ download: new Uint8Array(100) });
  const dest = await Deno.makeTempFile();
  try {
    await assertRejects(
      () => downloadToFile(f, "https://x/big.raw", dest, { maxBytes: 16 }),
      Error,
      "maxBytes",
    );
  } finally {
    await Deno.remove(dest).catch(() => {});
  }
});

Deno.test("attachVdi: a post-write VM snapshot failure does NOT throw (no dup-VBD retry)", async () => {
  // GET /vms/vm-1 succeeds for the pre-write verify, POST /vbds succeeds, then
  // the post-write snapshot's writeResource('vm') fails. attachVdi must still
  // resolve (returning the recorded VBD handle), not throw.
  const { f } = router([
    {
      match: (u, m) => m === "POST" && u.endsWith("/vbds"),
      body: { id: "vbd-1" },
    },
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-1"),
      body: { uuid: "vm-1" },
    },
  ]);
  const { context, writes } = stubContext();
  // Make only the 'vm' snapshot write fail (the inventory write still lands).
  const realWrite = context.writeResource;
  context.writeResource = (
    spec: string,
    name: string,
    data: Record<string, unknown>,
  ) =>
    spec === "vm"
      ? Promise.reject(new Error("transient snapshot store failure"))
      : realWrite(spec, name, data);
  const out = await model.methods.attachVdi.execute(
    asArgs({
      vmId: "vm-1",
      vdiId: "vdi-9",
      bootable: true,
      mode: "RW",
      _fetch: f,
    }),
    context,
  );
  // Resolves with just the VBD handle; the attachedVbd record was persisted.
  assertEquals(out.dataHandles.length, 1);
  assertEquals(writes.map((w) => w.spec), ["inventory"]);
  assertEquals(
    (writes[0].data.items as Array<Record<string, unknown>>)[0].uuid,
    "vbd-1",
  );
});

Deno.test("listVbds: fans a VM's VBDs into an inventory snapshot (device + raw)", async () => {
  const { f } = router([
    {
      match: (u, m) => m === "GET" && u.endsWith("/vms/vm-1"),
      body: { uuid: "vm-1", VBDs: ["vbd-a", "vbd-b"] },
    },
    {
      match: (u, m) => m === "GET" && u.endsWith("/vbds/vbd-a"),
      body: { uuid: "vbd-a", device: "0", bootable: false, VDI: "vdi-scratch" },
    },
    {
      match: (u, m) => m === "GET" && u.endsWith("/vbds/vbd-b"),
      body: { uuid: "vbd-b", device: "3", is_cd_drive: true, VDI: "vdi-cloud" },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listVbds.execute(
    asArgs({ id: "vm-1", _fetch: f }),
    context,
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "inventory");
  assertEquals(writes[0].data.kind, "vbds");
  const items = writes[0].data.items as Array<Record<string, unknown>>;
  assertEquals(items.length, 2);
  assertEquals(items[0].uuid, "vbd-a");
  assertEquals(items[0].name_label, "0"); // device position
  assertEquals((items[0].raw as Record<string, unknown>).VDI, "vdi-scratch");
});

// ---------------------------------------------------------------------------
// Token management (listAuthTokens / createAuthToken) — VSA-2026-062 IR
// ---------------------------------------------------------------------------

// A realistic (43-char) XO bearer-token id; the raw value must never land in
// any persisted resource or log.
const TOK_SECRET = "ioJRvxbO-uTIdwfJTlADEoh2kutgDZRenOGtRFLtoio";

Deno.test("listAuthTokens: masks the id, never persists the raw secret, trims users", async () => {
  const { f } = router([
    {
      match: (u, m) =>
        m === "GET" && u.includes("users/me/authentication_tokens"),
      body: [{
        id: TOK_SECRET,
        description: "firefox",
        created_at: 111,
        expiration: 222,
        client: { id: "c1" },
        user_id: "u-1",
        last_uses: { "10.0.0.1": { timestamp: 1 } },
        extraSecretField: "should-not-persist",
      }],
    },
    {
      match: (u, m) => m === "GET" && u.includes("/users?"),
      body: [{
        id: "u-1",
        email: "admin@example.com",
        permission: "admin",
        groups: [],
        extra: "drop",
      }],
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listAuthTokens.execute(asArgs({ _fetch: f }), context);

  const blob = JSON.stringify(writes);
  // The raw bearer secret must never appear in any persisted resource.
  assertEquals(blob.includes(TOK_SECRET), false);
  // Nor any field blanket-copied from the token/user object.
  assertEquals(blob.includes("should-not-persist"), false);
  assertEquals(blob.includes("drop"), false);

  const tokRes = writes.find((w) => w.name === "authTokens");
  assertEquals(tokRes !== undefined, true);
  const item = (tokRes!.data.items as Array<Record<string, unknown>>)[0];
  assertEquals(String(item.uuid).includes("...(43)..."), true);
  assertEquals(item.uuid !== TOK_SECRET, true);
  // raw carries metadata but NOT the id
  assertEquals("id" in (item.raw as Record<string, unknown>), false);
});

Deno.test("listAuthTokens: fully masks a short token id (no reconstruction)", async () => {
  const { f } = router([
    {
      match: (u, m) =>
        m === "GET" && u.includes("users/me/authentication_tokens"),
      body: [{ id: "abcd1234", description: "s" }], // 8 chars
    },
    { match: (u, m) => m === "GET" && u.includes("/users?"), body: [] },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listAuthTokens.execute(asArgs({ _fetch: f }), context);
  const tokRes = writes.find((w) => w.name === "authTokens")!;
  const item = (tokRes.data.items as Array<Record<string, unknown>>)[0];
  assertEquals(item.uuid, "***(8)***");
  assertEquals(JSON.stringify(writes).includes("abcd1234"), false);
});

Deno.test("createAuthToken dryRun: records a plan and makes no XO call", async () => {
  const { f, calls } = router([]);
  const { context, writes } = stubContext();
  await model.methods.createAuthToken.execute(
    asArgs({
      description: "swamp",
      clientId: "",
      force: false,
      dryRun: true,
      _fetch: f,
    }),
    context,
  );
  assertEquals(calls.length, 0);
  assertEquals(writes.some((w) => w.name === "authTokenPlan"), true);
});

Deno.test("createAuthToken mint: parses nested {token:{id}}, vaults secret, keeps it out of logs", async () => {
  const NEW = "NEWSECRET-abcdefghijklmnopqrstuvwxyz0123456789";
  const { f, calls } = router([
    {
      match: (u, m) =>
        m === "POST" && u.includes("users/authentication_tokens"),
      body: {
        token: {
          id: NEW,
          created_at: 10,
          expiration: 20,
          description: "swamp",
          client: { id: "c1" },
          user_id: "u-1",
        },
      },
    },
  ]);
  const { context, writes, logs } = stubContext();
  await model.methods.createAuthToken.execute(
    asArgs({
      description: "swamp",
      clientId: "c1",
      force: true, // skips the idempotency GET
      dryRun: false,
      _fetch: f,
    }),
    context,
  );
  assertEquals(calls.length, 1);
  assertEquals(calls[0].method, "POST");
  const mint = writes.find((w) => w.spec === "mintedToken")!;
  assertEquals(mint.data.tokenId, NEW); // the sensitive (vaulted) field
  assertEquals(mint.name.startsWith("mintedToken-"), true);
  // the secret must never appear in a log line
  assertEquals(JSON.stringify(logs).includes(NEW), false);
});

Deno.test("createAuthToken: {token:null} fails gracefully (no raw TypeError)", async () => {
  const { f } = router([
    {
      match: (u, m) =>
        m === "POST" && u.includes("users/authentication_tokens"),
      body: { token: null },
    },
  ]);
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.createAuthToken.execute(
        asArgs({
          description: "x",
          clientId: "",
          force: true,
          dryRun: false,
          _fetch: f,
        }),
        context,
      ),
    Error,
    "no token id",
  );
});

Deno.test("createAuthToken: refuses a duplicate (same description+clientId) unless force", async () => {
  const { f, calls } = router([
    {
      match: (u, m) =>
        m === "GET" && u.includes("users/me/authentication_tokens"),
      body: [{ description: "swamp", client: { id: "c1" } }],
    },
    {
      match: (u, m) =>
        m === "POST" && u.includes("users/authentication_tokens"),
      body: { token: { id: "X" } },
    },
  ]);
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.createAuthToken.execute(
        asArgs({
          description: "swamp",
          clientId: "c1",
          force: false,
          dryRun: false,
          _fetch: f,
        }),
        context,
      ),
    Error,
    "already exists",
  );
  assertEquals(calls.some((c) => c.method === "POST"), false);
});

Deno.test("createAuthToken: fail-closed when the token list is not an array", async () => {
  const { f } = router([
    {
      match: (u, m) =>
        m === "GET" && u.includes("users/me/authentication_tokens"),
      body: { unexpected: true },
    },
  ]);
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.createAuthToken.execute(
        asArgs({
          description: "swamp",
          clientId: "",
          force: false,
          dryRun: false,
          _fetch: f,
        }),
        context,
      ),
    Error,
    "fail-closed",
  );
});

// ---------------------------------------------------------------------------
// WebSocket JSON-RPC transport (xoJsonRpc) via an injected fake RpcConnect
// ---------------------------------------------------------------------------

/** Emit one inbound frame to xoJsonRpc's onMessage handler. */
type Emit = (frame: RpcFrame) => void;

/** A parsed outbound JSON-RPC request recorded by the fake socket. */
interface SentRpc {
  jsonrpc?: string;
  id?: number;
  method?: string;
  params?: Record<string, unknown>;
}

/**
 * Build a fake {@link RpcConnect} analogous to the {@link router}/{@link once}
 * fetch fakes: `opened` resolves immediately, every outbound `send` is recorded
 * and parsed, and a `reply` callback scripts the inbound frames per send. No
 * real socket, no network, no token minting.
 */
function fakeRpc(
  reply: (sent: SentRpc, emit: Emit) => void,
  opts: { opened?: Promise<void> } = {},
): { connect: RpcConnect; sends: SentRpc[]; closedCount: () => number } {
  const sends: SentRpc[] = [];
  let closed = 0;
  let onMsg: Emit = () => {};
  const connect: RpcConnect = (): RpcSocket => ({
    opened: opts.opened ?? Promise.resolve(),
    send: (data: string) => {
      const parsed = JSON.parse(data) as SentRpc;
      sends.push(parsed);
      // Reply on a microtask so onMessage is registered and the handshake can
      // drive the next send (sign-in -> method) exactly as the real flow does.
      queueMicrotask(() => reply(parsed, (frame) => onMsg(frame)));
    },
    close: () => {
      closed++;
    },
    onMessage: (cb) => {
      onMsg = cb;
    },
    onError: () => {},
    onClose: () => {},
  });
  return { connect, sends, closedCount: () => closed };
}

/** Reply to a sign-in send with success (id 1); subclass per-test for the call. */
function onSignInOk(sent: SentRpc, emit: Emit): boolean {
  if (sent.method === "session.signInWithToken") {
    emit({
      kind: "text",
      data: JSON.stringify({ jsonrpc: "2.0", id: 1, result: true }),
    });
    return true;
  }
  return false;
}

Deno.test("xoJsonRpc: success — signs in first, sends method, unwraps result", async () => {
  const { connect, sends } = fakeRpc((sent, emit) => {
    if (onSignInOk(sent, emit)) return;
    // The call (id 2) is answered with a result object.
    emit({
      kind: "text",
      data: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        result: { version: "5.111.1" },
      }),
    });
  });
  const result = await xoJsonRpc(
    CFG,
    "system.getServerVersion",
    {},
    {},
    connect,
  );
  assertEquals(result, { version: "5.111.1" });
  // Handshake ordering + id correlation.
  assertEquals(sends.length, 2);
  assertEquals(sends[0].method, "session.signInWithToken");
  assertEquals(sends[0].id, 1);
  assertEquals((sends[0].params as { token: string }).token, "TOK");
  assertEquals(sends[1].method, "system.getServerVersion");
  assertEquals(sends[1].id, 2);
});

Deno.test("xoJsonRpc: JSON-RPC error rejects with code+message, not token/params", async () => {
  const { connect } = fakeRpc((sent, emit) => {
    if (onSignInOk(sent, emit)) return;
    emit({
      kind: "text",
      data: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        error: { code: 10, message: "unknown method", data: { x: 1 } },
      }),
    });
  });
  const err = await assertRejects(
    () => xoJsonRpc(CFG, "no.such", { secret: "PARAMVAL" }, {}, connect),
    Error,
  );
  assertEquals(err.message.includes("10"), true);
  assertEquals(err.message.includes("unknown method"), true);
  assertEquals(err.message.includes("TOK"), false);
  assertEquals(err.message.includes("PARAMVAL"), false);
});

Deno.test("xoJsonRpc: timeout — never-answers rejects within deadline and closes", async () => {
  const { connect, closedCount } = fakeRpc(() => {
    // Never emit a reply: the call hangs until the deadline fires.
  });
  const t0 = Date.now();
  await assertRejects(
    () =>
      xoJsonRpc(CFG, "system.getServerVersion", {}, { timeoutMs: 40 }, connect),
    Error,
    "timed out",
  );
  // Rejected on the deadline (generous upper bound), and the socket was closed
  // so the per-model lock releases.
  assertEquals(Date.now() - t0 < 2000, true);
  assertEquals(closedCount() >= 1, true);
});

Deno.test("xoJsonRpc: non-text (binary) frame rejects as malformed", async () => {
  const { connect } = fakeRpc((sent, emit) => {
    if (onSignInOk(sent, emit)) return;
    emit({ kind: "binary" });
  });
  await assertRejects(
    () => xoJsonRpc(CFG, "system.getServerVersion", {}, {}, connect),
    Error,
    "malformed RPC response",
  );
});

Deno.test("xoJsonRpc: non-JSON text frame rejects as malformed", async () => {
  const { connect } = fakeRpc((sent, emit) => {
    if (onSignInOk(sent, emit)) return;
    emit({ kind: "text", data: "not json {" });
  });
  await assertRejects(
    () => xoJsonRpc(CFG, "system.getServerVersion", {}, {}, connect),
    Error,
    "malformed RPC response",
  );
});

Deno.test("xoJsonRpc: frame missing both result and error rejects as malformed", async () => {
  const { connect } = fakeRpc((sent, emit) => {
    if (onSignInOk(sent, emit)) return;
    emit({ kind: "text", data: JSON.stringify({ jsonrpc: "2.0", id: 2 }) });
  });
  await assertRejects(
    () => xoJsonRpc(CFG, "system.getServerVersion", {}, {}, connect),
    Error,
    "no result",
  );
});

Deno.test("xoJsonRpc: id-mismatched terminal frame rejects as malformed", async () => {
  const { connect } = fakeRpc((sent, emit) => {
    if (onSignInOk(sent, emit)) return;
    emit({
      kind: "text",
      data: JSON.stringify({ jsonrpc: "2.0", id: 99, result: "nope" }),
    });
  });
  await assertRejects(
    () => xoJsonRpc(CFG, "system.getServerVersion", {}, {}, connect),
    Error,
    "id mismatch",
  );
});

Deno.test("xoJsonRpc: id-null error frame is terminal malformed (not a timeout)", async () => {
  const { connect } = fakeRpc((sent, emit) => {
    if (onSignInOk(sent, emit)) return;
    // A server-side JSON-RPC parse/protocol error: id null, carries an error.
    emit({
      kind: "text",
      data: JSON.stringify({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: "Parse error" },
      }),
    });
  });
  const err = await assertRejects(
    () =>
      xoJsonRpc(
        CFG,
        "system.getServerVersion",
        {},
        { timeoutMs: 5000 },
        connect,
      ),
    Error,
    "malformed RPC response",
  );
  assertEquals(err.message.includes("-32700"), true);
  assertEquals(err.message.includes("Parse error"), true);
});

Deno.test("xoJsonRpc: interleaved no-id notification is ignored, result still returns", async () => {
  const { connect } = fakeRpc((sent, emit) => {
    if (onSignInOk(sent, emit)) return;
    // XO pushes an unsolicited object-update notification (no id) first.
    emit({
      kind: "text",
      data: JSON.stringify({
        jsonrpc: "2.0",
        method: "all",
        params: { foo: 1 },
      }),
    });
    emit({
      kind: "text",
      data: JSON.stringify({ jsonrpc: "2.0", id: 2, result: "5.0" }),
    });
  });
  const result = await xoJsonRpc(
    CFG,
    "system.getServerVersion",
    {},
    {},
    connect,
  );
  assertEquals(result, "5.0");
});

Deno.test("xoJsonRpc: sign-in failure rejects distinctly and never sends the method", async () => {
  const { connect, sends } = fakeRpc((sent, emit) => {
    if (sent.method === "session.signInWithToken") {
      emit({
        kind: "text",
        data: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          error: { code: 3, message: "authentication failed" },
        }),
      });
      return;
    }
    // Must never be reached.
    emit({
      kind: "text",
      data: JSON.stringify({ jsonrpc: "2.0", id: 2, result: "x" }),
    });
  });
  await assertRejects(
    () => xoJsonRpc(CFG, "system.getServerVersion", {}, {}, connect),
    Error,
    "sign-in failed",
  );
  // Only the sign-in frame was sent; the method frame was never dispatched.
  assertEquals(sends.length, 1);
  assertEquals(sends[0].method, "session.signInWithToken");
});

Deno.test("xoJsonRpc: no thrown message ever contains the auth token", async () => {
  const secretCfg = {
    ...(CFG as object),
    authToken: "SUPER-SECRET-TOKEN",
  } as unknown as Cfg;
  const { connect } = fakeRpc((sent, emit) => {
    if (onSignInOk(sent, emit)) return;
    emit({
      kind: "text",
      data: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        error: { code: 1, message: "boom" },
      }),
    });
  });
  const err = await assertRejects(
    () => xoJsonRpc(secretCfg, "system.getServerVersion", {}, {}, connect),
    Error,
  );
  assertEquals(err.message.includes("SUPER-SECRET-TOKEN"), false);
});

Deno.test("xoJsonRpc: a CR/LF/; token is rejected before the wire", async () => {
  const badCfg = {
    ...(CFG as object),
    authToken: "tok\r\ninjected",
  } as unknown as Cfg;
  const { connect, sends } = fakeRpc((sent, emit) => {
    onSignInOk(sent, emit);
  });
  await assertRejects(
    () => xoJsonRpc(badCfg, "system.getServerVersion", {}, {}, connect),
    Error,
    "illegal characters",
  );
  assertEquals(sends.length, 0);
});

// ---------------------------------------------------------------------------
// Pure transport helper: rpcWsUrl + the private-CA (caCert) limitation
// ---------------------------------------------------------------------------

Deno.test("rpcWsUrl: https -> wss, http -> ws, trailing slashes normalized", () => {
  assertEquals(rpcWsUrl("https://xo.example:443"), "wss://xo.example:443/api/");
  assertEquals(rpcWsUrl("http://xo.example:80"), "ws://xo.example:80/api/");
  // Trailing-slash normalization mirrors xoRequest's baseUrl.replace(/\/+$/,"").
  assertEquals(rpcWsUrl("https://xo.example///"), "wss://xo.example/api/");
});

Deno.test("xoJsonRpc: a private-CA (caCert) config rejects with a clear limitation", async () => {
  // The built-in WebSocket cannot present a custom CA, so a caCert must be
  // refused honestly (via the DEFAULT makeRpcConnect) rather than silently
  // ignored. No fake connect is injected: the default factory throws before any
  // socket is constructed, surfacing as a rejection (xoJsonRpc is async).
  const caCfg = {
    ...(CFG as object),
    caCert: "-----BEGIN CERTIFICATE-----",
  } as unknown as Cfg;
  await assertRejects(
    () => xoJsonRpc(caCfg, "system.getServerVersion", {}),
    Error,
    "not supported over WebSocket",
  );
});

// ---------------------------------------------------------------------------
// getServerVersion method + ServerVersionSchema conformance
// ---------------------------------------------------------------------------

Deno.test("getServerVersion: records a schema-valid serverVersion resource", async () => {
  const { connect, sends } = fakeRpc((sent, emit) => {
    if (onSignInOk(sent, emit)) return;
    emit({
      kind: "text",
      data: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        result: { version: "5.111.1" },
      }),
    });
  });
  const { context, writes } = stubContext();
  const res = await model.methods.getServerVersion.execute(
    asArgs({ _connect: connect }),
    context,
  );
  assertEquals(res.dataHandles.length, 1);
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "serverVersion");
  assertEquals(writes[0].name, "serverVersion");
  assertEquals(writes[0].data.version, "5.111.1");
  assertEquals(typeof writes[0].data.retrievedAt, "string");
  // The method RPC was exercised end to end through the transport.
  assertEquals(sends[1].method, "system.getServerVersion");
  // The recorded payload conforms to the REAL declared schema (not a stub),
  // so a schema mismatch fails the test rather than false-greening.
  const spec = model.resources.serverVersion.schema;
  const parsed = spec.parse(writes[0].data);
  assertEquals(parsed.version, "5.111.1");
});

// ---------------------------------------------------------------------------
// Backup repositories (remotes): helpers
// ---------------------------------------------------------------------------

Deno.test("redactRepoUrl() strips userinfo and query on a parseable URL", () => {
  const out = redactRepoUrl("smb://user:pass@host/share?x=1");
  assertEquals(out, "smb://host/share?<redacted>");
  // No credential or query VALUE survives.
  assertEquals(out.includes("user"), false);
  assertEquals(out.includes("pass"), false);
  assertEquals(out.includes("x=1"), false);
});

Deno.test("redactRepoUrl() keeps a credential-free URL readable", () => {
  assertEquals(redactRepoUrl("nfs://192.0.2.4/export"), "nfs://192.0.2.4/export");
  assertEquals(redactRepoUrl("file:///srv/backups"), "file:///srv/backups");
});

Deno.test("redactRepoUrl() fallback drops userinfo on an UNPARSEABLE string", () => {
  // A space in the authority makes new URL() throw; the fallback must still
  // remove the secret (userinfo) while keeping the host.
  const out = redactRepoUrl("smb://user:SEKRET@host badchar/share");
  assertEquals(out.includes("SEKRET"), false);
  assertEquals(out.includes("user"), false);
  // The host is retained (the fallback does not nuke everything).
  assertEquals(out.startsWith("smb://host"), true);
});

Deno.test("redactRepoUrl() fallback drops userinfo with a scheme-less authority", () => {
  // A protocol-relative URL with a space: new URL() throws, exercising the
  // fallback, which must still strip the userinfo while keeping the host.
  const out = redactRepoUrl("//user:SEKRET@ho st/share");
  assertEquals(out.includes("SEKRET"), false);
  assertEquals(out.includes("user"), false);
  assertEquals(out, "ho st");
});

Deno.test("rawObject() passes objects, wraps non-objects", () => {
  assertEquals(rawObject({ a: 1 }), { a: 1 });
  assertEquals(rawObject("tasks/abc"), { result: "tasks/abc" });
  assertEquals(rawObject(null), { result: null });
  assertEquals(rawObject([1, 2]), { result: [1, 2] });
});

Deno.test("extractTaskRef() finds task refs, else null", () => {
  assertEquals(extractTaskRef("/rest/v0/tasks/task-7"), "task-7");
  assertEquals(extractTaskRef("br-1"), null);
  assertEquals(extractTaskRef({ href: "/rest/v0/tasks/task-3" }), "task-3");
  assertEquals(extractTaskRef({ reclaimed: 5 }), null);
  assertEquals(extractTaskRef(null), null);
});

Deno.test("normalizeBackupRepository() redacts url and drops secret keys", () => {
  const repo = normalizeBackupRepository({
    id: "br-1",
    name: "box",
    type: "smb",
    url: "smb://user:SEKRET@host/share",
    enabled: true,
    password: "SEKRET",
    options: { password: "SEKRET", soft: "true" },
  });
  assertEquals(repo.id, "br-1");
  assertEquals(repo.name, "box");
  assertEquals(repo.type, "smb");
  assertEquals(repo.enabled, true);
  assertEquals(repo.urlRedacted, "smb://host/share");
  // The whole persisted row must be free of the secret.
  const blob = JSON.stringify(repo);
  assertEquals(blob.includes("SEKRET"), false);
  // options survives but with the password key dropped.
  assertEquals(
    repo.raw.options as Record<string, unknown>,
    { soft: "true" },
  );
});

Deno.test("normalizeBackupRepository() tolerates id/label aliases", () => {
  const repo = normalizeBackupRepository({ uuid: "br-9", label: "nas" });
  assertEquals(repo.id, "br-9");
  assertEquals(repo.name, "nas");
  assertEquals(repo.urlRedacted, null);
  assertEquals(repo.enabled, null);
});

// ---------------------------------------------------------------------------
// Backup repositories: method paths
// ---------------------------------------------------------------------------

/** True when any recorded write payload's JSON contains the needle. */
function anyWriteHas(
  writes: Array<{ data: Record<string, unknown> }>,
  needle: string,
): boolean {
  return writes.some((w) => JSON.stringify(w.data).includes(needle));
}

/** True when any captured log (msg or params) contains the needle. */
function anyLogHas(
  logs: Array<{ msg: string; params?: Record<string, unknown> }>,
  needle: string,
): boolean {
  return logs.some((l) =>
    l.msg.includes(needle) ||
    (l.params !== undefined && JSON.stringify(l.params).includes(needle))
  );
}

Deno.test("listBackupRepositories: fans a collection into one list snapshot", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/backup-repositories?"),
      body: [
        { id: "br-1", name: "box", type: "smb", url: "smb://u:p@h/s" },
        { id: "br-2", name: "nas", type: "nfs", url: "nfs://h/e" },
      ],
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listBackupRepositories.execute(
    asArgs({ _fetch: f }),
    context,
  );
  assertEquals(calls[0].url.includes("fields="), true);
  assertEquals(writes[0].spec, "backupRepositoryList");
  assertEquals(writes[0].name, "backupRepositories");
  assertEquals(writes[0].data.count, 2);
  const items = writes[0].data.items as Array<{ urlRedacted: string }>;
  assertEquals(items[0].urlRedacted, "smb://h/s");
  // Credential never persisted.
  assertEquals(anyWriteHas(writes, "u:p"), false);
  // Schema conformance against the REAL declared spec.
  model.resources.backupRepositoryList.schema.parse(writes[0].data);
});

Deno.test("listBackupRepositories: a non-array envelope records an empty list", async () => {
  const { f } = once({ unexpected: true });
  const { context, writes } = stubContext();
  await model.methods.listBackupRepositories.execute(
    asArgs({ _fetch: f }),
    context,
  );
  assertEquals(writes[0].data.count, 0);
  model.resources.backupRepositoryList.schema.parse(writes[0].data);
});

Deno.test("getBackupRepository: GETs by id, records a redacted snapshot", async () => {
  const { f } = router([
    {
      match: (u, m) => m === "GET" && /\/backup-repositories\/br-1$/.test(u),
      body: {
        id: "br-1",
        name: "box",
        type: "smb",
        url: "smb://u:SEKRET@h/s",
        enabled: true,
      },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.getBackupRepository.execute(
    asArgs({ id: "br-1", _fetch: f }),
    context,
  );
  assertEquals(writes[0].spec, "backupRepository");
  assertEquals(writes[0].name, "backupRepository:br-1");
  assertEquals(
    (writes[0].data as { urlRedacted: string }).urlRedacted,
    "smb://h/s",
  );
  assertEquals(anyWriteHas(writes, "SEKRET"), false);
  model.resources.backupRepository.schema.parse(writes[0].data);
});

Deno.test("getBackupRepository: an empty/non-object response throws", async () => {
  const { f } = router([{ match: () => true, status: 204, body: "" }]);
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.getBackupRepository.execute(
        asArgs({ id: "nope", _fetch: f }),
        context,
      ),
    Error,
    "not found",
  );
});

Deno.test("getBackupRepository: percent-encodes an id containing a slash", async () => {
  const { f, calls } = router([
    { match: (u, m) => m === "GET", body: { id: "a/b", name: "x" } },
  ]);
  const { context } = stubContext();
  await model.methods.getBackupRepository.execute(
    asArgs({ id: "a/b", _fetch: f }),
    context,
  );
  assertEquals(calls[0].url.includes("a%2Fb"), true);
});

Deno.test("createBackupRepository: POSTs, re-GETs, records; url never leaks", async () => {
  const url = "smb://user:SEKRET@host/share";
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/backup-repositories?"),
      body: [],
    },
    {
      match: (u, m) => m === "POST" && u.endsWith("/backup-repositories"),
      body: { id: "br-1" },
    },
    {
      match: (u, m) => m === "GET" && /\/backup-repositories\/br-1$/.test(u),
      body: { id: "br-1", name: "box", type: "smb", url, enabled: true },
    },
  ]);
  const { context, writes, logs } = stubContext();
  await model.methods.createBackupRepository.execute(
    asArgs({ name: "box", url, type: "smb", _fetch: f }),
    context,
  );
  // The raw url IS sent over the wire (sole egress) but never persisted/logged.
  const post = calls.find((c) => c.method === "POST");
  assertEquals(JSON.parse(post?.body ?? "{}").url, url);
  assertEquals(writes[0].spec, "backupRepository");
  assertEquals(writes[0].name, "backupRepository:br-1");
  assertEquals(anyWriteHas(writes, "SEKRET"), false);
  assertEquals(anyLogHas(logs, "SEKRET"), false);
  assertEquals(
    (writes[0].data as { urlRedacted: string }).urlRedacted,
    "smb://host/share",
  );
  model.resources.backupRepository.schema.parse(writes[0].data);
});

Deno.test("createBackupRepository: reuses a same-name remote (no POST) unless force", async () => {
  const reuseRoutes: Route[] = [
    {
      match: (u, m) => m === "GET" && u.includes("/backup-repositories?"),
      body: [{ id: "br-9", name: "box" }],
    },
    {
      match: (u, m) => m === "GET" && /\/backup-repositories\/br-9$/.test(u),
      body: { id: "br-9", name: "box", type: "smb", url: "smb://h/s" },
    },
    {
      match: (u, m) => m === "GET" && /\/backup-repositories\/br-new$/.test(u),
      body: { id: "br-new", name: "box", type: "smb", url: "smb://h/s" },
    },
    { match: (u, m) => m === "POST", body: { id: "br-new" } },
  ];
  const reuse = router(reuseRoutes);
  const ctxReuse = stubContext();
  await model.methods.createBackupRepository.execute(
    asArgs({ name: "box", url: "smb://u:p@h/s", _fetch: reuse.f }),
    ctxReuse.context,
  );
  assertEquals(reuse.calls.some((c) => c.method === "POST"), false);
  assertEquals(ctxReuse.writes[0].name, "backupRepository:br-9");

  const force = router(reuseRoutes);
  const ctxForce = stubContext();
  await model.methods.createBackupRepository.execute(
    asArgs({ name: "box", url: "smb://u:p@h/s", force: true, _fetch: force.f }),
    ctxForce.context,
  );
  assertEquals(force.calls.some((c) => c.method === "POST"), true);
});

Deno.test("createBackupRepository: no-id response throws orphan error with NO secret", async () => {
  const url = "smb://user:SEKRET@host/share";
  const { f } = router([
    {
      match: (u, m) => m === "POST" && u.endsWith("/backup-repositories"),
      status: 200,
      body: "",
    },
  ]);
  const { context, logs } = stubContext();
  const err = await assertRejects(
    () =>
      model.methods.createBackupRepository.execute(
        asArgs({ name: "box", url, force: true, _fetch: f }),
        context,
      ),
    Error,
    "returned no id",
  );
  assertEquals(err.message.includes("SEKRET"), false);
  assertEquals(err.message.includes("user:"), false);
  assertEquals(anyLogHas(logs, "SEKRET"), false);
});

Deno.test("updateBackupRepository: pre-verifies, PATCHes partial, re-GETs; no leak", async () => {
  const url = "smb://user:SEKRET@host/share";
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && /\/backup-repositories\/br-1$/.test(u),
      body: { id: "br-1", name: "box", type: "smb", url, enabled: true },
    },
    {
      match: (u, m) => m === "PATCH" && /\/backup-repositories\/br-1$/.test(u),
      body: { id: "br-1" },
    },
  ]);
  const { context, writes, logs } = stubContext();
  await model.methods.updateBackupRepository.execute(
    asArgs({ id: "br-1", url, enabled: false, _fetch: f }),
    context,
  );
  const patch = calls.find((c) => c.method === "PATCH");
  const patchBody = JSON.parse(patch?.body ?? "{}");
  assertEquals(patchBody.enabled, false);
  assertEquals(patchBody.url, url); // raw url sent to XO only
  assertEquals("name" in patchBody, false); // partial: unset field omitted
  assertEquals(anyWriteHas(writes, "SEKRET"), false);
  assertEquals(anyLogHas(logs, "SEKRET"), false);
  model.resources.backupRepository.schema.parse(writes[0].data);
});

Deno.test("updateBackupRepository: missing repo rejects before PATCH", async () => {
  const { f, calls } = router([{
    match: (u, m) => m === "GET",
    status: 404,
    body: "nope",
  }]);
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.updateBackupRepository.execute(
        asArgs({ id: "br-x", name: "y", _fetch: f }),
        context,
      ),
    Error,
    "HTTP 404",
  );
  assertEquals(calls.some((c) => c.method === "PATCH"), false);
});

Deno.test("updateBackupRepository: empty body (no fields) rejects", async () => {
  const { f } = router([{
    match: (u, m) => m === "GET",
    body: { id: "br-1", name: "box" },
  }]);
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.updateBackupRepository.execute(
        asArgs({ id: "br-1", _fetch: f }),
        context,
      ),
    Error,
    "no fields to update",
  );
});

Deno.test("forgetBackupRepository: dryRun pre-verifies and records a plan, NO POST", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && /\/backup-repositories\/br-1$/.test(u),
      body: { id: "br-1", name: "box" },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.forgetBackupRepository.execute(
    asArgs({ id: "br-1", _fetch: f }),
    context,
  );
  assertEquals(calls.some((c) => c.method === "POST"), false);
  assertEquals(writes[0].spec, "backupRepositoryAction");
  assertEquals(writes[0].name, "forget:br-1");
  assertEquals((writes[0].data as { action: string }).action, "forget-plan");
  assertEquals((writes[0].data as { status: string }).status, "planned");
  model.resources.backupRepositoryAction.schema.parse(writes[0].data);
});

Deno.test("forgetBackupRepository: dryRun=false POSTs forget once; bare-string result parses", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && /\/backup-repositories\/br-1$/.test(u),
      body: { id: "br-1", name: "box" },
    },
    {
      match: (u, m) => m === "POST" && u.includes("/actions/forget"),
      body: "/rest/v0/tasks/task-9",
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.forgetBackupRepository.execute(
    asArgs({ id: "br-1", dryRun: false, _fetch: f }),
    context,
  );
  const posts = calls.filter((c) => c.method === "POST");
  assertEquals(posts.length, 1);
  assertEquals(posts[0].url.includes("/actions/forget"), true);
  assertEquals((writes[0].data as { action: string }).action, "forget");
  assertEquals((writes[0].data as { taskRef: string }).taskRef, "task-9");
  // raw is an OBJECT even though XO returned a bare string.
  assertEquals((writes[0].data as { raw: Record<string, unknown> }).raw, {
    result: "/rest/v0/tasks/task-9",
  });
  model.resources.backupRepositoryAction.schema.parse(writes[0].data);
});

Deno.test("forgetBackupRepository: missing repo rejects before any POST", async () => {
  const { f, calls } = router([{
    match: (u, m) => m === "GET",
    status: 404,
    body: "gone",
  }]);
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.forgetBackupRepository.execute(
        asArgs({ id: "br-x", dryRun: false, _fetch: f }),
        context,
      ),
    Error,
    "HTTP 404",
  );
  assertEquals(calls.some((c) => c.method === "POST"), false);
});

Deno.test("reclaimBackupRepositorySpace: dryRun records a plan, NO POST", async () => {
  const { f, calls } = router([
    { match: (u, m) => m === "GET", body: { id: "br-1", name: "box" } },
  ]);
  const { context, writes } = stubContext();
  await model.methods.reclaimBackupRepositorySpace.execute(
    asArgs({ id: "br-1", _fetch: f }),
    context,
  );
  assertEquals(calls.some((c) => c.method === "POST"), false);
  assertEquals(
    (writes[0].data as { action: string }).action,
    "reclaim-space-plan",
  );
  model.resources.backupRepositoryAction.schema.parse(writes[0].data);
});

Deno.test("reclaimBackupRepositorySpace: inline result (taskRef null, status done)", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && !u.includes("/actions/"),
      body: { id: "br-1", name: "box" },
    },
    {
      match: (u, m) => m === "POST" && u.includes("/actions/reclaim-space"),
      body: { reclaimed: 12345 },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.reclaimBackupRepositorySpace.execute(
    asArgs({ id: "br-1", dryRun: false, _fetch: f }),
    context,
  );
  assertEquals(calls.filter((c) => c.method === "POST").length, 1);
  assertEquals((writes[0].data as { taskRef: string | null }).taskRef, null);
  assertEquals((writes[0].data as { status: string }).status, "done");
  assertEquals((writes[0].data as { raw: Record<string, unknown> }).raw, {
    reclaimed: 12345,
  });
  model.resources.backupRepositoryAction.schema.parse(writes[0].data);
});

Deno.test("reclaimBackupRepositorySpace: async task ref (taskRef set, status submitted, no second request)", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && !u.includes("/actions/"),
      body: { id: "br-1", name: "box" },
    },
    {
      match: (u, m) => m === "POST" && u.includes("/actions/reclaim-space"),
      body: "/rest/v0/tasks/task-7",
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.reclaimBackupRepositorySpace.execute(
    asArgs({ id: "br-1", dryRun: false, _fetch: f }),
    context,
  );
  // One pre-verify GET + one POST; the task is NOT polled.
  assertEquals(calls.map((c) => c.method), ["GET", "POST"]);
  assertEquals((writes[0].data as { taskRef: string }).taskRef, "task-7");
  assertEquals((writes[0].data as { status: string }).status, "submitted");
  model.resources.backupRepositoryAction.schema.parse(writes[0].data);
});

Deno.test("benchmarkBackupRepository: inline metrics (status done, no poll)", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && !u.includes("/actions/"),
      body: { id: "br-1", name: "box" },
    },
    {
      match: (u, m) => m === "POST" && u.includes("/actions/benchmark"),
      body: { writeMbps: 100, readMbps: 200 },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.benchmarkBackupRepository.execute(
    asArgs({ id: "br-1", _fetch: f }),
    context,
  );
  assertEquals(calls.map((c) => c.method), ["GET", "POST"]);
  assertEquals((writes[0].data as { taskRef: string | null }).taskRef, null);
  assertEquals((writes[0].data as { status: string }).status, "done");
  assertEquals((writes[0].data as { action: string }).action, "benchmark");
  model.resources.backupRepositoryAction.schema.parse(writes[0].data);
});

Deno.test("benchmarkBackupRepository: async task ref (status submitted, no poll)", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && !u.includes("/actions/"),
      body: { id: "br-1", name: "box" },
    },
    {
      match: (u, m) => m === "POST" && u.includes("/actions/benchmark"),
      body: { href: "/rest/v0/tasks/task-3" },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.benchmarkBackupRepository.execute(
    asArgs({ id: "br-1", _fetch: f }),
    context,
  );
  assertEquals(calls.map((c) => c.method), ["GET", "POST"]);
  assertEquals((writes[0].data as { taskRef: string }).taskRef, "task-3");
  assertEquals((writes[0].data as { status: string }).status, "submitted");
  model.resources.backupRepositoryAction.schema.parse(writes[0].data);
});

Deno.test("benchmarkBackupRepository: missing repo rejects before POST", async () => {
  const { f, calls } = router([{
    match: (u, m) => m === "GET",
    status: 404,
    body: "no",
  }]);
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.benchmarkBackupRepository.execute(
        asArgs({ id: "br-x", _fetch: f }),
        context,
      ),
    Error,
    "HTTP 404",
  );
  assertEquals(calls.some((c) => c.method === "POST"), false);
});

Deno.test("getBackupRepositoryHealth: records raw health; empty body becomes an object", async () => {
  const ok = router([
    {
      match: (u, m) => m === "GET" && u.includes("/health"),
      body: { status: "ok", writable: true },
    },
  ]);
  const ctxOk = stubContext();
  await model.methods.getBackupRepositoryHealth.execute(
    asArgs({ id: "br-1", _fetch: ok.f }),
    ctxOk.context,
  );
  assertEquals(ctxOk.writes[0].spec, "backupRepositoryHealth");
  assertEquals(ctxOk.writes[0].name, "health:br-1");
  assertEquals((ctxOk.writes[0].data as { raw: Record<string, unknown> }).raw, {
    status: "ok",
    writable: true,
  });
  model.resources.backupRepositoryHealth.schema.parse(ctxOk.writes[0].data);

  const empty = router([{
    match: (u, m) => m === "GET",
    status: 204,
    body: "",
  }]);
  const ctxEmpty = stubContext();
  await model.methods.getBackupRepositoryHealth.execute(
    asArgs({ id: "br-1", _fetch: empty.f }),
    ctxEmpty.context,
  );
  assertEquals(
    (ctxEmpty.writes[0].data as { raw: Record<string, unknown> }).raw,
    { result: null },
  );
  model.resources.backupRepositoryHealth.schema.parse(ctxEmpty.writes[0].data);
});

Deno.test("getBackupRepositoryHealth: a non-2xx raises", async () => {
  const { f } = once({ error: "x" }, { status: 401 });
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.getBackupRepositoryHealth.execute(
        asArgs({ id: "br-1", _fetch: f }),
        context,
      ),
    Error,
    "HTTP 401",
  );
});

// ---------------------------------------------------------------------------
// Typed error seam (XoHttpError)
// ---------------------------------------------------------------------------

Deno.test("xoRequest: rejects with a typed XoHttpError carrying .status, message unchanged", async () => {
  const { f } = once({ error: "nope" }, { status: 409 });
  const err = await assertRejects(
    () => xoRequest(CFG, "GET", "tasks/t1", {}, f),
    XoHttpError,
    "HTTP 409",
  );
  // Backward-compat: still an Error, same message format callers assert on.
  assertEquals(err instanceof Error, true);
  assertEquals(err.status, 409);
  assertEquals(
    err.message,
    'XO GET tasks/t1 failed (HTTP 409): {"error":"nope"}',
  );
});

// ---------------------------------------------------------------------------
// Task management (listTasks / deleteTask / deleteTasks / abortTask)
// ---------------------------------------------------------------------------

Deno.test("listTasks: records an inventory snapshot (kind tasks)", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/tasks"),
      body: [{ id: "t1", name_label: "copy" }, { id: "t2" }],
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.listTasks.execute(
    asArgs({ _fetch: f }),
    context,
  );
  assertEquals(calls[0].method, "GET");
  assertEquals(calls[0].url.endsWith("/tasks"), true);
  assertEquals(writes[0].spec, "inventory");
  assertEquals(writes[0].name, "tasks");
  assertEquals(writes[0].data.kind, "tasks");
  assertEquals(writes[0].data.count, 2);
  assertEquals(
    (writes[0].data.items as Array<{ uuid: string }>)[0].uuid,
    "t1",
  );
  assertEquals(res.dataHandles.length, 1);
  // Schema conformance (writeResource does NOT validate in the stub).
  model.resources.inventory.schema.parse(writes[0].data);
});

Deno.test("listTasks: appends a filter query param; an empty list is count 0", async () => {
  const { f, calls } = router([
    { match: (u, m) => m === "GET" && u.includes("/tasks"), body: [] },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listTasks.execute(
    asArgs({ filter: "status:pending", _fetch: f }),
    context,
  );
  assertEquals(calls[0].url.includes("filter=status%3Apending"), true);
  assertEquals(writes[0].data.count, 0); // empty collection is valid
  model.resources.inventory.schema.parse(writes[0].data);
});

Deno.test("listTasks: a non-array body raises (drift, not a silent 0)", async () => {
  const { f } = once({ not: "a list" });
  const { context } = stubContext();
  await assertRejects(
    () => model.methods.listTasks.execute(asArgs({ _fetch: f }), context),
    Error,
    "did not return a list",
  );
});

Deno.test("deleteTask: verifies (GET) then deletes, recording nothing", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/tasks/t1"),
      body: { id: "t1" },
    },
    {
      match: (u, m) => m === "DELETE" && u.includes("/tasks/t1"),
      status: 204,
      body: "",
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.deleteTask.execute(
    asArgs({ id: "t1", _fetch: f }),
    context,
  );
  assertEquals(calls.map((c) => c.method), ["GET", "DELETE"]);
  assertEquals(writes.length, 0);
  assertEquals(res.dataHandles.length, 0);
});

Deno.test("deleteTask: a missing task (404 on verify) never issues the DELETE", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/tasks/"),
      status: 404,
      body: { error: "not found" },
    },
    { match: (_u, m) => m === "DELETE", status: 204, body: "" },
  ]);
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.deleteTask.execute(
        asArgs({ id: "gone", _fetch: f }),
        context,
      ),
    Error,
    "HTTP 404",
  );
  assertEquals(calls.map((c) => c.method), ["GET"]); // DELETE never reached
});

Deno.test("deleteTask: percent-encodes the id in both GET and DELETE paths", async () => {
  const { f, calls } = router([
    { match: (_u, m) => m === "GET", body: { id: "x" } },
    { match: (_u, m) => m === "DELETE", status: 204, body: "" },
  ]);
  const { context } = stubContext();
  await model.methods.deleteTask.execute(
    asArgs({ id: "t/9", _fetch: f }),
    context,
  );
  assertEquals(calls[0].url.includes("/tasks/t%2F9"), true);
  assertEquals(calls[1].url.includes("/tasks/t%2F9"), true);
  assertEquals(calls[0].url.includes("/tasks/t/9"), false);
});

Deno.test("deleteTasks: ids-mode deletes each and records a task-deletions summary", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "DELETE" && u.endsWith("/tasks/a"),
      status: 204,
      body: "",
    },
    {
      match: (u, m) => m === "DELETE" && u.endsWith("/tasks/b"),
      status: 204,
      body: "",
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.deleteTasks.execute(
    asArgs({ ids: ["a", "b"], _fetch: f }),
    context,
  );
  assertEquals(calls.map((c) => c.method), ["DELETE", "DELETE"]);
  assertEquals(calls[0].url.endsWith("/tasks/a"), true);
  assertEquals(calls[1].url.endsWith("/tasks/b"), true);
  assertEquals(writes[0].spec, "taskDeletions");
  assertEquals(writes[0].data.mode, "ids");
  assertEquals(writes[0].data.deleted, ["a", "b"]);
  assertEquals(writes[0].data.alreadyGone, []);
  assertEquals(writes[0].data.count, 2);
  assertEquals(res.dataHandles.length, 1);
  model.resources.taskDeletions.schema.parse(writes[0].data);
});

Deno.test("deleteTasks: ids-mode tolerates a 404 as already-gone and continues", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "DELETE" && u.endsWith("/tasks/a"),
      status: 404,
      body: { error: "gone" },
    },
    {
      match: (u, m) => m === "DELETE" && u.endsWith("/tasks/b"),
      status: 204,
      body: "",
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.deleteTasks.execute(
    asArgs({ ids: ["a", "b"], _fetch: f }),
    context,
  );
  assertEquals(calls.length, 2); // both attempted; the batch continued past 404
  assertEquals(writes[0].data.alreadyGone, ["a"]);
  assertEquals(writes[0].data.deleted, ["b"]);
  assertEquals(writes[0].data.failed, []);
  model.resources.taskDeletions.schema.parse(writes[0].data);
});

Deno.test("deleteTasks: ids-mode rethrows after a non-404, recording the summary first and stopping", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "DELETE" && u.endsWith("/tasks/a"),
      status: 500,
      body: { error: "boom" },
    },
    {
      match: (u, m) => m === "DELETE" && u.endsWith("/tasks/b"),
      status: 204,
      body: "",
    },
  ]);
  const { context, writes } = stubContext();
  await assertRejects(
    () =>
      model.methods.deleteTasks.execute(
        asArgs({ ids: ["a", "b"], _fetch: f }),
        context,
      ),
    Error,
    "HTTP 500",
  );
  // Batch stopped at 'a' (fail-loud): 'b' was never attempted.
  assertEquals(calls.length, 1);
  assertEquals(calls[0].url.endsWith("/tasks/a"), true);
  // Summary was persisted BEFORE the rethrow.
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "taskDeletions");
  assertEquals(writes[0].data.deleted, []);
  assertEquals(
    (writes[0].data.failed as Array<{ id: string }>)[0].id,
    "a",
  );
  model.resources.taskDeletions.schema.parse(writes[0].data);
});

Deno.test("deleteTasks: all-mode issues a single bulk DELETE /tasks", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "DELETE" && u.endsWith("/tasks"),
      body: { count: 7 },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.deleteTasks.execute(
    asArgs({ all: true, _fetch: f }),
    context,
  );
  assertEquals(calls.length, 1); // no per-id DELETE calls
  assertEquals(calls[0].method, "DELETE");
  assertEquals(calls[0].url.endsWith("/tasks"), true);
  assertEquals(writes[0].data.mode, "all");
  assertEquals(writes[0].data.count, 7);
  assertEquals(writes[0].data.requested, []);
  model.resources.taskDeletions.schema.parse(writes[0].data);
});

Deno.test("deleteTasks: the arguments guard rejects empty/ambiguous selections", () => {
  // The superRefine runs at argument-parse time (before execute), so delete-all
  // can never fire on a bare or ambiguous run.
  for (const bad of [{}, { ids: [], all: false }, { ids: ["x"], all: true }]) {
    assertThrows(() => model.methods.deleteTasks.arguments.parse(bad));
  }
  // Exactly-one selections parse cleanly.
  model.methods.deleteTasks.arguments.parse({ ids: ["a"] });
  model.methods.deleteTasks.arguments.parse({ all: true });
});

Deno.test("abortTask: a pending task is aborted (GET, POST, re-GET) and snapshotted", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/tasks/t1"),
      body: { id: "t1", status: "pending" },
    },
    {
      match: (u, m) => m === "POST" && u.includes("/tasks/t1/actions/abort"),
      status: 204,
      body: "",
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.abortTask.execute(
    asArgs({ id: "t1", _fetch: f }),
    context,
  );
  assertEquals(calls.map((c) => c.method), ["GET", "POST", "GET"]);
  assertEquals(calls[1].url.endsWith("/tasks/t1/actions/abort"), true);
  assertEquals(writes[0].spec, "inventory");
  assertEquals(writes[0].name, "task");
  assertEquals(writes[0].data.kind, "task");
  assertEquals(res.dataHandles.length, 1);
  model.resources.inventory.schema.parse(writes[0].data);
});

Deno.test("abortTask: a settled task short-circuits to a no-op (no POST)", async () => {
  for (const status of ["success", "interrupted"]) {
    const { f, calls } = router([
      {
        match: (u, m) => m === "GET" && u.includes("/tasks/t1"),
        body: { id: "t1", status },
      },
      { match: (_u, m) => m === "POST", status: 204, body: "" },
    ]);
    const { context, writes } = stubContext();
    const res = await model.methods.abortTask.execute(
      asArgs({ id: "t1", _fetch: f }),
      context,
    );
    assertEquals(calls.map((c) => c.method), ["GET"]); // POST never fired
    assertEquals(writes[0].spec, "inventory");
    assertEquals(res.dataHandles.length, 1);
    model.resources.inventory.schema.parse(writes[0].data);
  }
});

Deno.test("abortTask: an absent task (404 on verify) never POSTs", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/tasks/"),
      status: 404,
      body: { error: "gone" },
    },
    { match: (_u, m) => m === "POST", status: 204, body: "" },
  ]);
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.abortTask.execute(
        asArgs({ id: "gone", _fetch: f }),
        context,
      ),
    Error,
    "HTTP 404",
  );
  assertEquals(calls.map((c) => c.method), ["GET"]);
});

Deno.test("abortTask: percent-encodes the id in the GET and abort POST paths", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/tasks/"),
      body: { id: "x", status: "pending" },
    },
    { match: (_u, m) => m === "POST", status: 204, body: "" },
  ]);
  const { context } = stubContext();
  await model.methods.abortTask.execute(
    asArgs({ id: "t/9", _fetch: f }),
    context,
  );
  assertEquals(calls[0].url.includes("/tasks/t%2F9"), true);
  assertEquals(calls[1].url.includes("/tasks/t%2F9/actions/abort"), true);
});

// ---------------------------------------------------------------------------
// pub-20: backup-archive discovery + file-level restore (mount/unmount)
// ---------------------------------------------------------------------------

Deno.test("listBackupArchives: GET /backup-archives, maps to inventory (kind backupArchives)", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.endsWith("/backup-archives"),
      body: [{ id: "arch-1", name_label: "daily" }, { id: "arch-2" }],
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.listBackupArchives.execute(
    asArgs({ _fetch: f }),
    context,
  );
  assertEquals(calls[0].method, "GET");
  assertEquals(calls[0].url.endsWith("/backup-archives"), true);
  assertEquals(writes[0].spec, "inventory");
  assertEquals(writes[0].name, "backupArchives");
  assertEquals(writes[0].data.kind, "backupArchives");
  assertEquals(writes[0].data.count, 2);
  // IDENTIFIER guard: normalizeRef lifts id->uuid, so the primary key survives.
  assertEquals(
    (writes[0].data.items as Array<{ uuid: string }>)[0].uuid,
    "arch-1",
  );
  assertEquals(res.dataHandles.length, 1);
  model.resources.inventory.schema.parse(writes[0].data);
});

Deno.test("listBackupArchives: a filter is passed as the ?filter= query param", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/backup-archives"),
      body: [],
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listBackupArchives.execute(
    asArgs({ filter: "vm:web", _fetch: f }),
    context,
  );
  assertEquals(calls[0].url.includes("filter=vm%3Aweb"), true);
  assertEquals(writes[0].data.count, 0);
  model.resources.inventory.schema.parse(writes[0].data);
});

Deno.test("listBackupArchives: a non-array body raises (drift, not a silent 0)", async () => {
  const { f } = once({ not: "a list" });
  const { context } = stubContext();
  await assertRejects(
    () =>
      model.methods.listBackupArchives.execute(asArgs({ _fetch: f }), context),
    Error,
    "did not return a list",
  );
});

Deno.test("getBackupArchive: single-item record (count 1); encodes the id", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/backup-archives/a%2F1"),
      body: { id: "a/1", name_label: "weekly" },
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.getBackupArchive.execute(
    asArgs({ id: "a/1", _fetch: f }),
    context,
  );
  assertEquals(calls[0].url.includes("/backup-archives/a%2F1"), true);
  assertEquals(writes[0].data.kind, "backupArchive");
  assertEquals(writes[0].data.count, 1);
  assertEquals(
    (writes[0].data.items as Array<{ uuid: string }>)[0].uuid,
    "a/1",
  );
  model.resources.inventory.schema.parse(writes[0].data);
});

Deno.test("getBackupArchive: an empty body raises (no phantom archive recorded)", async () => {
  const { f } = router([{ match: () => true, status: 204, body: "" }]);
  const { context, writes } = stubContext();
  await assertRejects(
    () =>
      model.methods.getBackupArchive.execute(
        asArgs({ id: "gone", _fetch: f }),
        context,
      ),
    Error,
    "returned empty",
  );
  assertEquals(writes.length, 0);
});

Deno.test("listBackupJobs: GET /backup-jobs (real endpoint), maps to inventory", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.endsWith("/backup-jobs"),
      body: [{ id: "job-1" }],
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listBackupJobs.execute(asArgs({ _fetch: f }), context);
  assertEquals(calls[0].url.endsWith("/backup-jobs"), true);
  // No deprecated /backup/jobs form, and no ?fields= projection.
  assertEquals(calls[0].url.includes("/backup/jobs"), false);
  assertEquals(calls[0].url.includes("fields="), false);
  assertEquals(writes[0].data.kind, "backupJobs");
  assertEquals(writes[0].data.count, 1);
  assertEquals(
    (writes[0].data.items as Array<{ uuid: string }>)[0].uuid,
    "job-1",
  );
  model.resources.inventory.schema.parse(writes[0].data);
});

Deno.test("listBackupJobs: a non-array body raises", async () => {
  const { f } = once({ not: "a list" });
  const { context } = stubContext();
  await assertRejects(
    () => model.methods.listBackupJobs.execute(asArgs({ _fetch: f }), context),
    Error,
    "did not return a list",
  );
});

Deno.test("listRestoreLogs: GET /restore-logs (real endpoint), maps to inventory", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.endsWith("/restore-logs"),
      body: [{ id: "log-1" }, { id: "log-2" }],
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listRestoreLogs.execute(asArgs({ _fetch: f }), context);
  assertEquals(calls[0].url.endsWith("/restore-logs"), true);
  assertEquals(calls[0].url.includes("/restore/logs"), false);
  assertEquals(calls[0].url.includes("/backup/logs"), false);
  assertEquals(writes[0].data.kind, "restoreLogs");
  assertEquals(writes[0].data.count, 2);
  model.resources.inventory.schema.parse(writes[0].data);
});

Deno.test("listRestoreLogs: a non-array body raises", async () => {
  const { f } = once({ not: "a list" });
  const { context } = stubContext();
  await assertRejects(
    () => model.methods.listRestoreLogs.execute(asArgs({ _fetch: f }), context),
    Error,
    "did not return a list",
  );
});

// ---------------------------------------------------------------------------
// Backup schedules: REST reads (listSchedules/getSchedule/runSchedule) +
// JSON-RPC writes (createSchedule/updateSchedule/deleteSchedule via fake connect)
// ---------------------------------------------------------------------------

Deno.test("normalizeSchedule(): lifts fields to scalars, keeps raw, stamps retrievedAt", () => {
  const s = normalizeSchedule({
    id: "sched-1",
    jobId: "job-1",
    cron: "0 2 * * *",
    timezone: "UTC",
    name: "nightly",
    enabled: true,
    extra: { keep: 1 },
  });
  assertEquals(s.id, "sched-1");
  assertEquals(s.jobId, "job-1");
  assertEquals(s.cron, "0 2 * * *");
  assertEquals(s.timezone, "UTC");
  assertEquals(s.name, "nightly");
  assertEquals(s.enabled, true);
  assertEquals(typeof s.retrievedAt, "string");
  assertEquals((s.raw as { extra?: unknown }).extra !== undefined, true);
  // Conforms to the REAL declared schema (not the recording stub).
  model.resources.schedule.schema.parse(s);
});

Deno.test("normalizeSchedule(): absent fields become null (never throws at parse)", () => {
  const s = normalizeSchedule({ id: "sched-2" });
  assertEquals(s.jobId, null);
  assertEquals(s.cron, null);
  assertEquals(s.timezone, null);
  assertEquals(s.name, null);
  assertEquals(s.enabled, null);
  model.resources.schedule.schema.parse(s);
});

Deno.test("listSchedules: GET /schedules (with fields), maps to inventory", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/schedules"),
      body: [{ id: "sched-1", name: "nightly" }, { id: "sched-2" }],
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.listSchedules.execute(asArgs({ _fetch: f }), context);
  assertEquals(calls[0].url.includes("/schedules"), true);
  assertEquals(calls[0].url.includes("fields="), true);
  assertEquals(writes[0].spec, "inventory");
  assertEquals(writes[0].data.kind, "schedules");
  assertEquals(writes[0].data.count, 2);
  assertEquals(
    (writes[0].data.items as Array<{ uuid: string }>)[0].uuid,
    "sched-1",
  );
  model.resources.inventory.schema.parse(writes[0].data);
});

Deno.test("listSchedules: a non-array body raises", async () => {
  const { f } = once({ not: "a list" });
  const { context } = stubContext();
  await assertRejects(
    () => model.methods.listSchedules.execute(asArgs({ _fetch: f }), context),
    Error,
    "did not return a list",
  );
});

Deno.test("listSchedules: a non-2xx (401) raises", async () => {
  const { f } = once({ error: "nope" }, { status: 401 });
  const { context } = stubContext();
  await assertRejects(
    () => model.methods.listSchedules.execute(asArgs({ _fetch: f }), context),
    Error,
    "HTTP 401",
  );
});

Deno.test("getSchedule: GET /schedules/{id}, records a schedule snapshot", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/schedules/sched-1"),
      body: {
        id: "sched-1",
        jobId: "job-1",
        cron: "0 3 * * *",
        timezone: "UTC",
        name: "nightly",
        enabled: true,
      },
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.getSchedule.execute(
    asArgs({ id: "sched-1", _fetch: f }),
    context,
  );
  assertEquals(calls[0].url.includes("/schedules/sched-1"), true);
  assertEquals(writes[0].spec, "schedule");
  assertEquals(writes[0].name, "schedule:sched-1");
  assertEquals(writes[0].data.id, "sched-1");
  assertEquals(writes[0].data.jobId, "job-1");
  assertEquals(res.dataHandles.length, 1);
  model.resources.schedule.schema.parse(writes[0].data);
});

Deno.test("getSchedule: a 404 raises and records nothing", async () => {
  const { f } = once({ error: "not found" }, { status: 404 });
  const { context, writes } = stubContext();
  await assertRejects(
    () =>
      model.methods.getSchedule.execute(
        asArgs({ id: "nope", _fetch: f }),
        context,
      ),
    Error,
    "HTTP 404",
  );
  assertEquals(writes.length, 0);
});

Deno.test("getSchedule: percent-encodes a crafted id in the path", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/schedules/"),
      body: { id: "x" },
    },
  ]);
  const { context } = stubContext();
  await model.methods.getSchedule.execute(
    asArgs({ id: "a/../b", _fetch: f }),
    context,
  );
  // enc() escapes the slashes so no path traversal reaches the server.
  assertEquals(calls[0].url.includes("a%2F..%2Fb"), true);
  assertEquals(calls[0].url.includes("/schedules/a/../b"), false);
});

Deno.test("runSchedule: verifies (GET) THEN POSTs run, records scheduleRun", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/schedules/sched-1"),
      body: { id: "sched-1" },
    },
    {
      match: (u, m) => m === "POST" && u.includes("/actions/run"),
      body: { id: "/rest/v0/tasks/task-9" },
    },
  ]);
  const { context, writes, logs } = stubContext();
  await model.methods.runSchedule.execute(
    asArgs({ id: "sched-1", _fetch: f }),
    context,
  );
  // Ordering: pre-verify GET precedes the mutating POST (Rule 5).
  assertEquals(calls.map((c) => c.method), ["GET", "POST"]);
  assertEquals(calls[1].url.includes("/schedules/sched-1/actions/run"), true);
  assertEquals(writes[0].spec, "inventory");
  assertEquals(writes[0].data.kind, "scheduleRun");
  assertEquals(writes[0].data.count, 1);
  assertEquals(logs.some((l) => l.level === "warning"), true);
  model.resources.inventory.schema.parse(writes[0].data);
});

Deno.test("runSchedule: a 404 on the pre-verify never POSTs", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/schedules/nope"),
      status: 404,
      body: { error: "not found" },
    },
  ]);
  const { context, writes } = stubContext();
  await assertRejects(
    () =>
      model.methods.runSchedule.execute(
        asArgs({ id: "nope", _fetch: f }),
        context,
      ),
    Error,
    "HTTP 404",
  );
  assertEquals(calls.every((c) => c.method !== "POST"), true);
  assertEquals(writes.length, 0);
});

Deno.test("createSchedule: JSON-RPC schedule.create (only-set params) then re-reads over REST", async () => {
  const { connect, sends } = fakeRpc((sent, emit) => {
    if (onSignInOk(sent, emit)) return;
    // schedule.create returns a bare new id.
    emit({
      kind: "text",
      data: JSON.stringify({ jsonrpc: "2.0", id: 2, result: "sched-new" }),
    });
  });
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/schedules/sched-new"),
      body: {
        id: "sched-new",
        jobId: "job-1",
        cron: "0 2 * * *",
        timezone: "UTC",
        name: "nightly",
        enabled: true,
      },
    },
  ]);
  const { context, writes } = stubContext();
  const res = await model.methods.createSchedule.execute(
    asArgs({
      jobId: "job-1",
      cron: "0 2 * * *",
      timezone: "UTC",
      _connect: connect,
      _fetch: f,
    }),
    context,
  );
  // Handshake then the write RPC with only the provided params.
  assertEquals(sends[1].method, "schedule.create");
  assertEquals(sends[1].params, {
    jobId: "job-1",
    cron: "0 2 * * *",
    timezone: "UTC",
  });
  // name/enabled were unset -> omitted, never sent as undefined keys.
  assertEquals("name" in (sends[1].params ?? {}), false);
  assertEquals("enabled" in (sends[1].params ?? {}), false);
  // The canonical state was re-read over REST and recorded deterministically.
  assertEquals(calls[0].url.includes("/schedules/sched-new"), true);
  assertEquals(writes[0].spec, "schedule");
  assertEquals(writes[0].name, "schedule:sched-new");
  assertEquals(writes[0].data.id, "sched-new");
  assertEquals(res.dataHandles.length, 1);
  model.resources.schedule.schema.parse(writes[0].data);
});

Deno.test("createSchedule: a JSON-RPC error rejects and leaks no token/params", async () => {
  const { connect } = fakeRpc((sent, emit) => {
    if (onSignInOk(sent, emit)) return;
    emit({
      kind: "text",
      data: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        error: { code: 11, message: "no such job" },
      }),
    });
  });
  const { f } = once({ id: "unused" });
  const { context, writes } = stubContext();
  const err = await assertRejects(
    () =>
      model.methods.createSchedule.execute(
        asArgs({
          jobId: "job-SECRET",
          cron: "0 2 * * *",
          name: "SECRETNAME",
          _connect: connect,
          _fetch: f,
        }),
        context,
      ),
    Error,
  );
  assertEquals(err.message.includes("11"), true);
  assertEquals(err.message.includes("no such job"), true);
  // Neither the auth token nor any param value is in the thrown message.
  assertEquals(err.message.includes("TOK"), false);
  assertEquals(err.message.includes("job-SECRET"), false);
  assertEquals(err.message.includes("SECRETNAME"), false);
  // Nothing recorded on a failed write.
  assertEquals(writes.length, 0);
});

Deno.test("updateSchedule: pre-reads, schedule.set with only-changed fields, re-reads", async () => {
  const { connect, sends } = fakeRpc((sent, emit) => {
    if (onSignInOk(sent, emit)) return;
    emit({
      kind: "text",
      data: JSON.stringify({ jsonrpc: "2.0", id: 2, result: true }),
    });
  });
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/schedules/sched-1"),
      body: {
        id: "sched-1",
        jobId: "job-1",
        cron: "30 4 * * *",
        enabled: false,
      },
    },
  ]);
  const { context, writes, logs } = stubContext();
  await model.methods.updateSchedule.execute(
    asArgs({
      id: "sched-1",
      cron: "30 4 * * *",
      enabled: false,
      _connect: connect,
      _fetch: f,
    }),
    context,
  );
  // Pre-read GET happened (Rule 5) before any write.
  assertEquals(calls.some((c) => c.method === "GET"), true);
  assertEquals(sends[1].method, "schedule.set");
  assertEquals(sends[1].params, {
    id: "sched-1",
    cron: "30 4 * * *",
    enabled: false,
  });
  // timezone/name were unset -> omitted.
  assertEquals("timezone" in (sends[1].params ?? {}), false);
  assertEquals("name" in (sends[1].params ?? {}), false);
  assertEquals(writes[0].spec, "schedule");
  assertEquals(writes[0].name, "schedule:sched-1");
  assertEquals(logs.some((l) => l.level === "warning"), true);
  model.resources.schedule.schema.parse(writes[0].data);
});

Deno.test("deleteSchedule: dryRun=true records a plan and NEVER invokes _connect", async () => {
  let connectCalls = 0;
  const connect: RpcConnect = () => {
    connectCalls++;
    throw new Error("JSON-RPC must not be called on a dry run");
  };
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/schedules/sched-1"),
      body: { id: "sched-1" },
    },
  ]);
  const { context, writes, logs } = stubContext();
  const res = await model.methods.deleteSchedule.execute(
    asArgs({ id: "sched-1", dryRun: true, _connect: connect, _fetch: f }),
    context,
  );
  assertEquals(connectCalls, 0);
  // Pre-read happened; no mutating RPC.
  assertEquals(calls.some((c) => c.method === "GET"), true);
  assertEquals(writes[0].spec, "inventory");
  assertEquals(writes[0].data.kind, "scheduleDeletePlan");
  assertEquals(writes[0].data.count, 1);
  assertEquals(logs.some((l) => l.level === "info"), true);
  assertEquals(res.dataHandles.length, 1);
  model.resources.inventory.schema.parse(writes[0].data);
});

Deno.test("deleteSchedule: dryRun=false pre-reads THEN calls schedule.delete", async () => {
  const { connect, sends } = fakeRpc((sent, emit) => {
    if (onSignInOk(sent, emit)) return;
    emit({
      kind: "text",
      data: JSON.stringify({ jsonrpc: "2.0", id: 2, result: true }),
    });
  });
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/schedules/sched-1"),
      body: { id: "sched-1" },
    },
  ]);
  const { context, writes, logs } = stubContext();
  const res = await model.methods.deleteSchedule.execute(
    asArgs({ id: "sched-1", dryRun: false, _connect: connect, _fetch: f }),
    context,
  );
  assertEquals(calls.some((c) => c.method === "GET"), true);
  assertEquals(sends[1].method, "schedule.delete");
  assertEquals(sends[1].params, { id: "sched-1" });
  assertEquals(logs.some((l) => l.level === "warning"), true);
  // A real delete records nothing (mirrors VM destroy).
  assertEquals(writes.length, 0);
  assertEquals(res.dataHandles.length, 0);
});

Deno.test("deleteSchedule: verify-before-destroy - a pre-read 404 never reaches schedule.delete", async () => {
  let connectCalls = 0;
  const connect: RpcConnect = () => {
    connectCalls++;
    throw new Error("JSON-RPC must not be called when the pre-read 404s");
  };
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/schedules/nope"),
      status: 404,
      body: { error: "not found" },
    },
  ]);
  const { context, writes } = stubContext();
  await assertRejects(
    () =>
      model.methods.deleteSchedule.execute(
        asArgs({ id: "nope", dryRun: false, _connect: connect, _fetch: f }),
        context,
      ),
    Error,
    "HTTP 404",
  );
  assertEquals(connectCalls, 0);
  assertEquals(calls.every((c) => c.method !== "POST"), true);
  assertEquals(writes.length, 0);
});

Deno.test("mountLiveDisk: verifies archive, POSTs mount, records liveDisk (object form)", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/backup-archives/arch-1"),
      body: { id: "arch-1" },
    },
    {
      match: (u, m) => m === "POST" && u.includes("/actions/mount_live_disk"),
      body: { liveDiskId: "ld-1" },
    },
  ]);
  const { context, writes, logs } = stubContext();
  const res = await model.methods.mountLiveDisk.execute(
    asArgs({ archiveId: "arch-1", _fetch: f }),
    context,
  );
  assertEquals(calls.map((c) => c.method), ["GET", "POST"]);
  assertEquals(
    calls[1].url.includes(
      "/backup-archives/arch-1/actions/mount_live_disk",
    ),
    true,
  );
  assertEquals(writes[0].spec, "liveDisk");
  assertEquals(writes[0].name, "liveDisk-ld-1");
  assertEquals(writes[0].data.status, "mounted");
  assertEquals(writes[0].data.liveDiskId, "ld-1");
  assertEquals(writes[0].data.unmountedAt, null);
  // A loud warning precedes the mutation.
  assertEquals(logs.some((l) => l.level === "warning"), true);
  assertEquals(res.dataHandles.length, 1);
  model.resources.liveDisk.schema.parse(writes[0].data);
});

Deno.test("mountLiveDisk: bare-string liveDiskId form also extracts and records", async () => {
  const { f } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/backup-archives/arch-1"),
      body: { id: "arch-1" },
    },
    {
      match: (u, m) => m === "POST" && u.includes("/mount_live_disk"),
      body: "ld-str", // XO may return a bare id as plain text
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.mountLiveDisk.execute(
    asArgs({ archiveId: "arch-1", _fetch: f }),
    context,
  );
  assertEquals(writes[0].name, "liveDisk-ld-str");
  assertEquals(writes[0].data.liveDiskId, "ld-str");
  model.resources.liveDisk.schema.parse(writes[0].data);
});

Deno.test("mountLiveDisk: a task-envelope response fails closed (records nothing)", async () => {
  const { f } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/backup-archives/arch-1"),
      body: { id: "arch-1" },
    },
    {
      match: (u, m) => m === "POST" && u.includes("/mount_live_disk"),
      body: { id: "/rest/v0/tasks/task-9" },
    },
  ]);
  const { context, writes } = stubContext();
  await assertRejects(
    () =>
      model.methods.mountLiveDisk.execute(
        asArgs({ archiveId: "arch-1", _fetch: f }),
        context,
      ),
    Error,
    "task envelope",
  );
  assertEquals(writes.length, 0);
});

Deno.test("mountLiveDisk: a bare task href string also fails closed", async () => {
  const { f } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/backup-archives/arch-1"),
      body: { id: "arch-1" },
    },
    {
      match: (u, m) => m === "POST" && u.includes("/mount_live_disk"),
      body: "/rest/v0/tasks/task-9",
    },
  ]);
  const { context, writes } = stubContext();
  await assertRejects(
    () =>
      model.methods.mountLiveDisk.execute(
        asArgs({ archiveId: "arch-1", _fetch: f }),
        context,
      ),
    Error,
    "task envelope",
  );
  assertEquals(writes.length, 0);
});

Deno.test("mountLiveDisk: a missing id fails closed (records nothing)", async () => {
  const { f } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/backup-archives/arch-1"),
      body: { id: "arch-1" },
    },
    {
      match: (u, m) => m === "POST" && u.includes("/mount_live_disk"),
      body: { somethingElse: true },
    },
  ]);
  const { context, writes } = stubContext();
  await assertRejects(
    () =>
      model.methods.mountLiveDisk.execute(
        asArgs({ archiveId: "arch-1", _fetch: f }),
        context,
      ),
    Error,
    "returned no liveDiskId",
  );
  assertEquals(writes.length, 0);
});

Deno.test("mountLiveDisk: a missing archive (404 on verify) never POSTs", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "GET" && u.includes("/backup-archives/"),
      status: 404,
      body: { error: "not found" },
    },
    { match: (_u, m) => m === "POST", body: { liveDiskId: "ld-x" } },
  ]);
  const { context, writes } = stubContext();
  await assertRejects(
    () =>
      model.methods.mountLiveDisk.execute(
        asArgs({ archiveId: "gone", _fetch: f }),
        context,
      ),
    Error,
    "HTTP 404",
  );
  assertEquals(calls.map((c) => c.method), ["GET"]); // POST never reached
  assertEquals(writes.length, 0);
});

Deno.test("unmountLiveDisk: POSTs the unmount, re-records status unmounted (mountedAt null)", async () => {
  const { f, calls } = router([
    {
      match: (u, m) => m === "POST" && u.includes("/actions/unmount"),
      status: 204,
      body: "",
    },
  ]);
  const { context, writes } = stubContext();
  await model.methods.unmountLiveDisk.execute(
    asArgs({ archiveId: "arch-1", liveDiskId: "ld-1", _fetch: f }),
    context,
  );
  assertEquals(
    calls[0].url.includes(
      "/backup-archives/arch-1/live_disks/ld-1/actions/unmount",
    ),
    true,
  );
  assertEquals(writes[0].spec, "liveDisk");
  assertEquals(writes[0].name, "liveDisk-ld-1");
  assertEquals(writes[0].data.status, "unmounted");
  assertEquals(writes[0].data.mountedAt, null);
  assertEquals(typeof writes[0].data.unmountedAt, "string");
  // The unmounted (mountedAt:null) row MUST satisfy the real schema - this is
  // the prod-only throw the no-op stub would otherwise hide.
  model.resources.liveDisk.schema.parse(writes[0].data);
});

Deno.test("unmountLiveDisk: encodes both path segments", async () => {
  const { f, calls } = router([
    { match: (_u, m) => m === "POST", status: 204, body: "" },
  ]);
  const { context } = stubContext();
  await model.methods.unmountLiveDisk.execute(
    asArgs({ archiveId: "a/1", liveDiskId: "l/2", _fetch: f }),
    context,
  );
  assertEquals(
    calls[0].url.includes("/backup-archives/a%2F1/live_disks/l%2F2/"),
    true,
  );
});

Deno.test("unmountLiveDisk: a non-2xx from unmount propagates (no swallow)", async () => {
  const { f } = once({ error: "nope" }, { status: 409 });
  const { context, writes } = stubContext();
  await assertRejects(
    () =>
      model.methods.unmountLiveDisk.execute(
        asArgs({ archiveId: "arch-1", liveDiskId: "ld-1", _fetch: f }),
        context,
      ),
    Error,
    "HTTP 409",
  );
  assertEquals(writes.length, 0);
});

Deno.test("liveDisk lifecycle: mount captures liveDiskId, unmount transitions it under one name", async () => {
  // Mount.
  const mount = router([
    {
      match: (u, m) => m === "GET" && u.includes("/backup-archives/arch-1"),
      body: { id: "arch-1" },
    },
    {
      match: (u, m) => m === "POST" && u.includes("/mount_live_disk"),
      body: { liveDiskId: "ld-life" },
    },
  ]);
  const mountCtx = stubContext();
  await model.methods.mountLiveDisk.execute(
    asArgs({ archiveId: "arch-1", _fetch: mount.f }),
    mountCtx.context,
  );
  const liveDiskId = mountCtx.writes[0].data.liveDiskId as string;
  assertEquals(liveDiskId, "ld-life");
  const mountName = mountCtx.writes[0].name;
  model.resources.liveDisk.schema.parse(mountCtx.writes[0].data);

  // Unmount using the captured id.
  const unmount = router([
    { match: (_u, m) => m === "POST", status: 204, body: "" },
  ]);
  const unmountCtx = stubContext();
  await model.methods.unmountLiveDisk.execute(
    asArgs({ archiveId: "arch-1", liveDiskId, _fetch: unmount.f }),
    unmountCtx.context,
  );
  // Same resource name, mounted -> unmounted.
  assertEquals(unmountCtx.writes[0].name, mountName);
  assertEquals(mountCtx.writes[0].data.status, "mounted");
  assertEquals(unmountCtx.writes[0].data.status, "unmounted");
  model.resources.liveDisk.schema.parse(unmountCtx.writes[0].data);
});
