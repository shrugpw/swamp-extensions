/**
 * Unit tests for `@shrug/grafana/instance`, driven through a mocked `fetch`
 * Grafana API and a real temp-file stand-in for `context.extensionFile()`.
 *
 * Coverage is weighted toward the consolidation delta over the
 * community `@keeb/grafana/instance` base it forks:
 *
 * - `pushDashboard` / `pushAlertRule` resolve their JSON from
 *   `context.extensionFile()` (never `context.repoDir`, which the stub
 *   context below never even sets) when given a file path, OR from inline
 *   `dashboardContent` / `ruleContent` when given content directly.
 * - `queryLogs` (the Loki sibling of `queryMetrics`, folded in as a native
 *   method here instead of a separate merge extension).
 *
 * @module
 */
import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import { model, resolveRelativeOrAbsoluteTime } from "./grafana_instance.ts";

type Reply = { status?: number; body?: unknown; raw?: string };
type Handler = Reply | (() => Reply);

interface RequestCall {
  method: string;
  path: string;
  search: string;
  body: unknown;
}

interface WriteCall {
  spec: string;
  name: string;
  data: Record<string, unknown>;
}

interface FetchMock {
  restore: () => void;
  calls: RequestCall[];
}

function installFetch(handlers: Record<string, Handler>): FetchMock {
  const original = globalThis.fetch;
  const calls: RequestCall[] = [];
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    const raw = typeof input === "string" ? input : input.toString();
    const url = new URL(raw);
    const path = url.pathname;
    const method = (init?.method ?? "GET").toUpperCase();
    let body: unknown;
    if (init?.body != null) {
      try {
        body = JSON.parse(String(init.body));
      } catch {
        body = String(init.body);
      }
    }
    calls.push({ method, path, search: url.search, body });
    const key = `${method} ${path}`;
    const handler = handlers[key];
    if (handler === undefined) {
      throw new Error(`unexpected route in test: ${key}`);
    }
    const reply = typeof handler === "function" ? handler() : handler;
    const status = reply.status ?? 200;
    const text = reply.raw !== undefined
      ? reply.raw
      : (reply.body === undefined ? "" : JSON.stringify(reply.body));
    return Promise.resolve(
      new Response(text, {
        status,
        statusText: status < 300 ? "OK" : "Error",
        headers: { "content-type": "application/json" },
      }),
    );
  }) as typeof fetch;
  return {
    restore: () => {
      globalThis.fetch = original;
    },
    calls,
  };
}

/**
 * Stub context deliberately has NO `repoDir` -- pushDashboard/pushAlertRule
 * must never touch it (that's the serve-dispatched-worker fix). `extensionFile`
 * resolves a path under the bundled-files sandbox the test sets up, mirroring
 * the real additionalFiles resolution without needing swamp's bundler.
 */
function stubContext(extensionFilesDir: string) {
  const writes: WriteCall[] = [];
  const context = {
    globalArgs: {
      grafanaUrl: "https://grafana.example.com",
      apiKey: "glsa_test",
    },
    writeResource: (
      spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      writes.push({ spec, name, data });
      return Promise.resolve({ name });
    },
    extensionFile: (relPath: string) => `${extensionFilesDir}/${relPath}`,
    // deno-lint-ignore no-explicit-any
  } as any;
  return { context, writes };
}

// deno-lint-ignore no-explicit-any
function method(name: string): any {
  // deno-lint-ignore no-explicit-any
  return (model as any).methods[name];
}

// --- resolveRelativeOrAbsoluteTime ------------------------------------------

Deno.test("resolveRelativeOrAbsoluteTime: relative tokens subtract from now", () => {
  const now = 1_000_000;
  assertEquals(resolveRelativeOrAbsoluteTime("1h", now), now - 3600);
  assertEquals(resolveRelativeOrAbsoluteTime("15m", now), now - 900);
  assertEquals(resolveRelativeOrAbsoluteTime("7d", now), now - 7 * 86400);
});

// --- pushDashboard -----------------------------------------------------------

Deno.test("pushDashboard: inline dashboardContent is used directly, no extensionFile/repoDir read", async () => {
  const mock = installFetch({
    "POST /api/dashboards/db": {
      body: { status: "success", uid: "dash-1" },
    },
  });
  try {
    // extensionFilesDir points nowhere real -- if the method tried to read a
    // file it would throw, proving inline content short-circuits the read.
    const { context, writes } = stubContext("/nonexistent");
    const dashboardJson = { uid: "dash-1", title: "CDN overview" };
    const res = await method("pushDashboard").execute(
      { dashboardFile: "", dashboardContent: JSON.stringify(dashboardJson) },
      context,
    );
    const post = mock.calls.find((c) => c.path === "/api/dashboards/db");
    assertEquals(post?.method, "POST");
    const sent = post?.body as { dashboard: { uid: string; id: null } };
    assertEquals(sent.dashboard.uid, "dash-1");
    assertEquals(sent.dashboard.id, null);
    assertEquals(writes[0].data.uid, "dash-1");
    assertEquals(writes[0].data.action, "success");
    assertEquals(res.dataHandles.length, 1);
  } finally {
    mock.restore();
  }
});

Deno.test("pushDashboard: dashboardFile resolves via context.extensionFile(), not repoDir", async () => {
  const mock = installFetch({
    "POST /api/dashboards/db": {
      body: { status: "success", uid: "dash-bundled" },
    },
  });
  const tmpDir = await Deno.makeTempDir();
  try {
    const dashboardJson = { uid: "dash-bundled", title: "Fleet overview" };
    await Deno.mkdir(`${tmpDir}/dashboards`, { recursive: true });
    await Deno.writeTextFile(
      `${tmpDir}/dashboards/fleet.json`,
      JSON.stringify(dashboardJson),
    );

    const { context, writes } = stubContext(tmpDir);
    // Stub context carries no `repoDir` at all -- a read via repoDir would
    // throw (string concatenation with `undefined`), so a passing test
    // proves the extensionFile path was used instead.
    assertEquals(Object.hasOwn(context, "repoDir"), false);

    const res = await method("pushDashboard").execute(
      { dashboardFile: "dashboards/fleet.json", dashboardContent: "" },
      context,
    );
    assertEquals(writes[0].data.uid, "dash-bundled");
    assertEquals(res.dataHandles.length, 1);
  } finally {
    mock.restore();
    await Deno.remove(tmpDir, { recursive: true }).catch(() => {});
  }
});

Deno.test("pushDashboard: requires dashboardFile or dashboardContent", async () => {
  const { context } = stubContext("/nonexistent");
  await assertRejects(
    () =>
      method("pushDashboard").execute(
        { dashboardFile: "", dashboardContent: "" },
        context,
      ),
    Error,
    "dashboardFile or dashboardContent is required",
  );
});

// --- pushAlertRule -----------------------------------------------------------

Deno.test("pushAlertRule: inline ruleContent is used directly, no extensionFile/repoDir read", async () => {
  const mock = installFetch({
    "POST /api/v1/provisioning/alert-rules": {
      body: { uid: "rule-uid-1" },
    },
  });
  try {
    const { context, writes } = stubContext("/nonexistent");
    const rule = { title: "edge-5xx-high" };
    const res = await method("pushAlertRule").execute(
      { ruleFile: "", ruleContent: JSON.stringify(rule) },
      context,
    );
    const post = mock.calls.find(
      (c) => c.path === "/api/v1/provisioning/alert-rules",
    );
    assertEquals(post?.method, "POST");
    assertEquals(writes[0].data.title, "edge-5xx-high");
    assertEquals(writes[0].data.uid, "rule-uid-1");
    assertEquals(res.dataHandles.length, 1);
  } finally {
    mock.restore();
  }
});

Deno.test("pushAlertRule: ruleFile resolves via context.extensionFile(), not repoDir", async () => {
  const mock = installFetch({
    "POST /api/v1/provisioning/alert-rules": {
      body: { uid: "rule-uid-bundled" },
    },
  });
  const tmpDir = await Deno.makeTempDir();
  try {
    await Deno.mkdir(`${tmpDir}/alerts`, { recursive: true });
    await Deno.writeTextFile(
      `${tmpDir}/alerts/edge-5xx.json`,
      JSON.stringify({ title: "edge-5xx-high" }),
    );

    const { context, writes } = stubContext(tmpDir);
    assertEquals(Object.hasOwn(context, "repoDir"), false);

    await method("pushAlertRule").execute(
      { ruleFile: "alerts/edge-5xx.json", ruleContent: "" },
      context,
    );
    assertEquals(writes[0].data.uid, "rule-uid-bundled");
  } finally {
    mock.restore();
    await Deno.remove(tmpDir, { recursive: true }).catch(() => {});
  }
});

Deno.test("pushAlertRule: requires ruleFile or ruleContent", async () => {
  const { context } = stubContext("/nonexistent");
  await assertRejects(
    () =>
      method("pushAlertRule").execute(
        { ruleFile: "", ruleContent: "" },
        context,
      ),
    Error,
    "ruleFile or ruleContent is required",
  );
});

// --- queryLogs (native method, formerly the @shrug/grafana-ext merge) ------

Deno.test("queryLogs: auto-discovers the first Loki datasource and snapshots the result", async () => {
  const mock = installFetch({
    "GET /api/datasources": {
      body: [
        { id: 1, name: "Mimir", type: "prometheus" },
        { id: 2, name: "Loki", type: "loki" },
      ],
    },
    "GET /api/datasources/proxy/2/loki/api/v1/query_range": {
      body: {
        status: "success",
        data: {
          resultType: "streams",
          result: [
            {
              stream: { service_name: "caddy" },
              values: [["1700000000000000000", "error: upstream timeout"]],
            },
          ],
        },
      },
    },
  });
  try {
    const { context, writes } = stubContext("/nonexistent");
    const res = await method("queryLogs").execute(
      {
        query: '{service_name="caddy"} |= `error`',
        start: "1h",
        end: "",
        limit: 100,
        direction: "backward",
        datasourceName: "",
      },
      context,
    );
    const proxied = mock.calls.find((c) =>
      c.path === "/api/datasources/proxy/2/loki/api/v1/query_range"
    );
    assertEquals(proxied !== undefined, true);
    const w = writes[0].data;
    assertEquals(w.resultType, "streams");
    assertEquals(w.seriesCount, 1);
    assertEquals(w.lineCount, 1);
    assertEquals(res.dataHandles.length, 1);
  } finally {
    mock.restore();
  }
});

Deno.test("queryLogs: disambiguates by datasourceName when multiple Loki datasources exist", async () => {
  const mock = installFetch({
    "GET /api/datasources": {
      body: [
        { id: 2, name: "Loki-primary", type: "loki" },
        { id: 3, name: "Loki-secondary", type: "loki" },
      ],
    },
    "GET /api/datasources/proxy/3/loki/api/v1/query_range": {
      body: { status: "success", data: { resultType: "streams", result: [] } },
    },
  });
  try {
    const { context } = stubContext("/nonexistent");
    await method("queryLogs").execute(
      {
        query: "{app=\"x\"}",
        start: "15m",
        end: "",
        limit: 50,
        direction: "forward",
        datasourceName: "Loki-secondary",
      },
      context,
    );
    const proxied = mock.calls.find((c) =>
      c.path === "/api/datasources/proxy/3/loki/api/v1/query_range"
    );
    assertEquals(proxied !== undefined, true);
  } finally {
    mock.restore();
  }
});

Deno.test("queryLogs: no Loki datasource throws", async () => {
  const mock = installFetch({
    "GET /api/datasources": {
      body: [{ id: 1, name: "Mimir", type: "prometheus" }],
    },
  });
  try {
    const { context } = stubContext("/nonexistent");
    await assertRejects(
      () =>
        method("queryLogs").execute(
          {
            query: "{app=\"x\"}",
            start: "1h",
            end: "",
            limit: 100,
            direction: "backward",
            datasourceName: "",
          },
          context,
        ),
      Error,
      "No Loki datasource found",
    );
  } finally {
    mock.restore();
  }
});

Deno.test("queryLogs: empty query is rejected", async () => {
  const { context } = stubContext("/nonexistent");
  await assertRejects(
    () =>
      method("queryLogs").execute(
        {
          query: "",
          start: "1h",
          end: "",
          limit: 100,
          direction: "backward",
          datasourceName: "",
        },
        context,
      ),
    Error,
    "query is required",
  );
});

// --- other upstream methods ported unchanged (smoke coverage) --------------

Deno.test("queryMetrics: auto-discovers Prometheus datasource and snapshots the result", async () => {
  const mock = installFetch({
    "GET /api/datasources": {
      body: [{ id: 5, name: "Mimir", type: "prometheus" }],
    },
    "GET /api/datasources/proxy/5/api/v1/query_range": {
      body: {
        status: "success",
        data: { resultType: "matrix", result: [] },
      },
    },
  });
  try {
    const { context, writes } = stubContext("/nonexistent");
    await method("queryMetrics").execute(
      { query: "up", start: "1h", end: "", step: "2m" },
      context,
    );
    assertEquals(writes[0].data.resultType, "matrix");
  } finally {
    mock.restore();
  }
});

Deno.test("createAnnotation: requires text", async () => {
  const { context } = stubContext("/nonexistent");
  await assertRejects(
    () =>
      method("createAnnotation").execute(
        { tags: "", text: "", dashboardUid: "" },
        context,
      ),
    Error,
    "text is required",
  );
});

Deno.test("model resources include logResult alongside the ported upstream resources", () => {
  // deno-lint-ignore no-explicit-any
  const resources = (model as any).resources;
  for (
    const r of [
      "instance",
      "dashboard",
      "dashboardContent",
      "alert",
      "annotation",
      "queryResult",
      "logResult",
    ]
  ) {
    assertEquals(r in resources, true, `missing resource: ${r}`);
  }
});

Deno.test("model methods include every ported upstream method plus queryLogs", () => {
  // deno-lint-ignore no-explicit-any
  const methods = (model as any).methods;
  for (
    const m of [
      "discover",
      "pushDashboard",
      "exportDashboard",
      "getDashboard",
      "configureContactPoint",
      "configureNotificationPolicy",
      "pushAlertRule",
      "createAnnotation",
      "queryMetrics",
      "queryLogs",
    ]
  ) {
    assertEquals(m in methods, true, `missing method: ${m}`);
  }
});
