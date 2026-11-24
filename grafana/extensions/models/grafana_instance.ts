/**
 * `@shrug/grafana/instance` -- consolidated fork of the community
 * `@keeb/grafana/instance` (MIT, keeb <keeb@systeminit.com>; see LICENSE.txt
 * beside this file), standing ALONGSIDE that upstream type (this
 * is not a rename, and @keeb/grafana/instance is untouched).
 *
 * Divergence from upstream (both validated in production use before being
 * consolidated here):
 *
 * 1. `pushDashboard` / `pushAlertRule` read their JSON from this extension's
 *    BUNDLED additionalFiles via `context.extensionFile()`, never
 *    `context.repoDir` -- so they resolve on a serve-dispatched worker (no
 *    repo checkout) under remote-only. Both also accept inline
 *    `dashboardContent` / `ruleContent` so a workflow can supply content
 *    resolved orchestrator-side. `pushAlertRule`'s upload temp file goes to
 *    `/tmp`, not repoDir (a serve-dispatched worker's repoDir is an empty
 *    scratch dir).
 * 2. `queryLogs` -- the Loki sibling of `queryMetrics` -- is folded in as a
 *    NATIVE method (previously a separate `@shrug/grafana-ext` merge
 *    extension that patched onto `@keeb/grafana/instance`).
 *
 * Every other upstream method (discover, exportDashboard, getDashboard,
 * configureContactPoint, configureNotificationPolicy, createAnnotation,
 * queryMetrics) is ported unchanged.
 *
 * Manages dashboards, alert rules, contact points, notification policies,
 * annotations, Prometheus queries, and Loki log queries against a Grafana
 * HTTP API endpoint.
 */
import { z } from "npm:zod@4.4.3";

// --- Transport ---------------------------------------------------------

interface Conn {
  grafanaUrl: string;
  apiKey?: string;
}

function grafanaHeaders(conn: Conn): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (conn.apiKey) h["Authorization"] = `Bearer ${conn.apiKey}`;
  return h;
}

// deno-lint-ignore no-explicit-any
async function grafanaApiGet(conn: Conn, path: string): Promise<any> {
  const resp = await fetch(`${conn.grafanaUrl}${path}`, {
    headers: grafanaHeaders(conn),
  });
  if (!resp.ok) {
    throw new Error(
      `Grafana API GET ${path} failed: ${resp.status} ${resp.statusText}`,
    );
  }
  return resp.json();
}

async function grafanaApiPost(
  conn: Conn,
  path: string,
  body: Record<string, unknown>,
  // deno-lint-ignore no-explicit-any
): Promise<any> {
  const resp = await fetch(`${conn.grafanaUrl}${path}`, {
    method: "POST",
    headers: grafanaHeaders(conn),
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    throw new Error(
      `Grafana API POST ${path} failed: ${resp.status} ${resp.statusText}`,
    );
  }
  const text = await resp.text();
  return text ? JSON.parse(text) : {};
}

async function grafanaApiPut(
  conn: Conn,
  path: string,
  body: Record<string, unknown>,
  // deno-lint-ignore no-explicit-any
): Promise<any> {
  const resp = await fetch(`${conn.grafanaUrl}${path}`, {
    method: "PUT",
    headers: grafanaHeaders(conn),
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    throw new Error(
      `Grafana API PUT ${path} failed: ${resp.status} ${resp.statusText}`,
    );
  }
  const text = await resp.text();
  return text ? JSON.parse(text) : {};
}

async function grafanaApiPostFile(
  conn: Conn,
  path: string,
  localFilePath: string,
  // deno-lint-ignore no-explicit-any
): Promise<any> {
  // @ts-ignore - Deno API
  const content = await Deno.readTextFile(localFilePath);
  const resp = await fetch(`${conn.grafanaUrl}${path}`, {
    method: "POST",
    headers: grafanaHeaders(conn),
    body: content,
  });
  if (!resp.ok) {
    throw new Error(
      `Grafana API POST ${path} failed: ${resp.status} ${resp.statusText}`,
    );
  }
  const text = await resp.text();
  return text ? JSON.parse(text) : {};
}

/**
 * Resolve an ISO8601 timestamp or a relative token like `15m`/`24h`/`7d` to a
 * whole-second Unix time, relative to `nowSec`. Shared by queryMetrics and
 * queryLogs.
 */
export function resolveRelativeOrAbsoluteTime(
  value: string,
  nowSec: number,
): number {
  const rel = value.match(/^(\d+)([smhd])$/);
  if (rel) {
    const num = parseInt(rel[1], 10);
    const mult: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };
    return nowSec - num * mult[rel[2]];
  }
  return Math.floor(new Date(value).getTime() / 1000);
}

// --- Arguments -----------------------------------------------------------

const GlobalArgs = z.object({
  grafanaUrl: z.string().describe(
    "Grafana URL (e.g., http://grafana.example.com)",
  ),
  apiKey: z.string().default("").meta({ sensitive: true }).describe(
    "Grafana API key for authentication (optional)",
  ),
});

const DiscoverArgs = z.object({});

const PushDashboardArgs = z.object({
  dashboardFile: z.string().default("").describe(
    "Path to dashboard JSON relative to this extension's directory (a bundled additionalFile), read via context.extensionFile() so it resolves on a serve-dispatched worker. Ignored when dashboardContent is set.",
  ),
  dashboardContent: z.string().default("").describe(
    "Inline dashboard JSON. When set it is used directly and dashboardFile is ignored (lets a workflow supply content resolved orchestrator-side).",
  ),
});

const ExportDashboardArgs = z.object({
  dashboardUid: z.string().default("").describe(
    "UID of the dashboard to export",
  ),
  outputFile: z.string().default("").describe(
    "Output file path relative to repo root",
  ),
});

const GetDashboardArgs = z.object({
  dashboardUid: z.string().default("").describe(
    "UID of the dashboard to fetch",
  ),
});

const ConfigureContactPointArgs = z.object({
  webhookUrl: z.string().default("").describe("Discord webhook URL"),
  name: z.string().default("discord-alerts").describe("Contact point name"),
});

const ConfigureNotificationPolicyArgs = z.object({
  contactPointName: z.string().default("discord-alerts").describe(
    "Contact point receiver name",
  ),
});

const PushAlertRuleArgs = z.object({
  ruleFile: z.string().default("").describe(
    "Path to alert rule JSON relative to this extension's directory (a bundled additionalFile), read via context.extensionFile(). Ignored when ruleContent is set.",
  ),
  ruleContent: z.string().default("").describe(
    "Inline alert rule JSON. When set it is used directly and ruleFile is ignored.",
  ),
});

const CreateAnnotationArgs = z.object({
  tags: z.string().default("").describe("JSON array of annotation tags"),
  text: z.string().default("").describe("Annotation text"),
  dashboardUid: z.string().default("").describe(
    "Optional dashboard UID to scope annotation",
  ),
});

const QueryMetricsArgs = z.object({
  query: z.string().default("").describe("PromQL query string"),
  start: z.string().default("").describe(
    "Range start time (ISO8601 or relative like '24h')",
  ),
  end: z.string().default("").describe(
    "Range end time (ISO8601, defaults to now)",
  ),
  step: z.string().default("2m").describe("Query step interval"),
});

const QueryLogsArgs = z.object({
  query: z.string().default("").describe("LogQL query string"),
  start: z.string().default("1h").describe(
    "Range start (ISO8601 or relative like '15m'/'24h')",
  ),
  end: z.string().default("").describe(
    "Range end (ISO8601 or relative; defaults to now)",
  ),
  limit: z.number().default(100).describe("Max log lines to return"),
  direction: z
    .enum(["backward", "forward"])
    .default("backward")
    .describe("Newest-first ('backward') or oldest-first ('forward')"),
  datasourceName: z
    .string()
    .default("")
    .describe(
      "Loki datasource name to disambiguate (default: first Loki DS)",
    ),
});

// --- Resource schemas ------------------------------------------------------

const InstanceSchema = z.object({
  grafanaVersion: z.string(),
  dashboards: z.string(),
  datasources: z.string(),
  timestamp: z.string(),
});

const DashboardSchema = z.object({
  uid: z.string(),
  title: z.string(),
  action: z.string(),
  timestamp: z.string(),
});

const DashboardContentSchema = z.object({
  uid: z.string(),
  title: z.string(),
  description: z.string(),
  tags: z.string(),
  panels: z.string(),
  templating: z.string(),
  panelCount: z.number(),
  timestamp: z.string(),
});

const AlertSchema = z.object({
  title: z.string(),
  uid: z.string().optional(),
  timestamp: z.string(),
});

const AnnotationSchema = z.object({
  id: z.number().optional(),
  tags: z.string(),
  text: z.string(),
  timestamp: z.string(),
});

const QueryResultSchema = z.object({
  query: z.string(),
  resultType: z.string(),
  results: z.string(),
  seriesCount: z.number(),
  timestamp: z.string(),
});

const LogResultSchema = z.object({
  query: z.string(),
  resultType: z.string().describe("Loki result type: 'streams' or 'matrix'"),
  results: z.string().describe("JSON-encoded Loki result array"),
  seriesCount: z.number().describe(
    "Number of streams (or matrix series) returned",
  ),
  lineCount: z.number().describe("Total log lines across all streams"),
  timestamp: z.string(),
});

/** Swamp behavior definition for `@shrug/grafana/instance`. */
export const model = {
  type: "@shrug/grafana/instance",
  version: "2026.11.23.1",
  resources: {
    "instance": {
      description: "Grafana instance discovery result",
      schema: InstanceSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "dashboard": {
      description: "Dashboard push/export result",
      schema: DashboardSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "dashboardContent": {
      description:
        "Full dashboard content from Grafana (panels, variables, etc.)",
      schema: DashboardContentSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "alert": {
      description: "Alert rule push result",
      schema: AlertSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "annotation": {
      description: "Grafana annotation",
      schema: AnnotationSchema,
      lifetime: "1h",
      garbageCollection: 50,
    },
    "queryResult": {
      description: "Prometheus query result",
      schema: QueryResultSchema,
      lifetime: "1h",
      garbageCollection: 20,
    },
    "logResult": {
      description: "Loki LogQL query result (streams + lines)",
      schema: LogResultSchema,
      lifetime: "1h",
      garbageCollection: 20,
    },
  },
  globalArguments: GlobalArgs,
  methods: {
    discover: {
      description:
        "Validate Grafana is running, list dashboards and datasources",
      arguments: DiscoverArgs,
      // deno-lint-ignore no-explicit-any
      execute: async (_args: Record<string, never>, context: any) => {
        const conn = context.globalArgs;

        console.log(`[discover] Checking Grafana on ${conn.grafanaUrl}`);

        const health = await grafanaApiGet(conn, "/api/health");
        console.log(
          `[discover] Grafana version: ${health.version}, database: ${health.database}`,
        );

        const dashboards = await grafanaApiGet(
          conn,
          "/api/search?type=dash-db",
        );
        console.log(`[discover] Found ${dashboards.length} dashboards:`);
        for (const d of dashboards) {
          console.log(`  - ${d.title} (uid: ${d.uid})`);
        }

        const datasources = await grafanaApiGet(conn, "/api/datasources");
        console.log(`[discover] Found ${datasources.length} datasources:`);
        for (const ds of datasources) {
          console.log(`  - ${ds.name} (type: ${ds.type})`);
        }

        const handles = [];

        const instanceHandle = await context.writeResource(
          "instance",
          "instance",
          {
            grafanaVersion: health.version || "unknown",
            dashboards: JSON.stringify(
              // deno-lint-ignore no-explicit-any
              dashboards.map((d: any) => ({ uid: d.uid, title: d.title })),
            ),
            datasources: JSON.stringify(
              // deno-lint-ignore no-explicit-any
              datasources.map((ds: any) => ({ name: ds.name, type: ds.type })),
            ),
            timestamp: new Date().toISOString(),
          },
        );
        handles.push(instanceHandle);

        // deno-lint-ignore no-explicit-any
        for (const d of dashboards as any[]) {
          const dHandle = await context.writeResource("dashboard", d.uid, {
            uid: d.uid,
            title: d.title,
            action: "discovered",
            timestamp: new Date().toISOString(),
          });
          handles.push(dHandle);
        }

        return { dataHandles: handles };
      },
    },

    pushDashboard: {
      description:
        "Push dashboard JSON to Grafana, read from a bundled file (context.extensionFile) or inline content",
      arguments: PushDashboardArgs,
      execute: async (
        args: { dashboardFile: string; dashboardContent: string },
        // deno-lint-ignore no-explicit-any
        context: any,
      ) => {
        const { dashboardFile, dashboardContent } = args;
        if (!dashboardFile && !dashboardContent) {
          throw new Error("dashboardFile or dashboardContent is required");
        }
        const conn = context.globalArgs;

        let raw: string;
        if (dashboardContent) {
          console.log(`[pushDashboard] Using inline dashboardContent`);
          raw = dashboardContent;
        } else {
          // Resolve from this extension's bundled additionalFiles so the
          // read works on a serve-dispatched worker (no repo checkout) under
          // remote-only -- NOT context.repoDir.
          const filePath = context.extensionFile(dashboardFile);
          console.log(`[pushDashboard] Reading ${filePath}`);
          // @ts-ignore - Deno API
          raw = await Deno.readTextFile(filePath);
        }
        const dashboardJson = JSON.parse(raw);

        // Ensure id is null so Grafana resolves by UID (create-or-update)
        dashboardJson.id = null;

        // Write wrapped payload to a temp file
        const payload = JSON.stringify({
          dashboard: dashboardJson,
          overwrite: true,
        });
        const tmpPath = `/tmp/grafana-dash-${Date.now()}.json`;
        // @ts-ignore - Deno API
        await Deno.writeTextFile(tmpPath, payload);

        try {
          console.log(
            `[pushDashboard] Pushing '${dashboardJson.title}' (uid: ${dashboardJson.uid})`,
          );
          const result = await grafanaApiPostFile(
            conn,
            "/api/dashboards/db",
            tmpPath,
          );
          console.log(
            `[pushDashboard] Result: status=${result.status}, uid=${result.uid}`,
          );

          const handle = await context.writeResource(
            "dashboard",
            dashboardJson.uid || "unknown",
            {
              uid: result.uid || dashboardJson.uid || "unknown",
              title: dashboardJson.title || "unknown",
              action: result.status || "pushed",
              timestamp: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } finally {
          // @ts-ignore - Deno API
          await Deno.remove(tmpPath).catch(() => {});
        }
      },
    },

    exportDashboard: {
      description: "Export a dashboard from Grafana to a local JSON file",
      arguments: ExportDashboardArgs,
      execute: async (
        args: { dashboardUid: string; outputFile: string },
        // deno-lint-ignore no-explicit-any
        context: any,
      ) => {
        const { dashboardUid, outputFile } = args;
        if (!dashboardUid) throw new Error("dashboardUid is required");
        if (!outputFile) throw new Error("outputFile is required");
        const conn = context.globalArgs;

        console.log(`[exportDashboard] Exporting uid=${dashboardUid}`);
        const result = await grafanaApiGet(
          conn,
          `/api/dashboards/uid/${dashboardUid}`,
        );

        const dashboard = result.dashboard;
        if (!dashboard) throw new Error(`Dashboard ${dashboardUid} not found`);

        // exportDashboard is an operator-driven, local-checkout operation
        // (not serve-dispatched), so it keeps writing via context.repoDir.
        const outPath = `${context.repoDir}/${outputFile}`;
        console.log(`[exportDashboard] Writing to ${outPath}`);
        // @ts-ignore - Deno API
        await Deno.writeTextFile(
          outPath,
          JSON.stringify(dashboard, null, 2) + "\n",
        );
        console.log(
          `[exportDashboard] Exported '${dashboard.title}' (${
            Object.keys(dashboard).length
          } top-level keys)`,
        );

        const handle = await context.writeResource("dashboard", dashboardUid, {
          uid: dashboardUid,
          title: dashboard.title || "unknown",
          action: "exported",
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    getDashboard: {
      description:
        "Fetch a dashboard from Grafana and store its full content (panels, variables, etc.)",
      arguments: GetDashboardArgs,
      execute: async (
        args: { dashboardUid: string },
        // deno-lint-ignore no-explicit-any
        context: any,
      ) => {
        const { dashboardUid } = args;
        if (!dashboardUid) throw new Error("dashboardUid is required");
        const conn = context.globalArgs;

        console.log(`[getDashboard] Fetching dashboard uid=${dashboardUid}`);
        const result = await grafanaApiGet(
          conn,
          `/api/dashboards/uid/${dashboardUid}`,
        );

        const dashboard = result.dashboard;
        if (!dashboard) throw new Error(`Dashboard ${dashboardUid} not found`);

        const panels = dashboard.panels || [];
        const templating = dashboard.templating?.list || [];

        console.log(`[getDashboard] Dashboard '${dashboard.title}'`);
        console.log(`[getDashboard]   Panels: ${panels.length}`);
        // deno-lint-ignore no-explicit-any
        for (const p of panels as any[]) {
          console.log(`    - [${p.type}] ${p.title || "(untitled)"}`);
        }
        if (templating.length > 0) {
          console.log(`[getDashboard]   Variables: ${templating.length}`);
          // deno-lint-ignore no-explicit-any
          for (const v of templating as any[]) {
            console.log(`    - ${v.name} (${v.type})`);
          }
        }

        const handle = await context.writeResource(
          "dashboardContent",
          dashboardUid,
          {
            uid: dashboardUid,
            title: dashboard.title || "unknown",
            description: dashboard.description || "",
            tags: JSON.stringify(dashboard.tags || []),
            panels: JSON.stringify(panels),
            templating: JSON.stringify(templating),
            panelCount: panels.length,
            timestamp: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    configureContactPoint: {
      description:
        "Create or update a Discord webhook contact point in Grafana",
      arguments: ConfigureContactPointArgs,
      execute: async (
        args: { webhookUrl: string; name: string },
        // deno-lint-ignore no-explicit-any
        context: any,
      ) => {
        const { webhookUrl, name = "discord-alerts" } = args;
        if (!webhookUrl) throw new Error("webhookUrl is required");
        const conn = context.globalArgs;

        console.log(
          `[configureContactPoint] Setting up '${name}' contact point`,
        );

        const contactPoint = {
          name,
          type: "discord",
          settings: {
            url: webhookUrl,
            use_discord_username: true,
          },
          disableResolveMessage: false,
        };

        const result = await grafanaApiPost(
          conn,
          "/api/v1/provisioning/contact-points",
          contactPoint,
        );
        console.log(
          `[configureContactPoint] Contact point '${name}' configured (uid: ${
            result.uid || "ok"
          })`,
        );

        const handle = await context.writeResource("alert", `cp-${name}`, {
          title: name,
          uid: result.uid,
          timestamp: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    configureNotificationPolicy: {
      description:
        "Set the default notification policy to route to a contact point",
      arguments: ConfigureNotificationPolicyArgs,
      execute: async (
        args: { contactPointName: string },
        // deno-lint-ignore no-explicit-any
        context: any,
      ) => {
        const { contactPointName = "discord-alerts" } = args;
        const conn = context.globalArgs;

        console.log(
          `[configureNotificationPolicy] Setting default receiver to '${contactPointName}'`,
        );

        const policy = {
          receiver: contactPointName,
          group_by: ["alertname", "instance"],
          group_wait: "30s",
          group_interval: "5m",
          repeat_interval: "4h",
        };

        await grafanaApiPut(conn, "/api/v1/provisioning/policies", policy);
        console.log(
          `[configureNotificationPolicy] Notification policy updated`,
        );

        const handle = await context.writeResource(
          "alert",
          "notification-policy",
          {
            title: `policy -> ${contactPointName}`,
            timestamp: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    pushAlertRule: {
      description:
        "Push alert rule JSON to Grafana, read from a bundled file (context.extensionFile) or inline content",
      arguments: PushAlertRuleArgs,
      execute: async (
        args: { ruleFile: string; ruleContent: string },
        // deno-lint-ignore no-explicit-any
        context: any,
      ) => {
        const { ruleFile, ruleContent } = args;
        if (!ruleFile && !ruleContent) {
          throw new Error("ruleFile or ruleContent is required");
        }
        const conn = context.globalArgs;

        let raw: string;
        if (ruleContent) {
          console.log(`[pushAlertRule] Using inline ruleContent`);
          raw = ruleContent;
        } else {
          // Bundled additionalFile (see pushDashboard) -- resolves on a
          // serve-dispatched worker.
          const filePath = context.extensionFile(ruleFile);
          console.log(`[pushAlertRule] Reading ${filePath}`);
          // @ts-ignore - Deno API
          raw = await Deno.readTextFile(filePath);
        }
        const rule = JSON.parse(raw);

        // Use file-based upload to avoid shell escaping $labels in annotation
        // templates. Write to /tmp, NOT repoDir: on a serve-dispatched worker
        // repoDir is an empty scratch dir, and locally this avoids littering
        // the checkout.
        const tmpFile = `/tmp/grafana-alert-${Date.now()}.json`;
        // @ts-ignore - Deno API
        await Deno.writeTextFile(tmpFile, raw);
        console.log(`[pushAlertRule] Pushing alert rule '${rule.title}'`);
        const result = await grafanaApiPostFile(
          conn,
          "/api/v1/provisioning/alert-rules",
          tmpFile,
        );
        // @ts-ignore - Deno API
        try {
          await Deno.remove(tmpFile);
        } catch (_e) { /* ignore */ }
        console.log(
          `[pushAlertRule] Alert rule pushed (uid: ${result.uid || "ok"})`,
        );

        const handle = await context.writeResource(
          "alert",
          rule.title || "unknown",
          {
            title: rule.title || "unknown",
            uid: result.uid,
            timestamp: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    createAnnotation: {
      description:
        "Create a Grafana annotation (global or scoped to a dashboard)",
      arguments: CreateAnnotationArgs,
      execute: async (
        args: { tags: string; text: string; dashboardUid: string },
        // deno-lint-ignore no-explicit-any
        context: any,
      ) => {
        const { tags: tagsStr, text, dashboardUid } = args;
        if (!text) throw new Error("text is required");
        const conn = context.globalArgs;

        const tags = tagsStr ? JSON.parse(tagsStr) : [];
        // deno-lint-ignore no-explicit-any
        const annotation: Record<string, any> = {
          text,
          tags,
          time: Date.now(),
        };

        if (dashboardUid) {
          // Look up dashboard ID from UID
          const dashResult = await grafanaApiGet(
            conn,
            `/api/dashboards/uid/${dashboardUid}`,
          );
          if (dashResult.dashboard) {
            annotation.dashboardId = dashResult.dashboard.id;
          }
        }

        console.log(
          `[createAnnotation] Creating annotation: "${text}" tags=${
            JSON.stringify(tags)
          }`,
        );
        const result = await grafanaApiPost(
          conn,
          "/api/annotations",
          annotation,
        );
        console.log(`[createAnnotation] Annotation created (id: ${result.id})`);

        const handle = await context.writeResource(
          "annotation",
          `ann-${Date.now()}`,
          {
            id: result.id,
            tags: JSON.stringify(tags),
            text,
            timestamp: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    queryMetrics: {
      description: "Query Prometheus metrics via Grafana datasource proxy",
      arguments: QueryMetricsArgs,
      execute: async (
        args: { query: string; start: string; end: string; step: string },
        // deno-lint-ignore no-explicit-any
        context: any,
      ) => {
        const { query, start, end, step = "2m" } = args;
        if (!query) throw new Error("query is required");
        if (!start) throw new Error("start is required");
        const conn = context.globalArgs;

        // Discover Prometheus datasource ID
        console.log(`[queryMetrics] Discovering Prometheus datasource...`);
        const datasources = await grafanaApiGet(conn, "/api/datasources");
        // deno-lint-ignore no-explicit-any
        const promDs = (datasources as any[]).find((ds) =>
          ds.type === "prometheus"
        );
        if (!promDs) {
          throw new Error("No Prometheus datasource found in Grafana");
        }
        console.log(
          `[queryMetrics] Using datasource '${promDs.name}' (id: ${promDs.id})`,
        );

        const nowSec = Math.floor(Date.now() / 1000);
        const startSec = resolveRelativeOrAbsoluteTime(start, nowSec);
        const endSec = end
          ? resolveRelativeOrAbsoluteTime(end, nowSec)
          : nowSec;

        console.log(`[queryMetrics] Query: ${query}`);
        console.log(
          `[queryMetrics] Range: ${
            new Date(startSec * 1000).toISOString()
          } -> ${new Date(endSec * 1000).toISOString()} step=${step}`,
        );

        // Query via datasource proxy -- use GET with URL-encoded params to
        // avoid shell escaping PromQL.
        const encodedQuery = encodeURIComponent(query);
        const path =
          `/api/datasources/proxy/${promDs.id}/api/v1/query_range?query=${encodedQuery}&start=${startSec}&end=${endSec}&step=${step}`;
        const response = await grafanaApiGet(conn, path);

        if (response.status !== "success") {
          throw new Error(
            `Prometheus query failed: ${
              response.error || JSON.stringify(response)
            }`,
          );
        }

        const resultType = response.data.resultType || "unknown";
        const series = response.data.result || [];
        console.log(
          `[queryMetrics] Result type: ${resultType}, series count: ${series.length}`,
        );

        // deno-lint-ignore no-explicit-any
        for (const s of series as any[]) {
          const labels = s.metric || {};
          const labelStr = Object.entries(labels).map(([k, v]) => `${k}="${v}"`)
            .join(", ");
          const values = s.values || [];
          // deno-lint-ignore no-explicit-any
          const nonZero = values.filter((v: any) => parseFloat(v[1]) > 0);

          console.log(
            `\n  Series: {${labelStr}} (${values.length} samples, ${nonZero.length} non-zero)`,
          );

          if (nonZero.length > 0 && nonZero.length <= 50) {
            // deno-lint-ignore no-explicit-any
            for (const v of nonZero as any[]) {
              const ts = new Date(v[0] * 1000).toISOString();
              console.log(`    ${ts}  ${v[1]}`);
            }
          } else if (nonZero.length > 50) {
            // deno-lint-ignore no-explicit-any
            for (const v of (nonZero as any[]).slice(0, 5)) {
              const ts = new Date(v[0] * 1000).toISOString();
              console.log(`    ${ts}  ${v[1]}`);
            }
            console.log(
              `    ... (${nonZero.length - 10} more non-zero samples)`,
            );
            // deno-lint-ignore no-explicit-any
            for (const v of (nonZero as any[]).slice(-5)) {
              const ts = new Date(v[0] * 1000).toISOString();
              console.log(`    ${ts}  ${v[1]}`);
            }
          }
        }

        console.log(
          `\n[queryMetrics] Done -- ${series.length} series returned`,
        );

        const handle = await context.writeResource(
          "queryResult",
          `query-${Date.now()}`,
          {
            query,
            resultType,
            results: JSON.stringify(series),
            seriesCount: series.length,
            timestamp: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    queryLogs: {
      description:
        "Query Loki logs via the Grafana Loki datasource proxy (LogQL query_range). The Loki sibling of queryMetrics.",
      arguments: QueryLogsArgs,
      execute: async (
        args: {
          query: string;
          start: string;
          end: string;
          limit: number;
          direction: "backward" | "forward";
          datasourceName: string;
        },
        // deno-lint-ignore no-explicit-any
        context: any,
      ) => {
        const { query, start, end, limit, direction, datasourceName } = args;
        if (!query) throw new Error("query is required");
        if (!start) throw new Error("start is required");
        const conn = context.globalArgs;

        console.log(`[queryLogs] Discovering Loki datasource...`);
        const datasources = await grafanaApiGet(conn, "/api/datasources");
        // deno-lint-ignore no-explicit-any
        const lokiCandidates = (datasources as any[]).filter((ds) =>
          ds.type === "loki"
        );
        if (lokiCandidates.length === 0) {
          throw new Error("No Loki datasource found in Grafana");
        }
        const lokiDs = datasourceName
          // deno-lint-ignore no-explicit-any
          ? lokiCandidates.find((ds: any) => ds.name === datasourceName)
          : lokiCandidates[0];
        if (!lokiDs) {
          throw new Error(
            `Loki datasource '${datasourceName}' not found (have: ${
              // deno-lint-ignore no-explicit-any
              lokiCandidates.map((d: any) => d.name).join(", ")})`,
          );
        }
        console.log(
          `[queryLogs] Using datasource '${lokiDs.name}' (id: ${lokiDs.id})`,
        );

        const nowSec = Math.floor(Date.now() / 1000);
        const startSec = resolveRelativeOrAbsoluteTime(start, nowSec);
        const endSec = end
          ? resolveRelativeOrAbsoluteTime(end, nowSec)
          : nowSec;
        // Loki wants nanosecond timestamps.
        const startNs = `${startSec}000000000`;
        const endNs = `${endSec}000000000`;

        console.log(`[queryLogs] Query: ${query}`);
        console.log(
          `[queryLogs] Range: ${new Date(startSec * 1000).toISOString()} -> ${
            new Date(endSec * 1000).toISOString()
          } limit=${limit} direction=${direction}`,
        );

        const params = new URLSearchParams({
          query,
          start: startNs,
          end: endNs,
          limit: String(limit),
          direction,
        });
        const path =
          `/api/datasources/proxy/${lokiDs.id}/loki/api/v1/query_range?${params.toString()}`;
        const response = await grafanaApiGet(conn, path);

        if (response.status !== "success") {
          throw new Error(
            `Loki query failed: ${response.error || JSON.stringify(response)}`,
          );
        }

        const resultType = response.data?.resultType || "unknown";
        const series = response.data?.result || [];
        let lineCount = 0;

        // deno-lint-ignore no-explicit-any
        for (const s of series as any[]) {
          const labels = s.stream || s.metric || {};
          const labelStr = Object.entries(labels).map(([k, v]) => `${k}="${v}"`)
            .join(", ");
          const values = s.values || [];
          lineCount += values.length;
          console.log(`\n  Stream: {${labelStr}} (${values.length} entries)`);
          const shown = values.slice(0, 20);
          // deno-lint-ignore no-explicit-any
          for (const [ts, line] of shown as any[]) {
            const iso = new Date(Number(ts) / 1e6).toISOString();
            console.log(`    ${iso}  ${line}`);
          }
          if (values.length > shown.length) {
            console.log(
              `    ... (${values.length - shown.length} more entries)`,
            );
          }
        }

        console.log(
          `\n[queryLogs] Done -- ${series.length} streams, ${lineCount} lines returned`,
        );

        const handle = await context.writeResource(
          "logResult",
          `logs-${Date.now()}`,
          {
            query,
            resultType,
            results: JSON.stringify(series),
            seriesCount: series.length,
            lineCount,
            timestamp: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
  },
};
