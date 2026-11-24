---
name: shrug-grafana
description: Shrug's consolidated Grafana extension and the preferred path for internal ShrugPW Grafana work, superseding the `grafana` (@keeb) skill for that use. Drives the `@shrug/grafana/instance` and `@shrug/grafana/admin` behavior types for dashboards and alerts via a bundled file OR orchestrator-safe inline content (dashboardContent/ruleContent, safe for serve-dispatched and repo-less workers), PromQL and LogQL queries, deploy annotations, Discord/webhook contact points and notification policies, and server-admin control-plane ops (orgs, datasources, service accounts, folders) over admin basic-auth. Triggers on "@shrug/grafana", "shrug grafana", "grafana_admin", "queryLogs", "logql via grafana", "ensureOrg", "ensureDatasource", "ensureServiceAccount", "ensureFolder", "inline dashboard content", "serve-dispatched grafana push", "grafana server-admin". For the upstream community `@keeb/grafana/instance` type specifically, use the `grafana` skill instead.
---

# @shrug/grafana

Swamp extension that manages Grafana via the HTTP API. Forked from the
community `@keeb/grafana` extension (its skill is this file's ancestor) and
consolidated with the former `@shrug/grafana-admin` + `@shrug/grafana-ext`
split. Two behavior types:

- `@shrug/grafana/instance` -- data plane, authenticates with an org-scoped
  service-account Bearer token.
- `@shrug/grafana/admin` -- control plane, authenticates with server
  admin basic-auth.

This extension stands ALONGSIDE the pre-existing `@keeb/grafana/instance` and
`@shrug/grafana-admin/instance` types. Neither is renamed or retired by it;
existing instances of those types keep running unchanged. Prefer the new
consolidated types for new work.

## Type: `@shrug/grafana/instance`

Type identifier: `@shrug/grafana/instance`. All methods talk directly to the
Grafana HTTP API using `fetch()` (no SDK).

### Global arguments

Set once on the instance -- applies to every method call.

| Field        | Required | Description                                                |
| ------------ | -------- | ---------------------------------------------------------- |
| `grafanaUrl` | yes      | Base URL, e.g. `http://grafana.example.com`                |
| `apiKey`     | no       | Bearer token. Empty string allowed for unauthenticated dev |

### Methods

| Method                        | Purpose                                                  | Required args                                  |
| ----------------------------- | --------------------------------------------------------- | ----------------------------------------------- |
| `discover`                    | Hit `/api/health`, list dashboards + datasources           | none                                             |
| `pushDashboard`                | Push dashboard JSON (bundled file or inline content)         | `dashboardFile` OR `dashboardContent`             |
| `exportDashboard`              | GET dashboard by UID, write JSON to the repo checkout       | `dashboardUid`, `outputFile`                      |
| `getDashboard`                 | Fetch full dashboard content (panels, variables) as data     | `dashboardUid`                                    |
| `configureContactPoint`        | Create/update Discord webhook contact point                  | `webhookUrl`                                      |
| `configureNotificationPolicy`  | Set default routing receiver                                  | none (defaults to discord-alerts)                  |
| `pushAlertRule`                | Push alert rule JSON (bundled file or inline content)          | `ruleFile` OR `ruleContent`                         |
| `createAnnotation`             | Create annotation (global or scoped to dashboard)              | `text`                                              |
| `queryMetrics`                 | PromQL query via Grafana datasource proxy                      | `query`, `start`                                     |
| `queryLogs`                    | LogQL query via Grafana's Loki datasource proxy                 | `query`, `start`                                     |

Method-arg notes:

- `pushDashboard` / `pushAlertRule` read `dashboardFile` / `ruleFile` as a
  path **relative to this extension's directory**, resolved via
  `context.extensionFile()` against the bundled `additionalFiles` -- NEVER
  `context.repoDir`. This is the change from the upstream `@keeb/grafana`
  behavior (which joined the path with `context.repoDir`): it lets a
  serve-dispatched worker with no repo checkout still push. Pass
  `dashboardContent` / `ruleContent` instead to supply the JSON inline (e.g.
  resolved orchestrator-side by a workflow); when content is set, the file
  input is ignored entirely and no file read happens.
- `exportDashboard`'s `outputFile` IS still relative to `context.repoDir` --
  it's an operator-driven, local-checkout export, not a push.
- `pushDashboard` forces `dashboard.id = null` so Grafana resolves by `uid`
  (create-or-update). Your dashboard JSON **must** have a `uid`.
- `pushAlertRule` writes a temp file to `/tmp` (not repoDir) to avoid
  shell-escaping `$labels` in annotation templates and to work when repoDir is
  an empty scratch dir.
- `createAnnotation.tags` is a **JSON array string**, e.g.
  `'["deploy","prod"]'`, not a YAML list -- the model calls `JSON.parse` on it.
- `queryMetrics` / `queryLogs` `start`/`end` accept relative shorthand (`24h`,
  `7d`, `30m`, `45s`) **or** ISO8601. `queryMetrics` auto-discovers the first
  `prometheus` datasource; `queryLogs` auto-discovers the first `loki`
  datasource (or pass `datasourceName` to disambiguate).
- `configureContactPoint` is hardcoded to `type: "discord"`. For a generic
  webhook (e.g. ntfy), use `@shrug/grafana/admin`'s
  `configureWebhookContactPoint` instead, or extend this model.

### Resources written

| Resource           | Lifetime | Notes                                   |
| ------------------ | -------- | ---------------------------------------- |
| `instance`         | infinite | One per `discover` call (id `instance`)   |
| `dashboard`        | infinite | id = dashboard `uid`                       |
| `dashboardContent` | infinite | Full panels/templating JSON, id = `uid`     |
| `alert`            | infinite | Used for alert rules and contact points       |
| `annotation`       | 1h       | id = `ann-<timestamp>`                       |
| `queryResult`      | 1h       | id = `query-<timestamp>`                     |
| `logResult`        | 1h       | id = `logs-<timestamp>`                      |

### Authoring inputs

```yaml
type: "@shrug/grafana/instance"
name: prod-grafana
globalArgs:
  grafanaUrl: https://grafana.example.com
  apiKey: "${{ vault.get(\"<vault>\", \"grafana/sa-token\") }}"
```

The `apiKey` is conventionally pulled from a swamp vault -- never hardcode it.

### Workflow patterns

Push a dashboard bundled with this extension, then annotate the deploy:

```yaml
jobs:
  deploy_dashboards:
    steps:
      - name: push
        model: prod-grafana
        method: pushDashboard
        args:
          dashboardFile: dashboards/api-overview.json
      - name: annotate
        model: prod-grafana
        method: createAnnotation
        args:
          text: "Deployed api-overview dashboard"
          tags: '["deploy","dashboard"]'
        dependsOn: [push]
```

Push a dashboard whose content a prior step resolved (inline content, no
bundled file needed -- this is the serve-dispatched path):

```yaml
- name: push_resolved
  model: prod-grafana
  method: pushDashboard
  args:
    dashboardContent: "${{ data.latest('render-dashboard', 'rendered').attributes.json }}"
```

Query Loki alongside Prometheus off the same instance:

```yaml
- name: recent_errors
  model: prod-grafana
  method: queryLogs
  args:
    query: '{service_name=~".+"} |= `error`'
    start: "1h"
    limit: 50
```

## Type: `@shrug/grafana/admin`

Type identifier: `@shrug/grafana/admin`. Server-admin basic-auth
control-plane -- operations an org-scoped SA token cannot do: creating other
service accounts, creating orgs, creating datasources.

### Global arguments

| Field           | Required | Description                                        |
| --------------- | -------- | --------------------------------------------------- |
| `grafanaUrl`    | yes      | Base URL (no trailing slash)                         |
| `adminUser`     | no       | Server-admin username (default `admin`)              |
| `adminPassword` | yes      | Server-admin password -- resolve from a vault, never hard-code |

### Methods

| Method                          | Purpose                                                         | Idempotency key          |
| -------------------------------- | ------------------------------------------------------------------ | -------------------------- |
| `listOrgs`                       | Read-only: list every org visible to the server admin                 | n/a                          |
| `ensureOrg`                       | Idempotently ensure an org by name, return its id                      | `name`                        |
| `ensureDatasource`                | Idempotently ensure a tenant-scoped prometheus/loki datasource           | `(orgId, name)`                 |
| `ensureServiceAccount`            | Idempotently ensure a service account, optionally mint a token             | `(orgId, name)`                   |
| `configureWebhookContactPoint`    | Idempotently ensure a generic webhook (e.g. ntfy) contact point            | `(orgId, name)`                   |
| `ensureFolder`                    | Idempotently ensure a folder by title, return its uid                       | `(orgId, title)`                    |

All mutating methods are **dry-run by default** -- pass `confirm:true` to
apply. `ensureServiceAccount`'s `mintToken:true` is a deliberate second
opt-in; the minted secret is logged once and never persisted into swamp data.
The admin's active org is switched to `orgId` for org-scoped operations and
restored afterward (best-effort, in a `finally`).

```bash
swamp behavior create @shrug/grafana/admin grafana-admin \
  --global-arg 'grafanaUrl=https://grafana.example.com' \
  --global-arg 'adminPassword=${{ vault.get("<vault>", "grafana/admin-password") }}'

swamp behavior run grafana-admin ensureServiceAccount \
  --input orgId:json=1 --input name=dashboards --input role=Editor \
  --input mintToken:json=true --input confirm:json=true
```

## Querying results

Use `swamp data query` with CEL predicates against the resources above.

```bash
swamp data query 'modelName == "prod-grafana" && name == "dashboard"' --select content
```

## Gotchas

- **`dashboard.id` collision**: Grafana errors out if you push a dashboard
  JSON exported from a different instance unless `id` is null.
  `pushDashboard` handles this, but if you craft payloads manually elsewhere,
  strip `id`.
- **`uid` is mandatory** for `pushDashboard` to be idempotent. Missing uids
  cause Grafana to create a new dashboard every run.
- **Tags must be a JSON string**, not a YAML list.
- **`queryMetrics`/`queryLogs` pick the first matching datasource** found
  unless disambiguated (`queryLogs` accepts `datasourceName`; `queryMetrics`
  does not -- extend the model if multiple Prometheus datasources need
  targeting).
- **No DELETE methods exposed** on `@shrug/grafana/instance`. To remove
  dashboards or alert rules, use the Grafana API directly or extend the
  model.
- **`ensureServiceAccount` never returns the token secret** after the first
  mint -- Grafana doesn't either. `force:true` rotates (delete + recreate) an
  existing token of the same name.
- **This extension does NOT touch `@keeb/grafana/instance` or
  `@shrug/grafana-admin/instance`**. If you're migrating an existing
  consumer from either, that's a separate, explicitly-scoped change -- not
  implied by installing this extension.
