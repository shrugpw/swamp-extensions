# @shrug/grafana

Consolidated Grafana swamp-native toolkit. Two types, standing
ALONGSIDE the pre-existing community
[`@keeb/grafana/instance`](https://github.com/keeb/swamp-grafana) and
`@shrug/grafana-admin/instance` -- neither of those is renamed, retired, or
migrated by this extension; every existing instance keeps running on its
current type.

1. **`@shrug/grafana/instance`** -- a fork of `@keeb/grafana/instance` (MIT,
   keeb) that:
   - Reads `pushDashboard` / `pushAlertRule` JSON from this extension's
     bundled `additionalFiles` via `context.extensionFile()` -- never
     `context.repoDir` -- or accepts the JSON inline (`dashboardContent` /
     `ruleContent`). This is what lets a serve-dispatched, repo-less worker
     push a dashboard or alert rule.
   - Folds `queryLogs` (the Loki sibling of `queryMetrics`) in as a *native*
     method, replacing the separate `@shrug/grafana-ext` merge-extension
     pattern.
   - Keeps every other upstream method unchanged: `discover`,
     `exportDashboard`, `getDashboard`, `configureContactPoint`,
     `configureNotificationPolicy`, `createAnnotation`, `queryMetrics`.
2. **`@shrug/grafana/admin`** -- ported from `@shrug/grafana-admin/instance`
   as a new type-id. Grafana *control-plane* operations over server
   **admin basic-auth**, for things an org-scoped SA token cannot do:
   `listOrgs`, `ensureOrg`, `ensureDatasource`, `ensureServiceAccount`
   (optionally minting a token), `configureWebhookContactPoint`,
   `ensureFolder`.

## `@shrug/grafana/instance`

### Global arguments

| Field        | Required | Description                                                |
| ------------ | -------- | ---------------------------------------------------------- |
| `grafanaUrl` | yes      | Base URL, e.g. `http://grafana.example.com`                |
| `apiKey`     | no       | Bearer token (org-scoped service-account token)             |

### Methods

| Method                        | Purpose                                                  |
| ------------------------------ | --------------------------------------------------------- |
| `discover`                     | Hit `/api/health`, list dashboards + datasources           |
| `pushDashboard`                | Push dashboard JSON (bundled file or inline content)        |
| `exportDashboard`              | GET dashboard by UID, write JSON to the repo checkout       |
| `getDashboard`                 | Fetch full dashboard content (panels, variables) as data     |
| `configureContactPoint`        | Create/update Discord webhook contact point                  |
| `configureNotificationPolicy`  | Set default routing receiver                                 |
| `pushAlertRule`                | Push alert rule JSON (bundled file or inline content)         |
| `createAnnotation`             | Create annotation (global or scoped to dashboard)             |
| `queryMetrics`                 | PromQL query via Grafana datasource proxy                    |
| `queryLogs`                    | LogQL query via Grafana's Loki datasource proxy               |

`pushDashboard` / `pushAlertRule` argument notes:

- `dashboardFile` / `ruleFile` are paths **relative to this extension's
  directory** -- resolved via `context.extensionFile()` against the bundled
  `additionalFiles`, not `context.repoDir`. Set `dashboardContent` /
  `ruleContent` instead to supply the JSON inline (e.g. resolved
  orchestrator-side by a workflow); when content is set the file input is
  ignored.
- `pushDashboard` forces `dashboard.id = null` so Grafana resolves by `uid`
  (create-or-update). Your dashboard JSON **must** have a `uid`.
- `pushAlertRule` writes its upload temp file to `/tmp`, not `repoDir` -- a
  serve-dispatched worker's `repoDir` is an empty scratch dir.
- `exportDashboard`'s `outputFile` is still relative to `context.repoDir`: it
  is an operator-driven, local-checkout export, not a serve-dispatched push.
- `createAnnotation.tags` is a **JSON array string**, e.g. `'["deploy","prod"]'`,
  not a YAML list.
- `queryMetrics` / `queryLogs` `start`/`end` accept relative shorthand (`24h`,
  `7d`, `30m`, `45s`) **or** ISO8601. Each auto-discovers the first datasource
  of the matching type (`prometheus` / `loki`); `queryLogs` also accepts
  `datasourceName` to disambiguate when more than one Loki datasource exists.
- `configureContactPoint` is hardcoded to `type: "discord"`. Extend the model
  for other contact-point types (see `@shrug/grafana/admin`'s
  `configureWebhookContactPoint` for a generic webhook alternative).

### Resources written

| Resource           | Lifetime | Notes                                   |
| ------------------- | -------- | ---------------------------------------- |
| `instance`          | infinite | One per `discover` call (id `instance`)   |
| `dashboard`         | infinite | id = dashboard `uid`                      |
| `dashboardContent`  | infinite | Full panels/templating JSON, id = `uid`    |
| `alert`             | infinite | Used for alert rules and contact points     |
| `annotation`        | 1h       | id = `ann-<timestamp>`                    |
| `queryResult`       | 1h       | id = `query-<timestamp>`                  |
| `logResult`         | 1h       | id = `logs-<timestamp>`                   |

## `@shrug/grafana/admin`

Dry-run by default -- every mutating method reports the plan and mutates
nothing until `confirm:true`. Minting a service-account token is a second
opt-in (`mintToken:true`); the secret is printed to the run log **once**
(Grafana never reveals it again) and is deliberately not persisted in swamp
data.

```bash
# Instance (admin basic-auth; password resolved from a vault via CEL)
swamp behavior create @shrug/grafana/admin grafana-admin \
  --global-arg 'grafanaUrl=https://grafana.example.com' \
  --global-arg 'adminPassword=${{ vault.get("<vault>", "grafana/admin-password") }}'

# Dry run -- what would happen?
swamp behavior run grafana-admin ensureServiceAccount \
  --input orgId:json=1 --input name=dashboards --input role=Editor

# Apply + mint the token (secret printed once)
swamp behavior run grafana-admin ensureServiceAccount \
  --input orgId:json=1 --input name=dashboards --input role=Editor \
  --input mintToken:json=true --input confirm:json=true
```

| Method                          | Purpose                                                         |
| -------------------------------- | ---------------------------------------------------------------- |
| `listOrgs`                       | Read-only: list every org visible to the server admin             |
| `ensureOrg`                       | Idempotently ensure an org by name, return its id                 |
| `ensureDatasource`                | Idempotently ensure a tenant-scoped prometheus/loki datasource     |
| `ensureServiceAccount`            | Idempotently ensure a service account, optionally mint a token      |
| `configureWebhookContactPoint`    | Idempotently ensure a generic webhook (e.g. ntfy) contact point      |
| `ensureFolder`                    | Idempotently ensure a folder by title, return its uid                |

The admin's active org is switched to `orgId` for org-scoped operations and
restored afterward.

## Tests

```bash
~/.swamp/deno/deno test -A extensions/models/grafana_instance_test.ts
~/.swamp/deno/deno test -A extensions/models/grafana_admin_test.ts
```

## Provenance

- `@shrug/grafana/instance` forks `@keeb/grafana/instance` (MIT, keeb
  <keeb@systeminit.com>); the inline-content / `extensionFile` divergence was
  validated in production use before being consolidated here.
- `queryLogs` was previously `@shrug/grafana-ext`'s `grafana_logs.ts` merge
  extension; it is now a native method on this type.
- `@shrug/grafana/admin` ports `@shrug/grafana-admin/instance`'s
  `grafana_admin.ts` logic verbatim under the new type-id.

## License

MIT -- (c) keeb <keeb@systeminit.com> (upstream `@keeb/grafana/instance`);
(c) Neil Hanlon / ShrugPW (fork, `@shrug/grafana/admin`, inline-content and
`queryLogs` additions). See LICENSE.txt.
