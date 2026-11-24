## 2026.11.23.1

**New:** First public release of `@shrug/grafana`, a consolidated Grafana
swamp-native toolkit. It stands alongside the community `@keeb/grafana` and the
prior `@shrug/grafana-admin` split; neither is renamed or retired by this
release.

Two behavior types:

- `@shrug/grafana/instance` forks `@keeb/grafana/instance` (MIT, keeb) and ports
  its data-plane methods (`discover`, `pushDashboard`, `exportDashboard`,
  `getDashboard`, `configureContactPoint`, `configureNotificationPolicy`,
  `pushAlertRule`, `createAnnotation`, `queryMetrics`). It adds
  orchestrator-safe inline content: `pushDashboard` and `pushAlertRule` read
  their JSON from the extension's bundled `additionalFiles` via
  `context.extensionFile()` (never `context.repoDir`) or accept it inline
  (`dashboardContent` / `ruleContent`), so a serve-dispatched worker with no
  repo checkout can push. `queryLogs` (the Loki sibling of `queryMetrics`,
  previously a separate `@shrug/grafana-ext` merge extension) is folded in as a
  native method.
- `@shrug/grafana/admin` ports `@shrug/grafana-admin/instance`'s control-plane
  methods (`listOrgs`, `ensureOrg`, `ensureDatasource`, `ensureServiceAccount`,
  `configureWebhookContactPoint`, `ensureFolder`) over Grafana server-admin
  basic auth, for operations an org-scoped service-account token cannot do.

Both types talk HTTPS to the Grafana API via `fetch()`; no host binaries are
shelled out, so the extension runs anywhere. Bundles a `shrug-grafana` skill.
