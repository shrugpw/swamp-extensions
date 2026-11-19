/**
 * Unit tests for @shrug/content-studio/library. Offline: the pure orchestration
 * is exercised directly, and the gated methods run against a fake in-memory
 * context (recording writeResource, serving readResource). No real datastore or
 * IO is touched. All fixtures are synthetic.
 *
 * Run with:
 *   ~/.swamp/deno/deno test library_test.ts
 *
 * @module
 */
import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.19";
import {
  auditEntries,
  type Entry,
  EntrySchema,
  filterEntries,
  isLapsed,
  model,
  reviewEntry,
  upsertEntry,
} from "./library.ts";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function entry(over: Partial<Record<string, unknown>> = {}): Entry {
  return EntrySchema.parse({
    key: "pay-schedule",
    value: "biweekly",
    scope: "company",
    status: "approved",
    tokens: ["[weekly / biweekly / semi-monthly]"],
    ...over,
  });
}

/** A fake context that records writes and serves one `entries` resource. */
function fakeContext(name: string, entries: Entry[]) {
  const writes: Array<{ spec: string; name: string; data: Record<string, unknown> }> = [];
  const ctx = {
    globalArgs: { name },
    writeResource: (spec: string, resName: string, data: Record<string, unknown>) => {
      writes.push({ spec, name: resName, data });
      return Promise.resolve({ name: resName });
    },
    readResource: (resName: string) => {
      if (resName === "entries") {
        return Promise.resolve({ library: name, entries } as Record<string, unknown>);
      }
      return Promise.resolve(null);
    },
  };
  return { ctx, writes };
}

// ---------------------------------------------------------------------------
// Pure: filterEntries
// ---------------------------------------------------------------------------

Deno.test("filterEntries matches by key, scope, tag, status", () => {
  const entries = [
    entry({ key: "pay-schedule", scope: "company", tags: ["pay"], status: "approved" }),
    entry({ key: "core-hours", scope: "company", tags: ["time"], status: "draft" }),
    entry({ key: "pay-schedule", scope: "AZ", tags: ["pay"], status: "approved" }),
  ];
  assertEquals(filterEntries(entries, { key: "pay-schedule" }).length, 2);
  assertEquals(filterEntries(entries, { scope: "AZ" }).length, 1);
  assertEquals(filterEntries(entries, { tag: "time" }).length, 1);
  assertEquals(filterEntries(entries, { status: "approved" }).length, 2);
  assertEquals(
    filterEntries(entries, { key: "pay-schedule", scope: "company" }).length,
    1,
  );
});

// ---------------------------------------------------------------------------
// Pure: upsertEntry
// ---------------------------------------------------------------------------

Deno.test("upsertEntry creates a new entry when key+scope is new", () => {
  const entries = [entry()];
  const { entries: next, created } = upsertEntry(entries, entry({ key: "core-hours", scope: "company" }));
  assertEquals(created, true);
  assertEquals(next.length, 2);
});

Deno.test("upsertEntry replaces an existing entry matched by key+scope", () => {
  const entries = [entry({ value: "biweekly" })];
  const { entries: next, created } = upsertEntry(entries, entry({ value: "semi-monthly" }));
  assertEquals(created, false);
  assertEquals(next.length, 1);
  assertEquals(next[0].value, "semi-monthly");
});

// ---------------------------------------------------------------------------
// Pure: reviewEntry
// ---------------------------------------------------------------------------

Deno.test("reviewEntry approve stamps status + provenance + lastReviewed", () => {
  const entries = [entry({ status: "draft" })];
  const { updated } = reviewEntry(entries, {
    key: "pay-schedule",
    scope: "company",
    action: "approve",
    provenance: { decidedBy: "owner", decidedAt: "2026-11-19T00:00:00Z", source: "decision" },
  });
  assertEquals(updated?.status, "approved");
  assertEquals(updated?.lastReviewed, "2026-11-19T00:00:00Z");
  assertEquals(updated?.provenance?.decidedBy, "owner");
});

Deno.test("reviewEntry retire sets status retired; a miss returns updated=null", () => {
  const entries = [entry()];
  const retire = reviewEntry(entries, {
    key: "pay-schedule",
    scope: "company",
    action: "retire",
    provenance: { decidedBy: "o", decidedAt: "2026-11-19T00:00:00Z", source: "s" },
  });
  assertEquals(retire.updated?.status, "retired");
  const miss = reviewEntry(entries, {
    key: "nope",
    scope: "company",
    action: "approve",
    provenance: { decidedBy: "o", decidedAt: "2026-11-19T00:00:00Z", source: "s" },
  });
  assertEquals(miss.updated, null);
});

// ---------------------------------------------------------------------------
// Pure: audit / isLapsed
// ---------------------------------------------------------------------------

Deno.test("isLapsed only flags approved entries past their cadence", () => {
  const asOf = Date.parse("2026-11-19T00:00:00Z");
  // approved, reviewed long ago, 30-day cadence -> lapsed
  assertEquals(
    isLapsed(entry({ lastReviewed: "2026-01-01T00:00:00Z", reviewCadence: 30 }), asOf),
    true,
  );
  // approved, reviewed yesterday, 30-day cadence -> not lapsed
  assertEquals(
    isLapsed(entry({ lastReviewed: "2026-11-18T00:00:00Z", reviewCadence: 30 }), asOf),
    false,
  );
  // draft never lapses
  assertEquals(
    isLapsed(entry({ status: "draft", lastReviewed: "2000-01-01T00:00:00Z", reviewCadence: 1 }), asOf),
    false,
  );
  // no cadence and no default -> not lapsed
  assertEquals(isLapsed(entry({ lastReviewed: "2000-01-01T00:00:00Z" }), asOf), false);
  // default cadence applies when the entry has none
  assertEquals(
    isLapsed(entry({ lastReviewed: "2000-01-01T00:00:00Z" }), asOf, 30),
    true,
  );
});

Deno.test("auditEntries flips lapsed approved entries to expiring in the returned list", () => {
  const entries = [
    entry({ key: "a", lastReviewed: "2026-01-01T00:00:00Z", reviewCadence: 30 }),
    entry({ key: "b", lastReviewed: "2026-11-18T00:00:00Z", reviewCadence: 30 }),
  ];
  const { lapsed, flipped } = auditEntries(entries, "2026-11-19T00:00:00Z");
  assertEquals(lapsed.length, 1);
  assertEquals(lapsed[0].key, "a");
  assertEquals(flipped.find((e) => e.key === "a")?.status, "expiring");
  assertEquals(flipped.find((e) => e.key === "b")?.status, "approved");
});

// ---------------------------------------------------------------------------
// Gated methods via a fake context
// ---------------------------------------------------------------------------

Deno.test("lookup writes a lookupResult and never the entry store", async () => {
  const { ctx, writes } = fakeContext("lib", [entry(), entry({ key: "core-hours" })]);
  await model.methods.lookup.execute({ key: "pay-schedule" }, ctx);
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "lookupResult");
  assertEquals((writes[0].data.matched as Entry[]).length, 1);
});

Deno.test("upsert confirm=false returns a plan and does NOT write the entry store", async () => {
  const { ctx, writes } = fakeContext("lib", [entry()]);
  await model.methods.upsert.execute(
    { entry: entry({ key: "core-hours", value: "9 to 5" }), confirm: false },
    ctx,
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "lookupResult");
  assertEquals(writes[0].name, "upsert-plan");
});

Deno.test("upsert confirm=true writes the merged entry store", async () => {
  const { ctx, writes } = fakeContext("lib", [entry()]);
  await model.methods.upsert.execute(
    { entry: entry({ key: "core-hours", value: "9 to 5" }), confirm: true },
    ctx,
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].spec, "entries");
  assertEquals((writes[0].data.entries as Entry[]).length, 2);
});

Deno.test("review confirm=true stamps and writes the entry store", async () => {
  const { ctx, writes } = fakeContext("lib", [entry({ status: "draft" })]);
  await model.methods.review.execute(
    { key: "pay-schedule", scope: "company", action: "approve", decidedBy: "owner", confirm: true },
    ctx,
  );
  assertEquals(writes[0].spec, "entries");
  assertEquals((writes[0].data.entries as Entry[])[0].status, "approved");
});

Deno.test("audit confirm=false reports only; confirm=true also writes the flipped store", async () => {
  const lapsed = entry({ lastReviewed: "2026-01-01T00:00:00Z", reviewCadence: 30 });
  const report = fakeContext("lib", [lapsed]);
  await model.methods.audit.execute({ asOf: "2026-11-19T00:00:00Z", confirm: false }, report.ctx);
  assertEquals(report.writes.length, 1);
  assertEquals(report.writes[0].spec, "auditReport");
  assertEquals(report.writes[0].data.applied, false);

  const apply = fakeContext("lib", [lapsed]);
  await model.methods.audit.execute({ asOf: "2026-11-19T00:00:00Z", confirm: true }, apply.ctx);
  assertEquals(apply.writes.length, 2);
  assertEquals(apply.writes[0].spec, "auditReport");
  assertEquals(apply.writes[0].data.applied, true);
  assertEquals(apply.writes[1].spec, "entries");
  assertEquals((apply.writes[1].data.entries as Entry[])[0].status, "expiring");
});

Deno.test("a malformed stored entries resource is refused, not silently wiped", async () => {
  // The stored entries resource EXISTS but fails schema validation (corrupted,
  // hand-edited, or written by an incompatible version). A confirm=true write
  // must throw rather than read an empty base and overwrite the store -- that
  // would silently drop every stored entry.
  const writes: Array<{ spec: string; name: string }> = [];
  const ctx = {
    globalArgs: { name: "lib" },
    writeResource: (spec: string, resName: string, _data: Record<string, unknown>) => {
      writes.push({ spec, name: resName });
      return Promise.resolve({ name: resName });
    },
    readResource: (resName: string) =>
      resName === "entries"
        ? Promise.resolve(
          { library: "lib", entries: "not-an-array" } as unknown as Record<string, unknown>,
        )
        : Promise.resolve(null),
  };
  await assertRejects(
    () =>
      model.methods.upsert.execute(
        { entry: entry({ key: "core-hours", value: "9 to 5" }), confirm: true },
        ctx,
      ),
    Error,
    "failed schema validation",
  );
  // Nothing was written to the entries store: the malformed data was preserved,
  // not overwritten -- no silent data loss.
  assertEquals(writes.filter((w) => w.spec === "entries").length, 0);
});
