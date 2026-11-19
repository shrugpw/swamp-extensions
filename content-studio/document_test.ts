/**
 * Unit tests for @shrug/content-studio/document. Offline: every detector and
 * orchestration function is pure text analysis; render is driven by an INJECTED
 * fake pandoc runner, so no real pandoc, filesystem, or network is touched. All
 * fixtures are synthetic and carry the canonical three-defect pattern.
 *
 * Run with:
 *   ~/.swamp/deno/deno test document_test.ts
 *
 * @module
 */
import { assertEquals } from "jsr:@std/assert@1.0.19";
import { type Entry, EntrySchema } from "./library.ts";
import {
  buildPandocArgs,
  checkText,
  type CommandRunner,
  defaultOutputPath,
  extractPlaceholders,
  fillText,
  findBrokenCrossRefs,
  findDraftMarkers,
  findInternalFileRefs,
  mapPlaceholders,
  model,
  renderDoc,
  scanText,
} from "./document.ts";

// ---------------------------------------------------------------------------
// Fixtures (synthetic; the canonical three-defect pattern)
// ---------------------------------------------------------------------------

const DIRTY = [
  "# Policy",
  "",
  "Drafted by an assistant for the owner to review.",
  "",
  "Pay is [weekly / biweekly / semi-monthly] and core hours are [core hours].",
  "",
  "See [the other policy](other-policy.md) and the [overview](#overview).",
  "",
  "## Scope",
  "",
  "Applies company-wide.",
].join("\n");

const CLEAN = [
  "# Policy",
  "",
  "Pay is biweekly and core hours are 9 to 5.",
  "",
  "## Overview",
  "",
  "See the [Overview](#overview).",
].join("\n");

const OPTS = {
  draftMarkers: ["drafted by", "to review"],
  internalFileExtensions: ["md"],
  requiredDisclaimers: [],
  toneFlags: ["i think"],
};

function entry(over: Partial<Record<string, unknown>> = {}): Entry {
  return EntrySchema.parse({
    key: "pay-schedule",
    value: "biweekly",
    status: "approved",
    tokens: ["[weekly / biweekly / semi-monthly]"],
    ...over,
  });
}

// ---------------------------------------------------------------------------
// Placeholder extraction + mapping
// ---------------------------------------------------------------------------

Deno.test("extractPlaceholders finds brackets but skips links, refs, and footnotes", () => {
  const text = "[pay schedule] and [core hours], not [a link](u) nor [ref][r] nor [^1].";
  const tokens = extractPlaceholders(text).map((p) => p.token);
  assertEquals(tokens, ["[pay schedule]", "[core hours]"]);
});

Deno.test("extractPlaceholders ignores GFM task-list checkboxes", () => {
  const text = [
    "# Checklist",
    "",
    "- [ ] unchecked item",
    "- [x] checked item",
    "- [X] also checked",
    "",
    "But [a real placeholder] must still be flagged.",
  ].join("\n");
  const tokens = extractPlaceholders(text).map((p) => p.token);
  assertEquals(tokens, ["[a real placeholder]"]);
});

Deno.test("mapPlaceholders maps to a library key via tokens, else needs-new-entry", () => {
  const placeholders = extractPlaceholders(
    "Pay is [weekly / biweekly / semi-monthly] and hours are [core hours].",
  );
  const mapped = mapPlaceholders(placeholders, [entry()]);
  assertEquals(mapped[0].mappedKey, "pay-schedule");
  assertEquals(mapped[0].needsNewEntry, false);
  assertEquals(mapped[1].mappedKey, null);
  assertEquals(mapped[1].needsNewEntry, true);
});

// ---------------------------------------------------------------------------
// Individual detectors
// ---------------------------------------------------------------------------

Deno.test("findDraftMarkers locates configured markers case-insensitively", () => {
  const hits = findDraftMarkers(DIRTY, OPTS.draftMarkers);
  assertEquals(hits.map((h) => h.marker).sort(), ["drafted by", "to review"]);
});

Deno.test("findInternalFileRefs flags bare source filenames", () => {
  const hits = findInternalFileRefs(DIRTY, ["md"]);
  assertEquals(hits.map((h) => h.ref), ["other-policy.md"]);
});

Deno.test("findBrokenCrossRefs flags anchors with no matching heading", () => {
  const broken = findBrokenCrossRefs(DIRTY); // #overview, no Overview heading
  assertEquals(broken.length, 1);
  assertEquals(broken[0].ref, "#overview");
  // In CLEAN the Overview heading exists, so the same anchor is not broken.
  assertEquals(findBrokenCrossRefs(CLEAN).length, 0);
});

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

Deno.test("scanText inventories every defect class and maps placeholders", () => {
  const report = scanText(DIRTY, "policy.md", OPTS, [entry()]);
  assertEquals(report.clean, false);
  assertEquals(report.placeholders.length, 2);
  assertEquals(report.placeholders[0].mappedKey, "pay-schedule");
  assertEquals(report.placeholders[1].needsNewEntry, true);
  assertEquals(report.draftMarkers.length, 2);
  assertEquals(report.internalFileRefs.length, 1);
  assertEquals(report.brokenCrossRefs.length, 1);
});

Deno.test("scanText reports clean=true on a resolved document", () => {
  const report = scanText(CLEAN, "policy.md", OPTS, []);
  assertEquals(report.clean, true);
  assertEquals(report.defectCount, 0);
});

Deno.test("scanText flags missing required disclaimers", () => {
  const report = scanText(CLEAN, "policy.md", {
    ...OPTS,
    requiredDisclaimers: ["This is not legal advice"],
  }, []);
  assertEquals(report.missingDisclaimers, ["This is not legal advice"]);
});

// ---------------------------------------------------------------------------
// fill
// ---------------------------------------------------------------------------

Deno.test("fillText resolves approved tokens, dedups, and reports unresolved", () => {
  const text = "Pay is [weekly / biweekly / semi-monthly]; again [weekly / biweekly / semi-monthly]; hours [core hours].";
  const res = fillText(text, [entry()]);
  assertEquals(res.filled.includes("[weekly / biweekly / semi-monthly]"), false);
  assertEquals(res.filled.includes("biweekly"), true);
  assertEquals(res.resolved.length, 1); // deduped
  assertEquals(res.resolved[0].key, "pay-schedule");
  assertEquals(res.unresolved, ["[core hours]"]);
  // The unresolved placeholder is left intact.
  assertEquals(res.filled.includes("[core hours]"), true);
});

Deno.test("fillText ignores non-approved entries", () => {
  const draft = entry({ status: "draft" });
  const res = fillText("Pay is [weekly / biweekly / semi-monthly].", [draft]);
  assertEquals(res.resolved.length, 0);
  assertEquals(res.unresolved, ["[weekly / biweekly / semi-monthly]"]);
});

// ---------------------------------------------------------------------------
// check (the sendability gate)
// ---------------------------------------------------------------------------

Deno.test("checkText rates survivors: placeholders/markers critical, refs high; not sendable", () => {
  const report = checkText(DIRTY, "policy.md", OPTS);
  assertEquals(report.sendable, false);
  const cats = report.findings.map((f) => f.category);
  assertEquals(cats.includes("unresolved-placeholder"), true);
  assertEquals(cats.includes("draft-marker"), true);
  assertEquals(cats.includes("internal-file-ref"), true);
  assertEquals(cats.includes("broken-cross-ref"), true);
  const placeholder = report.findings.find((f) => f.category === "unresolved-placeholder");
  assertEquals(placeholder?.severity, "critical");
  const ref = report.findings.find((f) => f.category === "internal-file-ref");
  assertEquals(ref?.severity, "high");
});

Deno.test("checkText passes a clean document as sendable", () => {
  const report = checkText(CLEAN, "policy.md", OPTS);
  assertEquals(report.sendable, true);
  assertEquals(report.findings.length, 0);
});

Deno.test("checkText rates tone flags medium and still sendable", () => {
  const report = checkText("I think this is fine.", "note.md", OPTS);
  assertEquals(report.findings.length, 1);
  assertEquals(report.findings[0].severity, "medium");
  assertEquals(report.sendable, true);
});

// ---------------------------------------------------------------------------
// render (injected fake pandoc runner)
// ---------------------------------------------------------------------------

function recordingRunner() {
  const calls: Array<{ cmd: string; args: string[] }> = [];
  const runner: CommandRunner = (cmd, args) => {
    calls.push({ cmd, args });
    return Promise.resolve({ code: 0, stdout: "", stderr: "" });
  };
  return { runner, calls };
}

Deno.test("buildPandocArgs builds a pandoc argv to the requested format", () => {
  const argv = buildPandocArgs({ inputPath: "a.md", outputPath: "a.pdf", format: "pdf" });
  assertEquals(argv, ["pandoc", "a.md", "--to", "pdf", "-o", "a.pdf"]);
});

Deno.test("defaultOutputPath swaps the extension for the format", () => {
  assertEquals(defaultOutputPath("policy.md", "docx"), "policy.docx");
  assertEquals(defaultOutputPath("policy", "pdf"), "policy.pdf");
});

Deno.test("renderDoc confirm=false plans the command and never calls the runner", async () => {
  const { runner, calls } = recordingRunner();
  const res = await renderDoc(runner, {
    inputPath: "policy.md",
    outputPath: "policy.pdf",
    format: "pdf",
    confirm: false,
  });
  assertEquals(res.rendered, false);
  assertEquals(res.command, ["pandoc", "policy.md", "--to", "pdf", "-o", "policy.pdf"]);
  assertEquals(calls.length, 0);
});

Deno.test("renderDoc confirm=true invokes the fake pandoc runner with the built argv", async () => {
  const { runner, calls } = recordingRunner();
  const res = await renderDoc(runner, {
    inputPath: "policy.md",
    outputPath: "policy.docx",
    format: "docx",
    confirm: true,
  });
  assertEquals(res.rendered, true);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].cmd, "pandoc");
  assertEquals(calls[0].args, ["policy.md", "--to", "docx", "-o", "policy.docx"]);
});

// ---------------------------------------------------------------------------
// Method execute paths over an injected file-IO seam (no disk, no process)
// ---------------------------------------------------------------------------

/**
 * A fake context with an injected reader/writer and recorded resource writes,
 * so the document methods' execute paths (fill's confirm/write-gating and the
 * inputPath override) run fully offline.
 */
function fakeDocContext(globalArgs: unknown, files: Record<string, string>) {
  const fs: Record<string, string> = { ...files };
  const writes: Array<{ path: string; content: string }> = [];
  const resources: Array<
    { spec: string; name: string; data: Record<string, unknown> }
  > = [];
  const ctx = {
    globalArgs,
    readText: (path: string): Promise<string> => {
      if (!(path in fs)) {
        return Promise.reject(new Error(`no such fake file: ${path}`));
      }
      return Promise.resolve(fs[path]);
    },
    writeText: (path: string, content: string): Promise<void> => {
      fs[path] = content;
      writes.push({ path, content });
      return Promise.resolve();
    },
    writeResource: (
      spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      resources.push({ spec, name, data });
      return Promise.resolve({ name });
    },
  };
  return { ctx, fs, writes, resources };
}

const FILLABLE = "Pay is [weekly / biweekly / semi-monthly].";

Deno.test("fill.execute writes nothing unless confirm=true", async () => {
  const { ctx, writes, resources } = fakeDocContext(
    { path: "policy.md" },
    { "policy.md": FILLABLE },
  );
  await model.methods.fill.execute({ entries: [entry()] }, ctx);
  assertEquals(writes.length, 0);
  const report = resources.find((r) => r.spec === "fillReport");
  assertEquals(report?.data.wrote, false);
});

Deno.test("fill.execute confirm=true writes the filled bytes to the default .filled.md", async () => {
  const { ctx, fs, writes, resources } = fakeDocContext(
    { path: "policy.md" },
    { "policy.md": FILLABLE },
  );
  await model.methods.fill.execute(
    { entries: [entry()], confirm: true },
    ctx,
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].path, "policy.md.filled.md");
  assertEquals(fs["policy.md.filled.md"], "Pay is biweekly.");
  // The original is untouched -- fill is non-destructive.
  assertEquals(fs["policy.md"], FILLABLE);
  const report = resources.find((r) => r.spec === "fillReport");
  assertEquals(report?.data.wrote, true);
  assertEquals(report?.data.outputPath, "policy.md.filled.md");
});

Deno.test("check.execute honors inputPath: gates the filled draft, not the original", async () => {
  const { ctx, resources } = fakeDocContext(
    { path: "policy.md" },
    { "policy.md": FILLABLE },
  );
  // Fill first (confirm) so the filled draft exists in the fake fs.
  await model.methods.fill.execute(
    { entries: [entry()], confirm: true },
    ctx,
  );

  // check WITHOUT inputPath reads the original (placeholder survives -> blocked).
  await model.methods.check.execute({}, ctx);
  // check WITH inputPath reads the filled draft (resolved -> sendable).
  await model.methods.check.execute({ inputPath: "policy.md.filled.md" }, ctx);

  const checks = resources.filter((r) => r.spec === "checkReport");
  assertEquals(checks.length, 2);
  // The original still carries the unresolved placeholder -> not sendable.
  assertEquals(checks[0].data.path, "policy.md");
  assertEquals(checks[0].data.sendable, false);
  // The filled draft is clean -> sendable; this is what the pipeline gates.
  assertEquals(checks[1].data.path, "policy.md.filled.md");
  assertEquals(checks[1].data.sendable, true);
});
