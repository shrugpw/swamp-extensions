/**
 * @shrug/content-studio/document - a piece of content under review.
 *
 * A document is markdown under review, bound (by name) to one or more
 * libraries. Its methods are a defect inventory (scan), a placeholder resolver
 * (fill), a sendability gate (check), and a build step (render):
 *
 * - scan  -- inventory defects (no mutation): unresolved bracket placeholders,
 *            draft/scaffolding markers, internal-filename refs, broken in-doc
 *            cross-refs, missing required disclaimers. Each placeholder is
 *            mapped to a library key when a passed-in entry's `tokens` matches,
 *            else flagged needs-new-entry. Captures a `scanReport`.
 * - fill  -- resolve placeholders against library ENTRIES PASSED IN AS A METHOD
 *            ARGUMENT (the pipeline wires them via CEL); emit filled text + an
 *            `unresolved[]` report. dry-run-gated: writes the filled file only
 *            when confirm=true, else returns the plan.
 * - check -- the sendability gate: severity-rated findings if any bracket, draft
 *            marker, or internal filename survives, plus tone/cross-ref/
 *            disclaimer checks. Captures a `checkReport`.
 * - render-- produce PDF/DOCX from the final markdown through an INJECTABLE
 *            pandoc runner (never a command/shell passthrough). confirm-gated.
 *
 * Cross-type library data NEVER arrives via `context.readResource` (that reads
 * only this instance's own resources); the pipeline passes library entries into
 * `fill` (and optionally `scan`) as a method argument via CEL
 * `data.latest(<library>, "entries")`. All detection is pure text analysis and
 * is unit-tested with no filesystem or process IO.
 *
 * @module
 */
import { z } from "npm:zod@4.4.3";
import { type Entry, EntrySchema } from "./library.ts";

// ---------------------------------------------------------------------------
// Instance spec (globalArguments)
// ---------------------------------------------------------------------------

const DEFAULT_DRAFT_MARKERS = [
  "drafted by",
  "to review",
  "for review",
  "internal draft",
  "do not send",
  "todo",
  "tbd",
  "fixme",
  "xxx",
  "placeholder",
  "scaffold",
  "lorem ipsum",
];

const DEFAULT_INTERNAL_EXTENSIONS = ["md", "markdown", "txt", "yaml", "yml"];

const DEFAULT_TONE_FLAGS = [
  "i think",
  "we should probably",
  "obviously",
  "just simply",
];

/** The document instance config. */
export const GlobalArgsSchema = z.object({
  path: z
    .string()
    .min(1)
    .describe("Filesystem path to the markdown document under review."),
  libraries: z
    .array(z.string().min(1))
    .default([])
    .describe(
      "Names of the libraries this document binds to (informational; entries " +
        "are passed into fill/scan as a method argument, not read from here).",
    ),
  draftMarkers: z
    .array(z.string().min(1))
    .default(DEFAULT_DRAFT_MARKERS)
    .describe("Case-insensitive draft/scaffolding marker phrases to flag."),
  internalFileExtensions: z
    .array(z.string().min(1))
    .default(DEFAULT_INTERNAL_EXTENSIONS)
    .describe(
      "Source-file extensions whose bare references are internal-ref defects.",
    ),
  requiredDisclaimers: z
    .array(z.string().min(1))
    .default([])
    .describe(
      "Disclaimer phrases that must be present; any absent is a defect.",
    ),
  toneFlags: z
    .array(z.string().min(1))
    .default(DEFAULT_TONE_FLAGS)
    .describe(
      "Case-insensitive tone phrases a sendability check flags (medium).",
    ),
});
export type DocumentConfig = z.infer<typeof GlobalArgsSchema>;

/** The detector options derived from the instance config. */
export interface DetectOptions {
  draftMarkers: string[];
  internalFileExtensions: string[];
  requiredDisclaimers: string[];
  toneFlags: string[];
}

/** Build DetectOptions from a parsed config. */
export function optionsFromConfig(cfg: DocumentConfig): DetectOptions {
  return {
    draftMarkers: cfg.draftMarkers,
    internalFileExtensions: cfg.internalFileExtensions,
    requiredDisclaimers: cfg.requiredDisclaimers,
    toneFlags: cfg.toneFlags,
  };
}

// ---------------------------------------------------------------------------
// Pure text helpers (no IO)
// ---------------------------------------------------------------------------

/** 1-based line number of a character offset in text. */
export function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === "\n") line++;
  }
  return line;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** A located placeholder, with its library mapping once entries are known. */
export interface Placeholder {
  token: string;
  line: number;
  mappedKey: string | null;
  needsNewEntry: boolean;
}

/**
 * Extract bracket placeholders like `[pay schedule]`, excluding markdown
 * inline links `[t](u)`, reference links `[t][r]`, reference definitions
 * `[r]: url`, and footnotes `[^1]`.
 */
export function extractPlaceholders(
  text: string,
): Array<{ token: string; line: number }> {
  const out: Array<{ token: string; line: number }> = [];
  const re = /\[([^\[\]\r\n]+)\]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const inner = m[1];
    if (inner.startsWith("^")) continue; // footnote
    if (inner === " " || inner === "x" || inner === "X") continue; // GFM task-list checkbox
    const before = m.index > 0 ? text[m.index - 1] : "";
    if (before === "]") continue; // the label half of a reference link [text][ref]
    const after = text[m.index + m[0].length];
    if (after === "(" || after === "[" || after === ":") continue; // a link/ref
    out.push({ token: m[0], line: lineOf(text, m.index) });
  }
  return out;
}

/** Map extracted placeholders to library keys via each entry's `tokens`. */
export function mapPlaceholders(
  placeholders: Array<{ token: string; line: number }>,
  entries: Entry[],
): Placeholder[] {
  return placeholders.map((p) => {
    const hit = entries.find((e) => e.tokens.includes(p.token));
    return {
      token: p.token,
      line: p.line,
      mappedKey: hit ? hit.key : null,
      needsNewEntry: !hit,
    };
  });
}

/** Located draft/scaffolding markers. */
export function findDraftMarkers(
  text: string,
  markers: string[],
): Array<{ marker: string; line: number }> {
  const out: Array<{ marker: string; line: number }> = [];
  for (const marker of markers) {
    const alnum = /^[a-z0-9]+$/i.test(marker);
    const body = escapeRegExp(marker);
    const re = new RegExp(alnum ? `\\b${body}\\b` : body, "gi");
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      out.push({ marker, line: lineOf(text, m.index) });
    }
  }
  return out;
}

/** Located internal source-filename references. */
export function findInternalFileRefs(
  text: string,
  extensions: string[],
): Array<{ ref: string; line: number }> {
  if (extensions.length === 0) return [];
  const out: Array<{ ref: string; line: number }> = [];
  const alt = extensions.map(escapeRegExp).join("|");
  const re = new RegExp(`\\b[\\w./-]+\\.(?:${alt})\\b`, "gi");
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    out.push({ ref: m[0], line: lineOf(text, m.index) });
  }
  return out;
}

function slugify(heading: string): string {
  return heading
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, "")
    .replace(/\s+/g, "-");
}

/** In-doc anchor cross-refs (`](#anchor)`) that match no heading slug. */
export function findBrokenCrossRefs(
  text: string,
): Array<{ ref: string; reason: string; line: number }> {
  const slugs = new Set<string>();
  const headingRe = /^#{1,6}\s+(.*)$/gm;
  let h: RegExpExecArray | null;
  while ((h = headingRe.exec(text)) !== null) slugs.add(slugify(h[1]));

  const out: Array<{ ref: string; reason: string; line: number }> = [];
  const linkRe = /\]\(#([^)\s]+)\)/g;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(text)) !== null) {
    const anchor = m[1];
    if (!slugs.has(anchor)) {
      out.push({
        ref: `#${anchor}`,
        reason: "no heading matches this anchor",
        line: lineOf(text, m.index),
      });
    }
  }
  return out;
}

/** Required disclaimer phrases absent from the text. */
export function findMissingDisclaimers(
  text: string,
  required: string[],
): string[] {
  const hay = text.toLowerCase();
  return required.filter((d) => !hay.includes(d.toLowerCase()));
}

/** Located tone-flag phrases. */
export function findToneFlags(
  text: string,
  toneFlags: string[],
): Array<{ phrase: string; line: number }> {
  const out: Array<{ phrase: string; line: number }> = [];
  for (const phrase of toneFlags) {
    const re = new RegExp(escapeRegExp(phrase), "gi");
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      out.push({ phrase, line: lineOf(text, m.index) });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

/** The full defect inventory for a document. */
export interface ScanReport {
  path: string;
  placeholders: Placeholder[];
  draftMarkers: Array<{ marker: string; line: number }>;
  internalFileRefs: Array<{ ref: string; line: number }>;
  brokenCrossRefs: Array<{ ref: string; reason: string; line: number }>;
  missingDisclaimers: string[];
  defectCount: number;
  clean: boolean;
}

/** Inventory every defect class in a document's text (no mutation). */
export function scanText(
  text: string,
  path: string,
  opts: DetectOptions,
  entries: Entry[] = [],
): ScanReport {
  const placeholders = mapPlaceholders(extractPlaceholders(text), entries);
  const draftMarkers = findDraftMarkers(text, opts.draftMarkers);
  const internalFileRefs = findInternalFileRefs(
    text,
    opts.internalFileExtensions,
  );
  const brokenCrossRefs = findBrokenCrossRefs(text);
  const missingDisclaimers = findMissingDisclaimers(
    text,
    opts.requiredDisclaimers,
  );
  const defectCount = placeholders.length + draftMarkers.length +
    internalFileRefs.length + brokenCrossRefs.length +
    missingDisclaimers.length;
  return {
    path,
    placeholders,
    draftMarkers,
    internalFileRefs,
    brokenCrossRefs,
    missingDisclaimers,
    defectCount,
    clean: defectCount === 0,
  };
}

// ---------------------------------------------------------------------------
// fill
// ---------------------------------------------------------------------------

/** The result of resolving a document's placeholders against a library. */
export interface FillResult {
  filled: string;
  resolved: Array<{ token: string; key: string; value: string }>;
  unresolved: string[];
}

/**
 * Replace each bracket placeholder with the value of the APPROVED library entry
 * whose `tokens` contains that literal placeholder string. Placeholders with no
 * approved entry are left intact and reported in `unresolved` (deduplicated).
 */
export function fillText(text: string, entries: Entry[]): FillResult {
  const placeholders = extractPlaceholders(text);
  const approved = entries.filter((e) => e.status === "approved");
  const resolved: Array<{ token: string; key: string; value: string }> = [];
  const unresolved = new Set<string>();
  const seenResolved = new Set<string>();
  let filled = text;

  for (const p of placeholders) {
    const hit = approved.find((e) => e.tokens.includes(p.token));
    if (!hit) {
      unresolved.add(p.token);
      continue;
    }
    if (!seenResolved.has(p.token)) {
      resolved.push({ token: p.token, key: hit.key, value: hit.value });
      seenResolved.add(p.token);
    }
    filled = filled.split(p.token).join(hit.value);
  }

  return { filled, resolved, unresolved: [...unresolved] };
}

// ---------------------------------------------------------------------------
// check (the sendability gate)
// ---------------------------------------------------------------------------

/** A severity-rated sendability finding. */
export interface Finding {
  id: string;
  severity: "critical" | "high" | "medium";
  category: string;
  message: string;
  line?: number;
}

/** The sendability-gate result. */
export interface CheckReport {
  path: string;
  findings: Finding[];
  sendable: boolean;
}

/**
 * Rate a document for sendability. A surviving bracket placeholder or draft
 * marker is critical; an internal-filename ref, a broken cross-ref, or a
 * missing disclaimer is high; a tone flag is medium. `sendable` is true only
 * when no finding is critical or high.
 */
export function checkText(
  text: string,
  path: string,
  opts: DetectOptions,
): CheckReport {
  const findings: Finding[] = [];
  let n = 0;
  const id = () => `F${++n}`;

  for (const p of extractPlaceholders(text)) {
    findings.push({
      id: id(),
      severity: "critical",
      category: "unresolved-placeholder",
      message: `unresolved placeholder ${p.token}`,
      line: p.line,
    });
  }
  for (const d of findDraftMarkers(text, opts.draftMarkers)) {
    findings.push({
      id: id(),
      severity: "critical",
      category: "draft-marker",
      message: `draft/scaffolding marker "${d.marker}"`,
      line: d.line,
    });
  }
  for (const r of findInternalFileRefs(text, opts.internalFileExtensions)) {
    findings.push({
      id: id(),
      severity: "high",
      category: "internal-file-ref",
      message: `internal-filename reference ${r.ref}`,
      line: r.line,
    });
  }
  for (const c of findBrokenCrossRefs(text)) {
    findings.push({
      id: id(),
      severity: "high",
      category: "broken-cross-ref",
      message: `broken cross-ref ${c.ref}: ${c.reason}`,
      line: c.line,
    });
  }
  for (const d of findMissingDisclaimers(text, opts.requiredDisclaimers)) {
    findings.push({
      id: id(),
      severity: "high",
      category: "missing-disclaimer",
      message: `missing required disclaimer: ${d}`,
    });
  }
  for (const t of findToneFlags(text, opts.toneFlags)) {
    findings.push({
      id: id(),
      severity: "medium",
      category: "tone",
      message: `tone flag "${t.phrase}"`,
      line: t.line,
    });
  }

  const sendable = !findings.some(
    (f) => f.severity === "critical" || f.severity === "high",
  );
  return { path, findings, sendable };
}

// ---------------------------------------------------------------------------
// render (injectable pandoc runner)
// ---------------------------------------------------------------------------

/** Output formats render supports. */
export const RenderFormatSchema = z.enum(["pdf", "docx"]);
export type RenderFormat = z.infer<typeof RenderFormatSchema>;

/**
 * Build the pandoc argv (including the leading "pandoc") for a render. The
 * output path defaults to the input path with the format's extension.
 */
export function buildPandocArgs(opts: {
  inputPath: string;
  outputPath: string;
  format: RenderFormat;
}): string[] {
  return ["pandoc", opts.inputPath, "--to", opts.format, "-o", opts.outputPath];
}

/** Default output path: swap the input's extension for the format's. */
export function defaultOutputPath(
  inputPath: string,
  format: RenderFormat,
): string {
  const dot = inputPath.lastIndexOf(".");
  const base = dot === -1 ? inputPath : inputPath.slice(0, dot);
  return `${base}.${format}`;
}

/**
 * The one injectable side effect for render: run a command and return its exit
 * code and captured output. Production wires `realRunner` (Deno.Command); tests
 * inject a fake so no real pandoc process runs.
 */
export type CommandRunner = (
  cmd: string,
  args: string[],
) => Promise<{ code: number; stdout: string; stderr: string }>;

/** Production CommandRunner backed by Deno.Command. */
export const realRunner: CommandRunner = async (cmd, args) => {
  // Spawning pandoc is the whole point of render; it is isolated to this one
  // injectable seam (tests use a fake), and cmd/args come only from validated
  // config/args, never free user text. Documented in the README.
  // swamp-quality-ignore deno-command
  const command = new Deno.Command(cmd, {
    args,
    stdout: "piped",
    stderr: "piped",
  });
  const { code, stdout, stderr } = await command.output();
  const dec = new TextDecoder();
  return { code, stdout: dec.decode(stdout), stderr: dec.decode(stderr) };
};

/** The render outcome (also the renderReport payload). */
export interface RenderResult {
  inputPath: string;
  outputPath: string;
  format: RenderFormat;
  command: string[];
  rendered: boolean;
}

/**
 * Plan (and, when confirm, execute) a pandoc render. When confirm is false the
 * command is only planned (rendered=false, no process); when true the runner is
 * invoked and a non-zero exit throws.
 */
export async function renderDoc(
  runner: CommandRunner,
  opts: {
    inputPath: string;
    outputPath: string;
    format: RenderFormat;
    confirm: boolean;
  },
): Promise<RenderResult> {
  const command = buildPandocArgs(opts);
  if (!opts.confirm) {
    return {
      inputPath: opts.inputPath,
      outputPath: opts.outputPath,
      format: opts.format,
      command,
      rendered: false,
    };
  }
  const res = await runner(command[0], command.slice(1));
  if (res.code !== 0) {
    throw new Error(
      `content-studio: pandoc exited ${res.code}: ${res.stderr.trim()}`,
    );
  }
  return {
    inputPath: opts.inputPath,
    outputPath: opts.outputPath,
    format: opts.format,
    command,
    rendered: true,
  };
}

// ---------------------------------------------------------------------------
// Method argument schemas
// ---------------------------------------------------------------------------

/** Arguments for `scan` (optional entries to map placeholders to keys). */
export const ScanArgs = z.object({
  entries: z
    .array(EntrySchema)
    .default([])
    .describe(
      "Library entries to map placeholders to keys (via CEL data.latest).",
    ),
  inputPath: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Override the file to read for this run; defaults to the instance path. " +
        "Point it at a filled draft (e.g. <path>.filled.md) to scan that.",
    ),
});

/** Arguments for `fill` (entries passed in; dry-run-gated write). */
export const FillArgs = z.object({
  entries: z
    .array(EntrySchema)
    .describe("Library entries to resolve against (via CEL data.latest)."),
  outputPath: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Where to write the filled document; defaults to <path>.filled.md.",
    ),
  confirm: z
    .boolean()
    .default(false)
    .describe(
      "Write the filled file only when true; otherwise return the plan.",
    ),
});

/** Arguments for `check` (optional input-path override). */
export const CheckArgs = z.object({
  inputPath: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Override the file the sendability gate reads; defaults to the instance " +
        "path. Point it at the filled draft (e.g. <path>.filled.md) so the gate " +
        "runs on the resolved content, not the original with placeholders.",
    ),
});

/** Arguments for `render` (confirm-gated pandoc build). */
export const RenderArgs = z.object({
  format: RenderFormatSchema.default("pdf").describe(
    "Output format: pdf | docx.",
  ),
  inputPath: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Override the markdown input to render; defaults to the instance path. " +
        "Point it at the filled draft (e.g. <path>.filled.md) to render that.",
    ),
  outputPath: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Output path; defaults to the input path with the format's extension.",
    ),
  confirm: z
    .boolean()
    .default(false)
    .describe(
      "Run pandoc only when true; otherwise return the planned command.",
    ),
});

// ---------------------------------------------------------------------------
// Behavior context / result interfaces + real IO
// ---------------------------------------------------------------------------

interface MethodLogger {
  info(message: string, properties?: Record<string, unknown>): void;
}

interface ExecuteContext {
  globalArgs: unknown;
  logger?: MethodLogger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
  // The file-IO seam. Production leaves these unset and the methods fall back to
  // the real Deno readers/writers below; tests inject fakes so fill's confirm/
  // write-gating and the inputPath override can be exercised with no disk IO.
  readText?: (path: string) => Promise<string>;
  writeText?: (path: string, content: string) => Promise<void>;
}

interface ExecuteResult {
  dataHandles: Array<{ name: string }>;
}

/** Read a document's text from disk (the production file reader). */
async function realReadText(path: string): Promise<string> {
  // Reading the document under review is the point of these methods; path comes
  // from validated config, never free user text.
  return await Deno.readTextFile(path);
}

/** Write filled content to disk (the production file writer). */
async function realWriteText(path: string, content: string): Promise<void> {
  // Writing the filled document is the point of fill; path comes from validated
  // config/args, never free user text.
  await Deno.writeTextFile(path, content);
}

// ---------------------------------------------------------------------------
// Resource schemas (for the behavior definition)
// ---------------------------------------------------------------------------

const PlaceholderSchema = z.object({
  // A placeholder token is the literal bracket string (e.g. "[core hours]"),
  // not a credential.
  // swamp-quality-ignore credentials-sensitive-field
  token: z.string(),
  line: z.number(),
  mappedKey: z.string().nullable(),
  needsNewEntry: z.boolean(),
});

const ScanReportSchema = z.object({
  path: z.string(),
  placeholders: z.array(PlaceholderSchema),
  draftMarkers: z.array(z.object({ marker: z.string(), line: z.number() })),
  internalFileRefs: z.array(z.object({ ref: z.string(), line: z.number() })),
  brokenCrossRefs: z.array(
    z.object({ ref: z.string(), reason: z.string(), line: z.number() }),
  ),
  missingDisclaimers: z.array(z.string()),
  defectCount: z.number(),
  clean: z.boolean(),
});

const FillReportSchema = z.object({
  path: z.string(),
  outputPath: z.string(),
  resolvedCount: z.number(),
  resolved: z.array(
    z.object({ token: z.string(), key: z.string(), value: z.string() }),
  ),
  unresolved: z.array(z.string()),
  wrote: z.boolean(),
});

const CheckReportSchema = z.object({
  path: z.string(),
  sendable: z.boolean(),
  findings: z.array(
    z.object({
      id: z.string(),
      severity: z.enum(["critical", "high", "medium"]),
      category: z.string(),
      message: z.string(),
      line: z.number().optional(),
    }),
  ),
});

const RenderReportSchema = z.object({
  inputPath: z.string(),
  outputPath: z.string(),
  format: RenderFormatSchema,
  command: z.array(z.string()),
  rendered: z.boolean(),
});

// ---------------------------------------------------------------------------
// Behavior definition
// ---------------------------------------------------------------------------

/** Behavior definition for the content-studio document type. */
export const model = {
  type: "@shrug/content-studio/document",
  version: "2026.11.19.1",
  description:
    "A piece of content under review: scan (defect inventory), fill (resolve " +
    "placeholders against library entries passed in as a method argument; " +
    "dry-run-gated), check (the sendability gate), render (PDF/DOCX via an " +
    "injectable pandoc runner). Domain-agnostic; reads library data as an arg, " +
    "never another behavior's resources.",
  globalArguments: GlobalArgsSchema,
  resources: {
    "scanReport": {
      description:
        "Defect inventory: placeholders (with library-key mapping), draft " +
        "markers, internal-file refs, broken cross-refs, missing disclaimers.",
      schema: ScanReportSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "fillReport": {
      description:
        "Outcome of a fill: resolved placeholders, the unresolved[] report, the " +
        "output path, and whether the filled file was written (confirm-gated).",
      schema: FillReportSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "checkReport": {
      description:
        "Sendability-gate result: severity-rated findings and whether the " +
        "document is sendable (no critical/high finding).",
      schema: CheckReportSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "renderReport": {
      description:
        "Outcome of a render: the input/output paths, format, the pandoc command, " +
        "and whether it actually ran (confirm-gated).",
      schema: RenderReportSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  methods: {
    scan: {
      description:
        "Inventory a document's defects (no mutation): unresolved placeholders " +
        "(mapped to library keys when passed entries' tokens match, else " +
        "needs-new-entry), draft markers, internal-file refs, broken cross-refs, " +
        "missing disclaimers. Captures a `scanReport`.",
      arguments: ScanArgs,
      execute: async (
        rawArgs: unknown,
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const a = ScanArgs.parse(rawArgs);
        const cfg = GlobalArgsSchema.parse(context.globalArgs);
        const read = context.readText ?? realReadText;
        const readPath = a.inputPath ?? cfg.path;
        const text = await read(readPath);
        const report = scanText(
          text,
          readPath,
          optionsFromConfig(cfg),
          a.entries,
        );
        context.logger?.info("content-studio document scan", {
          method: "scan",
          path: readPath,
          defects: report.defectCount,
        });
        const handle = await context.writeResource(
          "scanReport",
          "scan",
          report as unknown as Record<string, unknown>,
        );
        return { dataHandles: [handle] };
      },
    },
    fill: {
      description:
        "Resolve placeholders against the library entries passed in (via CEL " +
        "data.latest). Emits filled text + an unresolved[] report. dry-run-gated: " +
        "writes the filled file only when confirm=true; otherwise returns the plan.",
      arguments: FillArgs,
      execute: async (
        rawArgs: unknown,
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const a = FillArgs.parse(rawArgs);
        const cfg = GlobalArgsSchema.parse(context.globalArgs);
        const read = context.readText ?? realReadText;
        const write = context.writeText ?? realWriteText;
        const text = await read(cfg.path);
        const result = fillText(text, a.entries);
        // Default output is non-destructive: the filled draft lives beside the
        // original, which keeps its placeholders. check/render target the filled
        // path via their inputPath argument.
        const outputPath = a.outputPath ?? `${cfg.path}.filled.md`;
        const wrote = a.confirm;
        context.logger?.info("content-studio document fill", {
          method: "fill",
          path: cfg.path,
          outputPath,
          resolved: result.resolved.length,
          unresolved: result.unresolved.length,
          confirm: a.confirm,
        });
        if (wrote) await write(outputPath, result.filled);
        const handle = await context.writeResource("fillReport", "fill", {
          path: cfg.path,
          outputPath,
          resolvedCount: result.resolved.length,
          resolved: result.resolved,
          unresolved: result.unresolved,
          wrote,
        });
        return { dataHandles: [handle] };
      },
    },
    check: {
      description:
        "The sendability gate: severity-rated findings if any bracket, draft " +
        "marker, or internal filename survives, plus cross-ref/disclaimer/tone " +
        "checks. Captures a `checkReport`; sendable only when no critical/high.",
      arguments: CheckArgs,
      execute: async (
        rawArgs: unknown,
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const a = CheckArgs.parse(rawArgs);
        const cfg = GlobalArgsSchema.parse(context.globalArgs);
        const read = context.readText ?? realReadText;
        const readPath = a.inputPath ?? cfg.path;
        const text = await read(readPath);
        const report = checkText(text, readPath, optionsFromConfig(cfg));
        context.logger?.info("content-studio document check", {
          method: "check",
          path: readPath,
          findings: report.findings.length,
          sendable: report.sendable,
        });
        const handle = await context.writeResource(
          "checkReport",
          "check",
          report as unknown as Record<string, unknown>,
        );
        return { dataHandles: [handle] };
      },
    },
    render: {
      description:
        "Produce PDF/DOCX from the final markdown via an injectable pandoc " +
        "runner. confirm-gated: runs pandoc only when confirm=true; otherwise " +
        "returns the planned command. Captures a `renderReport`.",
      arguments: RenderArgs,
      execute: async (
        rawArgs: unknown,
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const a = RenderArgs.parse(rawArgs);
        const cfg = GlobalArgsSchema.parse(context.globalArgs);
        const inputPath = a.inputPath ?? cfg.path;
        const outputPath = a.outputPath ??
          defaultOutputPath(inputPath, a.format);
        const result = await renderDoc(realRunner, {
          inputPath,
          outputPath,
          format: a.format,
          confirm: a.confirm,
        });
        context.logger?.info("content-studio document render", {
          method: "render",
          path: inputPath,
          format: a.format,
          rendered: result.rendered,
        });
        const handle = await context.writeResource(
          "renderReport",
          "render",
          result as unknown as Record<string, unknown>,
        );
        return { dataHandles: [handle] };
      },
    },
  },
};
