/**
 * @shrug/content-studio/library - the canonical content/answer store.
 *
 * A library is a "content hub": a set of approved answer blocks (entries) that
 * many documents reuse. Each entry is keyed by `key`, scoped (company-wide, a
 * state code, or any consumer-defined namespace), carries a status
 * (draft/approved/retired/expiring), a review cadence, and the literal
 * placeholder `tokens` it satisfies -- the map `document.fill` uses to resolve a
 * document's placeholders.
 *
 * The TYPE is domain-agnostic: it holds no HR, legal, or organization-specific
 * values. Consumer values live in a local instance's resource store only.
 *
 * All four methods are pure orchestration over an in-memory entry list; the one
 * side effect (reading/writing the `entries` resource) goes through the swamp
 * context. The pure functions are exported and unit-tested with no IO.
 *
 * Gotcha (kept on the record): zod 4 `z.record` takes TWO args
 * (`z.record(z.string(), z.unknown())`); this module avoids keyed maps and uses
 * arrays instead. `context.readResource` reads only THIS instance's own
 * resources -- a document never reads a library through it; the pipeline passes
 * library entries into `document.fill` as a method argument via CEL.
 *
 * @module
 */
import { z } from "npm:zod@4.4.3";

// ---------------------------------------------------------------------------
// Entry + provenance schemas
// ---------------------------------------------------------------------------

/** Who decided an entry's value, when, and from what source. */
export const ProvenanceSchema = z.object({
  decidedBy: z
    .string()
    .min(1)
    .describe("Who decided this value (a person or role)."),
  decidedAt: z
    .string()
    .min(1)
    .describe("ISO-8601 timestamp of the decision."),
  source: z
    .string()
    .min(1)
    .describe(
      "What the value rests on: a human decision, a prior doc, a statute.",
    ),
});
export type Provenance = z.infer<typeof ProvenanceSchema>;

/** The lifecycle status of a library entry. */
export const StatusSchema = z.enum([
  "draft",
  "approved",
  "retired",
  "expiring",
]);
export type EntryStatus = z.infer<typeof StatusSchema>;

/**
 * One library entry (an approved answer block). `scope` is company | a state
 * code (AZ, NY) | any consumer namespace; `tokens` are the literal placeholder
 * strings this entry satisfies (e.g. "[weekly / biweekly / semi-monthly]").
 * `reviewCadence` is a whole number of DAYS between required re-reviews.
 */
export const EntrySchema = z.object({
  key: z.string().min(1).describe(
    "Stable key for the answer (e.g. pay-schedule).",
  ),
  value: z.string().min(1).describe(
    "The approved value used to fill placeholders.",
  ),
  scope: z
    .string()
    .min(1)
    .default("company")
    .describe("company | a state code | a consumer-defined namespace."),
  status: StatusSchema.default("draft").describe(
    "draft | approved | retired | expiring.",
  ),
  owner: z.string().min(1).optional().describe(
    "Who owns keeping this entry current.",
  ),
  lastReviewed: z
    .string()
    .min(1)
    .optional()
    .describe("ISO-8601 date the entry was last reviewed."),
  reviewCadence: z
    .number()
    .int()
    .positive()
    .optional()
    .describe("Whole days between required re-reviews; drives audit."),
  tags: z
    .array(z.string().min(1))
    .default([])
    .describe("Free-form tags for grouping/lookup."),
  tokens: z
    .array(z.string().min(1))
    .default([])
    .describe(
      "Literal placeholder strings this entry satisfies (the fill map).",
    ),
  provenance: ProvenanceSchema.optional().describe(
    "Who decided, when, and the source.",
  ),
});
export type Entry = z.infer<typeof EntrySchema>;

// ---------------------------------------------------------------------------
// Instance spec (globalArguments)
// ---------------------------------------------------------------------------

/** The library instance config. */
export const GlobalArgsSchema = z.object({
  name: z
    .string()
    .min(1)
    .describe("Human label for this library (one instance is one library)."),
  defaultReviewCadence: z
    .number()
    .int()
    .positive()
    .optional()
    .describe(
      "Default whole-day review cadence applied by audit when an entry has none.",
    ),
});
export type LibraryConfig = z.infer<typeof GlobalArgsSchema>;

// ---------------------------------------------------------------------------
// The persisted `entries` resource payload
// ---------------------------------------------------------------------------

/** The single resource a library maintains: the full entry list. */
export const EntriesResourceSchema = z.object({
  library: z.string(),
  entries: z.array(EntrySchema),
});
export type EntriesResource = z.infer<typeof EntriesResourceSchema>;

// ---------------------------------------------------------------------------
// Method argument schemas
// ---------------------------------------------------------------------------

/** Arguments for `lookup` (all optional filters; a read). */
export const LookupArgs = z.object({
  key: z.string().min(1).optional().describe(
    "Match entries with this exact key.",
  ),
  scope: z.string().min(1).optional().describe("Match entries in this scope."),
  tag: z.string().min(1).optional().describe(
    "Match entries carrying this tag.",
  ),
  status: StatusSchema.optional().describe("Match entries with this status."),
});

/** Arguments for `upsert` (a human-gated write). */
export const UpsertArgs = z.object({
  entry: EntrySchema.describe(
    "The entry to add or replace (matched by key + scope).",
  ),
  confirm: z
    .boolean()
    .default(false)
    .describe(
      "Write only when true; otherwise return the plan without mutating.",
    ),
});

/** Arguments for `review` (approve or retire an entry; a human-gated write). */
export const ReviewArgs = z.object({
  key: z.string().min(1).describe("Key of the entry to review."),
  scope: z.string().min(1).default("company").describe(
    "Scope of the entry to review.",
  ),
  action: z.enum(["approve", "retire"]).describe(
    "approve -> approved; retire -> retired.",
  ),
  decidedBy: z.string().min(1).describe(
    "Who made the review decision (provenance).",
  ),
  source: z
    .string()
    .min(1)
    .default("review decision")
    .describe("What the decision rests on (provenance source)."),
  at: z
    .string()
    .min(1)
    .optional()
    .describe("ISO-8601 timestamp of the decision; defaults to now."),
  confirm: z
    .boolean()
    .default(false)
    .describe(
      "Write only when true; otherwise return the plan without mutating.",
    ),
});

/** Arguments for `audit` (flip entries past their review cadence to expiring). */
export const AuditArgs = z.object({
  asOf: z
    .string()
    .min(1)
    .optional()
    .describe("ISO-8601 date to evaluate cadence against; defaults to now."),
  confirm: z
    .boolean()
    .default(false)
    .describe(
      "Apply the status flip only when true; otherwise report without mutating.",
    ),
});

// ---------------------------------------------------------------------------
// Pure orchestration (exported, unit-tested with no IO)
// ---------------------------------------------------------------------------

/** Filter entries by any combination of key / scope / tag / status. */
export function filterEntries(
  entries: Entry[],
  query: z.infer<typeof LookupArgs>,
): Entry[] {
  return entries.filter((e) => {
    if (query.key !== undefined && e.key !== query.key) return false;
    if (query.scope !== undefined && e.scope !== query.scope) return false;
    if (query.status !== undefined && e.status !== query.status) return false;
    if (query.tag !== undefined && !e.tags.includes(query.tag)) return false;
    return true;
  });
}

/**
 * Add or replace an entry, matched by (key, scope). Returns a NEW list and
 * whether the operation created a new entry or replaced an existing one.
 */
export function upsertEntry(
  entries: Entry[],
  entry: Entry,
): { entries: Entry[]; created: boolean } {
  const idx = entries.findIndex(
    (e) => e.key === entry.key && e.scope === entry.scope,
  );
  if (idx === -1) return { entries: [...entries, entry], created: true };
  const next = entries.slice();
  next[idx] = entry;
  return { entries: next, created: false };
}

/**
 * Approve or retire the entry matched by (key, scope). Stamps status,
 * provenance, and lastReviewed. Returns the NEW list and the updated entry, or
 * updated=null when no entry matched.
 */
export function reviewEntry(
  entries: Entry[],
  args: {
    key: string;
    scope: string;
    action: "approve" | "retire";
    provenance: Provenance;
  },
): { entries: Entry[]; updated: Entry | null } {
  const idx = entries.findIndex(
    (e) => e.key === args.key && e.scope === args.scope,
  );
  if (idx === -1) return { entries, updated: null };
  const prev = entries[idx];
  const updated: Entry = {
    ...prev,
    status: args.action === "approve" ? "approved" : "retired",
    lastReviewed: args.provenance.decidedAt,
    provenance: args.provenance,
  };
  const next = entries.slice();
  next[idx] = updated;
  return { entries: next, updated };
}

/** True when an approved entry's review cadence has lapsed as of `asOf`. */
export function isLapsed(
  entry: Entry,
  asOfMs: number,
  defaultCadence?: number,
): boolean {
  if (entry.status !== "approved") return false;
  const cadence = entry.reviewCadence ?? defaultCadence;
  if (cadence === undefined) return false;
  if (!entry.lastReviewed) return true;
  const last = Date.parse(entry.lastReviewed);
  if (Number.isNaN(last)) return true;
  const dueMs = last + cadence * 24 * 60 * 60 * 1000;
  return asOfMs > dueMs;
}

/**
 * Identify approved entries whose review cadence has lapsed. Returns the lapsed
 * entries and a NEW list with those flipped to `expiring` (the flip the caller
 * applies when confirmed).
 */
export function auditEntries(
  entries: Entry[],
  asOf: string,
  defaultCadence?: number,
): { lapsed: Entry[]; flipped: Entry[] } {
  const asOfMs = Date.parse(asOf);
  const lapsed: Entry[] = [];
  const flipped = entries.map((e) => {
    if (isLapsed(e, asOfMs, defaultCadence)) {
      lapsed.push(e);
      return { ...e, status: "expiring" as const };
    }
    return e;
  });
  return { lapsed, flipped };
}

// ---------------------------------------------------------------------------
// Behavior context / result interfaces
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
  // Reads this instance's own previously written resource by name; returns null
  // when never written. Cannot read another behavior's resources.
  readResource?: (
    name: string,
    version?: number,
  ) => Promise<Record<string, unknown> | null>;
}

interface ExecuteResult {
  dataHandles: Array<{ name: string }>;
}

/** The fixed name of the entry-store resource this type reads and writes. */
const ENTRIES = "entries";

/** Read the current entries resource for this instance (empty when unset). */
async function readEntries(
  context: ExecuteContext,
  library: string,
): Promise<Entry[]> {
  if (!context.readResource) return [];
  const prior = await context.readResource(ENTRIES);
  if (!prior) return [];
  const parsed = EntriesResourceSchema.safeParse(prior);
  if (!parsed.success) {
    // A stored entries resource EXISTS but does not match the schema (corrupted,
    // hand-edited, or written by an incompatible version). Refuse rather than
    // return an empty set: a later confirm=true upsert/review/audit would read
    // this empty base and persist over the malformed resource, silently dropping
    // every stored entry. Fail loudly so the store is inspected and recovered.
    throw new Error(
      `content-studio library "${library}": the stored entries resource failed ` +
        `schema validation and cannot be read safely; refusing to proceed so a ` +
        `write does not overwrite and lose existing entries. Details: ` +
        parsed.error.message,
    );
  }
  // The stored resource is stamped with its owning library's name; a mismatch
  // means these entries belong to a different library, so they are not ours.
  if (parsed.data.library !== library) return [];
  return parsed.data.entries;
}

// ---------------------------------------------------------------------------
// Behavior definition
// ---------------------------------------------------------------------------

/** Behavior definition for the content-studio library type. */
export const model = {
  type: "@shrug/content-studio/library",
  version: "2026.11.19.1",
  description:
    "Canonical content/answer store (a content hub): entries keyed by `key` " +
    "with scope/status/owner/review cadence/tags/tokens/provenance. lookup " +
    "(read), upsert (gated write), review (approve/retire), audit (flip lapsed " +
    "entries to expiring). Domain-agnostic; values live in local instance data.",
  globalArguments: GlobalArgsSchema,
  resources: {
    "entries": {
      description:
        "The full entry list for this library (the content hub). Written by " +
        "upsert/review/audit and read back by every method. The pipeline wires " +
        'this into document.fill via CEL data.latest(<library>, "entries").',
      schema: EntriesResourceSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "lookupResult": {
      description:
        "Entries matched by a lookup query (a read snapshot; the entry store is " +
        "not mutated).",
      schema: z.object({
        library: z.string(),
        query: z.object({
          key: z.string().optional(),
          scope: z.string().optional(),
          tag: z.string().optional(),
          status: StatusSchema.optional(),
        }),
        count: z.number(),
        matched: z.array(EntrySchema),
      }),
      lifetime: "infinite",
      garbageCollection: 10,
    },
    "auditReport": {
      description:
        "Entries whose review cadence has lapsed as of the audit date, and " +
        "whether the expiring flip was applied.",
      schema: z.object({
        library: z.string(),
        asOf: z.string(),
        applied: z.boolean(),
        lapsedCount: z.number(),
        lapsed: z.array(EntrySchema),
      }),
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  methods: {
    lookup: {
      description:
        "Read the approved value(s) for a key / scope / tag / status. A read: " +
        "captures a `lookupResult`; never mutates the entry store.",
      arguments: LookupArgs,
      execute: async (
        rawArgs: unknown,
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const a = LookupArgs.parse(rawArgs);
        const cfg = GlobalArgsSchema.parse(context.globalArgs);
        const entries = await readEntries(context, cfg.name);
        const matched = filterEntries(entries, a);
        context.logger?.info("content-studio library lookup", {
          method: "lookup",
          library: cfg.name,
          matched: matched.length,
        });
        const handle = await context.writeResource("lookupResult", "lookup", {
          library: cfg.name,
          query: a,
          count: matched.length,
          matched,
        });
        return { dataHandles: [handle] };
      },
    },
    upsert: {
      description:
        "Add or replace an entry (matched by key + scope) with its value + " +
        "metadata + provenance. Human-gated: writes the entry store only when " +
        "confirm=true; otherwise returns the plan.",
      arguments: UpsertArgs,
      execute: async (
        rawArgs: unknown,
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const a = UpsertArgs.parse(rawArgs);
        const cfg = GlobalArgsSchema.parse(context.globalArgs);
        const entries = await readEntries(context, cfg.name);
        const { entries: next, created } = upsertEntry(entries, a.entry);
        context.logger?.info("content-studio library upsert", {
          method: "upsert",
          library: cfg.name,
          key: a.entry.key,
          scope: a.entry.scope,
          created,
          confirm: a.confirm,
        });
        if (!a.confirm) {
          const handle = await context.writeResource(
            "lookupResult",
            "upsert-plan",
            {
              library: cfg.name,
              query: { key: a.entry.key, scope: a.entry.scope },
              count: 1,
              matched: [a.entry],
            },
          );
          return { dataHandles: [handle] };
        }
        const handle = await context.writeResource(ENTRIES, ENTRIES, {
          library: cfg.name,
          entries: next,
        });
        return { dataHandles: [handle] };
      },
    },
    review: {
      description:
        "Approve or retire an entry: stamps status + provenance + lastReviewed. " +
        "Human-gated: writes only when confirm=true; otherwise returns the plan.",
      arguments: ReviewArgs,
      execute: async (
        rawArgs: unknown,
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const a = ReviewArgs.parse(rawArgs);
        const cfg = GlobalArgsSchema.parse(context.globalArgs);
        const entries = await readEntries(context, cfg.name);
        const provenance: Provenance = {
          decidedBy: a.decidedBy,
          decidedAt: a.at ?? new Date().toISOString(),
          source: a.source,
        };
        const { entries: next, updated } = reviewEntry(entries, {
          key: a.key,
          scope: a.scope,
          action: a.action,
          provenance,
        });
        context.logger?.info("content-studio library review", {
          method: "review",
          library: cfg.name,
          key: a.key,
          scope: a.scope,
          action: a.action,
          found: updated !== null,
          confirm: a.confirm,
        });
        if (updated === null) {
          throw new Error(
            `content-studio: no entry with key "${a.key}" in scope "${a.scope}"`,
          );
        }
        if (!a.confirm) {
          const handle = await context.writeResource(
            "lookupResult",
            "review-plan",
            {
              library: cfg.name,
              query: { key: a.key, scope: a.scope },
              count: 1,
              matched: [updated],
            },
          );
          return { dataHandles: [handle] };
        }
        const handle = await context.writeResource(ENTRIES, ENTRIES, {
          library: cfg.name,
          entries: next,
        });
        return { dataHandles: [handle] };
      },
    },
    audit: {
      description:
        "Surface approved entries whose review cadence has lapsed and flip them " +
        "to expiring. Reports always; applies the flip only when confirm=true.",
      arguments: AuditArgs,
      execute: async (
        rawArgs: unknown,
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const a = AuditArgs.parse(rawArgs);
        const cfg = GlobalArgsSchema.parse(context.globalArgs);
        const entries = await readEntries(context, cfg.name);
        const asOf = a.asOf ?? new Date().toISOString();
        const { lapsed, flipped } = auditEntries(
          entries,
          asOf,
          cfg.defaultReviewCadence,
        );
        context.logger?.info("content-studio library audit", {
          method: "audit",
          library: cfg.name,
          lapsed: lapsed.length,
          confirm: a.confirm,
        });
        const handles: Array<{ name: string }> = [];
        handles.push(
          await context.writeResource("auditReport", "audit", {
            library: cfg.name,
            asOf,
            applied: a.confirm && lapsed.length > 0,
            lapsedCount: lapsed.length,
            lapsed,
          }),
        );
        if (a.confirm && lapsed.length > 0) {
          handles.push(
            await context.writeResource(ENTRIES, ENTRIES, {
              library: cfg.name,
              entries: flipped,
            }),
          );
        }
        return { dataHandles: handles };
      },
    },
  },
};
