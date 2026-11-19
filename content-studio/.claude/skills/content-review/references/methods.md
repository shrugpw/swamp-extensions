# content-studio methods

Both types parse their arguments with zod and capture a resource per run. Every
write is gated: a library mutation needs `confirm=true`; a document fill or
render needs `confirm=true`. Without it you get a plan, not a change.

## type `@shrug/content-studio/library`

Instance config (`globalArguments`):

| Field                  | Type      | Meaning                                                      |
| ---------------------- | --------- | ----------------------------------------------------------- |
| `name`                 | string    | Human label; one instance is one library.                   |
| `defaultReviewCadence` | number?   | Whole-day cadence `audit` applies when an entry has none.    |

Entry shape (the `entries` resource holds the full list):

| Field           | Type       | Meaning                                                              |
| --------------- | ---------- | -------------------------------------------------------------------- |
| `key`           | string     | Stable key for the answer (e.g. `pay-schedule`).                     |
| `value`         | string     | The approved value used to fill placeholders.                        |
| `scope`         | string     | `company` \| a state code \| any consumer namespace.                 |
| `status`        | enum       | `draft` \| `approved` \| `retired` \| `expiring`.                    |
| `owner`         | string?    | Who owns keeping the entry current.                                  |
| `lastReviewed`  | string?    | ISO-8601 date of the last review.                                    |
| `reviewCadence` | number?    | Whole days between required re-reviews; drives `audit`.              |
| `tags`          | string[]   | Free-form grouping/lookup tags.                                      |
| `tokens`        | string[]   | Literal placeholder strings this entry satisfies (the fill map).     |
| `provenance`    | object?    | `{ decidedBy, decidedAt, source }` -- who decided, when, from what.  |

Methods:

- **lookup** `{ key?, scope?, tag?, status? }` -- a read. Filters the entries and
  captures a `lookupResult`; never mutates the store.
- **upsert** `{ entry, confirm=false }` -- add or replace an entry matched by
  (key, scope). `confirm=false` returns the plan; `confirm=true` writes the
  store. Run on a person's word, with provenance in the entry.
- **review** `{ key, scope, action: approve|retire, decidedBy, source?, at?,
  confirm=false }` -- stamps `status`, `provenance`, and `lastReviewed`.
  `confirm=true` writes; a missing entry errors.
- **audit** `{ asOf?, confirm=false }` -- finds approved entries whose
  `reviewCadence` has lapsed as of `asOf` and flips them to `expiring`. Always
  captures an `auditReport`; applies the flip to the store only when
  `confirm=true`.

## type `@shrug/content-studio/document`

Instance config (`globalArguments`):

| Field                    | Type      | Meaning                                                         |
| ------------------------ | --------- | -------------------------------------------------------------- |
| `path`                   | string    | Path to the markdown document under review.                    |
| `libraries`              | string[]  | Library instance names this document binds to (informational). |
| `draftMarkers`           | string[]  | Draft/scaffolding phrases to flag (sensible defaults).         |
| `internalFileExtensions` | string[]  | Source-file extensions whose bare refs are defects.            |
| `requiredDisclaimers`    | string[]  | Phrases that must be present; any absent is a defect.          |
| `toneFlags`              | string[]  | Tone phrases `check` flags at medium severity.                 |

Methods:

- **scan** `{ entries? }` -- inventories defects (no mutation): placeholders
  (mapped to a library key when a passed-in entry's `tokens` matches, else
  `needsNewEntry`), draft markers, internal-file refs, broken in-doc cross-refs,
  missing disclaimers. Captures a `scanReport`.
- **fill** `{ entries, outputPath?, confirm=false }` -- replaces each placeholder
  with the value of the APPROVED entry whose `tokens` contains it. Captures a
  `fillReport` with `resolved` and `unresolved[]`. Writes the filled file only
  when `confirm=true`; otherwise it is a plan.
- **check** `{}` -- the sendability gate. A surviving placeholder or draft marker
  is **critical**; an internal-file ref, broken cross-ref, or missing disclaimer
  is **high**; a tone flag is **medium**. Captures a `checkReport`; `sendable` is
  true only when there is no critical/high finding.
- **render** `{ format: pdf|docx, outputPath?, confirm=false }` -- builds a
  pandoc command through an injectable runner and runs it only when
  `confirm=true` (otherwise returns the planned command). pandoc is never a
  `command/shell` passthrough; it is one isolated, injectable seam.

## Gotchas

- **Entries are a method argument, not a cross-read.** `document.fill`/`scan`
  resolve against the `entries` you pass in. Wire them with CEL
  `data.latest("<library>", "entries").attributes.entries`. A method cannot read
  another behavior's resources.
- **Only `approved` entries fill.** `fill` ignores draft/retired/expiring
  entries; those placeholders come back `unresolved`.
- **`check` is mechanical.** It proves no bracket/marker/internal-ref survives
  and runs the configured tone/disclaimer checks. Judgement about voice and
  fitness is the content-professional reviewer's job (see
  `references/pipeline.md`), layered on top of the mechanical pass -- not a claim
  the gate makes on its own.
