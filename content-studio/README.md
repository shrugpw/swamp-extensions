# @shrug/content-studio

A swamp-native content-review toolkit. It gives you a reusable way to keep the
answers a document reuses in one place, resolve a document's placeholders
against them, and gate the document for sendability before it goes out -- the
"content hub" model a content-review professional works with (tools in the RFP /
answer-library category), built as first-class typed swamp behaviors rather than
a script or a flat file.

The extension bundles three cleanly layered pieces:

- two **behavior types** -- the reusable, domain-agnostic primitives;
- a generic **content-review-pipeline** stagecraft factory template (an example
  definition file) that owns the gated process and calls the types' methods;
- a **content-review** skill (under `.claude/skills/`) that drives both.

Everything here is domain-agnostic. The types carry no values; the values a
document fills with live in a LOCAL library instance's data only.

## The two types

### `@shrug/content-studio/library`

The canonical answer/content hub. One instance is one library; its entries are
the approved answer blocks many documents reuse. Each entry is keyed by `key`,
scoped (`company`, a state code, or any consumer namespace), has a `status`
(`draft` / `approved` / `retired` / `expiring`), a review cadence, the literal
placeholder `tokens` it satisfies, and `provenance` (who decided, when, from
what source).

| Method   | What it does                                                                     |
| -------- | -------------------------------------------------------------------------------- |
| `lookup` | Read the approved value(s) for a key / scope / tag / status. No mutation.         |
| `upsert` | Add or replace an entry (value + metadata + provenance). Gated: `confirm=true`.   |
| `review` | Approve or retire an entry; stamps status + provenance. Gated: `confirm=true`.    |
| `audit`  | Flip approved entries past their review cadence to `expiring`. Reports always; applies the flip on `confirm=true`. |

### `@shrug/content-studio/document`

A piece of content under review, bound (by name) to one or more libraries.

| Method   | What it does                                                                     |
| -------- | -------------------------------------------------------------------------------- |
| `scan`   | Inventory defects (no mutation): unresolved bracket placeholders, draft/scaffolding markers, internal-filename refs, broken in-doc cross-refs, missing disclaimers. Each placeholder maps to a library key via `tokens`, else `needsNewEntry`. |
| `fill`   | Resolve placeholders against the library's APPROVED entries; emit filled text + an `unresolved[]` report. Writes the filled file only on `confirm=true`. |
| `check`  | The sendability gate: severity-rated findings if any bracket, draft marker, or internal filename survives, plus cross-ref / disclaimer / tone checks. `sendable` only when no critical/high finding. |
| `render` | Produce PDF/DOCX from the final markdown via an injectable pandoc runner (never a `command/shell` passthrough). Runs pandoc only on `confirm=true`. |

## How a document reads a library

A method never reads another behavior's resources -- `context.readResource`
reads only a behavior's own. The library's approved entries reach
`document.fill` (and optionally `document.scan`) as a **method argument**, wired
by the pipeline with CEL:

```
data.latest("<library-instance>", "entries").attributes.entries
```

passed as the `entries` argument. The document unit tests cover this by injecting
the entries as that argument; it is proven at runtime, not by a definition
`validate`.

## Quick start

Scan a document against a library's entries, resolve its placeholders, gate it,
and render it. `fill` is non-destructive: it writes a filled draft beside the
original (`<path>.filled.md` by default) and leaves the original's placeholders
intact. So `check` and `render` are pointed at the filled draft with their
`inputPath` argument -- the whole flow then targets one coherent file:

```bash
# Inventory defects and map placeholders to library keys.
swamp behavior run <document> scan --arg entries='<library entries via CEL>'

# Preview the fill, then write the filled draft (defaults to <path>.filled.md).
swamp behavior run <document> fill --arg entries='...'
swamp behavior run <document> fill --arg entries='...' --arg confirm=true

# Gate and render the FILLED draft, not the original (inputPath override).
swamp behavior run <document> check --arg inputPath='<path>.filled.md'
swamp behavior run <document> render \
  --arg inputPath='<path>.filled.md' --arg format=pdf --arg confirm=true
```

Omit `inputPath` and a method falls back to the instance's configured `path`
(the original), preserving the simplest single-file case.

## The gates

Every change is explicit. A library `upsert`/`review` writes only with
`confirm=true`; `audit` applies its status flip only with `confirm=true`. A
document `fill` writes the filled file only with `confirm=true`; `render` runs
pandoc only with `confirm=true`. Without it, each method returns a plan and
mutates nothing.

## The bundled pipeline and skill

- `examples/content-review-pipeline.yaml` -- a generic stagecraft factory
  template: `intake -> resolve -> sendability-review -> counsel -> approve ->
  render -> done`. A content-professional reviewer persona occupies the
  `sendability-review` stage; the `counsel` stage is CEL-gated to legal documents
  with a deferred-waiver path. Copy it, bind your instances, and adapt the
  prompts. Validate it with the stagecraft path
  (`swamp behavior run <factory> validate`).
- `.claude/skills/content-review/` -- the operating guide for both types and the
  pipeline. See its `references/methods.md` and `references/pipeline.md`.

## Design notes

- The injectable pandoc runner is the one side-effect seam in `render`; the
  orchestration is pure and unit-tested with a fake runner, so no real pandoc,
  filesystem, or network is touched in tests.
- zod 4's `z.record` takes two arguments; this extension uses arrays rather than
  keyed maps throughout.

## Publish posture

The code, the bundled template, and the skill are all generic and public: no
domain values, no contacts, no instance data. A consumer's values live in a
LOCAL library instance only. A publish-scan leak gate is the backstop.

## License

MIT. See `LICENSE.txt`.
