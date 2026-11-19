---
name: content-review
description: >
  Drive the @shrug/content-studio behavior types and the content-review-pipeline
  template: a library (a canonical answer/content hub) and a document (a piece of
  content under review). Use when scanning a document for defects, resolving its
  placeholders against an approved library, running the sendability gate, applying
  the content-professional reviewer lens, driving the content-review pipeline, or
  managing library entries. Triggers on "content review", "sendability",
  "content library", "answer library", "fill placeholders", "scan a document",
  "is this sendable", the `@shrug/content-studio/library` or
  `@shrug/content-studio/document` types, or the content-review-pipeline factory.
---

# content-review

The operating guide for `@shrug/content-studio`: two domain-agnostic behavior
types plus a generic pipeline that drives them. A **library** is a content hub
-- a set of approved answer blocks (entries) that many documents reuse. A
**document** is a piece of content under review that resolves its placeholders
against a library and must pass a sendability gate before it goes out.

This skill is a **router** -- read the matching reference file for detail:

- `references/methods.md` -- every method on both types: arguments, the
  dry-run/confirm gates, what each captures, and the exact gotchas.
- `references/pipeline.md` -- the `content-review-pipeline` stagecraft template:
  its stages, the counsel gate, the content-professional reviewer persona, and
  how to instantiate and drive it.

## The model in one paragraph

A document carries three recurring defect classes: unresolved bracket
placeholders (`[core hours]`), draft/scaffolding markers ("drafted by ... to
review"), and internal-filename references (`some-policy.md` instead of a
reader-facing title). Rather than hand-fix each document, the recurring answers
live once in a **library** and fill many documents. The flow is: **scan**
(inventory defects, map each placeholder to a library key) -> **fill** (resolve
placeholders against the library's approved entries) -> **check** (the
sendability gate) -> a content-professional reviewer's sign-off -> render.

## The one wiring rule you must not get wrong

A document method never reads the library directly. `context.readResource` reads
only a behavior's OWN resources. The library's approved entries reach
`document.fill` (and optionally `document.scan`) as a **method argument**, wired
by the pipeline with CEL:

```
data.latest("<library-instance>", "entries").attributes.entries
```

passed as the `entries` argument to `fill`/`scan`. If you find yourself trying to
make a document read a library instance, stop -- pass the entries in.

## Quick path (outside the pipeline)

```bash
# 1. Scan the document, mapping placeholders against the library's entries.
swamp behavior run <document> scan \
  --arg entries='<library entries via CEL data.latest>'

# 2. Resolve placeholders (preview first; confirm to write the filled file).
swamp behavior run <document> fill --arg entries='...'              # plan
swamp behavior run <document> fill --arg entries='...' --arg confirm=true

# 3. The sendability gate -- sendable only when no critical/high finding.
swamp behavior run <document> check

# 4. Render the final markdown (confirm to actually run pandoc).
swamp behavior run <document> render --arg format=pdf --arg confirm=true
```

For repeatable, gated, human-approved runs, use the pipeline instead of loose
calls -- see `references/pipeline.md`.

## Publish posture

The `@shrug/content-studio` code, the bundled `content-review-pipeline`
template, and this skill are all GENERIC and public: no domain values, no
contacts, no instance data. Every value a document fills with lives in a LOCAL
library instance's data, never in the extension, the template, or this skill.
Keep that wall when you adapt them.
