# content-review-pipeline

A generic stagecraft factory template bundled with the extension at
`examples/content-review-pipeline.yaml`. It owns the gated process -- human
stops, review gates, approvals -- and calls the two types' methods. It names no
domain and no values; a consumer copies it, binds instances, and adapts the
prompts.

## Stages

| Stage                | Mode        | What happens                                                                 |
| -------------------- | ----------- | --------------------------------------------------------------------------- |
| `intake`             | interactive | `document.scan`; classify legal vs not; record the defect inventory and the placeholder-to-question list. |
| `resolve`            | interactive | Fill tokens already approved in the library (`document.fill` with entries from CEL); for new ones, get the answer, `library.upsert`, then fill. De-scaffold and fix references. |
| `sendability-review` | dispatch    | A content-professional reviewer runs `document.check`; an open blocking finding sends the draft back to `resolve`. |
| `counsel`            | interactive | Legal documents only (CEL-gated on `intake.legal`). When no counsel is engaged, a person records a deferred waiver and the document proceeds counsel-pending. |
| `approve`            | interactive | A person approves for sending, or sends it back with recorded feedback.     |
| `render`             | interactive | `document.render` to PDF/DOCX; record the output path.                       |
| `done`               | terminal    |                                                                             |

## The content-professional reviewer

`sendability-review` is a dispatch stage whose prompt carries a
content-professional reviewer's lens -- the person who curates an answer library
and signs off that a document is fit to send. It is NOT a copy editor. On top of
the mechanical `document.check` result it judges: nothing unfinished ships; one
consistent voice that matches the library; reader-facing titles, not internal
names; and that the document claims nothing the organization cannot stand
behind. Findings are critical/high only when sending as-is would be wrong,
harmful, or unfinished; voice and wording are medium at most.

This gate is a SEAM a human can occupy later: once there is a GUI around
content-studio, a human content professional reviews here instead of the agent
persona. The same persona can augment a publish factory when it reviews
content-bearing public artifacts (READMEs, descriptions, docs).

## The counsel gate

Legal documents cannot skip counsel; non-legal documents skip straight to
approval (CEL on `intake.legal`). When no counsel is engaged, the gate does not
park the document indefinitely: a person records a deferred internal-review
waiver (`counsel-waiver` evidence) and the document proceeds flagged
counsel-pending, re-openable when counsel lands. This is a deliberate
deferred-waiver, not an absence of a gate.

## Instantiate and drive it

1. Create your library and document instances (the document's `path`, its bound
   `libraries`, any `requiredDisclaimers`). Seed the library's entries with
   `library.upsert` (confirm=true) -- this instance data is LOCAL and never
   ships with the template.
2. Copy `examples/content-review-pipeline.yaml`, replace `<library>` and
   `<document>` with your instance names, and adapt the stage prompts (the
   reviewer voice, the counsel CEL, the render format).
3. Validate the adapted definition with the stagecraft validate path --
   `swamp behavior run <factory> validate` (NOT `swamp workflow validate`) --
   which checks the stage graph, gates, transitions, and the saved scenarios.
4. Start a work item per document and drive it stage by stage, stopping at every
   human gate (`send-approval`, the counsel waiver, `abandon-confirmation`).

Note on what `validate` proves: it covers the stage graph, gates, transitions,
and scenarios. It does NOT resolve the runtime `data.latest(<library>,
"entries")` method-arg wiring -- a generic template has no bound instance, and
stagecraft stages dispatch agents rather than declaratively wiring method args.
That cross-type wiring is covered by the document unit tests (library entries
injected as the `entries` argument) and by a runtime run, not by `validate`.
