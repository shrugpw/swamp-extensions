## 2026.11.19.1

**New:** First public release of `@shrug/content-studio`, a swamp-native toolkit
for keeping a body of documents sendable.

Two domain-agnostic behavior types. `library` is the canonical content hub: a
content-review professional's model of answers keyed by `key`, each carrying
value, scope, status, owner, review cadence, tags, the literal placeholder
`tokens` it satisfies, and provenance. Its methods are `lookup`, `upsert`
(gated write), `review` (approve / retire), and `audit` (flip entries past their
review cadence to `expiring`). `document` is a piece of content under review,
with `scan` (defect inventory, each placeholder mapped to a library key via its
tokens), `fill` (resolve placeholders from library entries passed in as a method
argument; dry-run-gated, writes only on `confirm=true`), `check` (the
sendability gate -- severity-rated findings if any bracket, draft marker, or
internal filename survives), and `render` (PDF / DOCX via an injectable pandoc
runner).

Ships a generic `content-review-pipeline` stagecraft factory template and a
`content-review` skill. The types carry no instance data; consumer values live
in local instance config only.
