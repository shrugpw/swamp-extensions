# Shrug Swamp Extensions

Shrug's `@shrug/*` extensions for
[swamp](https://github.com/swamp-club/swamp) -- behavior types, skills, and
templates published to the [swamp.club registry](https://swamp.club).

## Layout

Each extension lives in its own self-contained directory at the repo root,
holding its `manifest.yaml`, implementation files, tests, `deno.json`, a
`RELEASE_NOTES.md`, and its own `.swamp.yaml` repo marker. The directory is the
unit of versioning and publishing.

## Using an extension

The **registry**, not git, is the distribution channel. Pull an extension into
your own swamp setup with:

```bash
swamp extension pull @shrug/<name>
```

You do not clone this repo to consume an extension -- `swamp extension pull`
fetches the published, versioned artifact from the registry.

## Extensions

| Extension | Description |
|-----------|-------------|
| [`@shrug/content-studio`](content-studio/) | Keep a body of documents sendable: a reusable content hub (`library`) plus a sendability gate (`document`) that catches unresolved placeholders, draft scaffolding, and internal-filename leakage. |

## License

MIT, repo-wide -- `Copyright (c) 2026 Neil Hanlon`. See [LICENSE](LICENSE).
