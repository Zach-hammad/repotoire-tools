# Run the checker

From a Git repository whose documentation you want to inspect:

```sh
repotoire docs-truth --format markdown .
repotoire docs-truth --format json --out .repotoire/docs-truth.json .
repotoire docs-truth --format collection-json .
```

A Markdown contract can be checked when `serve` has a supported literal return such as `return 'ok';`:

```markdown
Repotoire contract: `src/service.ts#serve` returns `'ok'`.
```

A matching check may verify that narrow claim. Other prose remains unverified. Explicit return contracts expose missing targets, conflicting returns, changed code, dirty files, and unavailable Git history with the appropriate uncertainty or contradiction. A generic inline reference alone does not prove a claim or guarantee a top-level missing-target diagnostic. Raw HTML is opaque to the Markdown intent parser and produces a diagnostic. The collection view lists selected documents as unverified review inputs and enforces bounded output.

Markdown files are discovered under the given root, subject to Git and `.repotoireignore` rules. `.repotoire-sources.toml` can declare exact document files and formats. Excluded documents and unsupported formats remain visible in diagnostics. The checker rejects paths outside the repository or through disallowed symlinks rather than treating them as code proof.

`--coverage-input`, `--witness-run`, and `--witness-state` are unavailable in this package and return exit status 2. Malformed usage returns 64; a report or output error returns 2; a collection limit returns 78. A successful report returns 0 even when it contains drifts: consumers must inspect the report's scorecard, diagnostics, and claim statuses. Plain `--version` and `-V` print the package version. The original full-product `--version --format json` runtime identity is outside this slice.
