# Run the checker

## First result: matching, stale, and unverified

After the [build](install.md), run this from `repotoire-tools/docs-checker/`. It creates a disposable Git repository so the matching contract has committed source and documentation. The expected results come from the literal TypeScript return shown below, not from the checker's own output.

```sh
checker="$PWD/target/release/repotoire"
demo_dir=$(mktemp -d)
mkdir -p "$demo_dir/project/src"
cd "$demo_dir/project"
git init -q
printf "export function serve() { return 'ok'; }\n" > src/service.ts
printf "# API\n\nRepotoire contract: \`src/service.ts#serve\` returns \`'ok'\`.\n" > README.md
git add README.md src/service.ts
git -c user.name=Demo -c user.email=demo@example.invalid -c commit.gpgsign=false commit -qm baseline
"$checker" docs-truth --format json . > "$demo_dir/matching.json"
printf "export function serve() { return 'changed'; }\n" > src/service.ts
"$checker" docs-truth --format json . > "$demo_dir/stale.json"
printf "# Guide\n\nThis service is secure, fast, and always available.\n" > README.md
"$checker" docs-truth --format json . > "$demo_dir/unverified.json"
```

Open the three JSON files outside `project/` and compare these fields:

| Report | Independently expected result |
| --- | --- |
| `matching.json` | `scorecard.return_contracts` is 1, `scorecard.drifts` is 0, and `consumer_view.verification_statuses` has a claim-ID key with value `verified`. The committed `serve` function returns `'ok'`. |
| `stale.json` | `scorecard.drifts` is 1; `drifts[0].kind` is `return_contract_mismatch`; the claim-ID value in `consumer_view.verification_statuses` is `contradicted`. The edited function returns `'changed'`. |
| `unverified.json` | `scorecard.return_contracts` is 0, `scorecard.drifts` is 0, and `consumer_view.reason_codes` includes `unsupported_syntax`. The prose has no supported literal-return contract. |

These are narrow outcomes. The checker currently verifies literal-return contracts only for `.ts` and `.tsx` targets. It can parse JavaScript and Rust structurally, but a `.js` or `.rs` return claim remains unverified. Python paths and ordinary prose are also not certified. Missing Git history may leave even a matching return claim unknown; keep the demo's commit step. Exit status 0 means a report was produced, including when it contains drift or unknowns. Inspect the scorecard, drifts, and claim statuses before deciding what to do.

## Run on your repository

From a Git repository whose documentation you want to inspect:

```sh
repotoire docs-truth --format markdown .
repotoire docs-truth --format json --out .repotoire/docs-truth.json .
repotoire docs-truth --format collection-json .
```

The default output is Markdown. A Markdown contract can be checked when a TypeScript or TSX function has a supported literal return such as `return 'ok';`:

```markdown
Repotoire contract: `src/service.ts#serve` returns `'ok'`.
```

A matching check may verify that narrow claim. Other prose remains unverified. Explicit return contracts expose missing targets, conflicting returns, changed code, dirty files, and unavailable Git history with the appropriate uncertainty or contradiction. A generic inline reference alone does not prove a claim or guarantee a top-level missing-target diagnostic. Raw HTML is opaque to the Markdown intent parser and produces a diagnostic. The collection view lists selected documents as unverified review inputs and enforces bounded output.

Markdown files are discovered under the given root, subject to Git and `.repotoireignore` rules. `.repotoire-sources.toml` can declare exact document files and formats. Excluded documents and unsupported formats remain visible in diagnostics. The checker rejects paths outside the repository or through disallowed symlinks rather than treating them as code proof.

`--coverage-input`, `--witness-run`, and `--witness-state` are unavailable in this package and return exit status 2. Malformed usage returns 64; a report or output error returns 2; a collection limit returns 78. A successful report returns 0 even when it contains drifts: consumers must inspect the report's scorecard, diagnostics, and claim statuses. Plain `--version` and `-V` print the package version. The original full-product `--version --format json` runtime identity is outside this slice.

Share optional, sanitized results through the [beta feedback form](https://github.com/Zach-hammad/repotoire-tools/issues/new?template=beta-feedback.yml). Use the [private security channel](../SECURITY.md) for vulnerability details.
