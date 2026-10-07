# RepoToire docs-truth checker

This standalone source package builds the existing `repotoire docs-truth` command. It reads a repository's Markdown documents and current code view, reports supported literal-return mismatches and reference/history evidence, and leaves unchecked prose unverified. A report with zero drifts is a review input, not proof that every statement is correct.

The default output is Markdown. Use `--format json` for the `repotoire.docs_truth.v2` report or `--format collection-json` for bounded `repotoire.docs_collection.v1` document accounting. `--out PATH` writes the same report bytes to a file and also prints them. `docs_truth` remains an alias. The command uses real source graphs, Git history where available, and the repository's ignore rules. History that cannot be established remains unknown.

This slice parses TypeScript/JavaScript and Rust source. Python paths may be observed as paths but the optional Python parser is excluded, so Python claims cannot receive parser-backed verification here. Runtime Witness, native coverage receipts, Machine, MCP, provider processes, and other RepoToire commands are outside this package. Their flags fail explicitly. See [installation](docs/install.md) and [examples](docs/examples.md).

This source snapshot is maintained by Zacharia Hammad for [Zach-hammad/repotoire-tools](https://github.com/Zach-hammad/repotoire-tools). Its first-party files are licensed under [Apache-2.0](LICENSE); see [NOTICE](NOTICE). The patched `ignore` dependency retains its own terms and attribution; see [third-party notices](THIRD-PARTY-NOTICES.md). Follow the [contribution guidance](CONTRIBUTING.md) for changes and the [private reporting channel](SECURITY.md) for vulnerabilities.
