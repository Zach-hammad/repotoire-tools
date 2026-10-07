# Contributing to this source package

Start with a bounded [issue or patch proposal](https://github.com/Zach-hammad/repotoire-tools/issues): intended behavior, owned paths, dependency changes, compatibility impact, and checks. Zacharia Hammad owns integration into primary `main`. Changes use local verification and manual releases; there is no automatic CI requirement.

Keep changes within the existing checker owners: `crates/repotoire-cli/src/docs_truth.rs` for report construction, `crates/repotoire/src/docs.rs` for claim/history assessment, and `crates/repotoire/src/markdown.rs` for Markdown intent parsing. Do not add a second graph loader or report engine. Include tests that exercise the production path, especially uncertain or failed observations. Run the focused offline locked checks in [installation](docs/install.md) before proposing integration. Changes to output fields, claim status, admitted source paths, or Git observation require explicit compatibility review.

Submit only material you have the right to contribute. Unless explicitly stated otherwise, contributions intentionally submitted for inclusion are under Apache-2.0 as described in [LICENSE](LICENSE), section 5. Preserve attribution and the vendored dependency's terms and notices. Report security defects through the [private reporting channel](SECURITY.md).
