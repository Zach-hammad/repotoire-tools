# Repotoire tools

This source snapshot contains two focused tools maintained by Zacharia Hammad for [Zach-hammad/repotoire-tools](https://github.com/Zach-hammad/repotoire-tools):

- [Docs-truth checker](docs-checker/README.md), version `0.1.0-beta.10`: builds the existing `repotoire docs-truth` command for Markdown claims and supported TypeScript/JavaScript and Rust source evidence. A report with zero drifts does not verify every statement.
- [Organized Chaos v2](organized-chaos/README.md): a portable skill for bounded delegation, proposal approval, independent review, and ordered acceptance. Installation does not connect model accounts or grant tool access.

Build the checker from `docs-checker/` using its [installation guide](docs-checker/docs/install.md). Install the skill from the included `organized-chaos/organized-chaos-v2.zip` after verifying its digest through a trusted source; see the [offline first run](organized-chaos/examples/offline.md). Keep personal configuration and credentials outside this repository and installed skill.

The checker was built and tested on macOS with Rust 1.97.1. The skill's packaging and extracted synthetic tests were verified on macOS with Python 3.14.7. These checks establish local behavior within the documented component boundaries. They do not establish cross-platform support, provider readiness, or readiness of the full private RepoToire product.

First-party source and documentation are licensed under [Apache-2.0](LICENSE); see [NOTICE](NOTICE). The bundled `ignore` dependency retains its own MIT/Unlicense terms and upstream notices in `docs-checker/vendor/ignore/`. Other dependencies retain their own terms; exact Rust versions are recorded in `docs-checker/Cargo.lock`.

Changes use [bounded issue or patch proposals](CONTRIBUTING.md), maintainer integration on `main`, local checks, and manual releases. There is no automatic CI or updater. Report vulnerabilities through the [private reporting channel](SECURITY.md).
