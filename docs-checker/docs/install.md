# Build and install locally

This source build needs Git, Rustup with Rust 1.97.1 (pinned in `rust-toolchain.toml`), and Cargo. macOS arm64 is the tested platform. From a public checkout, build and print the version:

```sh
git clone https://github.com/Zach-hammad/repotoire-tools.git
cd repotoire-tools/docs-checker
cargo build --locked --release -p repotoire-cli
./target/release/repotoire --version
```

The first build may download the locked crates. It needs network access if those crates are not already cached; an online cold build has not been qualified here. For a repeat build with every dependency cached, `cargo build --offline --locked --release -p repotoire-cli` prevents network access. The executable is `target/release/repotoire`; use that path for the [first demo](examples.md#first-result-matching-stale-and-unverified). Use this package-local binary alongside any existing RepoToire installation; leave other executables and `PATH` unchanged.

Run `cargo test --offline --locked -p repotoire-cli` and `cargo test --offline --locked -p repotoire --test markdown_html_contracts` after dependencies are cached to verify the focused contracts. The `--offline` form fails if a locked crate is missing.

The package uses a patched `ignore` 0.4.26 under `vendor/ignore`. Build from this root so Cargo applies the root `[patch.crates-io]` entry. Do not replace the vendored walker with an unpatched release: its ignored-entry and policy-input observations are part of the report's admission proof.

The checker version is `0.1.0-beta.10`. These instructions build from the source snapshot; they do not require hosted binaries. Installation and upgrading are manual: replace the local executable with a newly verified build after reviewing the source and dependency changes. There is no automatic updater.
