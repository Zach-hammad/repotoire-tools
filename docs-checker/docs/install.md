# Build and install locally

Use Rust 1.97.1, as pinned in `rust-toolchain.toml`. In [Zach-hammad/repotoire-tools](https://github.com/Zach-hammad/repotoire-tools), change into the `docs-checker/` package root. With dependencies already cached, run:

```sh
cargo build --offline --locked --release -p repotoire-cli
./target/release/repotoire --version
```

The executable is `target/release/repotoire`. Copy that executable into a directory on your `PATH` if you want a local install. Run `cargo test --offline --locked -p repotoire-cli` and `cargo test --offline --locked -p repotoire --test markdown_html_contracts` to verify the focused checker contracts. The `--offline` form requires the locked crates to be present locally; an unavailable crate is a build failure.

The package uses a patched `ignore` 0.4.26 under `vendor/ignore`. Build from this root so Cargo applies the root `[patch.crates-io]` entry. Do not replace the vendored walker with an unpatched release: its ignored-entry and policy-input observations are part of the report's admission proof.

The checker version is `0.1.0-beta.10`. These instructions build from the source snapshot; they do not require hosted binaries. Installation and upgrading are manual: replace the local executable with a newly verified build after reviewing the source and dependency changes. There is no automatic updater.
