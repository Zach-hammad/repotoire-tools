# Repotoire tools

This source snapshot contains two focused tools maintained by Zacharia Hammad for [Zach-hammad/repotoire-tools](https://github.com/Zach-hammad/repotoire-tools):

- [Docs-truth checker](docs-checker/README.md), version `0.1.0-beta.10`: builds the existing `repotoire docs-truth` command. It parses TypeScript/JavaScript and Rust source evidence; literal-return contracts are checked for `.ts` and `.tsx` files only. A report with zero drifts does not verify every statement.
- [Organized Chaos v2](organized-chaos/README.md): a portable skill for bounded delegation, proposal approval, independent review, and ordered acceptance. Installation does not connect model accounts or grant tool access.

For the checker, follow the [first build](docs-checker/docs/install.md) and then try the [three-result demo](docs-checker/docs/examples.md#first-result-matching-stale-and-unverified). For the skill in Codex CLI on macOS, use the steps below. The ZIP and its digest should come from a source revision you trust; a checksum stored beside an untrusted ZIP does not authenticate it.

```sh
(
  set -eu
  git clone https://github.com/Zach-hammad/repotoire-tools.git
  cd repotoire-tools
  git rev-parse HEAD
  shasum -a 256 -c SHA256SUMS
  unzip -l organized-chaos/organized-chaos-v2.zip
  mkdir -p "$HOME/.agents/skills"
  if [ -e "$HOME/.agents/skills/organized-chaos" ] || [ -L "$HOME/.agents/skills/organized-chaos" ]; then
    printf '%s\n' 'organized-chaos already exists; follow the upgrade guide' >&2
    exit 1
  fi
  unzip -q organized-chaos/organized-chaos-v2.zip -d "$HOME/.agents/skills"
  test -f "$HOME/.agents/skills/organized-chaos/SKILL.md"
)
```

If the destination already exists, follow the [upgrade guide](organized-chaos/README.md#upgrade-or-recover) instead of overwriting it. Start a new `codex` session, run `/skills` to find `organized-chaos`, then try this harmless task in a disposable directory:

```sh
demo_dir=$(mktemp -d)
cd "$demo_dir"
git init -q
codex
```

In Codex, enter:

> $organized-chaos Create `greeting.txt` containing `hello` in this disposable repository. First show the scope and checks. Have a writer propose the exact edit before approval, then check the result and get an independent review before acceptance. If the required model access is unavailable, report the pending step and stop.

[Codex's skill guide](https://developers.openai.com/codex/skills) documents the personal skill location, `/skills`, and explicit `$` invocation. The [offline skill example](organized-chaos/examples/offline.md) checks local workflow logic; it does not prove live model access or this host journey.

The checker was built and tested on macOS arm64 with Rust 1.97.1 and an existing Cargo registry cache. The skill's packaging and extracted synthetic tests were verified on macOS with Python 3.14.7. An online cold build, fresh Codex discovery, a live skill task, and other platforms remain unqualified.

First-party source and documentation are licensed under [Apache-2.0](LICENSE); see [NOTICE](NOTICE). The bundled `ignore` dependency retains its own MIT/Unlicense terms and upstream notices in `docs-checker/vendor/ignore/`. Other dependencies retain their own terms; exact Rust versions are recorded in `docs-checker/Cargo.lock`.

Changes use [bounded issue or patch proposals](CONTRIBUTING.md), maintainer integration on `main`, local checks, and manual releases. There is no automatic CI or updater. Share optional, sanitized beta feedback through the [beta issue form](https://github.com/Zach-hammad/repotoire-tools/issues/new?template=beta-feedback.yml). Report vulnerabilities through the [private reporting channel](SECURITY.md).
