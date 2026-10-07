# Organized Chaos v2

This package contains the [skill instructions](SKILL.md), supporting references, Python adapters, and synthetic offline tests. It coordinates bounded agent work; installing it does not connect a model account or grant tool access.

## Install

1. Obtain `organized-chaos-v2.zip` and its digest from [SHA256SUMS](https://github.com/Zach-hammad/repotoire-tools/blob/main/SHA256SUMS) at the same source revision. Trust the maintainer channel or commit through which you obtain them; an untrusted ZIP and checksum cannot authenticate each other. Compare the downloaded file with that digest, then inspect and extract it. The archive contains one `organized-chaos/` directory.
2. Read [SKILL.md](SKILL.md) and [onboarding](references/onboarding.md). Check that your agent supports skills and identify its skills directory from that agent's own instructions.
3. Copy the extracted `organized-chaos/` directory into that skills directory. Keep `~/.config/organized-chaos/` and any other personal inventory, observation, credential, receipt, or backup outside the installed skill.
4. Run the [offline example](examples/offline.md). Configure and verify selected model access separately before dispatching a real task.

Python 3 is needed for the adapters and tests. Local verification used macOS and Python 3.14.7; Linux and Windows behavior has not been established by that result. Provider access, a Jev gateway, and model selection remain separately configured.

## Upgrade or recover

Preserve the currently installed skill directory as a local backup. Verify the new archive's trusted digest, inspect its contents, and replace only the installed `organized-chaos/` directory. Do not overwrite the private configuration directory or copy its contents into the package. Re-run the offline suite and fresh access checks before using the upgraded skill. If the new version fails, restore the prior skill directory and retain the private configuration.

The `source-manifest.json` delivered beside the ZIP by the release builder records SHA-256 hashes of every source file. The ZIP digest must be distributed through a trusted release channel because an untrusted manifest beside an untrusted ZIP cannot authenticate either artifact.

## Build from the repository layout

From any working directory, use the Python packager with an absolute or relative `--root` if needed:

```sh
python3 -B /path/to/repotoire-tools/skill-packaging/package-organized-chaos.py --check --test
```

The default package root is the `organized-chaos/` sibling of `skill-packaging/`. In the original web monorepo, pass `--root /path/to/repo/apps/repotoire-web/public/skills/organized-chaos/v2` when using this packager at a different script location. `--write` explicitly regenerates the manifest and ZIP; review source changes before using it. Packaging is local and does not contact provider services.

This source snapshot is maintained by Zacharia Hammad for [Zach-hammad/repotoire-tools](https://github.com/Zach-hammad/repotoire-tools). Its first-party files are licensed under [Apache-2.0](LICENSE); see [NOTICE](NOTICE). Read [security boundaries and private reporting](SECURITY.md) and [contribution notes](CONTRIBUTING.md) before redistributing changes.
