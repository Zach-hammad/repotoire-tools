# Contribution notes

Changes should start with a bounded proposal: intended behavior, owned paths, dependency changes, and checks. Keep the [skill contract](SKILL.md) and its references coherent. A writer implements only an approved scope; a fresh reviewer using a different model reviews the fixed result, and the coordinator checks findings against source before acceptance. The [delivery procedure](references/delivery.md) describes this sequence.

For package edits, keep personal configuration and credentials outside this directory. Run the packager's focused checks and the extracted synthetic suite, then record exact commands, results, source hashes, and any unavailable checks. Regenerate the manifest and ZIP only after source review. Acceptance, repository integration, and publication are separate owner decisions.

Submit bounded [issues or patch proposals](https://github.com/Zach-hammad/repotoire-tools/issues). Zacharia Hammad owns integration into primary `main`. Changes use local verification and manual releases; there is no automatic CI requirement.

Submit only material you have the right to contribute. Unless explicitly stated otherwise, contributions intentionally submitted for inclusion are under Apache-2.0 as described in [LICENSE](LICENSE), section 5. Preserve attribution and use the [private reporting channel](SECURITY.md) for security defects.
