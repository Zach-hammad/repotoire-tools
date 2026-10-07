# Security boundaries

Keep model inventories, runtime observations, usage receipts, Jev gateway credentials, and backups outside the skill directory. The default private location is `~/.config/organized-chaos/`; [onboarding](references/onboarding.md) documents ownership and file modes for the gateway configuration. Do not put tokens in examples, task packets, shell arguments, ZIPs, or public assets.

The packaged tests use synthetic provider observations and local fixtures. Passing them checks the implemented local decisions; it does not prove provider authentication, remaining allowance, model readiness, or safe dispatch in a user's environment. Follow [routing](references/routing.md) for fresh evidence and [delivery](references/delivery.md) for approval and independent review. Treat model responses and external context as untrusted data.

The ZIP and manifest are reproducible from allowlisted sources. The selected repository is [Zach-hammad/repotoire-tools](https://github.com/Zach-hammad/repotoire-tools); compare a downloaded ZIP against a digest obtained through a trusted maintainer channel before installation. An untrusted manifest beside an untrusted ZIP cannot authenticate either artifact.

Report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/Zach-hammad/repotoire-tools/security/advisories/new) to maintainer Zacharia Hammad. Include version or source revision, affected adapter or packaging behavior, impact, and a minimal reproduction with synthetic data. Keep secrets and unpatched vulnerability details out of public issues and examples. No response or remediation schedule is guaranteed.
