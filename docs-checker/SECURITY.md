# Security scope

The checker reads untrusted repository files. Its source admission, ignore-policy observations, bounded collection, regular-file checks, bounded Git subprocesses, and snapshot rechecks are part of the security boundary. Keep failure and uncertainty visible; do not silently skip unreadable inputs or promote an unverified claim.

Report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/Zach-hammad/repotoire-tools/security/advisories/new) to maintainer Zacharia Hammad. Include version or source revision, affected behavior, impact, and a minimal reproduction with synthetic files. Keep tokens, private repository contents, and unpatched exploit details out of public issues. No response or remediation schedule is guaranteed. The standalone package has no provider credentials, network service, or automatic update path.
