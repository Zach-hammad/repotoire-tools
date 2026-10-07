# RepoToire downstream patch

Source: crates.io `ignore` 0.4.26, archive SHA-256
`b915661dd01db3f05050265b2477bcc6527b3792388e2749b41623cc592be67d`.

Downstream delta: the serial `Walk` can receive an optional ignored-entry
observer from `Walk::observe_ignored`. The callback receives the rejected
path, directory flag, and the authoritative winning `gitignore::Glob` selected
by the existing matcher. `dir.rs` exposes that glob only within this crate.
Parallel walks deliberately do not invoke the observer. No matching order,
filter, or traversal behavior is changed.

Directory-local ignore loading also retains metadata, open, and read failures
on present policy files. Missing optional policy files and `NotFound` races
remain normal absence. The matcher, precedence, and Windows no-prestat path are
unchanged.

An optional `WalkBuilder::observe_policy_inputs` sink records exact bytes read
from ignore files and global Git configuration inputs, plus absent optional
ignore candidates. Repeated observations of one path that disagree are marked
as changed during capture. The default walker path has no observation sink and
keeps the existing matching behavior.
