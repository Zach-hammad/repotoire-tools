//! Content identity helpers for durable status, proof, checkpoint, and
//! writeback owners. Stateless context and impact views do not emit these
//! fingerprints; callers that persist evidence compute identity from the
//! source records they already own.
use crate::deadline::{ObservationScope, RequestDeadline};
use std::io;
use std::path::{Path, PathBuf};

const GIT_OBSERVATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const MAX_GIT_STATUS_BYTES: usize = 16 * 1024 * 1024;
const MAX_GIT_REF_BYTES: usize = 16 * 1024;

/// Deterministic 64-bit FNV-1a hash (hex) of arbitrary bytes.
pub fn bytes_hash(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV offset basis
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3); // FNV prime
    }
    format!("{h:016x}")
}

/// Deterministic 64-bit FNV-1a hash (hex) of a file's current bytes.
pub fn file_hash(path: &Path) -> io::Result<String> {
    std::fs::read(path).map(|bytes| bytes_hash(&bytes))
}

/// Deterministic 64-bit FNV-1a hash (hex) of the sorted `(path, bytes)` pairs
/// — a content fingerprint of the walked working tree. Deterministic across
/// runs and processes (unlike `std`'s `DefaultHasher`, which we avoid here so
/// the stamp is stable and self-documenting). Order-independent via an
/// internal sort, so it does not depend on walk order.
pub fn working_tree_hash(pairs: &[(String, Vec<u8>)]) -> String {
    working_tree_hash_iter(
        pairs
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice())),
    )
}

pub fn working_tree_hash_iter<'a, I>(files: I) -> String
where
    I: IntoIterator<Item = (&'a str, &'a [u8])>,
{
    let mut sorted: Vec<(&str, &[u8])> = files.into_iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV offset basis
    let mut mix = |bytes: &[u8]| {
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3); // FNV prime
        }
    };
    for (path, bytes) in sorted {
        mix(path.as_bytes());
        mix(&[0]); // path/content separator so (ab,c) != (a,bc)
        mix(bytes);
        mix(&[0]);
    }
    format!("{h:016x}")
}

/// Compute durable provenance from source bytes already captured by an owner.
/// This accepts plain source records, not a live-view object, so persistence
/// policy stays outside `CodebaseView`.
pub fn working_tree_hash_for_source_files(files: &[crate::project::SourceFileRef<'_>]) -> String {
    working_tree_hash_iter(files.iter().map(|file| (file.path, file.bytes)))
}

/// Fast source-content fingerprint for status/freshness paths that need the
/// same source-byte sensitivity as the durable provenance function above
/// without paying parser, resolver, or graph-construction cost.
pub fn source_working_tree_hash(root: &Path) -> io::Result<String> {
    let walked = crate::walk::walk_sources(root)?;
    Ok(working_tree_hash_iter(walked.files.iter().map(|file| {
        (file.rel_path.as_str(), file.bytes.as_slice())
    })))
}

/// Source-content fingerprint for live status paths. This hashes only files
/// that are architectural source bytes in the worktree; it deliberately avoids
/// resolver-only expansion such as tsconfig library files or dependency-module
/// closure discovery.
pub fn status_source_working_tree_hash(root: &Path) -> io::Result<String> {
    let files = crate::walk::walk_source_fingerprint_files(root)?;
    Ok(working_tree_hash_iter(
        files
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice())),
    ))
}

/// The HEAD commit SHA, or `None` if not a git repo / unresolvable.
/// Resolves the git dir without spawning a process when possible — handling
/// **worktrees and submodules**, where `.git` is a *file* (`gitdir: <path>`)
/// rather than a directory, and a worktree's branch refs live in the linked
/// repo's `commondir`. Falls back to `git rev-parse HEAD` for packed refs or
/// any layout we don't read directly.
pub fn git_sha(project_root: &Path) -> Option<String> {
    git_sha_until(project_root, ObservationScope::deadline_current()).ok()
}

/// Fallible HEAD observation for consumers that must retain request failures.
pub(crate) fn git_sha_until(root: &Path, deadline: RequestDeadline) -> io::Result<String> {
    ObservationScope::check_current("Git identity")?;
    deadline.check("Git identity")?;
    let sha = if let Some(sha) = git_sha_no_spawn(root, deadline) {
        sha
    } else {
        let bytes = observe_git(
            std::process::Command::new("git")
                .args(["rev-parse", "--verify", "HEAD"])
                .current_dir(root),
            MAX_GIT_REF_BYTES,
            deadline,
        )?;
        let sha = String::from_utf8(bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if sha.trim().is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty Git HEAD"));
        }
        sha.trim().to_string()
    };
    ObservationScope::check_current("Git identity")?;
    deadline.check("Git identity")?;
    Ok(sha)
}

fn read_git_ref(path: &Path, deadline: RequestDeadline) -> Option<String> {
    let bytes = crate::durable_io::read_bytes_bounded_until(
        path,
        MAX_GIT_REF_BYTES as u64,
        deadline,
        "Git ref read",
    )
    .ok()?;
    String::from_utf8(bytes).ok()
}

/// Tri-state comparison between the Repotoire build identity and the analyzed
/// project identity. Build scripts stamp a short SHA; git roots commonly
/// expose full SHAs, so clean prefix matches count as matches.
pub fn build_matches_project(
    build_git_sha: &str,
    build_dirty: &str,
    project_git_sha: Option<&str>,
) -> &'static str {
    let Some(project_git_sha) = project_git_sha else {
        return "unknown";
    };
    if project_git_sha.is_empty()
        || build_git_sha.is_empty()
        || build_git_sha == "unknown"
        || build_dirty != "false"
    {
        return "unknown";
    }
    if git_sha_matches(build_git_sha, project_git_sha) {
        "true"
    } else {
        "false"
    }
}

fn git_sha_matches(left: &str, right: &str) -> bool {
    left == right
        || (left.len() >= 7 && right.starts_with(left))
        || (right.len() >= 7 && left.starts_with(right))
}

fn git_sha_no_spawn(project_root: &Path, deadline: RequestDeadline) -> Option<String> {
    let git_dir = resolve_git_dir(project_root, deadline)?;
    let head = read_git_ref(&git_dir.join("HEAD"), deadline)?;
    let head = head.trim();
    if let Some(ref_rel) = head.strip_prefix("ref: ") {
        // Symbolic ref: the loose ref may live in this git dir OR, for a
        // worktree, in the linked repo's commondir.
        for base in git_ref_search_dirs(&git_dir, deadline) {
            if let Some(sha) = read_git_ref(&base.join(ref_rel), deadline) {
                let sha = sha.trim();
                if !sha.is_empty() {
                    return Some(sha.to_string());
                }
            }
        }
        return None; // packed ref or absent — let the caller spawn `git`.
    }
    // Detached HEAD (common after `git checkout <sha>`): the file *is* the SHA.
    if head.len() >= 7 && head.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some(head.to_string());
    }
    None
}

/// The real git directory for `project_root`. For a normal repo this is
/// `<root>/.git/`; for a worktree/submodule `.git` is a file containing
/// `gitdir: <path>` pointing at the linked git dir.
pub(crate) fn git_worktree_root_no_spawn(project_root: &Path) -> Option<PathBuf> {
    let canonical = project_root.canonicalize().ok()?;
    let start = if canonical.is_file() {
        canonical.parent()?.to_path_buf()
    } else {
        canonical
    };
    for candidate in start.ancestors() {
        let dot_git = candidate.join(".git");
        if std::fs::metadata(&dot_git).is_ok() {
            return Some(candidate.to_path_buf());
        }
    }
    None
}

fn resolve_git_dir(project_root: &Path, deadline: RequestDeadline) -> Option<PathBuf> {
    let worktree_root = git_worktree_root_no_spawn(project_root)?;
    let dot_git = worktree_root.join(".git");
    let md = std::fs::metadata(&dot_git).ok()?;
    if md.is_dir() {
        return Some(dot_git);
    }
    let content = read_git_ref(&dot_git, deadline)?;
    let rel = content.strip_prefix("gitdir:")?.trim();
    let gd = PathBuf::from(rel);
    Some(if gd.is_absolute() {
        gd
    } else {
        worktree_root.join(gd)
    })
}

/// Directories to search for a loose ref: the git dir itself, plus the
/// `commondir` (a worktree git dir holds branch refs in the linked repo).
fn git_ref_search_dirs(git_dir: &Path, deadline: RequestDeadline) -> Vec<std::path::PathBuf> {
    let mut dirs = vec![git_dir.to_path_buf()];
    if let Some(c) = read_git_ref(&git_dir.join("commondir"), deadline) {
        let cd = std::path::PathBuf::from(c.trim());
        dirs.push(if cd.is_absolute() {
            cd
        } else {
            git_dir.join(cd)
        });
    }
    dirs
}

/// Observe tracked changes and untracked source files supported by this build.
/// Untracked non-source files are intentionally ignored. An unavailable Git
/// observation is an error, never a successful clean result.
pub fn working_tree_dirty(root: &Path) -> io::Result<bool> {
    working_tree_dirty_matching(root, ObservationScope::deadline_current(), |path| {
        repotoire::source_pipeline::parser_supports_source_language(
            repotoire::source_pipeline::source_language_for_path(path),
        )
    })
}

/// Share status mechanics while callers retain their untracked-file policy.
/// NUL framing preserves literal paths; `all` expands untracked directories
/// and overrides a user configuration that hides untracked files.
pub(crate) fn working_tree_dirty_matching(
    root: &Path,
    deadline: RequestDeadline,
    include_untracked: impl Fn(&Path) -> bool,
) -> io::Result<bool> {
    let stdout = observe_git(
        std::process::Command::new("git")
            .args(["status", "--porcelain", "-z", "--untracked-files=all"])
            .env("GIT_OPTIONAL_LOCKS", "0")
            .current_dir(root),
        MAX_GIT_STATUS_BYTES,
        deadline,
    )?;
    let dirty = stdout.split(|&byte| byte == 0).any(|record| {
        if record.is_empty() {
            return false;
        }
        let record = String::from_utf8_lossy(record);
        if let Some(path) = record.strip_prefix("?? ") {
            include_untracked(Path::new(path))
        } else {
            true
        }
    });
    ObservationScope::check_current("Git status parse")?;
    deadline.check("Git status parse")?;
    Ok(dirty)
}

/// Git semantics sit here; worker_runtime retains process-tree retirement,
/// cancellation and aggregate output capture. Partial/failed output is unusable.
fn observe_git(
    command: &mut std::process::Command,
    max_output_bytes: usize,
    deadline: RequestDeadline,
) -> io::Result<Vec<u8>> {
    use crate::worker_runtime::BoundedProcessTermination;
    let timeout = deadline.subprocess_timeout("Git observation", GIT_OBSERVATION_TIMEOUT)?;
    let output = crate::worker_runtime::run_bounded_command(command, max_output_bytes, timeout)?;
    ObservationScope::check_current("Git observation")?;
    deadline.check("Git observation")?;
    match output.termination {
        BoundedProcessTermination::TimedOut => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Git observation timed out",
        )),
        BoundedProcessTermination::Cancelled => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "Git observation cancelled",
        )),
        BoundedProcessTermination::OutputLimit => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Git observation exceeded output limit",
        )),
        BoundedProcessTermination::Exited if output.status.success() => Ok(output.stdout),
        BoundedProcessTermination::Exited => Err(io::Error::other(format!(
            "Git observation failed: {}",
            output.status
        ))),
    }
}
