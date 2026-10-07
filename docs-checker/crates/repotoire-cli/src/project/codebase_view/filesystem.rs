use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

use serde_json::json;

use super::{DirectoryIdentity, FilesystemErrorKind, PathEvidence, TaskCodebaseView};

static NEXT_STAGING_DIRECTORY: AtomicU64 = AtomicU64::new(0);

impl TaskCodebaseView {
    /// Write this already-selected task view as disposable agent-readable files.
    ///
    /// Selection belongs to `CodebaseView::task_view`; this writer never reads
    /// the repository graph or changes which source files are present.
    pub(crate) fn write_to_filesystem(&self, output: &Path) -> io::Result<()> {
        publish_projection(
            &self.origin_root,
            &self.origin_identity,
            output,
            |staging| self.write_projection(staging),
        )
    }

    fn write_projection(&self, output: &cap_std::fs::Dir) -> io::Result<()> {
        for (path, bytes) in &self.sources {
            let relative = crate::repository_path::relative(path)?;
            let projected_source = Path::new("source").join(relative);
            let parent = projected_source
                .parent()
                .expect("a repository-relative source path has a parent");
            output.create_dir_all(parent)?;
            output.write(projected_source, bytes)?;
        }

        let relationships = self
            .relationships
            .iter()
            .map(|relationship| {
                json!({
                    "kind": relationship.kind,
                    "source_name": relationship.source_name,
                    "source_file": relationship.source_file,
                    "target_name": relationship.target_name,
                    "target_file": relationship.target_file,
                })
            })
            .collect::<Vec<_>>();
        let manifest = json!({
            "target": {
                "file": self.target_file,
                "symbol": self.target_symbol,
                "line": self.target_line,
                "state": target_state_name(self.target_state),
                "filesystem_error": target_state_error(self.target_state),
            },
            "sources": self.sources.keys().collect::<Vec<_>>(),
            "relationships": relationships,
            "relationship_summary": {
                "returned": self.relationships.len(),
                "omitted": self.omitted_relationship_count,
            },
            "limitations": self.limitations.iter().map(limitation_json).collect::<Vec<_>>(),
            "diagnostics": self.diagnostics,
        });
        let manifest = serde_json::to_vec(&manifest).map_err(io::Error::other)?;
        output.write("VIEW.json", manifest)
    }
}

fn limitation_json(limitation: &repotoire::impact::evidence::Limitation) -> serde_json::Value {
    use repotoire::impact::evidence::Limitation;

    match limitation {
        Limitation::ExternalConsumers => json!({"kind": "external_consumers"}),
        Limitation::MemberDispatch => json!({"kind": "member_dispatch"}),
        Limitation::Dynamic => json!({"kind": "dynamic"}),
        Limitation::UnresolvedBindings => json!({"kind": "unresolved_bindings"}),
        Limitation::TsxNotScanned => json!({"kind": "tsx_not_scanned"}),
        Limitation::RestrictedReadScope => json!({"kind": "restricted_read_scope"}),
        Limitation::ProvenanceUnavailable { family } => {
            json!({"kind": "provenance_unavailable", "family": family})
        }
        Limitation::Diagnostics { count } => json!({
            "kind": "diagnostics",
            "count": count,
        }),
    }
}

struct ProjectionDestination {
    parent: cap_std::fs::Dir,
    parent_path: PathBuf,
    parent_identity: DirectoryIdentity,
    file_name: OsString,
}

fn projection_destination(
    repository_root: &Path,
    repository_identity: &DirectoryIdentity,
    output: &Path,
) -> io::Result<ProjectionDestination> {
    if !repository_identity.still_names(repository_root)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the codebase view origin changed; read a fresh view before projection",
        ));
    }
    let file_name = output.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "projection output must name a new directory: {}",
                output.display()
            ),
        )
    })?;
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = parent.canonicalize()?;
    let parent_identity = DirectoryIdentity::capture(&canonical_parent)?;
    let parent =
        cap_std::fs::Dir::open_ambient_dir(&canonical_parent, cap_std::ambient_authority())?;
    if directory_is_within(&parent, repository_identity)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "projection output must be outside the repository: {}",
                output.display()
            ),
        ));
    }

    Ok(ProjectionDestination {
        parent,
        parent_path: canonical_parent,
        parent_identity,
        file_name: file_name.to_os_string(),
    })
}

fn publish_projection(
    repository_root: &Path,
    repository_identity: &DirectoryIdentity,
    output: &Path,
    write: impl FnOnce(&cap_std::fs::Dir) -> io::Result<()>,
) -> io::Result<()> {
    let destination = projection_destination(repository_root, repository_identity, output)?;
    let (staging_name, staging) = create_staging_directory(&destination.parent)?;

    if let Err(error) = write(&staging) {
        return match destination.parent.remove_dir_all(&staging_name) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(io::Error::new(
                error.kind(),
                format!(
                    "{error}; also failed to remove incomplete projection staging directory: {cleanup_error}"
                ),
            )),
        };
    }

    if let Err(error) = require_unchanged_directory(
        repository_identity,
        repository_root,
        "the codebase view origin changed; read a fresh view before projection",
    ) {
        return discard_staging(&destination.parent, Path::new(&staging_name), error);
    }
    if let Err(error) = require_unchanged_directory(
        &destination.parent_identity,
        &destination.parent_path,
        "the projection parent changed during construction",
    ) {
        return discard_staging(&destination.parent, Path::new(&staging_name), error);
    }

    if let Err(error) = rename_directory_noreplace(
        &destination.parent,
        Path::new(&staging_name),
        Path::new(&destination.file_name),
    ) {
        return match destination.parent.remove_dir_all(&staging_name) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(io::Error::new(
                error.kind(),
                format!(
                    "{error}; also failed to remove complete unpublished projection {}: {cleanup_error}",
                    staging_name.to_string_lossy()
                ),
            )),
        };
    }
    Ok(())
}

fn create_staging_directory(parent: &cap_std::fs::Dir) -> io::Result<(OsString, cap_std::fs::Dir)> {
    for _ in 0..100 {
        let sequence = NEXT_STAGING_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let name = OsString::from(format!(
            ".repotoire-task-view-{}-{sequence}",
            std::process::id()
        ));
        match parent.create_dir(&name) {
            Ok(()) => match parent.open_dir(&name) {
                Ok(staging) => return Ok((name, staging)),
                Err(error) => return discard_staging(parent, Path::new(&name), error),
            },
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a projection staging directory",
    ))
}

fn require_unchanged_directory(
    identity: &DirectoryIdentity,
    path: &Path,
    changed_message: &'static str,
) -> io::Result<()> {
    match identity.still_names(path) {
        Ok(true) => Ok(()),
        Ok(false) => Err(io::Error::new(io::ErrorKind::InvalidInput, changed_message)),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("{changed_message}: {error}"),
        )),
    }
}

fn discard_staging<T>(
    parent: &cap_std::fs::Dir,
    staging_name: &Path,
    error: io::Error,
) -> io::Result<T> {
    match parent.remove_dir_all(staging_name) {
        Ok(()) => Err(error),
        Err(cleanup_error) => Err(io::Error::new(
            error.kind(),
            format!("{error}; also failed to remove projection staging directory: {cleanup_error}"),
        )),
    }
}

#[cfg(unix)]
fn directory_is_within(
    parent: &cap_std::fs::Dir,
    repository: &DirectoryIdentity,
) -> io::Result<bool> {
    use std::fs::File;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd};

    fn identity(file: &File) -> io::Result<(u64, u64)> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `stat` points to writable storage and `file` owns a valid fd.
        if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful fstat initialized the complete structure.
        let stat = unsafe { stat.assume_init() };
        Ok((stat.st_dev as u64, stat.st_ino as u64))
    }

    // SAFETY: fcntl duplicates a valid directory fd. `File` owns the returned
    // descriptor and closes it exactly once.
    let duplicate = unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut current = unsafe { File::from_raw_fd(duplicate) };

    loop {
        let current_identity = identity(&current)?;
        if current_identity == (repository.device, repository.inode) {
            return Ok(true);
        }

        let dotdot = b"..\0";
        // SAFETY: the path is a fixed null-terminated string and the returned
        // fd, when nonnegative, is uniquely transferred to `File`.
        let ancestor_fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                dotdot.as_ptr().cast(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if ancestor_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let ancestor = unsafe { File::from_raw_fd(ancestor_fd) };
        if identity(&ancestor)? == current_identity {
            return Ok(false);
        }
        current = ancestor;
    }
}

#[cfg(not(unix))]
fn directory_is_within(
    _parent: &cap_std::fs::Dir,
    _repository: &DirectoryIdentity,
) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "handle-relative projection confinement is unsupported on this platform",
    ))
}

#[cfg(unix)]
fn path_c_string(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path contains a null byte: {}", path.display()),
        )
    })
}

#[cfg(target_vendor = "apple")]
fn rename_directory_noreplace(
    parent: &cap_std::fs::Dir,
    source: &Path,
    destination: &Path,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let source = path_c_string(source)?;
    let destination = path_c_string(destination)?;
    // SAFETY: both pointers remain valid, null-terminated path strings for the
    // duration of this call. RENAME_EXCL makes absence and rename one operation.
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn rename_directory_noreplace(
    parent: &cap_std::fs::Dir,
    source: &Path,
    destination: &Path,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let source = path_c_string(source)?;
    let destination = path_c_string(destination)?;
    // SAFETY: both pointers remain valid, null-terminated path strings for the
    // duration of this call. RENAME_NOREPLACE makes absence and rename atomic.
    let result = unsafe {
        libc::renameat2(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn rename_directory_noreplace(
    _parent: &cap_std::fs::Dir,
    _source: &Path,
    _destination: &Path,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "handle-relative no-replace projection publication is unsupported on Windows",
    ))
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    windows
)))]
fn rename_directory_noreplace(
    _parent: &cap_std::fs::Dir,
    _source: &Path,
    _destination: &Path,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace directory publication is unsupported on this platform",
    ))
}

fn target_state_name(state: PathEvidence) -> &'static str {
    match state {
        PathEvidence::Absent => "absent",
        PathEvidence::RegularFile => "regular_file",
        PathEvidence::Directory => "directory",
        PathEvidence::Symlink => "symlink",
        PathEvidence::Other => "other",
        PathEvidence::OutsideRoot => "outside_root",
        PathEvidence::Unreadable(_) => "unreadable",
    }
}

fn target_state_error(state: PathEvidence) -> Option<&'static str> {
    let PathEvidence::Unreadable(error) = state else {
        return None;
    };
    Some(match error {
        FilesystemErrorKind::NotFound => "not_found",
        FilesystemErrorKind::PermissionDenied => "permission_denied",
        FilesystemErrorKind::NotADirectory => "not_a_directory",
        FilesystemErrorKind::Other => "other",
    })
}
