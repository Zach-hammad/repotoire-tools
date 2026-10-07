use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use cap_std::ambient_authority;
use cap_std::fs::Dir;

/// A semantic reader selects its input authority once. Captured reads never
/// consult the host, including existence probes and paths reached by `extends`.
#[derive(Clone, Copy)]
pub(crate) enum ReadOnlyFiles<'a> {
    Repository,
    Bounded(&'a BoundedRepositoryFiles),
    Captured {
        root: &'a Path,
        files: &'a std::collections::BTreeMap<String, Vec<u8>>,
    },
}

#[derive(Debug)]
pub(crate) struct RepositoryReadLimit(pub &'static str);

impl std::fmt::Display for RepositoryReadLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "repository input limit: {}", self.0)
    }
}

impl std::error::Error for RepositoryReadLimit {}

#[derive(Clone, Copy)]
pub(crate) struct RepositoryReadLimits {
    pub file_bytes: usize,
    pub total_bytes: usize,
    pub files: usize,
    pub operations: usize,
}

impl RepositoryReadLimits {
    pub(crate) const COLLECTION_METADATA: Self = Self {
        file_bytes: 4 * 1024 * 1024,
        total_bytes: 32 * 1024 * 1024,
        files: 10_000,
        operations: 100_000,
    };
}

#[derive(Default)]
struct BoundedReadState {
    inputs: BTreeMap<PathBuf, RepositoryInputObservation>,
    bytes: usize,
    operations: usize,
    exceeded: Option<&'static str>,
}

#[derive(Clone)]
enum RepositoryInputObservation {
    File,
    FileBytes(Arc<[u8]>),
    UnreadableFile(io::ErrorKind),
    Directory,
    Other,
    Unavailable(io::ErrorKind),
}

impl RepositoryInputObservation {
    fn is_file(&self) -> bool {
        matches!(
            self,
            Self::File | Self::FileBytes(_) | Self::UnreadableFile(_)
        )
    }
}

/// One capability and budget owns metadata reads throughout inventory,
/// parsing, and linking. Cached bytes count once; every probe or read counts
/// toward work. A limit remains fatal even when a parser ignores an IO error.
pub(crate) struct BoundedRepositoryFiles {
    root: PathBuf,
    directory: Dir,
    limits: RepositoryReadLimits,
    state: Mutex<BoundedReadState>,
}

impl BoundedRepositoryFiles {
    pub(crate) fn new(root: &Path, limits: RepositoryReadLimits) -> io::Result<Self> {
        let root = root.canonicalize()?;
        let directory = repository_dir(&root)?;
        Ok(Self {
            root,
            directory,
            limits,
            state: Mutex::new(BoundedReadState::default()),
        })
    }

    fn relative_path(&self, path: &Path) -> io::Result<PathBuf> {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                Component::ParentDir => {
                    if !normalized.pop() {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "input is outside repository",
                        ));
                    }
                }
                Component::CurDir => {}
                other => normalized.push(other.as_os_str()),
            }
        }
        normalized
            .strip_prefix(&self.root)
            .map(Path::to_path_buf)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "input is outside repository",
                )
            })
    }

    fn admit_operation(&self, state: &mut BoundedReadState) -> io::Result<()> {
        if state.operations >= self.limits.operations {
            state.exceeded.get_or_insert("metadata work");
        }
        if let Some(reason) = state.exceeded {
            return Err(io::Error::other(RepositoryReadLimit(reason)));
        }
        state.operations += 1;
        Ok(())
    }

    pub(crate) fn visit(&self) -> io::Result<()> {
        self.admit_operation(&mut self.state.lock().expect("bounded input mutex poisoned"))
    }

    pub(crate) fn check(&self) -> io::Result<()> {
        match self
            .state
            .lock()
            .expect("bounded input mutex poisoned")
            .exceeded
        {
            Some(reason) => Err(io::Error::other(RepositoryReadLimit(reason))),
            None => Ok(()),
        }
    }

    fn observe(&self, relative: &Path) -> RepositoryInputObservation {
        match self.directory.metadata(relative) {
            Ok(metadata) if metadata.is_file() => RepositoryInputObservation::File,
            Ok(metadata) if metadata.is_dir() => RepositoryInputObservation::Directory,
            Ok(_) => RepositoryInputObservation::Other,
            Err(error) => RepositoryInputObservation::Unavailable(error.kind()),
        }
    }

    fn captured_observation(
        &self,
        state: &mut BoundedReadState,
        relative: &Path,
    ) -> io::Result<RepositoryInputObservation> {
        if let Some(observation) = state.inputs.get(relative) {
            return Ok(observation.clone());
        }
        if state.inputs.len() >= self.limits.files {
            state.exceeded = Some("metadata file count");
            return Err(io::Error::other(RepositoryReadLimit("metadata file count")));
        }
        let observation = self.observe(relative);
        state
            .inputs
            .insert(relative.to_path_buf(), observation.clone());
        Ok(observation)
    }

    fn probe(&self, path: &Path) -> io::Result<RepositoryInputObservation> {
        let relative = self.relative_path(path)?;
        let mut state = self.state.lock().expect("bounded input mutex poisoned");
        self.admit_operation(&mut state)?;
        self.captured_observation(&mut state, &relative)
    }

    fn is_file(&self, path: &Path) -> bool {
        self.probe(path)
            .is_ok_and(|observation| observation.is_file())
    }

    pub(crate) fn read(&self, path: &Path) -> io::Result<Arc<[u8]>> {
        let relative = self.relative_path(path)?;
        let mut state = self.state.lock().expect("bounded input mutex poisoned");
        self.admit_operation(&mut state)?;
        match self.captured_observation(&mut state, &relative)? {
            RepositoryInputObservation::FileBytes(bytes) => return Ok(bytes),
            RepositoryInputObservation::UnreadableFile(kind)
            | RepositoryInputObservation::Unavailable(kind) => return Err(kind.into()),
            RepositoryInputObservation::Directory | RepositoryInputObservation::Other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "input is not a regular file",
                ));
            }
            RepositoryInputObservation::File => {}
        }
        let remaining = self.limits.total_bytes.saturating_sub(state.bytes);
        let maximum = self.limits.file_bytes.min(remaining);
        let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
        if let Err(error) = self
            .directory
            .open(&relative)
            .and_then(|file| file.take(maximum as u64 + 1).read_to_end(&mut bytes))
        {
            state.inputs.insert(
                relative,
                RepositoryInputObservation::UnreadableFile(error.kind()),
            );
            return Err(error);
        }
        if bytes.len() > maximum {
            let reason = if remaining < self.limits.file_bytes {
                "metadata total bytes"
            } else {
                "metadata file bytes"
            };
            state.exceeded = Some(reason);
            return Err(io::Error::other(RepositoryReadLimit(reason)));
        }
        state.bytes += bytes.len();
        let bytes: Arc<[u8]> = bytes.into();
        state.inputs.insert(
            relative,
            RepositoryInputObservation::FileBytes(bytes.clone()),
        );
        Ok(bytes)
    }

    /// Reobserve only admitted paths, with byte reads capped by the captured
    /// lengths. Missing inputs and existence probes are part of the snapshot.
    pub(crate) fn validate_snapshot(&self) -> Result<(), (PathBuf, io::Error)> {
        self.check().map_err(|error| (self.root.clone(), error))?;
        let state = self.state.lock().expect("bounded input mutex poisoned");
        for (relative, captured) in &state.inputs {
            let current = self.observe(relative);
            let matches = match (captured, &current) {
                (RepositoryInputObservation::File, RepositoryInputObservation::File)
                | (RepositoryInputObservation::Directory, RepositoryInputObservation::Directory)
                | (RepositoryInputObservation::Other, RepositoryInputObservation::Other) => true,
                (
                    RepositoryInputObservation::Unavailable(before),
                    RepositoryInputObservation::Unavailable(after),
                ) => before == after,
                (
                    RepositoryInputObservation::FileBytes(before),
                    RepositoryInputObservation::File,
                ) => {
                    let mut bytes = Vec::new();
                    self.directory
                        .open(relative)
                        .and_then(|file| file.take(before.len() as u64 + 1).read_to_end(&mut bytes))
                        .is_ok()
                        && bytes.as_slice() == before.as_ref()
                }
                (
                    RepositoryInputObservation::UnreadableFile(before),
                    RepositoryInputObservation::File,
                ) => {
                    let mut byte = [0_u8; 1];
                    self.directory
                        .open(relative)
                        .and_then(|mut file| file.read(&mut byte))
                        .map_err(|error| error.kind())
                        .err()
                        == Some(*before)
                }
                _ => false,
            };
            if !matches {
                let path = self.root.join(relative);
                return Err((
                    path.clone(),
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "repository metadata changed during report generation: {}",
                            path.display()
                        ),
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Deterministic binding for metadata bytes and negative/probe evidence.
    /// It contains no host root spelling and never reopens a captured input.
    pub(crate) fn snapshot_fingerprint(&self) -> io::Result<String> {
        use sha2::{Digest, Sha256};
        self.check()?;
        let state = self.state.lock().expect("bounded input mutex poisoned");
        let mut hash = Sha256::new();
        let mut field = |bytes: &[u8]| {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        };
        field(b"repotoire.repository_inputs.v1");
        field(&(state.inputs.len() as u64).to_be_bytes());
        for (path, observation) in &state.inputs {
            field(path.as_os_str().as_encoded_bytes());
            match observation {
                RepositoryInputObservation::File => field(b"file_probe"),
                RepositoryInputObservation::FileBytes(bytes) => {
                    field(b"file_bytes");
                    field(bytes);
                }
                RepositoryInputObservation::UnreadableFile(kind) => {
                    field(b"unreadable_file");
                    field(format!("{kind:?}").as_bytes());
                }
                RepositoryInputObservation::Directory => field(b"directory"),
                RepositoryInputObservation::Other => field(b"other"),
                RepositoryInputObservation::Unavailable(kind) => {
                    field(b"unavailable");
                    field(format!("{kind:?}").as_bytes());
                }
            }
        }
        Ok(format!("sha256:{:x}", hash.finalize()))
    }
}

impl ReadOnlyFiles<'_> {
    fn captured_bytes(&self, path: &Path) -> Option<&[u8]> {
        let Self::Captured { root, files } = self else {
            return None;
        };
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                Component::ParentDir => {
                    if !normalized.pop() {
                        return None;
                    }
                }
                Component::CurDir => {}
                other => normalized.push(other.as_os_str()),
            }
        }
        let relative = normalized.strip_prefix(root).ok()?.to_str()?;
        files.get(relative).map(Vec::as_slice)
    }

    pub(crate) fn is_file(&self, path: &Path) -> bool {
        match self {
            Self::Repository => path.is_file(),
            Self::Bounded(files) => files.is_file(path),
            Self::Captured { .. } => self.captured_bytes(path).is_some(),
        }
    }

    /// Preserve denied and failed probes when absence would change resolution.
    pub(crate) fn try_is_file(&self, path: &Path) -> io::Result<bool> {
        match self {
            Self::Repository => match std::fs::metadata(path) {
                Ok(metadata) => Ok(metadata.is_file()),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) =>
                {
                    Ok(false)
                }
                Err(error) => Err(error),
            },
            Self::Bounded(files) => match files.probe(path)? {
                RepositoryInputObservation::Unavailable(kind)
                    if !matches!(kind, io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) =>
                {
                    Err(kind.into())
                }
                observation => Ok(observation.is_file()),
            },
            Self::Captured { .. } => Ok(self.captured_bytes(path).is_some()),
        }
    }

    pub(crate) fn is_directory(&self, path: &Path) -> bool {
        match self {
            Self::Repository => path.is_dir(),
            Self::Bounded(files) => files.probe(path).is_ok_and(|observation| {
                matches!(observation, RepositoryInputObservation::Directory)
            }),
            Self::Captured { .. } => false,
        }
    }

    pub(crate) fn read_to_string(&self, path: &Path) -> io::Result<String> {
        match self {
            Self::Repository => std::fs::read_to_string(path),
            Self::Bounded(files) => String::from_utf8(files.read(path)?.to_vec())
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
            Self::Captured { .. } => {
                let bytes = self.captured_bytes(path).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "file is outside captured inputs")
                })?;
                String::from_utf8(bytes.to_vec())
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            }
        }
    }

    pub(crate) fn visit(&self) -> io::Result<()> {
        match self {
            Self::Bounded(files) => files.visit(),
            _ => Ok(()),
        }
    }

    pub(crate) fn check_limits(&self) -> io::Result<()> {
        match self {
            Self::Bounded(files) => files.check(),
            _ => Ok(()),
        }
    }
}

/// Resolve a repository-relative path without allowing an existing ancestor
/// to redirect the operation outside the repository root.
pub(crate) fn resolve(root: &Path, entry: &str) -> io::Result<PathBuf> {
    let relative = relative(entry)?;

    let canonical_root = root.canonicalize()?;
    let target = canonical_root.join(relative);
    let mut probe = target.as_path();

    loop {
        match std::fs::symlink_metadata(probe) {
            Ok(_) => {
                let resolved = probe.canonicalize()?;
                if !resolved.starts_with(&canonical_root) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("path resolves outside the repository root: {entry}"),
                    ));
                }
                if probe != target && !std::fs::metadata(probe)?.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotADirectory,
                        format!("path ancestor is not a directory: {}", probe.display()),
                    ));
                }
                return Ok(target);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                probe = probe.parent().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("path has no repository ancestor: {entry}"),
                    )
                })?;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Parse the shared repository-relative path spelling used by both live reads
/// and capability-relative Source Writeback mutations.
pub(crate) fn relative(entry: &str) -> io::Result<&Path> {
    let relative = Path::new(entry);
    if entry.is_empty()
        || entry.contains('\\')
        || relative.is_absolute()
        || relative.components().any(|component| {
            !matches!(component, Component::Normal(_))
                // Reserve every ASCII spelling on case-sensitive and case-insensitive hosts.
                || component
                    .as_os_str()
                    .to_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case(".git"))
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path must be repository-relative: {entry}"),
        ));
    }
    Ok(relative)
}

/// Inspect an entry through a descriptor rooted at the repository. A symlink
/// ancestor can never redirect this observation outside that descriptor.
/// A missing entry includes descendants of a non-directory ancestor.
pub(crate) fn entry_exists(root: &Path, entry: &str) -> io::Result<bool> {
    let relative = relative(entry)?;
    let directory = repository_dir(root)?;
    match directory.symlink_metadata(relative) {
        Ok(_) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// Read one regular, non-symlink repository entry with an explicit byte bound.
/// `None` means the entry is absent or is not a regular file.
pub(crate) fn read_regular_file_bounded(
    root: &Path,
    entry: &str,
    max_bytes: usize,
) -> io::Result<Option<Vec<u8>>> {
    let relative = relative(entry)?;
    let directory = repository_dir(root)?;
    let metadata = match directory.symlink_metadata(relative) {
        Ok(metadata) => metadata,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Ok(None);
    }

    // cap-std resolves this open beneath the already-open directory. Even if
    // the entry changes after metadata inspection, the read cannot escape the
    // repository capability.
    let mut file = directory.open(relative)?;
    let read_limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
    file.by_ref().take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("repository entry `{entry}` exceeds {max_bytes} bytes"),
        ));
    }
    Ok(Some(bytes))
}

fn repository_dir(root: &Path) -> io::Result<Dir> {
    let canonical_root = root.canonicalize()?;
    Dir::open_ambient_dir(canonical_root, ambient_authority())
}

/// Classify an input without following its final symlink or leaving the root.
/// Directory membership is deliberately not enumerated by this operation.
pub(crate) fn input_kind(root: &Path, entry: &str) -> io::Result<RepositoryInputKind> {
    let directory = repository_dir(root)?;
    match directory.symlink_metadata(relative(entry)?) {
        Ok(metadata) if metadata.is_file() => Ok(RepositoryInputKind::File),
        Ok(metadata) if metadata.is_dir() => Ok(RepositoryInputKind::Directory),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported input kind",
        )),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(RepositoryInputKind::Absent)
        }
        Err(error) => Err(error),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RepositoryInputKind {
    File,
    Directory,
    Absent,
}
