//! Custom ignore policy over candidate paths. Git owns enumeration; this
//! owner only admits or excludes paths, independent of source-file existence.
//! Policy discovery uses candidate ancestors, so Git-ignored policy files
//! still participate, including when a changed source file has been deleted.
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ignore::gitignore::{Gitignore, GitignoreBuilder};

use crate::deadline::{ObservationScope, RequestDeadline};

const POLICY_FILE: &str = ".repotoireignore";
const MAX_POLICY_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOTAL_POLICY_BYTES: usize = 16 * 1024 * 1024;

struct DirectoryPolicy {
    parent: Option<Arc<Self>>,
    matcher: Option<Gitignore>,
    excluded: bool,
}

impl DirectoryPolicy {
    fn ignores(&self, path: &Path, is_dir: bool) -> bool {
        let mut current = Some(self);
        while let Some(policy) = current {
            if let Some(matcher) = &policy.matcher {
                let matched = matcher.matched(path, is_dir);
                if !matched.is_none() {
                    return matched.is_ignore();
                }
            }
            current = policy.parent.as_deref();
        }
        false
    }
}

pub(crate) struct OverlayPolicy {
    directories: BTreeMap<PathBuf, Arc<DirectoryPolicy>>,
    total_bytes: usize,
    pub(super) present: bool,
}

impl OverlayPolicy {
    pub(crate) fn new(root: &Path, deadline: RequestDeadline) -> io::Result<Self> {
        let mut policy = Self {
            directories: BTreeMap::new(),
            total_bytes: 0,
            present: false,
        };
        // The walker admits an explicit root and inherits custom policies all
        // the way to the filesystem root, including above the Git worktree.
        let mut parent = None;
        for directory in root.ancestors().collect::<Vec<_>>().into_iter().rev() {
            let matcher = policy.read(directory, deadline)?;
            let state = Arc::new(DirectoryPolicy {
                parent,
                matcher,
                excluded: false,
            });
            policy
                .directories
                .insert(directory.to_path_buf(), state.clone());
            parent = Some(state);
        }
        Ok(policy)
    }

    pub(crate) fn admits(&mut self, path: &Path, deadline: RequestDeadline) -> io::Result<bool> {
        check(deadline)?;
        let mut missing = Vec::new();
        let mut parent = path
            .parent()
            .ok_or_else(|| invalid("source has no parent"))?;
        while !self.directories.contains_key(parent) {
            missing.push(parent);
            parent = parent
                .parent()
                .ok_or_else(|| invalid("source lies outside policy root"))?;
        }
        let mut state = self.directories[parent].clone();
        for directory in missing.into_iter().rev() {
            check(deadline)?;
            // Excluded parents cannot be revived by a descendant whitelist.
            // Do not read policies below a pruned directory.
            let excluded = state.excluded || state.ignores(directory, true);
            let matcher = if excluded {
                None
            } else {
                self.read(directory, deadline)?
            };
            let next = Arc::new(DirectoryPolicy {
                parent: Some(state),
                matcher,
                excluded,
            });
            self.directories
                .insert(directory.to_path_buf(), next.clone());
            state = next;
        }
        check(deadline)?;
        Ok(!state.excluded && !state.ignores(path, false))
    }

    fn read(
        &mut self,
        directory: &Path,
        deadline: RequestDeadline,
    ) -> io::Result<Option<Gitignore>> {
        check(deadline)?;
        let path = directory.join(POLICY_FILE);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        self.present = true;
        // A missing policy is empty; an unreadable, special, or malformed
        // policy is unknown. Never publish trusted membership from unknown.
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(invalid("ignore policy must be a regular file"));
        }
        let budget = MAX_POLICY_BYTES.min(MAX_TOTAL_POLICY_BYTES - self.total_bytes);
        if metadata.len() > budget as u64 {
            return Err(invalid("ignore policy exceeds its byte budget"));
        }
        let mut file = fs::File::open(&path)?.take(budget as u64 + 1);
        let mut bytes = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            check(deadline)?;
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..count]);
            if bytes.len() > budget {
                return Err(invalid("ignore policy exceeds its byte budget"));
            }
        }
        self.total_bytes += bytes.len();
        let text =
            std::str::from_utf8(&bytes).map_err(|_| invalid("ignore policy is not UTF-8"))?;
        let mut builder = GitignoreBuilder::new(directory);
        for (index, line) in text.lines().enumerate() {
            check(deadline)?;
            let line = if index == 0 {
                line.trim_start_matches('\u{feff}')
            } else {
                line
            };
            builder
                .add_line(Some(path.clone()), line)
                .map_err(|error| invalid(&error.to_string()))?;
        }
        let matcher = builder
            .build()
            .map_err(|error| invalid(&error.to_string()))?;
        check(deadline)?;
        Ok(Some(matcher))
    }
}

fn check(deadline: RequestDeadline) -> io::Result<()> {
    deadline.check("RepoToire ignore policy")?;
    ObservationScope::check_current("RepoToire ignore policy")
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
