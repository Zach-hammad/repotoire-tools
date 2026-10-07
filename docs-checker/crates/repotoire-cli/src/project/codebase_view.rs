use std::collections::{BTreeMap, HashSet};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::deadline::RequestDeadline;

use repotoire::archive::SourceBundle;
use repotoire::schema::NodeKind;
use repotoire::source_role::{CompleteSourceRoleIndex, SourceRole};
use repotoire::ts::diagnostics::Diagnostic;

use super::{
    evidence_load, CodebaseSnapshot, LanguageCounts, LoadOptions, NativeEvidenceLoadScope,
    ProjectEvidenceColdExtractionFinished, ProjectEvidenceColdExtractionStarted,
    ProjectEvidenceDeclarationsReady, ProjectEvidenceLoadAccounting,
    ProjectEvidenceLoadAccountingBuilder, ProjectEvidenceLoadEvent, ProjectEvidenceLoadObserver,
    ProjectEvidenceNativeEvidenceReady, ProjectEvidenceSourceInventoryReady, SourceFileRef,
    SourceInventoryMetrics,
};

mod filesystem;
mod task_view;

pub(crate) use task_view::{TaskCodebaseView, TaskViewError, TaskViewTarget};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DirectoryIdentity {
    #[cfg(not(unix))]
    canonical_path: PathBuf,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl DirectoryIdentity {
    pub(super) fn capture(path: &Path) -> io::Result<Self> {
        let canonical_path = path.canonicalize()?;
        let metadata = canonical_path.metadata()?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("codebase root is not a directory: {}", path.display()),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self { canonical_path })
        }
    }

    pub(super) fn still_names(&self, path: &Path) -> io::Result<bool> {
        let current = Self::capture(path)?;
        #[cfg(unix)]
        {
            Ok(current.device == self.device && current.inode == self.inode)
        }
        #[cfg(not(unix))]
        {
            Ok(current.canonical_path == self.canonical_path)
        }
    }
}

/// One fresh, read-only view of a repository for a single request.
pub struct CodebaseView {
    requested_root: PathBuf,
    root: PathBuf,
    options: LoadOptions,
    root_identity: DirectoryIdentity,
    snapshot: CodebaseSnapshot,
    captured_filesystem: BTreeMap<String, crate::walk::CapturedFilesystemEntry>,
    explicit_file_tasks: HashSet<String>,
    reference_targets: Option<Vec<String>>,
    source_paths: BTreeMap<String, PathBuf>,
    source_inventory: SourceInventoryMetrics,
    accounting: ProjectEvidenceLoadAccounting,
}

/// Stable, serializable evidence about how a fresh [`CodebaseView`] was built.
#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub struct CodebaseViewReport {
    pub source_inventory_total_file_count: u64,
    pub source_inventory_walk_file_count: u64,
    pub source_inventory_walk_ms: u64,
    pub source_inventory_source_read_file_count: u64,
    pub source_inventory_source_read_byte_count: u64,
    pub native_decode_file_count: u64,
    pub source_role_complete: bool,
    pub source_role_counts: BTreeMap<String, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_roles_by_rel_path: Option<BTreeMap<String, SourceRole>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_roles_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_roles_omitted_count: Option<u64>,
    pub project_evidence_load_accounting: ProjectEvidenceLoadAccounting,
}

impl CodebaseView {
    /// Describe this view without asking a renderer to understand its internals.
    pub(crate) fn report(&self) -> CodebaseViewReport {
        self.report_checked(&|| Ok(()))
            .expect("unbounded view report")
    }

    pub(crate) fn report_checked(
        &self,
        check: &dyn Fn() -> io::Result<()>,
    ) -> io::Result<CodebaseViewReport> {
        self.report_with_role_paths(true, check)
    }

    /// Project the captured role authority without repeating every path in a
    /// focused or budgeted answer. Counts and completeness retain their full
    /// captured-inventory meaning.
    pub(crate) fn compact_context_report_checked(
        &self,
        check: &dyn Fn() -> io::Result<()>,
    ) -> io::Result<CodebaseViewReport> {
        self.report_with_role_paths(false, check)
    }

    fn report_with_role_paths(
        &self,
        include_paths: bool,
        check: &dyn Fn() -> io::Result<()>,
    ) -> io::Result<CodebaseViewReport> {
        check()?;
        let roles = self.source_roles().as_map();
        let source_inventory = self.source_inventory();
        let mut source_role_counts = BTreeMap::new();
        for role in roles.values() {
            check()?;
            *source_role_counts
                .entry(role.as_str().to_string())
                .or_insert(0) += 1;
        }
        let source_roles_sha256 = if include_paths {
            None
        } else {
            let mut bytes = b"repotoire.source_roles.v1\0".to_vec();
            for (path, role) in roles {
                check()?;
                let path_bytes = path.as_bytes();
                let role_bytes = role.as_str().as_bytes();
                bytes.extend_from_slice(&(path_bytes.len() as u64).to_be_bytes());
                bytes.extend_from_slice(path_bytes);
                bytes.extend_from_slice(&(role_bytes.len() as u64).to_be_bytes());
                bytes.extend_from_slice(role_bytes);
            }
            Some(format!("sha256:{}", repotoire::hash::sha256_hex(&bytes)))
        };
        check()?;
        Ok(CodebaseViewReport {
            source_inventory_total_file_count: source_inventory.total_file_count,
            source_inventory_walk_file_count: source_inventory.walk_file_count,
            source_inventory_walk_ms: source_inventory.walk_inventory_ms,
            source_inventory_source_read_file_count: source_inventory.source_read_file_count,
            source_inventory_source_read_byte_count: source_inventory.source_read_byte_count,
            native_decode_file_count: source_inventory.native_decode_file_count,
            source_role_complete: roles.len() as u64 == source_inventory.total_file_count,
            source_role_counts,
            source_roles_by_rel_path: include_paths.then(|| roles.clone()),
            source_roles_sha256,
            source_roles_omitted_count: (!include_paths).then_some(roles.len() as u64),
            project_evidence_load_accounting: self.accounting().clone(),
        })
    }

    /// Read current source files and build their graph evidence.
    pub fn read(root: &Path, options: LoadOptions) -> io::Result<Self> {
        let mut observer = IgnoreProjectEvidenceLoadEvents;
        Self::read_with_observer_deadline_and_file_tasks(
            root,
            options,
            &mut observer,
            &[],
            NativeEvidenceLoadScope::FullInventory,
            None,
            RequestDeadline::unbounded(),
        )
    }

    /// Read explicit repository-relative file tasks at the same instant as the
    /// source inventory. Explicit selection may override ignore policy, but
    /// never containment, symlink, generated-tree, count, or byte bounds.
    pub(crate) fn read_for_file_tasks<T: AsRef<str>>(
        root: &Path,
        options: LoadOptions,
        targets: &[T],
    ) -> io::Result<Self> {
        let targets = crate::walk::canonical_explicit_file_tasks(targets)?;
        let mut observer = IgnoreProjectEvidenceLoadEvents;
        Self::read_with_observer_deadline_and_file_tasks(
            root,
            options,
            &mut observer,
            &targets,
            NativeEvidenceLoadScope::FullInventory,
            None,
            RequestDeadline::unbounded(),
        )
    }

    /// Capture optional references, including negative admission evidence. Proposal
    /// discovery parses only a bounded lexical candidate set from the inventory.
    pub(crate) fn read_for_reference_candidates<T: AsRef<str>>(
        root: &Path,
        options: LoadOptions,
        targets: &[T],
        discovery_queries: &[String],
    ) -> io::Result<Self> {
        let targets = crate::walk::canonical_exact_file_candidates(targets)?;
        let mut observer = IgnoreProjectEvidenceLoadEvents;
        Self::read_with_observer_deadline_and_file_tasks(
            root,
            options,
            &mut observer,
            &targets,
            NativeEvidenceLoadScope::ExactFileWorkingSet,
            Some(discovery_queries),
            RequestDeadline::unbounded(),
        )
    }

    /// Read the same view while reporting construction milestones.
    pub fn read_with_observer(
        root: &Path,
        options: LoadOptions,
        observer: &mut dyn ProjectEvidenceLoadObserver,
    ) -> io::Result<Self> {
        Self::read_with_observer_and_deadline(root, options, observer, RequestDeadline::unbounded())
    }

    pub(crate) fn read_with_observer_and_deadline(
        root: &Path,
        options: LoadOptions,
        observer: &mut dyn ProjectEvidenceLoadObserver,
        deadline: RequestDeadline,
    ) -> io::Result<Self> {
        Self::read_with_observer_deadline_and_file_tasks(
            root,
            options,
            observer,
            &[],
            NativeEvidenceLoadScope::FullInventory,
            None,
            deadline,
        )
    }

    fn read_with_observer_deadline_and_file_tasks(
        root: &Path,
        options: LoadOptions,
        observer: &mut dyn ProjectEvidenceLoadObserver,
        explicit_file_tasks: &[String],
        native_load_scope: NativeEvidenceLoadScope,
        reference_queries: Option<&[String]>,
        deadline: RequestDeadline,
    ) -> io::Result<Self> {
        deadline.check("codebase view start")?;
        let requested_root = root.canonicalize()?;
        let mut accounting = ProjectEvidenceLoadAccountingBuilder::new();
        let evidence_load::SourceInventoryStageOutcome {
            prepared,
            captured_filesystem,
            mut source_inventory,
            stage_timing: source_inventory_timing,
        } = evidence_load::run_source_inventory_stage(
            evidence_load::SourceInventoryStageInput {
                root: &requested_root,
                options,
                explicit_file_tasks,
                file_task_admission: if reference_queries.is_some() {
                    crate::walk::FileTaskAdmission::ReferenceCandidates
                } else {
                    crate::walk::FileTaskAdmission::RequiredFiles
                },
                deadline,
            },
            &mut accounting,
        )?;
        // The inventory stage owns source-root resolution. A single-file
        // request may widen to its import closure, crate, or workspace, so the
        // protected CodebaseView root must be that resolved directory rather
        // than the caller's file path.
        let root = prepared.inventory.source_root.clone();
        let root_identity = DirectoryIdentity::capture(&root)?;
        observer.emit(ProjectEvidenceLoadEvent::SourceInventoryReady(
            ProjectEvidenceSourceInventoryReady {
                root: &root,
                language: options.language,
                analysis_profile: options.analysis_profile,
                source_inventory: &source_inventory.metrics,
                stage_timing: source_inventory_timing,
            },
        ))?;

        let explicit_file_task_set = explicit_file_tasks.iter().cloned().collect::<HashSet<_>>();
        let mut working_set = explicit_file_task_set.clone();
        if let Some(queries) = reference_queries {
            let mut discovered = 0usize;
            let mut selected_bytes = 0usize;
            // Bound native parsing independently of query count. The inventory
            // remains lexical evidence; omitted files cannot establish absence.
            for file in &prepared.inventory.files {
                if working_set.contains(&file.rel_path) {
                    continue;
                }
                if discovered >= 64
                    || selected_bytes.saturating_add(file.bytes.len()) > 16 * 1024 * 1024
                {
                    continue;
                }
                if queries
                    .iter()
                    .filter(|query| !query.is_empty())
                    .any(|query| {
                        file.bytes
                            .windows(query.len())
                            .any(|bytes| bytes == query.as_bytes())
                    })
                {
                    working_set.insert(file.rel_path.clone());
                    discovered += 1;
                    selected_bytes += file.bytes.len();
                }
            }
        }
        let source_paths = prepared
            .inventory
            .files
            .iter()
            .filter(|file| reference_queries.is_some() && working_set.contains(&file.rel_path))
            .map(|file| (file.rel_path.clone(), file.path.clone()))
            .collect();
        let native_evidence = evidence_load::run_native_evidence_stage(
            evidence_load::NativeEvidenceStageInput {
                inventory: prepared.inventory,
                load_scope: native_load_scope,
                working_set_extra_paths: &working_set,
                source_inventory: &mut source_inventory,
                deadline,
            },
            &mut accounting,
        )?;
        emit_native_evidence_stage_events(
            observer,
            &root,
            &source_inventory.metrics,
            &native_evidence,
        )?;
        let native = native_evidence.outcome.native;

        let cold_extraction_start =
            evidence_load::prepare_cold_extraction_stage(&accounting, &native);
        observer.emit(ProjectEvidenceLoadEvent::ColdExtractionStarted(
            ProjectEvidenceColdExtractionStarted {
                root: &root,
                source_file_count: cold_extraction_start.source_file_count,
                source_byte_count: cold_extraction_start.source_byte_count,
                language_counts: cold_extraction_start.language_counts,
                stage_timing: cold_extraction_start.stage_timing,
            },
        ))?;
        let evidence_load::ColdExtractionStageOutcome {
            snapshot,
            stage_timing: cold_extraction_finished_timing,
        } = evidence_load::run_cold_extraction_stage(
            evidence_load::ColdExtractionStageInput {
                root: &root,
                options,
                native,
                deadline,
            },
            &mut accounting,
        )?;
        observer.emit(ProjectEvidenceLoadEvent::ColdExtractionFinished(
            ProjectEvidenceColdExtractionFinished {
                root: &root,
                source_file_count: snapshot.source_file_count,
                source_byte_count: snapshot.source_byte_count,
                diagnostic_count: snapshot.diagnostics.len(),
                warning_count: snapshot.warnings.len(),
                language_counts: snapshot.language_counts,
                stage_timing: cold_extraction_finished_timing,
            },
        ))?;

        let accounting = accounting.complete("fresh_repository_read");
        let mut load = Self {
            requested_root,
            root,
            options,
            root_identity,
            snapshot,
            captured_filesystem,
            explicit_file_tasks: explicit_file_task_set,
            reference_targets: reference_queries.map(|_| explicit_file_tasks.to_vec()),
            source_paths,
            source_inventory: source_inventory.metrics,
            accounting,
        };
        observer.emit(ProjectEvidenceLoadEvent::ProjectEvidenceReady(&load))?;
        Ok(load)
    }

    /// Derive a closed view from already captured regular inputs. The root is
    /// identity/display only; native decisions never reopen the repository.
    pub(crate) fn from_captured_inputs(
        root: &Path,
        inputs: BTreeMap<String, Vec<u8>>,
    ) -> io::Result<Self> {
        let root = root.canonicalize()?;
        let root_identity = DirectoryIdentity::capture(&root)?;
        let options = LoadOptions::agent_context(crate::walk::AnalysisProfile::All);
        let mut source_inventory = SourceInventoryMetrics::default();
        let captured_filesystem = inputs
            .iter()
            .map(|(path, bytes)| {
                (
                    path.clone(),
                    crate::walk::CapturedFilesystemEntry::RegularFile(Some(bytes.clone())),
                )
            })
            .collect();
        let explicit_file_tasks = inputs.keys().cloned().collect();
        let native = super::native_evidence_units::NativeEvidenceUnits::from_captured(
            &root,
            inputs,
            &mut source_inventory,
        )?;
        let mut accounting = ProjectEvidenceLoadAccountingBuilder::new();
        let snapshot = evidence_load::run_cold_extraction_stage(
            evidence_load::ColdExtractionStageInput {
                root: &root,
                options,
                native,
                deadline: RequestDeadline::unbounded(),
            },
            &mut accounting,
        )?
        .snapshot;
        Ok(Self {
            requested_root: root.clone(),
            root,
            options,
            root_identity,
            snapshot,
            captured_filesystem,
            explicit_file_tasks,
            reference_targets: None,
            source_paths: BTreeMap::new(),
            source_inventory,
            accounting: accounting.complete("captured_inputs"),
        })
    }

    pub fn graph(&self) -> repotoire::csr::CodeGraph<'_> {
        self.snapshot.owned_graph.as_view()
    }

    /// Configuration failures limit TypeScript evidence within the affected scope.
    pub(crate) fn typescript_configuration_gaps<'a>(
        &'a self,
        path: &'a str,
    ) -> impl Iterator<Item = &'a str> {
        let relative = Path::new(path.strip_prefix("./").unwrap_or(path));
        let is_typescript = repotoire::source_pipeline::source_language_for_path(relative)
            == repotoire::source_pipeline::SourceLanguage::TypeScript;
        self.snapshot
            .typescript_configuration_gaps
            .iter()
            .filter(move |gap| {
                is_typescript
                    && relative
                        .starts_with(gap.scope_dir.strip_prefix("./").unwrap_or(&gap.scope_dir))
            })
            .map(|gap| gap.message.as_str())
    }

    /// Canonical source root captured for this request.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Exact canonical file or directory the caller asked this view to read.
    ///
    /// This can be narrower than [`Self::root`]: a file request may widen to
    /// its crate or import closure for analysis. Consumers that operate on the
    /// requested surface, rather than the analyzed source universe, use this
    /// path without needing a parallel argument.
    pub fn requested_root(&self) -> &Path {
        &self.requested_root
    }

    /// Construction choices that define which evidence this view contains.
    pub fn options(&self) -> LoadOptions {
        self.options
    }

    /// Whether this repository-relative path existed in the captured read.
    pub(crate) fn captured_path_exists(&self, entry: &str) -> bool {
        self.captured_filesystem.contains_key(entry)
    }

    /// Bytes of an admitted regular file, including files without a source parser.
    /// Never follows a path or rereads the filesystem after this view was captured.
    pub(crate) fn captured_file_bytes(&self, entry: &str) -> Option<&[u8]> {
        match self.captured_filesystem.get(entry)? {
            crate::walk::CapturedFilesystemEntry::RegularFile(Some(bytes)) => Some(bytes),
            _ => None,
        }
    }

    /// Reobserve exactly the source evidence used by a reference report. Stable
    /// negative admission is valid evidence; changes to bytes, admission, root,
    /// or an admitted symlink's canonical target invalidate the generation.
    pub(crate) fn validate_reference_snapshot(&self) -> Result<(), (PathBuf, io::Error)> {
        let changed = |path: PathBuf, message: &str| {
            let error = io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{message}: {}", path.display()),
            );
            (path, error)
        };
        if !self
            .root_identity
            .still_names(&self.root)
            .map_err(|error| (self.root.clone(), error))?
        {
            return Err(changed(
                self.root.clone(),
                "source root changed during report generation",
            ));
        }
        if let Some(inputs) = &self.snapshot.metadata_inputs {
            inputs.validate_snapshot()?;
        }
        if let Some(targets) = &self.reference_targets {
            let current = crate::walk::capture_reference_candidates(
                &self.root,
                targets,
                RequestDeadline::unbounded(),
                self.options.source_inventory_limits,
            )
            .map_err(|error| (self.root.clone(), error))?;
            for (relative, captured) in &self.captured_filesystem {
                if current.get(relative) == Some(captured) {
                    continue;
                }
                let path = self.root.join(relative);
                use crate::walk::CapturedFilesystemEntry as Entry;
                if matches!(captured, Entry::RegularFile(Some(_))) {
                    if matches!(
                        current.get(relative),
                        Some(Entry::Unreadable(io::ErrorKind::NotFound))
                    ) {
                        return Err((path, io::Error::from(io::ErrorKind::NotFound)));
                    }
                    let message =
                        if matches!(current.get(relative), Some(Entry::RegularFile(Some(_)))) {
                            "source reference changed during report generation"
                        } else {
                            "source reference is no longer an admitted regular file"
                        };
                    return Err(changed(path, message));
                }
                return Err(changed(
                    path,
                    "source reference availability changed during report generation",
                ));
            }
            if current.len() != self.captured_filesystem.len() {
                return Err(changed(
                    self.root.clone(),
                    "source reference availability changed during report generation",
                ));
            }
        }
        let directory =
            cap_std::fs::Dir::open_ambient_dir(&self.root, cap_std::ambient_authority())
                .map_err(|error| (self.root.clone(), error))?;
        for source in self.source_file_refs() {
            if self
                .reference_targets
                .as_ref()
                .is_some_and(|targets| targets.iter().any(|path| path == source.path))
            {
                continue;
            }
            let path = self.root.join(source.path);
            let canonical = path.canonicalize().map_err(|error| (path.clone(), error))?;
            if self.source_paths.get(source.path) != Some(&canonical) {
                return Err(changed(
                    path,
                    "source reference target changed during report generation",
                ));
            }
            let relative = canonical
                .strip_prefix(&self.root)
                .map_err(|_| changed(path.clone(), "source reference escaped the captured root"))?;
            let file = directory
                .open(relative)
                .map_err(|error| (path.clone(), error))?;
            if file
                .metadata()
                .map_err(|error| (path.clone(), error))?
                .len()
                != source.bytes.len() as u64
            {
                return Err(changed(
                    path,
                    "source reference changed during report generation",
                ));
            }
            let mut bytes = Vec::new();
            file.take(source.bytes.len() as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| (path.clone(), error))?;
            if bytes != source.bytes {
                return Err(changed(
                    path,
                    "source reference changed during report generation",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn reference_unavailable_reason(&self, path: &str) -> &'static str {
        use crate::walk::CapturedFilesystemEntry as Entry;
        match self.captured_filesystem.get(path) {
            Some(Entry::Directory) => "the reference names a directory, not a file",
            Some(Entry::Symlink) => "explicit references cannot admit symbolic links",
            Some(Entry::Other) => "the reference is not a regular file",
            Some(Entry::Unreadable(io::ErrorKind::NotFound)) => {
                "the reference or a parent directory was missing at capture"
            }
            Some(Entry::Unreadable(io::ErrorKind::PermissionDenied)) => {
                "access was denied or the reference crosses an unsafe ancestor"
            }
            Some(Entry::Unreadable(io::ErrorKind::InvalidData)) => {
                "the reference exceeded the 4 MiB file or 16 MiB aggregate capture limit"
            }
            Some(Entry::Unreadable(_)) => "the reference could not be read at capture",
            _ => "no admitted file bytes are available in the captured snapshot",
        }
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.snapshot.diagnostics
    }

    pub fn warnings(&self) -> &[String] {
        &self.snapshot.warnings
    }

    pub fn language_counts(&self) -> LanguageCounts {
        self.snapshot.language_counts
    }

    pub fn typescript_paths(&self) -> &[String] {
        &self.snapshot.ts_paths
    }

    pub fn skipped_by_extension(&self) -> &BTreeMap<String, u64> {
        &self.snapshot.skipped_by_extension
    }

    pub fn render_paths(&self) -> Option<&[String]> {
        self.snapshot.render_paths.as_deref()
    }

    pub fn analysis_inventory_complete(&self) -> bool {
        self.snapshot.analysis_inventory_complete
    }

    pub fn source_inventory_deletion_trusted(&self) -> bool {
        self.snapshot.source_inventory_deletion_trusted
    }

    pub fn source_file_count(&self) -> usize {
        self.snapshot.source_file_count
    }

    pub fn source_byte_count(&self) -> u64 {
        self.snapshot.source_byte_count
    }

    pub fn source_roles(&self) -> &CompleteSourceRoleIndex {
        &self.snapshot.source_roles
    }

    pub fn source_role_for_path(&self, rel_path: &str) -> Option<SourceRole> {
        self.snapshot.source_roles.role_for_path(rel_path)
    }

    pub fn source_bundle(&self) -> SourceBundle<'_> {
        let archive = self
            .snapshot
            .owned_archive
            .as_ref()
            .map(|archive| archive.as_view());
        let source_lookup = self.snapshot.source_pairs.as_ref().map(|pairs| {
            repotoire::archive::SourceLookup::from_pairs(
                pairs,
                self.snapshot.source_pair_index.as_ref(),
                self.snapshot.source_pair_metadata.as_ref(),
            )
        });
        SourceBundle::with_source_roles_and_lookup(
            self.snapshot.owned_graph.as_view(),
            archive,
            &self.snapshot.source_roles,
            source_lookup,
        )
    }

    pub fn source_file_refs(&self) -> Vec<SourceFileRef<'_>> {
        if let Some(pairs) = &self.snapshot.source_pairs {
            return pairs
                .iter()
                .map(|(path, bytes)| SourceFileRef {
                    path: path.as_str(),
                    bytes: bytes.as_slice(),
                })
                .collect();
        }

        let bundle = self.source_bundle();
        bundle
            .graph
            .nodes_of_kind(NodeKind::File)
            .filter_map(|file| {
                let bytes = bundle.source_bytes(file)?;
                Some(SourceFileRef {
                    path: bundle.graph.node_name(file),
                    bytes,
                })
            })
            .collect()
    }

    pub fn source_file_paths(&self) -> Vec<String> {
        self.source_file_refs()
            .into_iter()
            .map(|file| file.path.to_string())
            .collect()
    }

    pub fn clone_owned_source_files(&self) -> Vec<(String, Vec<u8>)> {
        self.source_file_refs()
            .into_iter()
            .map(|file| (file.path.to_string(), file.bytes.to_vec()))
            .collect()
    }

    pub fn source_inventory(&self) -> &SourceInventoryMetrics {
        &self.source_inventory
    }

    pub fn accounting(&self) -> &ProjectEvidenceLoadAccounting {
        &self.accounting
    }

    #[cfg(test)]
    pub(super) fn serialized_graph(&self) -> &[u8] {
        self.snapshot.owned_graph.as_bytes()
    }
}

/// Observe one repository-relative path without requiring source parsing.
///
/// Repair compilation uses this boundary because broken source is a valid
/// compiler input. Graph construction remains available through
/// [`CodebaseView::read`] for consumers that actually need graph evidence.
pub(crate) fn observe_repository_path(root: &Path, entry: &str) -> PathEvidence {
    let path = root.join(entry);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            let kind = metadata.file_type();
            if kind.is_symlink() {
                PathEvidence::Symlink
            } else if kind.is_file() {
                PathEvidence::RegularFile
            } else if kind.is_dir() {
                PathEvidence::Directory
            } else {
                PathEvidence::Other
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match crate::repository_path::resolve(root, entry) {
                Ok(_) => PathEvidence::Absent,
                Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
                    PathEvidence::OutsideRoot
                }
                Err(error) => PathEvidence::Unreadable(FilesystemErrorKind::from(error.kind())),
            }
        }
        Err(error) => PathEvidence::Unreadable(FilesystemErrorKind::from(error.kind())),
    }
}

pub(crate) struct IgnoreProjectEvidenceLoadEvents;

impl ProjectEvidenceLoadObserver for IgnoreProjectEvidenceLoadEvents {
    fn emit(&mut self, _event: ProjectEvidenceLoadEvent<'_>) -> io::Result<()> {
        Ok(())
    }
}

fn emit_native_evidence_stage_events(
    observer: &mut dyn ProjectEvidenceLoadObserver,
    root: &Path,
    source_inventory: &SourceInventoryMetrics,
    native_evidence: &evidence_load::NativeEvidenceStageResult,
) -> io::Result<()> {
    let outcome = &native_evidence.outcome;
    observer.emit(ProjectEvidenceLoadEvent::NativeEvidenceReady(
        ProjectEvidenceNativeEvidenceReady {
            root,
            working_set: outcome.working_set.clone(),
            source_file_count: outcome.source_file_count,
            source_byte_count: outcome.source_byte_count,
            language_counts: outcome.language_counts,
            source_inventory,
            stage_timing: native_evidence.stage_timing,
        },
    ))?;
    observer.emit(ProjectEvidenceLoadEvent::ProjectEvidenceDeclarationsReady(
        ProjectEvidenceDeclarationsReady {
            root,
            working_set: outcome.working_set.clone(),
            source_file_count: outcome.source_file_count,
            source_byte_count: outcome.source_byte_count,
            language_counts: outcome.language_counts,
            declaration_inventory: outcome.declaration_readiness.declaration_inventory.clone(),
            source_role_complete: outcome.declaration_readiness.source_role_complete,
            source_role_counts: outcome.declaration_readiness.source_role_counts.clone(),
            classification: outcome.declaration_readiness.classification.clone(),
            source_inventory,
            stage_timing: native_evidence.stage_timing,
        },
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathEvidence {
    Absent,
    RegularFile,
    Directory,
    Symlink,
    Other,
    OutsideRoot,
    Unreadable(FilesystemErrorKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilesystemErrorKind {
    NotFound,
    PermissionDenied,
    NotADirectory,
    Other,
}

impl From<io::ErrorKind> for FilesystemErrorKind {
    fn from(kind: io::ErrorKind) -> Self {
        match kind {
            io::ErrorKind::NotFound => Self::NotFound,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::NotADirectory => Self::NotADirectory,
            _ => Self::Other,
        }
    }
}
