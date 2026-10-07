use crate::{tsconfig, walk};
use repotoire::archive::SourceLookupMetadata;
use repotoire::builder::GraphBuilder;
use repotoire::source_pipeline::SourceLanguage;
use repotoire::source_role::{CompleteSourceRoleIndex, SourceRole};
use repotoire::ts::diagnostics::Diagnostic;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io;
use std::path::Path;
use std::time::Instant;

use crate::deadline::RequestDeadline;

/// One immutable CodebaseView never exposes more diagnostics than this.
/// Consumers may therefore compute exact diagnostic summaries with fixed
/// memory. Loads above the ceiling fail closed instead of silently dropping
/// evidence and producing a false-green trust verdict.
pub(crate) const MAX_CODEBASE_DIAGNOSTICS: usize = 65_536;

mod codebase_view;
mod evidence_load;
mod native_evidence_units;

use evidence_load::ProjectEvidenceLoadAccountingBuilder;
use native_evidence_units::{
    DecodedNativeEvidenceUnit, NativeEvidenceFile, NativeEvidenceLoadScope, NativeEvidenceUnits,
};

pub use crate::walk::AnalysisProfile;
pub use codebase_view::{CodebaseView, CodebaseViewReport};
pub(crate) use codebase_view::{TaskViewError, TaskViewTarget};
pub use evidence_load::{
    ProjectEvidenceLoadAccounting, ProjectEvidenceLoadStage, ProjectEvidenceStageAccounting,
    ProjectEvidenceStageTiming, StageDisposition, STAGE_CENSUS,
};

struct CodebaseSnapshot {
    metadata_inputs: Option<std::sync::Arc<crate::repository_path::BoundedRepositoryFiles>>,
    owned_graph: repotoire::csr::OwnedGraph,
    owned_archive: Option<repotoire::archive::OwnedSourceArchive>,
    diagnostics: Vec<Diagnostic>,
    typescript_configuration_gaps: Vec<tsconfig::ConfigGap>,
    source_pairs: Option<Vec<(String, Vec<u8>)>>,
    source_pair_index: Option<BTreeMap<String, usize>>,
    source_pair_metadata: Option<BTreeMap<String, SourceLookupMetadata>>,
    source_roles: CompleteSourceRoleIndex,
    source_file_count: usize,
    source_byte_count: u64,
    ts_paths: Vec<String>,
    skipped_by_extension: BTreeMap<String, u64>,
    language_counts: LanguageCounts,
    warnings: Vec<String>,
    render_paths: Option<Vec<String>>,
    /// True only when the load was a full-inventory walk that saw every
    /// entry (no unreadable directories). Persisted to the evidence summary
    /// as `source_role_complete`; consumers must treat `false` as "the
    /// inventory may be silently truncated" and never conclude absence.
    analysis_inventory_complete: bool,
    /// True when the selected inventory method is stable enough to support
    /// deletion proof. `CodebaseView` uses the Git-aware source inventory and
    /// trusts it only when Git enumeration succeeded or the root is not a Git
    /// worktree. Consumed only at the checkpoint evidence boundary as an AND
    /// over `analysis_inventory_complete`; it must never affect summary serving.
    source_inventory_deletion_trusted: bool,
}

#[derive(Clone, Copy)]
pub struct SourceFileRef<'a> {
    pub path: &'a str,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanguageCounts {
    pub typescript: usize,
    pub rust: usize,
    pub python: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanguageFilter {
    TypeScript,
    Rust,
    #[cfg(feature = "python")]
    Python,
}

impl LanguageFilter {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "typescript" | "ts" | "javascript" | "js" => Some(Self::TypeScript),
            "rust" | "rs" => Some(Self::Rust),
            #[cfg(feature = "python")]
            "python" | "py" => Some(Self::Python),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::TypeScript => "typescript",
            Self::Rust => "rust",
            #[cfg(feature = "python")]
            Self::Python => "python",
        }
    }

    fn matches(self, language: SourceLanguage) -> bool {
        match (self, language) {
            (Self::TypeScript, SourceLanguage::TypeScript) => true,
            (Self::Rust, SourceLanguage::Rust) => true,
            #[cfg(feature = "python")]
            (Self::Python, SourceLanguage::Python) => true,
            _ => false,
        }
    }

    fn source_language(self) -> SourceLanguage {
        match self {
            Self::TypeScript => SourceLanguage::TypeScript,
            Self::Rust => SourceLanguage::Rust,
            #[cfg(feature = "python")]
            Self::Python => SourceLanguage::Python,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadOptions {
    pub language: Option<LanguageFilter>,
    pub analysis_profile: AnalysisProfile,
    pub include_source_archive: bool,
    pub retain_source_pairs: bool,
    pub(crate) source_inventory_limits: Option<walk::SourceInventoryLimits>,
}

impl LoadOptions {
    pub fn agent_context(analysis_profile: AnalysisProfile) -> Self {
        Self::default()
            .with_analysis_profile(analysis_profile)
            .with_source_archive(false)
            .with_source_pairs(true)
    }

    pub fn with_language(mut self, language: Option<LanguageFilter>) -> Self {
        self.language = language;
        self
    }

    pub fn with_source_archive(mut self, include_source_archive: bool) -> Self {
        self.include_source_archive = include_source_archive;
        self
    }

    pub fn with_analysis_profile(mut self, analysis_profile: AnalysisProfile) -> Self {
        self.analysis_profile = analysis_profile;
        self
    }

    pub fn with_source_pairs(mut self, retain_source_pairs: bool) -> Self {
        self.retain_source_pairs = retain_source_pairs;
        self
    }
}

impl Default for LoadOptions {
    fn default() -> Self {
        Self {
            language: None,
            analysis_profile: AnalysisProfile::All,
            include_source_archive: true,
            retain_source_pairs: false,
            source_inventory_limits: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProjectEvidenceLoadSummary {
    pub source_inventory: SourceInventoryMetrics,
    pub source_file_count: usize,
    pub source_byte_count: u64,
    pub language_counts: LanguageCounts,
    pub source_roles_by_rel_path: BTreeMap<String, SourceRole>,
    pub source_role_complete: bool,
    pub accounting: ProjectEvidenceLoadAccounting,
}

pub enum ProjectEvidenceLoadEvent<'a> {
    SourceInventoryReady(ProjectEvidenceSourceInventoryReady<'a>),
    NativeEvidenceReady(ProjectEvidenceNativeEvidenceReady<'a>),
    ProjectEvidenceDeclarationsReady(ProjectEvidenceDeclarationsReady<'a>),
    ColdExtractionStarted(ProjectEvidenceColdExtractionStarted<'a>),
    ColdExtractionFinished(ProjectEvidenceColdExtractionFinished<'a>),
    ProjectEvidenceReady(&'a CodebaseView),
}

impl ProjectEvidenceLoadEvent<'_> {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::SourceInventoryReady(_) => "source_inventory_ready",
            Self::NativeEvidenceReady(_) => "native_evidence_ready",
            Self::ProjectEvidenceDeclarationsReady(_) => "project_evidence_declarations_ready",
            Self::ColdExtractionStarted(_) => "cold_extraction_started",
            Self::ColdExtractionFinished(_) => "cold_extraction_finished",
            Self::ProjectEvidenceReady(_) => "project_evidence_ready",
        }
    }
}

pub struct ProjectEvidenceSourceInventoryReady<'a> {
    pub root: &'a Path,
    pub language: Option<LanguageFilter>,
    pub analysis_profile: AnalysisProfile,
    pub source_inventory: &'a SourceInventoryMetrics,
    pub stage_timing: ProjectEvidenceStageTiming,
}

pub struct ProjectEvidenceNativeEvidenceReady<'a> {
    pub root: &'a Path,
    pub working_set: ProjectEvidenceWorkingSetSummary,
    pub source_file_count: usize,
    pub source_byte_count: u64,
    pub language_counts: LanguageCounts,
    pub source_inventory: &'a SourceInventoryMetrics,
    pub stage_timing: ProjectEvidenceStageTiming,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProjectEvidenceWorkingSetSummary {
    pub scope: String,
    pub inventory_source_file_count: usize,
    pub source_file_count: usize,
    pub omitted_source_file_count: usize,
    pub full_inventory: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ProjectEvidenceDeclarationInventory {
    pub total_declaration_count: u64,
    pub declarations_by_language: BTreeMap<String, u64>,
    pub declarations_by_source_role: BTreeMap<String, u64>,
}

pub struct ProjectEvidenceDeclarationsReady<'a> {
    pub root: &'a Path,
    pub working_set: ProjectEvidenceWorkingSetSummary,
    pub source_file_count: usize,
    pub source_byte_count: u64,
    pub language_counts: LanguageCounts,
    pub declaration_inventory: ProjectEvidenceDeclarationInventory,
    pub source_role_complete: bool,
    pub source_role_counts: BTreeMap<String, u64>,
    pub classification: String,
    pub source_inventory: &'a SourceInventoryMetrics,
    pub stage_timing: ProjectEvidenceStageTiming,
}

pub struct ProjectEvidenceColdExtractionStarted<'a> {
    pub root: &'a Path,
    pub source_file_count: usize,
    pub source_byte_count: u64,
    pub language_counts: LanguageCounts,
    pub stage_timing: ProjectEvidenceStageTiming,
}

pub struct ProjectEvidenceColdExtractionFinished<'a> {
    pub root: &'a Path,
    pub source_file_count: usize,
    pub source_byte_count: u64,
    pub diagnostic_count: usize,
    pub warning_count: usize,
    pub language_counts: LanguageCounts,
    pub stage_timing: ProjectEvidenceStageTiming,
}

pub trait ProjectEvidenceLoadObserver {
    fn emit(&mut self, event: ProjectEvidenceLoadEvent<'_>) -> io::Result<()>;
}

#[derive(Default)]
pub struct ProjectEvidenceLoadCollector {
    milestones: Vec<ProjectEvidenceLoadMilestone>,
}

impl ProjectEvidenceLoadCollector {
    pub fn milestones(&self) -> &[ProjectEvidenceLoadMilestone] {
        &self.milestones
    }
}

impl ProjectEvidenceLoadObserver for ProjectEvidenceLoadCollector {
    fn emit(&mut self, event: ProjectEvidenceLoadEvent<'_>) -> io::Result<()> {
        self.milestones
            .push(ProjectEvidenceLoadMilestone::from_event(event));
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProjectEvidenceLoadMilestone {
    SourceInventoryReady {
        root: String,
        language: Option<String>,
        analysis_profile: String,
        source_inventory: SourceInventoryMetrics,
        stage_timing: ProjectEvidenceStageTiming,
    },
    NativeEvidenceReady {
        root: String,
        working_set: ProjectEvidenceWorkingSetSummary,
        source_file_count: usize,
        source_byte_count: u64,
        language_counts: LanguageCounts,
        source_inventory: SourceInventoryMetrics,
        stage_timing: ProjectEvidenceStageTiming,
    },
    ProjectEvidenceDeclarationsReady {
        root: String,
        working_set: ProjectEvidenceWorkingSetSummary,
        source_file_count: usize,
        source_byte_count: u64,
        language_counts: LanguageCounts,
        declaration_inventory: ProjectEvidenceDeclarationInventory,
        source_role_complete: bool,
        source_role_counts: BTreeMap<String, u64>,
        classification: String,
        source_inventory: SourceInventoryMetrics,
        stage_timing: ProjectEvidenceStageTiming,
    },
    ColdExtractionStarted {
        root: String,
        source_file_count: usize,
        source_byte_count: u64,
        language_counts: LanguageCounts,
        stage_timing: ProjectEvidenceStageTiming,
    },
    ColdExtractionFinished {
        root: String,
        source_file_count: usize,
        source_byte_count: u64,
        diagnostic_count: usize,
        warning_count: usize,
        language_counts: LanguageCounts,
        stage_timing: ProjectEvidenceStageTiming,
    },
    ProjectEvidenceReady {
        source_inventory: SourceInventoryMetrics,
        accounting: ProjectEvidenceLoadAccounting,
    },
}

impl ProjectEvidenceLoadMilestone {
    fn from_event(event: ProjectEvidenceLoadEvent<'_>) -> Self {
        match event {
            ProjectEvidenceLoadEvent::SourceInventoryReady(event) => Self::SourceInventoryReady {
                root: event.root.to_string_lossy().into_owned(),
                language: event.language.map(|language| language.as_str().to_string()),
                analysis_profile: event.analysis_profile.as_str().to_string(),
                source_inventory: event.source_inventory.clone(),
                stage_timing: event.stage_timing,
            },
            ProjectEvidenceLoadEvent::NativeEvidenceReady(event) => Self::NativeEvidenceReady {
                root: event.root.to_string_lossy().into_owned(),
                working_set: event.working_set.clone(),
                source_file_count: event.source_file_count,
                source_byte_count: event.source_byte_count,
                language_counts: event.language_counts,
                source_inventory: event.source_inventory.clone(),
                stage_timing: event.stage_timing,
            },
            ProjectEvidenceLoadEvent::ProjectEvidenceDeclarationsReady(event) => {
                Self::ProjectEvidenceDeclarationsReady {
                    root: event.root.to_string_lossy().into_owned(),
                    working_set: event.working_set.clone(),
                    source_file_count: event.source_file_count,
                    source_byte_count: event.source_byte_count,
                    language_counts: event.language_counts,
                    declaration_inventory: event.declaration_inventory.clone(),
                    source_role_complete: event.source_role_complete,
                    source_role_counts: event.source_role_counts.clone(),
                    classification: event.classification.clone(),
                    source_inventory: event.source_inventory.clone(),
                    stage_timing: event.stage_timing,
                }
            }
            ProjectEvidenceLoadEvent::ColdExtractionStarted(event) => Self::ColdExtractionStarted {
                root: event.root.to_string_lossy().into_owned(),
                source_file_count: event.source_file_count,
                source_byte_count: event.source_byte_count,
                language_counts: event.language_counts,
                stage_timing: event.stage_timing,
            },
            ProjectEvidenceLoadEvent::ColdExtractionFinished(event) => {
                Self::ColdExtractionFinished {
                    root: event.root.to_string_lossy().into_owned(),
                    source_file_count: event.source_file_count,
                    source_byte_count: event.source_byte_count,
                    diagnostic_count: event.diagnostic_count,
                    warning_count: event.warning_count,
                    language_counts: event.language_counts,
                    stage_timing: event.stage_timing,
                }
            }
            ProjectEvidenceLoadEvent::ProjectEvidenceReady(load) => Self::ProjectEvidenceReady {
                source_inventory: load.source_inventory().clone(),
                accounting: load.accounting().clone(),
            },
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceInventoryMetrics {
    pub total_file_count: u64,
    pub walk_file_count: u64,
    pub walk_inventory_ms: u64,
    pub source_read_file_count: u64,
    pub source_read_byte_count: u64,
    pub native_decode_file_count: u64,
}

struct SourceInventoryRead {
    metrics: SourceInventoryMetrics,
}

struct SourceInventoryPreparation {
    inventory: walk::WalkInventoryOutput,
    walk_file_count: u64,
    walk_inventory_ms: u64,
}

fn prepare_source_inventory(
    root: &Path,
    options: LoadOptions,
    explicit_file_tasks: &[String],
    file_task_admission: walk::FileTaskAdmission,
    deadline: RequestDeadline,
) -> io::Result<SourceInventoryPreparation> {
    let walk_started = Instant::now();
    let inventory = prepare_walk_inventory(
        root,
        options,
        explicit_file_tasks,
        file_task_admission,
        deadline,
    )?;
    let walk_inventory_ms = elapsed_ms(walk_started);
    let walk_file_count = inventory.files.len() as u64;
    Ok(SourceInventoryPreparation {
        inventory,
        walk_file_count,
        walk_inventory_ms,
    })
}
fn prepare_walk_inventory(
    root: &Path,
    options: LoadOptions,
    explicit_file_tasks: &[String],
    file_task_admission: walk::FileTaskAdmission,
    deadline: RequestDeadline,
) -> io::Result<walk::WalkInventoryOutput> {
    let walked = walk::walk_source_inventory_with_canonical_file_tasks_and_deadline(
        root,
        options.analysis_profile,
        options.language.map(LanguageFilter::source_language),
        explicit_file_tasks,
        file_task_admission,
        deadline,
        options.source_inventory_limits,
    )?;
    Ok(filter_walk_inventory_for_options(walked, options))
}

fn filter_walk_inventory_for_options(
    mut walked: walk::WalkInventoryOutput,
    options: LoadOptions,
) -> walk::WalkInventoryOutput {
    if let Some(language) = options.language {
        walked.files.retain(|file| language.matches(file.language));
        let remaining_paths = walked
            .files
            .iter()
            .map(|file| file.rel_path.clone())
            .collect::<HashSet<_>>();
        walked
            .rust_crate_roots
            .retain(|(path, _)| remaining_paths.contains(path));
        walked
            .rust_module_paths
            .retain(|(path, _)| remaining_paths.contains(path));
        walked
            .rust_module_path_aliases
            .retain(|(path, _)| remaining_paths.contains(path));
        walked
            .python_module_paths
            .retain(|(path, _)| remaining_paths.contains(path));
        retain_optional_paths(&mut walked.diagnostic_paths, &remaining_paths);
        retain_optional_paths(&mut walked.render_paths, &remaining_paths);
    }
    walked
}

pub(super) fn build_source_pair_index(pairs: &[(String, Vec<u8>)]) -> BTreeMap<String, usize> {
    pairs
        .iter()
        .enumerate()
        .map(|(index, (path, _))| (path.clone(), index))
        .collect()
}

pub(super) fn build_source_pair_metadata(
    pairs: &[(String, Vec<u8>)],
) -> BTreeMap<String, SourceLookupMetadata> {
    pairs
        .iter()
        .map(|(path, bytes)| {
            (
                path.clone(),
                SourceLookupMetadata {
                    sha256: repotoire::hash::sha256(bytes),
                    content_length: bytes.len() as u64,
                },
            )
        })
        .collect()
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

struct NativeEvidenceLinkPlan<'a> {
    inputs: crate::repository_path::ReadOnlyFiles<'a>,
    captured_filesystem: &'a BTreeMap<String, walk::CapturedFilesystemEntry>,
    source_root: &'a Path,
    files: Vec<&'a NativeEvidenceFile>,
    ts_project_paths: &'a [String],
    captured_inputs: Option<&'a BTreeMap<String, Vec<u8>>>,
    rust_crate_roots: &'a [(String, String)],
    rust_external_crate_bindings: &'a [(String, String)],
    rust_module_paths: &'a [(String, String)],
    rust_module_path_aliases: &'a [(String, String)],
    #[cfg(feature = "python")]
    python_module_paths: &'a [(String, String)],
}

impl<'a> NativeEvidenceLinkPlan<'a> {
    fn from_units(native: &'a NativeEvidenceUnits) -> Self {
        use crate::repository_path::ReadOnlyFiles;
        let inputs = if let Some(files) = &native.captured_inputs {
            ReadOnlyFiles::Captured {
                root: &native.source_root,
                files,
            }
        } else {
            native
                .bounded_inputs
                .as_deref()
                .map_or(ReadOnlyFiles::Repository, ReadOnlyFiles::Bounded)
        };
        Self {
            inputs,
            source_root: &native.source_root,
            files: native.files.iter().collect(),
            ts_project_paths: &native.ts_paths,
            captured_inputs: native.captured_inputs.as_ref(),
            captured_filesystem: &native.captured_filesystem,
            rust_crate_roots: &native.rust_crate_roots,
            rust_external_crate_bindings: &native.rust_external_crate_bindings,
            rust_module_paths: &native.rust_module_paths,
            rust_module_path_aliases: &native.rust_module_path_aliases,
            #[cfg(feature = "python")]
            python_module_paths: &native.python_module_paths,
        }
    }

    fn ts_units(&self) -> Vec<repotoire::ts::NativeEvidenceUnit<'a>> {
        let mut units = Vec::new();
        for file in &self.files {
            if let DecodedNativeEvidenceUnit::TypeScript(parsed_file) = &file.decoded {
                units.push(repotoire::ts::NativeEvidenceUnit {
                    path: file.rel_path.as_str(),
                    bytes: file.bytes.as_slice(),
                    parsed: parsed_file,
                });
            }
        }
        units
    }

    fn rust_units(&self) -> Vec<repotoire::rust::NativeEvidenceUnit<'a>> {
        let mut units = Vec::new();
        for file in &self.files {
            if let DecodedNativeEvidenceUnit::Rust {
                parsed: Some(parsed_file),
                ..
            } = &file.decoded
            {
                units.push(repotoire::rust::NativeEvidenceUnit {
                    path: file.rel_path.as_str(),
                    bytes: file.bytes.as_slice(),
                    parsed: parsed_file,
                });
            }
        }
        units
    }

    fn rust_extract_options(&self) -> repotoire::rust::ExtractOptions {
        let external_crates_by_path = self.rust_external_crate_bindings.iter().cloned().fold(
            BTreeMap::new(),
            |mut by_path, (path, alias)| {
                by_path
                    .entry(path)
                    .or_insert_with(BTreeSet::new)
                    .insert(alias);
                by_path
            },
        );
        repotoire::rust::ExtractOptions {
            edition: repotoire::rust::RustEdition::Edition2015,
            crate_roots: self.rust_crate_roots.iter().cloned().collect(),
            external_crates_by_path,
            module_paths: self.rust_module_paths.iter().cloned().collect(),
            module_path_aliases: self.rust_module_path_aliases.iter().cloned().fold(
                BTreeMap::new(),
                |mut aliases, (path, alias)| {
                    aliases.entry(path).or_insert_with(Vec::new).push(alias);
                    aliases
                },
            ),
        }
    }

    #[cfg(feature = "python")]
    fn python_source_file_count(&self) -> usize {
        self.files
            .iter()
            .filter(|file| file.language == SourceLanguage::Python)
            .count()
    }

    #[cfg(feature = "python")]
    fn python_units(&self) -> Vec<repotoire::python::NativeEvidenceUnit<'a>> {
        let mut units = Vec::new();
        for file in &self.files {
            if let DecodedNativeEvidenceUnit::Python {
                parsed: Some(parsed_file),
                ..
            } = &file.decoded
            {
                units.push(repotoire::python::NativeEvidenceUnit {
                    path: file.rel_path.as_str(),
                    bytes: file.bytes.as_slice(),
                    parsed: parsed_file,
                });
            }
        }
        units
    }

    #[cfg(feature = "python")]
    fn python_extract_options(&self) -> repotoire::python::ExtractOptions {
        repotoire::python::ExtractOptions {
            module_paths: self.python_module_paths.iter().cloned().collect(),
        }
    }

    fn parse_diagnostics(&self) -> impl Iterator<Item = &Diagnostic> {
        self.files.iter().filter_map(|file| match &file.decoded {
            DecodedNativeEvidenceUnit::Rust {
                parse_diagnostic, ..
            } => parse_diagnostic.as_ref(),
            #[cfg(feature = "python")]
            DecodedNativeEvidenceUnit::Python {
                parse_diagnostic, ..
            } => parse_diagnostic.as_ref(),
            DecodedNativeEvidenceUnit::TypeScript(_) => None,
        })
    }
}

struct TypeScriptResolutionUnit {
    rel_path: String,
    bytes: Vec<u8>,
    parsed: repotoire::ts::ParsedFile,
}

impl TypeScriptResolutionUnit {
    fn as_native_unit(&self) -> repotoire::ts::NativeEvidenceUnit<'_> {
        repotoire::ts::NativeEvidenceUnit {
            path: self.rel_path.as_str(),
            bytes: self.bytes.as_slice(),
            parsed: &self.parsed,
        }
    }
}

fn explicit_typescript_resolution_units(
    plan: &NativeEvidenceLinkPlan<'_>,
    deadline: RequestDeadline,
) -> io::Result<Vec<TypeScriptResolutionUnit>> {
    if plan.captured_inputs.is_some() {
        return Ok(Vec::new());
    }

    let mut known_paths = plan
        .ts_project_paths
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for file in &plan.files {
        if matches!(&file.decoded, DecodedNativeEvidenceUnit::TypeScript(_)) {
            known_paths.insert(file.rel_path.as_str());
        }
    }

    let source_files =
        cap_std::fs::Dir::open_ambient_dir(plan.source_root, cap_std::ambient_authority())?;
    let read_source = |path: &Path| {
        if let crate::repository_path::ReadOnlyFiles::Bounded(inputs) = plan.inputs {
            return inputs.read(path).ok().map(|bytes| bytes.to_vec());
        }
        walk::read_admitted_source(
            &source_files,
            plan.source_root,
            path,
            plan.captured_filesystem,
            None,
        )
        .ok()
        .flatten()
    };
    let mut paths =
        tsconfig::explicit_type_package_files(plan.inputs, plan.source_root, read_source);
    paths.extend(tsconfig::explicit_lib_files(
        plan.inputs,
        plan.source_root,
        read_source,
    ));
    paths.sort();
    paths.dedup();

    let mut units = Vec::new();
    for path in paths {
        deadline.check("TypeScript resolution unit")?;
        let Some(rel_path) = source_relative_normal_path(plan.source_root, &path) else {
            continue;
        };
        if known_paths.contains(rel_path.as_str()) {
            continue;
        }
        let bytes = if let crate::repository_path::ReadOnlyFiles::Bounded(inputs) = plan.inputs {
            inputs.read(&path)?.to_vec()
        } else {
            let Some(bytes) = walk::read_admitted_source(
                &source_files,
                plan.source_root,
                &path,
                plan.captured_filesystem,
                None,
            )?
            else {
                continue;
            };
            bytes
        };
        deadline.check("TypeScript resolution parse")?;
        let parsed = repotoire::ts::parse_file(&rel_path, &bytes);
        deadline.check("TypeScript resolution unit completion")?;
        units.push(TypeScriptResolutionUnit {
            rel_path,
            bytes,
            parsed,
        });
    }
    Ok(units)
}

fn source_relative_normal_path(source_root: &Path, path: &Path) -> Option<String> {
    let rel_path = path.strip_prefix(source_root).ok()?;
    if rel_path
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return None;
    }
    Some(rel_path.to_string_lossy().replace('\\', "/"))
}

fn emit_native_evidence_graph(
    builder: &mut GraphBuilder,
    plan: &NativeEvidenceLinkPlan<'_>,
    deadline: RequestDeadline,
) -> io::Result<(Vec<Diagnostic>, Vec<tsconfig::ConfigGap>)> {
    deadline.check("native evidence extraction")?;
    let ts_units = plan.ts_units();
    let resolver_only_ts_units = if ts_units.is_empty() {
        Vec::new()
    } else {
        explicit_typescript_resolution_units(plan, deadline)?
    };
    let resolver_only_ts_unit_refs = resolver_only_ts_units
        .iter()
        .map(TypeScriptResolutionUnit::as_native_unit)
        .collect::<Vec<_>>();
    let rust_units = plan.rust_units();
    #[cfg(feature = "python")]
    let has_non_python_inputs = !ts_units.is_empty() || !rust_units.is_empty();
    let mut diagnostics = Vec::new();
    let mut typescript_configuration_gaps = Vec::new();
    for diagnostic in plan.parse_diagnostics() {
        ensure_diagnostic_capacity(diagnostics.len(), 1, "native parse")?;
        diagnostics.push(diagnostic.clone());
    }

    if !ts_units.is_empty() {
        deadline.check("TypeScript evidence resolution")?;
        let ts_paths = ts_units.iter().map(|unit| unit.path).collect::<Vec<_>>();
        let resolution =
            tsconfig::build_alias_map_for_source_paths(plan.inputs, plan.source_root, &ts_paths);
        ensure_diagnostic_capacity(0, resolution.gaps.len(), "TypeScript configuration")?;
        typescript_configuration_gaps = resolution.gaps;
        let options = repotoire::ts::ExtractOptions {
            alias_map: resolution.alias_map,
            known_project_paths: plan.ts_project_paths.to_vec(),
        };
        let res = repotoire::ts::resolve_native_evidence_units_with_resolver_units(
            builder,
            &ts_units,
            &resolver_only_ts_unit_refs,
            &options,
        )
        .map_err(|e| io::Error::other(format!("typescript extract failed: {e:?}")))?;
        extend_diagnostics_bounded(&mut diagnostics, res.diagnostics, "TypeScript")?;
    }

    if !rust_units.is_empty() {
        deadline.check("Rust evidence resolution")?;
        let rust_options = plan.rust_extract_options();
        let res =
            repotoire::rust::resolve_native_evidence_units(builder, &rust_units, &rust_options)
                .map_err(|e| io::Error::other(format!("rust extract failed: {e:?}")))?;
        extend_diagnostics_bounded(&mut diagnostics, res.diagnostics, "Rust")?;
    }

    #[cfg(feature = "python")]
    if plan.python_source_file_count() > 0 {
        deadline.check("Python evidence resolution")?;
        let python_units = plan.python_units();
        if python_units.is_empty() {
            if !has_non_python_inputs {
                return Err(io::Error::other(
                    "python extract failed: no parseable Python files",
                ));
            }
        } else {
            let python_options = plan.python_extract_options();
            let res = repotoire::python::resolve_native_evidence_units_with_options(
                builder,
                &python_units,
                &python_options,
            )
            .map_err(|e| io::Error::other(format!("python extract failed: {e:?}")))?;
            extend_diagnostics_bounded(&mut diagnostics, res.diagnostics, "Python")?;
        }
    }

    deadline.check("native evidence resolution completion")?;
    Ok((diagnostics, typescript_configuration_gaps))
}

fn extend_diagnostics_bounded(
    diagnostics: &mut Vec<Diagnostic>,
    incoming: Vec<Diagnostic>,
    language: &'static str,
) -> io::Result<()> {
    ensure_diagnostic_capacity(diagnostics.len(), incoming.len(), language)?;
    diagnostics.extend(incoming);
    Ok(())
}

fn ensure_diagnostic_capacity(
    current: usize,
    incoming: usize,
    language: &'static str,
) -> io::Result<()> {
    let total = current
        .checked_add(incoming)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "diagnostic count overflow"))?;
    if total > MAX_CODEBASE_DIAGNOSTICS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{language} extraction produced {total} diagnostics; CodebaseView limit is {MAX_CODEBASE_DIAGNOSTICS}"
            ),
        ));
    }
    Ok(())
}

fn cold_extract_codebase_snapshot(
    _root: &Path,
    options: LoadOptions,
    native: NativeEvidenceUnits,
    deadline: RequestDeadline,
) -> io::Result<CodebaseSnapshot> {
    let source_file_count = native.source_file_count();
    let source_byte_count = native.source_byte_count;
    let analysis_inventory_complete = native.is_full_inventory() && native.walk_degraded_count == 0;
    let source_inventory_deletion_trusted = native.source_inventory_deletion_trusted;
    let language_counts = native.language_counts;
    let skipped_by_extension = native.skipped_by_extension.clone();
    let render_paths = native.render_paths.clone();
    let diagnostic_paths = native.diagnostic_paths.clone();
    let warnings = native.warnings.clone();
    let source_root = native.source_root.clone();
    let source_roles = native.complete_source_roles()?;

    let mut builder = if options.include_source_archive {
        GraphBuilder::new()
    } else {
        GraphBuilder::new_graph_only()
    };
    let (mut diagnostics, typescript_configuration_gaps) = {
        let plan = NativeEvidenceLinkPlan::from_units(&native);
        let diagnostics = emit_native_evidence_graph(&mut builder, &plan, deadline)?;
        plan.inputs.check_limits()?;
        diagnostics
    };
    let (owned_graph, owned_archive) = if options.include_source_archive {
        let (owned_graph, owned_archive) = builder.freeze();
        (owned_graph, Some(owned_archive))
    } else {
        (builder.freeze_graph(), None)
    };

    if let Some(paths) = diagnostic_paths {
        let paths: HashSet<String> = paths.into_iter().collect();
        diagnostics.retain(|diag| paths.contains(&diag.file_path));
    }
    if native.captured_inputs.is_none() {
        walk::suppress_scoped_out_existing_relative_phantoms(&mut diagnostics, &source_root);
    }

    let ts_paths = native.ts_paths.clone();
    let metadata_inputs = native.bounded_inputs.clone();
    let source_pairs = if options.retain_source_pairs || !options.include_source_archive {
        Some(native.into_source_pairs())
    } else {
        None
    };
    let source_pair_index = source_pairs
        .as_ref()
        .map(|pairs| build_source_pair_index(pairs));
    let source_pair_metadata = source_pairs
        .as_ref()
        .map(|pairs| build_source_pair_metadata(pairs));

    Ok(CodebaseSnapshot {
        metadata_inputs,
        owned_graph,
        owned_archive,
        diagnostics,
        typescript_configuration_gaps,
        source_pairs,
        source_pair_index,
        source_pair_metadata,
        source_roles,
        source_file_count,
        source_byte_count,
        ts_paths,
        skipped_by_extension,
        language_counts,
        warnings,
        render_paths,
        analysis_inventory_complete,
        source_inventory_deletion_trusted,
    })
}

fn retain_optional_paths(paths: &mut Option<Vec<String>>, remaining: &HashSet<String>) {
    if let Some(paths) = paths {
        paths.retain(|path| remaining.contains(path));
    }
}
