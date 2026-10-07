use super::{
    LanguageCounts, ProjectEvidenceDeclarationInventory, ProjectEvidenceWorkingSetSummary,
    SourceInventoryMetrics,
};
use crate::repository_path::ReadOnlyFiles;
use crate::walk;
use repotoire::source_pipeline::SourceLanguage;
use repotoire::source_role::{CompleteSourceRoleIndex, SourceRole};
use repotoire::spans::Span;
use repotoire::ts::diagnostics::{Diagnostic, DiagnosticKind};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io;
use std::path::PathBuf;

use crate::deadline::RequestDeadline;

const CONTEXT_ORIENTATION_ENTRY_SEED_LIMIT: usize = 64;
const CONTEXT_ORIENTATION_FALLBACK_SEED_LIMIT: usize = 32;

pub(super) struct NativeEvidenceUnitLoad<'a> {
    pub inventory: walk::WalkInventoryOutput,
    pub load_scope: NativeEvidenceLoadScope,
    pub working_set_extra_paths: &'a HashSet<String>,
    pub metrics: &'a mut SourceInventoryMetrics,
    pub deadline: RequestDeadline,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeEvidenceLoadScope {
    FullInventory,
    ContextOrientationWorkingSet,
    ExactFileWorkingSet,
    CapturedInputs,
}

impl NativeEvidenceLoadScope {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::FullInventory => "full_inventory",
            Self::ContextOrientationWorkingSet => "context_orientation_working_set",
            Self::ExactFileWorkingSet => "exact_file_working_set",
            Self::CapturedInputs => "captured_inputs",
        }
    }

    pub(super) fn stage_classification(self) -> &'static str {
        match self {
            Self::FullInventory => "decoded",
            Self::ContextOrientationWorkingSet => "decoded:context_orientation_working_set",
            Self::ExactFileWorkingSet => "decoded:exact_file_working_set",
            Self::CapturedInputs => "decoded:captured_inputs",
        }
    }
}

pub(super) fn load_native_evidence_units(
    load: NativeEvidenceUnitLoad<'_>,
) -> io::Result<NativeEvidenceUnits> {
    let working_set = NativeEvidenceWorkingSetSelection::from_inventory(
        load.load_scope,
        &load.inventory,
        load.working_set_extra_paths,
    );
    let mut files = Vec::with_capacity(working_set.source_file_count);
    for file in load.inventory.files {
        load.deadline.check("native evidence working set")?;
        if !working_set.includes(&file.rel_path) {
            continue;
        }
        files.push(walk::WalkedFile {
            rel_path: file.rel_path,
            bytes: file.bytes,
            language: file.language,
            source_role: file.source_role,
        });
    }
    let walked = walk::WalkOutput {
        source_root: load.inventory.source_root,
        files,
        rust_crate_roots: working_set.filter_path_pairs(load.inventory.rust_crate_roots),
        rust_external_crate_bindings: working_set
            .filter_path_pairs(load.inventory.rust_external_crate_bindings),
        rust_module_paths: working_set.filter_path_pairs(load.inventory.rust_module_paths),
        rust_module_path_aliases: working_set
            .filter_path_pairs(load.inventory.rust_module_path_aliases),
        python_module_paths: working_set.filter_path_pairs(load.inventory.python_module_paths),
        warnings: load.inventory.warnings,
        diagnostic_paths: working_set.filter_paths(load.inventory.diagnostic_paths),
        render_paths: working_set.filter_paths(load.inventory.render_paths),
        skipped_by_extension: load.inventory.skipped_by_extension,
        walk_degraded_count: load.inventory.walk_degraded_count,
        source_inventory_deletion_trusted: load.inventory.source_inventory_deletion_trusted,
    };
    let bounded_inputs = load.inventory.bounded_inputs;
    let inputs = bounded_inputs
        .as_deref()
        .map_or(ReadOnlyFiles::Repository, ReadOnlyFiles::Bounded);
    let mut native =
        NativeEvidenceUnits::from_walked_with_inputs(walked, load.metrics, load.deadline, inputs)?;
    inputs.check_limits()?;
    native.bounded_inputs = bounded_inputs;
    native.captured_filesystem = load.inventory.captured_filesystem;
    native.load_scope = working_set.load_scope;
    native.inventory_source_file_count = working_set.inventory_source_file_count;
    Ok(native)
}

struct NativeEvidenceWorkingSetSelection {
    load_scope: NativeEvidenceLoadScope,
    rel_paths: Option<BTreeSet<String>>,
    inventory_source_file_count: usize,
    source_file_count: usize,
}

impl NativeEvidenceWorkingSetSelection {
    fn from_inventory(
        requested_scope: NativeEvidenceLoadScope,
        inventory: &walk::WalkInventoryOutput,
        extra_paths: &HashSet<String>,
    ) -> Self {
        let inventory_source_file_count = inventory.files.len();
        let mut selected = match requested_scope {
            NativeEvidenceLoadScope::FullInventory => BTreeSet::new(),
            NativeEvidenceLoadScope::ContextOrientationWorkingSet => {
                context_orientation_working_set_paths(inventory)
            }
            NativeEvidenceLoadScope::CapturedInputs => {
                unreachable!("captured inputs bypass repository inventory")
            }
            NativeEvidenceLoadScope::ExactFileWorkingSet => extra_paths
                .iter()
                .filter(|rel_path| {
                    inventory
                        .files
                        .iter()
                        .any(|file| file.rel_path == rel_path.as_str())
                })
                .cloned()
                .collect(),
        };
        let mut included_extra_paths = false;
        if requested_scope == NativeEvidenceLoadScope::ContextOrientationWorkingSet {
            let inventory_paths = inventory
                .files
                .iter()
                .map(|file| file.rel_path.as_str())
                .collect::<HashSet<_>>();
            let selected_extra_paths = extra_paths
                .iter()
                .filter(|rel_path| inventory_paths.contains(rel_path.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            included_extra_paths = !selected_extra_paths.is_empty();
            selected.extend(selected_extra_paths);
        }
        let selected_is_scoped_view = matches!(
            requested_scope,
            NativeEvidenceLoadScope::ExactFileWorkingSet
                | NativeEvidenceLoadScope::ContextOrientationWorkingSet
        ) && (included_extra_paths
            || requested_scope == NativeEvidenceLoadScope::ExactFileWorkingSet);
        let empty_fallback =
            selected.is_empty() && requested_scope != NativeEvidenceLoadScope::ExactFileWorkingSet;
        let covers_full_unscoped_inventory =
            selected.len() >= inventory_source_file_count && !selected_is_scoped_view;
        let loads_full_inventory = requested_scope == NativeEvidenceLoadScope::FullInventory
            || empty_fallback
            || covers_full_unscoped_inventory;
        let source_file_count = if loads_full_inventory {
            selected.clear();
            inventory_source_file_count
        } else {
            selected.len()
        };
        let load_scope = if selected.is_empty()
            && requested_scope != NativeEvidenceLoadScope::ExactFileWorkingSet
        {
            NativeEvidenceLoadScope::FullInventory
        } else {
            requested_scope
        };
        Self {
            load_scope,
            rel_paths: (requested_scope == NativeEvidenceLoadScope::ExactFileWorkingSet
                || !selected.is_empty())
            .then_some(selected),
            inventory_source_file_count,
            source_file_count,
        }
    }

    fn includes(&self, rel_path: &str) -> bool {
        match &self.rel_paths {
            Some(rel_paths) => rel_paths.contains(rel_path),
            None => true,
        }
    }

    fn filter_path_pairs(&self, pairs: Vec<(String, String)>) -> Vec<(String, String)> {
        match &self.rel_paths {
            Some(rel_paths) => pairs
                .into_iter()
                .filter(|(rel_path, _)| rel_paths.contains(rel_path))
                .collect(),
            None => pairs,
        }
    }

    fn filter_paths(&self, paths: Option<Vec<String>>) -> Option<Vec<String>> {
        match (&self.rel_paths, paths) {
            (Some(rel_paths), Some(paths)) => Some(
                paths
                    .into_iter()
                    .filter(|rel_path| rel_paths.contains(rel_path))
                    .collect(),
            ),
            (_, paths) => paths,
        }
    }
}

pub(super) fn context_orientation_working_set_paths(
    inventory: &walk::WalkInventoryOutput,
) -> BTreeSet<String> {
    let inventory_paths = inventory
        .files
        .iter()
        .map(|file| file.rel_path.as_str())
        .collect::<HashSet<_>>();
    let mut selected = inventory
        .render_paths
        .iter()
        .flat_map(|paths| paths.iter())
        .chain(
            inventory
                .diagnostic_paths
                .iter()
                .flat_map(|paths| paths.iter()),
        )
        .filter(|rel_path| inventory_paths.contains(rel_path.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>();

    let current_product_files = inventory
        .files
        .iter()
        .filter(|file| file.source_role == SourceRole::Product)
        .collect::<Vec<_>>();

    let mut entry_seed = current_product_files
        .iter()
        .filter(|file| !selected.contains(&file.rel_path))
        .filter_map(|file| {
            context_orientation_entry_seed_rank(file)
                .map(|rank| (rank, file.rel_path.as_str(), file.rel_path.clone()))
        })
        .collect::<Vec<_>>();
    entry_seed.sort_by(|(left_rank, left_path, _), (right_rank, right_path, _)| {
        left_rank
            .cmp(right_rank)
            .then_with(|| left_path.cmp(right_path))
    });
    let remaining_entry_seed = CONTEXT_ORIENTATION_ENTRY_SEED_LIMIT.saturating_sub(selected.len());
    selected.extend(
        entry_seed
            .into_iter()
            .take(remaining_entry_seed)
            .map(|(_, _, rel_path)| rel_path),
    );

    if !selected.is_empty() {
        return selected;
    }

    selected.extend(
        current_product_files
            .into_iter()
            .take(CONTEXT_ORIENTATION_FALLBACK_SEED_LIMIT)
            .map(|file| file.rel_path.clone()),
    );
    selected
}

fn context_orientation_entry_seed_rank(file: &walk::WalkedSourceEntry) -> Option<u8> {
    let rel_path = normalize_rel_path(&file.rel_path);
    let file_name = rel_path.rsplit('/').next().unwrap_or(rel_path.as_str());
    let stem = file_name
        .rsplit_once('.')
        .map_or(file_name, |(stem, _)| stem);
    match file.language {
        SourceLanguage::Rust => rust_context_orientation_entry_rank(rel_path.as_str()),
        SourceLanguage::TypeScript => {
            typescript_context_orientation_entry_rank(rel_path.as_str(), stem)
        }
        #[cfg(feature = "python")]
        SourceLanguage::Python => python_context_orientation_entry_rank(file_name, stem),
        #[cfg(not(feature = "python"))]
        SourceLanguage::Python => None,
        SourceLanguage::Unknown => None,
    }
}

fn normalize_rel_path(rel_path: &str) -> String {
    rel_path.replace('\\', "/")
}

fn rust_context_orientation_entry_rank(rel_path: &str) -> Option<u8> {
    if rel_path.ends_with("/src/lib.rs") || rel_path.ends_with("/src/main.rs") {
        return Some(0);
    }
    if rel_path == "src/lib.rs" || rel_path == "src/main.rs" {
        return Some(0);
    }
    if rel_path.contains("/src/bin/") {
        return Some(1);
    }
    if rel_path.ends_with("/mod.rs") {
        return Some(2);
    }
    None
}

fn typescript_context_orientation_entry_rank(rel_path: &str, stem: &str) -> Option<u8> {
    let is_common_entry_name = matches!(
        stem,
        "index" | "main" | "app" | "server" | "cli" | "worker" | "router" | "lib" | "mod"
    );
    if !is_common_entry_name {
        return None;
    }
    let depth = rel_path.matches('/').count();
    if rel_path.starts_with("src/") || rel_path.starts_with("app/") {
        return Some(depth.min(3) as u8);
    }
    if depth <= 1 {
        return Some(3);
    }
    None
}

#[cfg(feature = "python")]
fn python_context_orientation_entry_rank(file_name: &str, stem: &str) -> Option<u8> {
    if matches!(file_name, "__init__.py" | "__main__.py") {
        return Some(0);
    }
    if matches!(stem, "main" | "app" | "server" | "cli" | "worker") {
        return Some(1);
    }
    None
}

#[derive(Debug, Clone)]
pub(super) enum DecodedNativeEvidenceUnit {
    TypeScript(repotoire::ts::ParsedFile),
    Rust {
        parsed: Option<repotoire::rust::ParsedFile>,
        parse_diagnostic: Option<Diagnostic>,
    },
    #[cfg(feature = "python")]
    Python {
        parsed: Option<repotoire::python::ParsedFile>,
        parse_diagnostic: Option<Diagnostic>,
    },
}

pub(super) struct NativeEvidenceFile {
    pub rel_path: String,
    pub bytes: Vec<u8>,
    pub language: SourceLanguage,
    pub source_role: SourceRole,
    pub decoded: DecodedNativeEvidenceUnit,
}

pub(super) struct NativeEvidenceUnits {
    pub captured_filesystem: BTreeMap<String, walk::CapturedFilesystemEntry>,
    pub captured_inputs: Option<BTreeMap<String, Vec<u8>>>,
    pub bounded_inputs: Option<std::sync::Arc<crate::repository_path::BoundedRepositoryFiles>>,
    pub source_root: PathBuf,
    pub files: Vec<NativeEvidenceFile>,
    pub load_scope: NativeEvidenceLoadScope,
    pub inventory_source_file_count: usize,
    pub rust_crate_roots: Vec<(String, String)>,
    pub rust_external_crate_bindings: Vec<(String, String)>,
    pub rust_module_paths: Vec<(String, String)>,
    pub rust_module_path_aliases: Vec<(String, String)>,
    #[cfg(feature = "python")]
    pub python_module_paths: Vec<(String, String)>,
    pub warnings: Vec<String>,
    pub diagnostic_paths: Option<Vec<String>>,
    pub render_paths: Option<Vec<String>>,
    pub skipped_by_extension: BTreeMap<String, u64>,
    /// Carried from the walk: count of entries the walker could not read.
    /// Non-zero means the source inventory is silently truncated; feeds
    /// `CodebaseView.analysis_inventory_complete`.
    pub walk_degraded_count: u32,
    /// Carried from the walk: whether the selected inventory method is stable
    /// enough to support deletion proof. Feeds
    /// `CodebaseView.source_inventory_deletion_trusted`; never affects
    /// completeness or summary serving.
    pub source_inventory_deletion_trusted: bool,
    pub language_counts: LanguageCounts,
    pub source_byte_count: u64,
    pub ts_paths: Vec<String>,
}

impl NativeEvidenceUnits {
    pub(super) fn from_captured(
        source_root: &std::path::Path,
        captured: BTreeMap<String, Vec<u8>>,
        metrics: &mut SourceInventoryMetrics,
    ) -> io::Result<Self> {
        let walked = walk::captured_native_inventory(source_root, &captured)?;
        metrics.total_file_count = captured.len() as u64;
        metrics.source_read_file_count = walked.files.len() as u64;
        metrics.source_read_byte_count = walked
            .files
            .iter()
            .map(|file| file.bytes.len() as u64)
            .sum();
        let mut native = Self::from_walked_with_inputs(
            walked,
            metrics,
            RequestDeadline::unbounded(),
            ReadOnlyFiles::Captured {
                root: source_root,
                files: &captured,
            },
        )?;
        native.load_scope = NativeEvidenceLoadScope::CapturedInputs;
        native.captured_inputs = Some(captured);
        Ok(native)
    }

    #[cfg(test)]
    pub(super) fn from_walked(walked: walk::WalkOutput) -> io::Result<Self> {
        let mut metrics = SourceInventoryMetrics::default();
        Self::from_walked_with_inputs(
            walked,
            &mut metrics,
            RequestDeadline::unbounded(),
            ReadOnlyFiles::Repository,
        )
    }

    fn from_walked_with_inputs(
        walked: walk::WalkOutput,
        metrics: &mut SourceInventoryMetrics,
        deadline: RequestDeadline,
        inputs: ReadOnlyFiles<'_>,
    ) -> io::Result<Self> {
        let walk::WalkOutput {
            source_root,
            files,
            rust_crate_roots,
            rust_external_crate_bindings,
            rust_module_paths,
            rust_module_path_aliases,
            python_module_paths,
            warnings,
            diagnostic_paths,
            render_paths,
            skipped_by_extension,
            walk_degraded_count,
            source_inventory_deletion_trusted,
        } = walked;
        #[cfg(not(feature = "python"))]
        let _ = python_module_paths;
        let files = decode_native_evidence_files(inputs, &source_root, files, metrics, deadline)?;

        let language_counts = language_counts(&files);
        let source_byte_count = files.iter().map(|file| file.bytes.len() as u64).sum();
        let ts_paths = files
            .iter()
            .filter(|file| file.language == SourceLanguage::TypeScript)
            .map(|file| file.rel_path.clone())
            .collect();

        Ok(Self {
            captured_inputs: None,
            bounded_inputs: None,
            captured_filesystem: BTreeMap::new(),
            source_root,
            load_scope: NativeEvidenceLoadScope::FullInventory,
            inventory_source_file_count: files.len(),
            files,
            rust_crate_roots,
            rust_external_crate_bindings,
            rust_module_paths,
            rust_module_path_aliases,
            #[cfg(feature = "python")]
            python_module_paths,
            warnings,
            diagnostic_paths,
            render_paths,
            skipped_by_extension,
            walk_degraded_count,
            source_inventory_deletion_trusted,
            language_counts,
            source_byte_count,
            ts_paths,
        })
    }

    pub(super) fn source_file_count(&self) -> usize {
        self.files.len()
    }

    pub(super) fn is_full_inventory(&self) -> bool {
        self.load_scope == NativeEvidenceLoadScope::FullInventory
    }

    pub(super) fn working_set_summary(&self) -> ProjectEvidenceWorkingSetSummary {
        ProjectEvidenceWorkingSetSummary {
            scope: if self.is_full_inventory() {
                NativeEvidenceLoadScope::FullInventory.as_str().to_string()
            } else {
                self.load_scope.as_str().to_string()
            },
            inventory_source_file_count: self.inventory_source_file_count,
            source_file_count: self.source_file_count(),
            omitted_source_file_count: self
                .inventory_source_file_count
                .saturating_sub(self.source_file_count()),
            full_inventory: self.is_full_inventory(),
        }
    }

    pub(super) fn complete_source_roles(&self) -> io::Result<CompleteSourceRoleIndex> {
        CompleteSourceRoleIndex::from_entries(
            self.files
                .iter()
                .map(|file| (file.rel_path.clone(), file.source_role)),
            self.files.iter().map(|file| file.rel_path.as_str()),
        )
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }

    pub(super) fn declaration_inventory(&self) -> ProjectEvidenceDeclarationInventory {
        let mut inventory = ProjectEvidenceDeclarationInventory::default();
        for file in &self.files {
            let declaration_count = declaration_count_for_decoded(&file.decoded);
            inventory.total_declaration_count += declaration_count;
            *inventory
                .declarations_by_language
                .entry(file.language.canonical_label().to_string())
                .or_insert(0) += declaration_count;
            *inventory
                .declarations_by_source_role
                .entry(file.source_role.as_str().to_string())
                .or_insert(0) += declaration_count;
        }
        inventory
    }

    pub(super) fn into_source_pairs(self) -> Vec<(String, Vec<u8>)> {
        self.files
            .into_iter()
            .map(|file| (file.rel_path, file.bytes))
            .collect()
    }
}

struct DecodedNativeEvidenceFileResult {
    index: usize,
    file: NativeEvidenceFile,
    metrics: SourceInventoryMetrics,
}

fn decode_native_evidence_files(
    inputs: ReadOnlyFiles<'_>,
    source_root: &std::path::Path,
    files: Vec<walk::WalkedFile>,
    metrics: &mut SourceInventoryMetrics,
    deadline: RequestDeadline,
) -> io::Result<Vec<NativeEvidenceFile>> {
    deadline.check("native evidence decode")?;
    let file_count = files.len();
    let worker_count = native_decode_worker_count(file_count);
    if worker_count <= 1 {
        return decode_native_evidence_files_sequential(
            inputs,
            source_root,
            files,
            metrics,
            deadline,
        );
    }

    let mut buckets = (0..worker_count)
        .map(|_| Vec::new())
        .collect::<Vec<Vec<(usize, walk::WalkedFile)>>>();
    for (index, file) in files.into_iter().enumerate() {
        buckets[index % worker_count].push((index, file));
    }

    let mut decoded_batches = Vec::with_capacity(worker_count);
    std::thread::scope(|scope| {
        let handles = buckets
            .into_iter()
            .map(|bucket| {
                scope.spawn(move || {
                    bucket
                        .into_iter()
                        .map(|(index, file)| {
                            deadline.check("native evidence file decode")?;
                            decode_native_evidence_file_result(inputs, source_root, index, file)
                        })
                        .collect::<io::Result<Vec<_>>>()
                })
            })
            .collect::<Vec<_>>();

        for handle in handles {
            let batch = handle
                .join()
                .map_err(|_| io::Error::other("native evidence decode worker panicked"))??;
            decoded_batches.push(batch);
        }
        Ok::<(), io::Error>(())
    })?;

    let mut decoded = (0..file_count).map(|_| None).collect::<Vec<_>>();
    for batch in decoded_batches {
        for result in batch {
            merge_native_decode_metrics(metrics, &result.metrics);
            decoded[result.index] = Some(result.file);
        }
    }
    decoded
        .into_iter()
        .enumerate()
        .map(|(index, file)| {
            file.ok_or_else(|| io::Error::other(format!("native evidence file {index} missing")))
        })
        .collect()
}

fn decode_native_evidence_files_sequential(
    inputs: ReadOnlyFiles<'_>,
    source_root: &std::path::Path,
    files: Vec<walk::WalkedFile>,
    metrics: &mut SourceInventoryMetrics,
    deadline: RequestDeadline,
) -> io::Result<Vec<NativeEvidenceFile>> {
    files
        .into_iter()
        .enumerate()
        .map(|(index, file)| {
            deadline.check("native evidence file decode")?;
            let result = decode_native_evidence_file_result(inputs, source_root, index, file)?;
            merge_native_decode_metrics(metrics, &result.metrics);
            Ok(result.file)
        })
        .collect()
}

fn decode_native_evidence_file_result(
    inputs: ReadOnlyFiles<'_>,
    source_root: &std::path::Path,
    index: usize,
    file: walk::WalkedFile,
) -> io::Result<DecodedNativeEvidenceFileResult> {
    let mut metrics = SourceInventoryMetrics::default();
    let decoded = decode_native_evidence_file(
        inputs,
        &file.rel_path,
        &file.bytes,
        file.language,
        file.source_role,
        source_root,
        &mut metrics,
    )?;
    Ok(DecodedNativeEvidenceFileResult {
        index,
        file: NativeEvidenceFile {
            rel_path: file.rel_path,
            bytes: file.bytes,
            language: file.language,
            source_role: file.source_role,
            decoded,
        },
        metrics,
    })
}

fn native_decode_worker_count(file_count: usize) -> usize {
    if file_count < 16 {
        return 1;
    }
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .clamp(1, file_count)
}

fn merge_native_decode_metrics(
    metrics: &mut SourceInventoryMetrics,
    decoded_metrics: &SourceInventoryMetrics,
) {
    metrics.native_decode_file_count += decoded_metrics.native_decode_file_count;
}

fn decode_native_evidence_file(
    inputs: ReadOnlyFiles<'_>,
    rel_path: &str,
    bytes: &[u8],
    language: SourceLanguage,
    _source_role: SourceRole,
    source_root: &std::path::Path,
    metrics: &mut SourceInventoryMetrics,
) -> io::Result<DecodedNativeEvidenceUnit> {
    let decoded = decode_native_evidence_file_cold(inputs, rel_path, bytes, language, source_root)?;
    metrics.native_decode_file_count += 1;
    Ok(decoded)
}

fn decode_native_evidence_file_cold(
    inputs: ReadOnlyFiles<'_>,
    rel_path: &str,
    bytes: &[u8],
    language: SourceLanguage,
    source_root: &std::path::Path,
) -> io::Result<DecodedNativeEvidenceUnit> {
    match language {
        SourceLanguage::TypeScript => {
            validate_native_evidence_utf8(rel_path, bytes, language)?;
            Ok(DecodedNativeEvidenceUnit::TypeScript(
                repotoire::ts::parse_file(rel_path, bytes),
            ))
        }
        SourceLanguage::Rust => match repotoire::rust::parse_file(
            rel_path,
            bytes,
            repotoire::rust::RustParseOptions {
                edition: walk::rust_edition_from_inputs(inputs, &source_root.join(rel_path))?,
                mode: repotoire::rust::RustParseMode::Complete,
            },
        ) {
            Ok(parsed) => Ok(DecodedNativeEvidenceUnit::Rust {
                parsed: Some(parsed),
                parse_diagnostic: None,
            }),
            Err(
                ref error @ repotoire::rust::RustParseError::Syntax {
                    ref diagnostics, ..
                },
            ) => {
                let span = diagnostics
                    .first()
                    .map_or(Span::new(0, 0), |diagnostic| diagnostic.span);
                Ok(DecodedNativeEvidenceUnit::Rust {
                    parsed: None,
                    parse_diagnostic: Some(Diagnostic {
                        kind: DiagnosticKind::SyntaxRecovered {
                            context: format!("Rust file omitted after syntax error: {error}"),
                        },
                        file_path: rel_path.to_string(),
                        span,
                    }),
                })
            }
            Err(error) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cannot parse Rust file {rel_path}: {error}"),
            )),
        },
        #[cfg(feature = "python")]
        SourceLanguage::Python => {
            let decoded = match repotoire::python::parse_file(rel_path, bytes) {
                Ok(parsed) => DecodedNativeEvidenceUnit::Python {
                    parsed: Some(parsed),
                    parse_diagnostic: None,
                },
                Err(err) => {
                    let span = match &err {
                        repotoire::python::PythonParseError::SourceEncoding {
                            invalid_byte_offset,
                        } => Span::new(u32::try_from(*invalid_byte_offset).unwrap_or(u32::MAX), 0),
                        repotoire::python::PythonParseError::Parse(error) => {
                            Span::new(u32::from(error.offset), 0)
                        }
                    };
                    DecodedNativeEvidenceUnit::Python {
                        parsed: None,
                        parse_diagnostic: Some(Diagnostic {
                            kind: DiagnosticKind::SyntaxRecovered {
                                context: format!("Python file omitted after parse error: {err:?}"),
                            },
                            file_path: rel_path.to_string(),
                            span,
                        }),
                    }
                }
            };
            Ok(decoded)
        }
        #[cfg(not(feature = "python"))]
        SourceLanguage::Python => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Python parser support is not enabled",
        )),
        SourceLanguage::Unknown => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("cannot decode unknown source language for {rel_path}"),
        )),
    }
}

fn validate_native_evidence_utf8(
    rel_path: &str,
    bytes: &[u8],
    language: SourceLanguage,
) -> io::Result<()> {
    std::str::from_utf8(bytes).map(|_| ()).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} native decode failed for {}: invalid UTF-8 at byte {}",
                language.canonical_label(),
                rel_path,
                err.valid_up_to()
            ),
        )
    })
}

fn language_counts(files: &[NativeEvidenceFile]) -> LanguageCounts {
    let mut counts = LanguageCounts::default();
    for file in files {
        match file.language {
            SourceLanguage::TypeScript => counts.typescript += 1,
            SourceLanguage::Rust => counts.rust += 1,
            #[cfg(feature = "python")]
            SourceLanguage::Python => counts.python += 1,
            #[cfg(not(feature = "python"))]
            SourceLanguage::Python => {}
            SourceLanguage::Unknown => {}
        }
    }
    counts
}

fn declaration_count_for_decoded(decoded: &DecodedNativeEvidenceUnit) -> u64 {
    match decoded {
        DecodedNativeEvidenceUnit::TypeScript(parsed) => parsed
            .events
            .iter()
            .filter(|event| matches!(event, repotoire::ts::Event::Decl(_)))
            .count() as u64,
        DecodedNativeEvidenceUnit::Rust { parsed, .. } => parsed
            .as_ref()
            .map(|parsed| rust_item_declaration_count(&parsed.items))
            .unwrap_or(0),
        #[cfg(feature = "python")]
        DecodedNativeEvidenceUnit::Python { parsed, .. } => parsed
            .as_ref()
            .map(|parsed| python_item_declaration_count(&parsed.items))
            .unwrap_or(0),
    }
}

fn rust_item_declaration_count(items: &[repotoire::rust::RustItem]) -> u64 {
    let mut count = 0_u64;
    let mut pending = items.iter().collect::<Vec<_>>();
    while let Some(item) = pending.pop() {
        count = count.saturating_add(1);
        pending.extend(item.children.iter());
    }
    count
}

#[cfg(feature = "python")]
fn python_item_declaration_count(items: &[repotoire::python::PythonItem]) -> u64 {
    items
        .iter()
        .map(|item| 1 + python_item_declaration_count(&item.children))
        .sum()
}
