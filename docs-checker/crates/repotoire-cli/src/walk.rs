pub(crate) use crate::repository_path::RepositoryReadLimit as SourceInventoryLimit;
use crate::repository_path::{BoundedRepositoryFiles, ReadOnlyFiles, RepositoryReadLimits};
pub(crate) mod overlay;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::deadline::RequestDeadline;
use crate::worker_runtime::{run_bounded_command, BoundedProcessOutput, BoundedProcessTermination};

use repotoire::source_pipeline::{
    parser_supports_source_language, source_language_for_path, SourceLanguage,
};
use repotoire::source_role::{SourceRole, SourceRoleFilter};
use repotoire::ts::diagnostics::{Diagnostic, DiagnosticKind};
use repotoire::ts::{Event, ExportEntry, RefEvent};

const MAX_DEPTH: usize = 64;
const MAX_EXPLICIT_FILE_TASKS: usize = 64;
const MAX_EXACT_FILE_CANDIDATES: usize = 4096;
const MAX_EXPLICIT_FILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_EXPLICIT_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_GIT_INVENTORY_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const GIT_INVENTORY_SAFETY_TIMEOUT: Duration = Duration::from_secs(30);
const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "venv",
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AnalysisProfile {
    Product,
    Corpus,
    #[default]
    All,
}

impl AnalysisProfile {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "product" => Some(Self::Product),
            "corpus" => Some(Self::Corpus),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Product => "product",
            Self::Corpus => "corpus",
            Self::All => "all",
        }
    }

    pub fn source_role_filter(self) -> SourceRoleFilter {
        match self {
            Self::Product => SourceRoleFilter::Product,
            Self::Corpus => SourceRoleFilter::Corpus,
            Self::All => SourceRoleFilter::All,
        }
    }

    fn includes(self, role: SourceRole) -> bool {
        self.source_role_filter().includes(role)
    }
}

fn analysis_profile_filter_entry(
    entry: &ignore::DirEntry,
    walk_root: &Path,
    source_root: &Path,
    profile: AnalysisProfile,
    role_policy: &SourceRolePolicy,
) -> bool {
    if !entry
        .file_name()
        .to_str()
        .map(|name| !SKIP_DIRS.contains(&name))
        .unwrap_or(true)
    {
        return false;
    }
    if entry.path() == walk_root {
        return true;
    }
    let Some(file_type) = entry.file_type() else {
        return true;
    };
    if !file_type.is_dir() {
        return true;
    }
    if entry.path() != walk_root && entry.path().join(".git").exists() {
        return false;
    }
    let rel_path = rel_path_from(source_root, entry.path());
    profile_allows_directory_descent(&rel_path, profile, role_policy)
}

fn profile_allows_directory_descent(
    rel_path: &str,
    profile: AnalysisProfile,
    role_policy: &SourceRolePolicy,
) -> bool {
    if profile != AnalysisProfile::Product {
        return true;
    }
    let role = role_policy.role_for_path(rel_path);
    profile.includes(role) || role_policy.has_marker_within(rel_path)
}

pub const SOURCE_ROLE_POLICY_VERSION: &str = "deterministic_inference_v1";

#[derive(Clone, Default)]
struct SourceRolePolicy {
    markers: Vec<SourceRoleMarker>,
    document_sources: Vec<DocumentSourceDeclaration>,
}

#[derive(Clone)]
struct SourceRoleMarker {
    path: String,
    role: SourceRole,
    prefix: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DocumentSourceDeclaration {
    pub path: String,
    pub format: String,
}

pub(crate) fn document_source_declarations(
    inputs: ReadOnlyFiles<'_>,
    source_root: &Path,
) -> Result<(Vec<DocumentSourceDeclaration>, Option<Vec<u8>>), String> {
    let config_path = source_root.join(".repotoire-sources.toml");
    if !inputs.is_file(&config_path) {
        return Ok((Vec::new(), None));
    }
    let body = inputs
        .read_to_string(&config_path)
        .map_err(|error| format!("cannot read {}: {error}", config_path.display()))?;
    let mut config = SourceRolePolicy::default();
    config.extend_from_body(&body, &config_path, &mut Vec::new(), true)?;
    Ok((config.document_sources, Some(body.into_bytes())))
}

fn parse_document_source_declarations(
    value: &toml::Value,
    config_path: &Path,
) -> Result<Vec<DocumentSourceDeclaration>, String> {
    let Some(entries) = value.get("document_source") else {
        return Ok(Vec::new());
    };
    let entries = entries.as_array().ok_or_else(|| {
        format!(
            "{}: `document_source` must be an array of tables",
            config_path.display()
        )
    })?;
    let mut declarations = BTreeMap::<String, String>::new();
    for (index, entry) in entries.iter().enumerate() {
        let entry = entry.as_table().ok_or_else(|| {
            format!(
                "{}: document_source {} must be a table",
                config_path.display(),
                index + 1
            )
        })?;
        if entry.keys().any(|key| key != "path" && key != "format") {
            return Err(format!(
                "{}: document_source {} contains an unknown field",
                config_path.display(),
                index + 1
            ));
        }
        let path = entry
            .get("path")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "{}: document_source {} requires string `path`",
                    config_path.display(),
                    index + 1
                )
            })?;
        let format = entry
            .get("format")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "{}: document_source {} requires string `format`",
                    config_path.display(),
                    index + 1
                )
            })?;
        let path = normalize_document_source_path(path).ok_or_else(|| {
            format!(
                "{}: document_source {} has an invalid repository-relative path",
                config_path.display(),
                index + 1
            )
        })?;
        if !valid_document_source_format(format) {
            return Err(format!(
                "{}: document_source {} has an invalid lowercase format",
                config_path.display(),
                index + 1
            ));
        }
        if let Some(previous) = declarations.insert(path.clone(), format.to_string()) {
            if previous != format {
                return Err(format!(
                    "{}: document source `{path}` has conflicting formats `{previous}` and `{format}`",
                    config_path.display()
                ));
            }
        }
    }
    Ok(declarations
        .into_iter()
        .map(|(path, format)| DocumentSourceDeclaration { path, format })
        .collect())
}

fn normalize_document_source_path(path: &str) -> Option<String> {
    let path = Path::new(path);
    if path.as_os_str().is_empty() || path.is_absolute() {
        return None;
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => parts.push(part.to_str()?.to_string()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if parts.last().is_some_and(|part| part != "..") {
                    parts.pop();
                } else {
                    parts.push("..".to_string());
                }
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn valid_document_source_format(format: &str) -> bool {
    let mut chars = format.chars();
    chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

impl SourceRolePolicy {
    fn load(inputs: ReadOnlyFiles<'_>, source_root: &Path, warnings: &mut Vec<String>) -> Self {
        let mut policy = Self::default();
        for filename in [".repotoire-sources.toml", ".repotoire-source-roles.toml"] {
            let path = source_root.join(filename);
            if !inputs.is_file(&path) {
                continue;
            }
            match inputs.read_to_string(&path) {
                Ok(body) => {
                    let _ = policy.extend_from_body(&body, &path, warnings, false);
                }
                Err(error) => warnings.push(format!(
                    "warning: cannot read source role markers {}: {error}",
                    path.display()
                )),
            }
        }
        policy
    }

    fn extend_from_body(
        &mut self,
        body: &str,
        path: &Path,
        warnings: &mut Vec<String>,
        validate_documents: bool,
    ) -> Result<(), String> {
        let value = match body.parse::<toml::Value>() {
            Ok(value) => value,
            Err(error) if validate_documents => {
                return Err(format!("cannot parse {}: {error}", path.display()));
            }
            Err(_) => {
                warnings.push("warning: cannot parse source role markers".to_string());
                return Ok(());
            }
        };
        self.extend_from_value(&value, warnings);
        if validate_documents {
            self.document_sources = parse_document_source_declarations(&value, path)?;
        }
        Ok(())
    }

    fn extend_from_value(&mut self, value: &toml::Value, warnings: &mut Vec<String>) {
        if let Some(table) = value.get("source_roles").and_then(|value| value.as_table()) {
            for (path, role) in table {
                let Some(role) = role.as_str().and_then(SourceRole::parse) else {
                    warnings.push(format!("warning: unknown source role marker for `{path}`"));
                    continue;
                };
                self.push_marker(path, role);
            }
        }
        if let Some(entries) = value.get("source_role").and_then(|value| value.as_array()) {
            for entry in entries {
                let Some(path) = entry
                    .get("path")
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
                else {
                    warnings.push("warning: source_role marker missing path".to_string());
                    continue;
                };
                let Some(role) = entry
                    .get("role")
                    .and_then(|value| value.as_str())
                    .and_then(SourceRole::parse)
                else {
                    warnings.push(format!("warning: source_role marker `{path}` missing role"));
                    continue;
                };
                self.push_marker(&path, role);
            }
        }
    }

    fn push_marker(&mut self, path: &str, role: SourceRole) {
        let prefix = path.ends_with('/') || path.ends_with("/**") || path.ends_with("/*");
        let path = normalize_marker_path(path);
        if !path.is_empty() {
            self.markers.push(SourceRoleMarker { path, role, prefix });
        }
    }

    fn role_for_path(&self, rel_path: &str) -> SourceRole {
        let rel_path = normalize_marker_path(rel_path);
        let inferred = infer_source_role(&rel_path);
        for marker in &self.markers {
            if marker.prefix {
                if rel_path == marker.path || rel_path.starts_with(&format!("{}/", marker.path)) {
                    return marker.role;
                }
            } else if rel_path == marker.path {
                return marker.role;
            }
        }
        inferred
    }

    fn has_marker_within(&self, rel_path: &str) -> bool {
        let rel_path = normalize_marker_path(rel_path);
        let rel_prefix = format!("{rel_path}/");
        self.markers
            .iter()
            .any(|marker| marker.path == rel_path || marker.path.starts_with(&rel_prefix))
    }
}

pub fn source_role_for_path(
    source_root: &Path,
    rel_path: &str,
    warnings: &mut Vec<String>,
) -> SourceRole {
    SourceRolePolicy::load(ReadOnlyFiles::Repository, source_root, warnings).role_for_path(rel_path)
}

fn normalize_marker_path(path: &str) -> String {
    let mut path = path.replace('\\', "/");
    while let Some(rest) = path.strip_prefix("./") {
        path = rest.to_string();
    }
    if let Some(rest) = path.strip_suffix("/**") {
        path = rest.to_string();
    } else if let Some(rest) = path.strip_suffix("/*") {
        path = rest.to_string();
    }
    path.trim_matches('/').to_string()
}

fn infer_source_role(rel_path: &str) -> SourceRole {
    let components = rel_path
        .split('/')
        .map(|component| component.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let file_name = components.last().map(String::as_str).unwrap_or("");
    if is_generated_path(&components, file_name) {
        return SourceRole::Generated;
    }
    if components.iter().any(|component| {
        matches!(
            component.as_str(),
            "calibration" | "calibrations" | "calibration-samples" | "calibration_samples"
        )
    }) {
        return SourceRole::CalibrationSample;
    }
    if components.iter().any(|component| {
        matches!(
            component.as_str(),
            "corpus"
                | "corpora"
                | "experiment"
                | "experiments"
                | "eval"
                | "evals"
                | "evaluation"
                | "golden"
                | "goldens"
                | "snapshot"
                | "snapshots"
                | "testdata"
                | "test_data"
        )
    }) {
        return SourceRole::Corpus;
    }
    if components.iter().any(|component| {
        matches!(
            component.as_str(),
            "bench" | "benches" | "benchmark" | "benchmarks" | "perf" | "performance"
        )
    }) {
        return SourceRole::Benchmark;
    }
    if components
        .iter()
        .any(|component| is_fixture_component(component))
    {
        return SourceRole::VendorFixture;
    }
    if components.iter().any(|component| {
        matches!(
            component.as_str(),
            "test" | "tests" | "__tests__" | "spec" | "specs"
        )
    }) || file_name.ends_with(".test.ts")
        || file_name.ends_with(".test.tsx")
        || file_name.ends_with(".spec.ts")
        || file_name.ends_with(".spec.tsx")
        || file_name.ends_with("_test.rs")
        || file_name.ends_with("_test.py")
    {
        return SourceRole::ContractTest;
    }
    SourceRole::Product
}

fn is_fixture_component(component: &str) -> bool {
    matches!(
        component,
        "fixture"
            | "fixtures"
            | "__fixtures__"
            | "vendor"
            | "vendors"
            | "node_modules"
            | "third_party"
            | "third-party"
            | "external"
    ) || ["_fixture", "_fixtures", "-fixture", "-fixtures"]
        .iter()
        .any(|suffix| component.ends_with(suffix))
}

fn is_generated_path(components: &[String], file_name: &str) -> bool {
    components.iter().any(|component| {
        matches!(
            component.as_str(),
            "generated" | "__generated__" | "codegen" | "gen" | "autogen"
        )
    }) || file_name.contains(".generated.")
        || file_name.contains(".gen.")
        || file_name.ends_with("_generated.rs")
        || file_name.ends_with("_generated.py")
        || file_name.ends_with(".pb.rs")
}

pub struct WalkedFile {
    pub rel_path: String,
    pub bytes: Vec<u8>,
    pub language: SourceLanguage,
    pub source_role: SourceRole,
}

/// Construct the native inventory without discovering or reopening any file.
/// Path-based native resolution remains available; project discovery is absent.
pub(crate) fn captured_native_inventory(
    root: &Path,
    captured: &BTreeMap<String, Vec<u8>>,
) -> io::Result<WalkOutput> {
    let inputs = ReadOnlyFiles::Captured {
        root,
        files: captured,
    };
    let mut warnings = vec![
        "Admitted input snapshot only: unadmitted configuration, declarations and dependencies are unavailable; unresolved results do not establish absence.".to_string(),
    ];
    let mut roles = SourceRolePolicy::default();
    for filename in [".repotoire-sources.toml", ".repotoire-source-roles.toml"] {
        if inputs.is_file(&root.join(filename)) {
            let body = inputs.read_to_string(&root.join(filename))?;
            let value = body
                .parse::<toml::Value>()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            roles.extend_from_value(&value, &mut warnings);
        }
    }
    let mut files = Vec::new();
    let mut total_bytes = 0usize;
    let mut rust_external_crate_bindings = Vec::new();
    for (rel_path, bytes) in captured {
        crate::repository_path::relative(rel_path)?;
        let language = source_language_for_path(Path::new(rel_path));
        if !parser_supports_source_language(language) {
            continue;
        }
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("captured source byte count overflow"))?;
        if bytes.len() > MAX_EXPLICIT_FILE_BYTES
            || total_bytes > MAX_EXPLICIT_TOTAL_BYTES
            || files.len() >= MAX_EXACT_FILE_CANDIDATES
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "captured sources exceed exact-file count or byte limits",
            ));
        }
        if language == SourceLanguage::Rust {
            if let Some(manifest) = nearest_cargo_manifest(inputs, &root.join(rel_path)) {
                let info = cargo_manifest_info(&inputs.read_to_string(&manifest)?);
                for alias in
                    resolved_cargo_dependencies(inputs, &manifest, &info)?.external_dependencies
                {
                    rust_external_crate_bindings.push((rel_path.clone(), alias));
                }
            }
        }
        files.push(WalkedFile {
            rel_path: rel_path.clone(),
            bytes: bytes.clone(),
            language,
            source_role: roles.role_for_path(rel_path),
        });
    }
    if files
        .iter()
        .any(|file| file.language == SourceLanguage::Rust)
    {
        warnings.push("Captured Rust resolution uses admitted Cargo editions and external dependency names with source-path module identities; Cargo target/module-path overrides and path-dependency discovery are excluded.".to_string());
    }
    #[cfg(feature = "python")]
    if files
        .iter()
        .any(|file| file.language == SourceLanguage::Python)
    {
        warnings.push("Captured Python resolution uses source-path module identities; project import-root and workspace discovery are excluded.".to_string());
    }
    Ok(WalkOutput {
        source_root: root.to_path_buf(),
        files,
        rust_crate_roots: Vec::new(),
        rust_external_crate_bindings,
        rust_module_paths: Vec::new(),
        rust_module_path_aliases: Vec::new(),
        python_module_paths: Vec::new(),
        warnings,
        diagnostic_paths: None,
        render_paths: None,
        skipped_by_extension: BTreeMap::new(),
        walk_degraded_count: 0,
        source_inventory_deletion_trusted: false,
    })
}

pub struct WalkOutput {
    pub source_root: PathBuf,
    pub files: Vec<WalkedFile>,
    pub rust_crate_roots: Vec<(String, String)>,
    /// Exact `(source graph path, Cargo crate alias)` bindings. Keeping the
    /// source path in the authority record prevents one workspace package
    /// from lending its dependencies to another package.
    pub rust_external_crate_bindings: Vec<(String, String)>,
    pub rust_module_paths: Vec<(String, String)>,
    pub rust_module_path_aliases: Vec<(String, String)>,
    pub python_module_paths: Vec<(String, String)>,
    /// One human-readable line per entry the walker could not read.
    /// The caller (CLI main) emits these to stderr so partial-read failures
    /// remain visible — narrows the spec's "unreadable inputs exit 2" to
    /// "unreadable inputs are reported; whole-walk success otherwise."
    pub warnings: Vec<String>,
    /// When present, callers should emit diagnostics only for these graph paths.
    /// Single-file context loads an import closure for resolution, but its
    /// diagnostic surface remains scoped to the requested file.
    pub diagnostic_paths: Option<Vec<String>>,
    /// When present, callers should render only these graph paths. Single-file
    /// context uses the import closure for resolution without promoting
    /// dependency files into the requested file's output body.
    pub render_paths: Option<Vec<String>>,
    /// Count of files seen on disk that LOOK like source (a recognized
    /// programming-language extension) but were skipped because repotoire has
    /// no analyzer for them — unsupported languages (`.go`, `.rb`, `.java`,
    /// …) and, when the Python feature is off, `.py`. Keyed by lowercase
    /// extension without the dot. This is the loud-coverage signal: a polyglot
    /// repo no longer looks fully covered just because the walker silently
    /// dropped everything it could not parse. Non-source files (`.md`,
    /// `.json`, `.css`, …) are deliberately excluded — they are not a
    /// code-graph coverage gap.
    pub skipped_by_extension: BTreeMap<String, u64>,
    /// Count of walk entries the walker could not read (structured twin of
    /// the "warning: cannot read" warnings; feeds
    /// `CodebaseView.analysis_inventory_complete`).
    pub walk_degraded_count: u32,
    /// Whether this inventory's enumeration method is stable enough for
    /// deletion-STALE promotion. The Git-aware inventory is trusted only when
    /// its Git fast path ran or the root is not a Git worktree. Rule D
    /// separately confirms that the candidate path is absent from disk before
    /// promoting it. Consumed only at the checkpoint evidence boundary — never
    /// affects summary serving.
    pub source_inventory_deletion_trusted: bool,
}

#[derive(Clone)]
pub struct WalkedSourceEntry {
    pub rel_path: String,
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub language: SourceLanguage,
    pub source_role: SourceRole,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CapturedFilesystemEntry {
    RegularFile(Option<Vec<u8>>),
    Directory,
    Symlink,
    Other,
    Unreadable(io::ErrorKind),
}

#[derive(Clone)]
pub struct WalkInventoryOutput {
    pub source_root: PathBuf,
    pub files: Vec<WalkedSourceEntry>,
    pub(crate) captured_filesystem: BTreeMap<String, CapturedFilesystemEntry>,
    inventory_limits: Option<SourceInventoryLimits>,
    pub(crate) bounded_inputs: Option<std::sync::Arc<BoundedRepositoryFiles>>,
    pub rust_crate_roots: Vec<(String, String)>,
    pub rust_external_crate_bindings: Vec<(String, String)>,
    pub rust_module_paths: Vec<(String, String)>,
    pub rust_module_path_aliases: Vec<(String, String)>,
    pub python_module_paths: Vec<(String, String)>,
    pub warnings: Vec<String>,
    pub diagnostic_paths: Option<Vec<String>>,
    pub render_paths: Option<Vec<String>>,
    pub skipped_by_extension: BTreeMap<String, u64>,
    pub metrics: WalkInventoryMetrics,
    pub walk_degraded_count: u32,
    /// See `WalkOutput::source_inventory_deletion_trusted`.
    pub source_inventory_deletion_trusted: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalkInventoryMetrics {
    pub rust_target_alias_scan_ms: u64,
    pub rust_target_alias_file_count: u64,
    pub git_inventory_ms: u64,
    pub git_inventory_candidate_count: u64,
    pub git_inventory_file_count: u64,
    pub git_inventory_used_count: u64,
    pub source_read_file_count: u64,
    pub source_read_byte_count: u64,
}

impl WalkInventoryOutput {
    pub fn into_walk_output(self) -> WalkOutput {
        let files = self
            .files
            .into_iter()
            .map(|file| WalkedFile {
                rel_path: file.rel_path,
                bytes: file.bytes,
                language: file.language,
                source_role: file.source_role,
            })
            .collect();
        WalkOutput {
            source_root: self.source_root,
            files,
            rust_crate_roots: self.rust_crate_roots,
            rust_external_crate_bindings: self.rust_external_crate_bindings,
            rust_module_paths: self.rust_module_paths,
            rust_module_path_aliases: self.rust_module_path_aliases,
            python_module_paths: self.python_module_paths,
            warnings: self.warnings,
            diagnostic_paths: self.diagnostic_paths,
            render_paths: self.render_paths,
            skipped_by_extension: self.skipped_by_extension,
            walk_degraded_count: self.walk_degraded_count,
            source_inventory_deletion_trusted: self.source_inventory_deletion_trusted,
        }
    }
}

#[derive(Default)]
struct CargoRustContext {
    crate_roots: Vec<(String, String)>,
    path_dependencies: Vec<CargoPathDependency>,
}

struct CargoPathDependency {
    alias: String,
    manifest_dir: PathBuf,
}

struct CargoManifestInfo {
    crate_name: Option<String>,
    lib_path: Option<String>,
    path_dependencies: Vec<(String, String)>,
    workspace_path_dependencies: Vec<(String, String)>,
    workspace_dependency_aliases: Vec<String>,
    workspace_inherited_dependencies: Vec<String>,
    external_dependencies: Vec<String>,
    package_workspace: Option<String>,
    has_workspace: bool,
    targets: Vec<CargoTargetInfo>,
}

struct CargoTargetInfo {
    kind: String,
    name: Option<String>,
    path: Option<String>,
}

struct RustClosureFile {
    path: PathBuf,
    bytes: Vec<u8>,
    module_path: Option<String>,
}

pub fn walk_ts(root: &Path) -> io::Result<WalkOutput> {
    walk_sources_with(root, false, AnalysisProfile::All)
}

pub(crate) fn walk_ts_until(root: &Path, deadline: RequestDeadline) -> io::Result<WalkOutput> {
    Ok(walk_source_inventory_with(
        root,
        false,
        AnalysisProfile::All,
        None,
        None,
        deadline,
        None,
    )?
    .into_walk_output())
}

pub fn walk_sources(root: &Path) -> io::Result<WalkOutput> {
    walk_sources_with(root, true, AnalysisProfile::All)
}

pub fn walk_sources_with_profile(root: &Path, profile: AnalysisProfile) -> io::Result<WalkOutput> {
    walk_sources_with(root, true, profile)
}

pub fn walk_source_inventory_with_profile(
    root: &Path,
    profile: AnalysisProfile,
) -> io::Result<WalkInventoryOutput> {
    walk_source_inventory_with(
        root,
        true,
        profile,
        None,
        None,
        RequestDeadline::unbounded(),
        None,
    )
}

pub(crate) fn walk_source_inventory_with_canonical_file_tasks_and_deadline(
    root: &Path,
    profile: AnalysisProfile,
    language: Option<SourceLanguage>,
    explicit_file_tasks: &[String],
    file_task_admission: FileTaskAdmission,
    deadline: RequestDeadline,
    limits: Option<SourceInventoryLimits>,
) -> io::Result<WalkInventoryOutput> {
    let mut out = walk_source_inventory_with(
        root,
        true,
        profile,
        language,
        (file_task_admission == FileTaskAdmission::ReferenceCandidates)
            .then_some(explicit_file_tasks),
        deadline,
        limits,
    )?;
    if file_task_admission == FileTaskAdmission::RequiredFiles {
        append_explicit_file_tasks(
            &mut out,
            profile,
            language,
            explicit_file_tasks,
            file_task_admission,
            deadline,
        )?;
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileTaskAdmission {
    RequiredFiles,
    ReferenceCandidates,
}

pub(crate) fn canonical_explicit_file_task(target: &str) -> io::Result<String> {
    let canonical = repotoire::impact::evidence::canonical_rel_path(target).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("explicit file task is outside the admissible repository surface: {target}"),
        )
    })?;
    let relative = Path::new(&canonical);
    if relative.components().count() > MAX_DEPTH || path_has_skipped_component(relative) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("explicit file task is outside the admissible repository surface: {target}"),
        ));
    }
    Ok(canonical)
}

pub(crate) fn canonical_explicit_file_tasks<T: AsRef<str>>(
    targets: &[T],
) -> io::Result<Vec<String>> {
    canonical_file_candidates(targets, MAX_EXPLICIT_FILE_TASKS, "explicit file-task")
}

pub(crate) fn canonical_exact_file_candidates<T: AsRef<str>>(
    targets: &[T],
) -> io::Result<Vec<String>> {
    canonical_file_candidates(targets, MAX_EXACT_FILE_CANDIDATES, "exact file-candidate")
}

fn canonical_file_candidates<T: AsRef<str>>(
    targets: &[T],
    max_candidates: usize,
    candidate_kind: &str,
) -> io::Result<Vec<String>> {
    let mut canonical = BTreeSet::new();
    for target in targets {
        canonical.insert(canonical_explicit_file_task(target.as_ref())?);
        if canonical.len() > max_candidates {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{candidate_kind} count exceeds the {max_candidates}-path limit"),
            ));
        }
    }
    Ok(canonical.into_iter().collect())
}

pub fn walk_source_fingerprint_files(root: &Path) -> io::Result<Vec<(String, Vec<u8>)>> {
    crate::deadline::ObservationScope::check_current("source observation")?;
    let root_canon = root.canonicalize()?;
    let root_md = fs::metadata(&root_canon)?;
    if !root_md.is_dir() {
        if parser_supports_source_language(source_language_for_path(&root_canon)) {
            let source_root = root_canon.parent().unwrap_or(&root_canon);
            return Ok(vec![(
                rel_path_from(source_root, &root_canon),
                fs::read(&root_canon)?,
            )]);
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is not a supported source file or directory",
                root_canon.display()
            ),
        ));
    }

    let mut files = Vec::new();
    let mut builder = ignore::WalkBuilder::new(&root_canon);
    builder
        .add_custom_ignore_filename(".repotoireignore")
        .follow_links(true)
        .hidden(true)
        .max_depth(Some(MAX_DEPTH))
        .parents(true)
        .filter_entry(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| !SKIP_DIRS.contains(&name))
                .unwrap_or(true)
        });

    for result in builder.build() {
        crate::deadline::ObservationScope::check_current("source observation")?;
        let entry = result.map_err(|error| io::Error::other(error.to_string()))?;
        let path = entry.path();
        if path == root_canon {
            continue;
        }
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() || !parser_supports_source_language(source_language_for_path(path))
        {
            continue;
        }
        let path_canon = path.canonicalize()?;
        files.push((rel_path_from(&root_canon, &path_canon), fs::read(path)?));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

pub fn source_language_presence(root: &Path) -> io::Result<BTreeSet<&'static str>> {
    crate::deadline::ObservationScope::check_current("source observation")?;
    let root_canon = root.canonicalize()?;
    let root_md = fs::metadata(&root_canon)?;
    let mut languages = BTreeSet::new();
    if !root_md.is_dir() {
        insert_source_language_presence(&mut languages, &root_canon);
        if languages.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is not a supported source file or directory",
                    root_canon.display()
                ),
            ));
        }
        return Ok(languages);
    }

    let mut builder = ignore::WalkBuilder::new(&root_canon);
    builder
        .add_custom_ignore_filename(".repotoireignore")
        .follow_links(true)
        .hidden(true)
        .max_depth(Some(MAX_DEPTH))
        .parents(true)
        .filter_entry(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| !SKIP_DIRS.contains(&name))
                .unwrap_or(true)
        });

    for result in builder.build() {
        crate::deadline::ObservationScope::check_current("source observation")?;
        let entry = result.map_err(|error| io::Error::other(error.to_string()))?;
        let path = entry.path();
        if path == root_canon {
            continue;
        }
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_file() {
            insert_source_language_presence(&mut languages, path);
        }
    }
    Ok(languages)
}

fn walk_sources_with(
    root: &Path,
    include_rust: bool,
    profile: AnalysisProfile,
) -> io::Result<WalkOutput> {
    Ok(walk_source_inventory_with(
        root,
        include_rust,
        profile,
        None,
        None,
        crate::deadline::ObservationScope::deadline_current(),
        None,
    )?
    .into_walk_output())
}

fn walk_source_inventory_with(
    root: &Path,
    include_rust: bool,
    profile: AnalysisProfile,
    language_filter: Option<SourceLanguage>,
    reference_targets: Option<&[String]>,
    deadline: RequestDeadline,
    limits: Option<SourceInventoryLimits>,
) -> io::Result<WalkInventoryOutput> {
    crate::deadline::ObservationScope::check_current("source inventory start")?;
    deadline.check("source inventory start")?;
    let root_canon = root.canonicalize()?;
    let root_md = fs::metadata(&root_canon)?;
    if !root_md.is_dir() {
        if limits.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bounded inventory requires a repository directory",
            ));
        }
        deadline.check("single-file source inventory")?;
        // Single-file invocation: dispatch by canonical source identity.
        if source_language_for_path(&root_canon) == SourceLanguage::TypeScript {
            let output = walk_single_file_import_closure(&root_canon, deadline)
                .map(inventory_from_walk_output)?;
            deadline.check("single-file TypeScript inventory")?;
            return Ok(output);
        }
        if include_rust && source_language_for_path(&root_canon) == SourceLanguage::Rust {
            let output = walk_single_rust_file_module_closure(&root_canon, deadline)
                .map(inventory_from_walk_output)?;
            deadline.check("single-file Rust inventory")?;
            return Ok(output);
        }
        #[cfg(feature = "python")]
        if include_rust && source_language_for_path(&root_canon) == SourceLanguage::Python {
            let output =
                walk_single_python_file(&root_canon, deadline).map(inventory_from_walk_output)?;
            deadline.check("single-file Python inventory")?;
            return Ok(output);
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is not a supported source file or directory",
                root_canon.display()
            ),
        ));
    }
    let rust_scope = if include_rust && reference_targets.is_none() {
        rust_directory_crate_scope(&root_canon)?
    } else {
        None
    };
    let cargo_scope = if include_rust && reference_targets.is_none() && rust_scope.is_none() {
        rust_directory_cargo_scope(&root_canon)?
    } else {
        None
    };
    let (walk_root, source_root, render_scope) = if let Some(crate_src_root) = rust_scope {
        (
            crate_src_root.clone(),
            crate_src_root,
            Some(root_canon.clone()),
        )
    } else if let Some(crate_root) = cargo_scope {
        (crate_root.clone(), crate_root, Some(root_canon.clone()))
    } else {
        (root_canon.clone(), root_canon.clone(), None)
    };
    let bounded_inputs = limits
        .map(|_| {
            BoundedRepositoryFiles::new(&source_root, RepositoryReadLimits::COLLECTION_METADATA)
                .map(std::sync::Arc::new)
        })
        .transpose()?;
    let inputs = bounded_inputs
        .as_deref()
        .map_or(ReadOnlyFiles::Repository, ReadOnlyFiles::Bounded);
    let cargo_context = if include_rust {
        rust_cargo_context_for_source_root(inputs, &source_root)?
    } else {
        CargoRustContext::default()
    };
    let source_files =
        cap_std::fs::Dir::open_ambient_dir(&source_root, cap_std::ambient_authority())?;
    let mut out = WalkInventoryOutput {
        source_root: source_root.clone(),
        files: Vec::new(),
        captured_filesystem: BTreeMap::new(),
        inventory_limits: limits,
        bounded_inputs: bounded_inputs.clone(),
        rust_crate_roots: cargo_context.crate_roots,
        rust_external_crate_bindings: Vec::new(),
        rust_module_paths: Vec::new(),
        rust_module_path_aliases: Vec::new(),
        python_module_paths: Vec::new(),
        warnings: Vec::new(),
        diagnostic_paths: None,
        render_paths: None,
        skipped_by_extension: BTreeMap::new(),
        metrics: WalkInventoryMetrics::default(),
        walk_degraded_count: 0,
        source_inventory_deletion_trusted: false,
    };
    // Optional reference admission precedes every ordinary source read. The
    // captured result owns both bytes and rejection reasons for this load.
    if let Some(targets) = reference_targets {
        append_explicit_file_tasks(
            &mut out,
            profile,
            language_filter,
            targets,
            FileTaskAdmission::ReferenceCandidates,
            deadline,
        )?;
    }
    let role_policy = SourceRolePolicy::load(inputs, &source_root, &mut out.warnings);
    let mut render_paths: Vec<String> =
        out.files.iter().map(|file| file.rel_path.clone()).collect();
    let mut seen_paths: BTreeSet<PathBuf> =
        out.files.iter().map(|file| file.path.clone()).collect();
    let filter_walk_root = walk_root.clone();
    let filter_source_root = source_root.clone();
    let filter_containment_root = source_root.clone();
    let filter_role_policy = role_policy.clone();
    let git_root = git_worktree_root(&source_root, deadline)?;
    let mut git_out = out.clone();
    let mut git_render_paths = render_paths.clone();
    let mut git_seen_paths = seen_paths.clone();
    let used_git_inventory = try_git_source_inventory(
        &mut git_out,
        git_root.as_deref(),
        &source_root,
        &walk_root,
        &root_canon,
        include_rust,
        language_filter,
        profile,
        &role_policy,
        render_scope.as_deref(),
        &mut git_render_paths,
        &mut git_seen_paths,
        &source_files,
        deadline,
    )?;
    if used_git_inventory {
        out = git_out;
        render_paths = git_render_paths;
        seen_paths = git_seen_paths;
    }
    // The Git-aware lane is deletion-trusted only when its Git fast path ran or
    // the root is not a Git worktree; otherwise its fallback can disagree with
    // a prior Git inventory about tracked-but-ignored files.
    //
    // KNOWN CONFLATION (Codex finding-3, follow-up carded): `git_root.is_none()`
    // treats "confirmed non-git root" and "git discovery FAILED" (e.g.
    // `git_worktree_root` could not stat `.git` and `git rev-parse` errored ⇒
    // `Ok(None)`) identically, so a failed discovery is wrongly counted as
    // deletion-trusted. This can no longer produce a false STALE on its own:
    // rule D's D-gone check (`checkpoint::rule_d_or_unverifiable`) independently
    // confirms the anchor path is absent from disk before promoting, so an
    // intact-but-filtered file can never STALE regardless of this trust
    // misclassification. The tri-state (Confirmed-non-git vs Unknown) hardening
    // is tracked separately; D-gone bounds its blast radius until then.
    out.source_inventory_deletion_trusted = used_git_inventory || git_root.is_none();
    let policy_inputs = limits.map(|_| {
        ignore::gitignore::PolicyInputObservations::bounded(
            4 * 1024 * 1024,
            32 * 1024 * 1024,
            10_000,
        )
    });
    if !used_git_inventory {
        let mut builder = ignore::WalkBuilder::new(&walk_root);
        if let Some(observations) = &policy_inputs {
            builder.observe_policy_inputs(observations.clone());
        }
        builder
            .add_custom_ignore_filename(".repotoireignore")
            .follow_links(true)
            .hidden(true)
            .max_depth(Some(MAX_DEPTH))
            .parents(true)
            .filter_entry(move |entry| {
                analysis_profile_filter_entry(
                    entry,
                    &filter_walk_root,
                    &filter_source_root,
                    profile,
                    &filter_role_policy,
                ) && entry
                    .path()
                    .canonicalize()
                    .is_ok_and(|path| path.starts_with(&filter_containment_root))
            });

        for (entries, result) in builder.build().enumerate() {
            if limits.is_some_and(|limit| entries as u64 >= limit.files.saturating_mul(10)) {
                return Err(io::Error::other(SourceInventoryLimit(
                    "source traversal entries",
                )));
            }
            crate::deadline::ObservationScope::check_current("source inventory")?;
            deadline.check("source inventory traversal")?;
            let entry = match result {
                Ok(entry) => entry,
                Err(e) => {
                    out.warnings.push(format!("warning: cannot read {e}"));
                    out.walk_degraded_count += 1;
                    continue;
                }
            };
            let path = entry.path();
            if path == walk_root {
                continue;
            }
            let rel = rel_path_from(&source_root, path);
            if matches!(out.captured_filesystem.get(&rel), Some(entry) if !matches!(entry, CapturedFilesystemEntry::RegularFile(None)))
            {
                continue;
            }
            let Some(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_file() {
                continue;
            }
            let language = source_language_for_path(path);
            if language == SourceLanguage::Unknown {
                if let Some(ext) = unsupported_source_extension(path) {
                    *out.skipped_by_extension.entry(ext).or_insert(0) += 1;
                }
                continue;
            }
            if !parser_supports_source_language(language) {
                if let Some(ext) = path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .map(str::to_ascii_lowercase)
                {
                    *out.skipped_by_extension.entry(ext).or_insert(0) += 1;
                }
                continue;
            }
            if !include_rust && language != SourceLanguage::TypeScript {
                continue;
            }
            if !source_language_matches_filter(language, language_filter) {
                continue;
            }
            if render_scope.is_some()
                && language != SourceLanguage::Rust
                && !path.starts_with(&root_canon)
            {
                continue;
            }
            let source_role = role_policy.role_for_path(&rel);
            if !profile.includes(source_role) {
                continue;
            }
            let path_canon = path.canonicalize()?;
            if !path_canon.starts_with(&source_root) {
                continue;
            }
            let Some(bytes) = read_admitted_source(
                &source_files,
                &source_root,
                &path_canon,
                &out.captured_filesystem,
                out.inventory_limits
                    .map(|limit| limit.read_limit(&out.metrics))
                    .transpose()?,
            )?
            else {
                continue;
            };
            record_source_read(&mut out.metrics, &bytes);
            seen_paths.insert(path_canon.clone());
            if render_scope
                .as_ref()
                .map(|scope| path.starts_with(scope))
                .unwrap_or(true)
            {
                render_paths.push(rel.clone());
            }
            out.files.push(WalkedSourceEntry {
                rel_path: rel,
                path: path_canon,
                bytes,
                language,
                source_role,
            });
        }
    }
    let include_typescript =
        source_language_matches_filter(SourceLanguage::TypeScript, language_filter);
    deadline.check("source inventory resolution files")?;
    let added_lib_resolution_files = if include_typescript {
        append_explicit_lib_entries(
            &mut out,
            &source_root,
            &source_files,
            &mut seen_paths,
            profile,
            &role_policy,
            deadline,
        )?
    } else {
        false
    };
    let added_type_resolution_files = if include_typescript {
        append_explicit_type_package_entries(
            &mut out,
            &source_root,
            &source_files,
            &mut seen_paths,
            profile,
            &role_policy,
            deadline,
        )?
    } else {
        false
    };
    let added_resolution_files = if include_rust {
        append_rust_cargo_target_module_overrides_inventory(
            &mut out,
            &source_root,
            &seen_paths,
            deadline,
        )?;
        append_rust_path_dependency_entries(
            &mut out,
            &source_root,
            &source_files,
            &cargo_context.path_dependencies,
            &mut seen_paths,
            profile,
            &role_policy,
            deadline,
        )?
    } else {
        false
    };
    #[cfg(feature = "python")]
    if source_language_matches_filter(SourceLanguage::Python, language_filter) {
        populate_python_module_paths_inventory(&mut out, deadline)?;
    }
    out.files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    out.rust_module_paths.sort();
    out.rust_module_paths.dedup();
    out.rust_module_path_aliases.sort();
    out.rust_module_path_aliases.dedup();
    let added_resolution_only_files =
        added_resolution_files || added_type_resolution_files || added_lib_resolution_files;
    if render_scope.is_some() || added_resolution_only_files {
        render_paths.sort();
        render_paths.dedup();
        if added_resolution_only_files && out.diagnostic_paths.is_none() {
            out.diagnostic_paths = Some(render_paths.clone());
        }
        out.render_paths = Some(render_paths);
    }
    populate_rust_external_crate_bindings_inventory(&mut out, deadline)?;
    inputs.check_limits()?;
    if let Some(observations) = policy_inputs {
        observations
            .snapshot()
            .map_err(|reason| io::Error::other(SourceInventoryLimit(reason)))?;
    }
    deadline.check("source inventory completion")?;
    Ok(out)
}

fn inventory_from_walk_output(out: WalkOutput) -> WalkInventoryOutput {
    let metrics = WalkInventoryMetrics {
        source_read_file_count: out.files.len() as u64,
        source_read_byte_count: out.files.iter().map(|file| file.bytes.len() as u64).sum(),
        ..WalkInventoryMetrics::default()
    };
    let source_root = out.source_root;
    let files = out
        .files
        .into_iter()
        .map(|file| WalkedSourceEntry {
            path: source_root.join(&file.rel_path),
            rel_path: file.rel_path,
            bytes: file.bytes,
            language: file.language,
            source_role: file.source_role,
        })
        .collect();
    WalkInventoryOutput {
        source_root,
        files,
        captured_filesystem: BTreeMap::new(),
        inventory_limits: None,
        bounded_inputs: None,
        rust_crate_roots: out.rust_crate_roots,
        rust_external_crate_bindings: out.rust_external_crate_bindings,
        rust_module_paths: out.rust_module_paths,
        rust_module_path_aliases: out.rust_module_path_aliases,
        python_module_paths: out.python_module_paths,
        warnings: out.warnings,
        diagnostic_paths: out.diagnostic_paths,
        render_paths: out.render_paths,
        skipped_by_extension: out.skipped_by_extension,
        metrics,
        walk_degraded_count: out.walk_degraded_count,
        source_inventory_deletion_trusted: out.source_inventory_deletion_trusted,
    }
}

#[allow(clippy::too_many_arguments)]
fn try_git_source_inventory(
    out: &mut WalkInventoryOutput,
    git_root: Option<&Path>,
    source_root: &Path,
    walk_root: &Path,
    request_root: &Path,
    include_rust: bool,
    language_filter: Option<SourceLanguage>,
    profile: AnalysisProfile,
    role_policy: &SourceRolePolicy,
    render_scope: Option<&Path>,
    render_paths: &mut Vec<String>,
    seen_paths: &mut BTreeSet<PathBuf>,
    source_files: &cap_std::fs::Dir,
    deadline: RequestDeadline,
) -> io::Result<bool> {
    let started = Instant::now();
    // `git_root` is hoisted to the caller so the I2 method-trust gate can
    // reuse the same worktree observation without a second git spawn.
    let Some(git_root) = git_root else {
        return Ok(false);
    };
    if !source_root.starts_with(git_root) || !walk_root.starts_with(git_root) {
        return Ok(false);
    }
    let mut command = Command::new("git");
    command
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(git_root);
    let output = match bounded_git_inventory_query(&mut command, deadline, "Git source inventory")?
    {
        Some(output) if output.status.success() => output,
        _ => return Ok(false),
    };
    // The fast path may only be trusted when enumeration was verifiably
    // noise-free: `git ls-files --others` warns on stderr and still exits 0
    // when it cannot read a directory, silently omitting the untracked files
    // under it. Any stderr ⇒ fall back to the filesystem walker, which
    // counts that degradation in `walk_degraded_count` (worst case is a
    // slower, truthful walk).
    if !output.stderr.iter().all(u8::is_ascii_whitespace) {
        return Ok(false);
    }

    let mut overlay = overlay::OverlayPolicy::new(walk_root, deadline)?;
    out.metrics.git_inventory_used_count = 1;
    let mut seen_git_paths = BTreeSet::new();
    for record in output.stdout.split(|byte| *byte == 0) {
        deadline.check("Git source inventory decoding")?;
        if record.is_empty() {
            continue;
        }
        let Ok(git_rel_text) = std::str::from_utf8(record) else {
            return Ok(false);
        };
        out.metrics.git_inventory_candidate_count += 1;
        let git_rel = Path::new(git_rel_text);
        if !seen_git_paths.insert(git_rel.to_path_buf()) {
            continue;
        }
        // Shared with `walk_universe_admits_rel_path` (the coherence-universe
        // predicate in_flight.rs consumes) — one composition, so the two can
        // never drift apart.
        if !walk_universe_admits_path_shape(git_rel) {
            continue;
        }
        let path = git_root.join(git_rel);
        if !path.starts_with(walk_root) || !path.starts_with(source_root) {
            continue;
        }
        // The language leg of the universe filter. `walk_universe_admits_rel_path`
        // pairs this same `source_language_for_path` call with the shape check above, so
        // consumers that must reproduce this universe (in_flight.rs's coherence
        // gates) ask ONE predicate rather than re-deriving these two rules.
        // Kept inline here rather than delegated because only this site owns the
        // `skipped_by_extension` bookkeeping in the reject branch.
        let language = source_language_for_path(git_rel);
        if language == SourceLanguage::Unknown {
            if let Some(ext) = unsupported_source_extension(git_rel) {
                *out.skipped_by_extension.entry(ext).or_insert(0) += 1;
            }
            continue;
        }
        if !parser_supports_source_language(language) {
            if let Some(ext) = git_rel
                .extension()
                .and_then(|extension| extension.to_str())
                .map(str::to_ascii_lowercase)
            {
                *out.skipped_by_extension.entry(ext).or_insert(0) += 1;
            }
            continue;
        }
        if !include_rust && language != SourceLanguage::TypeScript {
            continue;
        }
        if !source_language_matches_filter(language, language_filter) {
            continue;
        }
        if render_scope.is_some()
            && language != SourceLanguage::Rust
            && !path.starts_with(request_root)
        {
            continue;
        }
        // Excluded source roles cannot make their policies or file state a
        // prerequisite for this inventory. Explicit role markers still apply.
        let rel = rel_path_from(source_root, &path);
        if matches!(out.captured_filesystem.get(&rel), Some(entry) if !matches!(entry, CapturedFilesystemEntry::RegularFile(None)))
        {
            continue;
        }
        let source_role = role_policy.role_for_path(&rel);
        if !profile.includes(source_role) {
            continue;
        }
        // Git owns completeness; the overlay only filters its candidates.
        // In particular, do not reapply .gitignore to tracked sources.
        if !overlay.admits(&path, deadline)? {
            continue;
        }
        match fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => continue,
            Err(_) => return Ok(false),
        };
        let path_canon = match classify_filesystem_entry(&path) {
            CapturedFilesystemEntry::Symlink | CapturedFilesystemEntry::Unreadable(_) => {
                path.canonicalize()?
            }
            _ => path.clone(),
        };
        seen_paths.insert(path_canon.clone());
        if render_scope
            .map(|scope| path.starts_with(scope))
            .unwrap_or(true)
        {
            render_paths.push(rel.clone());
        }
        out.metrics.git_inventory_file_count += 1;
        let Some(bytes) = read_admitted_source(
            source_files,
            source_root,
            &path_canon,
            &out.captured_filesystem,
            out.inventory_limits
                .map(|limit| limit.read_limit(&out.metrics))
                .transpose()?,
        )?
        else {
            continue;
        };
        record_source_read(&mut out.metrics, &bytes);
        out.files.push(WalkedSourceEntry {
            rel_path: rel,
            path: path_canon,
            bytes,
            language,
            source_role,
        });
    }
    out.metrics.git_inventory_ms = elapsed_ms(started);
    Ok(true)
}

fn git_worktree_root(root: &Path, deadline: RequestDeadline) -> io::Result<Option<PathBuf>> {
    if let Some(root) = crate::provenance::git_worktree_root_no_spawn(root) {
        return Ok(Some(root));
    }
    let mut command = Command::new("git");
    command
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(root);
    let output =
        match bounded_git_inventory_query(&mut command, deadline, "Git worktree discovery")? {
            Some(output) if output.status.success() => output,
            _ => return Ok(None),
        };
    let root = String::from_utf8(output.stdout)
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .map(PathBuf::from);
    root.map(|root| root.canonicalize().or(Ok(root)))
        .transpose()
}

fn source_root_has_repotoireignore_overlay(
    git_root: &Path,
    source_root: &Path,
    deadline: RequestDeadline,
) -> io::Result<bool> {
    let mut overlay = overlay::OverlayPolicy::new(source_root, deadline)?;
    if overlay.present {
        return Ok(true);
    }
    let mut command = Command::new("git");
    command
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(git_root);
    let output = match bounded_git_inventory_query(
        &mut command,
        deadline,
        "RepoToire ignore-overlay discovery",
    )? {
        Some(output)
            if output.status.success() && output.stderr.iter().all(u8::is_ascii_whitespace) =>
        {
            output
        }
        _ => return Ok(true),
    };
    for record in output.stdout.split(|byte| *byte == 0) {
        deadline.check("RepoToire ignore-overlay decoding")?;
        if record.is_empty() {
            continue;
        }
        let Ok(text) = std::str::from_utf8(record) else {
            return Ok(true);
        };
        let rel = Path::new(text);
        if !walk_universe_admits_rel_path(rel) {
            continue;
        }
        let path = git_root.join(rel);
        if !path.starts_with(source_root) {
            continue;
        }
        overlay.admits(&path, deadline)?;
        if overlay.present {
            return Ok(true);
        }
    }
    Ok(false)
}

fn bounded_git_inventory_query(
    command: &mut Command,
    deadline: RequestDeadline,
    operation: &'static str,
) -> io::Result<Option<BoundedProcessOutput>> {
    let timeout = deadline.subprocess_timeout(operation, GIT_INVENTORY_SAFETY_TIMEOUT)?;
    match run_bounded_command(command, MAX_GIT_INVENTORY_OUTPUT_BYTES, timeout) {
        Ok(output) => match output.termination {
            BoundedProcessTermination::Exited => Ok(Some(output)),
            BoundedProcessTermination::TimedOut => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("query deadline expired during {operation}"),
            )),
            BoundedProcessTermination::Cancelled => Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!("{operation} was cancelled"),
            )),
            BoundedProcessTermination::OutputLimit => Ok(None),
        },
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn source_language_matches_filter(
    language: SourceLanguage,
    language_filter: Option<SourceLanguage>,
) -> bool {
    language_filter
        .map(|requested| requested == language)
        .unwrap_or(true)
}

/// The path-SHAPE half of the git fast path's universe filter, factored out
/// so the fast path and any other consumer that must reproduce
/// `walk_sources`' universe share ONE composition rather than two that can
/// drift apart. Rejects absolute/`..`-bearing paths, anything under a
/// [`SKIP_DIRS`] component, and anything under a dot-directory.
pub(crate) fn walk_universe_admits_path_shape(path: &Path) -> bool {
    is_normal_relative_path(path)
        && !path_has_skipped_component(path)
        && !path_has_hidden_component(path)
}

/// Whether `walk_sources` would ENUMERATE `git_rel` (a repo-root-relative
/// path) at all — i.e. whether it is inside the COHERENCE UNIVERSE that a
/// working-tree hash covers.
///
/// This is deliberately the same shape filter the git fast path applies
/// (`walk_universe_admits_path_shape`) PLUS the same language acceptance
/// (`source_language_for_path`), calling those functions rather than restating their
/// rules, so there is exactly one definition of each. Being listed by
/// `git ls-files --cached --others --exclude-standard` is NECESSARY but not
/// SUFFICIENT: `package.json`, `.mts`/`.cts`, `.internal/api.ts` and a
/// committed `build/gen.ts` are all ls-files-visible and all walk-INVISIBLE.
///
/// **Path relativity is the caller's contract.** `git_rel` must be relative
/// to the SAME origin the walk's `rel_path` values use. Two facts make that
/// non-obvious: `git ls-files` emits paths relative to its working directory
/// (which coincides with repo-relative only when that directory is the
/// worktree TOP), and `walk_sources` derives `rel_path` from its `source_root`
/// (which coincides with the repo root except when a Cargo/crate scope moves
/// it). Callers today run against lane worktree tops, where all three
/// coincide; a caller elsewhere must normalize before asking.
///
/// Language coverage is the walk's own, so it is NOT TypeScript-only:
/// `walk_sources` passes `include_rust = true`, and `source_language` maps
/// `.rs` to `SourceLanguage::Rust` (and `.py` to Python under the `python`
/// feature) — so this admits every language a working-tree hash covers.
///
/// Known non-coverage, safe in the narrowing direction only: this does not
/// evaluate `AnalysisProfile`/`SourceRole` admission or a Cargo/crate render
/// scope. `walk_sources` uses `AnalysisProfile::All` (admits every role) and
/// resolves a render scope only for Rust crate roots, whereas the consumers
/// of this predicate resolve TS-family re-export targets and `.ts`/`.rs`
/// relevant files — so neither can narrow the universe further underneath it
/// today. A caller in a different position must re-check that before relying
/// on this.
pub(crate) fn walk_universe_admits_rel_path(git_rel: &Path) -> bool {
    walk_universe_admits_path_shape(git_rel)
        && parser_supports_source_language(source_language_for_path(git_rel))
}

/// Whether custom policy can narrow the source universe. Predicate-only
/// consumers must still apply path policy through `OverlayPolicy` or withhold
/// speculative support. Discovery shares the inventory's policy owner,
/// including parent policies and policy files that Git itself ignores.
pub(crate) fn repotoireignore_overlay_present(root: &Path) -> io::Result<bool> {
    let deadline = RequestDeadline::new(Instant::now(), GIT_INVENTORY_SAFETY_TIMEOUT);
    let root_canon = root.canonicalize()?;
    match git_worktree_root(&root_canon, deadline)? {
        Some(git_root) if root_canon.starts_with(&git_root) => {
            source_root_has_repotoireignore_overlay(&git_root, &root_canon, deadline)
        }
        // No Git universe is available for a predicate-only reconstruction.
        _ => Ok(true),
    }
}

fn is_normal_relative_path(path: &Path) -> bool {
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn path_has_skipped_component(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .map(|name| SKIP_DIRS.contains(&name))
            .unwrap_or(false)
    })
}

fn path_has_hidden_component(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .map(|name| name.starts_with('.') && name != "." && name != "..")
            .unwrap_or(false)
    })
}

fn classify_filesystem_entry(path: &Path) -> CapturedFilesystemEntry {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                CapturedFilesystemEntry::Symlink
            } else if file_type.is_file() {
                CapturedFilesystemEntry::RegularFile(None)
            } else if file_type.is_dir() {
                CapturedFilesystemEntry::Directory
            } else {
                CapturedFilesystemEntry::Other
            }
        }
        Err(error) => CapturedFilesystemEntry::Unreadable(error.kind()),
    }
}

fn record_captured_entry(
    captured: &mut BTreeMap<String, CapturedFilesystemEntry>,
    path: String,
    observed: CapturedFilesystemEntry,
) {
    match captured.entry(path) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(observed);
        }
        std::collections::btree_map::Entry::Occupied(mut entry)
            if matches!(entry.get(), CapturedFilesystemEntry::RegularFile(None))
                && matches!(observed, CapturedFilesystemEntry::RegularFile(Some(_))) =>
        {
            entry.insert(observed);
        }
        std::collections::btree_map::Entry::Occupied(_) => {}
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SourceInventoryLimits {
    pub files: u64,
    pub file_bytes: u64,
    pub total_bytes: u64,
}

impl SourceInventoryLimits {
    fn read_limit(self, metrics: &WalkInventoryMetrics) -> io::Result<u64> {
        if metrics.source_read_file_count >= self.files {
            return Err(io::Error::other(SourceInventoryLimit("source file count")));
        }
        Ok(self.file_bytes.min(
            self.total_bytes
                .saturating_sub(metrics.source_read_byte_count),
        ))
    }
}

pub(crate) fn read_admitted_source(
    source_files: &cap_std::fs::Dir,
    source_root: &Path,
    canonical_path: &Path,
    captured: &BTreeMap<String, CapturedFilesystemEntry>,
    max_bytes: Option<u64>,
) -> io::Result<Option<Vec<u8>>> {
    let Ok(relative_path) = canonical_path.strip_prefix(source_root) else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "source path is outside the admitted root: {}",
                canonical_path.display()
            ),
        ));
    };
    if relative_path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "an admitted source must name a file below the source root",
        ));
    }
    match captured.get(&relative_path.to_string_lossy().replace('\\', "/")) {
        Some(CapturedFilesystemEntry::RegularFile(Some(bytes))) => {
            if max_bytes.is_some_and(|limit| bytes.len() as u64 > limit) {
                return Err(io::Error::other(SourceInventoryLimit("source bytes")));
            }
            Ok(Some(bytes.clone()))
        }
        Some(CapturedFilesystemEntry::RegularFile(None)) | None => {
            if let Some(limit) = max_bytes {
                use std::io::Read;
                let mut bytes = Vec::new();
                source_files
                    .open(relative_path)?
                    .take(limit.saturating_add(1))
                    .read_to_end(&mut bytes)?;
                if bytes.len() as u64 > limit {
                    return Err(io::Error::other(SourceInventoryLimit("source bytes")));
                }
                Ok(Some(bytes))
            } else {
                source_files.read(relative_path).map(Some)
            }
        }
        Some(_) => Ok(None),
    }
}

fn record_source_read(metrics: &mut WalkInventoryMetrics, bytes: &[u8]) {
    metrics.source_read_file_count += 1;
    metrics.source_read_byte_count += bytes.len() as u64;
}

/// Capture references and their path ancestors. Bounded collections fail on a
/// byte limit; optional-reference views retain InvalidData as negative evidence.
/// Repeating that observation detects a candidate becoming admissible.
pub(crate) fn capture_reference_candidates(
    root: &Path,
    targets: &[String],
    deadline: RequestDeadline,
    limits: Option<SourceInventoryLimits>,
) -> io::Result<BTreeMap<String, CapturedFilesystemEntry>> {
    let directory = cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())?;
    let mut captured = BTreeMap::new();
    let capture_limits = limits.unwrap_or(SourceInventoryLimits {
        files: u64::MAX,
        file_bytes: MAX_EXPLICIT_FILE_BYTES as u64,
        total_bytes: MAX_EXPLICIT_TOTAL_BYTES as u64,
    });
    let mut metrics = WalkInventoryMetrics::default();
    for target in targets {
        deadline.check("reference candidate capture")?;
        let relative = Path::new(target);
        let mut ancestors = relative
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
            .collect::<Vec<_>>();
        ancestors.reverse();
        let mut blocked = None;
        for ancestor in ancestors {
            let observed = classify_filesystem_entry(&root.join(ancestor));
            let safe = matches!(observed, CapturedFilesystemEntry::Directory);
            let error = match &observed {
                CapturedFilesystemEntry::Unreadable(error) => *error,
                _ => io::ErrorKind::PermissionDenied,
            };
            record_captured_entry(
                &mut captured,
                ancestor
                    .to_string_lossy()
                    .replace(std::path::MAIN_SEPARATOR, "/"),
                observed,
            );
            if !safe {
                blocked = Some(error);
                break;
            }
        }
        let observed = if let Some(error) = blocked {
            CapturedFilesystemEntry::Unreadable(error)
        } else {
            let path = root.join(relative);
            match classify_filesystem_entry(&path) {
                CapturedFilesystemEntry::RegularFile(_) => {
                    let read = (|| -> io::Result<Vec<u8>> {
                        // Opening through the capability prevents an ancestor race
                        // from escaping the root. Never read an unbounded file.
                        let file = directory.open(relative)?;
                        let length = file.metadata()?.len();
                        let read_limit = capture_limits.read_limit(&metrics)?;
                        if length > read_limit {
                            return Err(io::Error::other(SourceInventoryLimit("reference bytes")));
                        }
                        let mut bytes = Vec::new();
                        file.take(read_limit.saturating_add(1))
                            .read_to_end(&mut bytes)?;
                        if bytes.len() as u64 > read_limit {
                            return Err(io::Error::other(SourceInventoryLimit("reference bytes")));
                        }
                        // A concurrent symlink replacement is never admitted.
                        if path.canonicalize()? != path || !fs::symlink_metadata(&path)?.is_file() {
                            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                        }
                        Ok(bytes)
                    })();
                    match read {
                        Ok(bytes) => {
                            record_source_read(&mut metrics, &bytes);
                            CapturedFilesystemEntry::RegularFile(Some(bytes))
                        }
                        Err(error)
                            if error
                                .get_ref()
                                .is_some_and(|cause| cause.is::<SourceInventoryLimit>()) =>
                        {
                            if limits.is_some() {
                                return Err(error);
                            }
                            CapturedFilesystemEntry::Unreadable(io::ErrorKind::InvalidData)
                        }
                        Err(error) => CapturedFilesystemEntry::Unreadable(error.kind()),
                    }
                }
                observed => observed,
            }
        };
        record_captured_entry(&mut captured, target.clone(), observed);
    }
    Ok(captured)
}

fn append_explicit_file_tasks(
    out: &mut WalkInventoryOutput,
    profile: AnalysisProfile,
    language_filter: Option<SourceLanguage>,
    explicit_file_tasks: &[String],
    file_task_admission: FileTaskAdmission,
    deadline: RequestDeadline,
) -> io::Result<()> {
    if file_task_admission == FileTaskAdmission::ReferenceCandidates {
        let captured = capture_reference_candidates(
            &out.source_root,
            explicit_file_tasks,
            deadline,
            out.inventory_limits,
        )?;
        let role_policy = SourceRolePolicy::load(
            out.bounded_inputs
                .as_deref()
                .map_or(ReadOnlyFiles::Repository, ReadOnlyFiles::Bounded),
            &out.source_root,
            &mut out.warnings,
        );
        for target in explicit_file_tasks {
            let Some(CapturedFilesystemEntry::RegularFile(Some(bytes))) = captured.get(target)
            else {
                continue;
            };
            let language = source_language_for_path(Path::new(target));
            let source_role = role_policy.role_for_path(target);
            if parser_supports_source_language(language)
                && source_language_matches_filter(language, language_filter)
                && profile.includes(source_role)
            {
                if let Some(limit) = out.inventory_limits {
                    if bytes.len() as u64 > limit.read_limit(&out.metrics)? {
                        return Err(io::Error::other(SourceInventoryLimit("source bytes")));
                    }
                }
                record_source_read(&mut out.metrics, bytes);
                out.files.push(WalkedSourceEntry {
                    rel_path: target.clone(),
                    path: out.source_root.join(target),
                    bytes: bytes.clone(),
                    language,
                    source_role,
                });
            }
        }
        out.captured_filesystem.extend(captured);
        out.files
            .sort_by(|left, right| left.rel_path.cmp(&right.rel_path));
        return Ok(());
    }
    let source_root = out.source_root.clone();
    let source_files =
        cap_std::fs::Dir::open_ambient_dir(&source_root, cap_std::ambient_authority())?;
    let inputs = out
        .bounded_inputs
        .as_deref()
        .map_or(ReadOnlyFiles::Repository, ReadOnlyFiles::Bounded);
    let role_policy = SourceRolePolicy::load(inputs, &source_root, &mut out.warnings);
    let mut admitted_bytes = 0usize;

    'targets: for target in explicit_file_tasks {
        deadline.check("explicit file-task admission")?;
        let relative = Path::new(target);
        debug_assert!(is_normal_relative_path(relative));
        debug_assert!(relative.components().count() <= MAX_DEPTH);
        debug_assert!(!path_has_skipped_component(relative));

        if out.files.iter().any(|file| file.rel_path == *target) {
            continue;
        }

        let mut ancestors = relative.ancestors().skip(1).collect::<Vec<_>>();
        ancestors.reverse();
        for ancestor in ancestors {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            let observed = classify_filesystem_entry(&source_root.join(ancestor));
            match observed {
                CapturedFilesystemEntry::Directory => {}
                CapturedFilesystemEntry::Unreadable(io::ErrorKind::NotFound) => continue,
                CapturedFilesystemEntry::Unreadable(error) => {
                    record_captured_entry(
                        &mut out.captured_filesystem,
                        target.clone(),
                        CapturedFilesystemEntry::Unreadable(error),
                    );
                    out.warnings.push(format!(
                        "warning: cannot read explicit file task `{target}`: {error}"
                    ));
                    out.walk_degraded_count += 1;
                    continue 'targets;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("explicit file task crosses an unsafe ancestor: {target}"),
                    ));
                }
            }
            record_captured_entry(
                &mut out.captured_filesystem,
                rel_path_from(&source_root, &source_root.join(ancestor)),
                observed,
            );
        }

        let path = source_root.join(relative);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                record_captured_entry(
                    &mut out.captured_filesystem,
                    target.clone(),
                    CapturedFilesystemEntry::Unreadable(error.kind()),
                );
                out.warnings.push(format!(
                    "warning: cannot read explicit file task `{target}`: {error}"
                ));
                out.walk_degraded_count += 1;
                continue;
            }
        };
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("explicit file task must name a regular file: {target}"),
            ));
        }
        if metadata.len() > MAX_EXPLICIT_FILE_BYTES as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "explicit file task exceeds the {MAX_EXPLICIT_FILE_BYTES}-byte limit: {target}"
                ),
            ));
        }
        let canonical = path.canonicalize()?;
        if !canonical.starts_with(&source_root) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("explicit file task escapes the repository root: {target}"),
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        source_files
            .open(relative)?
            .take(MAX_EXPLICIT_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_EXPLICIT_FILE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "explicit file task exceeds the {MAX_EXPLICIT_FILE_BYTES}-byte limit: {target}"
                ),
            ));
        }
        admitted_bytes = admitted_bytes.checked_add(bytes.len()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "explicit file-task byte count overflow",
            )
        })?;
        if admitted_bytes > MAX_EXPLICIT_TOTAL_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "explicit file tasks exceed the {MAX_EXPLICIT_TOTAL_BYTES}-byte total limit"
                ),
            ));
        }
        record_captured_entry(
            &mut out.captured_filesystem,
            target.clone(),
            CapturedFilesystemEntry::RegularFile(Some(bytes.clone())),
        );
        out.warnings.push(format!(
            "explicit selection override admitted `{target}` outside default discovery"
        ));

        let source_language = source_language_for_path(relative);
        if !parser_supports_source_language(source_language)
            || !source_language_matches_filter(source_language, language_filter)
        {
            continue;
        }
        let source_role = role_policy.role_for_path(target);
        if !profile.includes(source_role) {
            continue;
        }
        record_source_read(&mut out.metrics, &bytes);
        out.files.push(WalkedSourceEntry {
            rel_path: target.clone(),
            path: canonical,
            bytes,
            language: source_language,
            source_role,
        });
    }
    out.files
        .sort_by(|left, right| left.rel_path.cmp(&right.rel_path));
    Ok(())
}

fn append_explicit_type_package_entries(
    out: &mut WalkInventoryOutput,
    source_root: &Path,
    source_files: &cap_std::fs::Dir,
    seen_paths: &mut BTreeSet<PathBuf>,
    profile: AnalysisProfile,
    role_policy: &SourceRolePolicy,
    deadline: RequestDeadline,
) -> io::Result<bool> {
    let mut added = false;
    let mut limit_error = None;
    let bounded_inputs = out.bounded_inputs.clone();
    let inputs = bounded_inputs
        .as_deref()
        .map_or(ReadOnlyFiles::Repository, ReadOnlyFiles::Bounded);
    let paths = crate::tsconfig::explicit_type_package_files(inputs, source_root, |path| {
        if let Some(inputs) = &bounded_inputs {
            return inputs.read(path).ok().map(|bytes| bytes.to_vec());
        }
        let max_bytes = out.inventory_limits.map(|limit| limit.file_bytes);
        match read_admitted_source(
            source_files,
            source_root,
            path,
            &out.captured_filesystem,
            max_bytes,
        ) {
            Ok(bytes) => bytes,
            Err(error) => {
                if error
                    .get_ref()
                    .is_some_and(|error| error.is::<SourceInventoryLimit>())
                {
                    limit_error = Some(error);
                }
                None
            }
        }
    });
    if let Some(error) = limit_error {
        return Err(error);
    }
    for path in paths {
        deadline.check("TypeScript type package inventory")?;
        if matches!(out.captured_filesystem.get(&rel_path_from(source_root, &path)),
            Some(entry) if !matches!(entry, CapturedFilesystemEntry::RegularFile(None)))
        {
            continue;
        }
        let path_canon = path.canonicalize()?;
        let rel_path = rel_path_from(source_root, &path_canon);
        let source_role = role_policy.role_for_path(&rel_path);
        if !profile.includes(source_role) {
            continue;
        }
        if !seen_paths.insert(path_canon.clone()) {
            continue;
        }
        let Some(bytes) = read_admitted_source(
            source_files,
            source_root,
            &path_canon,
            &out.captured_filesystem,
            out.inventory_limits
                .map(|limit| limit.read_limit(&out.metrics))
                .transpose()?,
        )?
        else {
            continue;
        };
        record_source_read(&mut out.metrics, &bytes);
        out.files.push(WalkedSourceEntry {
            source_role,
            rel_path,
            bytes,
            path: path_canon,
            language: SourceLanguage::TypeScript,
        });
        added = true;
    }
    Ok(added)
}

fn append_explicit_lib_entries(
    out: &mut WalkInventoryOutput,
    source_root: &Path,
    source_files: &cap_std::fs::Dir,
    seen_paths: &mut BTreeSet<PathBuf>,
    profile: AnalysisProfile,
    role_policy: &SourceRolePolicy,
    deadline: RequestDeadline,
) -> io::Result<bool> {
    let mut added = false;
    let mut limit_error = None;
    let bounded_inputs = out.bounded_inputs.clone();
    let inputs = bounded_inputs
        .as_deref()
        .map_or(ReadOnlyFiles::Repository, ReadOnlyFiles::Bounded);
    let paths = crate::tsconfig::explicit_lib_files(inputs, source_root, |path| {
        if let Some(inputs) = &bounded_inputs {
            return inputs.read(path).ok().map(|bytes| bytes.to_vec());
        }
        let max_bytes = out.inventory_limits.map(|limit| limit.file_bytes);
        match read_admitted_source(
            source_files,
            source_root,
            path,
            &out.captured_filesystem,
            max_bytes,
        ) {
            Ok(bytes) => bytes,
            Err(error) => {
                if error
                    .get_ref()
                    .is_some_and(|error| error.is::<SourceInventoryLimit>())
                {
                    limit_error = Some(error);
                }
                None
            }
        }
    });
    if let Some(error) = limit_error {
        return Err(error);
    }
    for path in paths {
        deadline.check("TypeScript lib inventory")?;
        if matches!(out.captured_filesystem.get(&rel_path_from(source_root, &path)),
            Some(entry) if !matches!(entry, CapturedFilesystemEntry::RegularFile(None)))
        {
            continue;
        }
        let path_canon = path.canonicalize()?;
        let rel_path = rel_path_from(source_root, &path_canon);
        let source_role = role_policy.role_for_path(&rel_path);
        if !profile.includes(source_role) {
            continue;
        }
        if !seen_paths.insert(path_canon.clone()) {
            continue;
        }
        let Some(bytes) = read_admitted_source(
            source_files,
            source_root,
            &path_canon,
            &out.captured_filesystem,
            out.inventory_limits
                .map(|limit| limit.read_limit(&out.metrics))
                .transpose()?,
        )?
        else {
            continue;
        };
        record_source_read(&mut out.metrics, &bytes);
        out.files.push(WalkedSourceEntry {
            source_role,
            rel_path,
            bytes,
            path: path_canon,
            language: SourceLanguage::TypeScript,
        });
        added = true;
    }
    Ok(added)
}

fn rust_crate_aliases_for_source_root(source_root: &Path) -> io::Result<Vec<(String, String)>> {
    Ok(rust_cargo_context_for_source_root(ReadOnlyFiles::Repository, source_root)?.crate_roots)
}

fn rust_cargo_context_for_source_root(
    inputs: ReadOnlyFiles<'_>,
    source_root: &Path,
) -> io::Result<CargoRustContext> {
    let Some(manifest) = cargo_manifest_for_source_root(inputs, source_root) else {
        return Ok(CargoRustContext::default());
    };
    let content = inputs.read_to_string(&manifest)?;
    let info = cargo_manifest_info(&content);
    let dependencies = resolved_cargo_dependencies(inputs, &manifest, &info)?;
    let mut context = CargoRustContext::default();
    if let Some(crate_name) = info.crate_name {
        context.crate_roots.push((crate_name, "crate".to_string()));
    }
    for (alias, dependency_base, rel_path) in dependencies.path_dependencies {
        let dep_dir = dependency_base.join(rel_path).canonicalize()?;
        let dep_manifest = dep_dir.join("Cargo.toml");
        if inputs.is_file(&dep_manifest) && dep_dir.join("src").is_dir() {
            context.path_dependencies.push(CargoPathDependency {
                alias,
                manifest_dir: dep_dir,
            });
        }
    }
    Ok(context)
}

fn populate_rust_external_crate_bindings_inventory(
    out: &mut WalkInventoryOutput,
    deadline: RequestDeadline,
) -> io::Result<()> {
    let mut manifest_cache = BTreeMap::new();
    let mut bindings = Vec::new();
    for file in &out.files {
        deadline.check("Rust external crate inventory")?;
        if file.language != SourceLanguage::Rust {
            continue;
        }
        for alias in cargo_external_crates_for_source_file(
            out.bounded_inputs
                .as_deref()
                .map_or(ReadOnlyFiles::Repository, ReadOnlyFiles::Bounded),
            &file.path,
            &mut manifest_cache,
        )? {
            bindings.push((file.rel_path.clone(), alias));
        }
    }
    bindings.sort();
    bindings.dedup();
    out.rust_external_crate_bindings = bindings;
    Ok(())
}

fn populate_rust_external_crate_bindings(out: &mut WalkOutput) -> io::Result<()> {
    let mut manifest_cache = BTreeMap::new();
    let mut bindings = Vec::new();
    for file in &out.files {
        if file.language != SourceLanguage::Rust {
            continue;
        }
        let source_path = out.source_root.join(&file.rel_path);
        for alias in cargo_external_crates_for_source_file(
            ReadOnlyFiles::Repository,
            &source_path,
            &mut manifest_cache,
        )? {
            bindings.push((file.rel_path.clone(), alias));
        }
    }
    bindings.sort();
    bindings.dedup();
    out.rust_external_crate_bindings = bindings;
    Ok(())
}

fn cargo_external_crates_for_source_file(
    inputs: ReadOnlyFiles<'_>,
    source_file: &Path,
    manifest_cache: &mut BTreeMap<PathBuf, Vec<String>>,
) -> io::Result<Vec<String>> {
    let Some(manifest) = nearest_cargo_manifest(inputs, source_file) else {
        return Ok(Vec::new());
    };
    if let Some(cached) = manifest_cache.get(&manifest) {
        return Ok(cached.clone());
    }
    let body = inputs.read_to_string(&manifest)?;
    let info = cargo_manifest_info(&body);
    let aliases = resolved_cargo_dependencies(inputs, &manifest, &info)?.external_dependencies;
    manifest_cache.insert(manifest, aliases.clone());
    Ok(aliases)
}

struct ResolvedCargoDependencies {
    path_dependencies: Vec<(String, PathBuf, String)>,
    external_dependencies: Vec<String>,
}

fn resolved_cargo_dependencies(
    inputs: ReadOnlyFiles<'_>,
    manifest: &Path,
    info: &CargoManifestInfo,
) -> io::Result<ResolvedCargoDependencies> {
    let manifest_dir = manifest.parent().unwrap_or_else(|| Path::new(""));
    let mut path_dependencies = info
        .path_dependencies
        .iter()
        .map(|(alias, path)| (alias.clone(), manifest_dir.to_path_buf(), path.clone()))
        .collect::<Vec<_>>();
    let inherited = info
        .workspace_inherited_dependencies
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut external_dependencies = info
        .external_dependencies
        .iter()
        .filter(|alias| !inherited.contains(alias.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>();

    if info.has_workspace {
        path_dependencies.extend(
            info.workspace_path_dependencies
                .iter()
                .map(|(alias, path)| (alias.clone(), manifest_dir.to_path_buf(), path.clone())),
        );
    }

    if !inherited.is_empty() {
        if let Some(workspace_manifest) = cargo_workspace_manifest(inputs, manifest, info)? {
            let workspace_dir = workspace_manifest.parent().unwrap_or_else(|| Path::new(""));
            let workspace_body = inputs.read_to_string(&workspace_manifest)?;
            let workspace_info = cargo_manifest_info(&workspace_body);
            let workspace_aliases = workspace_info
                .workspace_dependency_aliases
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            let workspace_paths = workspace_info
                .workspace_path_dependencies
                .iter()
                .map(|(alias, path)| (alias.as_str(), path.as_str()))
                .collect::<BTreeMap<_, _>>();
            for alias in inherited {
                if let Some(path) = workspace_paths.get(alias) {
                    path_dependencies.push((
                        alias.to_string(),
                        workspace_dir.to_path_buf(),
                        (*path).to_string(),
                    ));
                } else if workspace_aliases.contains(alias) {
                    external_dependencies.insert(alias.to_string());
                }
            }
        }
    }

    path_dependencies.sort();
    path_dependencies.dedup();
    Ok(ResolvedCargoDependencies {
        path_dependencies,
        external_dependencies: external_dependencies.into_iter().collect(),
    })
}

fn cargo_workspace_manifest(
    inputs: ReadOnlyFiles<'_>,
    manifest: &Path,
    info: &CargoManifestInfo,
) -> io::Result<Option<PathBuf>> {
    let manifest_dir = manifest.parent().unwrap_or_else(|| Path::new(""));
    if let Some(workspace) = info.package_workspace.as_deref() {
        let candidate = manifest_dir.join(workspace).join("Cargo.toml");
        return Ok(inputs.is_file(&candidate).then_some(candidate));
    }
    if info.has_workspace {
        return Ok(Some(manifest.to_path_buf()));
    }

    let mut ancestor = manifest_dir.parent();
    while let Some(directory) = ancestor {
        let candidate = directory.join("Cargo.toml");
        if inputs.is_file(&candidate) {
            let body = inputs.read_to_string(&candidate)?;
            if cargo_manifest_info(&body).has_workspace {
                return Ok(Some(candidate));
            }
        }
        ancestor = directory.parent();
    }
    Ok(None)
}

fn nearest_cargo_manifest(inputs: ReadOnlyFiles<'_>, source_file: &Path) -> Option<PathBuf> {
    let mut directory = source_file.parent()?;
    loop {
        let manifest = directory.join("Cargo.toml");
        if inputs.is_file(&manifest) {
            return Some(manifest);
        }
        directory = directory.parent()?;
    }
}

pub(crate) fn rust_edition_for_source_file(
    source_file: &Path,
) -> io::Result<repotoire::rust::RustEdition> {
    rust_edition_from_inputs(ReadOnlyFiles::Repository, source_file)
}

pub(crate) fn rust_edition_from_inputs(
    inputs: ReadOnlyFiles<'_>,
    source_file: &Path,
) -> io::Result<repotoire::rust::RustEdition> {
    let Some(manifest) = nearest_cargo_manifest(inputs, source_file) else {
        return Ok(repotoire::rust::RustEdition::Edition2015);
    };
    let body = inputs.read_to_string(&manifest)?;
    let parsed = body.parse::<toml::Value>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "cannot parse Cargo manifest {}: {error}",
                manifest.display()
            ),
        )
    })?;
    if let Some(edition) = parsed
        .get("package")
        .and_then(|package| package.get("edition"))
        .and_then(toml::Value::as_str)
    {
        return parse_rust_edition(edition, &manifest);
    }
    let inherits_workspace_edition = parsed
        .get("package")
        .and_then(|package| package.get("edition"))
        .and_then(|edition| edition.get("workspace"))
        .and_then(toml::Value::as_bool)
        == Some(true);
    if inherits_workspace_edition {
        let info = cargo_manifest_info(&body);
        let workspace_manifest =
            cargo_workspace_manifest(inputs, &manifest, &info)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Cargo package {} inherits edition without a workspace manifest",
                        manifest.display()
                    ),
                )
            })?;
        let workspace_body = inputs.read_to_string(&workspace_manifest)?;
        let workspace = workspace_body.parse::<toml::Value>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "cannot parse Cargo workspace manifest {}: {error}",
                    workspace_manifest.display()
                ),
            )
        })?;
        let edition = workspace
            .get("workspace")
            .and_then(|workspace| workspace.get("package"))
            .and_then(|package| package.get("edition"))
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Cargo workspace {} does not declare workspace.package.edition",
                        workspace_manifest.display()
                    ),
                )
            })?;
        return parse_rust_edition(edition, &workspace_manifest);
    }
    Ok(repotoire::rust::RustEdition::Edition2015)
}

fn parse_rust_edition(edition: &str, manifest: &Path) -> io::Result<repotoire::rust::RustEdition> {
    match edition {
        "2015" => Ok(repotoire::rust::RustEdition::Edition2015),
        "2018" => Ok(repotoire::rust::RustEdition::Edition2018),
        "2021" => Ok(repotoire::rust::RustEdition::Edition2021),
        "2024" => Ok(repotoire::rust::RustEdition::Edition2024),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Cargo manifest {} declares unsupported Rust edition {edition:?}",
                manifest.display()
            ),
        )),
    }
}

fn cargo_manifest_for_source_root(
    inputs: ReadOnlyFiles<'_>,
    source_root: &Path,
) -> Option<PathBuf> {
    if inputs.is_file(&source_root.join("Cargo.toml")) {
        return Some(source_root.join("Cargo.toml"));
    }
    if source_root.file_name().and_then(|name| name.to_str()) == Some("src") {
        let crate_root = source_root.parent()?;
        let manifest = crate_root.join("Cargo.toml");
        if inputs.is_file(&manifest) {
            return Some(manifest);
        }
    }
    None
}

fn append_rust_path_dependency_files(
    out: &mut WalkOutput,
    source_root: &Path,
    dependencies: &[CargoPathDependency],
    seen_paths: &mut BTreeSet<PathBuf>,
    profile: AnalysisProfile,
    role_policy: &SourceRolePolicy,
) -> io::Result<bool> {
    let mut added = false;
    for dependency in dependencies {
        let dep_manifest = dependency.manifest_dir.join("Cargo.toml");
        let manifest = fs::read_to_string(&dep_manifest)?;
        let info = cargo_manifest_info(&manifest);
        let lib_path = info.lib_path.as_deref().unwrap_or("src/lib.rs");
        let lib_path = dependency.manifest_dir.join(lib_path).canonicalize()?;
        let lib_rel_path = rel_path_from(source_root, &lib_path);
        out.rust_crate_roots.push((
            dependency.alias.clone(),
            repotoire::rust::module_path_for_file(&lib_rel_path),
        ));
        let dep_src = dependency.manifest_dir.join("src");
        added |= append_rust_files_from_root(
            out,
            source_root,
            &dep_src,
            seen_paths,
            profile,
            role_policy,
        )?;
    }
    Ok(added)
}

fn append_rust_path_dependency_entries(
    out: &mut WalkInventoryOutput,
    source_root: &Path,
    source_files: &cap_std::fs::Dir,
    dependencies: &[CargoPathDependency],
    seen_paths: &mut BTreeSet<PathBuf>,
    profile: AnalysisProfile,
    role_policy: &SourceRolePolicy,
    deadline: RequestDeadline,
) -> io::Result<bool> {
    let mut added = false;
    for dependency in dependencies {
        deadline.check("Rust path dependency inventory")?;
        let dep_manifest = dependency.manifest_dir.join("Cargo.toml");
        let manifest = out
            .bounded_inputs
            .as_deref()
            .map_or(ReadOnlyFiles::Repository, ReadOnlyFiles::Bounded)
            .read_to_string(&dep_manifest)?;
        let info = cargo_manifest_info(&manifest);
        let lib_path = info.lib_path.as_deref().unwrap_or("src/lib.rs");
        let lib_path = dependency.manifest_dir.join(lib_path).canonicalize()?;
        let lib_rel_path = rel_path_from(source_root, &lib_path);
        out.rust_crate_roots.push((
            dependency.alias.clone(),
            repotoire::rust::module_path_for_file(&lib_rel_path),
        ));
        let dep_src = dependency.manifest_dir.join("src");
        added |= append_rust_entries_from_root(
            out,
            source_root,
            source_files,
            &dep_src,
            seen_paths,
            profile,
            role_policy,
            deadline,
        )?;
    }
    Ok(added)
}

fn push_rust_closure_files(
    out: &mut WalkOutput,
    source_root: &Path,
    files: Vec<RustClosureFile>,
    seen_paths: &mut BTreeSet<PathBuf>,
    role_policy: &SourceRolePolicy,
) -> io::Result<()> {
    for file in files {
        let path_canon = file.path.canonicalize()?;
        if !seen_paths.insert(path_canon.clone()) {
            continue;
        }
        let rel_path = rel_path_from(source_root, &path_canon);
        if let Some(module_path) = file.module_path {
            out.rust_module_paths.push((rel_path.clone(), module_path));
        }
        out.files.push(WalkedFile {
            source_role: role_policy.role_for_path(&rel_path),
            rel_path,
            bytes: file.bytes,
            language: SourceLanguage::Rust,
        });
    }
    Ok(())
}

fn push_seen_rust_closure_aliases(
    out: &mut WalkOutput,
    source_root: &Path,
    files: Vec<RustClosureFile>,
    seen_paths: &BTreeSet<PathBuf>,
) -> io::Result<()> {
    for file in files {
        let Some(module_path) = file.module_path else {
            continue;
        };
        let path_canon = file.path.canonicalize()?;
        if seen_paths.contains(&path_canon) {
            out.rust_module_path_aliases
                .push((rel_path_from(source_root, &path_canon), module_path));
        }
    }
    Ok(())
}

fn push_seen_rust_closure_alias_entries(
    out: &mut WalkInventoryOutput,
    source_root: &Path,
    files: Vec<RustClosureFile>,
    seen_paths: &BTreeSet<PathBuf>,
) -> io::Result<()> {
    for file in files {
        let Some(module_path) = file.module_path else {
            continue;
        };
        let path_canon = file.path.canonicalize()?;
        if seen_paths.contains(&path_canon) {
            out.rust_module_path_aliases
                .push((rel_path_from(source_root, &path_canon), module_path));
        }
    }
    Ok(())
}

fn append_rust_cargo_target_module_overrides_inventory(
    out: &mut WalkInventoryOutput,
    source_root: &Path,
    seen_paths: &BTreeSet<PathBuf>,
    deadline: RequestDeadline,
) -> io::Result<()> {
    let inputs = out
        .bounded_inputs
        .as_deref()
        .map_or(ReadOnlyFiles::Repository, ReadOnlyFiles::Bounded);
    let Some(manifest) = cargo_manifest_for_source_root(inputs, source_root) else {
        inputs.check_limits()?;
        return Ok(());
    };
    let crate_root = manifest.parent().unwrap_or_else(|| Path::new(""));
    for (root_file, module_path) in rust_cargo_target_roots(inputs, crate_root) {
        deadline.check("Rust target module inventory")?;
        if !root_file.is_file() {
            continue;
        }
        let root_file = root_file.canonicalize()?;
        if !seen_paths.contains(&root_file) {
            continue;
        }
        out.rust_module_paths
            .push((rel_path_from(source_root, &root_file), module_path.clone()));
        let alias_scan_started = Instant::now();
        let admitted_sources =
            (out.inventory_limits.is_some() || !out.captured_filesystem.is_empty()).then(|| {
                out.files
                    .iter()
                    .map(|file| (file.path.clone(), file.bytes.as_slice()))
                    .collect()
            });
        let target_files = collect_rust_file_module_closure(
            &root_file,
            Some(&module_path),
            admitted_sources.as_ref(),
            deadline,
        )?;
        out.metrics.rust_target_alias_scan_ms += elapsed_ms(alias_scan_started);
        out.metrics.rust_target_alias_file_count += target_files.len() as u64;
        push_seen_rust_closure_alias_entries(out, source_root, target_files, seen_paths)?;
    }
    Ok(())
}

fn rust_cargo_target_roots(inputs: ReadOnlyFiles<'_>, crate_root: &Path) -> Vec<(PathBuf, String)> {
    let mut roots = Vec::new();
    let src = crate_root.join("src");
    push_rust_target_root(&mut roots, src.join("main.rs"), "bin", "main");
    push_rust_target_roots_from_dir(inputs, &mut roots, &src.join("bin"), "bin");
    push_rust_target_roots_from_dir(inputs, &mut roots, &crate_root.join("examples"), "example");
    push_rust_target_roots_from_dir(inputs, &mut roots, &crate_root.join("benches"), "bench");
    push_rust_target_roots_from_dir(inputs, &mut roots, &crate_root.join("tests"), "test");
    push_rust_target_root(&mut roots, crate_root.join("build.rs"), "build", "script");
    append_explicit_rust_cargo_target_roots(inputs, &mut roots, crate_root);
    roots
}

fn append_explicit_rust_cargo_target_roots(
    inputs: ReadOnlyFiles<'_>,
    roots: &mut Vec<(PathBuf, String)>,
    crate_root: &Path,
) {
    let manifest = crate_root.join("Cargo.toml");
    let Ok(body) = inputs.read_to_string(&manifest) else {
        return;
    };
    for target in cargo_manifest_info(&body).targets {
        let Some(path) = target.path else {
            continue;
        };
        let name = target
            .name
            .or_else(|| cargo_target_name_from_path(&path))
            .unwrap_or_default();
        push_rust_target_root(roots, crate_root.join(path), &target.kind, &name);
    }
}

fn cargo_target_name_from_path(path: &str) -> Option<String> {
    Path::new(path)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .map(normalize_crate_name)
}

fn push_rust_target_roots_from_dir(
    inputs: ReadOnlyFiles<'_>,
    roots: &mut Vec<(PathBuf, String)>,
    dir: &Path,
    kind: &str,
) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if inputs.visit().is_err() {
            return;
        }
        let path = entry.path();
        if source_language_for_path(&path) == SourceLanguage::Rust {
            if let Some(stem) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_string)
            {
                push_rust_target_root(roots, path, kind, &stem);
            }
            continue;
        }
        if path.is_dir() {
            let root = path.join("main.rs");
            if root.is_file() {
                if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                    push_rust_target_root(roots, root, kind, name);
                }
            }
        }
    }
}

fn push_rust_target_root(
    roots: &mut Vec<(PathBuf, String)>,
    path: PathBuf,
    kind: &str,
    name: &str,
) {
    if !name.is_empty() {
        roots.push((
            path,
            format!("{kind}::{}::crate", normalize_crate_name(name)),
        ));
    }
}

fn append_rust_files_from_root(
    out: &mut WalkOutput,
    source_root: &Path,
    root: &Path,
    seen_paths: &mut BTreeSet<PathBuf>,
    profile: AnalysisProfile,
    role_policy: &SourceRolePolicy,
) -> io::Result<bool> {
    append_rust_files_from_root_with_module_root(
        out,
        source_root,
        root,
        seen_paths,
        None,
        profile,
        role_policy,
    )
}

fn append_rust_entries_from_root(
    out: &mut WalkInventoryOutput,
    source_root: &Path,
    source_files: &cap_std::fs::Dir,
    root: &Path,
    seen_paths: &mut BTreeSet<PathBuf>,
    profile: AnalysisProfile,
    role_policy: &SourceRolePolicy,
    deadline: RequestDeadline,
) -> io::Result<bool> {
    append_rust_entries_from_root_with_module_root(
        out,
        source_root,
        source_files,
        root,
        seen_paths,
        None,
        profile,
        role_policy,
        deadline,
    )
}

fn append_rust_files_from_root_with_module_root(
    out: &mut WalkOutput,
    source_root: &Path,
    root: &Path,
    seen_paths: &mut BTreeSet<PathBuf>,
    module_root: Option<&str>,
    profile: AnalysisProfile,
    role_policy: &SourceRolePolicy,
) -> io::Result<bool> {
    let mut added = false;
    let filter_root = root.to_path_buf();
    let filter_source_root = source_root.to_path_buf();
    let filter_role_policy = role_policy.clone();
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .add_custom_ignore_filename(".repotoireignore")
        .follow_links(true)
        .hidden(true)
        .max_depth(Some(MAX_DEPTH))
        .parents(true)
        .filter_entry(move |entry| {
            analysis_profile_filter_entry(
                entry,
                &filter_root,
                &filter_source_root,
                profile,
                &filter_role_policy,
            )
        });
    for result in builder.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(e) => {
                out.warnings.push(format!("warning: cannot read {e}"));
                out.walk_degraded_count += 1;
                continue;
            }
        };
        let path = entry.path();
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() || source_language_for_path(path) != SourceLanguage::Rust {
            continue;
        }
        let rel_path = rel_path_from(source_root, path);
        let source_role = role_policy.role_for_path(&rel_path);
        if !profile.includes(source_role) {
            continue;
        }
        let path_canon = path.canonicalize()?;
        if !seen_paths.insert(path_canon.clone()) {
            continue;
        }
        let bytes = fs::read(&path_canon)?;
        if let Some(module_root) = module_root {
            out.rust_module_paths.push((
                rel_path.clone(),
                rust_module_path_with_root(&rel_path, module_root),
            ));
        }
        out.files.push(WalkedFile {
            rel_path,
            bytes,
            language: SourceLanguage::Rust,
            source_role,
        });
        added = true;
    }
    Ok(added)
}

fn append_rust_entries_from_root_with_module_root(
    out: &mut WalkInventoryOutput,
    source_root: &Path,
    source_files: &cap_std::fs::Dir,
    root: &Path,
    seen_paths: &mut BTreeSet<PathBuf>,
    module_root: Option<&str>,
    profile: AnalysisProfile,
    role_policy: &SourceRolePolicy,
    deadline: RequestDeadline,
) -> io::Result<bool> {
    let mut added = false;
    let filter_root = root.to_path_buf();
    let filter_source_root = source_root.to_path_buf();
    let filter_role_policy = role_policy.clone();
    let bounded_inputs = out.bounded_inputs.clone();
    let policy_inputs = out.inventory_limits.map(|_| {
        ignore::gitignore::PolicyInputObservations::bounded(
            4 * 1024 * 1024,
            32 * 1024 * 1024,
            10_000,
        )
    });
    let mut builder = ignore::WalkBuilder::new(root);
    if let Some(observations) = &policy_inputs {
        builder.observe_policy_inputs(observations.clone());
    }
    builder
        .add_custom_ignore_filename(".repotoireignore")
        .follow_links(true)
        .hidden(true)
        .max_depth(Some(MAX_DEPTH))
        .parents(true)
        .filter_entry(move |entry| {
            if let Some(inputs) = &bounded_inputs {
                if inputs.visit().is_err()
                    || !entry
                        .path()
                        .canonicalize()
                        .is_ok_and(|path| path.starts_with(&filter_source_root))
                {
                    return false;
                }
            }
            analysis_profile_filter_entry(
                entry,
                &filter_root,
                &filter_source_root,
                profile,
                &filter_role_policy,
            )
        });
    for result in builder.build() {
        deadline.check("Rust dependency source inventory")?;
        let entry = match result {
            Ok(entry) => entry,
            Err(e) => {
                out.warnings.push(format!("warning: cannot read {e}"));
                out.walk_degraded_count += 1;
                continue;
            }
        };
        let path = entry.path();
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() || source_language_for_path(path) != SourceLanguage::Rust {
            continue;
        }
        let rel_path = rel_path_from(source_root, path);
        if matches!(out.captured_filesystem.get(&rel_path), Some(entry) if !matches!(entry, CapturedFilesystemEntry::RegularFile(None)))
        {
            continue;
        }
        let source_role = role_policy.role_for_path(&rel_path);
        if !profile.includes(source_role) {
            continue;
        }
        let path_canon = path.canonicalize()?;
        if !seen_paths.insert(path_canon.clone()) {
            continue;
        }
        if let Some(module_root) = module_root {
            out.rust_module_paths.push((
                rel_path.clone(),
                rust_module_path_with_root(&rel_path, module_root),
            ));
        }
        let bytes = if path_canon.starts_with(source_root) {
            read_admitted_source(
                source_files,
                source_root,
                &path_canon,
                &out.captured_filesystem,
                out.inventory_limits
                    .map(|limit| limit.read_limit(&out.metrics))
                    .transpose()?,
            )?
        } else if out.inventory_limits.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "bounded source inventory cannot read outside its root",
            ));
        } else {
            Some(fs::read(&path_canon)?)
        };
        let Some(bytes) = bytes else { continue };
        record_source_read(&mut out.metrics, &bytes);
        out.files.push(WalkedSourceEntry {
            rel_path,
            bytes,
            path: path_canon,
            language: SourceLanguage::Rust,
            source_role,
        });
        added = true;
    }
    if let Some(inputs) = &out.bounded_inputs {
        inputs.check()?;
    }
    if let Some(observations) = policy_inputs {
        observations
            .snapshot()
            .map_err(|reason| io::Error::other(SourceInventoryLimit(reason)))?;
    }
    Ok(added)
}

#[cfg(test)]
fn cargo_lib_crate_name(manifest: &str) -> Option<String> {
    cargo_manifest_info(manifest).crate_name
}

fn cargo_manifest_info(manifest: &str) -> CargoManifestInfo {
    let parsed = manifest.parse::<toml::Value>().ok();
    let package = parsed.as_ref().and_then(|value| value.get("package"));
    let lib = parsed.as_ref().and_then(|value| value.get("lib"));
    let package_name = package
        .and_then(|value| value.get("name"))
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    let lib_name = lib
        .and_then(|value| value.get("name"))
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    let lib_path = lib
        .and_then(|value| value.get("path"))
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    let package_workspace = package
        .and_then(|value| value.get("workspace"))
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    let mut path_dependencies = Vec::new();
    let mut workspace_path_dependencies = Vec::new();
    let mut workspace_dependency_aliases = BTreeSet::new();
    let mut workspace_inherited_dependencies = BTreeSet::new();
    let mut dependency_aliases = BTreeSet::new();
    let mut targets = Vec::new();

    if let Some(value) = parsed.as_ref() {
        for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
            collect_cargo_package_dependencies(
                value.get(section),
                &mut dependency_aliases,
                &mut workspace_inherited_dependencies,
                &mut path_dependencies,
            );
        }
        if let Some(targets_table) = value.get("target").and_then(toml::Value::as_table) {
            for target in targets_table.values() {
                for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
                    collect_cargo_package_dependencies(
                        target.get(section),
                        &mut dependency_aliases,
                        &mut workspace_inherited_dependencies,
                        &mut path_dependencies,
                    );
                }
            }
        }
        collect_cargo_workspace_dependencies(
            value
                .get("workspace")
                .and_then(|workspace| workspace.get("dependencies")),
            &mut workspace_dependency_aliases,
            &mut workspace_path_dependencies,
        );
        for kind in ["bin", "example", "bench", "test"] {
            let Some(entries) = value.get(kind).and_then(toml::Value::as_array) else {
                continue;
            };
            for entry in entries {
                let name = entry
                    .get("name")
                    .and_then(toml::Value::as_str)
                    .map(str::to_string);
                let path = entry
                    .get("path")
                    .and_then(toml::Value::as_str)
                    .map(str::to_string);
                if name.is_some() || path.is_some() {
                    targets.push(CargoTargetInfo {
                        kind: kind.to_string(),
                        name,
                        path,
                    });
                }
            }
        }
    }

    let path_dependency_aliases = path_dependencies
        .iter()
        .map(|(alias, _)| alias.as_str())
        .collect::<BTreeSet<_>>();
    let external_dependencies = dependency_aliases
        .into_iter()
        .filter(|alias| !path_dependency_aliases.contains(alias.as_str()))
        .collect();
    CargoManifestInfo {
        crate_name: lib_name
            .or(package_name)
            .map(|name| normalize_crate_name(&name)),
        lib_path,
        path_dependencies,
        workspace_path_dependencies,
        workspace_dependency_aliases: workspace_dependency_aliases.into_iter().collect(),
        workspace_inherited_dependencies: workspace_inherited_dependencies.into_iter().collect(),
        external_dependencies,
        package_workspace,
        has_workspace: parsed
            .as_ref()
            .and_then(|value| value.get("workspace"))
            .is_some(),
        targets,
    }
}

fn collect_cargo_package_dependencies(
    dependencies: Option<&toml::Value>,
    aliases: &mut BTreeSet<String>,
    inherited: &mut BTreeSet<String>,
    paths: &mut Vec<(String, String)>,
) {
    let Some(dependencies) = dependencies.and_then(toml::Value::as_table) else {
        return;
    };
    for (raw_alias, specification) in dependencies {
        let alias = normalize_crate_name(raw_alias);
        aliases.insert(alias.clone());
        if specification
            .get("workspace")
            .and_then(toml::Value::as_bool)
            == Some(true)
        {
            inherited.insert(alias.clone());
        }
        if let Some(path) = specification.get("path").and_then(toml::Value::as_str) {
            paths.push((alias, path.to_string()));
        }
    }
}

fn collect_cargo_workspace_dependencies(
    dependencies: Option<&toml::Value>,
    aliases: &mut BTreeSet<String>,
    workspace_paths: &mut Vec<(String, String)>,
) {
    let Some(dependencies) = dependencies.and_then(toml::Value::as_table) else {
        return;
    };
    for (raw_alias, specification) in dependencies {
        let alias = normalize_crate_name(raw_alias);
        aliases.insert(alias.clone());
        if let Some(path) = specification.get("path").and_then(toml::Value::as_str) {
            workspace_paths.push((alias, path.to_string()));
        }
    }
}

fn normalize_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

fn rust_module_path_with_root(rel_path: &str, module_root: &str) -> String {
    let path = repotoire::rust::module_path_for_file(rel_path);
    if path == "crate" {
        return module_root.to_string();
    }
    path.strip_prefix("crate::")
        .map(|suffix| format!("{module_root}::{suffix}"))
        .unwrap_or(path)
}

fn join_rust_module_path(prefix: &str, suffix: &str) -> String {
    let prefix = prefix.trim().trim_end_matches("::");
    let suffix = suffix.trim().trim_start_matches("::");
    match (prefix.is_empty(), suffix.is_empty()) {
        (true, true) => String::new(),
        (true, false) => suffix.to_string(),
        (false, true) => prefix.to_string(),
        (false, false) => format!("{prefix}::{suffix}"),
    }
}

fn rust_cargo_target_root_module_path(
    primary_path: &Path,
    crate_src_root: &Path,
) -> Option<String> {
    let rel = primary_path.strip_prefix(crate_src_root).ok()?;
    let parts = rel
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect::<Vec<_>>();
    match parts.as_slice() {
        ["main.rs"] => Some("bin::main::crate".to_string()),
        ["bin", file] => file
            .strip_suffix(".rs")
            .filter(|stem| !stem.is_empty())
            .map(|stem| format!("bin::{stem}::crate")),
        ["bin", dir, "main.rs"] if !dir.is_empty() => Some(format!("bin::{dir}::crate")),
        _ => None,
    }
}

fn is_module_root_path(module_path: Option<&str>) -> bool {
    module_path
        .map(|path| path == "crate" || path.ends_with("::crate"))
        .unwrap_or(false)
}

fn rust_directory_crate_scope(root: &Path) -> io::Result<Option<PathBuf>> {
    let Some(crate_src_root) = rust_crate_source_root(root) else {
        return Ok(None);
    };
    if root == crate_src_root {
        return Ok(None);
    }
    directory_contains_rust_source(root).map(|has_rust| has_rust.then_some(crate_src_root))
}

fn rust_directory_cargo_scope(root: &Path) -> io::Result<Option<PathBuf>> {
    if root.file_name().and_then(|name| name.to_str()) == Some("src")
        && root
            .parent()
            .map(|parent| parent.join("Cargo.toml").is_file())
            .unwrap_or(false)
    {
        return Ok(None);
    }
    let Some(crate_root) = cargo_project_root_for_path(root) else {
        return Ok(None);
    };
    if root == crate_root {
        return Ok(None);
    }
    if !is_cargo_rust_source_or_target_scope(root, &crate_root)? {
        return Ok(None);
    }
    directory_contains_rust_source(root).map(|has_rust| has_rust.then_some(crate_root))
}

fn is_cargo_rust_source_or_target_scope(root: &Path, crate_root: &Path) -> io::Result<bool> {
    let root = root.canonicalize()?;
    let crate_root = crate_root.canonicalize()?;
    let Ok(rel) = root.strip_prefix(&crate_root) else {
        return Ok(false);
    };
    let first = rel
        .components()
        .next()
        .and_then(|component| match component {
            std::path::Component::Normal(name) => name.to_str(),
            _ => None,
        });
    if matches!(first, Some("src" | "tests" | "examples" | "benches")) {
        return Ok(true);
    }

    let manifest = crate_root.join("Cargo.toml");
    let Ok(body) = fs::read_to_string(&manifest) else {
        return Ok(false);
    };
    for target in cargo_manifest_info(&body).targets {
        let Some(path) = target.path else {
            continue;
        };
        let target_rel = Path::new(&path);
        let Some(parent) = target_rel
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        else {
            continue;
        };
        if root.starts_with(crate_root.join(parent)) {
            return Ok(true);
        }
    }

    Ok(false)
}

fn rust_crate_source_root(root: &Path) -> Option<PathBuf> {
    for ancestor in root.ancestors() {
        if ancestor.file_name().and_then(|name| name.to_str()) != Some("src") {
            continue;
        }
        let crate_root = ancestor.parent()?;
        if crate_root.join("Cargo.toml").is_file() {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

fn cargo_project_root_for_path(path: &Path) -> Option<PathBuf> {
    let start = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or(path)
    };
    for ancestor in start.ancestors() {
        if ancestor.join("Cargo.toml").is_file() {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

fn directory_contains_rust_source(root: &Path) -> io::Result<bool> {
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .add_custom_ignore_filename(".repotoireignore")
        .follow_links(true)
        .hidden(true)
        .max_depth(Some(MAX_DEPTH))
        .parents(true)
        .filter_entry(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| !SKIP_DIRS.contains(&name))
                .unwrap_or(true)
        });
    for result in builder.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(e) => {
                return Err(io::Error::other(e));
            }
        };
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_file() && source_language_for_path(entry.path()) == SourceLanguage::Rust {
            return Ok(true);
        }
    }
    Ok(false)
}

fn walk_single_file_import_closure(
    root_file: &Path,
    deadline: RequestDeadline,
) -> io::Result<WalkOutput> {
    let mut queue = VecDeque::from([root_file.to_path_buf()]);
    let mut seen = BTreeSet::new();
    let mut files = Vec::new();

    while let Some(path) = queue.pop_front() {
        deadline.check("single-file TypeScript import closure")?;
        let path = path.canonicalize()?;
        if !seen.insert(path.clone()) {
            continue;
        }
        if source_language_for_path(&path) != SourceLanguage::TypeScript {
            continue;
        }
        let bytes = fs::read(&path)?;
        deadline.check("single-file TypeScript parse")?;
        let specifiers = relative_import_specifiers(&path, &bytes);
        deadline.check("single-file TypeScript import resolution")?;
        for specifier in specifiers {
            deadline.check("single-file TypeScript import resolution")?;
            if let Some(target) = resolve_relative_source_file(&path, &specifier) {
                if !seen.contains(&target) {
                    queue.push_back(target);
                }
            }
        }
        files.push((path, bytes));
    }

    let corpus_root = common_parent_dir(files.iter().map(|(path, _)| path.as_path()))
        .unwrap_or_else(|| root_file.parent().unwrap_or(root_file).to_path_buf());
    let primary_path = root_file.canonicalize()?;
    let primary_rel_path = rel_path_from(&corpus_root, &primary_path);
    let mut warnings = Vec::new();
    let role_policy =
        SourceRolePolicy::load(ReadOnlyFiles::Repository, &corpus_root, &mut warnings);
    let mut walked = files
        .into_iter()
        .map(|(path, bytes)| WalkedFile {
            source_role: role_policy.role_for_path(&rel_path_from(&corpus_root, &path)),
            rel_path: rel_path_from(&corpus_root, &path),
            bytes,
            language: SourceLanguage::TypeScript,
        })
        .collect::<Vec<_>>();
    walked.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(WalkOutput {
        source_root: corpus_root,
        files: walked,
        rust_crate_roots: Vec::new(),
        rust_external_crate_bindings: Vec::new(),
        rust_module_paths: Vec::new(),
        rust_module_path_aliases: Vec::new(),
        python_module_paths: Vec::new(),
        warnings,
        diagnostic_paths: Some(vec![primary_rel_path.clone()]),
        render_paths: Some(vec![primary_rel_path]),
        skipped_by_extension: BTreeMap::new(),
        walk_degraded_count: 0,
        // Single-file context closure, not a full-inventory method: never
        // deletion-trusted (I2).
        source_inventory_deletion_trusted: false,
    })
}

fn walk_single_rust_file_module_closure(
    root_file: &Path,
    deadline: RequestDeadline,
) -> io::Result<WalkOutput> {
    let primary_path = root_file.canonicalize()?;
    if let Some(crate_root) = cargo_project_root_for_path(&primary_path) {
        return walk_single_rust_file_in_cargo_project(&primary_path, &crate_root, deadline);
    }

    let files = collect_rust_file_module_closure(&primary_path, Some("crate"), None, deadline)?;
    let corpus_root = common_parent_dir(files.iter().map(|file| file.path.as_path()))
        .unwrap_or_else(|| root_file.parent().unwrap_or(root_file).to_path_buf());
    let primary_rel_path = rel_path_from(&corpus_root, &primary_path);
    let rust_crate_roots = rust_crate_aliases_for_source_root(&corpus_root)?;
    let mut warnings = Vec::new();
    let role_policy =
        SourceRolePolicy::load(ReadOnlyFiles::Repository, &corpus_root, &mut warnings);
    let mut out = WalkOutput {
        source_root: corpus_root.clone(),
        files: Vec::new(),
        rust_crate_roots,
        rust_external_crate_bindings: Vec::new(),
        rust_module_paths: Vec::new(),
        rust_module_path_aliases: Vec::new(),
        python_module_paths: Vec::new(),
        warnings,
        diagnostic_paths: None,
        render_paths: Some(vec![primary_rel_path]),
        skipped_by_extension: BTreeMap::new(),
        walk_degraded_count: 0,
        // Single-file context closure, not a full-inventory method: never
        // deletion-trusted (I2).
        source_inventory_deletion_trusted: false,
    };
    let mut seen_paths = BTreeSet::new();
    push_rust_closure_files(&mut out, &corpus_root, files, &mut seen_paths, &role_policy)?;
    out.files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    out.rust_module_paths.sort();
    populate_rust_external_crate_bindings(&mut out)?;
    Ok(out)
}

fn walk_single_rust_file_in_cargo_project(
    primary_path: &Path,
    crate_root: &Path,
    deadline: RequestDeadline,
) -> io::Result<WalkOutput> {
    let crate_src_root = crate_root.join("src").canonicalize().ok();
    let primary_is_under_crate_src = crate_src_root
        .as_ref()
        .map(|src| primary_path.starts_with(src))
        .unwrap_or(false);
    let source_root = if primary_is_under_crate_src {
        crate_src_root.clone().expect("checked Some above")
    } else {
        crate_root.to_path_buf()
    };
    let target_root_module_path = if primary_is_under_crate_src {
        crate_src_root
            .as_ref()
            .and_then(|src| rust_cargo_target_root_module_path(primary_path, src))
    } else {
        None
    };
    let primary_rel_path = rel_path_from(&source_root, primary_path);
    let mut cargo_context =
        rust_cargo_context_for_source_root(ReadOnlyFiles::Repository, &source_root)?;
    let local_lib_module_root = if primary_is_under_crate_src {
        None
    } else {
        cargo_context
            .crate_roots
            .iter_mut()
            .find(|(_, root)| root == "crate")
            .map(|(alias, root)| {
                *root = alias.clone();
                alias.clone()
            })
    };
    let mut out = WalkOutput {
        source_root: source_root.clone(),
        files: Vec::new(),
        rust_crate_roots: cargo_context.crate_roots,
        rust_external_crate_bindings: Vec::new(),
        rust_module_paths: Vec::new(),
        rust_module_path_aliases: Vec::new(),
        python_module_paths: Vec::new(),
        warnings: Vec::new(),
        diagnostic_paths: None,
        render_paths: Some(vec![primary_rel_path]),
        skipped_by_extension: BTreeMap::new(),
        walk_degraded_count: 0,
        // Single-file context closure, not a full-inventory method: never
        // deletion-trusted (I2).
        source_inventory_deletion_trusted: false,
    };
    let mut seen_paths = BTreeSet::new();
    let role_policy =
        SourceRolePolicy::load(ReadOnlyFiles::Repository, &source_root, &mut out.warnings);
    if let Some(root_module_path) = target_root_module_path.as_deref() {
        let target_files =
            collect_rust_file_module_closure(primary_path, Some(root_module_path), None, deadline)?;
        push_rust_closure_files(
            &mut out,
            &source_root,
            target_files,
            &mut seen_paths,
            &role_policy,
        )?;
    }
    if let Some(crate_src_root) = crate_src_root.as_ref() {
        append_rust_files_from_root_with_module_root(
            &mut out,
            &source_root,
            crate_src_root,
            &mut seen_paths,
            local_lib_module_root.as_deref(),
            AnalysisProfile::All,
            &role_policy,
        )?;
    }
    if target_root_module_path.is_some() {
        if let Some(lib_rs) = crate_src_root
            .as_ref()
            .map(|src| src.join("lib.rs"))
            .filter(|path| path.is_file())
        {
            let lib_files =
                collect_rust_file_module_closure(&lib_rs, Some("crate"), None, deadline)?;
            push_seen_rust_closure_aliases(&mut out, &source_root, lib_files, &seen_paths)?;
        }
    }
    if target_root_module_path.is_none() {
        let root_module_path = (!primary_is_under_crate_src).then_some("crate");
        let primary_files =
            collect_rust_file_module_closure(primary_path, root_module_path, None, deadline)?;
        push_rust_closure_files(
            &mut out,
            &source_root,
            primary_files,
            &mut seen_paths,
            &role_policy,
        )?;
    }
    append_rust_path_dependency_files(
        &mut out,
        &source_root,
        &cargo_context.path_dependencies,
        &mut seen_paths,
        AnalysisProfile::All,
        &role_policy,
    )?;
    out.files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    out.rust_module_paths.sort();
    out.rust_module_path_aliases.sort();
    out.rust_module_path_aliases.dedup();
    populate_rust_external_crate_bindings(&mut out)?;
    Ok(out)
}

fn collect_rust_file_module_closure(
    root_file: &Path,
    root_module_path: Option<&str>,
    admitted_sources: Option<&BTreeMap<PathBuf, &[u8]>>,
    deadline: RequestDeadline,
) -> io::Result<Vec<RustClosureFile>> {
    let mut queue = VecDeque::from([(
        root_file.to_path_buf(),
        root_module_path.map(str::to_string),
    )]);
    let mut seen = BTreeSet::new();
    let mut files = Vec::new();

    while let Some((path, module_path)) = queue.pop_front() {
        deadline.check("single-file Rust module closure")?;
        if admitted_sources.is_some_and(|sources| !sources.contains_key(&path)) {
            continue;
        }
        let path = path.canonicalize()?;
        if !seen.insert(path.clone()) {
            continue;
        }
        if source_language_for_path(&path) != SourceLanguage::Rust {
            continue;
        }
        let bytes = match admitted_sources {
            Some(sources) => match sources.get(&path) {
                Some(bytes) => bytes.to_vec(),
                None => continue,
            },
            None => fs::read(&path)?,
        };
        deadline.check("single-file Rust parse")?;
        let parsed = repotoire::rust::parse_file(
            &path.to_string_lossy(),
            &bytes,
            repotoire::rust::RustParseOptions {
                edition: rust_edition_for_source_file(&path)?,
                mode: repotoire::rust::RustParseMode::Items,
            },
        );
        match parsed {
            Ok(parsed) => {
                deadline.check("single-file Rust module resolution")?;
                for item in parsed.items {
                    deadline.check("single-file Rust module resolution")?;
                    if item.kind == repotoire::rust::RustItemKind::Module {
                        let targets =
                            rust_module_candidates(&path, module_path.as_deref(), &item.name);
                        deadline.check("single-file Rust module resolution")?;
                        for target in targets {
                            if admitted_sources.map_or_else(
                                || target.is_file(),
                                |sources| sources.contains_key(&target),
                            ) && !seen.contains(&target)
                            {
                                let child_module_path = module_path
                                    .as_ref()
                                    .map(|base| join_rust_module_path(base, &item.name));
                                queue.push_back((target, child_module_path));
                            }
                        }
                    }
                }
            }
            Err(repotoire::rust::RustParseError::Syntax { .. }) => {
                // The native evidence decoder owns syntax quarantine and its
                // warning. A malformed file remains observable, but cannot
                // safely expand the single-file module closure.
            }
            Err(error) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot parse Rust file {}: {error}", path.display()),
                ));
            }
        }
        files.push(RustClosureFile {
            path,
            bytes,
            module_path,
        });
    }
    Ok(files)
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(feature = "python")]
#[derive(Debug, Clone)]
struct PythonWorkspaceContext {
    source_root: PathBuf,
    member_roots: Vec<PathBuf>,
    import_roots: Vec<PathBuf>,
}

#[cfg(feature = "python")]
fn walk_single_python_file(root_file: &Path, deadline: RequestDeadline) -> io::Result<WalkOutput> {
    let primary_path = root_file.canonicalize()?;
    if let Some(context) = python_project_context_for_path(&primary_path)? {
        return walk_python_context(&primary_path, context, deadline);
    }

    let corpus_root = python_project_root_for_path(&primary_path)
        .unwrap_or_else(|| primary_path.parent().unwrap_or(&primary_path).to_path_buf());
    let files = collect_python_file_import_closure(&primary_path, &corpus_root, deadline)?;
    let primary_rel_path = rel_path_from(&corpus_root, &primary_path);
    let mut warnings = Vec::new();
    let role_policy =
        SourceRolePolicy::load(ReadOnlyFiles::Repository, &corpus_root, &mut warnings);
    let mut walked = files
        .into_iter()
        .map(|(path, bytes)| WalkedFile {
            source_role: role_policy.role_for_path(&rel_path_from(&corpus_root, &path)),
            rel_path: rel_path_from(&corpus_root, &path),
            bytes,
            language: SourceLanguage::Python,
        })
        .collect::<Vec<_>>();
    walked.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    let mut out = WalkOutput {
        source_root: corpus_root,
        files: walked,
        rust_crate_roots: Vec::new(),
        rust_external_crate_bindings: Vec::new(),
        rust_module_paths: Vec::new(),
        rust_module_path_aliases: Vec::new(),
        python_module_paths: Vec::new(),
        warnings,
        diagnostic_paths: Some(vec![primary_rel_path.clone()]),
        render_paths: Some(vec![primary_rel_path]),
        skipped_by_extension: BTreeMap::new(),
        walk_degraded_count: 0,
        // Single-file context closure, not a full-inventory method: never
        // deletion-trusted (I2).
        source_inventory_deletion_trusted: false,
    };
    populate_python_module_paths(&mut out)?;
    Ok(out)
}

#[cfg(feature = "python")]
fn walk_python_context(
    primary_path: &Path,
    context: PythonWorkspaceContext,
    deadline: RequestDeadline,
) -> io::Result<WalkOutput> {
    let primary_rel_path = rel_path_from(&context.source_root, primary_path);
    let mut out = WalkOutput {
        source_root: context.source_root.clone(),
        files: Vec::new(),
        rust_crate_roots: Vec::new(),
        rust_external_crate_bindings: Vec::new(),
        rust_module_paths: Vec::new(),
        rust_module_path_aliases: Vec::new(),
        python_module_paths: Vec::new(),
        warnings: Vec::new(),
        diagnostic_paths: Some(vec![primary_rel_path.clone()]),
        render_paths: Some(vec![primary_rel_path]),
        skipped_by_extension: BTreeMap::new(),
        walk_degraded_count: 0,
        // Single-file context closure, not a full-inventory method: never
        // deletion-trusted (I2).
        source_inventory_deletion_trusted: false,
    };
    let mut seen_paths = BTreeSet::new();
    let role_policy = SourceRolePolicy::load(
        ReadOnlyFiles::Repository,
        &context.source_root,
        &mut out.warnings,
    );
    for member_root in &context.member_roots {
        deadline.check("single-file Python workspace")?;
        append_python_files_from_root(
            &mut out,
            member_root,
            &mut seen_paths,
            &role_policy,
            deadline,
        )?;
    }
    push_python_file(&mut out, primary_path, &mut seen_paths, &role_policy)?;
    populate_python_module_paths_from_roots(&mut out, &context.import_roots);
    out.files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    out.python_module_paths.sort();
    out.python_module_paths.dedup();
    Ok(out)
}

#[cfg(feature = "python")]
fn append_python_files_from_root(
    out: &mut WalkOutput,
    root: &Path,
    seen_paths: &mut BTreeSet<PathBuf>,
    role_policy: &SourceRolePolicy,
    deadline: RequestDeadline,
) -> io::Result<()> {
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .add_custom_ignore_filename(".repotoireignore")
        .follow_links(true)
        .hidden(true)
        .max_depth(Some(MAX_DEPTH))
        .parents(true)
        .filter_entry(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| !SKIP_DIRS.contains(&name))
                .unwrap_or(true)
        });

    for result in builder.build() {
        deadline.check("single-file Python workspace inventory")?;
        let entry = match result {
            Ok(entry) => entry,
            Err(e) => {
                out.warnings.push(format!("warning: cannot read {e}"));
                out.walk_degraded_count += 1;
                continue;
            }
        };
        let path = entry.path();
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_file() {
            push_python_file(out, path, seen_paths, role_policy)?;
        }
    }
    Ok(())
}

#[cfg(feature = "python")]
fn push_python_file(
    out: &mut WalkOutput,
    path: &Path,
    seen_paths: &mut BTreeSet<PathBuf>,
    role_policy: &SourceRolePolicy,
) -> io::Result<()> {
    if source_language_for_path(path) != SourceLanguage::Python {
        return Ok(());
    }
    let path_canon = path.canonicalize()?;
    if !seen_paths.insert(path_canon.clone()) {
        return Ok(());
    }
    let bytes = fs::read(&path_canon)?;
    let rel_path = rel_path_from(&out.source_root, &path_canon);
    out.files.push(WalkedFile {
        source_role: role_policy.role_for_path(&rel_path),
        rel_path,
        bytes,
        language: SourceLanguage::Python,
    });
    Ok(())
}

#[cfg(feature = "python")]
fn populate_python_module_paths(out: &mut WalkOutput) -> io::Result<()> {
    let import_roots = python_import_roots_for_path(&out.source_root)?;
    populate_python_module_paths_from_roots(out, &import_roots);
    Ok(())
}

#[cfg(feature = "python")]
fn populate_python_module_paths_inventory(
    out: &mut WalkInventoryOutput,
    deadline: RequestDeadline,
) -> io::Result<()> {
    deadline.check("Python module inventory")?;
    let import_roots = python_import_roots_for_path(&out.source_root)?;
    populate_python_module_paths_from_roots_inventory(out, &import_roots);
    Ok(())
}

#[cfg(feature = "python")]
fn python_import_roots_for_path(path: &Path) -> io::Result<Vec<PathBuf>> {
    if let Some(context) = python_project_context_for_path(path)? {
        return Ok(context.import_roots);
    }
    let project_root = python_project_root_for_path(path).unwrap_or_else(|| path.to_path_buf());
    Ok(python_import_roots_for_project_root(&project_root))
}

#[cfg(feature = "python")]
fn populate_python_module_paths_from_roots(out: &mut WalkOutput, import_roots: &[PathBuf]) {
    let source_root = out.source_root.clone();
    let mut import_roots = import_roots.to_vec();
    import_roots.sort_by(|a, b| {
        b.components()
            .count()
            .cmp(&a.components().count())
            .then(a.cmp(b))
    });
    import_roots.dedup();
    out.python_module_paths.clear();
    for file in &out.files {
        if file.language != SourceLanguage::Python {
            continue;
        }
        let abs = source_root.join(&file.rel_path);
        let abs = abs.canonicalize().unwrap_or(abs);
        if let Some(module_path) = python_module_path_for_import_roots(&abs, &import_roots) {
            out.python_module_paths
                .push((file.rel_path.clone(), module_path));
        }
    }
    out.python_module_paths.sort();
    out.python_module_paths.dedup();
}

#[cfg(feature = "python")]
fn populate_python_module_paths_from_roots_inventory(
    out: &mut WalkInventoryOutput,
    import_roots: &[PathBuf],
) {
    let source_root = out.source_root.clone();
    let mut import_roots = import_roots.to_vec();
    import_roots.sort_by(|a, b| {
        b.components()
            .count()
            .cmp(&a.components().count())
            .then(a.cmp(b))
    });
    import_roots.dedup();
    out.python_module_paths.clear();
    for file in &out.files {
        if file.language != SourceLanguage::Python {
            continue;
        }
        let abs = source_root.join(&file.rel_path);
        let abs = abs.canonicalize().unwrap_or(abs);
        if let Some(module_path) = python_module_path_for_import_roots(&abs, &import_roots) {
            out.python_module_paths
                .push((file.rel_path.clone(), module_path));
        }
    }
    out.python_module_paths.sort();
    out.python_module_paths.dedup();
}

#[cfg(feature = "python")]
fn python_workspace_context_from_member_roots(
    source_root: PathBuf,
    member_roots: Vec<PathBuf>,
) -> io::Result<PythonWorkspaceContext> {
    let mut import_roots = Vec::new();
    for member_root in &member_roots {
        let src_root = member_root.join("src");
        if src_root.is_dir() {
            import_roots.push(src_root.canonicalize()?);
        }
        import_roots.push(member_root.clone());
    }
    let root_src = source_root.join("src");
    if root_src.is_dir() {
        import_roots.push(root_src.canonicalize()?);
    }
    import_roots.push(source_root.clone());
    import_roots.sort();
    import_roots.dedup();

    Ok(PythonWorkspaceContext {
        source_root,
        member_roots,
        import_roots,
    })
}

#[cfg(feature = "python")]
fn python_project_context_for_path(path: &Path) -> io::Result<Option<PythonWorkspaceContext>> {
    let Some(primary_root) = python_project_root_for_path(path) else {
        return Ok(None);
    };
    let primary_root = primary_root.canonicalize()?;
    let source_root = python_repo_search_root_for_path(path, &primary_root)?;
    let mut member_roots = BTreeSet::from([primary_root.clone()]);
    let mut has_project_graph = false;

    for manifest in collect_python_pyproject_manifests(&source_root)? {
        let Some(project_root) = manifest.parent() else {
            continue;
        };
        let Ok(project_root) = project_root.canonicalize() else {
            continue;
        };
        if !project_root.starts_with(&source_root) {
            continue;
        }

        if let Some(members) = python_uv_workspace_members(&manifest)? {
            has_project_graph = true;
            member_roots.insert(project_root.clone());
            for member in members {
                for candidate in expand_python_workspace_member(&project_root, &member)? {
                    let Ok(candidate) = candidate.canonicalize() else {
                        continue;
                    };
                    if candidate.is_dir() && candidate.starts_with(&source_root) {
                        member_roots.insert(candidate);
                    }
                }
            }
        }

        for source in python_uv_path_sources(&manifest)? {
            let candidate = project_root.join(source);
            let Ok(candidate) = candidate.canonicalize() else {
                continue;
            };
            if candidate.is_dir() && candidate.starts_with(&source_root) {
                has_project_graph = true;
                member_roots.insert(project_root.clone());
                member_roots.insert(candidate);
            }
        }
    }

    if !has_project_graph {
        return Ok(None);
    }
    let member_roots = member_roots.into_iter().collect::<Vec<_>>();
    python_workspace_context_from_member_roots(source_root, member_roots).map(Some)
}

#[cfg(feature = "python")]
fn python_repo_search_root_for_path(path: &Path, fallback: &Path) -> io::Result<PathBuf> {
    let start = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or(path)
    };
    let mut highest_manifest_root = None;
    for ancestor in start.ancestors() {
        if ancestor.join(".git").is_dir() {
            return ancestor.canonicalize();
        }
        if ancestor.join("pyproject.toml").is_file() {
            highest_manifest_root = Some(ancestor.to_path_buf());
        }
    }
    highest_manifest_root
        .unwrap_or_else(|| fallback.to_path_buf())
        .canonicalize()
}

#[cfg(feature = "python")]
fn collect_python_pyproject_manifests(source_root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut manifests = Vec::new();
    let mut builder = ignore::WalkBuilder::new(source_root);
    builder
        .add_custom_ignore_filename(".repotoireignore")
        .follow_links(true)
        .hidden(true)
        .max_depth(Some(MAX_DEPTH))
        .parents(true)
        .filter_entry(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| !SKIP_DIRS.contains(&name))
                .unwrap_or(true)
        });
    for result in builder.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if entry.path().file_name().and_then(|name| name.to_str()) == Some("pyproject.toml") {
            manifests.push(entry.path().to_path_buf());
        }
    }
    manifests.sort();
    manifests.dedup();
    Ok(manifests)
}

#[cfg(feature = "python")]
fn python_uv_path_sources(manifest: &Path) -> io::Result<Vec<PathBuf>> {
    let body = fs::read_to_string(manifest)?;
    let Ok(value) = body.parse::<toml::Value>() else {
        return Ok(Vec::new());
    };
    let Some(sources) = value
        .get("tool")
        .and_then(|tool| tool.get("uv"))
        .and_then(|uv| uv.get("sources"))
        .and_then(|sources| sources.as_table())
    else {
        return Ok(Vec::new());
    };
    let mut paths = Vec::new();
    for source in sources.values() {
        let Some(path) = source.get("path").and_then(|path| path.as_str()) else {
            continue;
        };
        paths.push(PathBuf::from(path));
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

#[cfg(feature = "python")]
fn python_uv_workspace_members(manifest: &Path) -> io::Result<Option<Vec<String>>> {
    let body = fs::read_to_string(manifest)?;
    let Ok(value) = body.parse::<toml::Value>() else {
        return Ok(None);
    };
    let Some(members) = value
        .get("tool")
        .and_then(|tool| tool.get("uv"))
        .and_then(|uv| uv.get("workspace"))
        .and_then(|workspace| workspace.get("members"))
        .and_then(|members| members.as_array())
    else {
        return Ok(None);
    };
    let members = members
        .iter()
        .filter_map(|member| member.as_str().map(str::to_string))
        .collect::<Vec<_>>();
    Ok(Some(members))
}

#[cfg(feature = "python")]
fn expand_python_workspace_member(workspace_root: &Path, member: &str) -> io::Result<Vec<PathBuf>> {
    let member = member.trim().trim_matches('/');
    if member.is_empty() {
        return Ok(Vec::new());
    }
    let components = member
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    let mut paths = vec![workspace_root.to_path_buf()];
    for component in components {
        let mut next = Vec::new();
        for base in paths {
            if component_has_glob(component) {
                let Ok(entries) = fs::read_dir(&base) else {
                    continue;
                };
                for entry in entries {
                    let entry = entry?;
                    let name = entry.file_name();
                    let Some(name) = name.to_str() else {
                        continue;
                    };
                    if simple_glob_match(component, name) {
                        next.push(entry.path());
                    }
                }
            } else {
                next.push(base.join(component));
            }
        }
        paths = next;
    }
    Ok(paths)
}

#[cfg(feature = "python")]
fn component_has_glob(component: &str) -> bool {
    component.contains('*') || component.contains('?')
}

#[cfg(feature = "python")]
fn simple_glob_match(pattern: &str, text: &str) -> bool {
    fn matches(pattern: &[char], text: &[char]) -> bool {
        match pattern.split_first() {
            None => text.is_empty(),
            Some(('*', rest)) => {
                matches(rest, text) || (!text.is_empty() && matches(pattern, &text[1..]))
            }
            Some(('?', rest)) => !text.is_empty() && matches(rest, &text[1..]),
            Some((expected, rest)) => text
                .split_first()
                .is_some_and(|(actual, tail)| expected == actual && matches(rest, tail)),
        }
    }
    matches(
        &pattern.chars().collect::<Vec<_>>(),
        &text.chars().collect::<Vec<_>>(),
    )
}

#[cfg(feature = "python")]
fn python_import_roots_for_project_root(project_root: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let src_root = project_root.join("src");
    if src_root.is_dir() {
        roots.push(src_root.canonicalize().unwrap_or(src_root));
    }
    roots.push(project_root.to_path_buf());
    roots
}

#[cfg(feature = "python")]
fn python_module_path_for_import_roots(file: &Path, import_roots: &[PathBuf]) -> Option<String> {
    for root in import_roots {
        let Ok(rel) = file.strip_prefix(root) else {
            continue;
        };
        if let Some(module_path) = python_module_path_from_rel_path(rel) {
            return Some(module_path);
        }
    }
    None
}

#[cfg(feature = "python")]
fn python_module_path_from_rel_path(rel: &Path) -> Option<String> {
    let rel = rel.to_string_lossy().replace('\\', "/");
    let trimmed = rel.strip_suffix(".py")?;
    let mut parts = trimmed
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.last() == Some(&"__init__") {
        parts.pop();
    }
    if parts.is_empty() || parts.iter().any(|part| !is_ascii_python_identifier(part)) {
        return None;
    }
    Some(parts.join("."))
}

#[cfg(feature = "python")]
fn is_ascii_python_identifier(part: &str) -> bool {
    let mut chars = part.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

#[cfg(feature = "python")]
fn collect_python_file_import_closure(
    root_file: &Path,
    source_root: &Path,
    deadline: RequestDeadline,
) -> io::Result<Vec<(PathBuf, Vec<u8>)>> {
    let mut queue = VecDeque::from([root_file.to_path_buf()]);
    let mut seen = BTreeSet::new();
    let mut files = Vec::new();

    while let Some(path) = queue.pop_front() {
        deadline.check("single-file Python import closure")?;
        let path = path.canonicalize()?;
        if !seen.insert(path.clone()) {
            continue;
        }
        if source_language_for_path(&path) != SourceLanguage::Python {
            continue;
        }
        let bytes = fs::read(&path)?;
        deadline.check("single-file Python parse")?;
        if let Ok(parsed) =
            repotoire::python::parse_file(&rel_path_from(source_root, &path), &bytes)
        {
            deadline.check("single-file Python import resolution")?;
            for import in parsed.imports {
                deadline.check("single-file Python import resolution")?;
                let targets = python_import_target_files(source_root, &path, &import);
                deadline.check("single-file Python import resolution")?;
                for target in targets {
                    if !seen.contains(&target) {
                        queue.push_back(target);
                    }
                }
            }
        }
        files.push((path, bytes));
    }

    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

#[cfg(feature = "python")]
fn python_import_target_files(
    source_root: &Path,
    current_file: &Path,
    import: &repotoire::python::PythonImport,
) -> Vec<PathBuf> {
    let mut targets = Vec::new();
    match import.kind {
        repotoire::python::PythonImportKind::Import => {
            for name in &import.names {
                if let Some(target) = python_module_file(source_root, &name.name) {
                    targets.push(target);
                }
            }
        }
        repotoire::python::PythonImportKind::FromImport => {
            let module = python_from_import_module(source_root, current_file, import);
            if let Some(target) = python_module_file(source_root, &module) {
                targets.push(target);
            }
            for name in &import.names {
                if name.name == "*" {
                    continue;
                }
                let submodule = python_join_module_path(&module, &name.name);
                if let Some(target) = python_module_file(source_root, &submodule) {
                    targets.push(target);
                }
            }
        }
    }
    targets.sort();
    targets.dedup();
    targets
}

#[cfg(feature = "python")]
fn python_project_root_for_path(path: &Path) -> Option<PathBuf> {
    let start = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or(path)
    };
    for ancestor in start.ancestors() {
        if ancestor.join("pyproject.toml").is_file()
            || ancestor.join("setup.py").is_file()
            || ancestor.join("setup.cfg").is_file()
            || ancestor.join("requirements.txt").is_file()
            || ancestor.join(".git").is_dir()
        {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

#[cfg(feature = "python")]
fn python_from_import_module(
    source_root: &Path,
    current_file: &Path,
    import: &repotoire::python::PythonImport,
) -> String {
    let module = import.module.as_deref().unwrap_or("");
    if import.level == 0 {
        return module.to_string();
    }

    let current_module = python_module_path_for_file(source_root, current_file);
    let base_module = if python_file_is_package_init(current_file) {
        current_module.as_str()
    } else {
        current_module
            .rsplit_once('.')
            .map(|(parent, _)| parent)
            .unwrap_or("")
    };
    let mut base = base_module
        .split('.')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    for _ in 1..import.level {
        base.pop();
    }
    if !module.is_empty() {
        base.extend(module.split('.').map(str::to_string));
    }
    base.join(".")
}

#[cfg(feature = "python")]
fn python_module_file(source_root: &Path, module: &str) -> Option<PathBuf> {
    if module.is_empty() {
        return None;
    }
    let rel = module.replace('.', "/");
    let base = source_root.join(rel);
    let module_file = base.with_extension("py");
    if module_file.is_file() {
        return module_file.canonicalize().ok();
    }
    let package_init = base.join("__init__.py");
    if package_init.is_file() {
        return package_init.canonicalize().ok();
    }
    None
}

#[cfg(feature = "python")]
fn python_module_path_for_file(source_root: &Path, file: &Path) -> String {
    let rel = rel_path_from(source_root, file);
    let trimmed = rel.trim_end_matches(".py");
    let mut parts = trimmed
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.last() == Some(&"__init__") {
        parts.pop();
    }
    parts.join(".")
}

#[cfg(feature = "python")]
fn python_file_is_package_init(path: &Path) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some("__init__.py")
}

#[cfg(feature = "python")]
fn python_join_module_path(module: &str, name: &str) -> String {
    if module.is_empty() {
        name.to_string()
    } else {
        format!("{module}.{name}")
    }
}

fn rust_module_candidates(
    current_file: &Path,
    current_module_path: Option<&str>,
    mod_name: &str,
) -> Vec<PathBuf> {
    let parent = current_file.parent().unwrap_or_else(|| Path::new(""));
    let stem = current_file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let base = if is_module_root_path(current_module_path)
        || stem == "lib"
        || stem == "main"
        || stem == "mod"
    {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    };
    vec![
        base.join(format!("{mod_name}.rs")),
        base.join(mod_name).join("mod.rs"),
    ]
}

pub fn suppress_scoped_out_existing_relative_phantoms(
    diagnostics: &mut Vec<Diagnostic>,
    source_root: &Path,
) {
    diagnostics.retain(|diag| !is_scoped_out_existing_relative_phantom(diag, source_root));
}

fn is_scoped_out_existing_relative_phantom(diag: &Diagnostic, source_root: &Path) -> bool {
    let DiagnosticKind::PhantomImport { specifier } = &diag.kind else {
        return false;
    };
    if !is_relative_specifier(specifier) {
        return false;
    }
    let importer = source_root.join(&diag.file_path);
    let Some(target) = resolve_relative_source_file(&importer, specifier) else {
        return false;
    };
    !target.starts_with(source_root)
}

fn relative_import_specifiers(path: &Path, bytes: &[u8]) -> Vec<String> {
    let parsed = repotoire::ts::parse_file(&path.to_string_lossy(), bytes);
    let mut specifiers = parsed
        .events
        .iter()
        .filter_map(|event| match event {
            Event::Ref(RefEvent::Import { specifier, .. }) if is_relative_specifier(specifier) => {
                Some(specifier.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    specifiers.extend(parsed.exports.iter().filter_map(|entry| match entry {
        ExportEntry::NamedFrom { from, .. }
        | ExportEntry::Namespace { from, .. }
        | ExportEntry::NamespaceAs { from, .. }
            if is_relative_specifier(from) =>
        {
            Some(from.clone())
        }
        _ => None,
    }));
    specifiers
}

fn is_relative_specifier(specifier: &str) -> bool {
    specifier == "."
        || specifier == ".."
        || specifier.starts_with("./")
        || specifier.starts_with("../")
}

fn resolve_relative_source_file(importer: &Path, specifier: &str) -> Option<std::path::PathBuf> {
    let specifier = specifier.split(['?', '#']).next().unwrap_or(specifier);
    let base = importer.parent()?;
    let candidate = base.join(specifier);
    probe_source_file(&candidate)
}

const PROBE_EXTS: &[&str] = &[".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"];

fn probe_source_file(candidate: &Path) -> Option<std::path::PathBuf> {
    if candidate.is_file() && source_language_for_path(candidate) == SourceLanguage::TypeScript {
        return candidate.canonicalize().ok();
    }
    if let Some(source_rewrite) = probe_runtime_source_rewrite(candidate) {
        return Some(source_rewrite);
    }
    for ext in PROBE_EXTS {
        let with_ext = path_with_appended_ext(candidate, ext);
        if with_ext.is_file() && source_language_for_path(&with_ext) == SourceLanguage::TypeScript {
            return with_ext.canonicalize().ok();
        }
    }
    for ext in PROBE_EXTS {
        let index = candidate.join(format!("index{ext}"));
        if index.is_file() && source_language_for_path(&index) == SourceLanguage::TypeScript {
            return index.canonicalize().ok();
        }
    }
    None
}

fn probe_runtime_source_rewrite(candidate: &Path) -> Option<std::path::PathBuf> {
    const RUNTIME_TO_SOURCE_EXTS: &[(&str, &[&str])] = &[
        (".js", &[".ts", ".tsx", ".d.ts"]),
        (".jsx", &[".tsx"]),
        (".mjs", &[".mts", ".d.mts"]),
        (".cjs", &[".cts", ".d.cts"]),
    ];

    let candidate = candidate.to_string_lossy();
    for (runtime_ext, source_exts) in RUNTIME_TO_SOURCE_EXTS {
        let Some(base) = candidate.strip_suffix(runtime_ext) else {
            continue;
        };
        for source_ext in *source_exts {
            let source = PathBuf::from(format!("{base}{source_ext}"));
            if source.is_file() && source_language_for_path(&source) == SourceLanguage::TypeScript {
                return source.canonicalize().ok();
            }
        }
    }
    None
}

fn path_with_appended_ext(candidate: &Path, ext: &str) -> PathBuf {
    let mut path = candidate.as_os_str().to_os_string();
    path.push(ext);
    PathBuf::from(path)
}

fn common_parent_dir<'a>(mut paths: impl Iterator<Item = &'a Path>) -> Option<std::path::PathBuf> {
    let first = paths.next()?;
    let mut common = first.parent().unwrap_or(first).to_path_buf();
    for path in paths {
        let parent = path.parent().unwrap_or(path);
        while !parent.starts_with(&common) {
            if !common.pop() {
                return None;
            }
        }
    }
    Some(common)
}

fn rel_path_from(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .and_then(|rel| {
            let text = rel
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            (!text.is_empty()).then_some(text)
        })
        .or_else(|| relative_path_between(root, path))
        .or_else(|| path.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

fn relative_path_between(root: &Path, path: &Path) -> Option<String> {
    let root_components = root.components().collect::<Vec<_>>();
    let path_components = path.components().collect::<Vec<_>>();
    let mut common = 0usize;
    while common < root_components.len()
        && common < path_components.len()
        && root_components[common] == path_components[common]
    {
        common += 1;
    }
    if common == 0 {
        return None;
    }
    let mut parts = Vec::new();
    for component in &root_components[common..] {
        if matches!(component, std::path::Component::Normal(_)) {
            parts.push("..".to_string());
        }
    }
    for component in &path_components[common..] {
        parts.push(component.as_os_str().to_string_lossy().into_owned());
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// Human-readable message emitted when a project root contains no
/// supported sources. Shared by the CLI and the MCP ops layer.
pub fn empty_corpus_message(project_root: &Path) -> String {
    let extensions = if cfg!(feature = "python") {
        "`.ts`, `.tsx`, `.mts`, `.cts`, `.jsx`, `.js`, `.mjs`, `.cjs`, `.rs`, `.py`, `.pyi`"
    } else {
        "`.ts`, `.tsx`, `.mts`, `.cts`, `.jsx`, `.js`, `.mjs`, `.cjs`, `.rs`"
    };
    let languages = if cfg!(feature = "python") {
        "TypeScript, JavaScript, Rust, or Python"
    } else {
        "TypeScript, JavaScript, or Rust"
    };
    format!(
        "No supported source files found in `{root}`.\n\n\
         repotoire walks files with these extensions: \
         {extensions}.\n\n\
         No source files matching the supported extensions were found. \
         Point `CLAUDE_PROJECT_DIR` (or the `path` argument) at a directory that \
         contains {languages} sources.",
        root = project_root.display(),
    )
}

/// True iff `path`'s language is one the extractor is TRUSTED to have walked
/// into declarations completely enough that ABSENCE from a complete inventory
/// proves deletion (checkpoint rule D). TypeScript/JavaScript only — both map
/// to `SourceLanguage::TypeScript` via the canonical path classifier, so this
/// reuses that mapping.
/// Rust/Python are NOT trusted (R1: extractor construct gaps); promoting a
/// language requires benchmark evidence by policy.
pub fn extraction_trusted_for_deletion(path: &Path) -> bool {
    source_language_for_path(path) == SourceLanguage::TypeScript
}

fn insert_source_language_presence(languages: &mut BTreeSet<&'static str>, path: &Path) {
    let language = source_language_for_path(path);
    if language != SourceLanguage::Unknown {
        languages.insert(language.canonical_label());
    }
}

/// Programming-language file extensions repotoire recognizes as *source* but
/// has no analyzer for. Used only to make coverage blindness loud: a file with
/// one of these extensions was seen on disk but skipped, so it is counted
/// rather than dropped silently. Deliberately excludes data/markup/config
/// extensions (`.json`, `.md`, `.css`, …) — those are not a code-graph gap.
/// `.py` is included here only when the Python feature is OFF (when it is ON,
/// `source_language` claims it and it never reaches the skip path).
const UNSUPPORTED_SOURCE_EXTS: &[&str] = &[
    "go",
    "rb",
    "java",
    "kt",
    "kts",
    "swift",
    "c",
    "h",
    "cc",
    "cpp",
    "cxx",
    "hpp",
    "hh",
    "cs",
    "php",
    "scala",
    "clj",
    "ex",
    "exs",
    "erl",
    "hs",
    "ml",
    "lua",
    "dart",
    "groovy",
    "mm",
    "pl",
    "pm",
    "jl",
    "zig",
    "nim",
    "vb",
    "fs",
    "fsx",
    #[cfg(not(feature = "python"))]
    "py",
    #[cfg(not(feature = "python"))]
    "pyi",
];

/// Lowercase extension (no dot) of a file that LOOKS like source but has no
/// analyzer — `Some` only for the recognized-unsupported set above.
pub(crate) fn unsupported_source_extension(path: &Path) -> Option<String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())?
        .to_ascii_lowercase();
    UNSUPPORTED_SOURCE_EXTS
        .contains(&ext.as_str())
        .then_some(ext)
}
