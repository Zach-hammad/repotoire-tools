use ignore::WalkBuilder;
use repotoire::csr::{CodeGraph, NameIndex};
use repotoire::docs::{
    decode_markdown_doc, decode_markdown_docs, DocChangeOrder, DocDecodeOptions, DocDecodeReport,
    DocDiagnostic, DocDiagnosticCode, DocGraph, DocNode, DocNodeKind, DocReferenceHistory,
    DocSource, DocVerificationEvidence,
};
use repotoire::evidence::{
    AgentEvidenceShape, ClaimVerificationStatus, ConsumerEvidenceView, EvidenceBundle,
    EvidenceDiagnostic, EvidenceLocation, EvidenceRepoRef,
};
use repotoire::markdown::{parse_markdown, MarkdownFact, MarkdownFactKind};
use repotoire::schema::{EdgeKind, NodeKind};
use repotoire::source_pipeline::{
    parser_supports_source_language, source_language_for_path, SourceLanguage,
};
use repotoire::spans::{LineCol, LineIndex, Span};
use repotoire::ts::diagnostics::Diagnostic;
use repotoire::ts::lexer::{Lexer, Token, TokenKind};
use repotoire::ts::{parse_file, DeclEvent, Event, ExportEntry};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use std::time::{Duration, Instant};

use crate::deadline::ObservationScope;

use crate::agent_abi::{
    AgentDiagnostic, AgentEvidence, AgentEvidenceKind, AgentPacket, AgentQuery,
    AgentSourceLocation, AgentUncertainty, PACKET_VERSION,
};

// v1 could promote fresh references to verified prose. Persisted v1 reports
// must be regenerated, even when their source fingerprints still match.
pub const DOCS_TRUTH_SCHEMA: &str = "repotoire.docs_truth.v2";
pub(crate) const DOCS_COLLECTION_SCHEMA: &str = "repotoire.docs_collection.v1";
const MAX_COLLECTION_DOCUMENTS: usize = 10_000;
const MAX_COLLECTION_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_COLLECTION_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_COLLECTION_FACTS: usize = 100_000;
// Reserve space inside the host's 16 MiB retained evidence envelope.
const MAX_COLLECTION_OUTPUT_BYTES: usize = 12 * 1024 * 1024;
const MAX_COLLECTION_WALK_ENTRIES: usize = 100_000;
const COLLECTION_SOURCE_LIMITS: crate::walk::SourceInventoryLimits =
    crate::walk::SourceInventoryLimits {
        files: 10_000,
        file_bytes: 4 * 1024 * 1024,
        total_bytes: 128 * 1024 * 1024,
    };
pub const DOCS_TRUTH_SERUM_SLICE_SCHEMA: &str = "repotoire.truth_serum.slice.v1";
const GIT_HISTORY_TIMEOUT: Duration = Duration::from_secs(5);
const GIT_HISTORY_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const GIT_HISTORY_OUTPUT_LIMIT: usize = 1024 * 1024;
const MAX_GIT_HISTORY_LINES: u32 = 10_000;
const MAX_GIT_HISTORY_REFERENCES: u32 = 64;
const MAX_GIT_HISTORY_PROCESSES: u32 = 256;
const GIT_DIRTY_SCAN_PROCESSES: u32 = 1;
const MAX_GIT_HISTORY_PROCESSES_PER_REFERENCE: u32 = 3;

#[derive(Debug)]
struct GitHistoryBudget {
    references_remaining: u32,
    processes_remaining: u32,
    deadline: Instant,
}

impl GitHistoryBudget {
    fn for_request() -> Self {
        assert!(
            max_git_history_processes_for(MAX_GIT_HISTORY_REFERENCES) <= MAX_GIT_HISTORY_PROCESSES,
            "the configured Git process budget must cover the maximum reference request"
        );
        Self::new(
            MAX_GIT_HISTORY_REFERENCES,
            MAX_GIT_HISTORY_PROCESSES,
            GIT_HISTORY_REQUEST_TIMEOUT,
        )
    }

    fn new(references: u32, processes: u32, timeout: Duration) -> Self {
        Self {
            references_remaining: references,
            processes_remaining: processes,
            deadline: Instant::now() + timeout,
        }
    }

    fn admit_reference(&mut self) -> bool {
        if self.references_remaining == 0 || Instant::now() >= self.deadline {
            return false;
        }
        self.references_remaining -= 1;
        true
    }

    fn process_timeout(&mut self) -> Option<Duration> {
        if self.processes_remaining == 0 {
            return None;
        }
        let remaining = self.deadline.checked_duration_since(Instant::now())?;
        if remaining.is_zero() {
            return None;
        }
        self.processes_remaining -= 1;
        Some(remaining.min(GIT_HISTORY_TIMEOUT))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GitLineHistoryKey {
    path: String,
    start_line: u32,
    end_line: u32,
}

#[derive(Debug)]
struct GitHistoryContext {
    budget: GitHistoryBudget,
    checked_paths: BTreeSet<String>,
    dirty_paths: Option<BTreeSet<String>>,
    line_changes: BTreeMap<GitLineHistoryKey, Option<GitLineChange>>,
    change_orders: BTreeMap<(String, String), DocChangeOrder>,
}

impl GitHistoryContext {
    fn for_request(root: &Path, paths: &BTreeSet<String>) -> Self {
        let mut context = Self {
            budget: GitHistoryBudget::for_request(),
            checked_paths: paths.clone(),
            dirty_paths: None,
            line_changes: BTreeMap::new(),
            change_orders: BTreeMap::new(),
        };
        context.dirty_paths = git_dirty_paths(&mut context.budget, root, paths);
        context
    }

    fn admit_reference(&mut self) -> bool {
        self.budget.admit_reference()
    }

    fn path_is_clean(&self, path: &str) -> Option<bool> {
        if !self
            .checked_paths
            .iter()
            .any(|checked_path| same_rel_path(checked_path, path))
        {
            return None;
        }
        let dirty_paths = self.dirty_paths.as_ref()?;
        Some(
            !dirty_paths
                .iter()
                .any(|dirty_path| same_rel_path(dirty_path, path)),
        )
    }
}

fn max_git_history_processes_for(reference_count: u32) -> u32 {
    GIT_DIRTY_SCAN_PROCESSES
        .saturating_add(reference_count.saturating_mul(MAX_GIT_HISTORY_PROCESSES_PER_REFERENCE))
}

#[derive(Debug)]
pub enum DocsTruthError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    CurrentView(String),
    CollectionLimit(&'static str),
}

impl fmt::Display for DocsTruthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "error reading {}: {source}", path.display()),
            Self::CurrentView(message) => write!(f, "{message}"),
            Self::CollectionLimit(resource) => write!(
                f,
                "documentation collection limit: {resource}; no complete report was produced"
            ),
        }
    }
}

impl std::error::Error for DocsTruthError {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DocsTruthOptions;

/// Freshness provenance captured at report-generation time. This is the ONLY honest
/// source of "when / against what" a docs-truth report was measured. The cockpit's
/// truth-serum transcoder must copy these persisted values through verbatim; it must
/// never re-derive them from its own run time (that would make every freshness check
/// compare a value against itself and never go stale). If this field is absent, the
/// transcoder forces Unknown.
#[derive(Debug, Clone, Serialize)]
pub struct DocsTruthProvenance {
    /// Wall-clock time (ms since epoch) when the report was built.
    pub generated_at_ms: u64,
    /// Git HEAD of `root` at build time, if resolvable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_head: Option<String>,
    /// Content fingerprint of `checked_paths` at build time.
    pub dirty_fingerprint: String,
    /// Absolute paths whose content `dirty_fingerprint` covers; the transcoder reuses
    /// these so the cockpit recomputes its fingerprint over the identical set.
    pub checked_paths: Vec<String>,
    /// Versioned digest of the captured documentation inventory and admission inputs.
    pub inventory_fingerprint: String,
}

#[derive(Debug, Serialize)]
pub struct DocsTruthReport {
    pub schema: &'static str,
    pub root: String,
    pub provenance: DocsTruthProvenance,
    pub scorecard: DocsTruthScorecard,
    /// Structural decode graph only -- NOT a truth signal. A `references_code` edge here means
    /// "the doc text mentions this code path", not "the referenced code exists / the claim is
    /// proven". The authoritative verification status lives in `consumer_view`
    /// (`verification_statuses`) and `agent_evidence[].proof_status`; consumers must read those,
    /// not the raw `doc_decode` edges, to decide whether a documented claim is verified.
    pub doc_decode: DocDecodeReport,
    pub evidence: EvidenceBundle,
    pub consumer_view: ConsumerEvidenceView,
    pub agent_evidence: Vec<AgentEvidenceShape>,
    pub truth_serum: DocsTruthSerumSlice,
    pub facts: Vec<DocsTruthFact>,
    pub drifts: Vec<DocsTruthDrift>,
    pub diagnostics: Vec<DocsTruthDiagnostic>,
}

/// A collection is an input to review, never a substitute for a verified truth
/// report. Each selected document is accounted for; decoder diagnostics are
/// counted by category rather than repeating source text and graph projections.
#[derive(Debug, Serialize)]
struct DocsCollectionReport {
    schema: &'static str,
    root: String,
    provenance: DocsTruthProvenance,
    scorecard: DocsTruthScorecard,
    documents: Vec<CollectedDocument>,
    facts: Vec<DocsTruthFact>,
    drifts: Vec<DocsTruthDrift>,
    diagnostics: Vec<DocsTruthDiagnostic>,
}

impl DocsCollectionReport {
    fn into_json(self) -> Result<Vec<u8>, DocsTruthError> {
        struct BoundedJson(Vec<u8>);
        impl std::io::Write for BoundedJson {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.0.len().saturating_add(bytes.len()) >= MAX_COLLECTION_OUTPUT_BYTES {
                    return Err(std::io::Error::other("collection output limit"));
                }
                self.0.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut output = BoundedJson(Vec::new());
        serde_json::to_writer(&mut output, &self)
            .map_err(|_| DocsTruthError::CollectionLimit("serialized output"))?;
        output.0.push(b'\n');
        Ok(output.0)
    }
}

#[derive(Debug, Serialize)]
struct CollectedDocument {
    entry: String,
    source_bytes: u64,
    decoded_nodes: u64,
    decoded_edges: u64,
    // Structural decoding cannot verify prose, even when no diagnostic exists.
    proof_status: &'static str,
    diagnostic_groups: Vec<CollectedDiagnostic>,
}

#[derive(Debug, Serialize)]
struct CollectedDiagnostic {
    kind: &'static str,
    count: u64,
    reason: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReportView {
    Detailed,
    Collection,
}

#[derive(Debug)]
enum ReportOutput {
    Detailed(Box<DocsTruthReport>),
    Collection(DocsCollectionReport),
}

impl DocsTruthReport {
    /// Find documents that explicitly reference any input in the requested source
    /// snapshot. Returned facts borrow this report's evidence, including references
    /// whose targets could not be resolved. They identify review candidates, not
    /// verified claims or a complete transitive semantic dependency closure.
    ///
    /// The caller must obtain `observed` from its source-observation owner. This
    /// lookup compares applicability; it does not observe the filesystem, refresh
    /// old evidence, or create another cache. Observation time alone is immaterial.
    /// For change selection, the caller supplies every changed or removed path,
    /// including both endpoints of a rename. Paths need not still exist: captured
    /// references remain review candidates even when their support disappears.
    /// Matching uses lexical path components, so repeated separators and interior
    /// `.` components and a leading `./` do not hide a dependency. No filesystem
    /// lookup is required.
    pub fn dependents_of(
        &self,
        support_inputs: &[&str],
        observed: &DocsTruthProvenance,
    ) -> Result<BTreeMap<&str, Vec<&DocsTruthFact>>, DocsTruthError> {
        let captured = &self.provenance;
        if captured.git_head != observed.git_head
            || captured.dirty_fingerprint != observed.dirty_fingerprint
            || captured.checked_paths != observed.checked_paths
            || captured.inventory_fingerprint != observed.inventory_fingerprint
        {
            return Err(DocsTruthError::CurrentView(
                "reverse documentation lookup requires matching source provenance".to_string(),
            ));
        }
        let support_inputs = support_inputs
            .iter()
            .map(|input| {
                documented_reference_path(input).ok_or_else(|| {
                    DocsTruthError::CurrentView(format!(
                        "reverse documentation lookup requires a repository-relative input: {input}"
                    ))
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let mut locations: BTreeMap<_, &DocsTruthFact> = BTreeMap::new();
        for fact in &self.facts {
            let Some(target) = fact.target.as_deref() else {
                continue;
            };
            let Some(identity) = documented_reference_path(target) else {
                continue;
            };
            if !support_inputs.contains(identity) {
                continue;
            }
            // One source span can have both file and symbol projections. Keep
            // the most detailed captured fact without duplicating the occurrence.
            locations
                .entry((
                    fact.file.as_str(),
                    fact.line,
                    fact.col,
                    fact.text.as_str(),
                    identity,
                ))
                .and_modify(|existing| {
                    if (fact.expected_return.is_some(), fact.symbol.is_some())
                        > (
                            existing.expected_return.is_some(),
                            existing.symbol.is_some(),
                        )
                    {
                        *existing = fact;
                    }
                })
                .or_insert(fact);
        }
        let mut dependents: BTreeMap<&str, Vec<&DocsTruthFact>> = BTreeMap::new();
        for fact in locations.into_values() {
            dependents.entry(&fact.file).or_default().push(fact);
        }
        Ok(dependents)
    }
}

#[derive(Debug, Default, Serialize)]
pub struct DocsTruthScorecard {
    pub markdown_files: u64,
    pub facts: u64,
    pub return_contracts: u64,
    pub drifts: u64,
    pub diagnostics: u64,
}

#[derive(Debug, Serialize)]
pub struct DocsTruthFact {
    pub kind: &'static str,
    pub file: String,
    pub line: u32,
    pub col: u32,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_return: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DocsTruthDrift {
    pub kind: &'static str,
    pub doc: DocsTruthLocation,
    pub source: DocsTruthLocation,
    pub symbol: String,
    pub expected_return: String,
    pub actual_return: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DocsTruthLocation {
    pub file: String,
    pub line: u32,
    pub col: u32,
}

#[derive(Debug, Serialize)]
pub struct DocsTruthDiagnostic {
    pub kind: String,
    pub message: String,
    pub file: String,
    pub line: u32,
    pub col: u32,
}

#[derive(Debug, Serialize)]
pub struct DocsTruthSerumSlice {
    pub schema: &'static str,
    pub covered_surfaces: Vec<&'static str>,
    pub scorecard: repotoire::truth::TruthSerumScorecard,
    pub diffs: Vec<DocsTruthSerumDiff>,
    pub cards: Vec<DocsTruthSerumCard>,
    pub diagnostics: Vec<DocsTruthSerumDiagnostic>,
    pub agent_packet: AgentPacket,
}

#[derive(Debug, Serialize)]
pub struct DocsTruthSerumDiff {
    pub kind: &'static str,
    pub classification: &'static str,
    pub graph_surface: &'static str,
    pub fixture_or_corpus_path: String,
    pub doc: DocsTruthLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<DocsTruthLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_return: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_return: Option<String>,
    pub truth_source: &'static str,
    pub truth_source_version: &'static str,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DocsTruthSerumCard {
    pub kind: &'static str,
    pub classification: &'static str,
    pub graph_surface: &'static str,
    pub fixture_or_corpus_path: String,
    pub truth_source: &'static str,
    pub truth_source_version: &'static str,
    pub diagnostic_code: &'static str,
    pub suspected_subsystem: &'static str,
    pub severity: &'static str,
    pub product_impact: &'static str,
    pub suggested_regression_test_location: &'static str,
    pub occurrence_count: u64,
    pub affected_paths: Vec<String>,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DocsTruthSerumDiagnostic {
    pub code: String,
    pub classification: &'static str,
    pub graph_surface: &'static str,
    pub file: String,
    pub line: u32,
    pub col: u32,
    pub severity: &'static str,
    pub message: String,
}

#[derive(Debug)]
struct LiteralReturn {
    value: String,
    line_col: LineCol,
}

#[derive(Debug)]
struct ReturnContractCheck {
    doc_file: String,
    source_file: String,
    symbol: String,
    expected_return: String,
    actual_return: String,
    status: ClaimVerificationStatus,
    evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CodeReferenceCandidate {
    target: String,
    symbol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiscoveredDocument {
    identity: String,
    path: PathBuf,
    format: String,
    declared: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum DocumentExclusionReason {
    OutsideRepository,
    HistoryDirectory(String),
    GeneratedDirectory(String),
    IgnorePolicy { file: String, pattern: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExcludedDocument {
    observed_path: String,
    identity: String,
    reason: DocumentExclusionReason,
}

#[derive(Debug, Default)]
struct DocumentDiscovery {
    included: Vec<DiscoveredDocument>,
    excluded: Vec<ExcludedDocument>,
    declaration_input: (PathBuf, Option<Vec<u8>>),
    policy_inputs: BTreeMap<PathBuf, ignore::gitignore::PolicyInputObservation>,
}

impl DocumentExclusionReason {
    fn message(&self) -> String {
        match self {
            Self::OutsideRepository => "outside repository root".to_string(),
            Self::HistoryDirectory(directory) => format!("history directory `{directory}`"),
            Self::GeneratedDirectory(directory) => format!("generated directory `{directory}`"),
            Self::IgnorePolicy { file, pattern } => {
                format!("ignore rule `{file}:{pattern}`")
            }
        }
    }
}

pub fn build_report(root: &Path) -> Result<DocsTruthReport, DocsTruthError> {
    build_report_with_options(root, DocsTruthOptions::default())
}

pub fn build_report_with_options(
    root: &Path,
    options: DocsTruthOptions,
) -> Result<DocsTruthReport, DocsTruthError> {
    build_report_with_observation_hook(root, options, || {})
}

fn build_report_with_observation_hook(
    root: &Path,
    _options: DocsTruthOptions,
    after_capture: impl FnOnce(),
) -> Result<DocsTruthReport, DocsTruthError> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let discovery = discover_documents(&root, ReportView::Detailed)?;
    match build_output_from_discovery(&root, discovery, ReportView::Detailed, after_capture)? {
        ReportOutput::Detailed(report) => Ok(*report),
        ReportOutput::Collection(_) => unreachable!("the requested view is fixed by the caller"),
    }
}

pub(crate) fn build_collection_json(
    root: &Path,
    _options: DocsTruthOptions,
) -> Result<Vec<u8>, DocsTruthError> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let discovery = discover_documents(&root, ReportView::Collection)?;
    let ReportOutput::Collection(report) =
        build_output_from_discovery(&root, discovery, ReportView::Collection, || {})?
    else {
        unreachable!("the requested view is fixed by the caller")
    };
    report.into_json()
}

fn build_output_from_discovery(
    root: &Path,
    discovery: DocumentDiscovery,
    view: ReportView,
    after_capture: impl FnOnce(),
) -> Result<ReportOutput, DocsTruthError> {
    if view == ReportView::Collection && discovery.included.len() > MAX_COLLECTION_DOCUMENTS {
        return Err(DocsTruthError::CollectionLimit("document count"));
    }
    let captured_inventory_fingerprint = inventory_fingerprint(root, &discovery, view)?;
    let captured_included = discovery.included.clone();
    let captured_excluded = discovery.excluded.clone();
    let declaration_input = discovery.declaration_input.clone();
    let policy_inputs = discovery.policy_inputs.clone();
    let mut scorecard = DocsTruthScorecard::default();
    let mut facts = Vec::new();
    let mut drifts = Vec::new();
    let mut diagnostics = Vec::new();
    let mut markdown_sources = Vec::new();
    let mut source_bytes = 0_u64;
    let mut contract_checks = Vec::new();
    let mut return_contract_facts = Vec::new();
    // Resolve each candidate once, but retain every affected documentation location.
    let mut code_reference_candidates: BTreeMap<CodeReferenceCandidate, Vec<DocsTruthLocation>> =
        BTreeMap::new();

    for exclusion in &discovery.excluded {
        diagnostics.push(DocsTruthDiagnostic {
            kind: "document_excluded".to_string(),
            message: format!(
                "excluded `{}` (canonical identity `{}`): {}",
                exclusion.observed_path,
                exclusion.identity,
                exclusion.reason.message()
            ),
            file: exclusion.observed_path.clone(),
            line: 0,
            col: 0,
        });
    }
    for document in discovery.included {
        if document.format != "markdown" {
            diagnostics.push(DocsTruthDiagnostic {
                kind: "unsupported_format".to_string(),
                message: format!(
                    "Document `{}` uses unsupported format `{}`; no capable decoder is available, so its content has not been verified",
                    document.identity, document.format
                ),
                file: document.identity,
                line: 0,
                col: 0,
            });
            continue;
        }
        let path = document.path;
        let rel = document.identity;
        let contents = read_document_source(&path, view, &mut source_bytes)?;
        scorecard.markdown_files += 1;
        let graph = parse_markdown(&rel, &contents);
        for diagnostic in graph.diagnostics {
            diagnostics.push(DocsTruthDiagnostic {
                kind: diagnostic.kind,
                message: diagnostic.message,
                file: rel.clone(),
                line: diagnostic.line,
                col: diagnostic.col,
            });
        }
        if view == ReportView::Collection
            && facts.len().saturating_add(graph.facts.len()) > MAX_COLLECTION_FACTS
        {
            return Err(DocsTruthError::CollectionLimit("fact count"));
        }
        for fact in graph.facts {
            collect_code_reference_candidate(&rel, &fact, &mut code_reference_candidates);
            if fact.kind == MarkdownFactKind::ReturnContract {
                scorecard.return_contracts += 1;
                return_contract_facts.push((rel.clone(), fact.clone()));
            }
            facts.push(to_report_fact(&rel, fact));
        }
        markdown_sources.push((rel, contents));
    }

    let discovery_queries = doc_support_queries(root, &markdown_sources);
    let codebase =
        load_docs_codebase_view(root, &code_reference_candidates, &discovery_queries, view)?;
    let source_files = codebase
        .as_ref()
        .map(crate::project::CodebaseView::source_file_refs);
    let code_graph = codebase.as_ref().map(crate::project::CodebaseView::graph);
    let name_index = code_graph.as_ref().map(NameIndex::build);
    let code_reference_resolver = match (
        codebase.as_ref(),
        source_files.as_deref(),
        code_graph.as_ref(),
        name_index.as_ref(),
    ) {
        (Some(codebase), Some(source_files), Some(graph), Some(name_index)) => Some(
            CodeReferenceResolver::new(codebase, source_files, graph, name_index),
        ),
        (None, None, None, None) => None,
        _ => unreachable!("CodebaseView projections are constructed atomically"),
    };
    for (doc_file, fact) in &return_contract_facts {
        if let Some(check) = check_return_contract(
            source_files.as_deref(),
            doc_file,
            fact,
            &mut drifts,
            &mut diagnostics,
        ) {
            contract_checks.push(check);
        }
    }
    let (decode_options, code_reference_gaps) = doc_decode_options(
        root,
        code_reference_resolver.as_ref(),
        &code_reference_candidates,
    );
    // A present-but-unverifiable reference (for example, a re-exported, member, or aliased symbol) is a
    // non-blocking truth_source_gap, not a blocking silent_divergence. Surface it explicitly with
    // the doc-file location so agents see an explained gap rather than a verified or a contradicted
    // claim.
    diagnostics.extend(code_reference_gaps);
    let provenance = build_docs_truth_provenance(
        root,
        &markdown_sources,
        code_reference_resolver.as_ref(),
        &code_reference_candidates,
        &drifts,
        captured_inventory_fingerprint,
    );
    let report = if view == ReportView::Collection {
        let mut documents = Vec::with_capacity(captured_included.len());
        let mut decode_diagnostics = 0_u64;
        for document in &captured_included {
            ObservationScope::check_current("documentation collection decode")
                .map_err(|error| DocsTruthError::CurrentView(error.to_string()))?;
            let mut summary = CollectedDocument {
                entry: document.identity.clone(),
                source_bytes: 0,
                decoded_nodes: 0,
                decoded_edges: 0,
                proof_status: "unverified",
                diagnostic_groups: Vec::new(),
            };
            if let Some((_, contents)) = markdown_sources
                .iter()
                .find(|(file, _)| file == &document.identity)
            {
                let graph =
                    decode_markdown_doc(&document.identity, contents, decode_options.clone());
                summary.source_bytes = contents.len() as u64;
                summary.decoded_nodes = graph.nodes.len() as u64;
                summary.decoded_edges = graph.edges.len() as u64;
                let mut counts = [0_u64; 4];
                for diagnostic in graph.diagnostics {
                    let index = match diagnostic.code {
                        DocDiagnosticCode::AmbiguousClaim => 0,
                        DocDiagnosticCode::UnsupportedSyntax => 1,
                        DocDiagnosticCode::UnresolvedReference => 2,
                        DocDiagnosticCode::UnsupportedFormat => 3,
                    };
                    counts[index] += 1;
                    decode_diagnostics += 1;
                }
                for (index, (kind, reason)) in [
                    ("ambiguous_claim", "Claim cannot be decoded unambiguously; its meaning and support remain unverified"),
                    ("unsupported_syntax", "Text has no supported claim rule; structural collection cannot verify it"),
                    ("unresolved_reference", "Documented reference lacks an admitted source or symbol; the claim remains unverified"),
                    ("unsupported_format", "No capable decoder is available; content remains unverified"),
                ].into_iter().enumerate() {
                    if counts[index] != 0 {
                        summary.diagnostic_groups.push(CollectedDiagnostic { kind, count: counts[index], reason });
                    }
                }
            } else {
                summary.diagnostic_groups.push(CollectedDiagnostic {
                    kind: "unsupported_format",
                    count: 1,
                    reason: "No capable decoder is available; content remains unverified",
                });
            }
            documents.push(summary);
        }
        scorecard.facts = facts.len() as u64;
        scorecard.drifts = drifts.len() as u64;
        scorecard.diagnostics = diagnostics.len() as u64 + decode_diagnostics;
        ReportOutput::Collection(DocsCollectionReport {
            schema: DOCS_COLLECTION_SCHEMA,
            root: root.to_string_lossy().into_owned(),
            provenance,
            scorecard,
            documents,
            facts,
            drifts,
            diagnostics,
        })
    } else {
        let mut doc_decode = decode_markdown_docs(
            markdown_sources
                .iter()
                .map(|(file, contents)| DocSource::new(file.as_str(), contents.as_str())),
            decode_options,
        );
        let proposal_subjects = unlinked_doc_subjects(&doc_decode.graphs);
        propose_doc_support(
            &mut doc_decode,
            proposal_subjects,
            &markdown_sources,
            codebase.as_ref(),
        );
        let history_paths =
            history_paths_for_doc_decode(&doc_decode, code_reference_resolver.as_ref());
        let mut history = GitHistoryContext::for_request(root, &history_paths);
        let mut evidence = evidence_bundle_for_doc_decode(
            root,
            &markdown_sources,
            &doc_decode,
            code_reference_resolver.as_ref(),
            &mut history,
        );
        apply_return_contract_checks(&mut evidence, &contract_checks);
        let consumer_view = evidence.consumer_view();
        let agent_evidence = agent_evidence_for_doc_decode(&doc_decode, &evidence);
        scorecard.facts = facts.len() as u64;
        scorecard.drifts = drifts.len() as u64;
        scorecard.diagnostics = diagnostics.len() as u64 + doc_decode.scorecard.diagnostics;
        let truth_serum =
            build_truth_serum_slice(root, &scorecard, &drifts, &diagnostics, &evidence);
        ReportOutput::Detailed(Box::new(DocsTruthReport {
            schema: DOCS_TRUTH_SCHEMA,
            root: root.to_string_lossy().into_owned(),
            provenance,
            scorecard,
            doc_decode,
            evidence,
            consumer_view,
            agent_evidence,
            truth_serum,
            facts,
            drifts,
            diagnostics,
        }))
    };
    after_capture();
    validate_generation_snapshot(
        root,
        &captured_included,
        &captured_excluded,
        &declaration_input,
        &policy_inputs,
        &markdown_sources,
        codebase.as_ref(),
        view,
    )?;
    let provenance = match &report {
        ReportOutput::Detailed(report) => &report.provenance,
        ReportOutput::Collection(report) => &report.provenance,
    };
    if inventory_fingerprint(root, &discover_documents(root, view)?, view)?
        != provenance.inventory_fingerprint
    {
        return Err(DocsTruthError::CurrentView(
            "proposal discovery inputs changed during report generation".to_string(),
        ));
    }
    Ok(report)
}

fn read_document_source(
    path: &Path,
    view: ReportView,
    total: &mut u64,
) -> Result<String, DocsTruthError> {
    let contents = if view == ReportView::Collection {
        use std::io::Read;
        let limit =
            MAX_COLLECTION_DOCUMENT_BYTES.min(MAX_COLLECTION_SOURCE_BYTES.saturating_sub(*total));
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(limit + 1).read_to_end(&mut bytes))
            .map_err(|source| DocsTruthError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if bytes.len() as u64 > limit {
            return Err(DocsTruthError::CollectionLimit("document source bytes"));
        }
        String::from_utf8(bytes).map_err(|error| DocsTruthError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
        })?
    } else {
        std::fs::read_to_string(path).map_err(|source| DocsTruthError::Io {
            path: path.to_path_buf(),
            source,
        })?
    };
    *total += contents.len() as u64;
    Ok(contents)
}

fn validate_generation_snapshot(
    root: &Path,
    included: &[DiscoveredDocument],
    excluded: &[ExcludedDocument],
    declaration_input: &(PathBuf, Option<Vec<u8>>),
    policy_inputs: &BTreeMap<PathBuf, ignore::gitignore::PolicyInputObservation>,
    markdown_sources: &[(String, String)],
    codebase: Option<&crate::project::CodebaseView>,
    view: ReportView,
) -> Result<(), DocsTruthError> {
    let current = discover_documents(root, view)?;
    if current.included != included || current.excluded != excluded {
        return Err(DocsTruthError::CurrentView(
            "documentation membership or exclusion reasons changed during report generation"
                .to_string(),
        ));
    }
    if &current.declaration_input != declaration_input {
        return Err(DocsTruthError::CurrentView(format!(
            "document declarations changed during report generation: {}",
            declaration_input.0.display()
        )));
    }
    if &current.policy_inputs != policy_inputs
        || policy_inputs
            .values()
            .chain(current.policy_inputs.values())
            .any(|observation| {
                matches!(
                    observation,
                    ignore::gitignore::PolicyInputObservation::ChangedDuringCapture
                )
            })
    {
        return Err(DocsTruthError::CurrentView(
            "ignore policy inputs changed during report generation".to_string(),
        ));
    }
    for (relative, captured) in markdown_sources {
        let path = root.join(relative);
        use std::io::Read;
        let mut current = Vec::new();
        std::fs::File::open(&path)
            .and_then(|file| {
                file.take(captured.len() as u64 + 1)
                    .read_to_end(&mut current)
            })
            .map_err(|source| DocsTruthError::Io {
                path: path.clone(),
                source,
            })?;
        if current != captured.as_bytes() {
            return Err(DocsTruthError::CurrentView(format!(
                "document changed during report generation: {}",
                path.display()
            )));
        }
    }
    if let Some(codebase) = codebase {
        codebase
            .validate_reference_snapshot()
            .map_err(|(path, source)| {
                if source.kind() == std::io::ErrorKind::InvalidData {
                    DocsTruthError::CurrentView(source.to_string())
                } else {
                    DocsTruthError::Io { path, source }
                }
            })?;
    }
    Ok(())
}

/// Capture freshness provenance at report-generation time. The fingerprint covers the
/// doc + source files this report actually read, resolved to absolute paths under
/// `root`. These same `checked_paths` are persisted so the cockpit recomputes its
/// fingerprint over an identical set; any post-build content change then diverges.
fn build_docs_truth_provenance(
    root: &Path,
    markdown_sources: &[(String, String)],
    resolver: Option<&CodeReferenceResolver<'_>>,
    code_references: &BTreeMap<CodeReferenceCandidate, Vec<DocsTruthLocation>>,
    drifts: &[DocsTruthDrift],
    inventory_fingerprint: String,
) -> DocsTruthProvenance {
    let mut checked = BTreeSet::new();
    let mut push = |rel: &str| {
        if rel.is_empty() {
            return;
        }
        let abs = root.join(rel);
        let abs = abs.canonicalize().unwrap_or(abs);
        checked.insert(abs.to_string_lossy().into_owned());
    };
    for (file, _) in markdown_sources {
        push(file);
    }
    for reference in code_references
        .keys()
        .filter(|reference| documented_reference_path(&reference.target).is_some())
    {
        push(&reference.target);
    }
    // Proposal lookup examines parsed sources beyond explicit references. Bind
    // their captured bytes too, even when the lookup finds no candidate.
    if let Some(resolver) = resolver {
        for path in resolver.source_by_path.keys() {
            push(path);
        }
    }
    for drift in drifts {
        push(&drift.doc.file);
        push(&drift.source.file);
    }
    if checked.is_empty() {
        checked.insert(root.to_string_lossy().into_owned());
    }
    let checked_paths: Vec<String> = checked.into_iter().collect();
    let generated_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let captured_inputs = checked_paths
        .iter()
        .map(|path| {
            let logical = repotoire::source_pipeline::canonical_project_path(root, Path::new(path));
            let bytes = markdown_sources
                .iter()
                .find(|(file, _)| same_rel_path(file, &logical))
                .map(|(_, contents)| contents.as_bytes())
                .or_else(|| resolver.and_then(|resolver| resolver.file_bytes(&logical)));
            (Path::new(path), bytes)
        })
        .collect::<Vec<_>>();
    let dirty_fingerprint =
        crate::truth_serum::dirty_fingerprint_for_captured_paths(root, captured_inputs);
    let git_head = crate::provenance::git_sha(root);
    DocsTruthProvenance {
        generated_at_ms,
        git_head,
        dirty_fingerprint,
        checked_paths,
        inventory_fingerprint,
    }
}

/// Recompute document admission and all source bytes consulted by lexical proposal
/// discovery, including sources that did not previously match a documented subject.
pub(crate) fn current_inventory_fingerprint(root: &Path) -> Result<String, String> {
    // The caller owns the observation budget. Report generation must not inherit
    // the short interactive-readiness cap, but still honors request cancellation
    // and deadlines through discovery, hashing, and final completion.
    ObservationScope::current()
        .run(|| {
            let discovery = discover_documents(root, ReportView::Detailed)
                .map_err(|error| error.to_string())?;
            inventory_fingerprint(root, &discovery, ReportView::Detailed)
                .map_err(|error| error.to_string())
        })
        .map_err(|error| error.to_string())?
}

/// An inventory observation constrains a hosted repair; it is not proof that
/// a document is true or that an executable is approved.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DocumentationRepairInventory {
    pub(crate) fingerprint: String,
    pub(crate) documents: BTreeSet<String>,
}

impl DocumentationRepairInventory {
    pub(crate) fn validate_write_scopes(
        &self,
        writes: &repotoire::scope::ScopeSet,
    ) -> Result<(), String> {
        let allowed = self
            .documents
            .iter()
            .map(|path| {
                repotoire::scope::Scope::from_file_path(path).map_err(|error| error.to_string())
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if writes.scopes().iter().any(|scope| {
            !matches!(scope, repotoire::scope::Scope::NoWrite) && !allowed.contains(scope)
        }) {
            return Err("repair write scopes must be exact selected document paths".into());
        }
        Ok(())
    }
}

/// Use the same discovery and policy owner as docs-truth. A directory scope
/// cannot become permission for future files merely because it contains docs.
pub(crate) fn admit_documentation_repair_scopes(
    root: &Path,
    writes: &repotoire::scope::ScopeSet,
) -> Result<DocumentationRepairInventory, String> {
    ObservationScope::current()
        .run(|| {
            let discovery = discover_documents(root, ReportView::Detailed)
                .map_err(|error| error.to_string())?;
            let documents = discovery
                .included
                .iter()
                .map(|document| document.identity.clone())
                .collect::<BTreeSet<_>>();
            let fingerprint = inventory_fingerprint(root, &discovery, ReportView::Detailed)
                .map_err(|error| error.to_string())?;
            let inventory = DocumentationRepairInventory {
                fingerprint,
                documents,
            };
            inventory.validate_write_scopes(writes)?;
            Ok(inventory)
        })
        .map_err(|error| error.to_string())?
}

fn inventory_fingerprint(
    root: &Path,
    discovery: &DocumentDiscovery,
    view: ReportView,
) -> Result<String, DocsTruthError> {
    use sha2::{Digest, Sha256};

    struct Encoder(Sha256);
    impl Encoder {
        fn field(&mut self, bytes: &[u8]) {
            self.0.update((bytes.len() as u64).to_be_bytes());
            self.0.update(bytes);
        }
        fn optional(&mut self, value: Option<&[u8]>) {
            match value {
                Some(bytes) => {
                    self.field(b"present");
                    self.field(bytes);
                }
                None => self.field(b"absent"),
            }
        }
    }

    let mut encoder = Encoder(Sha256::new());
    encoder.field(b"repotoire.docs_truth.inventory.v4");
    let mut included = discovery.included.iter().collect::<Vec<_>>();
    included.sort_by(|left, right| {
        (&left.identity, &left.format, left.declared).cmp(&(
            &right.identity,
            &right.format,
            right.declared,
        ))
    });
    encoder.field(&(included.len() as u64).to_be_bytes());
    for document in included {
        encoder.field(b"included");
        encoder.field(document.identity.as_bytes());
        encoder.field(document.format.as_bytes());
        encoder.field(&[u8::from(document.declared)]);
    }

    let mut excluded = discovery.excluded.iter().collect::<Vec<_>>();
    excluded.sort_by(|left, right| {
        (&left.observed_path, &left.identity, &left.reason).cmp(&(
            &right.observed_path,
            &right.identity,
            &right.reason,
        ))
    });
    encoder.field(&(excluded.len() as u64).to_be_bytes());
    for document in excluded {
        encoder.field(b"excluded");
        encoder.field(document.observed_path.as_bytes());
        encoder.field(document.identity.as_bytes());
        match &document.reason {
            DocumentExclusionReason::OutsideRepository => encoder.field(b"outside_repository"),
            DocumentExclusionReason::HistoryDirectory(name) => {
                encoder.field(b"history_directory");
                encoder.field(name.as_bytes());
            }
            DocumentExclusionReason::GeneratedDirectory(name) => {
                encoder.field(b"generated_directory");
                encoder.field(name.as_bytes());
            }
            DocumentExclusionReason::IgnorePolicy { file, pattern } => {
                encoder.field(b"ignore_policy");
                encoder.field(file.as_bytes());
                encoder.field(pattern.as_bytes());
            }
        }
    }

    encoder.field(b"declaration_input");
    encoder.field(discovery.declaration_input.0.to_string_lossy().as_bytes());
    encoder.optional(discovery.declaration_input.1.as_deref());
    // Absence is omission from the set of present policy inputs. Discovery
    // probes missing policy paths in every visited directory; binding those
    // probes would make unrelated directory creation invalidate a report.
    // A newly created policy (even empty) enters this set and changes the hash.
    let policy_inputs = discovery
        .policy_inputs
        .iter()
        .filter(|(_, observation)| {
            !matches!(
                observation,
                ignore::gitignore::PolicyInputObservation::Stable(None)
            )
        })
        .collect::<Vec<_>>();
    encoder.field(&(policy_inputs.len() as u64).to_be_bytes());
    for (path, observation) in policy_inputs {
        encoder.field(b"policy_input");
        encoder.field(path.to_string_lossy().as_bytes());
        match observation {
            ignore::gitignore::PolicyInputObservation::Stable(bytes) => {
                encoder.optional(bytes.as_deref())
            }
            ignore::gitignore::PolicyInputObservation::ChangedDuringCapture => {
                return Err(DocsTruthError::CurrentView(format!(
                    "ignore policy input changed during inventory capture: {}",
                    path.display()
                )));
            }
        }
    }
    // Proposal discovery scans every admitted source before choosing its bounded
    // parser working set. Bind that input set, not only the eventual matches.
    // Keep explicit references in the same negative-admission lane as CodebaseView
    // so missing or inadmissible references remain reportable unresolved evidence.
    let mut references = BTreeMap::new();
    let mut markdown_sources = Vec::new();
    let mut source_bytes = 0_u64;
    for document in &discovery.included {
        ObservationScope::check_current("documentation inventory inputs")
            .map_err(|error| DocsTruthError::CurrentView(error.to_string()))?;
        if document.format != "markdown" {
            continue;
        }
        let contents = read_document_source(&document.path, view, &mut source_bytes)?;
        for fact in parse_markdown(&document.identity, &contents).facts {
            collect_code_reference_candidate(&document.identity, &fact, &mut references);
        }
        markdown_sources.push((document.identity.clone(), contents));
    }
    let discovery_queries = doc_support_queries(root, &markdown_sources);
    ObservationScope::check_current("documentation discovery queries")
        .map_err(|error| DocsTruthError::CurrentView(error.to_string()))?;
    // Heading-only or unsupported documents cannot discover source candidates.
    // Do not read unrelated source bytes merely to revalidate their admission.
    if references.is_empty() && discovery_queries.is_empty() {
        encoder.field(b"no_source_discovery");
        return Ok(format!("sha256:{:x}", encoder.0.finalize()));
    }
    let targets = references
        .keys()
        .filter(|reference| documented_reference_path(&reference.target).is_some())
        .filter_map(|reference| crate::walk::canonical_explicit_file_task(&reference.target).ok())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut inventory = crate::walk::walk_source_inventory_with_canonical_file_tasks_and_deadline(
        root,
        crate::walk::AnalysisProfile::All,
        None,
        &targets,
        crate::walk::FileTaskAdmission::ReferenceCandidates,
        ObservationScope::deadline_current(),
        (view == ReportView::Collection).then_some(COLLECTION_SOURCE_LIMITS),
    )
    .map_err(|error| {
        let limit = error.get_ref().and_then(|error| {
            error
                .downcast_ref::<crate::walk::SourceInventoryLimit>()
                .map(|limit| limit.0)
                .or_else(|| {
                    error
                        .downcast_ref::<crate::repository_path::RepositoryReadLimit>()
                        .map(|limit| limit.0)
                })
        });
        match limit {
            Some(limit) => DocsTruthError::CollectionLimit(limit),
            None => DocsTruthError::CurrentView(format!("proposal discovery inventory: {error}")),
        }
    })?;
    if let Some(inputs) = &inventory.bounded_inputs {
        // Linking uses per-source aliases even when a paths change does not
        // change inventory membership. Bind those semantic inputs as well.
        let paths = inventory
            .files
            .iter()
            .filter(|source| {
                source.language == repotoire::source_pipeline::SourceLanguage::TypeScript
            })
            .map(|source| source.rel_path.as_str())
            .collect::<Vec<_>>();
        if !paths.is_empty() {
            let _ = crate::tsconfig::build_alias_map_for_source_paths(
                crate::repository_path::ReadOnlyFiles::Bounded(inputs),
                &inventory.source_root,
                &paths,
            );
        }
        if let Err(error) = inputs.check() {
            let limit = error
                .get_ref()
                .and_then(|error| {
                    error.downcast_ref::<crate::repository_path::RepositoryReadLimit>()
                })
                .expect("bounded repository limit");
            return Err(DocsTruthError::CollectionLimit(limit.0));
        }
        inputs
            .validate_snapshot()
            .map_err(|(_, error)| DocsTruthError::CurrentView(error.to_string()))?;
        encoder.field(b"proposal_discovery_metadata");
        encoder.field(
            inputs
                .snapshot_fingerprint()
                .map_err(|error| DocsTruthError::CurrentView(error.to_string()))?
                .as_bytes(),
        );
    }
    inventory.files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    encoder.field(b"proposal_discovery_sources");
    encoder.field(&(inventory.files.len() as u64).to_be_bytes());
    for source in inventory.files {
        ObservationScope::check_current("documentation source fingerprint")
            .map_err(|error| DocsTruthError::CurrentView(error.to_string()))?;
        encoder.field(source.rel_path.as_bytes());
        encoder.field(&source.bytes);
    }
    Ok(format!("sha256:{:x}", encoder.0.finalize()))
}

pub fn render_markdown(report: &DocsTruthReport) -> String {
    let mut out = String::new();
    out.push_str("# Docs Truth\n\n");
    out.push_str(&format!("- schema: {}\n", report.schema));
    out.push_str(&format!(
        "- markdown_files: {}\n",
        report.scorecard.markdown_files
    ));
    out.push_str(&format!("- facts: {}\n", report.scorecard.facts));
    out.push_str(&format!(
        "- return_contracts: {}\n",
        report.scorecard.return_contracts
    ));
    out.push_str(&format!("- drifts: {}\n", report.scorecard.drifts));
    out.push_str(&format!(
        "- diagnostics: {}\n",
        report.scorecard.diagnostics
    ));
    out.push_str(&format!(
        "- doc_graphs: {}\n",
        report.doc_decode.graphs.len()
    ));
    out.push_str(&format!(
        "- doc_claims: {}\n",
        report.evidence.doc_claims.len()
    ));
    out.push_str(&format!(
        "- silent_divergences: {}\n",
        report.truth_serum.scorecard.silent_divergences
    ));
    if !report.drifts.is_empty() {
        out.push_str("\n## Drifts\n");
        for drift in &report.drifts {
            out.push_str(&format!(
                "- `{}`#`{}` expected `{}` but returned `{}` (doc {}:{})\n",
                drift.source.file,
                drift.symbol,
                drift.expected_return,
                drift.actual_return,
                drift.doc.file,
                drift.doc.line
            ));
        }
    }
    if !report.truth_serum.diagnostics.is_empty() {
        out.push_str("\n## Diagnostics\n\n");
        for diagnostic in &report.truth_serum.diagnostics {
            out.push_str(&format!("- `{}`", diagnostic.file));
            if diagnostic.line > 0 {
                out.push_str(&format!(":{}", diagnostic.line));
                if diagnostic.col > 0 {
                    out.push_str(&format!(":{}", diagnostic.col));
                }
            }
            out.push_str(&format!(" ({}): {}\n", diagnostic.code, diagnostic.message));
        }
    }
    out
}

fn build_truth_serum_slice(
    root: &Path,
    scorecard: &DocsTruthScorecard,
    drifts: &[DocsTruthDrift],
    diagnostics: &[DocsTruthDiagnostic],
    evidence: &EvidenceBundle,
) -> DocsTruthSerumSlice {
    let mut diffs = drifts
        .iter()
        .map(|drift| DocsTruthSerumDiff {
            kind: "docs_return_contract_mismatch",
            classification: "silent_divergence",
            graph_surface: "docs.return_contracts",
            fixture_or_corpus_path: drift.doc.file.clone(),
            doc: drift.doc.clone(),
            source: Some(drift.source.clone()),
            symbol: Some(drift.symbol.clone()),
            expected_return: Some(drift.expected_return.clone()),
            actual_return: Some(drift.actual_return.clone()),
            truth_source: "repotoire.docs_truth.return_contract",
            truth_source_version: env!("CARGO_PKG_VERSION"),
            evidence_ids: drift.evidence_ids.clone(),
        })
        .collect::<Vec<_>>();
    let mut cards = drifts
        .iter()
        .map(|drift| DocsTruthSerumCard {
            kind: "docs_return_contract_mismatch",
            classification: "silent_divergence",
            graph_surface: "docs.return_contracts",
            fixture_or_corpus_path: drift.doc.file.clone(),
            truth_source: "repotoire.docs_truth.return_contract",
            truth_source_version: env!("CARGO_PKG_VERSION"),
            diagnostic_code: "docs_return_contract_mismatch",
            suspected_subsystem: "docs_truth",
            severity: "high",
            product_impact:
                "A documented API behavior contradicts the implementation and can mislead agents.",
            suggested_regression_test_location: "crates/repotoire-cli/tests/docs_truth.rs",
            occurrence_count: 1,
            affected_paths: vec![drift.doc.file.clone()],
            evidence_ids: drift.evidence_ids.clone(),
        })
        .collect::<Vec<_>>();
    for diagnostic in evidence
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == "unresolved_reference")
    {
        let doc = evidence_diagnostic_location(diagnostic);
        let evidence_ids = evidence_diagnostic_ids(diagnostic);
        diffs.push(DocsTruthSerumDiff {
            kind: "docs_code_reference_unresolved",
            classification: "silent_divergence",
            graph_surface: "docs.code_refs",
            fixture_or_corpus_path: doc.file.clone(),
            doc,
            source: None,
            symbol: None,
            expected_return: None,
            actual_return: None,
            truth_source: "repotoire.docs_truth.code_reference",
            truth_source_version: env!("CARGO_PKG_VERSION"),
            evidence_ids: evidence_ids.clone(),
        });
        cards.push(DocsTruthSerumCard {
            kind: "docs_code_reference_unresolved",
            classification: "silent_divergence",
            graph_surface: "docs.code_refs",
            fixture_or_corpus_path: evidence_diagnostic_location(diagnostic).file,
            truth_source: "repotoire.docs_truth.code_reference",
            truth_source_version: env!("CARGO_PKG_VERSION"),
            diagnostic_code: "docs_code_reference_unresolved",
            suspected_subsystem: "docs_truth",
            severity: "high",
            product_impact:
                "A documented code/API reference does not resolve in the repo snapshot.",
            suggested_regression_test_location: "crates/repotoire-cli/tests/docs_truth.rs",
            occurrence_count: 1,
            affected_paths: vec![evidence_diagnostic_location(diagnostic).file],
            evidence_ids,
        });
    }
    for verification in evidence
        .claim_verifications
        .iter()
        .filter(|verification| verification.status == ClaimVerificationStatus::Stale)
    {
        let Some(claim) = evidence
            .doc_claims
            .iter()
            .find(|claim| claim.claim_id == verification.claim_id)
        else {
            continue;
        };
        let doc = evidence_location_to_docs_location(&claim.provenance.location);
        let mut evidence_ids = verification.evidence_ids.clone();
        evidence_ids.push(claim.provenance.evidence_id.clone());
        evidence_ids.sort();
        evidence_ids.dedup();
        diffs.push(DocsTruthSerumDiff {
            kind: "docs_claim_stale",
            classification: "silent_divergence",
            graph_surface: "docs.claims",
            fixture_or_corpus_path: doc.file.clone(),
            doc: doc.clone(),
            source: None,
            symbol: claim.attributes.get("symbol").cloned(),
            expected_return: None,
            actual_return: None,
            truth_source: "repotoire.docs_truth.git_history",
            truth_source_version: env!("CARGO_PKG_VERSION"),
            evidence_ids: evidence_ids.clone(),
        });
        cards.push(DocsTruthSerumCard {
            kind: "docs_claim_stale",
            classification: "silent_divergence",
            graph_surface: "docs.claims",
            fixture_or_corpus_path: doc.file.clone(),
            truth_source: "repotoire.docs_truth.git_history",
            truth_source_version: env!("CARGO_PKG_VERSION"),
            diagnostic_code: "docs_claim_stale",
            suspected_subsystem: "docs_truth",
            severity: "high",
            product_impact: "A documented code claim predates the referenced symbol change.",
            suggested_regression_test_location: "crates/repotoire-cli/tests/docs_truth.rs",
            occurrence_count: 1,
            affected_paths: vec![doc.file],
            evidence_ids,
        });
    }
    let cards = cluster_docs_truth_cards(cards);
    let mut serum_diagnostics = diagnostics
        .iter()
        .map(|diagnostic| DocsTruthSerumDiagnostic {
            code: diagnostic.kind.clone(),
            classification: docs_diagnostic_classification(&diagnostic.kind),
            graph_surface: docs_diagnostic_surface(&diagnostic.kind),
            file: diagnostic.file.clone(),
            line: diagnostic.line,
            col: diagnostic.col,
            severity: "warning",
            message: diagnostic.message.clone(),
        })
        .collect::<Vec<_>>();
    serum_diagnostics.extend(evidence_diagnostics_as_serum_diagnostics(evidence));
    serum_diagnostics.extend(unproven_doc_claim_diagnostics(evidence));

    let mut truth_scorecard = repotoire::truth::TruthSerumScorecard {
        silent_divergences: diffs
            .iter()
            .filter(|diff| diff.classification == "silent_divergence")
            .count() as u64,
        unsupported_constructs: serum_diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.classification == "unsupported_construct")
            .count() as u64,
        truth_source_gaps: serum_diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.classification == "truth_source_gap")
            .count() as u64,
        files_checked: scorecard.markdown_files,
        graph_facts_checked: scorecard.return_contracts
            + evidence_code_reference_count(evidence)
            + unproven_doc_claim_count(evidence)
            + runtime_witness_verified_doc_claim_count(evidence),
        ..repotoire::truth::TruthSerumScorecard::default()
    };
    truth_scorecard.explained_divergences =
        truth_scorecard.unsupported_constructs + truth_scorecard.truth_source_gaps;
    truth_scorecard.supported_surface_coverage = if truth_scorecard.graph_facts_checked == 0 {
        1.0
    } else {
        truth_scorecard
            .graph_facts_checked
            .saturating_sub(truth_scorecard.silent_divergences) as f64
            / truth_scorecard.graph_facts_checked as f64
    };

    let mut covered_surfaces = Vec::new();
    if scorecard.return_contracts > 0 {
        covered_surfaces.push("docs.return_contracts");
    }
    if evidence_code_reference_count(evidence) > 0 {
        covered_surfaces.push("docs.code_refs");
    }
    if unproven_doc_claim_count(evidence) > 0 {
        covered_surfaces.push("docs.claims");
    }
    if runtime_witness_verified_doc_claim_count(evidence) > 0 {
        covered_surfaces.push("docs.claims");
        covered_surfaces.push("runtime.witness");
        covered_surfaces.sort();
        covered_surfaces.dedup();
    }
    let agent_packet =
        build_docs_truth_serum_agent_packet(root, &truth_scorecard, &cards, &serum_diagnostics);
    DocsTruthSerumSlice {
        schema: DOCS_TRUTH_SERUM_SLICE_SCHEMA,
        covered_surfaces,
        scorecard: truth_scorecard,
        diffs,
        cards,
        diagnostics: serum_diagnostics,
        agent_packet,
    }
}

fn cluster_docs_truth_cards(cards: Vec<DocsTruthSerumCard>) -> Vec<DocsTruthSerumCard> {
    let mut buckets = BTreeMap::<
        (
            &'static str,
            &'static str,
            &'static str,
            &'static str,
            &'static str,
            &'static str,
        ),
        DocsTruthSerumCard,
    >::new();
    for mut card in cards {
        card.affected_paths
            .push(card.fixture_or_corpus_path.clone());
        let key = (
            card.kind,
            card.classification,
            card.graph_surface,
            card.truth_source,
            card.diagnostic_code,
            card.suspected_subsystem,
        );
        buckets
            .entry(key)
            .and_modify(|existing| {
                existing.occurrence_count = existing
                    .occurrence_count
                    .saturating_add(card.occurrence_count);
                existing.affected_paths.extend(card.affected_paths.clone());
                existing.evidence_ids.extend(card.evidence_ids.clone());
                if severity_weight(card.severity) > severity_weight(existing.severity) {
                    existing.severity = card.severity;
                }
            })
            .or_insert(card);
    }
    buckets
        .into_values()
        .map(|mut card| {
            card.affected_paths.sort();
            card.affected_paths.dedup();
            card.evidence_ids.sort();
            card.evidence_ids.dedup();
            if let Some(path) = card.affected_paths.first() {
                card.fixture_or_corpus_path = path.clone();
            }
            card
        })
        .collect()
}

fn severity_weight(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn evidence_code_reference_count(evidence: &EvidenceBundle) -> u64 {
    let decoded_refs = evidence
        .doc_facts
        .iter()
        .filter(|fact| fact.predicate == "references_code")
        .count() as u64;
    let unresolved_or_unsupported_refs = evidence
        .diagnostics
        .iter()
        .filter(|diagnostic| {
            matches!(
                diagnostic.code.as_str(),
                "unresolved_reference" | "unsupported_reference_language"
            )
        })
        .count() as u64;
    decoded_refs + unresolved_or_unsupported_refs
}

fn unproven_doc_claim_count(evidence: &EvidenceBundle) -> u64 {
    evidence
        .claim_verifications
        .iter()
        .filter(|verification| {
            matches!(
                verification.status,
                ClaimVerificationStatus::Unverified | ClaimVerificationStatus::Unknown
            )
        })
        .filter(|verification| {
            evidence
                .doc_claims
                .iter()
                .find(|claim| claim.claim_id == verification.claim_id)
                .is_some_and(|claim| {
                    claim.attributes.get("doc_node_kind").map(String::as_str)
                        != Some("api_contract")
                })
        })
        .count() as u64
}

fn runtime_witness_verified_doc_claim_count(evidence: &EvidenceBundle) -> u64 {
    evidence
        .claim_verifications
        .iter()
        .filter(|verification| verification.status == ClaimVerificationStatus::Verified)
        .filter(|verification| verification.verifier == "repotoire.docs_truth.runtime_witness")
        .count() as u64
}

fn unproven_doc_claim_diagnostics(evidence: &EvidenceBundle) -> Vec<DocsTruthSerumDiagnostic> {
    evidence
        .claim_verifications
        .iter()
        .filter(|verification| {
            matches!(
                verification.status,
                ClaimVerificationStatus::Unverified | ClaimVerificationStatus::Unknown
            )
        })
        .filter_map(|verification| {
            let claim = evidence
                .doc_claims
                .iter()
                .find(|claim| claim.claim_id == verification.claim_id)?;
            if claim.attributes.get("doc_node_kind").map(String::as_str) == Some("api_contract") {
                return None;
            }
            let location = evidence_location_to_docs_location(&claim.provenance.location);
            Some(DocsTruthSerumDiagnostic {
                code: "docs_claim_unverified".to_string(),
                classification: "truth_source_gap",
                graph_surface: "docs.claims",
                file: location.file,
                line: location.line,
                col: location.col,
                severity: "warning",
                message: format!(
                    "documentation claim `{}` is {} and must not be treated as verified truth",
                    claim.text,
                    claim_status_key(verification.status)
                ),
            })
        })
        .collect()
}

fn evidence_diagnostics_as_serum_diagnostics(
    evidence: &EvidenceBundle,
) -> Vec<DocsTruthSerumDiagnostic> {
    evidence
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code != "unresolved_reference")
        .map(|diagnostic| {
            let location = evidence_diagnostic_location(diagnostic);
            DocsTruthSerumDiagnostic {
                code: diagnostic.code.clone(),
                classification: docs_diagnostic_classification(&diagnostic.code),
                graph_surface: docs_diagnostic_surface(&diagnostic.code),
                file: location.file,
                line: location.line,
                col: location.col,
                severity: "warning",
                message: diagnostic.message.clone(),
            }
        })
        .collect()
}

fn evidence_diagnostic_location(diagnostic: &EvidenceDiagnostic) -> DocsTruthLocation {
    evidence_location_to_docs_location(&diagnostic.provenance.location)
}

fn evidence_location_to_docs_location(location: &EvidenceLocation) -> DocsTruthLocation {
    match location {
        EvidenceLocation::Span { file, .. } => DocsTruthLocation {
            file: file.clone(),
            line: 0,
            col: 0,
        },
        EvidenceLocation::LineColumn {
            file, line, column, ..
        } => DocsTruthLocation {
            file: file.clone(),
            line: *line,
            col: column.unwrap_or(0),
        },
        EvidenceLocation::Uri { uri, file, .. } => DocsTruthLocation {
            file: file.clone().unwrap_or_else(|| uri.clone()),
            line: 0,
            col: 0,
        },
    }
}

fn evidence_diagnostic_ids(diagnostic: &EvidenceDiagnostic) -> Vec<String> {
    if diagnostic.evidence_ids.is_empty() {
        vec![diagnostic.diagnostic_id.clone()]
    } else {
        diagnostic.evidence_ids.clone()
    }
}

fn docs_diagnostic_classification(kind: &str) -> &'static str {
    match kind {
        "document_excluded" => "coverage_exclusion",
        "unsupported_contract_target" | "unsupported_syntax" | "unsupported_format" => {
            "unsupported_construct"
        }
        "unsupported_reference_language" => "unsupported_construct",
        "unresolved_reference" => "silent_divergence",
        "contract_source_read_failed" | "contract_source_return_unknown" => "truth_source_gap",
        _ => "truth_source_gap",
    }
}

fn docs_diagnostic_surface(kind: &str) -> &'static str {
    match kind {
        "contract_source_read_failed"
        | "contract_source_return_unknown"
        | "unsupported_contract_target" => "docs.return_contracts",
        "unresolved_reference"
        | "unsupported_reference_language"
        | "code_reference_unverifiable" => "docs.code_refs",
        _ => "docs.claims",
    }
}

fn build_docs_truth_serum_agent_packet(
    root: &Path,
    scorecard: &repotoire::truth::TruthSerumScorecard,
    cards: &[DocsTruthSerumCard],
    diagnostics: &[DocsTruthSerumDiagnostic],
) -> AgentPacket {
    let proof_status = if scorecard.silent_divergences > 0 {
        "silent_divergences_present"
    } else if scorecard.explained_divergences > 0 {
        "explained_divergences_present"
    } else {
        "verified"
    };
    let divergence_evidence_id = "evidence:docs_truth:truth_serum".to_string();
    let mut evidence = vec![AgentEvidence {
        evidence_id: divergence_evidence_id.clone(),
        kind: AgentEvidenceKind::DivergenceEvidence,
        source: Some(AgentSourceLocation {
            file: root.to_string_lossy().into_owned(),
            line: None,
            col: None,
        }),
        precision: "docs_code_truth".to_string(),
        proof_status: proof_status.to_string(),
        confidence: "high".to_string(),
        note: format!(
            "docs_truth checked {} docs/code facts, found {} silent divergence(s), {} auto-card(s).",
            scorecard.graph_facts_checked,
            scorecard.silent_divergences,
            cards.len()
        ),
    }];
    for (idx, card) in cards.iter().enumerate() {
        evidence.push(AgentEvidence {
            evidence_id: format!("evidence:docs_truth:card:{idx}"),
            kind: AgentEvidenceKind::DivergenceEvidence,
            source: Some(AgentSourceLocation {
                file: card.fixture_or_corpus_path.clone(),
                line: None,
                col: None,
            }),
            precision: "docs_code_truth".to_string(),
            proof_status: "carded".to_string(),
            confidence: "high".to_string(),
            note: serde_json::to_string(card).unwrap_or_else(|_| card.kind.to_string()),
        });
    }
    let mut uncertainty = Vec::new();
    if scorecard.unsupported_constructs > 0 {
        uncertainty.push(AgentUncertainty {
            uncertainty_id: "uncertainty:docs_truth:unsupported_constructs".to_string(),
            kind: "uncertainty.unsupported_construct".to_string(),
            severity: "medium".to_string(),
            reason: format!(
                "{} docs construct(s) are unsupported and must not be treated as verified truth.",
                scorecard.unsupported_constructs
            ),
            evidence_ids: vec![divergence_evidence_id.clone()],
        });
    }
    if scorecard.truth_source_gaps > 0 {
        uncertainty.push(AgentUncertainty {
            uncertainty_id: "uncertainty:docs_truth:truth_source_gaps".to_string(),
            kind: "uncertainty.truth_source_gap".to_string(),
            severity: "medium".to_string(),
            reason: format!(
                "{} docs truth source gap(s) are explained but not verified truth.",
                scorecard.truth_source_gaps
            ),
            evidence_ids: vec![divergence_evidence_id.clone()],
        });
    }

    AgentPacket {
        packet_version: PACKET_VERSION.to_string(),
        query: AgentQuery {
            tool: "docs_truth".to_string(),
            symbol: "docs_code_truth".to_string(),
            found: scorecard.silent_divergences == 0 && scorecard.explained_divergences == 0,
            verification: true,
            proof_status: Some(proof_status.to_string()),
            proof_precision: Some("docs_code_truth".to_string()),
        },
        entities: Vec::new(),
        edges: Vec::new(),
        evidence,
        diagnostics: diagnostics
            .iter()
            .enumerate()
            .map(|(index, diagnostic)| AgentDiagnostic {
                diagnostic_id: format!("diagnostic:docs_truth:{index}"),
                kind: diagnostic.classification.into(),
                source: Some(AgentSourceLocation {
                    file: diagnostic.file.clone(),
                    line: Some(diagnostic.line),
                    col: Some(diagnostic.col),
                }),
                severity: diagnostic.severity.into(),
                code: diagnostic.code.clone(),
                message: diagnostic.message.clone(),
                evidence_ids: vec![divergence_evidence_id.clone()],
            })
            .collect(),
        weights: Vec::new(),
        uncertainty,
        next_actions: Vec::new(),
        type_witness: None,
    }
}

fn doc_decode_options(
    root: &Path,
    resolver: Option<&CodeReferenceResolver<'_>>,
    code_reference_candidates: &BTreeMap<CodeReferenceCandidate, Vec<DocsTruthLocation>>,
) -> (DocDecodeOptions, Vec<DocsTruthDiagnostic>) {
    let root_string = root.to_string_lossy().into_owned();
    let mut options = DocDecodeOptions::new(
        EvidenceRepoRef::new(format!("repo:{}", id_fragment(&root_string))).with_root(root_string),
        format!(
            "snapshot:docs_truth:{}",
            id_fragment(&root.to_string_lossy())
        ),
        "docs-truth:scan",
    );
    if !code_reference_candidates.is_empty() {
        options = options.with_code_reference_validation();
    }
    let mut gaps = Vec::new();
    for (reference, locations) in code_reference_candidates {
        let resolved = resolve_code_reference(resolver, reference);
        match resolved.resolution {
            CodeReferenceResolution::Resolved => {
                options = options
                    .with_known_code_reference(reference.target.clone(), reference.symbol.clone());
            }
            CodeReferenceResolution::Gap(reason) => {
                // Register as "known" so the decoder does NOT emit a blocking unresolved_reference
                // diagnostic; we instead record it as a non-blocking truth_source_gap.
                options = options
                    .with_known_code_reference(reference.target.clone(), reference.symbol.clone());
                gaps.extend(locations.iter().map(|location| {
                    code_reference_gap_diagnostic(reference, location, reason, resolver)
                }));
            }
            CodeReferenceResolution::Unresolved(reason) => {
                options = options.with_unresolved_code_reference_reason(
                    reference.target.clone(),
                    reference.symbol.clone(),
                    reason.explanation(),
                );
            }
        }
    }
    (options, gaps)
}

const MAX_DOC_SUPPORT_QUERIES: usize = 128;
const MAX_DOC_SUPPORT_TOKENS: usize = 32;
const MAX_DOC_SUPPORT_CITATIONS: usize = 8;

/// Generation and freshness must agree on whether lexical discovery consumes sources.
fn doc_support_queries(root: &Path, markdown_sources: &[(String, String)]) -> Vec<String> {
    let (options, _) = doc_decode_options(root, None, &BTreeMap::new());
    let mut sources = markdown_sources.iter().collect::<Vec<_>>();
    sources.sort_by(|left, right| left.0.cmp(&right.0));
    let mut seen = BTreeSet::new();
    let mut queries = Vec::new();
    for (file, text) in sources {
        let decoded = decode_markdown_doc(file, text, options.clone());
        for subject in unlinked_doc_subjects([&decoded]) {
            let EvidenceLocation::Span { start, len, .. } = subject.provenance.location else {
                continue;
            };
            let Some(subject_text) = text.get(start as usize..start.saturating_add(len) as usize)
            else {
                continue;
            };
            for token in doc_support_tokens(subject_text).take(MAX_DOC_SUPPORT_TOKENS) {
                if seen.insert(token.to_string()) {
                    queries.push(token.to_string());
                    if queries.len() == MAX_DOC_SUPPORT_QUERIES {
                        return queries;
                    }
                }
            }
        }
    }
    queries
}

fn unlinked_doc_subjects<'a>(graphs: impl IntoIterator<Item = &'a DocGraph>) -> Vec<DocDiagnostic> {
    let mut subjects = BTreeMap::new();
    for graph in graphs {
        let mut admit = |provenance: &repotoire::evidence::EvidenceProvenance| {
            let EvidenceLocation::Span { file, start, len } = &provenance.location else {
                return;
            };
            if *len == 0 {
                return;
            }
            let end = start.saturating_add(*len);
            let has_explicit_link = graph.nodes.iter().any(|node| {
                node.target.is_some()
                    && matches!(&node.provenance.location,
                        EvidenceLocation::Span { start: other, len: size, .. }
                        if *other < end && other.saturating_add(*size) > *start)
            });
            if has_explicit_link {
                return;
            }
            let mut provenance = provenance.clone();
            let original_id = provenance.evidence_id.clone();
            provenance.evidence_id.push_str(":support_proposal");
            subjects
                .entry((file.clone(), *start, *len))
                .or_insert(DocDiagnostic {
                    code: DocDiagnosticCode::AmbiguousClaim,
                    message: String::new(),
                    provenance,
                    evidence_ids: vec![original_id],
                });
        };
        for node in &graph.nodes {
            if matches!(
                node.kind,
                DocNodeKind::Requirement
                    | DocNodeKind::ADRDecision
                    | DocNodeKind::APIContract
                    | DocNodeKind::RunbookStep
                    | DocNodeKind::ArchitectureClaim
            ) {
                admit(&node.provenance);
            }
        }
        for diagnostic in &graph.diagnostics {
            let summarizes_page = graph.nodes.iter().any(|node| {
                node.kind == DocNodeKind::DocPage
                    && diagnostic
                        .evidence_ids
                        .contains(&node.provenance.evidence_id)
            });
            if summarizes_page {
                continue;
            }
            if matches!(
                diagnostic.code,
                DocDiagnosticCode::UnsupportedSyntax | DocDiagnosticCode::AmbiguousClaim
            ) {
                admit(&diagnostic.provenance);
            }
        }
    }
    subjects.into_values().collect()
}

fn doc_support_tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|ch: char| !ch.is_alphanumeric() && ch != '_' && ch != '$')
        .filter(|token| {
            token.len() <= 128
                && token
                    .chars()
                    .next()
                    .is_some_and(|ch| ch.is_alphabetic() || ch == '_' || ch == '$')
        })
}

/// Discovery produces located diagnostics only. It cannot add a reference,
/// support edge, code fact, or successful claim verification.
fn propose_doc_support(
    decoded: &mut DocDecodeReport,
    subjects: Vec<DocDiagnostic>,
    sources: &[(String, String)],
    codebase: Option<&crate::project::CodebaseView>,
) {
    use crate::project::{TaskViewError, TaskViewTarget};

    let mut queried: BTreeMap<String, Option<String>> = BTreeMap::new();
    for mut subject in subjects {
        let EvidenceLocation::Span { file, start, len } = &subject.provenance.location else {
            continue;
        };
        let text = sources
            .iter()
            .find(|(path, _)| path == file)
            .and_then(|(_, contents)| {
                contents.get(*start as usize..start.saturating_add(*len) as usize)
            });
        let mut tokens = doc_support_tokens(text.unwrap_or_default());
        let mut results = BTreeSet::new();
        let mut examined = BTreeSet::new();
        let mut limited = false;
        for token in tokens.by_ref().take(MAX_DOC_SUPPORT_TOKENS) {
            if token.len() > 128 {
                limited = true;
                continue;
            }
            if !queried.contains_key(token) {
                if queried.len() >= MAX_DOC_SUPPORT_QUERIES {
                    limited = true;
                    continue;
                }
                let result = match codebase
                    .map(|view| view.task_view(TaskViewTarget::Symbol(token.to_string())))
                {
                    Some(Ok(view)) => Some(format!(
                        "candidate `{}` at `{}:{}`",
                        token,
                        view.target_file(),
                        view.target_line().unwrap_or(0)
                    )),
                    Some(Err(TaskViewError::AmbiguousSymbol { mut candidates, .. })) => {
                        candidates.sort_by(|left, right| {
                            (&left.file, left.line).cmp(&(&right.file, right.line))
                        });
                        let citations = candidates
                            .iter()
                            .take(MAX_DOC_SUPPORT_CITATIONS)
                            .map(|candidate| format!("`{}:{}`", candidate.file, candidate.line))
                            .collect::<Vec<_>>()
                            .join(", ");
                        Some(format!(
                            "ambiguous `{token}`: {} candidates ({citations}); {} citations omitted",
                            candidates.len(),
                            candidates.len().saturating_sub(MAX_DOC_SUPPORT_CITATIONS)
                        ))
                    }
                    Some(Err(TaskViewError::NonUniqueSymbol {
                        declaration_count, ..
                    })) => Some(format!(
                        "ambiguous `{token}`: {declaration_count} declarations; symbol context cannot select a unique source"
                    )),
                    Some(Err(TaskViewError::SourceUnavailable { path })) => Some(format!(
                        "candidate `{token}` has unavailable source context `{path}`"
                    )),
                    Some(Err(TaskViewError::SymbolNotFound { .. })) | None => None,
                };
                queried.insert(token.to_string(), result);
            }
            if let Some(Some(result)) = queried.get(token) {
                results.insert(result.clone());
            }
            if codebase.is_some() {
                examined.insert(token);
            }
        }
        limited |= tokens.next().is_some();
        let result = if text.is_none() {
            "inaccessible evidence: the document span is unavailable; the cause is unknown and the original document text is required".to_string()
        } else if codebase.is_none() {
            "inaccessible evidence: no captured source snapshot is available; no identifiers were examined, the cause is unknown and a source snapshot is required".to_string()
        } else if results.is_empty() {
            "no candidate found by exact identifier lookup in the captured parsed sources; support is absent from these lookup results only, which does not establish that support is absent from the system; a located supporting source is still required".to_string()
        } else {
            results.into_iter().collect::<Vec<_>>().join("; ")
        };
        let design_assertion = decoded.graphs.iter().any(|graph| {
            graph.file == *file
                && graph.nodes.iter().any(|node| {
                    node.kind == DocNodeKind::ADRDecision
                        && subject.evidence_ids.contains(&node.provenance.evidence_id)
                })
        });
        let external_reference =
            text.is_some_and(|text| text.contains("https://") || text.contains("http://"));
        let examined = examined
            .into_iter()
            .map(|token| format!("`{token}`"))
            .collect::<Vec<_>>()
            .join(", ");
        subject.message = format!(
            "Support proposal for `{file}` at byte {start}: {result}. Examined exact identifiers: [{}]. Discovery parses at most 64 lexical candidate files and 16 MiB beyond explicit references; omitted files are unexamined. Provisional only: name matches do not verify prose; normal claim verification is still required.{}{}{}",
            examined,
            if design_assertion {
                " Design assertion: the decoder classified this statement as an ADR decision; intended behavior does not prove implementation, so implementation evidence is still required."
            } else {
                ""
            },
            if external_reference {
                " External reference observed: this text contains an HTTP(S) URL; external content was not inspected, so whether it supports the assertion is unknown and supporting evidence is still required."
            } else {
                ""
            },
            if limited {
                " Search limit reached; remaining identifiers were not examined."
            } else {
                ""
            }
        );
        if let Some(graph) = decoded.graphs.iter_mut().find(|graph| graph.file == *file) {
            graph.diagnostics.push(subject);
            decoded.scorecard.diagnostics += 1;
        }
    }
}

fn load_docs_codebase_view(
    root: &Path,
    references: &BTreeMap<CodeReferenceCandidate, Vec<DocsTruthLocation>>,
    discovery_queries: &[String],
    view: ReportView,
) -> Result<Option<crate::project::CodebaseView>, DocsTruthError> {
    if references.is_empty() && discovery_queries.is_empty() {
        return Ok(None);
    }
    let mut load_options = crate::project::LoadOptions::default();
    load_options.source_inventory_limits =
        (view == ReportView::Collection).then_some(COLLECTION_SOURCE_LIMITS);
    let targets = references
        .keys()
        .filter(|reference| documented_reference_path(&reference.target).is_some())
        .filter_map(|reference| crate::walk::canonical_explicit_file_task(&reference.target).ok())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    crate::project::CodebaseView::read_for_reference_candidates(
        root,
        load_options,
        &targets,
        discovery_queries,
    )
    .map(Some)
    .map_err(|error| {
        let limit = error.get_ref().and_then(|error| {
            error
                .downcast_ref::<crate::walk::SourceInventoryLimit>()
                .map(|limit| limit.0)
                .or_else(|| {
                    error
                        .downcast_ref::<crate::repository_path::RepositoryReadLimit>()
                        .map(|limit| limit.0)
                })
        });
        match limit {
            Some(limit) => DocsTruthError::CollectionLimit(limit),
            None => DocsTruthError::CurrentView(format!(
                "failed to build the current CodebaseView for docs verification: {error}"
            )),
        }
    })
}

/// Explain the resolver's observed limitation at each affected document location.
fn code_reference_gap_diagnostic(
    reference: &CodeReferenceCandidate,
    location: &DocsTruthLocation,
    reason: CodeReferenceFailure,
    resolver: Option<&CodeReferenceResolver<'_>>,
) -> DocsTruthDiagnostic {
    let label = match &reference.symbol {
        Some(symbol) => format!("{}#{}", reference.target, symbol),
        None => reference.target.clone(),
    };
    let explanation = match (reason, resolver) {
        (CodeReferenceFailure::ConfigurationUnavailable, Some(resolver)) => format!(
            "inaccessible configuration evidence: {}; complete inherited configuration is required",
            resolver
                .codebase
                .typescript_configuration_gaps(&reference.target)
                .collect::<Vec<_>>()
                .join("; ")
        ),
        _ => reason.explanation(),
    };
    DocsTruthDiagnostic {
        kind: if reason == CodeReferenceFailure::UnsupportedLanguage {
            "unsupported_reference_language"
        } else {
            "code_reference_unverifiable"
        }
        .to_string(),
        message: format!(
            "Documented reference `{label}` at `{}:{}:{}` remains unverified: {}",
            location.file, location.line, location.col, explanation,
        ),
        file: location.file.clone(),
        line: location.line,
        col: location.col,
    }
}

fn collect_code_reference_candidate(
    doc_file: &str,
    fact: &MarkdownFact,
    code_reference_candidates: &mut BTreeMap<CodeReferenceCandidate, Vec<DocsTruthLocation>>,
) {
    if let Some(target) = &fact.target {
        // URI targets are outside repository-file resolution. Return-contract
        // checking retains ownership of their unsupported-target diagnostic.
        if target.contains("://") {
            return;
        }
        // Keep inadmissible references as diagnostic evidence. File-access
        // consumers validate targets separately; resolution explains rejection.
        code_reference_candidates
            .entry(CodeReferenceCandidate {
                target: target.clone(),
                symbol: fact.symbol.clone(),
            })
            .or_default()
            .push(DocsTruthLocation {
                file: doc_file.to_string(),
                line: fact.line,
                col: fact.col,
            });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodeReferenceResolution {
    Resolved,
    Gap(CodeReferenceFailure),
    Unresolved(CodeReferenceFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResolvedCodeReference {
    resolution: CodeReferenceResolution,
    span: Option<Span>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodeReferenceFailure {
    InvalidPath,
    SnapshotUnavailable,
    BytesUnavailable(&'static str),
    ConfigurationUnavailable,
    UnsupportedLanguage,
    FileNodeUnavailable,
    DeclarationAbsent,
    ExportUnresolved,
    Ambiguous(usize),
    SpanUnavailable,
}

impl CodeReferenceFailure {
    fn explanation(self) -> String {
        match self {
            Self::InvalidPath => "unsupported analysis: the documented path is not an admissible repository-relative file; a valid in-repository target is required".into(),
            Self::SnapshotUnavailable => "inaccessible evidence: no captured source snapshot is available to examine; the cause is unknown and a source snapshot is required".into(),
            Self::BytesUnavailable(reason) => format!("inaccessible evidence: {reason}; captured file bytes are required"),
            Self::ConfigurationUnavailable => "inaccessible configuration evidence: inherited TypeScript settings could not be fully examined; complete configuration is required".into(),
            Self::UnsupportedLanguage => "unsupported analysis: target bytes were captured, but the file language has no symbol parser; a capable symbol analysis is required".into(),
            Self::FileNodeUnavailable => "unsupported analysis: target bytes were captured, but the graph has no unique file node; the cause is unknown and unique file-level graph evidence is required".into(),
            Self::DeclarationAbsent => "absent support in the examined declaration index: no declaration matches this symbol and its requested owner in the captured target; this does not prove runtime absence; matching declaration evidence is required".into(),
            Self::ExportUnresolved => "unsupported analysis: the captured target exports this name, but its declaration could not be resolved; a resolved export declaration is required".into(),
            Self::Ambiguous(count) => format!("ambiguous candidates: {count} declarations in the captured target match this symbol and requested owner; a unique declaration is required"),
            Self::SpanUnavailable => "inaccessible evidence: the captured graph identifies a declaration without a source span; the cause is unknown and located declaration bytes are required".into(),
        }
    }
}

struct CodeReferenceResolver<'a> {
    codebase: &'a crate::project::CodebaseView,
    graph: &'a CodeGraph<'a>,
    name_index: &'a NameIndex<'a>,
    source_by_path: BTreeMap<&'a str, crate::project::SourceFileRef<'a>>,
    file_nodes_by_path: BTreeMap<&'a str, Vec<repotoire::ids::NodeId>>,
    explicit_export_names_by_path: BTreeMap<&'a str, BTreeSet<String>>,
}

impl<'a> CodeReferenceResolver<'a> {
    fn new(
        codebase: &'a crate::project::CodebaseView,
        source_files: &'a [crate::project::SourceFileRef<'a>],
        graph: &'a CodeGraph<'a>,
        name_index: &'a NameIndex<'a>,
    ) -> Self {
        let source_by_path = source_files
            .iter()
            .map(|source| (source.path, *source))
            .collect();
        let mut file_nodes_by_path = BTreeMap::<_, Vec<_>>::new();
        for node in graph.nodes_of_kind(NodeKind::File) {
            file_nodes_by_path
                .entry(graph.node_name(node))
                .or_default()
                .push(node);
        }
        let explicit_export_names_by_path = source_files
            .iter()
            .filter_map(|source| {
                let names = explicit_typescript_export_names(*source);
                (!names.is_empty()).then_some((source.path, names))
            })
            .collect();
        Self {
            codebase,
            graph,
            name_index,
            source_by_path,
            file_nodes_by_path,
            explicit_export_names_by_path,
        }
    }

    fn source(&self, path: &str) -> Option<crate::project::SourceFileRef<'a>> {
        self.source_by_path.get(path).copied().or_else(|| {
            self.source_by_path
                .iter()
                .find(|(candidate, _)| same_rel_path(candidate, path))
                .map(|(_, source)| *source)
        })
    }

    fn file_node(&self, path: &str) -> Option<repotoire::ids::NodeId> {
        let nodes = self.file_nodes_by_path.get(path).or_else(|| {
            self.file_nodes_by_path
                .iter()
                .find(|(candidate, _)| same_rel_path(candidate, path))
                .map(|(_, nodes)| nodes)
        })?;
        (nodes.len() == 1).then_some(nodes[0])
    }

    fn file_bytes(&self, path: &str) -> Option<&'a [u8]> {
        self.source(path)
            .map(|source| source.bytes)
            .or_else(|| self.codebase.captured_file_bytes(path))
    }

    fn file_exports_symbol(&self, path: &str, file: repotoire::ids::NodeId, symbol: &str) -> bool {
        self.graph.out_slots(file, EdgeKind::Exports).any(|slot| {
            self.graph.edge_label_str(EdgeKind::Exports, slot) == Some(symbol)
                || self
                    .graph
                    .node_name(self.graph.out_target(EdgeKind::Exports, slot))
                    == symbol
        }) || self
            .explicit_export_names_by_path
            .get(path)
            .or_else(|| {
                self.explicit_export_names_by_path
                    .iter()
                    .find(|(candidate, _)| same_rel_path(candidate, path))
                    .map(|(_, names)| names)
            })
            .is_some_and(|names| names.contains(symbol))
    }
}

fn explicit_typescript_export_names(source: crate::project::SourceFileRef<'_>) -> BTreeSet<String> {
    if source_language_for_path(Path::new(source.path)) != SourceLanguage::TypeScript {
        return BTreeSet::new();
    }
    parse_file(source.path, source.bytes)
        .exports
        .into_iter()
        .filter_map(|entry| match entry {
            ExportEntry::Direct { exported, .. }
            | ExportEntry::Named { exported, .. }
            | ExportEntry::NamedFrom { exported, .. } => Some(exported),
            ExportEntry::NamespaceAs { local, .. } => Some(local),
            ExportEntry::Namespace { .. } => None,
        })
        .collect()
}

fn resolve_code_reference(
    resolver: Option<&CodeReferenceResolver<'_>>,
    reference: &CodeReferenceCandidate,
) -> ResolvedCodeReference {
    if documented_reference_path(&reference.target).is_none() {
        return ResolvedCodeReference {
            resolution: CodeReferenceResolution::Unresolved(CodeReferenceFailure::InvalidPath),
            span: None,
        };
    }
    let Some(resolver) = resolver else {
        return ResolvedCodeReference {
            resolution: CodeReferenceResolution::Gap(CodeReferenceFailure::SnapshotUnavailable),
            span: None,
        };
    };
    if resolver.file_bytes(&reference.target).is_none() {
        return ResolvedCodeReference {
            resolution: CodeReferenceResolution::Unresolved(
                CodeReferenceFailure::BytesUnavailable(
                    resolver
                        .codebase
                        .reference_unavailable_reason(&reference.target),
                ),
            ),
            span: None,
        };
    }
    let Some(symbol) = reference.symbol.as_deref() else {
        return ResolvedCodeReference {
            resolution: CodeReferenceResolution::Resolved,
            span: None,
        };
    };
    if resolver
        .codebase
        .typescript_configuration_gaps(&reference.target)
        .next()
        .is_some()
    {
        return ResolvedCodeReference {
            resolution: CodeReferenceResolution::Gap(
                CodeReferenceFailure::ConfigurationUnavailable,
            ),
            span: None,
        };
    }
    let graph = resolver.graph;
    let name_index = resolver.name_index;
    let Some(file_node) = resolver.file_node(&reference.target) else {
        return ResolvedCodeReference {
            resolution: CodeReferenceResolution::Gap(
                if is_supported_symbol_reference_path(&reference.target) {
                    CodeReferenceFailure::FileNodeUnavailable
                } else {
                    CodeReferenceFailure::UnsupportedLanguage
                },
            ),
            span: None,
        };
    };
    let (owner_path, member_name) = symbol
        .rsplit_once('.')
        .map_or((None, symbol), |(owner, member)| (Some(owner), member));
    let locations = name_index
        .locations_named(member_name)
        .iter()
        .filter(|location| location.file == Some(file_node))
        .filter(|location| {
            owner_path
                .is_none_or(|owner| graph_node_matches_qualified_owner(graph, location.node, owner))
        })
        .collect::<Vec<_>>();
    if locations.is_empty() {
        let exported_owner = owner_path
            .and_then(|owner| owner.split('.').next())
            .unwrap_or(member_name);
        let exported = resolver.file_exports_symbol(&reference.target, file_node, exported_owner);
        return ResolvedCodeReference {
            resolution: if exported {
                CodeReferenceResolution::Gap(CodeReferenceFailure::ExportUnresolved)
            } else {
                CodeReferenceResolution::Unresolved(CodeReferenceFailure::DeclarationAbsent)
            },
            span: None,
        };
    }
    if locations.len() != 1 {
        return ResolvedCodeReference {
            resolution: CodeReferenceResolution::Gap(CodeReferenceFailure::Ambiguous(
                locations.len(),
            )),
            span: None,
        };
    }
    let location = locations[0];
    let span = [location.name_span, location.decl_span, location.body_span]
        .into_iter()
        .flatten()
        .fold(None, |combined: Option<Span>, span| {
            Some(match combined {
                Some(combined) => Span::new(
                    combined.start().min(span.start()),
                    combined.end().max(span.end()) - combined.start().min(span.start()),
                ),
                None => span,
            })
        });
    ResolvedCodeReference {
        resolution: if span.is_some() {
            CodeReferenceResolution::Resolved
        } else {
            CodeReferenceResolution::Gap(CodeReferenceFailure::SpanUnavailable)
        },
        span,
    }
}

fn graph_node_matches_qualified_owner(
    graph: &CodeGraph<'_>,
    node: repotoire::ids::NodeId,
    owner_path: &str,
) -> bool {
    let mut child = node;
    for owner in owner_path.rsplit('.') {
        let mut parents = graph
            .incoming(child, EdgeKind::Contains)
            .filter(|parent| graph.node_name(*parent) == owner);
        let Some(parent) = parents.next() else {
            return false;
        };
        if parents.next().is_some() {
            return false;
        }
        child = parent;
    }
    true
}

fn is_supported_symbol_reference_path(path: &str) -> bool {
    parser_supports_source_language(source_language_for_path(Path::new(path)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GitLineChange {
    commit: String,
}

fn doc_verification_evidence(
    root: &Path,
    doc_source: Option<&str>,
    doc_graph: &DocGraph,
    resolver: Option<&CodeReferenceResolver<'_>>,
    history: &mut GitHistoryContext,
) -> DocVerificationEvidence {
    let mut evidence = DocVerificationEvidence::default();
    let nodes_by_id = doc_graph
        .nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let doc_line_index = doc_source.map(|source| LineIndex::build(source.as_bytes()));
    for code_ref in doc_graph
        .nodes
        .iter()
        .filter(|node| node.kind == DocNodeKind::CodeReference)
    {
        let Some(target) = code_ref.target.as_deref() else {
            continue;
        };
        let reference = CodeReferenceCandidate {
            target: target.to_string(),
            symbol: code_ref.symbol.clone(),
        };
        let resolution = resolve_code_reference(resolver, &reference);
        if matches!(
            resolution.resolution,
            CodeReferenceResolution::Unresolved(_)
        ) {
            continue;
        }

        let history = if matches!(resolution.resolution, CodeReferenceResolution::Gap(_)) {
            DocReferenceHistory::unavailable()
        } else {
            history_for_reference(
                root,
                doc_graph,
                code_ref,
                resolution.span,
                resolver,
                &nodes_by_id,
                doc_line_index.as_ref(),
                history,
            )
        };
        let history_evidence_id = format!(
            "evidence:docs_truth:git:{}:{}",
            id_fragment(&doc_graph.file),
            id_fragment(&code_ref.provenance.evidence_id)
        );
        evidence = evidence.with_code_reference_observation(
            code_ref.provenance.evidence_id.clone(),
            target,
            code_ref.symbol.clone(),
            format!(
                "evidence:docs_truth:codebase:{}:{}",
                id_fragment(target),
                id_fragment(code_ref.symbol.as_deref().unwrap_or("file"))
            ),
            history,
            history_evidence_id,
        );
    }
    evidence
}

fn history_for_reference(
    root: &Path,
    doc_graph: &DocGraph,
    code_ref: &DocNode,
    code_span: Option<Span>,
    resolver: Option<&CodeReferenceResolver<'_>>,
    nodes_by_id: &BTreeMap<&str, &DocNode>,
    doc_line_index: Option<&LineIndex>,
    history: &mut GitHistoryContext,
) -> DocReferenceHistory {
    if !history.admit_reference() {
        return DocReferenceHistory::unavailable();
    }
    let Some(doc_line_index) = doc_line_index else {
        return DocReferenceHistory::unavailable();
    };
    let Some(section) = enclosing_doc_section(nodes_by_id, code_ref) else {
        return DocReferenceHistory::unavailable();
    };
    let Some(doc_lines) =
        evidence_location_line_range(&section.provenance.location, doc_line_index)
    else {
        return DocReferenceHistory::unavailable();
    };
    let Some(target) = code_ref.target.as_deref() else {
        return DocReferenceHistory::unavailable();
    };
    let Some(code_bytes) = resolver.and_then(|resolver| resolver.file_bytes(target)) else {
        return DocReferenceHistory::unavailable();
    };
    let code_line_index = LineIndex::build(code_bytes);
    let Some(code_lines) = code_line_range(code_bytes, &code_line_index, code_span) else {
        return DocReferenceHistory::unavailable();
    };
    let doc_change = git_last_change_for_lines(history, root, &doc_graph.file, doc_lines);
    let code_change = git_last_change_for_lines(history, root, target, code_lines);
    git_reference_history(history, root, doc_change, code_change)
}

fn enclosing_doc_section<'a>(
    nodes_by_id: &BTreeMap<&str, &'a DocNode>,
    node: &DocNode,
) -> Option<&'a DocNode> {
    let mut parent = node.parent_id.as_deref();
    for _ in 0..nodes_by_id.len() {
        let current = *nodes_by_id.get(parent?)?;
        if current.kind == DocNodeKind::DocSection {
            return Some(current);
        }
        parent = current.parent_id.as_deref();
    }
    None
}

fn evidence_location_line_range(
    location: &EvidenceLocation,
    index: &LineIndex,
) -> Option<(u32, u32)> {
    let EvidenceLocation::Span { start, len, .. } = location else {
        return None;
    };
    let end = start.checked_add(*len)?;
    let last_byte = if *len == 0 { *start } else { end - 1 };
    Some((
        index.line_col(*start)?.line,
        index.line_col(last_byte)?.line,
    ))
}

fn code_line_range(source: &[u8], index: &LineIndex, span: Option<Span>) -> Option<(u32, u32)> {
    if source.is_empty() {
        return Some((1, 1));
    }
    match span {
        Some(span) => {
            let last_byte = if span.length() == 0 {
                span.start()
            } else {
                span.end() - 1
            };
            Some((
                index.line_col(span.start())?.line,
                index.line_col(last_byte)?.line,
            ))
        }
        None => Some((
            1,
            source.iter().filter(|byte| **byte == b'\n').count() as u32 + 1,
        )),
    }
}

fn git_last_change_for_lines(
    history: &mut GitHistoryContext,
    root: &Path,
    path: &str,
    (start_line, end_line): (u32, u32),
) -> Option<GitLineChange> {
    if start_line == 0
        || end_line < start_line
        || end_line.saturating_sub(start_line) >= MAX_GIT_HISTORY_LINES
    {
        return None;
    }
    let key = GitLineHistoryKey {
        path: path.to_string(),
        start_line,
        end_line,
    };
    if let Some(change) = history.line_changes.get(&key) {
        return change.clone();
    }
    if history.path_is_clean(path) != Some(true) {
        history.line_changes.insert(key, None);
        return None;
    }
    let line_range = format!("{start_line},{end_line}:{path}");
    let output = run_bounded_git(
        &mut history.budget,
        root,
        &["log", "-1", "--format=%H", "--no-patch", "-L", &line_range],
    );
    let change = output.and_then(|output| {
        if output.termination != crate::worker_runtime::BoundedProcessTermination::Exited
            || !output.status.success()
        {
            return None;
        }
        let commit = std::str::from_utf8(&output.stdout).ok()?.trim();
        valid_git_commit(commit).then(|| GitLineChange {
            commit: commit.to_string(),
        })
    });
    history.line_changes.insert(key, change.clone());
    change
}

fn git_reference_history(
    history: &mut GitHistoryContext,
    root: &Path,
    doc: Option<GitLineChange>,
    code: Option<GitLineChange>,
) -> DocReferenceHistory {
    let section_change = doc.map(|change| change.commit);
    let reference_change = code.map(|change| change.commit);
    let order = match (section_change.as_deref(), reference_change.as_deref()) {
        (Some(section), Some(reference)) if section == reference => DocChangeOrder::SameChange,
        (Some(section), Some(reference)) => git_change_order(history, root, section, reference),
        _ => DocChangeOrder::Unknown,
    };
    DocReferenceHistory {
        section_change,
        reference_change,
        order,
    }
}

fn git_change_order(
    history: &mut GitHistoryContext,
    root: &Path,
    section: &str,
    reference: &str,
) -> DocChangeOrder {
    let key = (section.to_string(), reference.to_string());
    if let Some(order) = history.change_orders.get(&key) {
        return *order;
    }
    let order = run_bounded_git(
        &mut history.budget,
        root,
        &["merge-base", section, reference],
    )
    .map_or(DocChangeOrder::Unknown, |output| {
        if output.termination != crate::worker_runtime::BoundedProcessTermination::Exited {
            return DocChangeOrder::Unknown;
        }
        match output.status.code() {
            Some(0) => {
                let merge_base = std::str::from_utf8(&output.stdout)
                    .ok()
                    .map(str::trim)
                    .filter(|commit| valid_git_commit(commit));
                match merge_base {
                    Some(commit) if commit == section => DocChangeOrder::SectionBeforeReference,
                    Some(commit) if commit == reference => DocChangeOrder::ReferenceBeforeSection,
                    Some(_) => DocChangeOrder::Diverged,
                    None => DocChangeOrder::Unknown,
                }
            }
            Some(1) => DocChangeOrder::Diverged,
            _ => DocChangeOrder::Unknown,
        }
    });
    history.change_orders.insert(key, order);
    order
}

fn valid_git_commit(commit: &str) -> bool {
    commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn git_dirty_paths(
    budget: &mut GitHistoryBudget,
    root: &Path,
    paths: &BTreeSet<String>,
) -> Option<BTreeSet<String>> {
    if paths.is_empty() {
        return Some(BTreeSet::new());
    }
    let mut args = vec!["diff", "--name-only", "-z", "HEAD", "--"];
    args.extend(paths.iter().map(String::as_str));
    let output = run_bounded_git(budget, root, &args)?;
    if output.termination != crate::worker_runtime::BoundedProcessTermination::Exited
        || !output.status.success()
    {
        return None;
    }
    output
        .stdout
        .split(|byte| *byte == b'\0')
        .filter(|path| !path.is_empty())
        .map(|path| std::str::from_utf8(path).ok().map(str::to_string))
        .collect()
}

fn run_bounded_git(
    budget: &mut GitHistoryBudget,
    root: &Path,
    args: &[&str],
) -> Option<crate::worker_runtime::BoundedProcessOutput> {
    let timeout = budget.process_timeout()?;
    let mut command = Command::new("git");
    command
        .current_dir(root)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null());
    crate::worker_runtime::run_bounded_command(&mut command, GIT_HISTORY_OUTPUT_LIMIT, timeout).ok()
}

fn history_paths_for_doc_decode(
    doc_decode: &DocDecodeReport,
    resolver: Option<&CodeReferenceResolver<'_>>,
) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    let mut reference_count = 0;
    'graphs: for doc_graph in &doc_decode.graphs {
        for code_ref in doc_graph
            .nodes
            .iter()
            .filter(|node| node.kind == DocNodeKind::CodeReference)
        {
            let Some(target) = code_ref.target.as_deref() else {
                continue;
            };
            let reference = CodeReferenceCandidate {
                target: target.to_string(),
                symbol: code_ref.symbol.clone(),
            };
            if resolve_code_reference(resolver, &reference).resolution
                != CodeReferenceResolution::Resolved
            {
                continue;
            }
            if reference_count == MAX_GIT_HISTORY_REFERENCES {
                break 'graphs;
            }
            paths.insert(doc_graph.file.clone());
            paths.insert(target.to_string());
            reference_count += 1;
        }
    }
    paths
}

fn evidence_bundle_for_doc_decode(
    root: &Path,
    markdown_sources: &[(String, String)],
    doc_decode: &DocDecodeReport,
    resolver: Option<&CodeReferenceResolver<'_>>,
    history: &mut GitHistoryContext,
) -> EvidenceBundle {
    let mut evidence = EvidenceBundle::new();
    let source_by_path = markdown_sources
        .iter()
        .map(|(file, source)| (file.as_str(), source.as_str()))
        .collect::<BTreeMap<_, _>>();
    for doc_graph in &doc_decode.graphs {
        let source = source_by_path.get(doc_graph.file.as_str()).copied();
        let verification = doc_verification_evidence(root, source, doc_graph, resolver, history);
        append_evidence_bundle(
            &mut evidence,
            doc_graph.to_verified_evidence_bundle(&verification),
        );
    }
    evidence
}

fn agent_evidence_for_doc_decode(
    doc_decode: &DocDecodeReport,
    evidence: &EvidenceBundle,
) -> Vec<AgentEvidenceShape> {
    let verification_by_evidence_id = evidence
        .doc_claims
        .iter()
        .filter_map(|claim| {
            evidence
                .claim_verifications
                .iter()
                .find(|verification| verification.claim_id == claim.claim_id)
                .map(|verification| (claim.provenance.evidence_id.clone(), verification.status))
        })
        .collect::<BTreeMap<_, _>>();

    doc_decode
        .graphs
        .iter()
        .flat_map(|graph| graph.to_agent_evidence_shapes())
        .map(|mut shape| {
            if shape.kind == "doc_claim" {
                if let Some(status) = verification_by_evidence_id.get(&shape.evidence_id) {
                    shape.proof_status = claim_status_key(*status).to_string();
                    shape.confidence = claim_status_confidence(*status).to_string();
                }
            }
            shape
        })
        .collect()
}

fn claim_status_key(status: ClaimVerificationStatus) -> &'static str {
    match status {
        ClaimVerificationStatus::Verified => "verified",
        ClaimVerificationStatus::Contradicted => "contradicted",
        ClaimVerificationStatus::Unsupported => "unsupported",
        ClaimVerificationStatus::Stale => "stale",
        ClaimVerificationStatus::Unknown => "unknown",
        ClaimVerificationStatus::Unverified => "unverified",
    }
}

fn claim_status_confidence(status: ClaimVerificationStatus) -> &'static str {
    match status {
        ClaimVerificationStatus::Verified | ClaimVerificationStatus::Contradicted => "high",
        ClaimVerificationStatus::Unsupported
        | ClaimVerificationStatus::Stale
        | ClaimVerificationStatus::Unknown => "low",
        ClaimVerificationStatus::Unverified => "medium",
    }
}

fn append_evidence_bundle(target: &mut EvidenceBundle, source: EvidenceBundle) {
    target.doc_facts.extend(source.doc_facts);
    target.doc_claims.extend(source.doc_claims);
    target.code_facts.extend(source.code_facts);
    target
        .repo_graph_snapshots
        .extend(source.repo_graph_snapshots);
    target.external_repo_refs.extend(source.external_repo_refs);
    target.federated_links.extend(source.federated_links);
    target.graph_freshness.extend(source.graph_freshness);
    target
        .claim_verifications
        .extend(source.claim_verifications);
    target.diagnostics.extend(source.diagnostics);
}

fn apply_return_contract_checks(evidence: &mut EvidenceBundle, checks: &[ReturnContractCheck]) {
    for check in checks {
        let Some((claim_id, claim_evidence_id)) = evidence
            .doc_claims
            .iter()
            .find(|claim| {
                claim.provenance.location.file() == Some(check.doc_file.as_str())
                    && claim.attributes.get("target") == Some(&check.source_file)
                    && claim.attributes.get("symbol") == Some(&check.symbol)
                    && claim.attributes.get("expected_return") == Some(&check.expected_return)
            })
            .map(|claim| (claim.claim_id.clone(), claim.provenance.evidence_id.clone()))
        else {
            continue;
        };
        let Some(verification) = evidence
            .claim_verifications
            .iter_mut()
            .find(|verification| verification.claim_id == claim_id)
        else {
            continue;
        };

        let contract_summary = match check.status {
            ClaimVerificationStatus::Verified => format!(
                "return contract `{}`#`{}` matched literal return `{}`",
                check.source_file, check.symbol, check.actual_return
            ),
            ClaimVerificationStatus::Contradicted => format!(
                "return contract `{}`#`{}` expected `{}` but returned `{}`",
                check.source_file, check.symbol, check.expected_return, check.actual_return
            ),
            _ => "return contract check did not produce a verified result".to_string(),
        };
        if check.status == ClaimVerificationStatus::Contradicted {
            verification.status = ClaimVerificationStatus::Contradicted;
            verification.verifier = "repotoire.docs_truth.return_contract".to_string();
            verification.summary = Some(contract_summary);
        } else {
            // Only the semantic checker may establish a positive claim result.
            // A literal match cannot erase stale, unknown, or contradicted
            // reference evidence supplied by the graph/history owner.
            if check.status == ClaimVerificationStatus::Verified
                && verification.status == ClaimVerificationStatus::Unverified
            {
                verification.status = ClaimVerificationStatus::Verified;
                verification.verifier = "repotoire.docs_truth.return_contract".to_string();
            }
            let freshness_summary = verification.summary.take();
            verification.summary = Some(match freshness_summary {
                Some(summary) => format!("{summary}; {contract_summary}"),
                None => contract_summary,
            });
        }
        verification
            .checked_surfaces
            .extend(["markdown.return_contract", "typescript.literal_return"].map(str::to_string));
        verification.checked_surfaces.sort();
        verification.checked_surfaces.dedup();
        verification.evidence_ids.push(claim_evidence_id);
        verification
            .evidence_ids
            .extend(check.evidence_ids.iter().cloned());
        verification.evidence_ids.sort();
        verification.evidence_ids.dedup();
    }
}

fn check_return_contract(
    source_files: Option<&[crate::project::SourceFileRef<'_>]>,
    doc_file: &str,
    fact: &MarkdownFact,
    drifts: &mut Vec<DocsTruthDrift>,
    diagnostics: &mut Vec<DocsTruthDiagnostic>,
) -> Option<ReturnContractCheck> {
    let source_file = fact.target.as_deref()?;
    let symbol = fact.symbol.as_deref()?;
    let expected_return = fact.expected_return.as_deref()?;
    if !valid_contract_source_path(source_file) {
        diagnostics.push(DocsTruthDiagnostic {
            kind: "unsupported_contract_target".to_string(),
            message: format!("unsupported Markdown contract target `{source_file}`"),
            file: doc_file.to_string(),
            line: fact.line,
            col: fact.col,
        });
        return None;
    }
    let bytes = match source_files.and_then(|files| {
        files
            .iter()
            .find(|source| same_rel_path(source.path, source_file))
            .map(|source| source.bytes)
    }) {
        Some(bytes) => bytes,
        None => {
            diagnostics.push(DocsTruthDiagnostic {
                kind: "contract_source_read_failed".to_string(),
                message: format!(
                    "`{source_file}` was not present in the current CodebaseView snapshot"
                ),
                file: doc_file.to_string(),
                line: fact.line,
                col: fact.col,
            });
            return None;
        }
    };
    let Some(actual) = literal_return_for_function(source_file, symbol, bytes) else {
        diagnostics.push(DocsTruthDiagnostic {
            kind: "contract_source_return_unknown".to_string(),
            message: format!("could not prove literal return for `{source_file}`#`{symbol}`"),
            file: doc_file.to_string(),
            line: fact.line,
            col: fact.col,
        });
        return None;
    };
    let suffix = id_fragment(&format!("{doc_file}#{source_file}#{symbol}"));
    let evidence_ids = vec![
        format!("evidence:docs_truth:doc_contract:{suffix}"),
        format!("evidence:docs_truth:source_return:{suffix}"),
    ];
    if actual.value == expected_return {
        return Some(ReturnContractCheck {
            doc_file: doc_file.to_string(),
            source_file: source_file.to_string(),
            symbol: symbol.to_string(),
            expected_return: expected_return.to_string(),
            actual_return: actual.value,
            status: ClaimVerificationStatus::Verified,
            evidence_ids,
        });
    }
    drifts.push(DocsTruthDrift {
        kind: "return_contract_mismatch",
        doc: DocsTruthLocation {
            file: doc_file.to_string(),
            line: fact.line,
            col: fact.col,
        },
        source: DocsTruthLocation {
            file: source_file.to_string(),
            line: actual.line_col.line,
            col: actual.line_col.column,
        },
        symbol: symbol.to_string(),
        expected_return: expected_return.to_string(),
        actual_return: actual.value.clone(),
        evidence_ids: evidence_ids.clone(),
    });
    Some(ReturnContractCheck {
        doc_file: doc_file.to_string(),
        source_file: source_file.to_string(),
        symbol: symbol.to_string(),
        expected_return: expected_return.to_string(),
        actual_return: actual.value,
        status: ClaimVerificationStatus::Contradicted,
        evidence_ids,
    })
}

const HISTORY_DOCUMENT_DIRS: &[&str] = &[".git", ".hg", ".svn"];
const GENERATED_DOCUMENT_DIRS: &[&str] = &[
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "venv",
];

fn first_ignore_error_path(error: &ignore::Error) -> Option<PathBuf> {
    match error {
        ignore::Error::Partial(errors) => errors.iter().find_map(first_ignore_error_path),
        ignore::Error::WithPath { path, .. } => Some(path.clone()),
        ignore::Error::WithLineNumber { err, .. } | ignore::Error::WithDepth { err, .. } => {
            first_ignore_error_path(err)
        }
        ignore::Error::Loop { child, .. } => Some(child.clone()),
        ignore::Error::Io(_)
        | ignore::Error::Glob { .. }
        | ignore::Error::UnrecognizedFileType(_)
        | ignore::Error::InvalidDefinition => None,
    }
}

fn first_located_ignore_io_error<'a>(
    error: &'a ignore::Error,
    inherited_path: Option<&Path>,
) -> Option<(Option<PathBuf>, &'a std::io::Error)> {
    match error {
        ignore::Error::Partial(errors) => errors
            .iter()
            .find_map(|error| first_located_ignore_io_error(error, inherited_path)),
        ignore::Error::WithPath { path, err } => first_located_ignore_io_error(err, Some(path)),
        ignore::Error::WithLineNumber { err, .. } | ignore::Error::WithDepth { err, .. } => {
            first_located_ignore_io_error(err, inherited_path)
        }
        ignore::Error::Io(source) => Some((inherited_path.map(Path::to_path_buf), source)),
        ignore::Error::Loop { .. }
        | ignore::Error::Glob { .. }
        | ignore::Error::UnrecognizedFileType(_)
        | ignore::Error::InvalidDefinition => None,
    }
}

fn walk_error(error: ignore::Error, fallback_path: &Path) -> DocsTruthError {
    let located_io =
        first_located_ignore_io_error(&error, None).map(|(path, source)| (path, source.kind()));
    let path = located_io
        .as_ref()
        .and_then(|(path, _)| path.clone())
        .or_else(|| first_ignore_error_path(&error))
        .unwrap_or_else(|| fallback_path.to_path_buf());
    let source = match located_io {
        Some((_, kind)) => std::io::Error::new(kind, error),
        None => std::io::Error::other(error),
    };
    DocsTruthError::Io { path, source }
}

fn walked_file_paths(
    walk: ignore::Walk,
    fallback_path: &Path,
    view: ReportView,
) -> Result<Vec<PathBuf>, DocsTruthError> {
    let mut paths = Vec::new();
    for (entries, result) in walk.enumerate() {
        if view == ReportView::Collection && entries >= MAX_COLLECTION_WALK_ENTRIES {
            return Err(DocsTruthError::CollectionLimit(
                "document traversal entries",
            ));
        }
        ObservationScope::check_current("documentation inventory traversal")
            .map_err(|error| DocsTruthError::CurrentView(error.to_string()))?;
        let entry = result.map_err(|error| walk_error(error, fallback_path))?;
        if let Some(error) = entry.error() {
            let error_path = if entry.path().as_os_str().is_empty() {
                fallback_path
            } else {
                entry.path()
            };
            return Err(walk_error(error.clone(), error_path));
        }
        if entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            paths.push(entry.into_path());
        }
    }
    Ok(paths)
}

#[derive(Default)]
struct DirectoryContainmentObservations {
    outside: BTreeSet<PathBuf>,
    errors: Vec<(PathBuf, std::io::ErrorKind, String)>,
}

fn entry_is_directory(
    entry: &ignore::DirEntry,
    observations: &std::sync::Mutex<DirectoryContainmentObservations>,
) -> bool {
    if entry
        .file_type()
        .is_some_and(|file_type| file_type.is_dir())
    {
        return true;
    }
    if !entry.path_is_symlink() {
        return false;
    }
    match entry.path().metadata() {
        Ok(metadata) => metadata.is_dir(),
        Err(source) => {
            observations
                .lock()
                .expect("directory containment observer mutex poisoned")
                .errors
                .push((
                    entry.path().to_path_buf(),
                    source.kind(),
                    source.to_string(),
                ));
            false
        }
    }
}

fn directory_is_within_root(
    root: &Path,
    path: &Path,
    observations: &std::sync::Mutex<DirectoryContainmentObservations>,
) -> bool {
    match path.canonicalize() {
        Ok(canonical) if canonical.starts_with(root) => true,
        Ok(_) => {
            observations
                .lock()
                .expect("directory containment observer mutex poisoned")
                .outside
                .insert(path.to_path_buf());
            false
        }
        Err(source) => {
            observations
                .lock()
                .expect("directory containment observer mutex poisoned")
                .errors
                .push((path.to_path_buf(), source.kind(), source.to_string()));
            false
        }
    }
}

fn discover_documents(root: &Path, view: ReportView) -> Result<DocumentDiscovery, DocsTruthError> {
    let root = root.canonicalize().map_err(|source| DocsTruthError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    let config_path = root.join(".repotoire-sources.toml");
    let bounded_inputs = (view == ReportView::Collection)
        .then(|| {
            crate::repository_path::BoundedRepositoryFiles::new(
                &root,
                crate::repository_path::RepositoryReadLimits::COLLECTION_METADATA,
            )
        })
        .transpose()
        .map_err(|source| DocsTruthError::Io {
            path: root.clone(),
            source,
        })?;
    let inputs = bounded_inputs.as_ref().map_or(
        crate::repository_path::ReadOnlyFiles::Repository,
        crate::repository_path::ReadOnlyFiles::Bounded,
    );
    let declarations = crate::walk::document_source_declarations(inputs, &root);
    if let Err(error) = inputs.check_limits() {
        return Err(DocsTruthError::CollectionLimit(
            error
                .get_ref()
                .and_then(|error| {
                    error.downcast_ref::<crate::repository_path::RepositoryReadLimit>()
                })
                .expect("bounded input error")
                .0,
        ));
    }
    let (declarations, declaration_bytes) = declarations.map_err(DocsTruthError::CurrentView)?;
    let declared_formats = declarations
        .into_iter()
        .map(|declaration| (declaration.path, declaration.format))
        .collect::<BTreeMap<_, _>>();

    let ignored = std::sync::Arc::new(std::sync::Mutex::new(BTreeMap::<
        PathBuf,
        DocumentExclusionReason,
    >::new()));
    let directory_observations = std::sync::Arc::new(std::sync::Mutex::new(
        DirectoryContainmentObservations::default(),
    ));
    let admission_root = root.clone();
    let admission_observations = directory_observations.clone();
    let observed_ignored = ignored.clone();
    let observed_root = root.clone();
    let ignore_limit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed_limit = ignore_limit.clone();
    let policy_inputs = if view == ReportView::Collection {
        ignore::gitignore::PolicyInputObservations::bounded(
            4 * 1024 * 1024,
            32 * 1024 * 1024,
            10_000,
        )
    } else {
        ignore::gitignore::PolicyInputObservations::default()
    };
    let mut builder = WalkBuilder::new(&root);
    builder
        .observe_policy_inputs(policy_inputs.clone())
        .add_custom_ignore_filename(".repotoireignore")
        .follow_links(true)
        .hidden(false)
        .parents(true)
        .filter_entry(move |entry| {
            let is_hard_directory = hard_directory_kind(entry.file_name()).is_some();
            if entry_is_directory(entry, &admission_observations)
                && !directory_is_within_root(&admission_root, entry.path(), &admission_observations)
            {
                return false;
            }
            !is_hard_directory
        });
    let mut walk = builder.build();
    walk.observe_ignored(move |path, _is_dir, glob| {
        let mut ignored = observed_ignored
            .lock()
            .expect("ignore observer mutex poisoned");
        if view == ReportView::Collection && ignored.len() >= MAX_COLLECTION_WALK_ENTRIES {
            observed_limit.store(true, std::sync::atomic::Ordering::Relaxed);
            return;
        }
        let file = glob
            .from()
            .map(|policy| rel_path(&observed_root, policy))
            .unwrap_or_else(|| "<global-ignore>".to_string());
        ignored.insert(
            path.to_path_buf(),
            DocumentExclusionReason::IgnorePolicy {
                file,
                pattern: glob.original().to_string(),
            },
        );
    });
    let walked_paths = walked_file_paths(walk, &root, view);
    // Ignore loaders can attach or suppress their I/O error. The read owner
    // retains the authoritative limit failure in either case.
    let policy_inputs = policy_inputs
        .snapshot()
        .map_err(DocsTruthError::CollectionLimit)?;
    let walked_paths = walked_paths?;
    if ignore_limit.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(DocsTruthError::CollectionLimit("ignored traversal entries"));
    }
    let ignored = std::sync::Arc::try_unwrap(ignored)
        .expect("ignore observer retained after serial walk")
        .into_inner()
        .expect("ignore observer mutex poisoned");
    let admitted_targets = walked_paths.iter().cloned().collect::<BTreeSet<_>>();

    let mut observer = WalkBuilder::new(&root);
    let observer_root = root.clone();
    let observer_observations = directory_observations.clone();
    observer
        .follow_links(true)
        .hidden(false)
        .parents(false)
        .ignore(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .filter_entry(move |entry| {
            !entry_is_directory(entry, &observer_observations)
                || directory_is_within_root(&observer_root, entry.path(), &observer_observations)
        });
    let mut candidate_paths = walked_file_paths(observer.build(), &root, view)?
        .into_iter()
        .filter(|path| {
            let lexical_identity = rel_path(&root, path);
            declared_formats.contains_key(&lexical_identity)
                || path.extension().and_then(|extension| extension.to_str()) == Some("md")
        })
        .collect::<Vec<_>>();
    candidate_paths.extend(declared_formats.keys().map(|identity| root.join(identity)));
    candidate_paths.sort();
    candidate_paths.dedup();
    if view == ReportView::Collection && candidate_paths.len() > MAX_COLLECTION_DOCUMENTS {
        return Err(DocsTruthError::CollectionLimit("document candidate count"));
    }

    let mut documents = BTreeMap::<String, DiscoveredDocument>::new();
    let mut exclusions = BTreeMap::<String, ExcludedDocument>::new();
    let observations = directory_observations
        .lock()
        .expect("directory containment observer mutex poisoned");
    if let Some((path, kind, message)) = observations.errors.first() {
        return Err(DocsTruthError::Io {
            path: path.clone(),
            source: std::io::Error::new(*kind, message.clone()),
        });
    }
    for path in &observations.outside {
        let identity = rel_path(&root, path);
        exclusions.insert(
            identity.clone(),
            ExcludedDocument {
                observed_path: identity.clone(),
                identity,
                reason: DocumentExclusionReason::OutsideRepository,
            },
        );
    }
    drop(observations);
    for path in candidate_paths {
        ObservationScope::check_current("documentation candidate admission")
            .map_err(|error| DocsTruthError::CurrentView(error.to_string()))?;
        let lexical_identity = rel_path(&root, &path);
        let declared_format = declared_formats.get(&lexical_identity);
        let canonical_path = path.canonicalize().map_err(|source| DocsTruthError::Io {
            path: path.clone(),
            source,
        })?;
        let Ok(canonical_relative) = canonical_path.strip_prefix(&root) else {
            exclusions
                .entry(lexical_identity.clone())
                .or_insert_with(|| ExcludedDocument {
                    observed_path: lexical_identity.clone(),
                    identity: lexical_identity,
                    reason: DocumentExclusionReason::OutsideRepository,
                });
            continue;
        };
        let identity = canonical_relative
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        let lexical_admitted = admitted_targets.contains(&path);
        let canonical_admitted = admitted_targets.contains(&canonical_path);
        if !lexical_admitted || !canonical_admitted {
            let excluded_path = if lexical_admitted {
                &canonical_path
            } else {
                &path
            };
            let reason = authoritative_ignore_exclusion(&ignored, excluded_path)
                .or_else(|| hard_directory_exclusion(&root, excluded_path))
                .or_else(|| authoritative_ignore_exclusion(&ignored, &canonical_path))
                .or_else(|| hard_directory_exclusion(&root, &canonical_path));
            let Some(reason) = reason else {
                if declared_format.is_some() {
                    return Err(DocsTruthError::CurrentView(format!(
                        "{}: document_source path `{lexical_identity}` was not admitted and has no observed exclusion reason",
                        config_path.display()
                    )));
                }
                return Err(DocsTruthError::CurrentView(format!(
                    "documentation candidate `{lexical_identity}` was not admitted and has no observed exclusion reason"
                )));
            };
            exclusions
                .entry(lexical_identity.clone())
                .or_insert(ExcludedDocument {
                    observed_path: lexical_identity,
                    identity,
                    reason,
                });
            continue;
        }
        let format = declared_format
            .cloned()
            .unwrap_or_else(|| "markdown".to_string());
        let document = DiscoveredDocument {
            identity: identity.clone(),
            path: canonical_path,
            format,
            declared: declared_format.is_some(),
        };
        if let Some(existing) = documents.get(&identity) {
            if existing.declared && document.declared && existing.format != document.format {
                return Err(DocsTruthError::CurrentView(format!(
                    "document `{identity}` has conflicting formats `{}` and `{}`",
                    existing.format, document.format
                )));
            }
            if !existing.declared && document.declared {
                documents.insert(identity, document);
            }
            continue;
        }
        documents.insert(identity, document);
    }
    Ok(DocumentDiscovery {
        included: documents.into_values().collect(),
        excluded: exclusions.into_values().collect(),
        declaration_input: (config_path, declaration_bytes),
        policy_inputs,
    })
}

fn hard_directory_kind(name: &std::ffi::OsStr) -> Option<bool> {
    let name = name.to_str()?;
    if HISTORY_DOCUMENT_DIRS.contains(&name) {
        return Some(true);
    }
    GENERATED_DOCUMENT_DIRS.contains(&name).then_some(false)
}

fn hard_directory_exclusion(root: &Path, path: &Path) -> Option<DocumentExclusionReason> {
    let relative = path.strip_prefix(root).ok()?;
    for component in relative.components() {
        let name = component.as_os_str();
        match hard_directory_kind(name) {
            Some(true) => {
                return Some(DocumentExclusionReason::HistoryDirectory(
                    name.to_string_lossy().into_owned(),
                ));
            }
            Some(false) => {
                return Some(DocumentExclusionReason::GeneratedDirectory(
                    name.to_string_lossy().into_owned(),
                ));
            }
            None => {}
        }
    }
    None
}

fn authoritative_ignore_exclusion(
    ignored: &BTreeMap<PathBuf, DocumentExclusionReason>,
    path: &Path,
) -> Option<DocumentExclusionReason> {
    path.ancestors()
        .find_map(|ancestor| ignored.get(ancestor).cloned())
}

fn to_report_fact(file: &str, fact: MarkdownFact) -> DocsTruthFact {
    DocsTruthFact {
        kind: fact_kind(fact.kind),
        file: file.to_string(),
        line: fact.line,
        col: fact.col,
        text: fact.text,
        target: fact.target,
        symbol: fact.symbol,
        expected_return: fact.expected_return,
    }
}

fn fact_kind(kind: MarkdownFactKind) -> &'static str {
    match kind {
        MarkdownFactKind::Heading => "heading",
        MarkdownFactKind::Task => "task",
        MarkdownFactKind::FileRef => "file_ref",
        MarkdownFactKind::SymbolRef => "symbol_ref",
        MarkdownFactKind::Command => "command",
        MarkdownFactKind::ReturnContract => "return_contract",
    }
}

fn literal_return_for_function(
    path: &str,
    function_name: &str,
    bytes: &[u8],
) -> Option<LiteralReturn> {
    let parsed = parse_file(path, bytes);
    let body_span = parsed.events.iter().find_map(|event| match event {
        Event::Decl(DeclEvent::Function {
            name, body_span, ..
        }) if name == function_name && body_span.length() > 0 => Some(*body_span),
        _ => None,
    })?;
    // A syntax error elsewhere in the file must not suppress this function's contract check;
    // only distrust the parse when a diagnostic falls within this function's own body span.
    if body_contains_diagnostic(&parsed.diagnostics, body_span) {
        return None;
    }
    literal_return_in_body(bytes, body_span)
}

/// True when any parser diagnostic overlaps `body` (half-open `[start, end)` interval overlap).
fn body_contains_diagnostic(diagnostics: &[Diagnostic], body: Span) -> bool {
    let body_start = body.start();
    let body_end = body.end();
    diagnostics
        .iter()
        .any(|diagnostic| diagnostic.span.start() < body_end && diagnostic.span.end() > body_start)
}

fn literal_return_in_body(bytes: &[u8], body_span: Span) -> Option<LiteralReturn> {
    let body_start = body_span.start();
    let body_end = body_span.end();
    let line_index = LineIndex::build(bytes);
    let mut lexer = Lexer::new(bytes);
    let mut depth = 0u32;

    loop {
        let token = lexer.next();
        if token.kind == TokenKind::Eof {
            break;
        }
        let start = token.span.start();
        if start < body_start {
            continue;
        }
        if start >= body_end {
            break;
        }
        match token.kind {
            TokenKind::LBrace => {
                depth = depth.saturating_add(1);
            }
            TokenKind::RBrace => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            TokenKind::Return if depth == 1 => {
                let return_start = token.span.start();
                if let Some(value) = literal_after_return(&mut lexer, bytes, body_end) {
                    let line_col = line_index.line_col(return_start)?;
                    return Some(LiteralReturn { value, line_col });
                }
            }
            _ => {}
        }
    }
    None
}

fn literal_after_return(lexer: &mut Lexer<'_>, bytes: &[u8], body_end: u32) -> Option<String> {
    let first = lexer.peek().clone();
    if lexer.had_line_terminator() || first.span.start() >= body_end {
        return None;
    }

    // Only consume tokens we positively classify as a literal start. Anything else (notably a
    // `{`/`[` opening an object/array return) must be LEFT for the caller's brace-depth counter,
    // otherwise consuming it here desyncs that counter and drops later literal returns.
    let value = match first.kind {
        TokenKind::Minus => {
            lexer.next();
            if lexer.had_line_terminator() {
                return None;
            }
            let number = lexer.peek().clone();
            if number.kind != TokenKind::Number {
                return None;
            }
            lexer.next();
            format!("-{}", token_text(bytes, &number)?)
        }
        TokenKind::Number | TokenKind::Str | TokenKind::Ident => {
            let token = lexer.next();
            literal_token_text(bytes, &token)?
        }
        _ => return None,
    };

    let terminator = lexer.peek().clone();
    if lexer.had_line_terminator()
        || terminator.span.start() >= body_end
        || matches!(terminator.kind, TokenKind::Semi | TokenKind::RBrace)
    {
        Some(value)
    } else {
        None
    }
}

fn literal_token_text(bytes: &[u8], token: &Token) -> Option<String> {
    match token.kind {
        TokenKind::Number | TokenKind::Str => token_text(bytes, token),
        TokenKind::Ident => {
            let text = token_text(bytes, token)?;
            if matches!(text.as_str(), "true" | "false" | "null" | "undefined") {
                Some(text)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn token_text(bytes: &[u8], token: &Token) -> Option<String> {
    let start = token.span.start() as usize;
    let end = token.span.end() as usize;
    std::str::from_utf8(bytes.get(start..end)?)
        .ok()
        .map(ToOwned::to_owned)
}

fn valid_contract_source_path(path: &str) -> bool {
    if documented_reference_path(path).is_none() {
        return false;
    }
    let path = Path::new(path);
    if !matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("ts" | "tsx")
    ) {
        return false;
    }
    true
}

fn documented_reference_path(path: &str) -> Option<&Path> {
    let path = path.strip_prefix("./").unwrap_or(path);
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.contains("://")
    {
        return None;
    }
    let path = Path::new(path);
    path.components()
        .all(|component| matches!(component, Component::Normal(_)))
        .then_some(path)
}

fn same_rel_path(a: &str, b: &str) -> bool {
    a.strip_prefix("./").unwrap_or(a) == b.strip_prefix("./").unwrap_or(b)
}

fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

fn id_fragment(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}
