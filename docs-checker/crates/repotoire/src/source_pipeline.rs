use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::scope::Scope;
use crate::spans::Span;

const WRITEBACK_EVIDENCE_SCHEMA: &str = "repotoire.source_writeback_evidence.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceLanguage {
    TypeScript,
    Rust,
    Python,
    Unknown,
}

impl SourceLanguage {
    /// Stable internal label used by caches, evidence surfaces, and routing.
    /// This is deliberately distinct from serde's preserved public v1 label.
    pub const fn canonical_label(self) -> &'static str {
        match self {
            Self::TypeScript => "typescript",
            Self::Rust => "rust",
            Self::Python => "python",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse_canonical_label(value: &str) -> Option<Self> {
        match value {
            "typescript" => Some(Self::TypeScript),
            "rust" => Some(Self::Rust),
            "python" => Some(Self::Python),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Classifies a source path independently of which optional parsers are
/// compiled into a particular frontend.
pub fn source_language_for_path(path: &Path) -> SourceLanguage {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("ts" | "tsx" | "mts" | "cts" | "js" | "jsx" | "mjs" | "cjs") => {
            SourceLanguage::TypeScript
        }
        Some("rs") => SourceLanguage::Rust,
        Some("py" | "pyi") => SourceLanguage::Python,
        _ => SourceLanguage::Unknown,
    }
}

/// Stable project-relative identity for source paths.
///
/// Absolute checkout roots never participate in evidence or cache identity.
/// Paths outside the declared project stay absolute so invalid scope cannot
/// collapse onto an in-project filename.
pub fn canonical_project_path(project_root: &Path, path: &Path) -> String {
    let logical = if path == project_root {
        path.file_name().map(Path::new).unwrap_or(path)
    } else {
        path.strip_prefix(project_root)
            .ok()
            .filter(|relative| !relative.as_os_str().is_empty())
            .unwrap_or(path)
    };
    logical.to_string_lossy().replace('\\', "/")
}

/// Reports whether the canonical language has an extraction backend in this
/// build. Identity stays stable when an optional backend is disabled.
pub const fn parser_supports_source_language(language: SourceLanguage) -> bool {
    match language {
        SourceLanguage::TypeScript | SourceLanguage::Rust => true,
        SourceLanguage::Python => cfg!(feature = "python"),
        SourceLanguage::Unknown => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeAddress {
    pub repo: String,
    pub git_sha: String,
    pub worktree_fingerprint: String,
    pub file: String,
    pub byte_start: u32,
    pub byte_end: u32,
    pub language: SourceLanguage,
    pub source_hash: String,
}

/// Location/identity fields for a [`CodeAddress`], grouped so that
/// [`CodeAddress::from_source`] stays under clippy's argument-count limit while
/// keeping each field individually ergonomic via `impl Into<String>` on
/// [`CodeAddressInput::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeAddressInput {
    pub repo: String,
    pub git_sha: String,
    pub worktree_fingerprint: String,
    pub file: String,
    pub byte_start: u32,
    pub byte_end: u32,
    pub language: SourceLanguage,
}

impl CodeAddressInput {
    pub fn new(
        repo: impl Into<String>,
        git_sha: impl Into<String>,
        worktree_fingerprint: impl Into<String>,
        file: impl Into<String>,
        byte_start: u32,
        byte_end: u32,
        language: SourceLanguage,
    ) -> Self {
        Self {
            repo: repo.into(),
            git_sha: git_sha.into(),
            worktree_fingerprint: worktree_fingerprint.into(),
            file: file.into(),
            byte_start,
            byte_end,
            language,
        }
    }
}

impl CodeAddress {
    pub fn from_source(input: CodeAddressInput, source: &[u8]) -> Self {
        let CodeAddressInput {
            repo,
            git_sha,
            worktree_fingerprint,
            file,
            byte_start,
            byte_end,
            language,
        } = input;
        assert!(
            byte_start <= byte_end,
            "CodeAddress byte range must be ordered"
        );
        Self {
            repo,
            git_sha,
            worktree_fingerprint,
            file,
            byte_start,
            byte_end,
            language,
            source_hash: source_hash(source),
        }
    }

    pub fn span(&self) -> Span {
        Span::new(self.byte_start, self.byte_end - self.byte_start)
    }

    fn overlaps(&self, other: &CodeAddress) -> bool {
        self.file == other.file
            && self.byte_start < other.byte_end
            && other.byte_start < self.byte_end
    }

    fn canonical_key(&self) -> String {
        format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{:?}\0{}",
            self.repo,
            self.git_sha,
            self.worktree_fingerprint,
            self.file,
            self.byte_start,
            self.byte_end,
            self.language,
            self.source_hash
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceTask {
    pub task_id: String,
    pub agent_id: String,
    pub query: String,
}

impl SourceTask {
    pub fn new(
        task_id: impl Into<String>,
        agent_id: impl Into<String>,
        query: impl Into<String>,
    ) -> Self {
        Self {
            task_id: task_id.into(),
            agent_id: agent_id.into(),
            query: query.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceProgramCounter {
    pub task_id: String,
    pub agent_id: String,
    pub next_fetch_index: usize,
    pub last_address: Option<CodeAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationEvidence {
    pub graph_epoch: String,
    pub truth_epoch: String,
    pub capability_epoch: String,
    pub verification_epoch: String,
    pub backend: Option<String>,
    pub backend_status: VerificationEvidenceStatus,
    pub diagnostics_command: Option<String>,
    pub diagnostics_count: usize,
    pub exit_code: Option<i32>,
}

impl VerificationEvidence {
    pub fn new(
        graph_epoch: impl Into<String>,
        truth_epoch: impl Into<String>,
        capability_epoch: impl Into<String>,
        verification_epoch: impl Into<String>,
    ) -> Self {
        Self {
            graph_epoch: graph_epoch.into(),
            truth_epoch: truth_epoch.into(),
            capability_epoch: capability_epoch.into(),
            verification_epoch: verification_epoch.into(),
            backend: None,
            backend_status: VerificationEvidenceStatus::NotRequired,
            diagnostics_command: None,
            diagnostics_count: 0,
            exit_code: None,
        }
    }

    pub fn with_backend(
        mut self,
        backend: impl Into<String>,
        backend_status: VerificationEvidenceStatus,
        diagnostics_command: impl Into<String>,
        diagnostics_count: usize,
        exit_code: Option<i32>,
    ) -> Self {
        self.backend = Some(backend.into());
        self.backend_status = backend_status;
        self.diagnostics_command = Some(diagnostics_command.into());
        self.diagnostics_count = diagnostics_count;
        self.exit_code = exit_code;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    RefreshDocsTruth,
    RefreshRepoSnapshot,
    RerunTruthSerum,
    ResolveLink,
    UpdateDocs,
    UpdateCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocsCodeEvidenceStatus {
    Verified,
    Stale,
    Contradicted,
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocsCodeEvidence {
    pub evidence_id: String,
    pub doc_file: String,
    pub code_file: String,
    pub symbol: String,
    pub status: DocsCodeEvidenceStatus,
    pub evidence_epoch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

impl DocsCodeEvidence {
    pub fn new(
        evidence_id: impl Into<String>,
        doc_file: impl Into<String>,
        code_file: impl Into<String>,
        symbol: impl Into<String>,
        status: DocsCodeEvidenceStatus,
        evidence_epoch: impl Into<String>,
    ) -> Self {
        Self {
            evidence_id: evidence_id.into(),
            doc_file: doc_file.into(),
            code_file: code_file.into(),
            symbol: symbol.into(),
            status,
            evidence_epoch: evidence_epoch.into(),
            surface: None,
            summary: None,
        }
    }

    pub fn with_surface(mut self, surface: impl Into<String>) -> Self {
        self.surface = Some(surface.into());
        self
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(bound_string(summary.into(), 160));
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationContractStatus {
    Verified,
    StaleRepoSnapshot,
    UnverifiedExternalLink,
    ManifestDrift,
    VersionMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationContractEvidence {
    pub evidence_id: String,
    pub source_file: String,
    pub package_name: String,
    pub status: FederationContractStatus,
    pub evidence_epoch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

impl FederationContractEvidence {
    pub fn new(
        evidence_id: impl Into<String>,
        source_file: impl Into<String>,
        package_name: impl Into<String>,
        status: FederationContractStatus,
        evidence_epoch: impl Into<String>,
    ) -> Self {
        Self {
            evidence_id: evidence_id.into(),
            source_file: source_file.into(),
            package_name: package_name.into(),
            status,
            evidence_epoch: evidence_epoch.into(),
            surface: None,
            summary: None,
        }
    }

    pub fn with_surface(mut self, surface: impl Into<String>) -> Self {
        self.surface = Some(surface.into());
        self
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(bound_string(summary.into(), 160));
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelatedUpdateEvidence {
    pub file: String,
    pub action: RecoveryAction,
    pub evidence_ids: Vec<String>,
    /// The evidence epoch produced by actually running `action` (e.g. the new docs-truth /
    /// truth-serum / repo-snapshot epoch). F11 (fail_open): a related update is only credible
    /// proof that the recovery action ran if it carries a freshly produced epoch that differs
    /// from the stale evidence epoch it claims to resolve. A self-asserted action with no
    /// produced epoch — or one that echoes the stale epoch — proves nothing and must not
    /// satisfy the writeback gate.
    pub produced_epoch: String,
}

impl RelatedUpdateEvidence {
    pub fn new(
        file: impl Into<String>,
        action: RecoveryAction,
        mut evidence_ids: Vec<String>,
        produced_epoch: impl Into<String>,
    ) -> Self {
        evidence_ids.sort();
        evidence_ids.dedup();
        Self {
            file: file.into(),
            action,
            evidence_ids,
            produced_epoch: produced_epoch.into(),
        }
    }

    fn cites(&self, evidence_id: &str) -> bool {
        self.evidence_ids.iter().any(|id| id == evidence_id)
    }

    /// True only when this update carries proof the recovery action actually ran: a non-empty
    /// produced epoch that differs from the stale evidence epoch it claims to resolve.
    fn proves_rerun(&self, stale_epoch: &str) -> bool {
        !self.produced_epoch.trim().is_empty() && self.produced_epoch != stale_epoch
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationEvidenceStatus {
    NotRequired,
    Ran,
    LaunchFailed,
    Unsupported,
}

impl VerificationEvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::Ran => "ran",
            Self::LaunchFailed => "launch_failed",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchDecision {
    MustFetch,
    ShouldFetch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefetchSignal {
    Import,
    Export,
    Declaration,
    Caller,
    Callee,
    TypeRef,
    Diagnostic,
    Test,
    Docs,
    TruthGap,
    DirtyHunk,
    GraphDistance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchCandidate {
    pub address: CodeAddress,
    pub decision: FetchDecision,
    pub signals: Vec<PrefetchSignal>,
    pub graph_distance: u32,
    pub score: i32,
    pub reason: String,
}

impl FetchCandidate {
    pub fn new(address: CodeAddress, decision: FetchDecision) -> Self {
        Self {
            address,
            decision,
            signals: Vec::new(),
            graph_distance: u32::MAX,
            score: 0,
            reason: String::new(),
        }
    }

    pub fn with_signal(mut self, signal: PrefetchSignal) -> Self {
        if !self.signals.contains(&signal) {
            self.signals.push(signal);
            self.signals.sort_by_key(|signal| signal_priority(*signal));
        }
        self
    }

    pub fn with_graph_distance(mut self, graph_distance: u32) -> Self {
        self.graph_distance = graph_distance;
        self
    }

    pub fn with_score(mut self, score: i32) -> Self {
        self.score = score;
        self
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchEntry {
    pub source_pc: usize,
    pub address: CodeAddress,
    pub decision: FetchDecision,
    pub signals: Vec<PrefetchSignal>,
    pub graph_distance: u32,
    pub score: i32,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchPlan {
    pub task_id: String,
    pub agent_id: String,
    pub budget_bytes: usize,
    pub verification_evidence: VerificationEvidence,
    pub source_pc: SourceProgramCounter,
    pub control_pc_hint: Option<u32>,
    pub entries: Vec<FetchEntry>,
}

impl FetchPlan {
    pub fn build(
        task: &SourceTask,
        budget_bytes: usize,
        evidence: &VerificationEvidence,
        candidates: Vec<FetchCandidate>,
    ) -> Self {
        // Aggregate by the complete identity before ranking or charging bytes.
        // Separate sightings contribute evidence, not additional source slices.
        let mut merged: BTreeMap<CodeAddress, (FetchCandidate, BTreeSet<String>)> = BTreeMap::new();
        for candidate in candidates {
            if let Some((existing, reasons)) = merged.get_mut(&candidate.address) {
                existing.decision = existing.decision.min(candidate.decision);
                existing.graph_distance = existing.graph_distance.min(candidate.graph_distance);
                existing.score = existing.score.max(candidate.score);
                existing.signals.extend(candidate.signals);
                if !candidate.reason.is_empty() {
                    reasons.insert(candidate.reason);
                }
            } else {
                let reasons = if candidate.reason.is_empty() {
                    BTreeSet::new()
                } else {
                    BTreeSet::from([candidate.reason.clone()])
                };
                merged.insert(candidate.address.clone(), (candidate, reasons));
            }
        }
        let mut candidates: Vec<_> = merged
            .into_values()
            .map(|(mut candidate, reasons)| {
                candidate.reason = reasons.into_iter().collect::<Vec<_>>().join("; ");
                candidate
            })
            .collect();
        candidates.iter_mut().for_each(|candidate| {
            candidate
                .signals
                .sort_by_key(|signal| signal_priority(*signal));
            candidate.signals.dedup();
            candidate.score = candidate
                .score
                .saturating_add(signal_bundle_score(&candidate.signals));
        });
        candidates.sort_by(fetch_candidate_cmp);

        let mut entries = Vec::new();
        let mut used = 0usize;
        for candidate in candidates {
            let len = (candidate.address.byte_end - candidate.address.byte_start) as usize;
            if !entries.is_empty() && used.saturating_add(len) > budget_bytes {
                continue;
            }
            used = used.saturating_add(len);
            entries.push(FetchEntry {
                source_pc: entries.len(),
                address: candidate.address,
                decision: candidate.decision,
                signals: candidate.signals,
                graph_distance: candidate.graph_distance,
                score: candidate.score,
                reason: candidate.reason,
            });
        }

        Self {
            task_id: task.task_id.clone(),
            agent_id: task.agent_id.clone(),
            budget_bytes,
            verification_evidence: evidence.clone(),
            source_pc: SourceProgramCounter {
                task_id: task.task_id.clone(),
                agent_id: task.agent_id.clone(),
                next_fetch_index: 0,
                last_address: None,
            },
            control_pc_hint: None,
            entries,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodeTape {
    pub source_address: CodeAddress,
    pub source_hash: String,
    pub tokens: Vec<DecodeToken>,
    pub diagnostics: Vec<PipelineDiagnostic>,
    pub lineage: Vec<String>,
}

impl DecodeTape {
    pub fn decode(
        source_address: CodeAddress,
        source: &[u8],
        diagnostics: Vec<PipelineDiagnostic>,
    ) -> Self {
        let source_hash = source_hash(source);
        let mut tokens = Vec::new();
        let mut i = 0usize;
        let mut nesting_depth = 0u32;

        while i < source.len() {
            let b = source[i];
            if b.is_ascii_whitespace() {
                i += 1;
                continue;
            }
            if is_ident_start(b) {
                let start = i;
                i += 1;
                while i < source.len() && is_ident_continue(source[i]) {
                    i += 1;
                }
                let text = String::from_utf8_lossy(&source[start..i]).into_owned();
                let role = if is_keyword(&text) {
                    DecodeTokenRole::Keyword
                } else {
                    DecodeTokenRole::Identifier
                };
                tokens.push(decode_token(
                    &source_address,
                    &source_hash,
                    start,
                    i,
                    text,
                    role,
                    nesting_depth,
                ));
                continue;
            }
            if b.is_ascii_digit() {
                let start = i;
                i += 1;
                while i < source.len() && source[i].is_ascii_digit() {
                    i += 1;
                }
                tokens.push(decode_token(
                    &source_address,
                    &source_hash,
                    start,
                    i,
                    String::from_utf8_lossy(&source[start..i]).into_owned(),
                    DecodeTokenRole::Literal,
                    nesting_depth,
                ));
                continue;
            }

            let start = i;
            i += 1;
            if b == b'}' {
                nesting_depth = nesting_depth.saturating_sub(1);
            }
            let text = String::from_utf8_lossy(&source[start..i]).into_owned();
            tokens.push(decode_token(
                &source_address,
                &source_hash,
                start,
                i,
                text,
                DecodeTokenRole::Punctuation,
                nesting_depth,
            ));
            if b == b'{' {
                nesting_depth = nesting_depth.saturating_add(1);
            }
        }

        Self {
            source_address: source_address.clone(),
            source_hash,
            tokens,
            diagnostics,
            lineage: vec![source_address.canonical_key()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodeToken {
    pub stable_id: String,
    pub text: String,
    pub span: Span,
    pub role: DecodeTokenRole,
    pub token_hash: String,
    pub source_hash: String,
    pub nesting_depth: u32,
    pub confidence: f32,
    pub lineage: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecodeTokenRole {
    Identifier,
    Keyword,
    Literal,
    Punctuation,
}

impl DecodeTokenRole {
    pub fn as_str(self) -> &'static str {
        match self {
            DecodeTokenRole::Identifier => "identifier",
            DecodeTokenRole::Keyword => "keyword",
            DecodeTokenRole::Literal => "literal",
            DecodeTokenRole::Punctuation => "punctuation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineDiagnostic {
    pub source: String,
    pub span: Span,
    pub message: String,
    pub severity: DiagnosticSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextRamEntry {
    pub address: CodeAddress,
    pub kind: ContextRamEntryKind,
    byte_len: usize,
}

impl ContextRamEntry {
    pub fn source(address: CodeAddress, bytes: Vec<u8>) -> Self {
        Self {
            address,
            byte_len: bytes.len(),
            kind: ContextRamEntryKind::Source { bytes },
        }
    }

    pub fn decode(address: CodeAddress, tape: DecodeTape) -> Self {
        let byte_len = tape
            .tokens
            .iter()
            .map(|token| token.text.len() + 32)
            .sum::<usize>()
            .max(1);
        Self {
            address,
            byte_len,
            kind: ContextRamEntryKind::Decode {
                tape: Box::new(tape),
            },
        }
    }

    pub fn docs_code_context(
        address: CodeAddress,
        evidence: Vec<DocsCodeEvidence>,
        budget_bytes: usize,
    ) -> Self {
        let evidence = bound_docs_code_evidence(evidence, budget_bytes);
        let byte_len = docs_code_evidence_len(&evidence).max(1);
        Self {
            address,
            byte_len,
            kind: ContextRamEntryKind::DocsCodeContext { evidence },
        }
    }

    pub fn federation_context(
        address: CodeAddress,
        evidence: Vec<FederationContractEvidence>,
        budget_bytes: usize,
    ) -> Self {
        let evidence = bound_federation_evidence(evidence, budget_bytes);
        let byte_len = federation_evidence_len(&evidence).max(1);
        Self {
            address,
            byte_len,
            kind: ContextRamEntryKind::FederationContext { evidence },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextRamEntryKind {
    Source {
        bytes: Vec<u8>,
    },
    Decode {
        tape: Box<DecodeTape>,
    },
    DocsCodeContext {
        evidence: Vec<DocsCodeEvidence>,
    },
    FederationContext {
        evidence: Vec<FederationContractEvidence>,
    },
}

#[derive(Debug, Clone)]
struct ResidentContextEntry {
    entry: ContextRamEntry,
    last_access: u64,
}

#[derive(Debug, Clone)]
pub struct ContextRam {
    capacity_bytes: usize,
    bytes_used: usize,
    clock: u64,
    entries: BTreeMap<CodeAddress, ResidentContextEntry>,
}

impl ContextRam {
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            capacity_bytes,
            bytes_used: 0,
            clock: 0,
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, entry: ContextRamEntry) {
        self.clock = self.clock.saturating_add(1);
        if let Some(previous) = self.entries.remove(&entry.address) {
            self.bytes_used = self.bytes_used.saturating_sub(previous.entry.byte_len);
        }
        self.bytes_used = self.bytes_used.saturating_add(entry.byte_len);
        self.entries.insert(
            entry.address.clone(),
            ResidentContextEntry {
                entry,
                last_access: self.clock,
            },
        );
        self.evict_to_capacity();
    }

    pub fn get(&mut self, address: &CodeAddress) -> Option<&ContextRamEntry> {
        let resident = self.entries.get_mut(address)?;
        self.clock = self.clock.saturating_add(1);
        resident.last_access = self.clock;
        Some(&resident.entry)
    }

    pub fn contains(&self, address: &CodeAddress) -> bool {
        self.entries.contains_key(address)
    }

    pub fn bytes_used(&self) -> usize {
        self.bytes_used
    }

    fn evict_to_capacity(&mut self) {
        while self.bytes_used > self.capacity_bytes {
            let Some(victim) = self
                .entries
                .iter()
                .min_by(|(left_address, left), (right_address, right)| {
                    (left.last_access, *left_address).cmp(&(right.last_access, *right_address))
                })
                .map(|(address, _)| address.clone())
            else {
                break;
            };
            if let Some(removed) = self.entries.remove(&victim) {
                self.bytes_used = self.bytes_used.saturating_sub(removed.entry.byte_len);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineWorld {
    pub current_git_sha: String,
    pub worktree_fingerprint: String,
    pub decode_epoch: String,
    pub graph_epoch: String,
    pub truth_epoch: String,
    pub capability_epoch: String,
    pub verification_epoch: String,
    pub sources: BTreeMap<String, CodeAddress>,
    #[serde(default)]
    pub docs_code_evidence: Vec<DocsCodeEvidence>,
    #[serde(default)]
    pub federation_evidence: Vec<FederationContractEvidence>,
}

impl PipelineWorld {
    pub fn new(
        current_git_sha: impl Into<String>,
        worktree_fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            current_git_sha: current_git_sha.into(),
            worktree_fingerprint: worktree_fingerprint.into(),
            decode_epoch: String::new(),
            graph_epoch: String::new(),
            truth_epoch: String::new(),
            capability_epoch: String::new(),
            verification_epoch: String::new(),
            sources: BTreeMap::new(),
            docs_code_evidence: Vec::new(),
            federation_evidence: Vec::new(),
        }
    }

    pub fn with_source(mut self, address: CodeAddress) -> Self {
        self.sources.insert(address.file.clone(), address);
        self
    }

    pub fn with_docs_code_evidence(mut self, evidence: DocsCodeEvidence) -> Self {
        self.docs_code_evidence.push(evidence);
        self.docs_code_evidence.sort();
        self.docs_code_evidence.dedup();
        self
    }

    pub fn with_federation_evidence(mut self, evidence: FederationContractEvidence) -> Self {
        self.federation_evidence.push(evidence);
        self.federation_evidence.sort();
        self.federation_evidence.dedup();
        self
    }

    pub fn with_epochs(
        mut self,
        decode_epoch: impl Into<String>,
        graph_epoch: impl Into<String>,
        truth_epoch: impl Into<String>,
        capability_epoch: impl Into<String>,
        verification_epoch: impl Into<String>,
    ) -> Self {
        self.decode_epoch = decode_epoch.into();
        self.graph_epoch = graph_epoch.into();
        self.truth_epoch = truth_epoch.into();
        self.capability_epoch = capability_epoch.into();
        self.verification_epoch = verification_epoch.into();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEpochs {
    pub decode_epoch: String,
    pub graph_epoch: String,
    pub truth_epoch: String,
    pub capability_epoch: String,
    pub verification_epoch: String,
}

impl EvidenceEpochs {
    fn new(
        decode_epoch: impl Into<String>,
        graph_epoch: impl Into<String>,
        truth_epoch: impl Into<String>,
        capability_epoch: impl Into<String>,
        verification_epoch: impl Into<String>,
    ) -> Self {
        Self {
            decode_epoch: decode_epoch.into(),
            graph_epoch: graph_epoch.into(),
            truth_epoch: truth_epoch.into(),
            capability_epoch: capability_epoch.into(),
            verification_epoch: verification_epoch.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchIntent {
    pub agent_id: String,
    pub base_git_sha: String,
    pub worktree_fingerprint: String,
    pub claimed_files: BTreeSet<String>,
    pub claimed_symbols: BTreeSet<String>,
    pub expected_source_hashes: Vec<ExpectedSourceHash>,
    pub touched_addresses: Vec<CodeAddress>,
    pub read_epochs: Option<EvidenceEpochs>,
    pub rationale: String,
    pub required_gates: BTreeSet<String>,
    #[serde(default)]
    pub docs_code_evidence: Vec<DocsCodeEvidence>,
    #[serde(default)]
    pub federation_evidence: Vec<FederationContractEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precision: Option<PatchPrecisionMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchPrecisionMetadata {
    pub intent_mode: PatchIntentMode,
    pub autonomous_write_ready: bool,
    #[serde(default)]
    pub evidence_tiers: BTreeMap<String, usize>,
    #[serde(default)]
    pub blockers: BTreeSet<PatchPrecisionBlocker>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calibration_profile: Option<String>,
}

impl PatchPrecisionMetadata {
    pub fn is_autonomous_write_ready(&self) -> bool {
        self.intent_mode == PatchIntentMode::AutonomousWrite
            && self.autonomous_write_ready
            && self.blockers.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchIntentMode {
    PreviewOnly,
    AutonomousWrite,
}

impl PatchIntentMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::PreviewOnly => "preview_only",
            Self::AutonomousWrite => "autonomous_write",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchPrecisionBlocker {
    PreviewOnly,
    GraphOnlyUncalibrated,
    AuthorityOnly,
    Unverified,
    Ambiguous,
    ForeignDefinition,
    SourceByteMismatch,
}

impl PatchPrecisionBlocker {
    fn as_str(self) -> &'static str {
        match self {
            Self::PreviewOnly => "preview_only",
            Self::GraphOnlyUncalibrated => "graph_only_uncalibrated",
            Self::AuthorityOnly => "authority_only",
            Self::Unverified => "unverified",
            Self::Ambiguous => "ambiguous",
            Self::ForeignDefinition => "foreign_definition",
            Self::SourceByteMismatch => "source_byte_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedSourceHash {
    pub address: CodeAddress,
    pub expected_source_hash: String,
}

impl PatchIntent {
    pub fn new(
        agent_id: impl Into<String>,
        base_git_sha: impl Into<String>,
        worktree_fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            base_git_sha: base_git_sha.into(),
            worktree_fingerprint: worktree_fingerprint.into(),
            claimed_files: BTreeSet::new(),
            claimed_symbols: BTreeSet::new(),
            expected_source_hashes: Vec::new(),
            touched_addresses: Vec::new(),
            read_epochs: None,
            rationale: String::new(),
            required_gates: BTreeSet::new(),
            docs_code_evidence: Vec::new(),
            federation_evidence: Vec::new(),
            precision: None,
        }
    }

    pub fn claim_file(mut self, file: impl Into<String>) -> Self {
        self.claimed_files.insert(file.into());
        self
    }

    pub fn claim_symbol(mut self, symbol: impl Into<String>) -> Self {
        self.claimed_symbols.insert(symbol.into());
        self
    }

    pub fn touch_address(mut self, address: CodeAddress) -> Self {
        self.touched_addresses.push(address);
        self.touched_addresses.sort();
        self.touched_addresses.dedup();
        self
    }

    pub fn expect_source_hash(
        mut self,
        address: CodeAddress,
        expected_source_hash: impl Into<String>,
    ) -> Self {
        let expected_source_hash = ExpectedSourceHash {
            address,
            expected_source_hash: expected_source_hash.into(),
        };
        if let Some(existing) = self
            .expected_source_hashes
            .iter_mut()
            .find(|existing| existing.address == expected_source_hash.address)
        {
            *existing = expected_source_hash;
        } else {
            self.expected_source_hashes.push(expected_source_hash);
        }
        self.expected_source_hashes.sort();
        self
    }

    pub fn with_read_epochs(
        mut self,
        decode_epoch: impl Into<String>,
        graph_epoch: impl Into<String>,
        truth_epoch: impl Into<String>,
        capability_epoch: impl Into<String>,
        verification_epoch: impl Into<String>,
    ) -> Self {
        self.read_epochs = Some(EvidenceEpochs::new(
            decode_epoch,
            graph_epoch,
            truth_epoch,
            capability_epoch,
            verification_epoch,
        ));
        self
    }

    pub fn require_gate(mut self, gate: impl Into<String>) -> Self {
        self.required_gates.insert(gate.into());
        self
    }

    pub fn acknowledge_docs_code_evidence(mut self, evidence: DocsCodeEvidence) -> Self {
        self.docs_code_evidence.push(evidence);
        self.docs_code_evidence.sort();
        self.docs_code_evidence.dedup();
        self
    }

    pub fn acknowledge_federation_evidence(mut self, evidence: FederationContractEvidence) -> Self {
        self.federation_evidence.push(evidence);
        self.federation_evidence.sort();
        self.federation_evidence.dedup();
        self
    }

    pub fn with_precision(mut self, precision: PatchPrecisionMetadata) -> Self {
        self.precision = Some(precision);
        self
    }

    pub fn with_rationale(mut self, rationale: impl Into<String>) -> Self {
        self.rationale = rationale.into();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefetchedEvidence {
    pub agent_id: String,
    pub address: CodeAddress,
    pub consumed: bool,
}

impl PrefetchedEvidence {
    pub fn new(agent_id: impl Into<String>, address: CodeAddress, consumed: bool) -> Self {
        Self {
            agent_id: agent_id.into(),
            address,
            consumed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStage {
    Fetch,
    Decode,
    Execute,
    Hazard,
    Writeback,
    Verify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StallReasonCode {
    RawStaleSource,
    WawWriteConflict,
    WarPrefetchInvalidation,
    SpanDrift,
    UnclaimedWriteScope,
    /// Additive diagnosis, not a gate of its own: a `claimed_files` entry
    /// failed `Scope::parse`. The claimed-gates (`claim_grants_path`) already
    /// fail closed on this via `UnclaimedWriteScope` — this stall exists so
    /// the deny doesn't read as a generic "not covered by claimed_files"
    /// when the real problem is an unreadable claim string (ADR 0007 /
    /// Write Scope glossary: a fault to surface, never a claim to silently
    /// drop).
    UnparseableWriteScope,
    VerificationEvidenceUnavailable,
    VerificationEvidenceFailed,
    MissingIntentReceipt,
    StaleIntentReceipt,
    StaleGraphEpoch,
    GraphInputUnavailable,
    StaleDecodeEpoch,
    StaleTruthEpoch,
    StaleCapabilityEpoch,
    StaleVerificationEpoch,
    GateFailed,
    StaleDocs,
    ContradictedDocs,
    StaleRepoSnapshot,
    UnverifiedExternalLink,
    ManifestDrift,
    VersionMismatch,
    PrecisionWritebackBlocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineStall {
    pub stage: PipelineStage,
    pub reason_code: StallReasonCode,
    pub blocking_evidence: Vec<String>,
    pub affected_addresses: Vec<CodeAddress>,
    pub next_action: String,
    #[serde(default)]
    pub recovery_actions: Vec<RecoveryAction>,
    pub resumable: bool,
}

pub struct HazardDetector;

impl HazardDetector {
    pub fn check_patch_intent(
        intent: &PatchIntent,
        world: &PipelineWorld,
        active_intents: &[PatchIntent],
    ) -> Vec<PipelineStall> {
        let mut stalls = Vec::new();
        if intent.base_git_sha != world.current_git_sha
            || intent.worktree_fingerprint != world.worktree_fingerprint
        {
            stalls.push(stall(
                PipelineStage::Writeback,
                StallReasonCode::RawStaleSource,
                vec![format!(
                    "intent base `{}`/`{}` != world `{}`/`{}`",
                    intent.base_git_sha,
                    intent.worktree_fingerprint,
                    world.current_git_sha,
                    world.worktree_fingerprint
                )],
                intent.touched_addresses.clone(),
                "refresh patch intent against current git/worktree",
                true,
            ));
        }

        for expected in &intent.expected_source_hashes {
            let address = &expected.address;
            let expected_hash = &expected.expected_source_hash;
            match world.sources.get(&address.file) {
                Some(current) if current.source_hash.as_str() == expected_hash.as_str() => {}
                Some(current) => {
                    stalls.push(stall(
                        PipelineStage::Writeback,
                        StallReasonCode::RawStaleSource,
                        vec![format!(
                            "{} expected {}, current {}",
                            address.file, expected_hash, current.source_hash
                        )],
                        vec![address.clone()],
                        "refetch source evidence before writeback",
                        true,
                    ));
                    if current.source_hash != address.source_hash
                        || current.byte_start != address.byte_start
                        || current.byte_end != address.byte_end
                    {
                        stalls.push(stall(
                            PipelineStage::Decode,
                            StallReasonCode::SpanDrift,
                            vec![format!(
                                "{} stored range {}..{} no longer matches current source hash",
                                address.file, address.byte_start, address.byte_end
                            )],
                            vec![address.clone(), current.clone()],
                            "re-decode current source range and remap spans",
                            true,
                        ));
                    }
                }
                None => stalls.push(stall(
                    PipelineStage::Writeback,
                    StallReasonCode::RawStaleSource,
                    vec![format!("{} missing from current world", address.file)],
                    vec![address.clone()],
                    "refetch missing source evidence",
                    true,
                )),
            }
        }

        if let Some(read_epochs) = &intent.read_epochs {
            push_epoch_stall(
                &mut stalls,
                read_epochs.decode_epoch.as_str(),
                world.decode_epoch.as_str(),
                StallReasonCode::StaleDecodeEpoch,
                &intent.touched_addresses,
            );
            push_epoch_stall(
                &mut stalls,
                read_epochs.graph_epoch.as_str(),
                world.graph_epoch.as_str(),
                StallReasonCode::StaleGraphEpoch,
                &intent.touched_addresses,
            );
            push_epoch_stall(
                &mut stalls,
                read_epochs.truth_epoch.as_str(),
                world.truth_epoch.as_str(),
                StallReasonCode::StaleTruthEpoch,
                &intent.touched_addresses,
            );
            push_epoch_stall(
                &mut stalls,
                read_epochs.capability_epoch.as_str(),
                world.capability_epoch.as_str(),
                StallReasonCode::StaleCapabilityEpoch,
                &intent.touched_addresses,
            );
            push_epoch_stall(
                &mut stalls,
                read_epochs.verification_epoch.as_str(),
                world.verification_epoch.as_str(),
                StallReasonCode::StaleVerificationEpoch,
                &intent.touched_addresses,
            );
        }

        stalls.extend(check_precision_metadata(intent));
        stalls.extend(check_docs_code_evidence(intent, world));
        stalls.extend(check_federation_evidence(intent, world));

        for active in active_intents {
            if active.agent_id == intent.agent_id {
                continue;
            }
            if file_claims_overlap(&active.claimed_files, &intent.claimed_files)
                || sets_intersect(&active.claimed_symbols, &intent.claimed_symbols)
                || addresses_overlap(&active.touched_addresses, &intent.touched_addresses)
            {
                stalls.push(stall(
                    PipelineStage::Writeback,
                    StallReasonCode::WawWriteConflict,
                    vec![format!(
                        "{} conflicts with active writer {}",
                        intent.agent_id, active.agent_id
                    )],
                    intent.touched_addresses.clone(),
                    "serialize overlapping patch intents or split write scopes",
                    true,
                ));
            }
        }

        dedup_stalls(stalls)
    }

    pub fn check_war(
        writer: &PatchIntent,
        prefetched: &[PrefetchedEvidence],
    ) -> Vec<PipelineStall> {
        let mut stalls = Vec::new();
        for evidence in prefetched {
            if evidence.consumed || evidence.agent_id == writer.agent_id {
                continue;
            }
            if writer
                .touched_addresses
                .iter()
                .any(|address| address.overlaps(&evidence.address))
            {
                stalls.push(stall(
                    PipelineStage::Hazard,
                    StallReasonCode::WarPrefetchInvalidation,
                    vec![format!(
                        "{} would invalidate unconsumed prefetch for {}",
                        writer.agent_id, evidence.agent_id
                    )],
                    vec![evidence.address.clone()],
                    "invalidate prefetched evidence and re-decode for reader",
                    true,
                ));
            }
        }
        dedup_stalls(stalls)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchApplication {
    pub file: String,
    pub bytes: Vec<u8>,
    pub gate_results: BTreeMap<String, bool>,
    #[serde(default)]
    pub related_updates: Vec<RelatedUpdateEvidence>,
}

impl PatchApplication {
    pub fn replace_file(file: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            file: file.into(),
            bytes,
            gate_results: BTreeMap::new(),
            related_updates: Vec::new(),
        }
    }

    pub fn with_gate_result(mut self, gate: impl Into<String>, passed: bool) -> Self {
        self.gate_results.insert(gate.into(), passed);
        self
    }

    pub fn with_related_update(mut self, update: RelatedUpdateEvidence) -> Self {
        self.related_updates.push(update);
        self.related_updates.sort();
        self.related_updates.dedup();
        self
    }
}

#[derive(Debug, Clone)]
pub struct WritebackEngine {
    world: PipelineWorld,
    active_intents: Vec<PatchIntent>,
    prefetched_evidence: Vec<PrefetchedEvidence>,
}

impl WritebackEngine {
    pub fn new(world: PipelineWorld) -> Self {
        Self {
            world,
            active_intents: Vec::new(),
            prefetched_evidence: Vec::new(),
        }
    }

    pub fn with_active_intent(mut self, intent: PatchIntent) -> Self {
        self.active_intents.push(intent);
        self
    }

    pub fn with_active_intents(mut self, intents: impl IntoIterator<Item = PatchIntent>) -> Self {
        self.active_intents.extend(intents);
        self
    }

    pub fn with_prefetched_evidence(mut self, evidence: PrefetchedEvidence) -> Self {
        self.prefetched_evidence.push(evidence);
        self
    }

    pub fn with_prefetched_evidence_items(
        mut self,
        evidence: impl IntoIterator<Item = PrefetchedEvidence>,
    ) -> Self {
        self.prefetched_evidence.extend(evidence);
        self
    }

    pub fn apply(
        &mut self,
        intent: PatchIntent,
        application: PatchApplication,
    ) -> Result<WritebackEvidencePacket, Vec<PipelineStall>> {
        let mut stalls =
            HazardDetector::check_patch_intent(&intent, &self.world, &self.active_intents);
        stalls.extend(HazardDetector::check_war(
            &intent,
            &self.prefetched_evidence,
        ));
        stalls.extend(check_claim_parseability(&intent));
        stalls.extend(check_application_scope(&intent, &application));
        stalls.extend(check_related_updates(&intent, &self.world, &application));
        for gate in &intent.required_gates {
            if application.gate_results.get(gate).copied() != Some(true) {
                stalls.push(stall(
                    PipelineStage::Verify,
                    StallReasonCode::GateFailed,
                    vec![format!("required gate `{gate}` did not pass")],
                    intent.touched_addresses.clone(),
                    "run required gate and retry writeback with fresh evidence",
                    true,
                ));
            }
        }
        if !stalls.is_empty() {
            return Err(dedup_stalls(stalls));
        }

        let previous = self.world.sources.get(&application.file).cloned();
        let language = previous
            .as_ref()
            .map(|address| address.language)
            .unwrap_or(SourceLanguage::Unknown);
        let repo = previous
            .as_ref()
            .map(|address| address.repo.clone())
            .unwrap_or_else(|| "repo:unknown".to_string());
        let new_address = CodeAddress::from_source(
            CodeAddressInput::new(
                repo,
                self.world.current_git_sha.clone(),
                self.world.worktree_fingerprint.clone(),
                application.file.clone(),
                0,
                application.bytes.len() as u32,
                language,
            ),
            &application.bytes,
        );
        self.world
            .sources
            .insert(application.file.clone(), new_address.clone());
        self.world.worktree_fingerprint = fingerprint_world(&self.world);

        let tape = DecodeTape::decode(new_address, &application.bytes, Vec::new());
        let gates = application
            .gate_results
            .iter()
            .map(|(gate_id, passed)| GateEvidence {
                gate_id: gate_id.clone(),
                passed: *passed,
            })
            .collect();

        Ok(WritebackEvidencePacket {
            schema: WRITEBACK_EVIDENCE_SCHEMA.to_string(),
            agent_id: intent.agent_id,
            base_git_sha: intent.base_git_sha,
            final_worktree_fingerprint: self.world.worktree_fingerprint.clone(),
            redecoded: vec![tape],
            reparse: ReparseEvidence { performed: true },
            graph_delta: GraphDeltaEvidence {
                touched_files: vec![application.file],
                changed_nodes: 1,
            },
            gates,
            related_updates: application.related_updates,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedEdit {
    pub intent: PatchIntent,
    pub application: ScopedEditApplication,
}

impl ScopedEdit {
    pub fn new(intent: PatchIntent, application: ScopedEditApplication) -> Self {
        Self {
            intent,
            application,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedEditApplication {
    pub files: Vec<RetirementBundleFile>,
    #[serde(default)]
    pub gate_results: BTreeMap<String, bool>,
    #[serde(default)]
    pub related_updates: Vec<RelatedUpdateEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_provenance: Option<ScopedEditDiffProvenance>,
}

impl ScopedEditApplication {
    pub fn new(files: Vec<RetirementBundleFile>) -> Self {
        Self {
            files,
            gate_results: BTreeMap::new(),
            related_updates: Vec::new(),
            diff_provenance: None,
        }
    }

    pub fn with_gate_result(mut self, gate: impl Into<String>, passed: bool) -> Self {
        self.gate_results.insert(gate.into(), passed);
        self
    }

    pub fn with_related_update(mut self, update: RelatedUpdateEvidence) -> Self {
        self.related_updates.push(update);
        self.related_updates.sort();
        self.related_updates.dedup();
        self
    }

    pub fn with_diff_provenance(mut self, provenance: ScopedEditDiffProvenance) -> Self {
        self.diff_provenance = Some(provenance);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedEditDiffProvenance {
    pub format: String,
    pub diff_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    #[serde(default)]
    pub materialization_diagnostics: Vec<String>,
}

impl ScopedEditDiffProvenance {
    pub fn new(format: impl Into<String>, diff_hash: impl Into<String>) -> Self {
        Self {
            format: format.into(),
            diff_hash: diff_hash.into(),
            preview: None,
            materialization_diagnostics: Vec::new(),
        }
    }

    pub fn with_preview(mut self, preview: impl Into<String>) -> Self {
        self.preview = Some(preview.into());
        self
    }

    pub fn with_materialization_diagnostic(mut self, diagnostic: impl Into<String>) -> Self {
        self.materialization_diagnostics.push(diagnostic.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementBundle {
    pub bundle_id: String,
    pub intent: PatchIntent,
    pub files: Vec<RetirementBundleFile>,
    #[serde(default)]
    pub gate_results: BTreeMap<String, bool>,
    #[serde(default)]
    pub related_updates: Vec<RelatedUpdateEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_role_policy_evidence_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_provenance: Option<ScopedEditDiffProvenance>,
}

impl RetirementBundle {
    pub fn new(intent: PatchIntent, files: Vec<RetirementBundleFile>) -> Self {
        let mut bundle = Self {
            bundle_id: String::new(),
            intent,
            files,
            gate_results: BTreeMap::new(),
            related_updates: Vec::new(),
            source_role_policy_evidence_ids: Vec::new(),
            diff_provenance: None,
        };
        bundle.refresh_identity();
        bundle
    }

    pub fn from_scoped_edit(edit: ScopedEdit) -> Self {
        let ScopedEdit {
            intent,
            application,
        } = edit;
        let mut bundle = Self {
            bundle_id: String::new(),
            intent,
            files: application.files,
            gate_results: application.gate_results,
            related_updates: application.related_updates,
            source_role_policy_evidence_ids: Vec::new(),
            diff_provenance: application.diff_provenance,
        };
        bundle.refresh_identity();
        bundle
    }

    pub fn from_patch_application(intent: PatchIntent, application: PatchApplication) -> Self {
        let expected_base_source_hash = intent
            .expected_source_hashes
            .iter()
            .find(|expected| expected.address.file == application.file)
            .map(|expected| expected.expected_source_hash.clone())
            .unwrap_or_default();
        let file = RetirementBundleFile::replace(
            application.file.clone(),
            expected_base_source_hash,
            application.bytes.clone(),
        );
        let mut bundle = Self {
            bundle_id: String::new(),
            intent,
            files: vec![file],
            gate_results: application.gate_results,
            related_updates: application.related_updates,
            source_role_policy_evidence_ids: Vec::new(),
            diff_provenance: None,
        };
        bundle.refresh_identity();
        bundle
    }

    pub fn with_gate_result(mut self, gate: impl Into<String>, passed: bool) -> Self {
        self.gate_results.insert(gate.into(), passed);
        self
    }

    pub fn with_related_update(mut self, update: RelatedUpdateEvidence) -> Self {
        self.related_updates.push(update);
        self.refresh_identity();
        self
    }

    pub fn with_source_role_policy_evidence_id(mut self, evidence_id: impl Into<String>) -> Self {
        self.source_role_policy_evidence_ids
            .push(evidence_id.into());
        self.refresh_identity();
        self
    }

    pub fn with_diff_provenance(mut self, provenance: ScopedEditDiffProvenance) -> Self {
        self.diff_provenance = Some(provenance);
        self
    }

    fn refresh_identity(&mut self) {
        self.files.sort_by(retirement_bundle_file_cmp);
        self.files.dedup();
        self.related_updates.sort();
        self.related_updates.dedup();
        self.source_role_policy_evidence_ids.sort();
        self.source_role_policy_evidence_ids.dedup();
        self.bundle_id = self.compute_bundle_id();
    }

    fn compute_bundle_id(&self) -> String {
        #[derive(Serialize)]
        struct BundleIdentity<'a> {
            schema: &'static str,
            intent: &'a PatchIntent,
            files: Vec<RetirementBundleFileIdentity<'a>>,
            related_updates: &'a [RelatedUpdateEvidence],
            source_role_policy_evidence_ids: &'a [String],
        }

        #[derive(Serialize)]
        struct RetirementBundleFileIdentity<'a> {
            operation: RetirementBundleOperation,
            file: &'a str,
            expected_base_source_hash: Option<&'a String>,
            nonexistence_evidence: Option<&'a String>,
            proposed_source_hash: Option<&'a String>,
            source_role_policy_evidence_ids: &'a [String],
        }

        let files = self
            .files
            .iter()
            .map(|file| RetirementBundleFileIdentity {
                operation: file.operation,
                file: file.file.as_str(),
                expected_base_source_hash: file.expected_base_source_hash.as_ref(),
                nonexistence_evidence: file.nonexistence_evidence.as_ref(),
                proposed_source_hash: file.proposed_source_hash.as_ref(),
                source_role_policy_evidence_ids: &file.source_role_policy_evidence_ids,
            })
            .collect::<Vec<_>>();
        let identity = BundleIdentity {
            schema: "repotoire.retirement_bundle.identity.v1",
            intent: &self.intent,
            files,
            related_updates: &self.related_updates,
            source_role_policy_evidence_ids: &self.source_role_policy_evidence_ids,
        };
        let bytes = serde_json::to_vec(&identity)
            .expect("retirement bundle identity should serialize without failure");
        format!("retirement_bundle:{}", crate::hash::sha256_hex(&bytes))
    }
}

fn retirement_bundle_file_cmp(
    left: &RetirementBundleFile,
    right: &RetirementBundleFile,
) -> std::cmp::Ordering {
    left.operation
        .cmp(&right.operation)
        .then_with(|| left.file.cmp(&right.file))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetirementBundleOperation {
    Create,
    Replace,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementBundleFile {
    pub operation: RetirementBundleOperation,
    pub file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_base_source_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonexistence_evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_source_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_bytes: Option<Vec<u8>>,
    #[serde(default)]
    pub source_role_policy_evidence_ids: Vec<String>,
}

impl RetirementBundleFile {
    pub fn create(
        file: impl Into<String>,
        nonexistence_evidence: impl Into<String>,
        proposed_bytes: Vec<u8>,
    ) -> Self {
        Self::new(
            RetirementBundleOperation::Create,
            file,
            None,
            Some(nonexistence_evidence.into()),
            Some(proposed_bytes),
        )
    }

    pub fn replace(
        file: impl Into<String>,
        expected_base_source_hash: impl Into<String>,
        proposed_bytes: Vec<u8>,
    ) -> Self {
        Self::new(
            RetirementBundleOperation::Replace,
            file,
            Some(expected_base_source_hash.into()),
            None,
            Some(proposed_bytes),
        )
    }

    pub fn delete(file: impl Into<String>, expected_base_source_hash: impl Into<String>) -> Self {
        Self::new(
            RetirementBundleOperation::Delete,
            file,
            Some(expected_base_source_hash.into()),
            None,
            None,
        )
    }

    pub fn with_source_role_policy_evidence_id(mut self, evidence_id: impl Into<String>) -> Self {
        self.source_role_policy_evidence_ids
            .push(evidence_id.into());
        self.source_role_policy_evidence_ids.sort();
        self.source_role_policy_evidence_ids.dedup();
        self
    }

    fn new(
        operation: RetirementBundleOperation,
        file: impl Into<String>,
        expected_base_source_hash: Option<String>,
        nonexistence_evidence: Option<String>,
        proposed_bytes: Option<Vec<u8>>,
    ) -> Self {
        let proposed_source_hash = proposed_bytes.as_ref().map(|bytes| source_hash(bytes));
        Self {
            operation,
            file: file.into(),
            expected_base_source_hash,
            nonexistence_evidence,
            proposed_source_hash,
            proposed_bytes,
            source_role_policy_evidence_ids: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SourceWriteback {
    engine: WritebackEngine,
}

impl SourceWriteback {
    pub fn new(world: PipelineWorld) -> Self {
        Self {
            engine: WritebackEngine::new(world),
        }
    }

    pub fn with_active_intent(mut self, intent: PatchIntent) -> Self {
        self.engine = self.engine.with_active_intent(intent);
        self
    }

    pub fn with_active_intents(mut self, intents: impl IntoIterator<Item = PatchIntent>) -> Self {
        self.engine = self.engine.with_active_intents(intents);
        self
    }

    pub fn with_prefetched_evidence(mut self, evidence: PrefetchedEvidence) -> Self {
        self.engine = self.engine.with_prefetched_evidence(evidence);
        self
    }

    pub fn with_prefetched_evidence_items(
        mut self,
        evidence: impl IntoIterator<Item = PrefetchedEvidence>,
    ) -> Self {
        self.engine = self.engine.with_prefetched_evidence_items(evidence);
        self
    }

    pub fn check_intent(
        &self,
        request: SourceWritebackCheckRequest,
    ) -> SourceWritebackCheckOutcome {
        let mut stalls = HazardDetector::check_patch_intent(
            &request.intent,
            &self.engine.world,
            &self.engine.active_intents,
        );
        stalls.extend(HazardDetector::check_war(
            &request.intent,
            &self.engine.prefetched_evidence,
        ));
        SourceWritebackCheckOutcome {
            stalls: dedup_stalls(stalls),
        }
    }

    pub fn apply(&mut self, request: SourceWritebackApplyRequest) -> SourceWritebackApplyOutcome {
        match self.engine.apply(request.intent, request.application) {
            Ok(evidence) => SourceWritebackApplyOutcome {
                evidence: Some(evidence),
                stalls: Vec::new(),
            },
            Err(stalls) => SourceWritebackApplyOutcome {
                evidence: None,
                stalls,
            },
        }
    }

    pub fn preview(&self, request: SourceWritebackPreviewRequest) -> SourceWritebackPreviewOutcome {
        let bundle = request.bundle;
        let mut stalls = HazardDetector::check_patch_intent(
            &bundle.intent,
            &self.engine.world,
            &self.engine.active_intents,
        );
        stalls.extend(HazardDetector::check_war(
            &bundle.intent,
            &self.engine.prefetched_evidence,
        ));
        stalls.extend(check_claim_parseability(&bundle.intent));
        stalls.extend(check_retirement_bundle_shape(&bundle));
        for file in &bundle.files {
            stalls.extend(check_retirement_bundle_file(
                &bundle.intent,
                &self.engine.world,
                file,
            ));
            stalls.extend(check_related_updates_for_file(
                &bundle.intent,
                &self.engine.world,
                &file.file,
                &bundle.related_updates,
            ));
        }
        stalls.extend(check_required_gates(
            &bundle.intent,
            &bundle.gate_results,
            bundle.intent.touched_addresses.clone(),
        ));
        SourceWritebackPreviewOutcome {
            bundle_id: bundle.bundle_id.clone(),
            side_effect_plan: SourceWritebackSideEffectPlan::planned_for_bundle(&bundle),
            stalls: dedup_stalls(stalls),
        }
    }

    pub fn retire(
        &mut self,
        request: SourceWritebackRetireRequest,
    ) -> SourceWritebackRetireOutcome {
        let bundle = request.bundle;
        let preview = self.preview(SourceWritebackPreviewRequest::new(bundle.clone()));
        if !preview.stalls.is_empty() {
            return SourceWritebackRetireOutcome {
                bundle_id: bundle.bundle_id,
                side_effect_plan: preview.side_effect_plan,
                evidence: None,
                stalls: preview.stalls,
                retirement_fault: None,
            };
        }
        let bundle_id = bundle.bundle_id.clone();
        let evidence = self.apply_retirement_bundle(bundle);
        SourceWritebackRetireOutcome {
            bundle_id,
            side_effect_plan: preview.side_effect_plan,
            evidence: Some(evidence),
            stalls: Vec::new(),
            retirement_fault: None,
        }
    }

    fn apply_retirement_bundle(&mut self, bundle: RetirementBundle) -> WritebackEvidencePacket {
        let mut redecoded = Vec::new();
        let mut touched_files = Vec::new();
        let gates = bundle
            .gate_results
            .iter()
            .map(|(gate_id, passed)| GateEvidence {
                gate_id: gate_id.clone(),
                passed: *passed,
            })
            .collect();

        for file in bundle.files {
            touched_files.push(file.file.clone());
            match file.operation {
                RetirementBundleOperation::Create | RetirementBundleOperation::Replace => {
                    let bytes = file
                        .proposed_bytes
                        .expect("preview verifies proposed bytes before retirement");
                    let previous = self.engine.world.sources.get(&file.file).cloned();
                    let language = previous
                        .as_ref()
                        .map(|address| address.language)
                        .unwrap_or(SourceLanguage::Unknown);
                    let repo = previous
                        .as_ref()
                        .or_else(|| bundle.intent.touched_addresses.first())
                        .map(|address| address.repo.clone())
                        .unwrap_or_else(|| "repo:unknown".to_string());
                    let new_address = CodeAddress::from_source(
                        CodeAddressInput::new(
                            repo,
                            self.engine.world.current_git_sha.clone(),
                            self.engine.world.worktree_fingerprint.clone(),
                            file.file.clone(),
                            0,
                            bytes.len() as u32,
                            language,
                        ),
                        &bytes,
                    );
                    self.engine
                        .world
                        .sources
                        .insert(file.file.clone(), new_address.clone());
                    redecoded.push(DecodeTape::decode(new_address, &bytes, Vec::new()));
                }
                RetirementBundleOperation::Delete => {
                    self.engine.world.sources.remove(&file.file);
                }
            }
        }
        self.engine.world.worktree_fingerprint = fingerprint_world(&self.engine.world);
        touched_files.sort();
        touched_files.dedup();

        WritebackEvidencePacket {
            schema: WRITEBACK_EVIDENCE_SCHEMA.to_string(),
            agent_id: bundle.intent.agent_id,
            base_git_sha: bundle.intent.base_git_sha,
            final_worktree_fingerprint: self.engine.world.worktree_fingerprint.clone(),
            redecoded,
            reparse: ReparseEvidence { performed: true },
            graph_delta: GraphDeltaEvidence {
                changed_nodes: touched_files.len() as u32,
                touched_files,
            },
            gates,
            related_updates: bundle.related_updates,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWritebackCheckRequest {
    pub intent: PatchIntent,
}

impl SourceWritebackCheckRequest {
    pub fn new(intent: PatchIntent) -> Self {
        Self { intent }
    }
}

impl From<PatchIntent> for SourceWritebackCheckRequest {
    fn from(intent: PatchIntent) -> Self {
        Self::new(intent)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWritebackCheckOutcome {
    pub stalls: Vec<PipelineStall>,
}

impl SourceWritebackCheckOutcome {
    pub fn is_ready(&self) -> bool {
        self.stalls.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWritebackApplyRequest {
    pub intent: PatchIntent,
    pub application: PatchApplication,
}

impl SourceWritebackApplyRequest {
    pub fn new(intent: PatchIntent, application: PatchApplication) -> Self {
        Self {
            intent,
            application,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWritebackApplyOutcome {
    pub evidence: Option<WritebackEvidencePacket>,
    pub stalls: Vec<PipelineStall>,
}

impl SourceWritebackApplyOutcome {
    pub fn is_applied(&self) -> bool {
        self.evidence.is_some()
    }

    pub fn into_result(self) -> Result<WritebackEvidencePacket, Vec<PipelineStall>> {
        match self.evidence {
            Some(evidence) => Ok(evidence),
            None => Err(self.stalls),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWritebackPreviewRequest {
    pub bundle: RetirementBundle,
}

impl SourceWritebackPreviewRequest {
    pub fn new(bundle: RetirementBundle) -> Self {
        Self { bundle }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWritebackPreviewOutcome {
    pub bundle_id: String,
    pub stalls: Vec<PipelineStall>,
    pub side_effect_plan: SourceWritebackSideEffectPlan,
}

impl SourceWritebackPreviewOutcome {
    pub fn is_ready(&self) -> bool {
        self.stalls.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWritebackRetireRequest {
    pub bundle: RetirementBundle,
}

impl SourceWritebackRetireRequest {
    pub fn new(bundle: RetirementBundle) -> Self {
        Self { bundle }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWritebackRetireOutcome {
    pub bundle_id: String,
    pub side_effect_plan: SourceWritebackSideEffectPlan,
    pub evidence: Option<WritebackEvidencePacket>,
    pub stalls: Vec<PipelineStall>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retirement_fault: Option<SourceWritebackRetirementFault>,
}

impl SourceWritebackRetireOutcome {
    pub fn is_retired(&self) -> bool {
        self.evidence.is_some() && self.retirement_fault.is_none()
    }

    pub fn into_result(self) -> Result<WritebackEvidencePacket, Vec<PipelineStall>> {
        if self.retirement_fault.is_some() {
            return Err(self.stalls);
        }
        match self.evidence {
            Some(evidence) => Ok(evidence),
            None => Err(self.stalls),
        }
    }
}

pub const SOURCE_WRITEBACK_PROCESSOR_VERDICT_SCHEMA: &str =
    "repotoire.source_writeback.processor_verdict.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWritebackProcessorVerdict {
    pub schema: String,
    pub operation: String,
    pub bundle_id: String,
    pub processor_class: SourceWritebackProcessorClass,
    pub status: String,
    pub reasons: Vec<SourceWritebackProcessorReason>,
    pub next_actions: Vec<SourceWritebackProcessorAction>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceWritebackProcessorClass {
    Ready,
    Stall,
    Blocker,
    Fault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceWritebackProcessorReasonKind {
    SourceEvidenceBlocker,
    ProcessorHazard,
    TrustBlocker,
    SideEffectFault,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWritebackProcessorReason {
    pub reason_id: String,
    pub kind: SourceWritebackProcessorReasonKind,
    pub code: String,
    pub severity: String,
    pub message: String,
    pub evidence_ids: Vec<String>,
    pub resumable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWritebackProcessorAction {
    pub action_id: String,
    pub kind: String,
    pub processor_class: SourceWritebackProcessorClass,
    pub priority: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_effect_id: Option<String>,
    pub evidence_ids: Vec<String>,
    pub replay_safe: bool,
    pub requires_authorization: bool,
    pub reason: String,
}

impl SourceWritebackProcessorVerdict {
    pub fn from_parts(
        operation: impl Into<String>,
        bundle_id: impl Into<String>,
        ready: bool,
        stalls: &[PipelineStall],
        retirement_fault: Option<&SourceWritebackRetirementFault>,
        mut external_reasons: Vec<SourceWritebackProcessorReason>,
        mut external_next_actions: Vec<SourceWritebackProcessorAction>,
    ) -> Self {
        let operation = operation.into();
        let bundle_id = bundle_id.into();
        let mut reasons = stalls
            .iter()
            .map(source_writeback_processor_reason_for_stall)
            .collect::<Vec<_>>();
        reasons.append(&mut external_reasons);
        let mut next_actions = stalls
            .iter()
            .map(source_writeback_processor_action_for_stall)
            .collect::<Vec<_>>();
        next_actions.append(&mut external_next_actions);

        if let Some(fault) = retirement_fault {
            reasons.push(source_writeback_processor_reason_for_fault(fault));
            next_actions.extend(
                fault
                    .next_actions
                    .iter()
                    .map(|action| source_writeback_processor_action_for_fault(action, fault)),
            );
        }

        dedup_processor_reasons(&mut reasons);
        dedup_processor_actions(&mut next_actions);
        let processor_class =
            source_writeback_processor_class(ready, retirement_fault.is_some(), &reasons);
        let status = match processor_class {
            SourceWritebackProcessorClass::Ready => "ready",
            SourceWritebackProcessorClass::Stall => "stalled",
            SourceWritebackProcessorClass::Blocker => "blocked",
            SourceWritebackProcessorClass::Fault => "faulted",
        }
        .to_string();

        Self {
            schema: SOURCE_WRITEBACK_PROCESSOR_VERDICT_SCHEMA.to_string(),
            operation,
            bundle_id,
            processor_class,
            status,
            reasons,
            next_actions,
            limitations: vec![
                "The processor verdict classifies Source Writeback readiness; adapter IO may still fault after authorization."
                    .to_string(),
                "A fault recovery action repairs or completes side effects and does not imply semantic rollback."
                    .to_string(),
            ],
        }
    }
}

fn source_writeback_processor_class(
    ready: bool,
    faulted: bool,
    reasons: &[SourceWritebackProcessorReason],
) -> SourceWritebackProcessorClass {
    if faulted
        || reasons
            .iter()
            .any(|reason| reason.kind == SourceWritebackProcessorReasonKind::SideEffectFault)
    {
        return SourceWritebackProcessorClass::Fault;
    }
    if reasons
        .iter()
        .any(|reason| reason.kind != SourceWritebackProcessorReasonKind::ProcessorHazard)
    {
        return SourceWritebackProcessorClass::Blocker;
    }
    if !reasons.is_empty() {
        return SourceWritebackProcessorClass::Stall;
    }
    if ready {
        SourceWritebackProcessorClass::Ready
    } else {
        SourceWritebackProcessorClass::Blocker
    }
}

fn source_writeback_processor_reason_for_stall(
    stall: &PipelineStall,
) -> SourceWritebackProcessorReason {
    let code = source_writeback_stall_reason_code_label(stall.reason_code).to_string();
    let kind = source_writeback_processor_reason_kind_for_stall(stall.reason_code);
    SourceWritebackProcessorReason {
        reason_id: format!("reason:source_writeback:{code}"),
        kind,
        code,
        severity: match kind {
            SourceWritebackProcessorReasonKind::ProcessorHazard => "medium",
            SourceWritebackProcessorReasonKind::SourceEvidenceBlocker
            | SourceWritebackProcessorReasonKind::TrustBlocker
            | SourceWritebackProcessorReasonKind::SideEffectFault => "high",
        }
        .to_string(),
        message: match kind {
            SourceWritebackProcessorReasonKind::ProcessorHazard => {
                "Machine must resolve the processor hazard before retiring this scoped edit."
            }
            SourceWritebackProcessorReasonKind::SourceEvidenceBlocker => {
                "Refresh, materialize, or reprove source evidence before retiring this scoped edit."
            }
            SourceWritebackProcessorReasonKind::TrustBlocker => {
                "Refresh trust or federation proof evidence before retirement."
            }
            SourceWritebackProcessorReasonKind::SideEffectFault => {
                "Recover Source Writeback side effects before declaring this scoped edit retired."
            }
        }
        .to_string(),
        evidence_ids: stall.blocking_evidence.clone(),
        resumable: stall.resumable,
    }
}

fn source_writeback_processor_action_for_stall(
    stall: &PipelineStall,
) -> SourceWritebackProcessorAction {
    let code = source_writeback_stall_reason_code_label(stall.reason_code).to_string();
    let kind = source_writeback_processor_reason_kind_for_stall(stall.reason_code);
    SourceWritebackProcessorAction {
        action_id: format!("action:source_writeback:{code}"),
        kind: match kind {
            SourceWritebackProcessorReasonKind::ProcessorHazard => "resolve_processor_hazard",
            SourceWritebackProcessorReasonKind::SourceEvidenceBlocker => "refresh_source_evidence",
            SourceWritebackProcessorReasonKind::TrustBlocker => "refresh_trust_evidence",
            SourceWritebackProcessorReasonKind::SideEffectFault => {
                "recover_retirement_side_effects"
            }
        }
        .to_string(),
        processor_class: match kind {
            SourceWritebackProcessorReasonKind::ProcessorHazard => {
                SourceWritebackProcessorClass::Stall
            }
            SourceWritebackProcessorReasonKind::SourceEvidenceBlocker
            | SourceWritebackProcessorReasonKind::TrustBlocker => {
                SourceWritebackProcessorClass::Blocker
            }
            SourceWritebackProcessorReasonKind::SideEffectFault => {
                SourceWritebackProcessorClass::Fault
            }
        },
        priority: match kind {
            SourceWritebackProcessorReasonKind::ProcessorHazard => "medium",
            SourceWritebackProcessorReasonKind::SourceEvidenceBlocker
            | SourceWritebackProcessorReasonKind::TrustBlocker
            | SourceWritebackProcessorReasonKind::SideEffectFault => "high",
        }
        .to_string(),
        target_effect_id: None,
        evidence_ids: stall.blocking_evidence.clone(),
        replay_safe: false,
        requires_authorization: true,
        reason: stall.next_action.clone(),
    }
}

fn source_writeback_processor_reason_kind_for_stall(
    reason_code: StallReasonCode,
) -> SourceWritebackProcessorReasonKind {
    match reason_code {
        StallReasonCode::WawWriteConflict | StallReasonCode::WarPrefetchInvalidation => {
            SourceWritebackProcessorReasonKind::ProcessorHazard
        }
        StallReasonCode::RawStaleSource
        | StallReasonCode::SpanDrift
        | StallReasonCode::UnclaimedWriteScope
        | StallReasonCode::UnparseableWriteScope
        | StallReasonCode::VerificationEvidenceUnavailable
        | StallReasonCode::VerificationEvidenceFailed
        | StallReasonCode::MissingIntentReceipt
        | StallReasonCode::StaleIntentReceipt
        | StallReasonCode::StaleGraphEpoch
        | StallReasonCode::GraphInputUnavailable
        | StallReasonCode::StaleDecodeEpoch
        | StallReasonCode::StaleTruthEpoch
        | StallReasonCode::StaleCapabilityEpoch
        | StallReasonCode::StaleVerificationEpoch
        | StallReasonCode::GateFailed
        | StallReasonCode::StaleDocs
        | StallReasonCode::ContradictedDocs
        | StallReasonCode::StaleRepoSnapshot
        | StallReasonCode::UnverifiedExternalLink
        | StallReasonCode::ManifestDrift
        | StallReasonCode::VersionMismatch
        | StallReasonCode::PrecisionWritebackBlocked => {
            SourceWritebackProcessorReasonKind::SourceEvidenceBlocker
        }
    }
}

fn source_writeback_stall_reason_code_label(reason_code: StallReasonCode) -> &'static str {
    match reason_code {
        StallReasonCode::RawStaleSource => "raw_stale_source",
        StallReasonCode::WawWriteConflict => "waw_write_conflict",
        StallReasonCode::WarPrefetchInvalidation => "war_prefetch_invalidation",
        StallReasonCode::SpanDrift => "span_drift",
        StallReasonCode::UnclaimedWriteScope => "unclaimed_write_scope",
        StallReasonCode::UnparseableWriteScope => "unparseable_write_scope",
        StallReasonCode::VerificationEvidenceUnavailable => "verification_evidence_unavailable",
        StallReasonCode::VerificationEvidenceFailed => "verification_evidence_failed",
        StallReasonCode::MissingIntentReceipt => "missing_intent_receipt",
        StallReasonCode::StaleIntentReceipt => "stale_intent_receipt",
        StallReasonCode::StaleGraphEpoch => "stale_graph_epoch",
        StallReasonCode::GraphInputUnavailable => "graph_input_unavailable",
        StallReasonCode::StaleDecodeEpoch => "stale_decode_epoch",
        StallReasonCode::StaleTruthEpoch => "stale_truth_epoch",
        StallReasonCode::StaleCapabilityEpoch => "stale_capability_epoch",
        StallReasonCode::StaleVerificationEpoch => "stale_verification_epoch",
        StallReasonCode::GateFailed => "gate_failed",
        StallReasonCode::StaleDocs => "stale_docs",
        StallReasonCode::ContradictedDocs => "contradicted_docs",
        StallReasonCode::StaleRepoSnapshot => "stale_repo_snapshot",
        StallReasonCode::UnverifiedExternalLink => "unverified_external_link",
        StallReasonCode::ManifestDrift => "manifest_drift",
        StallReasonCode::VersionMismatch => "version_mismatch",
        StallReasonCode::PrecisionWritebackBlocked => "precision_writeback_blocked",
    }
}

fn source_writeback_processor_reason_for_fault(
    fault: &SourceWritebackRetirementFault,
) -> SourceWritebackProcessorReason {
    SourceWritebackProcessorReason {
        reason_id: format!("reason:source_writeback:fault:{}", fault.reason_code),
        kind: SourceWritebackProcessorReasonKind::SideEffectFault,
        code: fault.reason_code.clone(),
        severity: fault.severity.clone(),
        message: fault.message.clone(),
        evidence_ids: std::iter::once(fault.faulted_effect_id.clone())
            .chain(fault.executed_effect_ids.iter().cloned())
            .chain(fault.pending_effect_ids.iter().cloned())
            .collect(),
        resumable: fault.repair_allowed,
    }
}

fn source_writeback_processor_action_for_fault(
    action: &SourceWritebackFaultAction,
    fault: &SourceWritebackRetirementFault,
) -> SourceWritebackProcessorAction {
    SourceWritebackProcessorAction {
        action_id: action.action_id.clone(),
        kind: action.kind.clone(),
        processor_class: SourceWritebackProcessorClass::Fault,
        priority: "high".to_string(),
        target_effect_id: Some(action.effect_id.clone()),
        evidence_ids: vec![fault.faulted_effect_id.clone()],
        replay_safe: action.replay_safe,
        requires_authorization: action.requires_authorization,
        reason: action.reason.clone(),
    }
}

fn dedup_processor_reasons(reasons: &mut Vec<SourceWritebackProcessorReason>) {
    let mut seen = BTreeSet::new();
    reasons.retain(|reason| seen.insert(reason.reason_id.clone()));
}

fn dedup_processor_actions(actions: &mut Vec<SourceWritebackProcessorAction>) {
    let mut seen = BTreeSet::new();
    actions.retain(|action| seen.insert(action.action_id.clone()));
}

pub const SOURCE_WRITEBACK_RETIREMENT_FAULT_SCHEMA: &str =
    "repotoire.source_writeback.retirement_fault.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWritebackRetirementFault {
    pub schema: String,
    pub status: String,
    pub bundle_id: String,
    pub reason_code: String,
    pub severity: String,
    pub repair_class: String,
    pub execution_allowed: bool,
    pub repair_allowed: bool,
    pub message: String,
    pub faulted_effect_id: String,
    pub faulted_effect_kind: SourceWritebackSideEffectKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub executed_effect_ids: Vec<String>,
    pub pending_effect_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery_refs: Vec<SourceWritebackRecoveryRef>,
    pub replay_safe: bool,
    pub retry_allowed: bool,
    pub next_actions: Vec<SourceWritebackFaultAction>,
}

impl SourceWritebackRetirementFault {
    fn from_effect(
        bundle_id: &str,
        faulted_effect: SourceWritebackSideEffect,
        reason_code: String,
        message: String,
        executed_effect_ids: Vec<String>,
        pending_effect_ids: Vec<String>,
    ) -> Self {
        let retry_allowed = faulted_effect.replay_safe;
        let mut next_actions = vec![SourceWritebackFaultAction {
            action_id: format!(
                "action:source_writeback:recover:{}",
                faulted_effect.effect_id
            ),
            kind: "recover_retirement_side_effects".to_string(),
            effect_id: faulted_effect.effect_id.clone(),
            replay_safe: false,
            requires_authorization: true,
            reason: "Inspect executed and pending side effects before declaring the scoped edit retired."
                .to_string(),
        }];
        if retry_allowed {
            next_actions.push(SourceWritebackFaultAction {
                action_id: format!("action:source_writeback:retry:{}", faulted_effect.effect_id),
                kind: "retry_faulted_side_effect".to_string(),
                effect_id: faulted_effect.effect_id.clone(),
                replay_safe: true,
                requires_authorization: true,
                reason: "The faulted effect is marked replay-safe by the side-effect plan."
                    .to_string(),
            });
        }

        Self {
            schema: SOURCE_WRITEBACK_RETIREMENT_FAULT_SCHEMA.to_string(),
            status: "faulted".to_string(),
            bundle_id: bundle_id.to_string(),
            reason_code,
            severity: "high".to_string(),
            repair_class: "side_effect_recovery".to_string(),
            execution_allowed: false,
            repair_allowed: true,
            message,
            faulted_effect_id: faulted_effect.effect_id,
            faulted_effect_kind: faulted_effect.kind,
            file: faulted_effect.file,
            executed_effect_ids,
            pending_effect_ids,
            recovery_refs: faulted_effect.recovery_refs,
            replay_safe: faulted_effect.replay_safe,
            retry_allowed,
            next_actions,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWritebackFaultAction {
    pub action_id: String,
    pub kind: String,
    pub effect_id: String,
    pub replay_safe: bool,
    pub requires_authorization: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWritebackSideEffectPlan {
    pub effects: Vec<SourceWritebackSideEffect>,
}

impl SourceWritebackSideEffectPlan {
    fn planned_for_bundle(bundle: &RetirementBundle) -> Self {
        let federation_effect_id = effect_id(
            SourceWritebackSideEffectKind::FederationInvalidation,
            None,
            &bundle.bundle_id,
        );
        let receipt_effect_id = effect_id(
            SourceWritebackSideEffectKind::ReceiptWrite,
            None,
            &bundle.bundle_id,
        );
        let evidence_effect_id = effect_id(
            SourceWritebackSideEffectKind::EvidencePersist,
            None,
            &bundle.bundle_id,
        );
        let mut effects = vec![SourceWritebackSideEffect::new(
            federation_effect_id.clone(),
            SourceWritebackSideEffectKind::FederationInvalidation,
            None,
        )];
        effects.push(
            SourceWritebackSideEffect::new(
                receipt_effect_id.clone(),
                SourceWritebackSideEffectKind::ReceiptWrite,
                None,
            )
            .with_dependencies(vec![federation_effect_id.clone()]),
        );
        let mut planned_directories = BTreeSet::new();
        let mut terminal_dependencies =
            vec![federation_effect_id.clone(), receipt_effect_id.clone()];

        for file in &bundle.files {
            let mut dependencies = vec![federation_effect_id.clone()];
            if let Some(parent) = source_parent_directory(&file.file) {
                let directory_effect_id = effect_id(
                    SourceWritebackSideEffectKind::DirectoryCreate,
                    Some(&parent),
                    &bundle.bundle_id,
                );
                if planned_directories.insert(parent.clone()) {
                    effects.push(
                        SourceWritebackSideEffect::new(
                            directory_effect_id.clone(),
                            SourceWritebackSideEffectKind::DirectoryCreate,
                            Some(parent),
                        )
                        .with_replay_safe(true)
                        .with_dependencies(vec![federation_effect_id.clone()]),
                    );
                }
                dependencies.push(directory_effect_id);
            }

            let kind = match file.operation {
                RetirementBundleOperation::Create | RetirementBundleOperation::Replace => {
                    SourceWritebackSideEffectKind::FileWrite
                }
                RetirementBundleOperation::Delete => SourceWritebackSideEffectKind::FileDelete,
            };
            let file_effect_id = effect_id(kind, Some(&file.file), &bundle.bundle_id);
            effects.push(
                SourceWritebackSideEffect::new(
                    file_effect_id.clone(),
                    kind,
                    Some(file.file.clone()),
                )
                .with_dependencies(dependencies)
                .with_file_identity(file),
            );
            terminal_dependencies.push(file_effect_id.clone());

            // Every mutation needs applied evidence, including deletion.
            let ledger_effect_id = effect_id(
                SourceWritebackSideEffectKind::LedgerAppend,
                Some(&file.file),
                &bundle.bundle_id,
            );
            effects.push(
                SourceWritebackSideEffect::new(
                    ledger_effect_id.clone(),
                    SourceWritebackSideEffectKind::LedgerAppend,
                    Some(file.file.clone()),
                )
                .with_dependencies(vec![receipt_effect_id.clone(), file_effect_id])
                .with_file_identity(file),
            );
            terminal_dependencies.push(ledger_effect_id);
        }

        terminal_dependencies.sort();
        terminal_dependencies.dedup();
        effects.push(
            SourceWritebackSideEffect::new(
                evidence_effect_id,
                SourceWritebackSideEffectKind::EvidencePersist,
                None,
            )
            .with_dependencies(terminal_dependencies),
        );
        Self { effects }
    }

    pub fn mark_executed(
        &mut self,
        kind: SourceWritebackSideEffectKind,
        file: Option<&str>,
    ) -> bool {
        let mut marked = false;
        for effect in &mut self.effects {
            if effect.kind == kind && effect.file.as_deref() == file {
                effect.status = SourceWritebackEffectStatus::Executed;
                marked = true;
            }
        }
        marked
    }

    pub fn mark_effect_executed(&mut self, effect_id: &str) -> bool {
        if let Some(effect) = self
            .effects
            .iter_mut()
            .find(|effect| effect.effect_id == effect_id)
        {
            effect.status = SourceWritebackEffectStatus::Executed;
            return true;
        }
        false
    }

    pub fn mark_effect_faulted(
        &mut self,
        bundle_id: &str,
        effect_id: &str,
        reason_code: impl Into<String>,
        message: impl Into<String>,
    ) -> Option<SourceWritebackRetirementFault> {
        let fault_index = self
            .effects
            .iter()
            .position(|effect| effect.effect_id == effect_id)?;
        for (index, effect) in self.effects.iter_mut().enumerate() {
            if index == fault_index {
                effect.status = SourceWritebackEffectStatus::Faulted;
            } else if index > fault_index && effect.status == SourceWritebackEffectStatus::Planned {
                effect.status = SourceWritebackEffectStatus::Pending;
            }
        }
        let faulted_effect = self.effects[fault_index].clone();
        let executed_effect_ids = self
            .effects
            .iter()
            .filter(|effect| effect.status == SourceWritebackEffectStatus::Executed)
            .map(|effect| effect.effect_id.clone())
            .collect();
        let pending_effect_ids = self
            .effects
            .iter()
            .filter(|effect| effect.status == SourceWritebackEffectStatus::Pending)
            .map(|effect| effect.effect_id.clone())
            .collect();
        Some(SourceWritebackRetirementFault::from_effect(
            bundle_id,
            faulted_effect,
            reason_code.into(),
            message.into(),
            executed_effect_ids,
            pending_effect_ids,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWritebackSideEffect {
    pub effect_id: String,
    pub kind: SourceWritebackSideEffectKind,
    pub status: SourceWritebackEffectStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_base_source_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonexistence_evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_source_hash: Option<String>,
    #[serde(default)]
    pub source_role_policy_evidence_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery_refs: Vec<SourceWritebackRecoveryRef>,
    pub replay_safe: bool,
}

impl SourceWritebackSideEffect {
    fn new(
        effect_id: impl Into<String>,
        kind: SourceWritebackSideEffectKind,
        file: Option<String>,
    ) -> Self {
        Self {
            effect_id: effect_id.into(),
            kind,
            status: SourceWritebackEffectStatus::Planned,
            file,
            expected_base_source_hash: None,
            nonexistence_evidence: None,
            proposed_source_hash: None,
            source_role_policy_evidence_ids: Vec::new(),
            depends_on: Vec::new(),
            recovery_refs: Vec::new(),
            replay_safe: false,
        }
    }

    fn with_dependencies(mut self, depends_on: Vec<String>) -> Self {
        self.depends_on = depends_on;
        self.depends_on.sort();
        self.depends_on.dedup();
        self
    }

    fn with_replay_safe(mut self, replay_safe: bool) -> Self {
        self.replay_safe = replay_safe;
        self
    }

    fn with_file_identity(mut self, file: &RetirementBundleFile) -> Self {
        self.expected_base_source_hash = file.expected_base_source_hash.clone();
        self.nonexistence_evidence = file.nonexistence_evidence.clone();
        self.proposed_source_hash = file.proposed_source_hash.clone();
        self.source_role_policy_evidence_ids = file.source_role_policy_evidence_ids.clone();
        self.recovery_refs = source_writeback_recovery_refs(file);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWritebackRecoveryRef {
    pub kind: SourceWritebackRecoveryRefKind,
    pub value: String,
    pub bounded: bool,
    pub replay_safe: bool,
    pub undo_safe: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceWritebackRecoveryRefKind {
    BaseSourceHash,
    ProposedSourceHash,
    NonexistenceEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceWritebackSideEffectKind {
    FileWrite,
    FileDelete,
    DirectoryCreate,
    ReceiptWrite,
    LedgerAppend,
    FederationInvalidation,
    EvidencePersist,
}

impl SourceWritebackSideEffectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FileWrite => "file_write",
            Self::FileDelete => "file_delete",
            Self::DirectoryCreate => "directory_create",
            Self::ReceiptWrite => "receipt_write",
            Self::LedgerAppend => "ledger_append",
            Self::FederationInvalidation => "federation_invalidation",
            Self::EvidencePersist => "evidence_persist",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceWritebackEffectStatus {
    Planned,
    Executed,
    Pending,
    Faulted,
}

fn effect_id(kind: SourceWritebackSideEffectKind, target: Option<&str>, bundle_id: &str) -> String {
    match target {
        Some(target) => format!("effect:{}:{}:{}", kind.as_str(), target, bundle_id),
        None => format!("effect:{}:{}", kind.as_str(), bundle_id),
    }
}

fn source_parent_directory(file: &str) -> Option<String> {
    let parent = std::path::Path::new(file).parent()?;
    let parent = parent.to_string_lossy();
    if parent.is_empty() || parent == "." {
        None
    } else {
        Some(parent.into_owned())
    }
}

fn source_writeback_recovery_refs(file: &RetirementBundleFile) -> Vec<SourceWritebackRecoveryRef> {
    let mut refs = Vec::new();
    if let Some(value) = &file.expected_base_source_hash {
        refs.push(SourceWritebackRecoveryRef {
            kind: SourceWritebackRecoveryRefKind::BaseSourceHash,
            value: value.clone(),
            bounded: true,
            replay_safe: false,
            undo_safe: false,
        });
    }
    if let Some(value) = &file.proposed_source_hash {
        refs.push(SourceWritebackRecoveryRef {
            kind: SourceWritebackRecoveryRefKind::ProposedSourceHash,
            value: value.clone(),
            bounded: true,
            replay_safe: false,
            undo_safe: false,
        });
    }
    if let Some(value) = &file.nonexistence_evidence {
        refs.push(SourceWritebackRecoveryRef {
            kind: SourceWritebackRecoveryRefKind::NonexistenceEvidence,
            value: value.clone(),
            bounded: true,
            replay_safe: false,
            undo_safe: false,
        });
    }
    refs
}

/// VALIDATE-ONCE diagnosis pass (ADR 0007 / Write Scope glossary): an
/// unreadable claim is "a fault to surface, never a claim to silently
/// drop". The claimed-gates (`check_application_scope`,
/// `check_retirement_bundle_file`) already fail closed on a parse error via
/// `claim_grants_path` — that behavior is unchanged. This pass runs
/// alongside them and emits one additive `UnparseableWriteScope` stall per
/// unparseable `claimed_files` entry, naming the offending claim and the
/// parse error so the deny doesn't read as a mute "not covered by
/// claimed_files".
fn check_claim_parseability(intent: &PatchIntent) -> Vec<PipelineStall> {
    intent
        .claimed_files
        .iter()
        .filter_map(|claim| match Scope::parse(claim) {
            Ok(_) => None,
            Err(err) => Some(stall(
                PipelineStage::Writeback,
                StallReasonCode::UnparseableWriteScope,
                vec![format!("claimed_files entry rejected: {err}")],
                intent.touched_addresses.clone(),
                "fix the claimed_files entry so it parses as a valid write scope",
                true,
            )),
        })
        .collect()
}

fn check_application_scope(
    intent: &PatchIntent,
    application: &PatchApplication,
) -> Vec<PipelineStall> {
    let claimed = intent
        .claimed_files
        .iter()
        .any(|claim| claim_grants_path(claim, &application.file));
    let touched = intent
        .touched_addresses
        .iter()
        .any(|address| address.file == application.file);
    let expected_hash = intent
        .expected_source_hashes
        .iter()
        .any(|expected| expected.address.file == application.file);
    if claimed && touched && expected_hash {
        return Vec::new();
    }

    let mut missing = Vec::new();
    if !claimed {
        missing.push("claimed_files");
    }
    if !touched {
        missing.push("touched_addresses");
    }
    if !expected_hash {
        missing.push("expected_source_hashes");
    }

    vec![stall(
        PipelineStage::Writeback,
        StallReasonCode::UnclaimedWriteScope,
        vec![format!(
            "{} is not covered by {}",
            application.file,
            missing.join(", ")
        )],
        intent.touched_addresses.clone(),
        "claim, touch, and source-hash the application file before writeback",
        true,
    )]
}

fn check_retirement_bundle_shape(bundle: &RetirementBundle) -> Vec<PipelineStall> {
    let mut seen = BTreeSet::new();
    let mut stalls = Vec::new();
    for file in &bundle.files {
        if !seen.insert(file.file.clone()) {
            stalls.push(stall(
                PipelineStage::Writeback,
                StallReasonCode::UnclaimedWriteScope,
                vec![format!(
                    "{} appears more than once in retirement bundle {}",
                    file.file, bundle.bundle_id
                )],
                bundle.intent.touched_addresses.clone(),
                "materialize one retirement operation per file before writeback",
                true,
            ));
        }
    }
    stalls
}

fn check_retirement_bundle_file(
    intent: &PatchIntent,
    world: &PipelineWorld,
    file: &RetirementBundleFile,
) -> Vec<PipelineStall> {
    let mut stalls = Vec::new();
    let claimed = intent
        .claimed_files
        .iter()
        .any(|claim| claim_grants_path(claim, &file.file));
    let touched = intent
        .touched_addresses
        .iter()
        .any(|address| address.file == file.file);
    let expected = intent
        .expected_source_hashes
        .iter()
        .find(|expected| expected.address.file == file.file);
    let mut missing = Vec::new();
    if !claimed {
        missing.push("claimed_files");
    }
    match file.operation {
        RetirementBundleOperation::Create => {
            let expected_nonexistence_evidence = source_nonexistence_evidence(
                &intent.base_git_sha,
                &intent.worktree_fingerprint,
                &file.file,
            );
            if file.nonexistence_evidence.as_deref()
                != Some(expected_nonexistence_evidence.as_str())
            {
                missing.push("nonexistence_evidence");
            }
            if file.proposed_bytes.is_none() {
                missing.push("proposed_bytes");
            }
            if world.sources.contains_key(&file.file) {
                stalls.push(stall(
                    PipelineStage::Writeback,
                    StallReasonCode::RawStaleSource,
                    vec![format!(
                        "{} create declared nonexistence but file exists in current world",
                        file.file
                    )],
                    intent.touched_addresses.clone(),
                    "refresh nonexistence evidence before creating file",
                    true,
                ));
            }
        }
        RetirementBundleOperation::Replace => {
            if !touched {
                missing.push("touched_addresses");
            }
            if expected.is_none() {
                missing.push("expected_source_hashes");
            }
            if file
                .expected_base_source_hash
                .as_deref()
                .is_none_or(str::is_empty)
            {
                missing.push("bundle.expected_base_source_hash");
            }
            if file.proposed_bytes.is_none() {
                missing.push("proposed_bytes");
            }
        }
        RetirementBundleOperation::Delete => {
            if !touched {
                missing.push("touched_addresses");
            }
            if expected.is_none() {
                missing.push("expected_source_hashes");
            }
            if file
                .expected_base_source_hash
                .as_deref()
                .is_none_or(str::is_empty)
            {
                missing.push("bundle.expected_base_source_hash");
            }
            if file.proposed_bytes.is_some() {
                missing.push("no_proposed_bytes_for_delete");
            }
        }
    }
    if !missing.is_empty() {
        stalls.push(stall(
            PipelineStage::Writeback,
            StallReasonCode::UnclaimedWriteScope,
            vec![format!(
                "{} is not covered by {}",
                file.file,
                missing.join(", ")
            )],
            intent.touched_addresses.clone(),
            "declare the bundle operation inside the scoped edit write envelope",
            true,
        ));
    }
    if let (Some(expected), Some(bundle_base)) = (expected, file.expected_base_source_hash.as_ref())
    {
        if expected.expected_source_hash != *bundle_base {
            stalls.push(stall(
                PipelineStage::Writeback,
                StallReasonCode::RawStaleSource,
                vec![format!(
                    "{} bundle base {} != intent expected {}",
                    file.file, bundle_base, expected.expected_source_hash
                )],
                vec![expected.address.clone()],
                "materialize the bundle from the same base identity as the intent",
                true,
            ));
        }
    }
    if let (Some(bytes), Some(proposed_hash)) = (
        file.proposed_bytes.as_ref(),
        file.proposed_source_hash.as_ref(),
    ) {
        let actual_hash = source_hash(bytes);
        if actual_hash != *proposed_hash {
            stalls.push(stall(
                PipelineStage::Writeback,
                StallReasonCode::RawStaleSource,
                vec![format!(
                    "{} proposed hash {} != materialized bytes {}",
                    file.file, proposed_hash, actual_hash
                )],
                intent.touched_addresses.clone(),
                "rematerialize proposed file image before writeback",
                true,
            ));
        }
    }
    dedup_stalls(stalls)
}

/// Identity of one absent path observation in the exact source world carried
/// by a checked write intent. This is evidence binding, not ambient authority:
/// Source Writeback still verifies the path is absent immediately before the
/// create side effect.
pub fn source_nonexistence_evidence(
    base_git_sha: &str,
    worktree_fingerprint: &str,
    file: &str,
) -> String {
    let mut bytes =
        Vec::with_capacity(base_git_sha.len() + worktree_fingerprint.len() + file.len() + 3);
    for part in [base_git_sha, worktree_fingerprint, file] {
        bytes.extend_from_slice(part.as_bytes());
        bytes.push(0);
    }
    format!("nonexistence:sha256:{}", crate::hash::sha256_hex(&bytes))
}

fn check_required_gates(
    intent: &PatchIntent,
    gate_results: &BTreeMap<String, bool>,
    affected_addresses: Vec<CodeAddress>,
) -> Vec<PipelineStall> {
    let mut stalls = Vec::new();
    for gate in &intent.required_gates {
        if gate_results.get(gate).copied() != Some(true) {
            stalls.push(stall(
                PipelineStage::Verify,
                StallReasonCode::GateFailed,
                vec![format!("required gate `{gate}` did not pass")],
                affected_addresses.clone(),
                "run required gate and retry writeback with fresh evidence",
                true,
            ));
        }
    }
    stalls
}

fn check_precision_metadata(intent: &PatchIntent) -> Vec<PipelineStall> {
    let Some(precision) = &intent.precision else {
        return Vec::new();
    };
    if precision.is_autonomous_write_ready() {
        return Vec::new();
    }

    let mut blocking_evidence = vec![
        format!("intent_mode={}", precision.intent_mode.as_str()),
        format!(
            "autonomous_write_ready={}",
            precision.autonomous_write_ready
        ),
    ];
    if let Some(profile) = &precision.calibration_profile {
        blocking_evidence.push(format!("calibration_profile={profile}"));
    }
    if !precision.blockers.is_empty() {
        let blockers = precision
            .blockers
            .iter()
            .map(|blocker| blocker.as_str())
            .collect::<Vec<_>>()
            .join(",");
        blocking_evidence.push(format!("precision_blockers={blockers}"));
    }
    if !precision.evidence_tiers.is_empty() {
        let evidence_tiers = precision
            .evidence_tiers
            .iter()
            .map(|(tier, count)| format!("{tier}:{count}"))
            .collect::<Vec<_>>()
            .join(",");
        blocking_evidence.push(format!("evidence_tiers={evidence_tiers}"));
    }

    vec![stall(
        PipelineStage::Writeback,
        StallReasonCode::PrecisionWritebackBlocked,
        blocking_evidence,
        intent.touched_addresses.clone(),
        "return a preview or refresh calibrated semantic evidence before autonomous writeback",
        true,
    )]
}

fn check_docs_code_evidence(intent: &PatchIntent, world: &PipelineWorld) -> Vec<PipelineStall> {
    let mut stalls = Vec::new();
    for evidence in &world.docs_code_evidence {
        if evidence.status == DocsCodeEvidenceStatus::Verified
            || !intent_affects_docs_code_evidence(intent, evidence)
            || intent
                .docs_code_evidence
                .iter()
                .any(|candidate| docs_code_evidence_matches(candidate, evidence))
        {
            continue;
        }
        let reason_code = docs_code_reason_code(evidence.status);
        stalls.push(stall(
            PipelineStage::Hazard,
            reason_code,
            vec![
                evidence.evidence_id.clone(),
                format!(
                    "{} linked to {}#{} has {:?} docs/code evidence at {}",
                    evidence.doc_file,
                    evidence.code_file,
                    evidence.symbol,
                    evidence.status,
                    evidence.evidence_epoch
                ),
            ],
            addresses_for_file(world, &evidence.code_file, intent),
            docs_code_next_action(evidence.status),
            true,
        ));
    }
    dedup_stalls(stalls)
}

fn check_federation_evidence(intent: &PatchIntent, world: &PipelineWorld) -> Vec<PipelineStall> {
    let mut stalls = Vec::new();
    for evidence in &world.federation_evidence {
        if evidence.status == FederationContractStatus::Verified
            || !intent_affects_federation_evidence(intent, evidence)
            || intent
                .federation_evidence
                .iter()
                .any(|candidate| federation_evidence_matches(candidate, evidence))
        {
            continue;
        }
        let reason_code = federation_reason_code(evidence.status);
        stalls.push(stall(
            PipelineStage::Hazard,
            reason_code,
            vec![
                evidence.evidence_id.clone(),
                format!(
                    "{} linked to package {} has {:?} federation evidence at {}",
                    evidence.source_file,
                    evidence.package_name,
                    evidence.status,
                    evidence.evidence_epoch
                ),
            ],
            addresses_for_file(world, &evidence.source_file, intent),
            federation_next_action(evidence.status),
            true,
        ));
    }
    dedup_stalls(stalls)
}

fn check_related_updates(
    intent: &PatchIntent,
    world: &PipelineWorld,
    application: &PatchApplication,
) -> Vec<PipelineStall> {
    let mut stalls = Vec::new();
    for evidence in &world.docs_code_evidence {
        if evidence.status == DocsCodeEvidenceStatus::Verified
            || !intent_affects_docs_code_evidence(intent, evidence)
            || !intent
                .docs_code_evidence
                .iter()
                .any(|candidate| docs_code_evidence_matches(candidate, evidence))
            || related_updates_cover(
                &application.related_updates,
                &evidence.evidence_id,
                &evidence.evidence_epoch,
                &docs_code_recovery_actions(evidence.status),
            )
        {
            continue;
        }
        stalls.push(stall(
            PipelineStage::Writeback,
            docs_code_reason_code(evidence.status),
            vec![
                evidence.evidence_id.clone(),
                format!(
                    "writeback for {} must update docs/code evidence for {}#{}",
                    application.file, evidence.doc_file, evidence.symbol
                ),
            ],
            addresses_for_file(world, &evidence.code_file, intent),
            "update affected docs or code, then retry writeback with related update evidence",
            true,
        ));
    }
    for evidence in &world.federation_evidence {
        if evidence.status == FederationContractStatus::Verified
            || !intent_affects_federation_evidence(intent, evidence)
            || !intent
                .federation_evidence
                .iter()
                .any(|candidate| federation_evidence_matches(candidate, evidence))
            || related_updates_cover(
                &application.related_updates,
                &evidence.evidence_id,
                &evidence.evidence_epoch,
                &federation_recovery_actions(evidence.status),
            )
        {
            continue;
        }
        stalls.push(stall(
            PipelineStage::Writeback,
            federation_reason_code(evidence.status),
            vec![
                evidence.evidence_id.clone(),
                format!(
                    "writeback for {} must update federation contract evidence for {}",
                    application.file, evidence.package_name
                ),
            ],
            addresses_for_file(world, &evidence.source_file, intent),
            "update code, manifests, links, or snapshots, then retry writeback with related update evidence",
            true,
        ));
    }
    dedup_stalls(stalls)
}

fn check_related_updates_for_file(
    intent: &PatchIntent,
    world: &PipelineWorld,
    file: &str,
    related_updates: &[RelatedUpdateEvidence],
) -> Vec<PipelineStall> {
    let application = PatchApplication {
        file: file.to_string(),
        bytes: Vec::new(),
        gate_results: BTreeMap::new(),
        related_updates: related_updates.to_vec(),
    };
    check_related_updates(intent, world, &application)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WritebackEvidencePacket {
    pub schema: String,
    pub agent_id: String,
    pub base_git_sha: String,
    pub final_worktree_fingerprint: String,
    pub redecoded: Vec<DecodeTape>,
    pub reparse: ReparseEvidence,
    pub graph_delta: GraphDeltaEvidence,
    pub gates: Vec<GateEvidence>,
    #[serde(default)]
    pub related_updates: Vec<RelatedUpdateEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReparseEvidence {
    pub performed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphDeltaEvidence {
    pub touched_files: Vec<String>,
    pub changed_nodes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateEvidence {
    pub gate_id: String,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotPathCosts {
    pub fetch_entries: usize,
    pub decode_tokens: usize,
    pub cache_lookups: usize,
    pub cache_hits: usize,
    pub cache_hit_rate_basis_points: u32,
    pub justification: String,
}

impl HotPathCosts {
    pub fn measure(
        plan: &FetchPlan,
        tape: &DecodeTape,
        ram: &mut ContextRam,
        lookups: &[CodeAddress],
    ) -> Self {
        let mut cache_hits = 0usize;
        for address in lookups {
            if ram.get(address).is_some() {
                cache_hits += 1;
            }
        }
        let cache_hit_rate_basis_points = if lookups.is_empty() {
            0
        } else {
            ((cache_hits * 10_000) / lookups.len()) as u32
        };
        Self {
            fetch_entries: plan.entries.len(),
            decode_tokens: tape.tokens.len(),
            cache_lookups: lookups.len(),
            cache_hits,
            cache_hit_rate_basis_points,
            justification: format!(
                "FetchPlan sort: O(n log n) over {} candidates; DecodeTape scan: O({}) tokens; ContextRAM lookup: O(log n) over {} lookups (hit_rate_bp={}).",
                plan.entries.len(),
                tape.tokens.len(),
                lookups.len(),
                cache_hit_rate_basis_points
            ),
        }
    }
}

fn fetch_candidate_cmp(a: &FetchCandidate, b: &FetchCandidate) -> std::cmp::Ordering {
    (
        decision_priority(a.decision),
        first_signal_priority(a),
        a.graph_distance,
        std::cmp::Reverse(a.score),
        a.address.file.as_str(),
        a.address.byte_start,
        a.address.byte_end,
        a.address.source_hash.as_str(),
        a.reason.as_str(),
    )
        .cmp(&(
            decision_priority(b.decision),
            first_signal_priority(b),
            b.graph_distance,
            std::cmp::Reverse(b.score),
            b.address.file.as_str(),
            b.address.byte_start,
            b.address.byte_end,
            b.address.source_hash.as_str(),
            b.reason.as_str(),
        ))
}

fn decision_priority(decision: FetchDecision) -> u8 {
    match decision {
        FetchDecision::MustFetch => 0,
        FetchDecision::ShouldFetch => 1,
    }
}

fn first_signal_priority(candidate: &FetchCandidate) -> u8 {
    candidate
        .signals
        .iter()
        .copied()
        .map(signal_priority)
        .min()
        .unwrap_or(99)
}

fn signal_priority(signal: PrefetchSignal) -> u8 {
    match signal {
        PrefetchSignal::Diagnostic => 0,
        PrefetchSignal::Test => 1,
        PrefetchSignal::TruthGap => 2,
        PrefetchSignal::DirtyHunk => 3,
        PrefetchSignal::Caller => 4,
        PrefetchSignal::Callee => 5,
        PrefetchSignal::TypeRef => 6,
        PrefetchSignal::Import => 7,
        PrefetchSignal::Export => 8,
        PrefetchSignal::Docs => 9,
        PrefetchSignal::Declaration => 10,
        PrefetchSignal::GraphDistance => 11,
    }
}

fn signal_bundle_score(signals: &[PrefetchSignal]) -> i32 {
    let mut score = 0i32;
    for signal in signals {
        score = score.saturating_add(signal_weight(*signal));
    }
    if signals.len() > 1 {
        score = score.saturating_add(((signals.len() - 1) as i32).saturating_mul(5));
    }
    score
}

fn signal_weight(signal: PrefetchSignal) -> i32 {
    match signal {
        PrefetchSignal::Diagnostic => 100,
        PrefetchSignal::Test => 90,
        PrefetchSignal::TruthGap => 80,
        PrefetchSignal::DirtyHunk => 75,
        PrefetchSignal::Caller => 65,
        PrefetchSignal::Callee => 60,
        PrefetchSignal::TypeRef => 55,
        PrefetchSignal::Import => 45,
        PrefetchSignal::Export => 40,
        PrefetchSignal::Declaration => 35,
        PrefetchSignal::Docs => 30,
        PrefetchSignal::GraphDistance => 25,
    }
}

fn decode_token(
    address: &CodeAddress,
    source_hash_value: &str,
    start: usize,
    end: usize,
    text: String,
    role: DecodeTokenRole,
    nesting_depth: u32,
) -> DecodeToken {
    let span = Span::new(start as u32, (end - start) as u32);
    let token_hash = source_hash(text.as_bytes());
    let stable_id = source_hash(
        format!(
            "{}\0{}\0{}\0{}\0{}",
            address.canonical_key(),
            start,
            end,
            token_hash,
            role.as_str()
        )
        .as_bytes(),
    );
    DecodeToken {
        stable_id,
        text,
        span,
        role,
        token_hash,
        source_hash: source_hash_value.to_string(),
        nesting_depth,
        confidence: 0.99,
        lineage: vec![address.canonical_key()],
    }
}

fn is_ident_start(b: u8) -> bool {
    b == b'_' || b == b'$' || b.is_ascii_alphabetic()
}

fn is_ident_continue(b: u8) -> bool {
    is_ident_start(b) || b.is_ascii_digit()
}

fn is_keyword(text: &str) -> bool {
    matches!(
        text,
        "as" | "const" | "export" | "from" | "function" | "import" | "let" | "return" | "type"
    )
}

fn push_epoch_stall(
    stalls: &mut Vec<PipelineStall>,
    read_epoch: &str,
    world_epoch: &str,
    reason_code: StallReasonCode,
    addresses: &[CodeAddress],
) {
    if read_epoch != world_epoch {
        stalls.push(stall(
            PipelineStage::Hazard,
            reason_code,
            vec![format!(
                "read epoch `{read_epoch}` != world epoch `{world_epoch}`"
            )],
            addresses.to_vec(),
            "refresh dependent evidence before writeback",
            true,
        ));
    }
}

fn intent_affects_docs_code_evidence(intent: &PatchIntent, evidence: &DocsCodeEvidence) -> bool {
    intent
        .touched_addresses
        .iter()
        .any(|address| address.file == evidence.code_file || address.file == evidence.doc_file)
        || intent.claimed_files.iter().any(|claim| {
            claim_touches_path(claim, &evidence.code_file)
                || claim_touches_path(claim, &evidence.doc_file)
        })
}

fn intent_affects_federation_evidence(
    intent: &PatchIntent,
    evidence: &FederationContractEvidence,
) -> bool {
    intent
        .touched_addresses
        .iter()
        .any(|address| address.file == evidence.source_file)
        || intent
            .claimed_files
            .iter()
            .any(|claim| claim_touches_path(claim, &evidence.source_file))
}

fn docs_code_evidence_matches(candidate: &DocsCodeEvidence, current: &DocsCodeEvidence) -> bool {
    candidate.evidence_id == current.evidence_id
        && candidate.status == current.status
        && candidate.evidence_epoch == current.evidence_epoch
}

fn federation_evidence_matches(
    candidate: &FederationContractEvidence,
    current: &FederationContractEvidence,
) -> bool {
    candidate.evidence_id == current.evidence_id
        && candidate.status == current.status
        && candidate.evidence_epoch == current.evidence_epoch
}

fn docs_code_reason_code(status: DocsCodeEvidenceStatus) -> StallReasonCode {
    match status {
        DocsCodeEvidenceStatus::Verified => StallReasonCode::StaleDocs,
        DocsCodeEvidenceStatus::Stale => StallReasonCode::StaleDocs,
        DocsCodeEvidenceStatus::Contradicted => StallReasonCode::ContradictedDocs,
        DocsCodeEvidenceStatus::Unverified => StallReasonCode::StaleDocs,
    }
}

fn federation_reason_code(status: FederationContractStatus) -> StallReasonCode {
    match status {
        FederationContractStatus::Verified => StallReasonCode::StaleRepoSnapshot,
        FederationContractStatus::StaleRepoSnapshot => StallReasonCode::StaleRepoSnapshot,
        FederationContractStatus::UnverifiedExternalLink => StallReasonCode::UnverifiedExternalLink,
        FederationContractStatus::ManifestDrift => StallReasonCode::ManifestDrift,
        FederationContractStatus::VersionMismatch => StallReasonCode::VersionMismatch,
    }
}

fn docs_code_next_action(status: DocsCodeEvidenceStatus) -> &'static str {
    match status {
        DocsCodeEvidenceStatus::Verified | DocsCodeEvidenceStatus::Stale => {
            "refresh docs truth before writing linked code"
        }
        DocsCodeEvidenceStatus::Contradicted => {
            "update docs or code, then rerun docs truth before writeback"
        }
        DocsCodeEvidenceStatus::Unverified => {
            "rerun truth serum or provide verified docs evidence before writeback"
        }
    }
}

fn federation_next_action(status: FederationContractStatus) -> &'static str {
    match status {
        FederationContractStatus::Verified | FederationContractStatus::StaleRepoSnapshot => {
            "refresh repo snapshot before writing federated code"
        }
        FederationContractStatus::UnverifiedExternalLink => {
            "resolve federated link before writing linked code"
        }
        FederationContractStatus::ManifestDrift => {
            "update manifest evidence or refresh repo snapshot before writeback"
        }
        FederationContractStatus::VersionMismatch => {
            "resolve package version mismatch before writing federated code"
        }
    }
}

fn docs_code_recovery_actions(status: DocsCodeEvidenceStatus) -> Vec<RecoveryAction> {
    match status {
        DocsCodeEvidenceStatus::Verified | DocsCodeEvidenceStatus::Stale => {
            vec![
                RecoveryAction::RefreshDocsTruth,
                RecoveryAction::RerunTruthSerum,
            ]
        }
        DocsCodeEvidenceStatus::Contradicted => vec![
            RecoveryAction::RefreshDocsTruth,
            RecoveryAction::RerunTruthSerum,
            RecoveryAction::UpdateDocs,
            RecoveryAction::UpdateCode,
        ],
        DocsCodeEvidenceStatus::Unverified => vec![
            RecoveryAction::RefreshDocsTruth,
            RecoveryAction::RerunTruthSerum,
            RecoveryAction::UpdateDocs,
        ],
    }
}

fn federation_recovery_actions(status: FederationContractStatus) -> Vec<RecoveryAction> {
    match status {
        FederationContractStatus::Verified | FederationContractStatus::StaleRepoSnapshot => {
            vec![RecoveryAction::RefreshRepoSnapshot]
        }
        FederationContractStatus::UnverifiedExternalLink => vec![
            RecoveryAction::ResolveLink,
            RecoveryAction::RefreshRepoSnapshot,
        ],
        FederationContractStatus::ManifestDrift => vec![
            RecoveryAction::RefreshRepoSnapshot,
            RecoveryAction::UpdateCode,
        ],
        FederationContractStatus::VersionMismatch => vec![
            RecoveryAction::ResolveLink,
            RecoveryAction::UpdateCode,
            RecoveryAction::RefreshRepoSnapshot,
        ],
    }
}

fn recovery_actions_for_reason(reason_code: StallReasonCode) -> Vec<RecoveryAction> {
    match reason_code {
        StallReasonCode::StaleDocs => {
            vec![
                RecoveryAction::RefreshDocsTruth,
                RecoveryAction::RerunTruthSerum,
            ]
        }
        StallReasonCode::ContradictedDocs => vec![
            RecoveryAction::RefreshDocsTruth,
            RecoveryAction::RerunTruthSerum,
            RecoveryAction::UpdateDocs,
            RecoveryAction::UpdateCode,
        ],
        StallReasonCode::StaleRepoSnapshot => vec![RecoveryAction::RefreshRepoSnapshot],
        StallReasonCode::UnverifiedExternalLink => vec![
            RecoveryAction::ResolveLink,
            RecoveryAction::RefreshRepoSnapshot,
        ],
        StallReasonCode::ManifestDrift => vec![
            RecoveryAction::RefreshRepoSnapshot,
            RecoveryAction::UpdateCode,
        ],
        StallReasonCode::VersionMismatch => vec![
            RecoveryAction::ResolveLink,
            RecoveryAction::UpdateCode,
            RecoveryAction::RefreshRepoSnapshot,
        ],
        StallReasonCode::StaleGraphEpoch => vec![RecoveryAction::RerunTruthSerum],
        StallReasonCode::StaleTruthEpoch => vec![RecoveryAction::RerunTruthSerum],
        StallReasonCode::PrecisionWritebackBlocked => vec![RecoveryAction::RerunTruthSerum],
        _ => Vec::new(),
    }
}

fn related_updates_cover(
    updates: &[RelatedUpdateEvidence],
    evidence_id: &str,
    stale_epoch: &str,
    accepted_actions: &[RecoveryAction],
) -> bool {
    updates.iter().any(|update| {
        update.cites(evidence_id)
            && accepted_actions.contains(&update.action)
            // F11 (fail_open): require proof the recovery action actually ran — a freshly
            // produced evidence epoch distinct from the stale one. A self-asserted action with
            // no produced epoch (or one echoing the stale epoch) does not clear the gate.
            && update.proves_rerun(stale_epoch)
    })
}

fn addresses_for_file(world: &PipelineWorld, file: &str, intent: &PatchIntent) -> Vec<CodeAddress> {
    if let Some(address) = world.sources.get(file) {
        return vec![address.clone()];
    }
    let addresses = intent
        .touched_addresses
        .iter()
        .filter(|address| address.file == file)
        .cloned()
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        intent.touched_addresses.clone()
    } else {
        addresses
    }
}

fn stall(
    stage: PipelineStage,
    reason_code: StallReasonCode,
    blocking_evidence: Vec<String>,
    affected_addresses: Vec<CodeAddress>,
    next_action: impl Into<String>,
    resumable: bool,
) -> PipelineStall {
    PipelineStall {
        stage,
        reason_code,
        blocking_evidence,
        affected_addresses,
        next_action: next_action.into(),
        recovery_actions: recovery_actions_for_reason(reason_code),
        resumable,
    }
}

fn dedup_stalls(mut stalls: Vec<PipelineStall>) -> Vec<PipelineStall> {
    stalls.sort_by(|a, b| {
        (
            a.reason_code as u8,
            a.stage as u8,
            a.next_action.as_str(),
            a.blocking_evidence.as_slice(),
        )
            .cmp(&(
                b.reason_code as u8,
                b.stage as u8,
                b.next_action.as_str(),
                b.blocking_evidence.as_slice(),
            ))
    });
    stalls.dedup_by(|a, b| {
        a.stage == b.stage
            && a.reason_code == b.reason_code
            && a.blocking_evidence == b.blocking_evidence
            && a.affected_addresses == b.affected_addresses
    });
    stalls
}

fn sets_intersect(left: &BTreeSet<String>, right: &BTreeSet<String>) -> bool {
    left.iter().any(|value| right.contains(value))
}

/// ADR 0007 / Write Scope contract, hazard direction: may these two CLAIMS
/// touch the same files? `true` is the alarming answer (a WAW conflict
/// stall), so parse failure must alarm — an unreadable claim never
/// masquerades as non-overlapping.
fn claims_overlap(left: &str, right: &str) -> bool {
    match (Scope::parse(left), Scope::parse(right)) {
        (Ok(left), Ok(right)) => left.overlaps(&right),
        _ => true,
    }
}

/// ADR 0007 / Write Scope contract, permissive direction: does `claim` GRANT
/// write authority over the concrete file at `path`? `true` suppresses an
/// UnclaimedWriteScope stall, so parse failure must deny — an unreadable
/// claim never grants permission. The file side is a concrete path, not a
/// claim: it parses via `Scope::from_file_path` (no sentinel or cross-repo
/// vocabulary), and coverage is the algebra's directional `covers`.
fn claim_grants_path(claim: &str, path: &str) -> bool {
    match (Scope::parse(claim), Scope::from_file_path(path)) {
        (Ok(claim), Ok(path)) => claim.covers(&path),
        _ => false,
    }
}

/// ADR 0007 / Write Scope contract, hazard direction: might `claim` TOUCH
/// the concrete file at `path`? `true` marks the intent as affecting
/// dependent evidence (a hazard to re-check), so parse failure must alarm.
/// Same claim-grammar/file-grammar split as `claim_grants_path`.
fn claim_touches_path(claim: &str, path: &str) -> bool {
    match (Scope::parse(claim), Scope::from_file_path(path)) {
        (Ok(claim), Ok(path)) => claim.covers(&path),
        _ => true,
    }
}

fn file_claims_overlap(left: &BTreeSet<String>, right: &BTreeSet<String>) -> bool {
    left.iter()
        .any(|left| right.iter().any(|right| claims_overlap(left, right)))
}

fn bound_docs_code_evidence(
    evidence: Vec<DocsCodeEvidence>,
    budget_bytes: usize,
) -> Vec<DocsCodeEvidence> {
    let mut out = Vec::new();
    let mut used = 0usize;
    for mut item in evidence {
        if let Some(summary) = item.summary.take() {
            item.summary = Some(bound_string(summary, 80));
        }
        if docs_code_evidence_len(std::slice::from_ref(&item)) > budget_bytes {
            item.summary = None;
        }
        if docs_code_evidence_len(std::slice::from_ref(&item)) > budget_bytes {
            item.surface = None;
        }
        let len = docs_code_evidence_len(std::slice::from_ref(&item));
        if !out.is_empty() && used.saturating_add(len) > budget_bytes {
            break;
        }
        used = used.saturating_add(len);
        out.push(item);
    }
    out
}

fn bound_federation_evidence(
    evidence: Vec<FederationContractEvidence>,
    budget_bytes: usize,
) -> Vec<FederationContractEvidence> {
    let mut out = Vec::new();
    let mut used = 0usize;
    for mut item in evidence {
        if let Some(summary) = item.summary.take() {
            item.summary = Some(bound_string(summary, 80));
        }
        if federation_evidence_len(std::slice::from_ref(&item)) > budget_bytes {
            item.summary = None;
        }
        if federation_evidence_len(std::slice::from_ref(&item)) > budget_bytes {
            item.surface = None;
        }
        let len = federation_evidence_len(std::slice::from_ref(&item));
        if !out.is_empty() && used.saturating_add(len) > budget_bytes {
            break;
        }
        used = used.saturating_add(len);
        out.push(item);
    }
    out
}

fn docs_code_evidence_len(evidence: &[DocsCodeEvidence]) -> usize {
    evidence
        .iter()
        .map(|item| {
            item.evidence_id.len()
                + item.doc_file.len()
                + item.code_file.len()
                + item.symbol.len()
                + item.evidence_epoch.len()
                + item.surface.as_ref().map_or(0, String::len)
                + item.summary.as_ref().map_or(0, String::len)
                + 32
        })
        .sum()
}

fn federation_evidence_len(evidence: &[FederationContractEvidence]) -> usize {
    evidence
        .iter()
        .map(|item| {
            item.evidence_id.len()
                + item.source_file.len()
                + item.package_name.len()
                + item.evidence_epoch.len()
                + item.surface.as_ref().map_or(0, String::len)
                + item.summary.as_ref().map_or(0, String::len)
                + 32
        })
        .sum()
}

fn bound_string(value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value[..end].to_string()
}

fn addresses_overlap(left: &[CodeAddress], right: &[CodeAddress]) -> bool {
    left.iter()
        .any(|left| right.iter().any(|right| left.overlaps(right)))
}

fn fingerprint_world(world: &PipelineWorld) -> String {
    let mut bytes = Vec::new();
    for (file, address) in &world.sources {
        bytes.extend_from_slice(file.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(address.source_hash.as_bytes());
        bytes.push(0);
    }
    format!("worktree:{}", crate::hash::sha256_hex(&bytes))
}

/// Source identity shared by evidence producers and writeback base validation.
pub fn source_hash(bytes: &[u8]) -> String {
    format!("sha256:{}", crate::hash::sha256_hex(bytes))
}
