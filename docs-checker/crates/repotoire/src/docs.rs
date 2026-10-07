use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::evidence::{
    AgentEvidenceShape, AgentSourceLocationShape, ClaimVerification, ClaimVerificationStatus,
    DocClaim as EvidenceDocClaim, DocFact as EvidenceDocFact, EvidenceBundle, EvidenceDiagnostic,
    EvidenceLocation, EvidenceProvenance, EvidenceRepoRef, EvidenceSource, EvidenceSourceKind,
    EvidenceTimestamp,
};
use crate::markdown::{parse_markdown, MarkdownDiagnostic, MarkdownFact, MarkdownFactKind};

pub const DOC_GRAPH_SCHEMA: &str = "repotoire.docs_claim_graph.v1";
pub const DOC_REPORT_SCHEMA: &str = "repotoire.docs_claim_report.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocSourceFormat {
    Markdown,
    Mdx,
    Rustdoc,
    PythonDocstring,
    OpenApi,
    GeneratedDocs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocDecodeOptions {
    pub repo: EvidenceRepoRef,
    pub snapshot_id: String,
    pub observed_at: String,
    #[serde(default, skip_serializing_if = "is_false")]
    validate_code_references: bool,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    known_code_references: BTreeSet<DocCodeReferenceKey>,
    // Explanatory context from the current resolver, never persisted authority.
    #[serde(skip)]
    unresolved_code_reference_reasons: BTreeMap<DocCodeReferenceKey, String>,
}

impl DocDecodeOptions {
    pub fn new(
        repo: EvidenceRepoRef,
        snapshot_id: impl Into<String>,
        observed_at: impl Into<String>,
    ) -> Self {
        Self {
            repo,
            snapshot_id: snapshot_id.into(),
            observed_at: observed_at.into(),
            validate_code_references: false,
            known_code_references: BTreeSet::new(),
            unresolved_code_reference_reasons: BTreeMap::new(),
        }
    }

    pub fn with_code_reference_validation(mut self) -> Self {
        self.validate_code_references = true;
        self
    }

    pub fn with_known_code_reference(
        mut self,
        target: impl Into<String>,
        symbol: Option<impl Into<String>>,
    ) -> Self {
        self.validate_code_references = true;
        self.known_code_references.insert(DocCodeReferenceKey {
            target: target.into(),
            symbol: symbol.map(Into::into),
        });
        self
    }

    fn code_reference_is_resolved(&self, target: Option<&str>, symbol: Option<&str>) -> bool {
        if !self.validate_code_references {
            return true;
        }
        let Some(target) = target else {
            return true;
        };
        self.known_code_references.contains(&DocCodeReferenceKey {
            target: target.to_string(),
            symbol: symbol.map(ToOwned::to_owned),
        })
    }

    /// Attach observed failure context without marking a reference as resolved.
    /// Serialization omits this request-local context; decoding without it stays unknown.
    pub fn with_unresolved_code_reference_reason(
        mut self,
        target: impl Into<String>,
        symbol: Option<impl Into<String>>,
        reason: impl Into<String>,
    ) -> Self {
        self.validate_code_references = true;
        self.unresolved_code_reference_reasons.insert(
            DocCodeReferenceKey {
                target: target.into(),
                symbol: symbol.map(Into::into),
            },
            reason.into(),
        );
        self
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocCodeReferenceKey {
    target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbol: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocNodeKind {
    DocPage,
    DocSection,
    Requirement,
    ADRDecision,
    APIContract,
    RunbookStep,
    CodeReference,
    ArchitectureClaim,
}

impl DocNodeKind {
    fn key(self) -> &'static str {
        match self {
            Self::DocPage => "doc_page",
            Self::DocSection => "doc_section",
            Self::Requirement => "requirement",
            Self::ADRDecision => "adr_decision",
            Self::APIContract => "api_contract",
            Self::RunbookStep => "runbook_step",
            Self::CodeReference => "code_reference",
            Self::ArchitectureClaim => "architecture_claim",
        }
    }

    fn is_claim(self) -> bool {
        matches!(
            self,
            Self::Requirement
                | Self::ADRDecision
                | Self::APIContract
                | Self::RunbookStep
                | Self::ArchitectureClaim
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocEdgeKind {
    Contains,
    ReferencesCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocDiagnosticCode {
    AmbiguousClaim,
    UnsupportedSyntax,
    UnresolvedReference,
    UnsupportedFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocNode {
    pub node_id: String,
    pub kind: DocNodeKind,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    pub attributes: BTreeMap<String, String>,
    pub provenance: EvidenceProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocEdge {
    pub edge_id: String,
    pub kind: DocEdgeKind,
    pub from_id: String,
    pub to_id: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocDiagnostic {
    pub code: DocDiagnosticCode,
    pub message: String,
    pub provenance: EvidenceProvenance,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocGraph {
    pub schema: String,
    pub file: String,
    pub nodes: Vec<DocNode>,
    pub edges: Vec<DocEdge>,
    pub diagnostics: Vec<DocDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocSource<'a> {
    pub file: &'a str,
    pub source: &'a str,
    pub format: DocSourceFormat,
}

impl<'a> DocSource<'a> {
    pub fn new(file: &'a str, source: &'a str) -> Self {
        Self {
            file,
            source,
            format: DocSourceFormat::Markdown,
        }
    }

    pub fn with_format(mut self, format: DocSourceFormat) -> Self {
        self.format = format;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocDecodeScorecard {
    pub documents: u64,
    pub source_bytes: u64,
    pub nodes: u64,
    pub edges: u64,
    pub diagnostics: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocDecodeReport {
    pub schema: String,
    pub scorecard: DocDecodeScorecard,
    pub graphs: Vec<DocGraph>,
    pub diagnostics: Vec<DocDiagnostic>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocVerificationEvidence {
    code_references: Vec<DocCodeReferenceEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocCodeReferenceEvidence {
    reference_evidence_id: String,
    target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbol: Option<String>,
    resolution_evidence_id: String,
    history: DocReferenceHistory,
    history_evidence_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocSectionFreshness {
    Fresh,
    Stale,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocChangeOrder {
    SameChange,
    SectionBeforeReference,
    ReferenceBeforeSection,
    Diverged,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocReferenceHistory {
    pub section_change: Option<String>,
    pub reference_change: Option<String>,
    pub order: DocChangeOrder,
}

impl DocReferenceHistory {
    pub fn unavailable() -> Self {
        Self {
            section_change: None,
            reference_change: None,
            order: DocChangeOrder::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocFreshnessReason {
    HistoryUnavailable,
    InvalidChangeIdentity,
    SameChange,
    ReferenceChangedAfterSection,
    SectionChangedAfterReference,
    DivergedHistory,
    OrderUnavailable,
    InconsistentEvidence,
}

impl DocFreshnessReason {
    pub fn message(self) -> &'static str {
        match self {
            Self::HistoryUnavailable => {
                "change history was unavailable for the documentation section or referenced symbol"
            }
            Self::InvalidChangeIdentity => {
                "change history contained an invalid opaque change identity"
            }
            Self::SameChange => "the documentation section and referenced symbol changed together",
            Self::ReferenceChangedAfterSection => {
                "the referenced symbol changed after the documentation section"
            }
            Self::SectionChangedAfterReference => {
                "the documentation section changed after the referenced symbol"
            }
            Self::DivergedHistory => {
                "the documentation section and referenced symbol have divergent histories"
            }
            Self::OrderUnavailable => {
                "change ordering was unavailable for the documentation section or referenced symbol"
            }
            Self::InconsistentEvidence => "change identities and ordering evidence disagreed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocFreshnessVerdict {
    pub freshness: DocSectionFreshness,
    pub reason: DocFreshnessReason,
}

pub fn verify_doc_reference_history(history: &DocReferenceHistory) -> DocFreshnessVerdict {
    const MAX_CHANGE_IDENTITY_BYTES: usize = 256;

    let (Some(section_change), Some(reference_change)) = (
        history.section_change.as_deref(),
        history.reference_change.as_deref(),
    ) else {
        return DocFreshnessVerdict {
            freshness: DocSectionFreshness::Unknown,
            reason: DocFreshnessReason::HistoryUnavailable,
        };
    };
    if section_change.is_empty()
        || reference_change.is_empty()
        || section_change.len() > MAX_CHANGE_IDENTITY_BYTES
        || reference_change.len() > MAX_CHANGE_IDENTITY_BYTES
    {
        return DocFreshnessVerdict {
            freshness: DocSectionFreshness::Unknown,
            reason: DocFreshnessReason::InvalidChangeIdentity,
        };
    }

    let identities_match = section_change == reference_change;
    match (identities_match, history.order) {
        (true, DocChangeOrder::SameChange) => DocFreshnessVerdict {
            freshness: DocSectionFreshness::Fresh,
            reason: DocFreshnessReason::SameChange,
        },
        (false, DocChangeOrder::SectionBeforeReference) => DocFreshnessVerdict {
            freshness: DocSectionFreshness::Stale,
            reason: DocFreshnessReason::ReferenceChangedAfterSection,
        },
        (false, DocChangeOrder::ReferenceBeforeSection) => DocFreshnessVerdict {
            freshness: DocSectionFreshness::Fresh,
            reason: DocFreshnessReason::SectionChangedAfterReference,
        },
        (false, DocChangeOrder::Diverged) => DocFreshnessVerdict {
            freshness: DocSectionFreshness::Unknown,
            reason: DocFreshnessReason::DivergedHistory,
        },
        (false, DocChangeOrder::Unknown) => DocFreshnessVerdict {
            freshness: DocSectionFreshness::Unknown,
            reason: DocFreshnessReason::OrderUnavailable,
        },
        _ => DocFreshnessVerdict {
            freshness: DocSectionFreshness::Unknown,
            reason: DocFreshnessReason::InconsistentEvidence,
        },
    }
}

impl DocVerificationEvidence {
    pub fn with_code_reference_observation(
        mut self,
        reference_evidence_id: impl Into<String>,
        target: impl Into<String>,
        symbol: Option<impl Into<String>>,
        resolution_evidence_id: impl Into<String>,
        history: DocReferenceHistory,
        history_evidence_id: impl Into<String>,
    ) -> Self {
        let reference = DocCodeReferenceEvidence {
            reference_evidence_id: reference_evidence_id.into(),
            target: target.into(),
            symbol: symbol.map(Into::into),
            resolution_evidence_id: resolution_evidence_id.into(),
            history,
            history_evidence_id: history_evidence_id.into(),
        };
        self.code_references
            .retain(|existing| existing.reference_evidence_id != reference.reference_evidence_id);
        self.code_references.push(reference);
        self.code_references
            .sort_by(|left, right| left.reference_evidence_id.cmp(&right.reference_evidence_id));
        self
    }

    fn code_reference_observation(
        &self,
        reference_evidence_id: &str,
        target: &str,
        symbol: Option<&str>,
    ) -> Option<&DocCodeReferenceEvidence> {
        self.code_references.iter().find(|reference| {
            reference.reference_evidence_id == reference_evidence_id
                && reference.target == target
                && reference.symbol.as_deref() == symbol
        })
    }
}

impl DocGraph {
    pub fn to_evidence_bundle(&self) -> EvidenceBundle {
        let mut bundle = EvidenceBundle::new();
        for node in &self.nodes {
            if node.kind.is_claim() {
                let mut claim = EvidenceDocClaim::new(
                    node.provenance.clone(),
                    node.node_id.clone(),
                    node.title.clone(),
                );
                claim.subject = node.parent_id.clone();
                claim
                    .attributes
                    .insert("doc_node_kind".to_string(), node.kind.key().to_string());
                claim
                    .attributes
                    .insert("doc_node_id".to_string(), node.node_id.clone());
                claim.attributes.extend(node.attributes.clone());

                let mut verification = ClaimVerification::new(
                    node.provenance.clone(),
                    claim.claim_id.clone(),
                    ClaimVerificationStatus::Unverified,
                )
                .with_evidence_id(claim.provenance.evidence_id.clone());
                verification.verifier = "repotoire.docs_claim_decoder".to_string();
                verification.checked_surfaces = vec!["documentation".to_string()];
                verification.summary = Some(
                    "decoded documentation claim awaits truth/divergence verification".to_string(),
                );

                bundle.doc_claims.push(claim);
                bundle.claim_verifications.push(verification);
            } else {
                let mut fact = EvidenceDocFact::new(
                    node.provenance.clone(),
                    node.parent_id
                        .clone()
                        .unwrap_or_else(|| format!("doc:{}", self.file)),
                    doc_fact_predicate(node.kind),
                    doc_fact_object(node),
                )
                .with_doc_kind(node.kind.key());
                fact.attributes
                    .insert("doc_node_kind".to_string(), node.kind.key().to_string());
                fact.attributes
                    .insert("doc_node_id".to_string(), node.node_id.clone());
                fact.attributes.extend(node.attributes.clone());
                bundle.doc_facts.push(fact);
            }
        }

        for diagnostic in &self.diagnostics {
            bundle
                .diagnostics
                .push(doc_diagnostic_to_evidence(diagnostic));
        }
        bundle
    }

    pub fn to_agent_evidence_shapes(&self) -> Vec<AgentEvidenceShape> {
        let mut shapes = Vec::new();
        for node in &self.nodes {
            let claim = node.kind.is_claim();
            shapes.push(AgentEvidenceShape {
                evidence_id: node.provenance.evidence_id.clone(),
                kind: if claim { "doc_claim" } else { "doc_fact" }.to_string(),
                source: agent_source_from_location(&node.provenance.location),
                precision: "doc_span".to_string(),
                proof_status: if claim { "unverified" } else { "decoded" }.to_string(),
                confidence: if claim { "medium" } else { "high" }.to_string(),
                note: format!(
                    "{} `{}` from docs claim decoder",
                    node.kind.key(),
                    node.title
                ),
            });
        }
        for diagnostic in &self.diagnostics {
            shapes.push(AgentEvidenceShape {
                evidence_id: diagnostic.provenance.evidence_id.clone(),
                kind: "doc_diagnostic".to_string(),
                source: agent_source_from_location(&diagnostic.provenance.location),
                precision: "doc_span".to_string(),
                proof_status: "diagnostic".to_string(),
                confidence: "high".to_string(),
                note: diagnostic.message.clone(),
            });
        }
        shapes
    }

    /// Assess reference resolution and change history, not the meaning of prose.
    /// Fresh references leave claims unverified until a claim-specific checker
    /// establishes their semantics. This layer cannot produce `Verified`.
    pub fn to_verified_evidence_bundle(
        &self,
        verification_evidence: &DocVerificationEvidence,
    ) -> EvidenceBundle {
        let mut bundle = self.to_evidence_bundle();
        for verification in &mut bundle.claim_verifications {
            let Some(node) = self
                .nodes
                .iter()
                .find(|node| node.node_id == verification.claim_id)
            else {
                continue;
            };
            let outcome = self.verify_claim_node(node, verification_evidence);
            verification.status = outcome.status;
            verification.verifier = "repotoire.docs_claim_verifier".to_string();
            verification.checked_surfaces =
                vec!["documentation".to_string(), "static_graph".to_string()];
            if outcome.checked_history {
                verification
                    .checked_surfaces
                    .push("change_history".to_string());
            }
            verification.summary = Some(outcome.summary);
            for evidence_id in outcome.evidence_ids {
                verification.evidence_ids.push(evidence_id);
            }
            verification.evidence_ids.sort();
            verification.evidence_ids.dedup();
        }
        bundle
    }

    fn verify_claim_node(
        &self,
        node: &DocNode,
        verification_evidence: &DocVerificationEvidence,
    ) -> DocVerificationOutcome {
        let code_refs = self
            .edges
            .iter()
            .filter(|edge| edge.kind == DocEdgeKind::ReferencesCode && edge.from_id == node.node_id)
            .filter_map(|edge| {
                self.nodes
                    .iter()
                    .find(|candidate| candidate.node_id == edge.to_id)
            })
            .filter(|candidate| candidate.kind == DocNodeKind::CodeReference)
            .collect::<Vec<_>>();

        let mut checked = Vec::new();
        let mut missing = Vec::new();
        let mut evidence_ids = Vec::new();
        let mut history_verdicts = Vec::new();
        for code_ref in code_refs {
            let Some(target) = code_ref.target.as_deref() else {
                continue;
            };
            let label = doc_fact_object(code_ref);
            checked.push(label.clone());
            if let Some(observation) = verification_evidence.code_reference_observation(
                &code_ref.provenance.evidence_id,
                target,
                code_ref.symbol.as_deref(),
            ) {
                evidence_ids.push(code_ref.provenance.evidence_id.clone());
                evidence_ids.push(observation.resolution_evidence_id.clone());
                evidence_ids.push(observation.history_evidence_id.clone());
                history_verdicts.push(verify_doc_reference_history(&observation.history));
            } else {
                missing.push(label);
            }
        }

        if checked.is_empty() {
            return DocVerificationOutcome {
                status: ClaimVerificationStatus::Unverified,
                evidence_ids,
                summary: "decoded documentation claim has no verifiable code reference evidence"
                    .to_string(),
                checked_history: false,
            };
        }
        if !missing.is_empty() {
            return DocVerificationOutcome {
                status: ClaimVerificationStatus::Contradicted,
                evidence_ids,
                summary: format!(
                    "documented code references did not resolve: {}",
                    missing.join(", ")
                ),
                checked_history: !history_verdicts.is_empty(),
            };
        }

        let freshness_status = if history_verdicts
            .iter()
            .any(|verdict| verdict.freshness == DocSectionFreshness::Stale)
        {
            Some(ClaimVerificationStatus::Stale)
        } else if history_verdicts
            .iter()
            .any(|verdict| verdict.freshness == DocSectionFreshness::Unknown)
        {
            Some(ClaimVerificationStatus::Unknown)
        } else {
            None
        };
        let freshness_reasons = history_verdicts
            .iter()
            .map(|verdict| verdict.reason.message())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join("; ");
        let status = freshness_status.unwrap_or(ClaimVerificationStatus::Unverified);
        let summary = format!(
            "all documented code references resolved; change-history verdict: {freshness_reasons}; reference resolution and history alone do not prove claim semantics"
        );
        DocVerificationOutcome {
            status,
            evidence_ids,
            summary,
            checked_history: !history_verdicts.is_empty(),
        }
    }
}

struct DocVerificationOutcome {
    status: ClaimVerificationStatus,
    evidence_ids: Vec<String>,
    summary: String,
    checked_history: bool,
}

fn doc_fact_predicate(kind: DocNodeKind) -> &'static str {
    match kind {
        DocNodeKind::DocPage => "defines_page",
        DocNodeKind::DocSection => "defines_section",
        DocNodeKind::CodeReference => "references_code",
        DocNodeKind::Requirement
        | DocNodeKind::ADRDecision
        | DocNodeKind::APIContract
        | DocNodeKind::RunbookStep
        | DocNodeKind::ArchitectureClaim => "documents_claim",
    }
}

fn doc_fact_object(node: &DocNode) -> String {
    match node.kind {
        DocNodeKind::CodeReference => match (&node.target, &node.symbol) {
            (Some(target), Some(symbol)) => format!("{target}#{symbol}"),
            (Some(target), None) => target.clone(),
            (None, Some(symbol)) => symbol.clone(),
            (None, None) => node.title.clone(),
        },
        _ => node.title.clone(),
    }
}

fn doc_diagnostic_to_evidence(diagnostic: &DocDiagnostic) -> EvidenceDiagnostic {
    let mut evidence = EvidenceDiagnostic::new(
        format!(
            "diagnostic:docs:{}",
            sanitize_id(&diagnostic.provenance.evidence_id)
        ),
        "doc_diagnostic",
        "warning",
        diagnostic.code.key(),
        diagnostic.message.clone(),
        diagnostic.provenance.clone(),
    );
    evidence
        .evidence_ids
        .push(diagnostic.provenance.evidence_id.clone());
    evidence
        .evidence_ids
        .extend(diagnostic.evidence_ids.iter().cloned());
    evidence.evidence_ids.sort();
    evidence.evidence_ids.dedup();
    evidence
}

fn agent_source_from_location(location: &EvidenceLocation) -> Option<AgentSourceLocationShape> {
    match location {
        EvidenceLocation::Span { file, .. } => Some(AgentSourceLocationShape {
            file: file.clone(),
            line: None,
            col: None,
        }),
        EvidenceLocation::LineColumn {
            file, line, column, ..
        } => Some(AgentSourceLocationShape {
            file: file.clone(),
            line: Some(*line),
            col: *column,
        }),
        EvidenceLocation::Uri { file, .. } => file.as_ref().map(|file| AgentSourceLocationShape {
            file: file.clone(),
            line: None,
            col: None,
        }),
    }
}

impl DocDiagnosticCode {
    fn key(self) -> &'static str {
        match self {
            Self::AmbiguousClaim => "ambiguous_claim",
            Self::UnsupportedSyntax => "unsupported_syntax",
            Self::UnresolvedReference => "unresolved_reference",
            Self::UnsupportedFormat => "unsupported_format",
        }
    }
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

struct DecodeState<'a> {
    file: &'a str,
    source_len: usize,
    options: DocDecodeOptions,
    graph: DocGraph,
    next_node: u32,
    next_edge: u32,
    next_evidence: u32,
    page_id: String,
    current_section: Option<SectionState>,
    section_stack: Vec<SectionState>,
    fence: Option<FenceState>,
}

#[derive(Debug, Clone)]
struct SectionState {
    id: String,
    level: u8,
    role: Option<SectionRole>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SectionRole {
    Requirements,
    Adr,
    ApiContract,
    Runbook,
    Architecture,
}

#[derive(Debug, Clone, Copy)]
struct FenceState {
    marker: u8,
    len: usize,
    content_start: usize,
    language_start: usize,
    language_len: usize,
}

#[derive(Debug, Clone)]
struct Line<'a> {
    text: &'a str,
    start: usize,
}

pub fn decode_markdown_doc(file: &str, source: &str, options: DocDecodeOptions) -> DocGraph {
    let markdown = parse_markdown(file, source);
    let mut state = DecodeState::new(file, options, source.len());
    let diagnosed_lines = markdown
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.line)
        .collect::<BTreeSet<_>>();
    for diagnostic in markdown.diagnostics {
        state.add_parser_diagnostic(source, diagnostic);
    }
    let mut return_contracts_by_line = markdown.facts.into_iter().fold(
        BTreeMap::<u32, Vec<MarkdownFact>>::new(),
        |mut by_line, fact| {
            if fact.kind == MarkdownFactKind::ReturnContract {
                by_line.entry(fact.line).or_default().push(fact);
            }
            by_line
        },
    );
    for (line_index, line) in lines_with_offsets(source).into_iter().enumerate() {
        let line_no = (line_index + 1) as u32;
        // A parser-diagnosed raw HTML block stays opaque to role-based claims.
        let classified =
            diagnosed_lines.contains(&line_no) || state.parse_line(source, line.clone());
        let needs_coverage = !classified;
        let mut covered_end = 0;
        if let Some(facts) = return_contracts_by_line.remove(&line_no) {
            for fact in facts {
                let start = fact.col.saturating_sub(1) as usize;
                if needs_coverage && start > covered_end {
                    state.add_unclassified_prose(Line {
                        text: &line.text[covered_end..start],
                        start: line.start + covered_end,
                    });
                }
                covered_end = covered_end.max(start + fact.text.len());
                state.add_return_contract(source, fact);
            }
        }
        if needs_coverage {
            state.add_unclassified_prose(Line {
                text: &line.text[covered_end..],
                start: line.start + covered_end,
            });
        }
    }
    for facts in return_contracts_by_line.into_values() {
        for fact in facts {
            state.add_return_contract(source, fact);
        }
    }
    if let Some(fence) = state.fence.take() {
        state.add_fenced_snippet(source, fence, source.len());
    }
    state.close_open_sections(source.len());
    if !state.graph.nodes.iter().any(|node| node.kind.is_claim()) {
        let provenance = state.provenance(0, source.len());
        state.graph.diagnostics.push(DocDiagnostic {
            code: DocDiagnosticCode::UnsupportedSyntax,
            message: format!(
                "Document `{file}` has no decoded claims; empty content, headings, references, and snippets alone do not establish verified documentation"
            ),
            provenance,
            // This summarizes the page, rather than identifying another prose span.
            evidence_ids: state
                .graph
                .nodes
                .iter()
                .filter(|node| node.node_id == state.page_id)
                .map(|node| node.provenance.evidence_id.clone())
                .collect(),
        });
    }
    state.graph
}

pub fn decode_markdown_docs<'a>(
    sources: impl IntoIterator<Item = DocSource<'a>>,
    options: DocDecodeOptions,
) -> DocDecodeReport {
    decode_docs(
        sources
            .into_iter()
            .map(|source| source.with_format(DocSourceFormat::Markdown)),
        options,
    )
}

pub fn decode_docs<'a>(
    sources: impl IntoIterator<Item = DocSource<'a>>,
    options: DocDecodeOptions,
) -> DocDecodeReport {
    let mut scorecard = DocDecodeScorecard {
        documents: 0,
        source_bytes: 0,
        nodes: 0,
        edges: 0,
        diagnostics: 0,
    };
    let mut graphs = Vec::new();
    let mut diagnostics = Vec::new();
    for source in sources {
        scorecard.documents += 1;
        scorecard.source_bytes += source.source.len() as u64;
        match source.format {
            DocSourceFormat::Markdown => {
                let graph = decode_markdown_doc(source.file, source.source, options.clone());
                scorecard.nodes += graph.nodes.len() as u64;
                scorecard.edges += graph.edges.len() as u64;
                scorecard.diagnostics += graph.diagnostics.len() as u64;
                graphs.push(graph);
            }
            format => {
                scorecard.diagnostics += 1;
                diagnostics.push(unsupported_format_diagnostic(&options, source, format));
            }
        }
    }
    DocDecodeReport {
        schema: DOC_REPORT_SCHEMA.to_string(),
        scorecard,
        graphs,
        diagnostics,
    }
}

fn unsupported_format_diagnostic(
    options: &DocDecodeOptions,
    source: DocSource<'_>,
    format: DocSourceFormat,
) -> DocDiagnostic {
    DocDiagnostic {
        code: DocDiagnosticCode::UnsupportedFormat,
        message: format!(
            "Doc source `{}` uses unsupported format `{}`; add a decoder before emitting graph evidence",
            source.file,
            format_key(format)
        ),
        provenance: EvidenceProvenance::new(
            format!("docs:{}:unsupported_format", source.file),
            options.repo.clone(),
            EvidenceLocation::span(source.file, 0, source.source.len() as u32),
            EvidenceSource::unversioned(EvidenceSourceKind::Documentation, "docs-format-dispatch"),
            EvidenceTimestamp::ObservedAt(options.observed_at.clone()),
        )
        .with_snapshot_id(options.snapshot_id.clone()),
        evidence_ids: Vec::new(),
    }
}

fn format_key(format: DocSourceFormat) -> &'static str {
    match format {
        DocSourceFormat::Markdown => "markdown",
        DocSourceFormat::Mdx => "mdx",
        DocSourceFormat::Rustdoc => "rustdoc",
        DocSourceFormat::PythonDocstring => "python_docstring",
        DocSourceFormat::OpenApi => "open_api",
        DocSourceFormat::GeneratedDocs => "generated_docs",
    }
}

impl<'a> DecodeState<'a> {
    fn new(file: &'a str, options: DocDecodeOptions, source_len: usize) -> Self {
        let mut state = Self {
            file,
            source_len,
            graph: DocGraph {
                schema: DOC_GRAPH_SCHEMA.to_string(),
                file: file.to_string(),
                nodes: Vec::new(),
                edges: Vec::new(),
                diagnostics: Vec::new(),
            },
            options,
            next_node: 0,
            next_edge: 0,
            next_evidence: 0,
            page_id: String::new(),
            current_section: None,
            section_stack: Vec::new(),
            fence: None,
        };
        let page_id = state.add_node(NodeInput {
            kind: DocNodeKind::DocPage,
            title: file.to_string(),
            parent_id: None,
            target: None,
            symbol: None,
            attributes: BTreeMap::new(),
            start: 0,
            len: source_len,
        });
        state.page_id = page_id;
        state
    }

    fn add_unclassified_prose(&mut self, line: Line<'_>) {
        let text = line.text.trim();
        if text.is_empty() {
            return;
        }
        let start = line.start + line.text.len() - line.text.trim_start().len();
        let provenance = self.provenance(start, text.len());
        self.graph.diagnostics.push(DocDiagnostic {
            code: DocDiagnosticCode::UnsupportedSyntax,
            message: format!(
                "Document `{}` contains unclassified prose; no supported claim rule applies, so this text has not been verified: {text}",
                self.file
            ),
            provenance,
            evidence_ids: Vec::new(),
        });
    }

    // A line is accounted for by structure, a claim, or an explicit diagnostic.
    // False leaves prose coverage to the owner that also integrates parser facts.
    fn parse_line(&mut self, source: &str, line: Line<'_>) -> bool {
        let trimmed = line.text.trim_start();
        let trim_start = line.text.len() - trimmed.len();
        if let Some(fence) = self.fence {
            if let Some(close_len) = closing_fence_len(trimmed, fence.marker, fence.len) {
                let content_end = line.start.saturating_sub(1);
                self.add_fenced_snippet(source, fence, content_end);
                self.fence = None;
                let _ = close_len;
            }
            return true;
        }

        if let Some((marker, len, language_start, language_len)) =
            opening_fence(trimmed, line.start + trim_start)
        {
            self.fence = Some(FenceState {
                marker,
                len,
                content_start: line.start + line.text.len(),
                language_start,
                language_len,
            });
            return true;
        }

        if let Some((level, title)) = heading(trimmed) {
            let start = line.start + trim_start;
            while self
                .section_stack
                .last()
                .is_some_and(|section| section.level >= level)
            {
                if let Some(section) = self.section_stack.pop() {
                    self.close_section(&section.id, line.start);
                }
            }
            let parent_section = self.section_stack.last();
            let parent_id = parent_section
                .map(|section| section.id.clone())
                .unwrap_or_else(|| self.page_id.clone());
            let role =
                section_role(title).or_else(|| parent_section.and_then(|section| section.role));
            let id = self.add_node(NodeInput {
                kind: DocNodeKind::DocSection,
                title: title.to_string(),
                parent_id: Some(parent_id.clone()),
                target: None,
                symbol: None,
                attributes: BTreeMap::from([("level".to_string(), level.to_string())]),
                start,
                len: trimmed.len(),
            });
            self.add_edge(DocEdgeKind::Contains, parent_id, id.clone(), Vec::new());
            let section = SectionState { id, level, role };
            self.current_section = Some(section.clone());
            self.section_stack.push(section);
            return true;
        }

        if trimmed.is_empty() {
            return true;
        }

        let current = self.current_section.clone();
        if let Some(section) = current.as_ref() {
            let start = line.start + trim_start;
            if section.role == Some(SectionRole::Requirements) && is_requirement(trimmed) {
                let claim_id = self.add_section_child(
                    section,
                    DocNodeKind::Requirement,
                    trimmed.to_string(),
                    start,
                    trimmed.len(),
                    BTreeMap::new(),
                );
                self.add_inline_code_refs(source, line, section, Some(claim_id));
                return true;
            }
            if section.role == Some(SectionRole::Adr) {
                if let Some(decision) = trimmed.strip_prefix("Decision:") {
                    let claim_id = self.add_section_child(
                        section,
                        DocNodeKind::ADRDecision,
                        decision.trim().to_string(),
                        start,
                        trimmed.len(),
                        BTreeMap::new(),
                    );
                    self.add_inline_code_refs(source, line, section, Some(claim_id));
                    return true;
                }
            }
            if section.role == Some(SectionRole::ApiContract) {
                if let Some(api) = first_inline_code(trimmed) {
                    let mut attrs = BTreeMap::new();
                    attrs.insert("api".to_string(), api.to_string());
                    let contract_id = self.add_section_child(
                        section,
                        DocNodeKind::APIContract,
                        trimmed.to_string(),
                        start,
                        trimmed.len(),
                        attrs,
                    );
                    self.add_api_reference(
                        api,
                        start + trimmed.find('`').unwrap_or(0) + 1,
                        contract_id,
                    );
                    return true;
                }
            }
            if section.role == Some(SectionRole::Runbook) && is_ordered_list_item(trimmed) {
                let claim_id = self.add_section_child(
                    section,
                    DocNodeKind::RunbookStep,
                    trimmed.to_string(),
                    start,
                    trimmed.len(),
                    BTreeMap::new(),
                );
                self.add_inline_code_refs(source, line, section, Some(claim_id));
                return true;
            }
            if section.role == Some(SectionRole::Architecture) {
                let refs = inline_code_spans(line.text);
                let code_ref = refs.iter().find_map(|(code, col)| {
                    parse_code_reference(code).map(|parsed| (parsed, *col))
                });
                if let Some((parsed, col)) = code_ref {
                    let mut attrs = BTreeMap::new();
                    if let Some(target) = &parsed.target {
                        attrs.insert("target".to_string(), target.clone());
                    }
                    if let Some(symbol) = &parsed.symbol {
                        attrs.insert("symbol".to_string(), symbol.clone());
                    }
                    let claim_id = self.add_section_child(
                        section,
                        DocNodeKind::ArchitectureClaim,
                        trimmed.to_string(),
                        start,
                        trimmed.len(),
                        attrs,
                    );
                    self.add_code_reference(
                        parsed.target,
                        parsed.symbol,
                        line.start + col,
                        parsed.text_len,
                        claim_id,
                        BTreeMap::new(),
                    );
                    return true;
                } else if looks_like_claim(trimmed) {
                    self.add_ambiguous_claim(trimmed, start, trimmed.len());
                    return true;
                }
            }
            self.add_inline_code_refs(source, line, section, None);
        }
        false
    }

    fn close_open_sections(&mut self, end: usize) {
        while let Some(section) = self.section_stack.pop() {
            self.close_section(&section.id, end);
        }
    }

    fn close_section(&mut self, section_id: &str, end: usize) {
        assert!(
            end <= self.source_len,
            "section end {end} exceeds document length {}",
            self.source_len
        );
        let Some(node) = self
            .graph
            .nodes
            .iter_mut()
            .find(|node| node.node_id == section_id)
        else {
            return;
        };
        let EvidenceLocation::Span { start, len, .. } = &mut node.provenance.location else {
            return;
        };
        let start = usize::try_from(*start).expect("u32 span start must fit usize");
        assert!(end >= start, "section end {end} precedes start {start}");
        *len = u32::try_from(end - start).expect("section span length exceeds u32");
    }

    fn add_section_child(
        &mut self,
        section: &SectionState,
        kind: DocNodeKind,
        title: String,
        start: usize,
        len: usize,
        attributes: BTreeMap<String, String>,
    ) -> String {
        let id = self.add_node(NodeInput {
            kind,
            title,
            parent_id: Some(section.id.clone()),
            target: None,
            symbol: None,
            attributes,
            start,
            len,
        });
        self.add_edge(
            DocEdgeKind::Contains,
            section.id.clone(),
            id.clone(),
            Vec::new(),
        );
        id
    }

    fn add_inline_code_refs(
        &mut self,
        _source: &str,
        line: Line<'_>,
        section: &SectionState,
        parent_override: Option<String>,
    ) {
        for (code, col) in inline_code_spans(line.text) {
            if let Some(parsed) = parse_code_reference(code) {
                self.add_code_reference(
                    parsed.target,
                    parsed.symbol,
                    line.start + col,
                    parsed.text_len,
                    parent_override
                        .clone()
                        .unwrap_or_else(|| section.id.clone()),
                    BTreeMap::new(),
                );
            }
        }
    }

    fn add_api_reference(&mut self, api: &str, start: usize, parent_id: String) {
        let mut attrs = BTreeMap::new();
        attrs.insert("api".to_string(), api.to_string());
        self.add_code_reference(
            None,
            Some(api.to_string()),
            start,
            api.len(),
            parent_id,
            attrs,
        );
    }

    fn add_fenced_snippet(&mut self, source: &str, fence: FenceState, content_end: usize) {
        if content_end <= fence.content_start {
            return;
        }
        let content = &source[fence.content_start..content_end];
        if content.trim().is_empty() {
            return;
        }
        let language = source
            .get(fence.language_start..fence.language_start + fence.language_len)
            .unwrap_or("")
            .trim();
        let mut attrs = BTreeMap::new();
        attrs.insert("reference_kind".to_string(), "fenced_snippet".to_string());
        if !language.is_empty() {
            attrs.insert("language".to_string(), language.to_string());
        }
        let parent_id = self
            .current_section
            .as_ref()
            .map(|section| section.id.clone())
            .unwrap_or_else(|| self.page_id.clone());
        let id = self.add_node(NodeInput {
            kind: DocNodeKind::CodeReference,
            title: first_non_empty_line(content)
                .unwrap_or("fenced snippet")
                .to_string(),
            parent_id: Some(parent_id.clone()),
            target: None,
            symbol: None,
            attributes: attrs,
            start: fence.content_start,
            len: content_end - fence.content_start,
        });
        let evidence_ids = vec![self
            .graph
            .nodes
            .last()
            .map(|node| node.provenance.evidence_id.clone())
            .unwrap_or_default()];
        self.add_edge(DocEdgeKind::ReferencesCode, parent_id, id, evidence_ids);
    }

    fn add_code_reference(
        &mut self,
        target: Option<String>,
        symbol: Option<String>,
        start: usize,
        len: usize,
        parent_id: String,
        attributes: BTreeMap<String, String>,
    ) -> Option<String> {
        if self.add_unresolved_reference_if_needed(target.as_deref(), symbol.as_deref(), start, len)
        {
            return None;
        }
        let title = match (&target, &symbol) {
            (Some(target), Some(symbol)) => format!("{target}#{symbol}"),
            (Some(target), None) => target.clone(),
            (None, Some(symbol)) => symbol.clone(),
            (None, None) => "code reference".to_string(),
        };
        let id = self.add_node(NodeInput {
            kind: DocNodeKind::CodeReference,
            title,
            parent_id: Some(parent_id.clone()),
            target,
            symbol,
            attributes,
            start,
            len,
        });
        let evidence_ids = vec![self
            .graph
            .nodes
            .last()
            .map(|node| node.provenance.evidence_id.clone())
            .unwrap_or_default()];
        self.add_edge(
            DocEdgeKind::ReferencesCode,
            parent_id,
            id.clone(),
            evidence_ids,
        );
        Some(id)
    }

    fn add_ambiguous_claim(&mut self, text: &str, start: usize, len: usize) {
        let provenance = self.provenance(start, len);
        self.graph.diagnostics.push(DocDiagnostic {
            code: DocDiagnosticCode::AmbiguousClaim,
            message: format!(
                "Architecture claim in `{}` is not backed by a concrete code reference: {text}",
                self.file
            ),
            provenance,
            evidence_ids: Vec::new(),
        });
    }

    fn add_parser_diagnostic(&mut self, source: &str, diagnostic: MarkdownDiagnostic) {
        let Some(line) = line_for_number(source, diagnostic.line) else {
            return;
        };
        let col = diagnostic.col.saturating_sub(1) as usize;
        let start = line.start + col.min(line.text.len());
        let len = line.text.len().saturating_sub(col);
        let provenance = self.provenance(start, len);
        self.graph.diagnostics.push(DocDiagnostic {
            code: DocDiagnosticCode::UnsupportedSyntax,
            message: diagnostic.message,
            provenance,
            evidence_ids: Vec::new(),
        });
    }

    fn add_unresolved_reference_if_needed(
        &mut self,
        target: Option<&str>,
        symbol: Option<&str>,
        start: usize,
        len: usize,
    ) -> bool {
        if self.options.code_reference_is_resolved(target, symbol) {
            return false;
        }
        let label = match (target, symbol) {
            (Some(target), Some(symbol)) => format!("{target}#{symbol}"),
            (Some(target), None) => target.to_string(),
            (None, Some(symbol)) => symbol.to_string(),
            (None, None) => "unknown reference".to_string(),
        };
        let provenance = self.provenance(start, len);
        let reason = target.and_then(|target| {
            self.options.unresolved_code_reference_reasons.get(&DocCodeReferenceKey {
                target: target.to_string(),
                symbol: symbol.map(ToOwned::to_owned),
            })
        }).map(String::as_str).filter(|reason| !reason.trim().is_empty()).unwrap_or(
            "cause unknown: the supplied graph evidence contains no accepted resolution or failure context; source evidence and a resolution explanation are still required"
        );
        self.graph.diagnostics.push(DocDiagnostic {
            code: DocDiagnosticCode::UnresolvedReference,
            message: format!(
                "Code reference `{label}` in `{}` at byte {start} remains unresolved: {reason}",
                self.file,
            ),
            provenance,
            evidence_ids: Vec::new(),
        });
        true
    }

    fn add_return_contract(&mut self, source: &str, fact: MarkdownFact) {
        let Some(line) = line_for_number(source, fact.line) else {
            return;
        };
        let col = fact.col.saturating_sub(1) as usize;
        let start = line.start + col.min(line.text.len());
        let len = fact.text.len();
        let parent_id = self
            .current_section
            .as_ref()
            .map(|section| section.id.clone())
            .unwrap_or_else(|| self.page_id.clone());
        let mut attrs = BTreeMap::new();
        if let Some(target) = &fact.target {
            attrs.insert("target".to_string(), target.clone());
        }
        if let Some(symbol) = &fact.symbol {
            attrs.insert("symbol".to_string(), symbol.clone());
        }
        if let Some(expected_return) = &fact.expected_return {
            attrs.insert("expected_return".to_string(), expected_return.clone());
        }
        let contract_id = self.add_node(NodeInput {
            kind: DocNodeKind::APIContract,
            title: fact.symbol.clone().unwrap_or_else(|| fact.text.clone()),
            parent_id: Some(parent_id.clone()),
            target: fact.target.clone(),
            symbol: fact.symbol.clone(),
            attributes: attrs,
            start,
            len,
        });
        self.add_edge(
            DocEdgeKind::Contains,
            parent_id,
            contract_id.clone(),
            Vec::new(),
        );
        if let (Some(target), Some(symbol)) = (fact.target, fact.symbol) {
            let reference = format!("{target}#{symbol}");
            if let Some((code, code_col)) = inline_code_spans(line.text)
                .into_iter()
                .find(|(code, _)| *code == reference)
            {
                self.add_code_reference(
                    Some(target),
                    Some(symbol),
                    line.start + code_col,
                    code.len(),
                    contract_id,
                    BTreeMap::new(),
                );
            }
        }
    }

    fn add_node(&mut self, input: NodeInput) -> String {
        let node_id = format!("doc-node-{}", self.next_node);
        self.next_node += 1;
        let provenance = self.provenance(input.start, input.len);
        self.graph.nodes.push(DocNode {
            node_id: node_id.clone(),
            kind: input.kind,
            title: input.title,
            parent_id: input.parent_id,
            target: input.target,
            symbol: input.symbol,
            attributes: input.attributes,
            provenance,
        });
        node_id
    }

    fn add_edge(
        &mut self,
        kind: DocEdgeKind,
        from_id: String,
        to_id: String,
        evidence_ids: Vec<String>,
    ) {
        let edge_id = format!("doc-edge-{}", self.next_edge);
        self.next_edge += 1;
        self.graph.edges.push(DocEdge {
            edge_id,
            kind,
            from_id,
            to_id,
            evidence_ids,
        });
    }

    fn provenance(&mut self, start: usize, len: usize) -> EvidenceProvenance {
        let end = start
            .checked_add(len)
            .expect("document span end overflowed");
        assert!(
            end <= self.source_len,
            "document span {start}..{end} exceeds document length {}",
            self.source_len
        );
        let start = u32::try_from(start).expect("document span start exceeds u32");
        let len = u32::try_from(len).expect("document span length exceeds u32");
        let evidence_id = format!("docs:{}:{}", self.file, self.next_evidence);
        self.next_evidence += 1;
        EvidenceProvenance::new(
            evidence_id,
            self.options.repo.clone(),
            EvidenceLocation::span(self.file, start, len),
            EvidenceSource::unversioned(EvidenceSourceKind::Documentation, "markdown-doc-decoder"),
            EvidenceTimestamp::ObservedAt(self.options.observed_at.clone()),
        )
        .with_snapshot_id(self.options.snapshot_id.clone())
    }
}

struct NodeInput {
    kind: DocNodeKind,
    title: String,
    parent_id: Option<String>,
    target: Option<String>,
    symbol: Option<String>,
    attributes: BTreeMap<String, String>,
    start: usize,
    len: usize,
}

struct ParsedCodeReference {
    target: Option<String>,
    symbol: Option<String>,
    text_len: usize,
}

fn lines_with_offsets(source: &str) -> Vec<Line<'_>> {
    let mut lines = Vec::new();
    let mut start = 0usize;
    for raw in source.split_inclusive('\n') {
        let text = raw.strip_suffix('\n').unwrap_or(raw);
        let text = text.strip_suffix('\r').unwrap_or(text);
        lines.push(Line { text, start });
        start += raw.len();
    }
    if source.is_empty() {
        lines.push(Line { text: "", start: 0 });
    } else if !source.ends_with('\n') && lines.is_empty() {
        lines.push(Line {
            text: source,
            start: 0,
        });
    }
    lines
}

fn line_for_number(source: &str, line_no: u32) -> Option<Line<'_>> {
    let index = usize::try_from(line_no.checked_sub(1)?).ok()?;
    lines_with_offsets(source).into_iter().nth(index)
}

fn heading(trimmed: &str) -> Option<(u8, &str)> {
    let level = trimmed.bytes().take_while(|byte| *byte == b'#').count();
    if !(1..=6).contains(&level) {
        return None;
    }
    let text = trimmed.get(level..)?.strip_prefix(' ')?;
    Some((level as u8, text.trim()))
}

fn is_requirement(trimmed: &str) -> bool {
    let item = trimmed
        .strip_prefix("- ")
        .or_else(|| trimmed.strip_prefix("* "))
        .unwrap_or(trimmed);
    item.starts_with("MUST ")
        || item.starts_with("SHOULD ")
        || item.starts_with("MAY ")
        || item.starts_with("Requirement:")
}

fn section_role(title: &str) -> Option<SectionRole> {
    if is_requirements_section(title) {
        Some(SectionRole::Requirements)
    } else if is_adr_section(title) {
        Some(SectionRole::Adr)
    } else if is_api_contract_section(title) {
        Some(SectionRole::ApiContract)
    } else if is_runbook_section(title) {
        Some(SectionRole::Runbook)
    } else if is_architecture_section(title) {
        Some(SectionRole::Architecture)
    } else {
        None
    }
}

fn is_requirements_section(title: &str) -> bool {
    section_words(title)
        .iter()
        .any(|word| word == "requirement" || word == "requirements")
}

fn is_adr_section(title: &str) -> bool {
    let words = section_words(title);
    words.iter().any(|word| word == "adr" || word == "adrs")
        || (words.iter().any(|word| word == "architecture")
            && words.iter().any(|word| word == "decision")
            && words
                .iter()
                .any(|word| word == "record" || word == "records"))
}

fn is_api_contract_section(title: &str) -> bool {
    let words = section_words(title);
    words.iter().any(|word| word == "api")
        && words
            .iter()
            .any(|word| word == "contract" || word == "contracts")
}

fn is_runbook_section(title: &str) -> bool {
    section_words(title)
        .iter()
        .any(|word| word == "runbook" || word == "runbooks")
}

fn is_architecture_section(title: &str) -> bool {
    section_words(title)
        .iter()
        .any(|word| word == "architecture")
}

fn section_words(title: &str) -> Vec<String> {
    title
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(|word| word.to_ascii_lowercase())
        .collect()
}

fn is_ordered_list_item(trimmed: &str) -> bool {
    let digits = trimmed
        .bytes()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    digits > 0
        && trimmed
            .get(digits..)
            .is_some_and(|rest| rest.starts_with(". "))
}

fn looks_like_claim(trimmed: &str) -> bool {
    trimmed.ends_with('.') && trimmed.split_whitespace().count() >= 4
}

fn first_inline_code(trimmed: &str) -> Option<&str> {
    inline_code_spans(trimmed)
        .into_iter()
        .next()
        .map(|(code, _)| code)
}

fn inline_code_spans(line: &str) -> Vec<(&str, usize)> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while let Some(start) = line[offset..].find('`') {
        let content_start = offset + start + 1;
        let Some(end) = line[content_start..].find('`') else {
            break;
        };
        let content_end = content_start + end;
        out.push((&line[content_start..content_end], content_start));
        offset = content_end + 1;
    }
    out
}

fn parse_code_reference(code: &str) -> Option<ParsedCodeReference> {
    if let Some((target, symbol)) = code.split_once('#') {
        if !is_file_ref(target) || !is_identifier_path(symbol) {
            return None;
        }
        return Some(ParsedCodeReference {
            target: Some(target.to_string()),
            symbol: Some(symbol.to_string()),
            text_len: code.len(),
        });
    }
    is_file_ref(code).then(|| ParsedCodeReference {
        target: Some(code.to_string()),
        symbol: None,
        text_len: code.len(),
    })
}

fn is_file_ref(code: &str) -> bool {
    let path = code.split_once('#').map(|(file, _)| file).unwrap_or(code);
    if path.is_empty()
        || path.starts_with('/')
        || path.contains("..")
        || path.contains('\\')
        || path.contains(' ')
    {
        return false;
    }
    path.contains('/')
        || matches!(
            path.rsplit('.').next(),
            Some("rs" | "ts" | "tsx" | "js" | "jsx" | "py" | "md" | "json" | "toml")
        )
}

fn is_identifier_path(symbol: &str) -> bool {
    !symbol.is_empty()
        && symbol
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(is_identifier_char))
}

fn is_identifier_char(ch: char) -> bool {
    ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()
}

fn opening_fence(trimmed: &str, line_start: usize) -> Option<(u8, usize, usize, usize)> {
    let bytes = trimmed.as_bytes();
    let &marker = bytes.first()?;
    if marker != b'`' && marker != b'~' {
        return None;
    }
    let len = bytes.iter().take_while(|&&byte| byte == marker).count();
    if len < 3 {
        return None;
    }
    if marker == b'`' && trimmed[len..].contains('`') {
        return None;
    }
    let language = trimmed[len..].trim();
    let language_offset = trimmed[len..]
        .find(language)
        .map(|offset| len + offset)
        .unwrap_or(trimmed.len());
    Some((marker, len, line_start + language_offset, language.len()))
}

fn closing_fence_len(trimmed: &str, marker: u8, opening_len: usize) -> Option<usize> {
    let run = trimmed
        .as_bytes()
        .iter()
        .take_while(|&&byte| byte == marker)
        .count();
    (run >= opening_len && trimmed[run..].trim().is_empty()).then_some(run)
}

fn first_non_empty_line(source: &str) -> Option<&str> {
    source.lines().map(str::trim).find(|line| !line.is_empty())
}
