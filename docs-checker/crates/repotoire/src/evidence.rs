use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::source_pipeline::PipelineWorld;
use crate::truth::{GraphFact, GraphFactKind, Language, TruthSerumReport};

pub const EVIDENCE_ABI_SCHEMA: &str = "repotoire.evidence.v1";
pub const EVIDENCE_ABI_VERSION: u32 = 1;
pub const CALIBRATION_BUNDLE_SCHEMA: &str = "repotoire.calibration_bundle.v1";
pub const CALIBRATION_INDEX_SCHEMA: &str = "repotoire.calibration_index.v1";
pub const NATIVE_CAPABILITY_SCHEMA: &str = "repotoire.native_capability.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeCapabilityStatus {
    High,
    Partial,
    Blocked,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCapabilityRecord {
    pub schema: String,
    pub surface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    pub status: NativeCapabilityStatus,
    pub measured_native_facts: u64,
    pub silent_divergences: u64,
    pub semantic_limits: u64,
    pub unsupported_constructs: u64,
    pub truth_source_gaps: u64,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
    #[serde(default)]
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationBundle {
    pub schema: String,
    pub bundle_id: String,
    pub repotoire_version: String,
    pub producer_version: String,
    pub corpus_version: String,
    pub policy_version: String,
    pub native_capabilities: Vec<NativeCapabilityRecord>,
    pub known_semantic_limits: Vec<String>,
    pub known_unsupported_constructs: Vec<String>,
    pub generated_at_ms: u64,
}

impl CalibrationBundle {
    pub fn new(
        repotoire_version: impl Into<String>,
        producer_version: impl Into<String>,
        corpus_version: impl Into<String>,
        policy_version: impl Into<String>,
        generated_at_ms: u64,
    ) -> Self {
        Self {
            schema: CALIBRATION_BUNDLE_SCHEMA.to_string(),
            bundle_id: String::new(),
            repotoire_version: repotoire_version.into(),
            producer_version: producer_version.into(),
            corpus_version: corpus_version.into(),
            policy_version: policy_version.into(),
            native_capabilities: Vec::new(),
            known_semantic_limits: Vec::new(),
            known_unsupported_constructs: Vec::new(),
            generated_at_ms,
        }
    }

    pub fn with_native_capability(mut self, record: NativeCapabilityRecord) -> Self {
        self.native_capabilities.push(record);
        self.native_capabilities.sort_by(|a, b| {
            a.surface
                .cmp(&b.surface)
                .then_with(|| a.language.cmp(&b.language))
        });
        self
    }

    pub fn with_known_semantic_limit(mut self, reason: impl Into<String>) -> Self {
        self.known_semantic_limits.push(reason.into());
        self.known_semantic_limits.sort();
        self.known_semantic_limits.dedup();
        self
    }

    pub fn with_known_unsupported_construct(mut self, reason: impl Into<String>) -> Self {
        self.known_unsupported_constructs.push(reason.into());
        self.known_unsupported_constructs.sort();
        self.known_unsupported_constructs.dedup();
        self
    }

    pub fn identity_payload(&self) -> serde_json::Value {
        let mut payload = serde_json::to_value(self).expect("CalibrationBundle serializes");
        if let serde_json::Value::Object(map) = &mut payload {
            map.remove("bundle_id");
            map.remove("generated_at_ms");
        }
        payload
    }

    pub fn with_computed_bundle_id(mut self) -> Result<Self, canonical::CanonicalError> {
        self.bundle_id = canonical::content_hash(&self.identity_payload())?;
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationIndex {
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_bundle_id: Option<String>,
    pub epoch: u64,
    #[serde(default)]
    pub previous_bundle_ids: Vec<String>,
    #[serde(default)]
    pub revoked_bundle_ids: Vec<String>,
}

impl CalibrationIndex {
    pub fn empty() -> Self {
        Self {
            schema: CALIBRATION_INDEX_SCHEMA.to_string(),
            active_bundle_id: None,
            epoch: 0,
            previous_bundle_ids: Vec::new(),
            revoked_bundle_ids: Vec::new(),
        }
    }

    pub fn is_revoked(&self, bundle_id: &str) -> bool {
        self.revoked_bundle_ids.iter().any(|id| id == bundle_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRepoRef {
    pub repo_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
}

impl EvidenceRepoRef {
    pub fn new(repo_id: impl Into<String>) -> Self {
        Self {
            repo_id: repo_id.into(),
            remote: None,
            revision: None,
            root: None,
        }
    }

    pub fn with_remote(mut self, remote: impl Into<String>) -> Self {
        self.remote = Some(remote.into());
        self
    }

    pub fn with_revision(mut self, revision: impl Into<String>) -> Self {
        self.revision = Some(revision.into());
        self
    }

    pub fn with_root(mut self, root: impl Into<String>) -> Self {
        self.root = Some(root.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceLocation {
    Span {
        file: String,
        start: u32,
        len: u32,
    },
    LineColumn {
        file: String,
        line: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        column: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        end_line: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        end_column: Option<u32>,
    },
    Uri {
        uri: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        file: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        anchor: Option<String>,
    },
}

impl EvidenceLocation {
    pub fn span(file: impl Into<String>, start: u32, len: u32) -> Self {
        Self::Span {
            file: file.into(),
            start,
            len,
        }
    }

    pub fn line_column(file: impl Into<String>, line: u32, column: Option<u32>) -> Self {
        Self::LineColumn {
            file: file.into(),
            line,
            column,
            end_line: None,
            end_column: None,
        }
    }

    pub fn uri(uri: impl Into<String>, file: Option<String>, anchor: Option<String>) -> Self {
        Self::Uri {
            uri: uri.into(),
            file,
            anchor,
        }
    }

    pub fn file(&self) -> Option<&str> {
        match self {
            Self::Span { file, .. } | Self::LineColumn { file, .. } => Some(file),
            Self::Uri { file, .. } => file.as_deref(),
        }
    }

    fn agent_source(&self) -> Option<AgentSourceLocationShape> {
        match self {
            Self::Span { file, .. } => Some(AgentSourceLocationShape {
                file: file.clone(),
                line: None,
                col: None,
            }),
            Self::LineColumn {
                file, line, column, ..
            } => Some(AgentSourceLocationShape {
                file: file.clone(),
                line: Some(*line),
                col: *column,
            }),
            Self::Uri { file, .. } => file.as_ref().map(|file| AgentSourceLocationShape {
                file: file.clone(),
                line: None,
                col: None,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSourceKind {
    Parser,
    TruthSource,
    RuntimeWitness,
    Documentation,
    AgentPacket,
    SourcePipeline,
    Cockpit,
    Writeback,
    External,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSource {
    pub kind: EvidenceSourceKind,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl EvidenceSource {
    pub fn new(
        kind: EvidenceSourceKind,
        name: impl Into<String>,
        version: Option<impl Into<String>>,
    ) -> Self {
        Self {
            kind,
            name: name.into(),
            version: version.map(Into::into),
        }
    }

    pub fn unversioned(kind: EvidenceSourceKind, name: impl Into<String>) -> Self {
        Self {
            kind,
            name: name.into(),
            version: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum EvidenceTimestamp {
    ObservedAt(String),
    Snapshot(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProvenance {
    pub evidence_id: String,
    pub repo: EvidenceRepoRef,
    pub location: EvidenceLocation,
    pub source: EvidenceSource,
    pub timestamp: EvidenceTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
}

impl EvidenceProvenance {
    pub fn new(
        evidence_id: impl Into<String>,
        repo: EvidenceRepoRef,
        location: EvidenceLocation,
        source: EvidenceSource,
        timestamp: EvidenceTimestamp,
    ) -> Self {
        Self {
            evidence_id: evidence_id.into(),
            repo,
            location,
            source,
            timestamp,
            snapshot_id: None,
        }
    }

    pub fn with_snapshot_id(mut self, snapshot_id: impl Into<String>) -> Self {
        self.snapshot_id = Some(snapshot_id.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocFact {
    pub provenance: EvidenceProvenance,
    pub subject: String,
    pub predicate: String,
    pub object: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_kind: Option<String>,
    pub attributes: BTreeMap<String, String>,
}

impl DocFact {
    pub fn new(
        provenance: EvidenceProvenance,
        subject: impl Into<String>,
        predicate: impl Into<String>,
        object: impl Into<String>,
    ) -> Self {
        Self {
            provenance,
            subject: subject.into(),
            predicate: predicate.into(),
            object: object.into(),
            doc_kind: None,
            attributes: BTreeMap::new(),
        }
    }

    pub fn with_doc_kind(mut self, doc_kind: impl Into<String>) -> Self {
        self.doc_kind = Some(doc_kind.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocClaim {
    pub provenance: EvidenceProvenance,
    pub claim_id: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub attributes: BTreeMap<String, String>,
}

impl DocClaim {
    pub fn new(
        provenance: EvidenceProvenance,
        claim_id: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        Self {
            provenance,
            claim_id: claim_id.into(),
            text: text.into(),
            subject: None,
            attributes: BTreeMap::new(),
        }
    }

    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeFact {
    pub provenance: EvidenceProvenance,
    pub fact_kind: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    pub attributes: BTreeMap<String, String>,
}

impl CodeFact {
    pub fn new(
        provenance: EvidenceProvenance,
        fact_kind: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            provenance,
            fact_kind: fact_kind.into(),
            name: name.into(),
            language: None,
            graph_kind: None,
            source_symbol: None,
            target_symbol: None,
            owner: None,
            attributes: BTreeMap::new(),
        }
    }

    pub fn with_language(mut self, language: impl Into<String>) -> Self {
        self.language = Some(language.into());
        self
    }

    pub fn with_graph_kind(mut self, graph_kind: impl Into<String>) -> Self {
        self.graph_kind = Some(graph_kind.into());
        self
    }

    pub fn with_source_symbol(mut self, source_symbol: impl Into<String>) -> Self {
        self.source_symbol = Some(source_symbol.into());
        self
    }

    pub fn with_target_symbol(mut self, target_symbol: impl Into<String>) -> Self {
        self.target_symbol = Some(target_symbol.into());
        self
    }

    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    pub fn embedded_query(
        provenance: EvidenceProvenance,
        name: impl Into<String>,
        query_language: impl Into<String>,
        owner_symbol: impl Into<String>,
    ) -> Self {
        let owner_symbol = owner_symbol.into();
        Self::new(provenance, "embedded_query", name)
            .with_graph_kind("query")
            .with_source_symbol(owner_symbol.clone())
            .with_attribute("query_language", query_language)
            .with_attribute("owner_symbol", owner_symbol)
    }

    pub fn query_parameter(
        provenance: EvidenceProvenance,
        parameter_name: impl Into<String>,
        query_name: impl Into<String>,
        binding_kind: impl Into<String>,
    ) -> Self {
        let parameter_name = parameter_name.into();
        Self::new(provenance, "query_parameter", parameter_name.clone())
            .with_graph_kind("query_parameter")
            .with_source_symbol(query_name)
            .with_target_symbol(parameter_name)
            .with_attribute("binding_kind", binding_kind)
    }

    pub fn authorization_guard(
        provenance: EvidenceProvenance,
        guard_name: impl Into<String>,
        guarded_symbol: impl Into<String>,
        guard_subject: impl Into<String>,
    ) -> Self {
        Self::new(provenance, "authorization_guard", guard_name)
            .with_graph_kind("authorization_guard")
            .with_target_symbol(guarded_symbol)
            .with_attribute("guard_subject", guard_subject)
    }

    pub fn data_access(
        provenance: EvidenceProvenance,
        access_name: impl Into<String>,
        operation: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        let resource = resource.into();
        Self::new(provenance, "data_access", access_name)
            .with_graph_kind("data_access")
            .with_target_symbol(resource.clone())
            .with_attribute("operation", operation)
            .with_attribute("resource", resource)
    }

    pub fn from_graph_fact(
        evidence_id: impl Into<String>,
        repo: EvidenceRepoRef,
        snapshot_id: impl Into<String>,
        observed_at: impl Into<String>,
        fact: &GraphFact,
    ) -> Self {
        let source = EvidenceSource::new(
            EvidenceSourceKind::TruthSource,
            fact.fact_source.truth_source.name.clone(),
            Some(fact.fact_source.truth_source.version.clone()),
        );
        let provenance = EvidenceProvenance::new(
            evidence_id,
            repo,
            EvidenceLocation::span(&fact.file, fact.span.start, fact.span.len),
            source,
            EvidenceTimestamp::ObservedAt(observed_at.into()),
        )
        .with_snapshot_id(snapshot_id);
        let mut code_fact = Self::new(
            provenance,
            graph_fact_kind_key(fact.kind),
            fact.name.clone(),
        )
        .with_graph_kind(fact.graph_kind.clone());
        code_fact.source_symbol = fact.source.clone();
        code_fact.target_symbol = fact.target.clone();
        code_fact.owner = fact.owner.clone();
        code_fact.attributes.insert(
            "truth_source".to_string(),
            fact.fact_source.truth_source.name.clone(),
        );
        code_fact.attributes.insert(
            "truth_source_version".to_string(),
            fact.fact_source.truth_source.version.clone(),
        );
        code_fact
    }

    pub fn to_agent_evidence_shape(
        &self,
        kind: impl Into<String>,
        precision: impl Into<String>,
        proof_status: impl Into<String>,
        confidence: impl Into<String>,
    ) -> AgentEvidenceShape {
        AgentEvidenceShape {
            evidence_id: self.provenance.evidence_id.clone(),
            kind: kind.into(),
            source: self.provenance.location.agent_source(),
            precision: precision.into(),
            proof_status: proof_status.into(),
            confidence: confidence.into(),
            note: format!(
                "{} `{}` from shared evidence ABI",
                self.fact_kind, self.name
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoGraphSnapshot {
    pub provenance: EvidenceProvenance,
    pub repo: EvidenceRepoRef,
    pub snapshot_id: String,
    pub fact_evidence_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freshness: Option<GraphFreshness>,
    pub diagnostics: Vec<EvidenceDiagnostic>,
}

impl RepoGraphSnapshot {
    pub fn new(
        provenance: EvidenceProvenance,
        repo: EvidenceRepoRef,
        snapshot_id: impl Into<String>,
    ) -> Self {
        Self {
            provenance,
            repo,
            snapshot_id: snapshot_id.into(),
            fact_evidence_ids: Vec::new(),
            freshness: None,
            diagnostics: Vec::new(),
        }
    }

    pub fn with_fact_evidence_id(mut self, evidence_id: impl Into<String>) -> Self {
        self.fact_evidence_ids.push(evidence_id.into());
        self.fact_evidence_ids.sort();
        self.fact_evidence_ids.dedup();
        self
    }

    pub fn with_freshness(mut self, freshness: GraphFreshness) -> Self {
        self.freshness = Some(freshness);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalRepoRef {
    pub provenance: EvidenceProvenance,
    pub repo: EvidenceRepoRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub attributes: BTreeMap<String, String>,
}

impl ExternalRepoRef {
    pub fn new(provenance: EvidenceProvenance, repo: EvidenceRepoRef) -> Self {
        Self {
            provenance,
            repo,
            description: None,
            attributes: BTreeMap::new(),
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederatedLink {
    pub provenance: EvidenceProvenance,
    pub from_evidence_id: String,
    pub to_evidence_id: String,
    pub relation: String,
    pub attributes: BTreeMap<String, String>,
}

impl FederatedLink {
    pub fn new(
        provenance: EvidenceProvenance,
        from_evidence_id: impl Into<String>,
        to_evidence_id: impl Into<String>,
        relation: impl Into<String>,
    ) -> Self {
        Self {
            provenance,
            from_evidence_id: from_evidence_id.into(),
            to_evidence_id: to_evidence_id.into(),
            relation: relation.into(),
            attributes: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessStatus {
    Fresh,
    Stale,
    Unknown,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphFreshness {
    pub provenance: EvidenceProvenance,
    pub snapshot_id: String,
    pub status: FreshnessStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_reason: Option<String>,
    pub epochs: BTreeMap<String, String>,
}

impl GraphFreshness {
    pub fn new(
        provenance: EvidenceProvenance,
        snapshot_id: impl Into<String>,
        status: FreshnessStatus,
    ) -> Self {
        Self {
            provenance,
            snapshot_id: snapshot_id.into(),
            status,
            checked_at: None,
            age_ms: None,
            max_age_ms: None,
            stale_reason: None,
            epochs: BTreeMap::new(),
        }
    }

    pub fn with_checked_at(mut self, checked_at: impl Into<String>) -> Self {
        self.checked_at = Some(checked_at.into());
        self
    }

    pub fn with_epoch(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.epochs.insert(key.into(), value.into());
        self
    }

    pub fn from_pipeline_world(provenance: EvidenceProvenance, world: &PipelineWorld) -> Self {
        let status = if world.graph_epoch.is_empty()
            || world.truth_epoch.is_empty()
            || world.decode_epoch.is_empty()
            || world.capability_epoch.is_empty()
            || world.verification_epoch.is_empty()
        {
            FreshnessStatus::Unknown
        } else {
            FreshnessStatus::Fresh
        };
        Self::new(provenance, world.current_git_sha.clone(), status)
            .with_epoch("decode", world.decode_epoch.clone())
            .with_epoch("graph", world.graph_epoch.clone())
            .with_epoch("truth", world.truth_epoch.clone())
            .with_epoch("capability", world.capability_epoch.clone())
            .with_epoch("verification", world.verification_epoch.clone())
            .with_epoch("worktree", world.worktree_fingerprint.clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimVerificationStatus {
    Verified,
    Contradicted,
    Unsupported,
    Stale,
    Unknown,
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimVerification {
    pub provenance: EvidenceProvenance,
    pub claim_id: String,
    pub status: ClaimVerificationStatus,
    pub verifier: String,
    pub evidence_ids: Vec<String>,
    pub checked_surfaces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

impl ClaimVerification {
    pub fn new(
        provenance: EvidenceProvenance,
        claim_id: impl Into<String>,
        status: ClaimVerificationStatus,
    ) -> Self {
        Self {
            provenance,
            claim_id: claim_id.into(),
            status,
            verifier: "repotoire.shared_evidence".to_string(),
            evidence_ids: Vec::new(),
            checked_surfaces: Vec::new(),
            summary: None,
        }
    }

    pub fn with_evidence_id(mut self, evidence_id: impl Into<String>) -> Self {
        self.evidence_ids.push(evidence_id.into());
        self.evidence_ids.sort();
        self.evidence_ids.dedup();
        self
    }

    pub fn from_truth_report(
        provenance: EvidenceProvenance,
        claim_id: impl Into<String>,
        report: &TruthSerumReport,
    ) -> Self {
        let status = if report.scorecard.silent_divergences == 0 {
            ClaimVerificationStatus::Verified
        } else {
            ClaimVerificationStatus::Contradicted
        };
        let mut verification = Self::new(provenance, claim_id, status);
        verification.verifier = "truth_serum".to_string();
        verification.checked_surfaces = vec![language_key(report.language).to_string()];
        verification.summary = Some(format!(
            "truth_serum silent_divergences={} explained_divergences={} graph_facts_checked={}",
            report.scorecard.silent_divergences,
            report.scorecard.explained_divergences,
            report.scorecard.graph_facts_checked
        ));
        for diff in &report.diffs {
            if let Some(fact) = &diff.expected_graph_fact {
                verification
                    .evidence_ids
                    .push(format!("truth:{}:{}", fact.file, fact.name));
            }
            if let Some(fact) = &diff.actual_graph_fact {
                verification
                    .evidence_ids
                    .push(format!("repotoire:{}:{}", fact.file, fact.name));
            }
        }
        verification.evidence_ids.sort();
        verification.evidence_ids.dedup();
        verification
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDiagnostic {
    pub diagnostic_id: String,
    pub kind: String,
    pub severity: String,
    pub code: String,
    pub message: String,
    pub provenance: EvidenceProvenance,
    pub evidence_ids: Vec<String>,
}

impl EvidenceDiagnostic {
    pub fn new(
        diagnostic_id: impl Into<String>,
        kind: impl Into<String>,
        severity: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
        provenance: EvidenceProvenance,
    ) -> Self {
        Self {
            diagnostic_id: diagnostic_id.into(),
            kind: kind.into(),
            severity: severity.into(),
            code: code.into(),
            message: message.into(),
            provenance,
            evidence_ids: Vec::new(),
        }
    }

    pub fn unsupported_fact(fact: UnsupportedEvidenceFact) -> Self {
        let evidence_id = fact.provenance.evidence_id.clone();
        Self {
            diagnostic_id: format!("diagnostic:unsupported:{}", sanitize_id(&evidence_id)),
            kind: "unsupported_fact".to_string(),
            severity: "warning".to_string(),
            code: "unsupported_fact".to_string(),
            message: format!(
                "Unsupported fact kind `{}` must be represented as a diagnostic, not guessed truth: {}",
                fact.fact_kind, fact.reason
            ),
            provenance: fact.provenance,
            evidence_ids: vec![evidence_id],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedEvidenceFact {
    pub provenance: EvidenceProvenance,
    pub fact_kind: String,
    pub reason: String,
}

impl UnsupportedEvidenceFact {
    pub fn new(
        provenance: EvidenceProvenance,
        fact_kind: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            provenance,
            fact_kind: fact_kind.into(),
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSourceLocationShape {
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEvidenceShape {
    pub evidence_id: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<AgentSourceLocationShape>,
    pub precision: String,
    pub proof_status: String,
    pub confidence: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerEvidenceView {
    pub evidence_ids: Vec<String>,
    pub reason_codes: Vec<String>,
    pub diagnostic_evidence_ids: Vec<String>,
    pub freshness_statuses: BTreeMap<String, FreshnessStatus>,
    pub verification_statuses: BTreeMap<String, ClaimVerificationStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundle {
    pub schema: String,
    pub version: u32,
    pub doc_facts: Vec<DocFact>,
    pub doc_claims: Vec<DocClaim>,
    pub code_facts: Vec<CodeFact>,
    pub repo_graph_snapshots: Vec<RepoGraphSnapshot>,
    pub external_repo_refs: Vec<ExternalRepoRef>,
    pub federated_links: Vec<FederatedLink>,
    pub graph_freshness: Vec<GraphFreshness>,
    pub claim_verifications: Vec<ClaimVerification>,
    pub diagnostics: Vec<EvidenceDiagnostic>,
}

impl Default for EvidenceBundle {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceBundle {
    pub fn new() -> Self {
        Self {
            schema: EVIDENCE_ABI_SCHEMA.to_string(),
            version: EVIDENCE_ABI_VERSION,
            doc_facts: Vec::new(),
            doc_claims: Vec::new(),
            code_facts: Vec::new(),
            repo_graph_snapshots: Vec::new(),
            external_repo_refs: Vec::new(),
            federated_links: Vec::new(),
            graph_freshness: Vec::new(),
            claim_verifications: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    pub fn with_doc_fact(mut self, fact: DocFact) -> Self {
        self.doc_facts.push(fact);
        self
    }

    pub fn with_doc_claim(mut self, claim: DocClaim) -> Self {
        self.doc_claims.push(claim);
        self
    }

    pub fn with_code_fact(mut self, fact: CodeFact) -> Self {
        self.code_facts.push(fact);
        self
    }

    pub fn with_repo_graph_snapshot(mut self, snapshot: RepoGraphSnapshot) -> Self {
        self.repo_graph_snapshots.push(snapshot);
        self
    }

    pub fn with_external_repo_ref(mut self, repo_ref: ExternalRepoRef) -> Self {
        self.external_repo_refs.push(repo_ref);
        self
    }

    pub fn with_federated_link(mut self, link: FederatedLink) -> Self {
        self.federated_links.push(link);
        self
    }

    pub fn with_graph_freshness(mut self, freshness: GraphFreshness) -> Self {
        self.graph_freshness.push(freshness);
        self
    }

    pub fn with_claim_verification(mut self, verification: ClaimVerification) -> Self {
        self.claim_verifications.push(verification);
        self
    }

    pub fn with_diagnostic(mut self, diagnostic: EvidenceDiagnostic) -> Self {
        self.diagnostics.push(diagnostic);
        self
    }

    pub fn ingest_unsupported_fact(&mut self, fact: UnsupportedEvidenceFact) {
        self.diagnostics
            .push(EvidenceDiagnostic::unsupported_fact(fact));
    }

    pub fn all_evidence_ids(&self) -> Vec<String> {
        let mut ids = BTreeSet::new();
        for fact in &self.doc_facts {
            ids.insert(fact.provenance.evidence_id.clone());
        }
        for claim in &self.doc_claims {
            ids.insert(claim.provenance.evidence_id.clone());
        }
        for fact in &self.code_facts {
            ids.insert(fact.provenance.evidence_id.clone());
        }
        for snapshot in &self.repo_graph_snapshots {
            ids.insert(snapshot.provenance.evidence_id.clone());
        }
        for repo_ref in &self.external_repo_refs {
            ids.insert(repo_ref.provenance.evidence_id.clone());
        }
        for link in &self.federated_links {
            ids.insert(link.provenance.evidence_id.clone());
        }
        for freshness in &self.graph_freshness {
            ids.insert(freshness.provenance.evidence_id.clone());
        }
        for verification in &self.claim_verifications {
            ids.insert(verification.provenance.evidence_id.clone());
        }
        for diagnostic in &self.diagnostics {
            ids.insert(diagnostic.provenance.evidence_id.clone());
            ids.extend(diagnostic.evidence_ids.iter().cloned());
        }
        ids.into_iter().collect()
    }

    pub fn consumer_view(&self) -> ConsumerEvidenceView {
        let mut reason_codes = BTreeSet::new();
        let mut diagnostic_evidence_ids = BTreeSet::new();
        let mut freshness_statuses = BTreeMap::new();
        let mut verification_statuses = BTreeMap::new();

        for diagnostic in &self.diagnostics {
            reason_codes.insert(diagnostic.code.clone());
            diagnostic_evidence_ids.extend(diagnostic.evidence_ids.iter().cloned());
        }
        for freshness in &self.graph_freshness {
            freshness_statuses.insert(freshness.snapshot_id.clone(), freshness.status);
        }
        for verification in &self.claim_verifications {
            verification_statuses.insert(verification.claim_id.clone(), verification.status);
        }

        ConsumerEvidenceView {
            evidence_ids: self.all_evidence_ids(),
            reason_codes: reason_codes.into_iter().collect(),
            diagnostic_evidence_ids: diagnostic_evidence_ids.into_iter().collect(),
            freshness_statuses,
            verification_statuses,
        }
    }
}

fn graph_fact_kind_key(kind: GraphFactKind) -> &'static str {
    match kind {
        GraphFactKind::Node => "node",
        GraphFactKind::Edge => "edge",
        GraphFactKind::Span => "span",
        GraphFactKind::Kind => "kind",
        GraphFactKind::Owner => "owner",
        GraphFactKind::Import => "import",
        GraphFactKind::Export => "export",
        GraphFactKind::Call => "call",
        GraphFactKind::TypeRef => "type_ref",
        GraphFactKind::ModuleRef => "module_ref",
        GraphFactKind::Route => "route",
        GraphFactKind::Query => "query",
        GraphFactKind::Test => "test",
        GraphFactKind::DynamicWitness => "dynamic_witness",
        GraphFactKind::CrossFileDependent => "cross_file_dependent",
    }
}

fn language_key(language: Language) -> &'static str {
    match language {
        Language::TypeScript => "typescript",
        Language::Rust => "rust",
        Language::Python => "python",
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

/// repotoire.canonical_json.v1 — a drift-proof RFC 8785 / JCS profile.
///
/// Rules:
/// - No insignificant whitespace.
/// - Object keys sorted by UTF-16 code-unit sequence (RFC 8785 §3.2.3).
/// - Strings: only `"`, `\`, and U+0000..U+001F are escaped; non-ASCII emitted as raw UTF-8.
/// - Numbers: I-JSON safe integers only (`|n| ≤ 2^53−1`). Fractions / exponents are rejected.
pub mod canonical {
    use serde_json::Value;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum CanonicalError {
        NonIntegerNumber,
        NumberOutOfRange,
        NonFiniteNumber,
        InvalidUtf8,
        /// Returned exclusively by `canonical_float_nano` when a named float field
        /// cannot be projected to a canonical i64 nanosecond value.
        FloatField {
            /// The field path, e.g. `"weights[2].score"`.
            field: String,
            /// Short human-readable reason, e.g. `"non-finite (NaN or Infinity)"`.
            reason: &'static str,
        },
    }

    impl std::fmt::Display for CanonicalError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NonIntegerNumber => {
                    f.write_str("canonical JSON forbids non-integer numbers (float-free profile)")
                }
                Self::NumberOutOfRange => f.write_str(
                    "integer outside the I-JSON safe range (|n| ≤ 2^53−1); encode as a string",
                ),
                Self::NonFiniteNumber => {
                    f.write_str("non-finite number (NaN/Infinity) cannot be canonicalized")
                }
                Self::InvalidUtf8 => f.write_str("invalid UTF-8 in a string"),
                Self::FloatField { field, reason } => {
                    write!(f, "{field}: {reason}")
                }
            }
        }
    }

    impl std::error::Error for CanonicalError {}

    const MAX_SAFE: i64 = 9_007_199_254_740_991; // 2^53 − 1

    pub const CANONICAL_JSON_SCHEME: &str = "canonical-json-v1";

    pub fn content_hash(value: &Value) -> Result<String, CanonicalError> {
        let bytes = canonical_json(value)?;
        Ok(format!(
            "sha256:{CANONICAL_JSON_SCHEME}:{}",
            crate::hash::sha256_hex(&bytes)
        ))
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Identity {
        pub algo: String,
        pub scheme: String,
        pub hex: String,
    }

    /// Parse `<algo>:<scheme>:<hex>`. Returns None for anything else (incl. bare hex / `sha256:<hex>`).
    pub fn parse_identity(s: &str) -> Option<Identity> {
        let mut parts = s.splitn(3, ':');
        let algo = parts.next()?;
        let scheme = parts.next()?;
        let hex = parts.next()?;
        if algo.is_empty() || scheme.is_empty() || hex.is_empty() || hex.contains(':') {
            return None;
        }
        Some(Identity {
            algo: algo.into(),
            scheme: scheme.into(),
            hex: hex.into(),
        })
    }

    /// Canonical nanosecond projection of a float evidence field.
    ///
    /// Shared helper for any f64 field that must be canonical-JSON-safe: converts
    /// `value * 1e9` to i64 using round-half-to-even, folds -0.0 → 0,
    /// rejects NaN/±Inf with NonFiniteNumber, rejects |nano| > MAX_SAFE with
    /// FloatField (which names the offending field). `field_name` appears in the
    /// returned Err to help callers identify the offending field
    /// (e.g. `"weights[2].score"`).
    ///
    /// Used by: `packet_identity` (AgentWeight.score → score_nano) and the
    /// deferred precision projection (TierPrecision.precision).
    pub fn canonical_float_nano(field_name: &str, value: f64) -> Result<i64, CanonicalError> {
        if !value.is_finite() {
            return Err(CanonicalError::FloatField {
                field: field_name.to_string(),
                reason: "non-finite (NaN or Infinity)",
            });
        }
        let scaled = value * 1e9; // IEEE-754 binary64 — identical in Rust & JS Number
                                  // Guard before round_half_to_even: a non-finite or huge scaled value would
                                  // saturate the `as i64` cast inside round_half_to_even.  Check here so the
                                  // helper always receives a finite, in-range value.
        if !scaled.is_finite() || scaled.abs() > MAX_SAFE as f64 {
            return Err(CanonicalError::FloatField {
                field: field_name.to_string(),
                reason: "out of I-JSON safe range after ×1e9",
            });
        }
        let r = round_half_to_even(scaled); // explicit; Node must NOT use Math.round
        if r == 0.0 {
            return Ok(0); // folds -0.0 → 0
        }
        Ok(r as i64)
    }

    fn round_half_to_even(x: f64) -> f64 {
        let f = x.floor();
        let diff = x - f;
        if diff < 0.5 {
            f
        } else if diff > 0.5 {
            f + 1.0
        } else if (f as i64) % 2 == 0 {
            f
        } else {
            f + 1.0
        }
    }

    /// Serialize `value` to a canonical JSON byte string (UTF-8).
    pub fn canonical_json(value: &Value) -> Result<Vec<u8>, CanonicalError> {
        let mut out = String::new();
        write_value(value, &mut out)?;
        Ok(out.into_bytes())
    }

    fn write_value(v: &Value, out: &mut String) -> Result<(), CanonicalError> {
        match v {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Number(n) => write_number(n, out)?,
            Value::String(s) => write_string(s, out),
            Value::Array(a) => {
                out.push('[');
                for (i, item) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_value(item, out)?;
                }
                out.push(']');
            }
            Value::Object(map) => {
                // Sort keys by UTF-16 code-unit order (RFC 8785 §3.2.3) — NOT Rust str order.
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort_by_key(|a| utf16_key(a));
                out.push('{');
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(k, out);
                    out.push(':');
                    write_value(&map[*k], out)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }

    fn utf16_key(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn write_number(n: &serde_json::Number, out: &mut String) -> Result<(), CanonicalError> {
        if let Some(u) = n.as_u64() {
            if u > MAX_SAFE as u64 {
                return Err(CanonicalError::NumberOutOfRange);
            }
            out.push_str(&u.to_string());
        } else if let Some(i) = n.as_i64() {
            if i.unsigned_abs() > MAX_SAFE as u64 {
                return Err(CanonicalError::NumberOutOfRange);
            }
            out.push_str(&i.to_string());
        } else {
            // f64 (had a fraction/exponent) — the float-free profile forbids it.
            return Err(if n.as_f64().map(|f| !f.is_finite()).unwrap_or(false) {
                CanonicalError::NonFiniteNumber
            } else {
                CanonicalError::NonIntegerNumber
            });
        }
        Ok(())
    }

    fn write_string(s: &str, out: &mut String) {
        out.push('"');
        for ch in s.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\u{08}' => out.push_str("\\b"),
                '\u{09}' => out.push_str("\\t"),
                '\u{0a}' => out.push_str("\\n"),
                '\u{0c}' => out.push_str("\\f"),
                '\u{0d}' => out.push_str("\\r"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c), // raw UTF-8 incl. non-ASCII
            }
        }
        out.push('"');
    }
}
