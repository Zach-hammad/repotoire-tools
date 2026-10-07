//! The existing packet wire fields used by the docs-truth report.
//!
//! This checker emits empty entity, edge, weight, action, and type-witness
//! projections. Their names and omission rules match the source AgentPacket.
use serde::{Deserialize, Serialize};

pub const PACKET_VERSION: &str = "agent-abi-v0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentPacket {
    pub packet_version: String,
    pub query: AgentQuery,
    pub entities: Vec<serde_json::Value>,
    pub edges: Vec<serde_json::Value>,
    pub evidence: Vec<AgentEvidence>,
    pub diagnostics: Vec<AgentDiagnostic>,
    pub weights: Vec<serde_json::Value>,
    pub uncertainty: Vec<AgentUncertainty>,
    pub next_actions: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_witness: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentQuery {
    pub tool: String,
    pub symbol: String,
    pub found: bool,
    pub verification: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_precision: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSourceLocation {
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentEvidence {
    pub evidence_id: String,
    pub kind: AgentEvidenceKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<AgentSourceLocation>,
    pub precision: String,
    pub proof_status: String,
    pub confidence: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentEvidenceKind {
    StaticGraph,
    SourceReference,
    CodeCheckDiagnostic,
    RuntimeWitness,
    DivergenceEvidence,
    RuntimeScope,
    DynamicImport,
    ServiceDispatch,
    TestResult,
    DiagnosticHealth,
    VerificationProfile,
    VerificationRun,
    PriorFailure,
    StalePriorResult,
    Heuristic,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentDiagnostic {
    pub diagnostic_id: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<AgentSourceLocation>,
    pub severity: String,
    pub code: String,
    pub message: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentUncertainty {
    pub uncertainty_id: String,
    pub kind: String,
    pub severity: String,
    pub reason: String,
    pub evidence_ids: Vec<String>,
}
