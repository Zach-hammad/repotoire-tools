use std::collections::BTreeMap;
use std::time::Instant;

use serde::Serialize;

mod cold_extraction;
mod native_evidence;
mod source_inventory;

pub(super) use cold_extraction::{
    prepare_cold_extraction_stage, run_cold_extraction_stage, ColdExtractionStageInput,
    ColdExtractionStageOutcome,
};
pub(super) use native_evidence::{
    run_native_evidence_stage, NativeEvidenceStageInput, NativeEvidenceStageResult,
};
pub(super) use source_inventory::{
    run_source_inventory_stage, SourceInventoryStageInput, SourceInventoryStageOutcome,
};

use super::{
    CodebaseSnapshot, LanguageCounts, ProjectEvidenceWorkingSetSummary, SourceInventoryMetrics,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectEvidenceLoadStage {
    SourceInventory,
    NativeEvidence,
    ColdExtraction,
    ProjectEvidenceFinalization,
}

impl ProjectEvidenceLoadStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceInventory => "source_inventory",
            Self::NativeEvidence => "native_evidence",
            Self::ColdExtraction => "cold_extraction",
            Self::ProjectEvidenceFinalization => "project_evidence_finalization",
        }
    }
}

/// Every stage in one fresh project-evidence read, in execution order.
pub const STAGE_CENSUS: [ProjectEvidenceLoadStage; 4] = [
    ProjectEvidenceLoadStage::SourceInventory,
    ProjectEvidenceLoadStage::NativeEvidence,
    ProjectEvidenceLoadStage::ColdExtraction,
    ProjectEvidenceLoadStage::ProjectEvidenceFinalization,
];

fn stage_census_index(stage: ProjectEvidenceLoadStage) -> usize {
    STAGE_CENSUS
        .iter()
        .position(|candidate| *candidate == stage)
        .unwrap_or(usize::MAX)
}

/// The recorded fate of a single gated stage in a project-evidence load.
///
/// `Ran`, `Skipped`, and `NotReached` are mutually exclusive by construction
/// (`#[serde(tag = "kind", ...)]`) and each carry exactly one detail field —
/// `outcome`, `reason`, or `blocked_by` respectively.
///
/// `Skipped` and `NotReached` remain available for future conditional stages.
/// Their classification uses `"<kind>:<detail>"`; split only on the first colon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StageDisposition {
    Ran { outcome: String },
    Skipped { reason: String },
    NotReached { blocked_by: String },
}

impl StageDisposition {
    pub fn reason_code(&self) -> &str {
        match self {
            Self::Ran { outcome } => outcome,
            Self::Skipped { reason } => reason,
            Self::NotReached { blocked_by } => blocked_by,
        }
    }

    fn classification(&self) -> String {
        match self {
            Self::Ran { outcome } => outcome.clone(),
            Self::Skipped { reason } => format!("skipped:{reason}"),
            Self::NotReached { blocked_by } => format!("not_reached:{blocked_by}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ProjectEvidenceStageTiming {
    pub stage: ProjectEvidenceLoadStage,
    pub stage_elapsed_ms: u64,
    pub load_elapsed_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProjectEvidenceStageAccounting {
    pub stage: ProjectEvidenceLoadStage,
    pub stage_elapsed_ms: u64,
    pub load_elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    pub disposition: StageDisposition,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub counters: BTreeMap<String, u64>,
}

impl ProjectEvidenceStageAccounting {
    fn timing(&self) -> ProjectEvidenceStageTiming {
        ProjectEvidenceStageTiming {
            stage: self.stage,
            stage_elapsed_ms: self.stage_elapsed_ms,
            load_elapsed_ms: self.load_elapsed_ms,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ProjectEvidenceLoadAccounting {
    pub total_elapsed_ms: u64,
    pub stages: Vec<ProjectEvidenceStageAccounting>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocking_stage: Option<ProjectEvidenceLoadStage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
}

fn stage_accounting_json(accounting: &ProjectEvidenceStageAccounting) -> serde_json::Value {
    serde_json::json!({
        "stage": accounting.stage.as_str(),
        "stage_elapsed_ms": accounting.stage_elapsed_ms,
        "load_elapsed_ms": accounting.load_elapsed_ms,
        "classification": accounting.classification.as_ref(),
        "disposition": &accounting.disposition,
        "reason_code": &accounting.reason_code,
        "counters": &accounting.counters,
    })
}

/// Renders [`ProjectEvidenceLoadAccounting`] as JSON.
///
/// Lives here (not in the `mcp`-gated `context_stream` module) because
/// callers outside the `mcp` feature — e.g. `cli.rs`'s
/// `project_load_outcome_query_evidence` — need this unconditionally. The
/// `context_stream` module re-uses this same function rather than defining
/// its own, so the two consumers can never drift in JSON shape.
pub(crate) fn load_accounting_json(
    accounting: &ProjectEvidenceLoadAccounting,
) -> serde_json::Value {
    serde_json::json!({
        "total_elapsed_ms": accounting.total_elapsed_ms,
        "stages": accounting
            .stages
            .iter()
            .map(stage_accounting_json)
            .collect::<Vec<_>>(),
        "blocking_stage": accounting.blocking_stage.map(|stage| stage.as_str()),
        "fallback_reason": accounting.fallback_reason.as_ref(),
    })
}

pub(super) struct ProjectEvidenceLoadAccountingBuilder {
    started: Instant,
    stages: Vec<ProjectEvidenceStageAccounting>,
}

impl ProjectEvidenceLoadAccountingBuilder {
    pub(super) fn new() -> Self {
        Self {
            started: Instant::now(),
            stages: Vec::new(),
        }
    }

    pub(super) fn marker(&self, stage: ProjectEvidenceLoadStage) -> ProjectEvidenceStageTiming {
        ProjectEvidenceStageTiming {
            stage,
            stage_elapsed_ms: 0,
            load_elapsed_ms: elapsed_ms_since(self.started),
        }
    }

    /// Records one stage in the fresh-read pipeline.
    pub(super) fn finish_stage(
        &mut self,
        stage: ProjectEvidenceLoadStage,
        stage_started: Instant,
        classification: impl Into<Option<String>>,
        disposition: StageDisposition,
        counters: BTreeMap<String, u64>,
    ) -> ProjectEvidenceStageTiming {
        let reason_code = disposition.reason_code().to_string();
        let accounting = ProjectEvidenceStageAccounting {
            stage,
            stage_elapsed_ms: elapsed_ms_since(stage_started),
            load_elapsed_ms: elapsed_ms_since(self.started),
            classification: classification.into(),
            disposition,
            reason_code,
            counters,
        };
        let timing = accounting.timing();
        debug_assert!(
            self.stages.iter().all(|existing| existing.stage != stage),
            "project evidence stage {stage:?} recorded twice"
        );
        self.stages.push(accounting);
        timing
    }

    pub(super) fn complete(
        &mut self,
        classification: impl Into<String>,
    ) -> ProjectEvidenceLoadAccounting {
        let classification = classification.into();
        self.backfill_missing_census_stages(&classification);
        let finalization_started = Instant::now();
        self.finish_stage(
            ProjectEvidenceLoadStage::ProjectEvidenceFinalization,
            finalization_started,
            Some(classification.clone()),
            StageDisposition::Ran {
                outcome: classification,
            },
            BTreeMap::new(),
        );
        self.debug_assert_stage_census_uniqueness();
        self.summary()
    }

    /// Gives every pipeline stage an explicit outcome in successful reports.
    fn backfill_missing_census_stages(&mut self, blocked_by: &str) {
        let present: std::collections::HashSet<ProjectEvidenceLoadStage> =
            self.stages.iter().map(|stage| stage.stage).collect();
        let load_elapsed_ms = elapsed_ms_since(self.started);
        for stage in STAGE_CENSUS {
            if stage == ProjectEvidenceLoadStage::ProjectEvidenceFinalization
                || present.contains(&stage)
            {
                continue;
            }
            let disposition = StageDisposition::NotReached {
                blocked_by: blocked_by.to_string(),
            };
            let reason_code = disposition.reason_code().to_string();
            let accounting = ProjectEvidenceStageAccounting {
                stage,
                stage_elapsed_ms: 0,
                load_elapsed_ms,
                classification: Some(disposition.classification()),
                disposition,
                reason_code,
                counters: BTreeMap::new(),
            };
            let insert_at = self
                .stages
                .iter()
                .position(|existing| stage_census_index(existing.stage) > stage_census_index(stage))
                .unwrap_or(self.stages.len());
            self.stages.insert(insert_at, accounting);
        }
    }

    fn debug_assert_stage_census_uniqueness(&self) {
        let mut seen = std::collections::HashSet::new();
        for stage in &self.stages {
            debug_assert!(
                seen.insert(stage.stage),
                "project evidence stage {:?} recorded more than once in one load's accounting: {:#?}",
                stage.stage,
                self.stages
            );
        }
    }

    fn summary(&self) -> ProjectEvidenceLoadAccounting {
        ProjectEvidenceLoadAccounting {
            total_elapsed_ms: elapsed_ms_since(self.started),
            stages: self.stages.clone(),
            blocking_stage: None,
            fallback_reason: None,
        }
    }
}

pub(super) fn source_inventory_stage_counters(
    metrics: &SourceInventoryMetrics,
) -> BTreeMap<String, u64> {
    let mut counters = BTreeMap::new();
    counters.insert("total_file_count".to_string(), metrics.total_file_count);
    counters.insert("walk_file_count".to_string(), metrics.walk_file_count);
    counters.insert("walk_inventory_ms".to_string(), metrics.walk_inventory_ms);
    counters.insert(
        "source_read_file_count".to_string(),
        metrics.source_read_file_count,
    );
    counters.insert(
        "source_read_byte_count".to_string(),
        metrics.source_read_byte_count,
    );
    counters
}

pub(super) fn native_evidence_stage_counters(
    working_set: &ProjectEvidenceWorkingSetSummary,
    source_byte_count: u64,
    language_counts: LanguageCounts,
    metrics: &SourceInventoryMetrics,
) -> BTreeMap<String, u64> {
    let mut counters = BTreeMap::new();
    counters.insert(
        "inventory_source_file_count".to_string(),
        working_set.inventory_source_file_count as u64,
    );
    counters.insert(
        "working_set_source_file_count".to_string(),
        working_set.source_file_count as u64,
    );
    counters.insert(
        "working_set_omitted_source_file_count".to_string(),
        working_set.omitted_source_file_count as u64,
    );
    counters.insert(
        "working_set_full_inventory".to_string(),
        u64::from(working_set.full_inventory),
    );
    counters.insert(
        "source_file_count".to_string(),
        working_set.source_file_count as u64,
    );
    counters.insert("source_byte_count".to_string(), source_byte_count);
    counters.insert(
        "typescript_file_count".to_string(),
        language_counts.typescript as u64,
    );
    counters.insert("rust_file_count".to_string(), language_counts.rust as u64);
    counters.insert(
        "python_file_count".to_string(),
        language_counts.python as u64,
    );
    counters.insert(
        "native_decode_file_count".to_string(),
        metrics.native_decode_file_count,
    );
    counters
}

pub(super) fn cold_extraction_started_stage_counters(
    source_file_count: usize,
    source_byte_count: u64,
    language_counts: LanguageCounts,
) -> BTreeMap<String, u64> {
    let mut counters = BTreeMap::new();
    counters.insert("source_file_count".to_string(), source_file_count as u64);
    counters.insert("source_byte_count".to_string(), source_byte_count);
    counters.insert(
        "typescript_file_count".to_string(),
        language_counts.typescript as u64,
    );
    counters.insert("rust_file_count".to_string(), language_counts.rust as u64);
    counters.insert(
        "python_file_count".to_string(),
        language_counts.python as u64,
    );
    counters
}

pub(super) fn cold_extraction_finished_stage_counters(
    project: &CodebaseSnapshot,
) -> BTreeMap<String, u64> {
    let mut counters = cold_extraction_started_stage_counters(
        project.source_file_count,
        project.source_byte_count,
        project.language_counts,
    );
    counters.insert(
        "diagnostic_count".to_string(),
        project.diagnostics.len() as u64,
    );
    counters.insert("warning_count".to_string(), project.warnings.len() as u64);
    counters
}

fn elapsed_ms_since(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
