use std::io;
use std::path::Path;
use std::time::Instant;

use crate::deadline::RequestDeadline;

use super::super::{
    cold_extract_codebase_snapshot, native_evidence_units::NativeEvidenceUnits, CodebaseSnapshot,
    LanguageCounts, LoadOptions, ProjectEvidenceStageTiming,
};
use super::{ProjectEvidenceLoadAccountingBuilder, ProjectEvidenceLoadStage, StageDisposition};

pub(in crate::project) struct ColdExtractionStageStart {
    pub source_file_count: usize,
    pub source_byte_count: u64,
    pub language_counts: LanguageCounts,
    pub stage_timing: ProjectEvidenceStageTiming,
}

pub(in crate::project) struct ColdExtractionStageInput<'a> {
    pub root: &'a Path,
    pub options: LoadOptions,
    pub native: NativeEvidenceUnits,
    pub deadline: RequestDeadline,
}

pub(in crate::project) struct ColdExtractionStageOutcome {
    pub snapshot: CodebaseSnapshot,
    pub stage_timing: ProjectEvidenceStageTiming,
}

pub(in crate::project) fn prepare_cold_extraction_stage(
    accounting: &ProjectEvidenceLoadAccountingBuilder,
    native: &NativeEvidenceUnits,
) -> ColdExtractionStageStart {
    ColdExtractionStageStart {
        source_file_count: native.source_file_count(),
        source_byte_count: native.source_byte_count,
        language_counts: native.language_counts,
        stage_timing: accounting.marker(ProjectEvidenceLoadStage::ColdExtraction),
    }
}

pub(in crate::project) fn run_cold_extraction_stage(
    input: ColdExtractionStageInput<'_>,
    accounting: &mut ProjectEvidenceLoadAccountingBuilder,
) -> io::Result<ColdExtractionStageOutcome> {
    let ColdExtractionStageInput {
        root,
        options,
        native,
        deadline,
    } = input;
    let started = Instant::now();
    let snapshot = cold_extract_codebase_snapshot(root, options, native, deadline)?;
    let stage_timing = accounting.finish_stage(
        ProjectEvidenceLoadStage::ColdExtraction,
        started,
        Some("finished".to_string()),
        StageDisposition::Ran {
            outcome: "finished".to_string(),
        },
        super::cold_extraction_finished_stage_counters(&snapshot),
    );
    Ok(ColdExtractionStageOutcome {
        snapshot,
        stage_timing,
    })
}
