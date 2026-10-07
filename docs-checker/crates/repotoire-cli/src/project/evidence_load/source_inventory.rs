use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::time::Instant;

use crate::deadline::RequestDeadline;

use super::super::{
    prepare_source_inventory, LoadOptions, ProjectEvidenceStageTiming, SourceInventoryPreparation,
    SourceInventoryRead,
};
use super::{ProjectEvidenceLoadAccountingBuilder, ProjectEvidenceLoadStage, StageDisposition};

pub(in crate::project) struct SourceInventoryStageInput<'a> {
    pub root: &'a Path,
    pub options: LoadOptions,
    pub explicit_file_tasks: &'a [String],
    pub file_task_admission: crate::walk::FileTaskAdmission,
    pub deadline: RequestDeadline,
}

pub(in crate::project) struct SourceInventoryStageOutcome {
    pub prepared: SourceInventoryPreparation,
    pub captured_filesystem: BTreeMap<String, crate::walk::CapturedFilesystemEntry>,
    pub source_inventory: SourceInventoryRead,
    pub stage_timing: ProjectEvidenceStageTiming,
}

pub(in crate::project) fn run_source_inventory_stage(
    input: SourceInventoryStageInput<'_>,
    accounting: &mut ProjectEvidenceLoadAccountingBuilder,
) -> io::Result<SourceInventoryStageOutcome> {
    let started = Instant::now();
    let prepared = prepare_source_inventory(
        input.root,
        input.options,
        input.explicit_file_tasks,
        input.file_task_admission,
        input.deadline,
    )?;
    let captured_filesystem = prepared.inventory.captured_filesystem.clone();
    let source_inventory = SourceInventoryRead {
        metrics: super::super::SourceInventoryMetrics {
            total_file_count: prepared.walk_file_count,
            walk_file_count: prepared.walk_file_count,
            walk_inventory_ms: prepared.walk_inventory_ms,
            source_read_file_count: prepared.inventory.metrics.source_read_file_count,
            source_read_byte_count: prepared.inventory.metrics.source_read_byte_count,
            ..Default::default()
        },
    };
    let classification = "fresh_repository_inventory".to_string();
    let stage_timing = accounting.finish_stage(
        ProjectEvidenceLoadStage::SourceInventory,
        started,
        Some(classification.clone()),
        StageDisposition::Ran {
            outcome: classification,
        },
        super::source_inventory_stage_counters(&source_inventory.metrics),
    );
    Ok(SourceInventoryStageOutcome {
        prepared,
        captured_filesystem,
        source_inventory,
        stage_timing,
    })
}
