use std::collections::{BTreeMap, HashSet};
use std::io;
use std::time::Instant;

use crate::deadline::RequestDeadline;

use super::super::{
    native_evidence_units::{
        load_native_evidence_units, NativeEvidenceLoadScope, NativeEvidenceUnitLoad,
        NativeEvidenceUnits,
    },
    LanguageCounts, ProjectEvidenceDeclarationInventory, ProjectEvidenceStageTiming,
    ProjectEvidenceWorkingSetSummary, SourceInventoryRead,
};
use super::{ProjectEvidenceLoadAccountingBuilder, ProjectEvidenceLoadStage, StageDisposition};
use crate::walk;
#[cfg(test)]
use repotoire::source_pipeline::SourceLanguage;
use repotoire::source_role::SourceRole;

pub(in crate::project) struct NativeEvidenceStageInput<'a> {
    pub inventory: walk::WalkInventoryOutput,
    pub load_scope: NativeEvidenceLoadScope,
    pub working_set_extra_paths: &'a HashSet<String>,
    pub source_inventory: &'a mut SourceInventoryRead,
    pub deadline: RequestDeadline,
}

pub(in crate::project) struct NativeEvidenceStageResult {
    pub outcome: NativeEvidenceStageOutcome,
    pub stage_timing: ProjectEvidenceStageTiming,
}

pub(in crate::project) struct NativeEvidenceStageOutcome {
    pub native: NativeEvidenceUnits,
    pub working_set: ProjectEvidenceWorkingSetSummary,
    pub source_file_count: usize,
    pub source_byte_count: u64,
    pub language_counts: LanguageCounts,
    pub declaration_readiness: NativeEvidenceDeclarationReadiness,
}

pub(in crate::project) struct NativeEvidenceDeclarationReadiness {
    pub declaration_inventory: ProjectEvidenceDeclarationInventory,
    pub source_role_complete: bool,
    pub source_role_counts: BTreeMap<String, u64>,
    pub classification: String,
}

impl NativeEvidenceDeclarationReadiness {
    fn from_native(native: &NativeEvidenceUnits) -> Self {
        let declaration_inventory = native.declaration_inventory();
        let (source_role_complete, source_role_counts) = native
            .complete_source_roles()
            .map(|source_roles| (true, source_role_counts(source_roles.as_map())))
            .unwrap_or_else(|_| (false, BTreeMap::new()));
        let mut classification = if source_role_complete {
            "declarations_ready:source_roles_complete"
        } else {
            "declarations_ready:source_roles_incomplete"
        }
        .to_string();
        if !native.is_full_inventory() {
            classification.push_str(":context_orientation_working_set");
        }
        Self {
            declaration_inventory,
            source_role_complete,
            source_role_counts,
            classification,
        }
    }
}

pub(in crate::project) fn run_native_evidence_stage(
    input: NativeEvidenceStageInput<'_>,
    accounting: &mut ProjectEvidenceLoadAccountingBuilder,
) -> io::Result<NativeEvidenceStageResult> {
    let NativeEvidenceStageInput {
        inventory,
        load_scope,
        working_set_extra_paths,
        source_inventory,
        deadline,
    } = input;
    let started = Instant::now();
    let native = load_native_evidence_units(NativeEvidenceUnitLoad {
        inventory,
        load_scope,
        working_set_extra_paths,
        metrics: &mut source_inventory.metrics,
        deadline,
    })?;
    let source_file_count = native.source_file_count();
    let source_byte_count = native.source_byte_count;
    let language_counts = native.language_counts;
    let working_set = native.working_set_summary();
    let declaration_readiness = NativeEvidenceDeclarationReadiness::from_native(&native);
    let classification = native.load_scope.stage_classification().to_string();
    let stage_timing = accounting.finish_stage(
        ProjectEvidenceLoadStage::NativeEvidence,
        started,
        Some(classification.clone()),
        StageDisposition::Ran {
            outcome: classification,
        },
        super::native_evidence_stage_counters(
            &working_set,
            source_byte_count,
            language_counts,
            &source_inventory.metrics,
        ),
    );
    Ok(NativeEvidenceStageResult {
        outcome: NativeEvidenceStageOutcome {
            native,
            working_set,
            source_file_count,
            source_byte_count,
            language_counts,
            declaration_readiness,
        },
        stage_timing,
    })
}

fn source_role_counts(
    source_roles_by_rel_path: &BTreeMap<String, SourceRole>,
) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for role in source_roles_by_rel_path.values() {
        *counts.entry(role.as_str().to_string()).or_insert(0) += 1;
    }
    counts
}
