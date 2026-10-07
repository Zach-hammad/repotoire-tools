use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use repotoire::ids::NodeId;
use repotoire::impact::evidence::{self, ImpactResolution, Limitation};
use repotoire::schema::EdgeKind;
use repotoire::ts::diagnostics::Diagnostic;

use super::{CodebaseView, PathEvidence};

const MAX_TASK_RELATIONSHIPS: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TaskViewTarget {
    File(String),
    Symbol(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TaskRelationship {
    pub(crate) kind: String,
    pub(crate) source_name: String,
    pub(crate) source_file: String,
    pub(crate) target_name: String,
    pub(crate) target_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskSymbolCandidate {
    pub(crate) file: String,
    pub(crate) line: u32,
    pub(crate) name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TaskViewError {
    SymbolNotFound {
        query: String,
    },
    AmbiguousSymbol {
        query: String,
        candidates: Vec<TaskSymbolCandidate>,
    },
    NonUniqueSymbol {
        query: String,
        declaration_count: usize,
    },
    SourceUnavailable {
        path: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskCodebaseView {
    pub(super) origin_root: PathBuf,
    pub(super) origin_identity: super::DirectoryIdentity,
    pub(super) target_file: String,
    pub(super) target_symbol: Option<String>,
    pub(super) target_line: Option<u32>,
    pub(super) target_state: PathEvidence,
    pub(super) sources: BTreeMap<String, Vec<u8>>,
    pub(super) relationships: Vec<TaskRelationship>,
    pub(super) omitted_relationship_count: usize,
    pub(super) diagnostics: Vec<Diagnostic>,
    pub(super) limitations: Vec<Limitation>,
}

impl CodebaseView {
    pub(crate) fn task_view(
        &self,
        target: TaskViewTarget,
    ) -> Result<TaskCodebaseView, TaskViewError> {
        match target {
            TaskViewTarget::File(path) => self.file_task_view(path),
            TaskViewTarget::Symbol(query) => self.symbol_task_view(query),
        }
    }

    fn file_task_view(&self, target_file: String) -> Result<TaskCodebaseView, TaskViewError> {
        let requested_target = target_file;
        let target_file =
            crate::walk::canonical_explicit_file_task(&requested_target).map_err(|_| {
                TaskViewError::SourceUnavailable {
                    path: requested_target.clone(),
                }
            })?;
        let graph = self.graph();
        let target_nodes = (0..graph.node_count())
            .map(NodeId::from_raw)
            .filter(|node| node_file(&graph, *node).as_deref() == Some(target_file.as_str()))
            .collect::<Vec<_>>();
        let RelationshipSelection {
            displayed: relationships,
            supporting_files: mut selected_paths,
            omitted_count: omitted_relationship_count,
        } = direct_relationships_for_nodes(&graph, target_nodes);
        selected_paths.insert(target_file.clone());

        self.build_task_view(
            target_file,
            None,
            None,
            relationships,
            omitted_relationship_count,
            selected_paths,
            evidence::standard_limitations(),
        )
    }

    fn resolve_task_symbol(
        &self,
        query: String,
    ) -> Result<Box<evidence::ImpactEvidence>, TaskViewError> {
        let bundle = self.source_bundle();
        let evidence = match evidence::extract_evidence_for_symbol(&bundle, &query) {
            ImpactResolution::Found(evidence) => evidence,
            ImpactResolution::Ambiguous { candidates, .. } => {
                return Err(TaskViewError::AmbiguousSymbol {
                    query,
                    candidates: candidates
                        .into_iter()
                        .map(|candidate| TaskSymbolCandidate {
                            file: candidate.file,
                            line: candidate.line,
                            name: candidate.name,
                        })
                        .collect(),
                });
            }
            ImpactResolution::NotFound { .. } => {
                return Err(TaskViewError::SymbolNotFound { query });
            }
        };

        let symbol_name = evidence::symbol_name_from_arg(&query);
        if symbol_name == query {
            let declaration_count = evidence::same_name_declaration_census(&bundle, symbol_name);
            if declaration_count > 1 {
                return Err(TaskViewError::NonUniqueSymbol {
                    query,
                    declaration_count,
                });
            }
        }

        Ok(evidence)
    }

    fn symbol_task_view(&self, query: String) -> Result<TaskCodebaseView, TaskViewError> {
        let evidence = self.resolve_task_symbol(query.clone())?;
        let bundle = self.source_bundle();
        let definition = evidence
            .definition
            .as_ref()
            .expect("a single evidence lookup always has a definition");
        let graph = self.graph();
        let RelationshipSelection {
            displayed: relationships,
            supporting_files: mut selected_paths,
            omitted_count: omitted_relationship_count,
        } = direct_relationships_for_nodes(&graph, evidence::resolve_symbol_nodes(&bundle, &query));
        selected_paths.insert(definition.file.clone());
        selected_paths.extend(
            evidence
                .imports
                .iter()
                .map(|relation| relation.file.clone()),
        );
        selected_paths.extend(
            evidence
                .exports
                .iter()
                .map(|relation| relation.file.clone()),
        );
        selected_paths.extend(evidence.uses.iter().map(|relation| relation.file.clone()));

        self.build_task_view(
            definition.file.clone(),
            Some(definition.name.clone()),
            Some(definition.line),
            relationships,
            omitted_relationship_count,
            selected_paths,
            evidence.limitations,
        )
    }

    fn build_task_view(
        &self,
        target_file: String,
        target_symbol: Option<String>,
        target_line: Option<u32>,
        relationships: Vec<TaskRelationship>,
        omitted_relationship_count: usize,
        selected_paths: BTreeSet<String>,
        limitations: Vec<Limitation>,
    ) -> Result<TaskCodebaseView, TaskViewError> {
        let available_sources: BTreeMap<_, _> = self
            .source_file_refs()
            .into_iter()
            .map(|source| (source.path, source.bytes))
            .collect();
        let captured_target = captured_target(&self.captured_filesystem, &target_file)?;
        let target_state = if available_sources.contains_key(target_file.as_str()) {
            PathEvidence::RegularFile
        } else if let Some(captured_target) = captured_target {
            captured_entry_state(captured_target)
        } else if self.explicit_file_tasks.contains(&target_file) {
            PathEvidence::Absent
        } else {
            return Err(TaskViewError::SourceUnavailable { path: target_file });
        };
        let mut sources = BTreeMap::new();
        for path in selected_paths {
            if let Some(bytes) = available_sources.get(path.as_str()) {
                sources.insert(path, bytes.to_vec());
                continue;
            }
            if path == target_file && target_state == PathEvidence::Absent {
                continue;
            }
            if path == target_file {
                if let Some(crate::walk::CapturedFilesystemEntry::RegularFile(Some(bytes))) =
                    captured_target
                {
                    sources.insert(path, bytes.clone());
                    continue;
                }
            }
            return Err(TaskViewError::SourceUnavailable { path });
        }

        let diagnostics = self
            .diagnostics()
            .iter()
            .filter(|diagnostic| sources.contains_key(&diagnostic.file_path))
            .cloned()
            .collect();

        Ok(TaskCodebaseView {
            origin_root: self.root.clone(),
            origin_identity: self.root_identity.clone(),
            target_file,
            target_symbol,
            target_line,
            target_state,
            sources,
            relationships,
            omitted_relationship_count,
            diagnostics,
            limitations,
        })
    }
}

fn captured_entry_state(entry: &crate::walk::CapturedFilesystemEntry) -> PathEvidence {
    match entry {
        crate::walk::CapturedFilesystemEntry::RegularFile(_) => PathEvidence::RegularFile,
        crate::walk::CapturedFilesystemEntry::Directory => PathEvidence::Directory,
        crate::walk::CapturedFilesystemEntry::Symlink => PathEvidence::Symlink,
        crate::walk::CapturedFilesystemEntry::Other => PathEvidence::Other,
        crate::walk::CapturedFilesystemEntry::Unreadable(error) => {
            PathEvidence::Unreadable((*error).into())
        }
    }
}

fn captured_target<'a>(
    captured: &'a BTreeMap<String, crate::walk::CapturedFilesystemEntry>,
    target: &str,
) -> Result<Option<&'a crate::walk::CapturedFilesystemEntry>, TaskViewError> {
    for ancestor in std::path::Path::new(target).ancestors().skip(1) {
        let ancestor = ancestor
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        if ancestor.is_empty() {
            continue;
        }
        match captured.get(&ancestor) {
            Some(crate::walk::CapturedFilesystemEntry::Directory) => {}
            Some(
                crate::walk::CapturedFilesystemEntry::RegularFile(_)
                | crate::walk::CapturedFilesystemEntry::Symlink
                | crate::walk::CapturedFilesystemEntry::Other
                | crate::walk::CapturedFilesystemEntry::Unreadable(_),
            ) => {
                return Err(TaskViewError::SourceUnavailable {
                    path: target.to_string(),
                });
            }
            None => {}
        }
    }
    Ok(captured.get(target))
}

impl TaskCodebaseView {
    /// Identity of captured task sources, including explicit non-code bytes.
    /// This does not replace full task equality or the graph witness snapshot.
    pub(crate) fn source_sha256(&self) -> std::io::Result<String> {
        let state = match self.target_state {
            PathEvidence::Absent => "absent",
            PathEvidence::RegularFile => "regular_file",
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "task target is not an admissible source state",
                ));
            }
        };
        let sources = self
            .sources
            .iter()
            .map(|(path, bytes)| (path, repotoire::hash::sha256_hex(bytes)))
            .collect::<Vec<_>>();
        let bytes = serde_json::to_vec(&(
            "repotoire.task_sources.v1",
            &self.target_file,
            state,
            sources,
        ))
        .map_err(std::io::Error::other)?;
        Ok(repotoire::hash::sha256_hex(&bytes))
    }

    pub(crate) fn target_file(&self) -> &str {
        &self.target_file
    }

    pub(crate) fn target_symbol(&self) -> Option<&str> {
        self.target_symbol.as_deref()
    }

    pub(crate) fn target_line(&self) -> Option<u32> {
        self.target_line
    }

    pub(crate) fn source_paths(&self) -> Vec<&str> {
        self.sources.keys().map(String::as_str).collect()
    }

    pub(crate) fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub(crate) fn relationships(&self) -> &[TaskRelationship] {
        &self.relationships
    }

    pub(crate) fn omitted_relationship_count(&self) -> usize {
        self.omitted_relationship_count
    }

    pub(crate) fn limitations(&self) -> &[Limitation] {
        &self.limitations
    }
}

struct RelationshipSelection {
    displayed: Vec<TaskRelationship>,
    supporting_files: BTreeSet<String>,
    omitted_count: usize,
}

fn direct_relationships_for_nodes(
    graph: &repotoire::csr::CodeGraph<'_>,
    nodes: Vec<NodeId>,
) -> RelationshipSelection {
    let mut relationships = BTreeSet::new();
    let mut seen_edges = BTreeSet::new();
    let mut unprojectable_relationship_count = 0;
    for node in nodes {
        for kind in EdgeKind::ALL {
            let outgoing = graph
                .out_slots(node, kind)
                .map(|slot| (node, graph.out_target(kind, slot)));
            let incoming = graph
                .in_slots(node, kind)
                .map(|slot| (graph.in_source(kind, slot), node));
            for (source, target) in outgoing.chain(incoming) {
                if !seen_edges.insert((kind as u16, source, target)) {
                    continue;
                }
                match project_relationship(graph, kind, source, target) {
                    RelationshipProjection::Projected(relationship) => {
                        relationships.insert(relationship);
                    }
                    RelationshipProjection::SameFile => {}
                    RelationshipProjection::Unprojectable => {
                        unprojectable_relationship_count += 1;
                    }
                }
            }
        }
    }
    let total = relationships.len();
    let supporting_files = relationships
        .iter()
        .flat_map(|relationship| {
            [
                relationship.source_file.clone(),
                relationship.target_file.clone(),
            ]
        })
        .collect();
    let displayed = relationships
        .into_iter()
        .take(MAX_TASK_RELATIONSHIPS)
        .collect::<Vec<_>>();
    RelationshipSelection {
        displayed,
        supporting_files,
        omitted_count: unprojectable_relationship_count
            + total.saturating_sub(MAX_TASK_RELATIONSHIPS),
    }
}

enum RelationshipProjection {
    Projected(TaskRelationship),
    SameFile,
    Unprojectable,
}

fn project_relationship(
    graph: &repotoire::csr::CodeGraph<'_>,
    kind: EdgeKind,
    source: NodeId,
    target: NodeId,
) -> RelationshipProjection {
    let (Some(source_file), Some(target_file)) =
        (node_file(graph, source), node_file(graph, target))
    else {
        return RelationshipProjection::Unprojectable;
    };
    if source_file == target_file {
        return RelationshipProjection::SameFile;
    }

    RelationshipProjection::Projected(TaskRelationship {
        kind: format!("{kind:?}"),
        source_name: graph.node_name(source).to_string(),
        source_file,
        target_name: graph.node_name(target).to_string(),
        target_file,
    })
}

fn node_file(graph: &repotoire::csr::CodeGraph<'_>, node: NodeId) -> Option<String> {
    graph
        .file_of(node)
        .map(|file| graph.node_name(file).to_string())
}
