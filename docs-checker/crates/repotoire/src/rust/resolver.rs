use crate::builder::GraphBuilder;
use crate::ids::NodeId;
use crate::rust::events::{
    ParsedFile, RustItem, RustItemKind, RustPathRefKind, RustRef, RustRefTarget, RustUseBinding,
    RustValueScopeIndex, RustVisibility,
};
use crate::rust::parser::{parse_file, RustParseError, RustParseMode, RustParseOptions};
use crate::schema::{EdgeKind, ExternalOrigin, NodeKind};
use crate::spans::{NodeSpans, SourceEncodingError};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug)]
pub struct ExtractResult {
    pub file_ids: Vec<NodeId>,
    /// Loud coverage signal: clearly-unbound free-function calls that did not
    /// bind to any known local declaration or import. Mirrors the TS resolver so
    /// doctor and coverage surfaces can report what repotoire could not see,
    /// instead of presenting a confident, complete-looking answer. Emitted very
    /// conservatively — only single-segment (non-`::`, non-method) call refs
    /// that are not a known prelude function — to keep false positives low.
    /// Uses the shared `ts::diagnostics::Diagnostic` type the project loader and
    /// doctor already consume.
    pub diagnostics: Vec<crate::ts::diagnostics::Diagnostic>,
}

#[derive(Debug, Default)]
pub struct ExtractOptions {
    pub edition: crate::rust::RustEdition,
    pub crate_roots: BTreeMap<String, String>,
    /// Cargo-declared external crate aliases keyed by the exact graph path of
    /// the Rust source file they belong to. Dependency authority is package
    /// scoped: one workspace member must never authorize another member's
    /// qualified trait reference.
    pub external_crates_by_path: BTreeMap<String, BTreeSet<String>>,
    pub module_paths: BTreeMap<String, String>,
    pub module_path_aliases: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Copy)]
pub struct NativeEvidenceUnit<'a> {
    pub path: &'a str,
    pub bytes: &'a [u8],
    pub parsed: &'a ParsedFile,
}

#[derive(Debug)]
pub enum ExtractError {
    LengthMismatch {
        files_len: usize,
        parsed_len: usize,
    },
    SourceEncoding {
        path: String,
        invalid_byte_offset: usize,
    },
    Parse {
        path: String,
        source: RustParseError,
    },
    DuplicatePath {
        path: String,
    },
}

impl From<SourceEncodingError> for ExtractError {
    fn from(e: SourceEncodingError) -> Self {
        let SourceEncodingError::NotUtf8 {
            path,
            invalid_byte_offset,
        } = e;
        ExtractError::SourceEncoding {
            path,
            invalid_byte_offset,
        }
    }
}

pub fn extract_project(
    builder: &mut GraphBuilder,
    files: &[(&str, &[u8])],
    options: &ExtractOptions,
) -> Result<ExtractResult, ExtractError> {
    let parsed = files
        .iter()
        .map(|(path, bytes)| {
            match parse_file(
                path,
                bytes,
                RustParseOptions {
                    edition: options.edition,
                    mode: RustParseMode::Complete,
                },
            ) {
                Ok(parsed) => Ok(parsed),
                Err(RustParseError::SourceEncoding {
                    invalid_byte_offset,
                }) => Err(ExtractError::SourceEncoding {
                    path: (*path).to_string(),
                    invalid_byte_offset,
                }),
                Err(source) => Err(ExtractError::Parse {
                    path: (*path).to_string(),
                    source,
                }),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    resolve_and_emit(builder, files, &parsed, options)
}

pub fn resolve_and_emit(
    builder: &mut GraphBuilder,
    files: &[(&str, &[u8])],
    parsed: &[ParsedFile],
    options: &ExtractOptions,
) -> Result<ExtractResult, ExtractError> {
    if files.len() != parsed.len() {
        return Err(ExtractError::LengthMismatch {
            files_len: files.len(),
            parsed_len: parsed.len(),
        });
    }

    let units = files
        .iter()
        .zip(parsed.iter())
        .map(|((path, bytes), parsed)| NativeEvidenceUnit {
            path,
            bytes,
            parsed,
        })
        .collect::<Vec<_>>();
    resolve_native_evidence_units(builder, &units, options)
}

pub fn resolve_native_evidence_units(
    builder: &mut GraphBuilder,
    units: &[NativeEvidenceUnit<'_>],
    options: &ExtractOptions,
) -> Result<ExtractResult, ExtractError> {
    let files = units
        .iter()
        .map(|unit| (unit.path, unit.bytes))
        .collect::<Vec<_>>();
    let parsed = units.iter().map(|unit| unit.parsed).collect::<Vec<_>>();

    let mut file_ids = Vec::with_capacity(files.len());
    let mut path_to_file = BTreeMap::new();
    for (idx, (path, bytes)) in files.iter().enumerate() {
        let normalized = normalize_graph_path(path);
        if path_to_file.contains_key(&normalized) {
            return Err(ExtractError::DuplicatePath { path: normalized });
        }
        let file_id = builder.add_file(path, bytes)?;
        file_ids.push(file_id);
        path_to_file.insert(normalized, (idx, file_id));
    }

    let module_paths: Vec<String> = files
        .iter()
        .map(|(path, _)| {
            options
                .module_paths
                .get(*path)
                .cloned()
                .unwrap_or_else(|| module_path_for_file(path))
        })
        .collect();
    let mut crate_roots = rust_crate_roots(&module_paths);
    for (name, root) in &options.crate_roots {
        crate_roots
            .entry(name.clone())
            .or_insert_with(|| root.clone());
    }

    let module_scopes = effective_module_scopes(&parsed, &module_paths, &crate_roots);
    let mut item_index = ItemIndex {
        module_scopes,
        ..ItemIndex::default()
    };
    for (file_idx, pf) in parsed.iter().enumerate() {
        let file_id = file_ids[file_idx];
        let module_path = &module_paths[file_idx];
        let enclosing_scope = enclosing_module_scope(module_path, &item_index.module_scopes);
        let emission = ItemEmissionContext {
            file_id,
            crate_roots: &crate_roots,
        };
        for item in &pf.items {
            emit_item(
                builder,
                item,
                ItemParent {
                    node: None,
                    kind: None,
                    path: module_path,
                },
                module_path,
                &enclosing_scope,
                &emission,
                &mut item_index,
            );
        }
        if let Some(aliases) = options.module_path_aliases.get(files[file_idx].0) {
            for alias in aliases {
                for item in &pf.items {
                    index_item_aliases(
                        item,
                        ItemParent {
                            node: None,
                            kind: None,
                            path: module_path,
                        },
                        ItemParent {
                            node: None,
                            kind: None,
                            path: alias,
                        },
                        &mut item_index,
                    );
                }
            }
        }
    }

    let mut reexports = Vec::new();
    for (file_idx, pf) in parsed.iter().enumerate() {
        for use_item in &pf.uses {
            let use_module_path = join_use_path(&module_paths[file_idx], &use_item.module_suffix);
            collect_public_use_aliases(
                use_item,
                &use_module_path,
                &item_index,
                &crate_roots,
                &mut reexports,
            );
        }
    }
    for (path, target) in reexports {
        item_index.by_path.insert(path.clone(), target);
        item_index.all_by_path.insert(path, target);
    }
    collect_import_aliases(&parsed, &module_paths, &crate_roots, &mut item_index);

    for (file_idx, pf) in parsed.iter().enumerate() {
        for item in &pf.items {
            emit_public_impl_method_exports(
                builder,
                file_ids[file_idx],
                item,
                &module_paths[file_idx],
                &module_paths[file_idx],
                &item_index,
                &crate_roots,
                None,
            );
        }
    }

    let suffix_index = UniqueSuffixIndex::from_item_paths(&item_index.all_by_path);
    for (file_idx, pf) in parsed.iter().enumerate() {
        for item in &pf.items {
            emit_trait_impl_edges(
                builder,
                item,
                &module_paths[file_idx],
                &module_paths[file_idx],
                &item_index,
                &crate_roots,
            );
        }
    }

    let ref_resolver = RustRefResolver {
        item_index: &item_index,
        crate_roots: &crate_roots,
        suffix_index: &suffix_index,
    };
    let mut diagnostics: Vec<crate::ts::diagnostics::Diagnostic> = Vec::new();
    for (file_idx, pf) in parsed.iter().enumerate() {
        let file_id = file_ids[file_idx];
        let current_path = files[file_idx].0;
        let file_scope = RustFileScope::from_parsed_file(
            pf,
            &module_paths[file_idx],
            options
                .external_crates_by_path
                .get(current_path)
                .cloned()
                .unwrap_or_default(),
        );
        for item in &pf.items {
            emit_module_edges(builder, file_id, current_path, item, &path_to_file);
        }
        for use_item in &pf.uses {
            let use_module_path = join_use_path(&module_paths[file_idx], &use_item.module_suffix);
            emit_use_edge(
                builder,
                file_id,
                use_item,
                &use_module_path,
                &item_index,
                &crate_roots,
            );
        }
        for item in &pf.items {
            emit_call_edges(
                builder,
                file_id,
                item,
                None,
                &module_paths[file_idx],
                &module_paths[file_idx],
                &ref_resolver,
                &file_scope,
                current_path,
                &mut diagnostics,
            );
        }
    }

    Ok(ExtractResult {
        file_ids,
        diagnostics,
    })
}

#[derive(Clone, Copy)]
struct ItemParent<'a> {
    node: Option<NodeId>,
    kind: Option<RustItemKind>,
    path: &'a str,
}

struct ItemEmissionContext<'a> {
    file_id: NodeId,
    crate_roots: &'a BTreeMap<String, String>,
}

fn emit_item(
    builder: &mut GraphBuilder,
    item: &RustItem,
    parent: ItemParent<'_>,
    module_path: &str,
    enclosing_scope: &VisibilityScope,
    emission: &ItemEmissionContext<'_>,
    item_index: &mut ItemIndex,
) -> NodeId {
    let node_name = graph_item_name(item);
    let node = builder.add_node(
        node_kind_for_item(item.kind),
        &node_name,
        NodeSpans {
            name: Some(item.name_span),
            decl: Some(item.decl_span),
            body: item.body_span,
        },
    );
    builder.add_edge(
        parent.node.unwrap_or(emission.file_id),
        EdgeKind::Contains,
        node,
        Some(item.signature_span),
    );
    let visibility_scope = if parent.kind == Some(RustItemKind::Trait) {
        // Trait members have no independent visibility syntax. Their trait is
        // the visibility owner, so the parser's default `Private` projection
        // must not narrow them to the defining module.
        enclosing_scope.clone()
    } else {
        declared_visibility_scope(&item.visibility, module_path, emission.crate_roots)
            .intersect(enclosing_scope)
    };
    if visibility_scope.is_public() && is_use_addressable_item(item.kind) {
        builder.add_export_edge_with_label(
            emission.file_id,
            node,
            Some(item.name_span),
            false,
            &item.name,
        );
    }
    let item_path = join_use_path(parent.path, &item.name);
    let child_namespace_path = namespace_path_for_children(parent.path, item);
    let index_path = indexed_item_path(parent.path, item);
    item_index.all_by_path.insert(index_path, node);
    item_index
        .visibility_by_node
        .insert(node, visibility_scope.clone());
    if is_use_addressable_item(item.kind) && parent.kind != Some(RustItemKind::Trait) {
        insert_unique(&mut item_index.by_name, &item.name, node);
        item_index.by_path.insert(item_path.clone(), node);
    }
    if visibility_scope.is_public() && is_public_contract_type_kind(item.kind) {
        item_index.public_contract_type_nodes.insert(node);
    }
    let child_module_path = if item.kind == RustItemKind::Module {
        &item_path
    } else {
        module_path
    };
    let child_enclosing_scope = if matches!(item.kind, RustItemKind::Module | RustItemKind::Trait) {
        &visibility_scope
    } else {
        // `impl` and `extern` blocks are containers, not visibility owners.
        // Their children retain their own declared visibility within the
        // surrounding module scope.
        enclosing_scope
    };
    for child in &item.children {
        emit_item(
            builder,
            child,
            ItemParent {
                node: Some(node),
                kind: Some(item.kind),
                path: &child_namespace_path,
            },
            child_module_path,
            child_enclosing_scope,
            emission,
            item_index,
        );
    }
    node
}

#[allow(clippy::too_many_arguments)]
fn emit_public_impl_method_exports(
    builder: &mut GraphBuilder,
    file_id: NodeId,
    item: &RustItem,
    parent_path: &str,
    module_path: &str,
    item_index: &ItemIndex,
    crate_roots: &BTreeMap<String, String>,
    public_impl_target: Option<NodeId>,
) {
    let item_path = join_use_path(parent_path, &item.name);
    let child_namespace_path = namespace_path_for_children(parent_path, item);
    if item.kind == RustItemKind::Method
        && item.visibility.is_public()
        && public_impl_target.is_some()
    {
        if let Some(method_node) = item_index
            .all_by_path
            .get(&indexed_item_path(parent_path, item))
            .copied()
        {
            builder.add_export_edge_with_label(
                file_id,
                method_node,
                Some(item.name_span),
                false,
                &item.name,
            );
        }
    }

    let next_public_impl_target = if item.kind == RustItemKind::Impl {
        resolve_local_path_in_index(&item.name, module_path, item_index, crate_roots, true)
            .filter(|target| item_index.public_contract_type_nodes.contains(target))
    } else {
        None
    };
    let child_module_path = if item.kind == RustItemKind::Module {
        &item_path
    } else {
        module_path
    };
    for child in &item.children {
        emit_public_impl_method_exports(
            builder,
            file_id,
            child,
            &child_namespace_path,
            child_module_path,
            item_index,
            crate_roots,
            next_public_impl_target,
        );
    }
}

fn index_item_aliases(
    item: &RustItem,
    primary_parent: ItemParent<'_>,
    alias_parent: ItemParent<'_>,
    item_index: &mut ItemIndex,
) {
    let alias_item_path = join_use_path(alias_parent.path, &item.name);
    let primary_child_namespace_path = namespace_path_for_children(primary_parent.path, item);
    let alias_child_namespace_path = namespace_path_for_children(alias_parent.path, item);
    let primary_index_path = indexed_item_path(primary_parent.path, item);
    let alias_index_path = indexed_item_path(alias_parent.path, item);
    let Some(node) = item_index.all_by_path.get(&primary_index_path).copied() else {
        return;
    };
    item_index.all_by_path.insert(alias_index_path, node);
    if is_use_addressable_item(item.kind) && primary_parent.kind != Some(RustItemKind::Trait) {
        item_index.by_path.insert(alias_item_path.clone(), node);
    }
    for child in &item.children {
        index_item_aliases(
            child,
            ItemParent {
                node: Some(node),
                kind: Some(item.kind),
                path: &primary_child_namespace_path,
            },
            ItemParent {
                node: Some(node),
                kind: Some(item.kind),
                path: &alias_child_namespace_path,
            },
            item_index,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_call_edges(
    builder: &mut GraphBuilder,
    file_id: NodeId,
    item: &RustItem,
    parent: Option<NodeId>,
    parent_path: &str,
    module_path: &str,
    resolver: &RustRefResolver<'_>,
    file_scope: &RustFileScope,
    file_path: &str,
    diagnostics: &mut Vec<crate::ts::diagnostics::Diagnostic>,
) {
    let item_path = join_use_path(parent_path, &item.name);
    let child_namespace_path = namespace_path_for_children(parent_path, item);
    let owner = resolver
        .item_index
        .all_by_path
        .get(&indexed_item_path(parent_path, item))
        .copied()
        .unwrap_or_else(|| parent.unwrap_or(file_id));
    for reference in &item.refs {
        let resolution =
            resolve_rust_reference(reference, parent_path, module_path, resolver, file_scope);
        match &resolution.binding {
            RustResolution::InGraph(target) => {
                if *target != owner {
                    let edge_kind = edge_kind_for_reference(reference);
                    builder.add_edge(owner, edge_kind, *target, Some(reference.span));
                }
            }
            RustResolution::External(binding) => {
                let target = builder.add_external(
                    &binding.symbol,
                    ExternalOrigin::ImportedPackage,
                    Some(&binding.package),
                );
                if target != owner {
                    let edge_kind = edge_kind_for_reference(reference);
                    builder.add_edge(owner, edge_kind, target, Some(reference.span));
                }
            }
            RustResolution::Unresolved => {
                record_unresolved_rust_ref(
                    reference,
                    module_path,
                    file_path,
                    file_scope,
                    diagnostics,
                );
            }
        }
        if let Some(target) = resolution.qualifier {
            if !matches!(resolution.binding, RustResolution::InGraph(primary) if primary == target)
                && target != owner
            {
                builder.add_edge(owner, EdgeKind::ValueRef, target, Some(reference.span));
            }
        }
    }

    let child_module_path = if item.kind == RustItemKind::Module {
        &item_path
    } else {
        module_path
    };
    for child in &item.children {
        emit_call_edges(
            builder,
            file_id,
            child,
            Some(owner),
            &child_namespace_path,
            child_module_path,
            resolver,
            file_scope,
            file_path,
            diagnostics,
        );
    }
}

fn edge_kind_for_reference(reference: &RustRef) -> EdgeKind {
    match reference.target {
        RustRefTarget::Path {
            kind: RustPathRefKind::Call,
            ..
        }
        | RustRefTarget::MethodCall { .. }
        | RustRefTarget::QualifiedTraitCall { .. } => EdgeKind::Calls,
        RustRefTarget::Path {
            kind: RustPathRefKind::Value,
            ..
        } => EdgeKind::ValueRef,
        RustRefTarget::Path {
            kind: RustPathRefKind::Type,
            ..
        } => EdgeKind::TypeRef,
    }
}

/// Record a loud "I could not see this" diagnostic for a clearly-unbound
/// free-function call. Deliberately narrow to keep false positives near zero:
///
///   * method calls (`receiver: Some(..)`) are skipped — `.iter()`, `.unwrap()`
///     etc. essentially never bind to a local decl and would flood the report;
///   * `::`-qualified paths are skipped — `Vec::new`, `String::from`,
///     `crate::foo::bar` reach into std / other crates the graph need not model;
///   * value refs (non-calls) are skipped — bare `::` consts/enum variants are
///     too often std/prelude;
///   * known prelude free functions (`drop`, `default`, …) are skipped.
///
/// What survives is a single-segment free-function *call* with no receiver and
/// no path separator that resolved to nothing — almost always either a genuine
/// typo / missing import, or a function repotoire genuinely could not see.
fn record_unresolved_rust_ref(
    reference: &RustRef,
    current_module_path: &str,
    file_path: &str,
    file_scope: &RustFileScope,
    diagnostics: &mut Vec<crate::ts::diagnostics::Diagnostic>,
) {
    let name = match &reference.target {
        RustRefTarget::Path {
            path,
            kind: RustPathRefKind::Call,
        } if !path.contains("::") => path.as_str(),
        RustRefTarget::QualifiedTraitCall { method, .. } => {
            diagnostics.push(crate::ts::diagnostics::Diagnostic {
                kind: crate::ts::diagnostics::DiagnosticKind::UnresolvedReference {
                    name: method.clone(),
                    position: crate::ts::diagnostics::RefPosition::Value,
                },
                file_path: file_path.to_string(),
                span: reference.span,
            });
            return;
        }
        RustRefTarget::Path { .. } | RustRefTarget::MethodCall { .. } => return,
    };
    if is_rust_prelude_free_fn(name) {
        return;
    }
    if file_scope.binds_name(name, reference.span.start(), current_module_path) {
        return;
    }
    diagnostics.push(crate::ts::diagnostics::Diagnostic {
        kind: crate::ts::diagnostics::DiagnosticKind::UnresolvedReference {
            name: name.to_string(),
            position: crate::ts::diagnostics::RefPosition::Value,
        },
        file_path: file_path.to_string(),
        span: reference.span,
    });
}

/// Bare prelude free functions that are callable without a path or import.
/// Tuple-struct / enum-variant constructors (`Some`, `Ok`, `None`, `Err`) are
/// included because they appear as bare `Some(x)`-style calls.
fn is_rust_prelude_free_fn(name: &str) -> bool {
    matches!(
        name,
        "drop"
            | "default"
            | "Some"
            | "None"
            | "Ok"
            | "Err"
            | "Box"
            | "Vec"
            | "String"
            | "format"
            | "panic"
            | "vec"
            | "assert"
            | "assert_eq"
            | "assert_ne"
            | "println"
            | "print"
            | "eprintln"
            | "eprint"
            | "write"
            | "writeln"
            | "dbg"
            | "todo"
            | "unimplemented"
            | "unreachable"
            | "matches"
            | "include_str"
            | "include_bytes"
            | "stringify"
            | "concat"
            | "env"
            | "into"
            | "from"
    )
}

fn emit_trait_impl_edges(
    builder: &mut GraphBuilder,
    item: &RustItem,
    parent_path: &str,
    module_path: &str,
    item_index: &ItemIndex,
    crate_roots: &BTreeMap<String, String>,
) {
    let item_path = join_use_path(parent_path, &item.name);
    let child_namespace_path = namespace_path_for_children(parent_path, item);
    if item.kind == RustItemKind::Impl {
        let target =
            resolve_local_path_in_index(&item.name, module_path, item_index, crate_roots, true);
        let impl_node = item_index
            .all_by_path
            .get(&indexed_item_path(parent_path, item))
            .copied();
        if let (Some(impl_node), Some(target)) = (impl_node, target) {
            builder.add_edge(
                impl_node,
                EdgeKind::ValueRef,
                target,
                Some(item.signature_span),
            );
        }
        if let (Some(target), Some(trait_node)) = (
            target,
            item.impl_trait_path.as_deref().and_then(|trait_path| {
                resolve_local_path_in_index(trait_path, module_path, item_index, crate_roots, true)
            }),
        ) {
            builder.add_edge(target, EdgeKind::Implements, trait_node, None);
            if let Some(impl_node) = impl_node {
                builder.add_edge(
                    impl_node,
                    EdgeKind::Implements,
                    trait_node,
                    Some(item.signature_span),
                );
            }
        }
    }

    let child_module_path = if item.kind == RustItemKind::Module {
        &item_path
    } else {
        module_path
    };
    for child in &item.children {
        emit_trait_impl_edges(
            builder,
            child,
            &child_namespace_path,
            child_module_path,
            item_index,
            crate_roots,
        );
    }
}

fn resolve_local_path_in_index(
    path: &str,
    module_path: &str,
    item_index: &ItemIndex,
    crate_roots: &BTreeMap<String, String>,
    allow_name_fallback: bool,
) -> Option<NodeId> {
    let by_path = absolute_local_use_path(path, module_path, crate_roots)
        .as_ref()
        .and_then(|path| direct_visible_node(path, module_path, item_index))
        .or_else(|| direct_visible_node(path, module_path, item_index));
    if allow_name_fallback {
        by_path.or_else(|| {
            unique_named_item(item_index, &target_use_segment(path))
                .filter(|target| node_is_visible(*target, module_path, item_index))
        })
    } else {
        by_path
    }
}

fn emit_module_edges(
    builder: &mut GraphBuilder,
    file_id: NodeId,
    current_path: &str,
    item: &RustItem,
    path_to_file: &BTreeMap<String, (usize, NodeId)>,
) {
    if item.kind == RustItemKind::Module && item.body_span.is_none() {
        if let Some(target_file) = resolve_mod_file(current_path, &item.name, path_to_file) {
            builder.add_import_edge_with_bindings(
                file_id,
                target_file,
                Some(item.name_span),
                false,
                &item.name,
            );
        }
    }
    for child in &item.children {
        emit_module_edges(builder, file_id, current_path, child, path_to_file);
    }
}

fn emit_use_edge(
    builder: &mut GraphBuilder,
    file_id: NodeId,
    use_item: &crate::rust::events::RustUse,
    current_module_path: &str,
    item_index: &ItemIndex,
    crate_roots: &BTreeMap<String, String>,
) {
    for binding in &use_item.bindings {
        let target = match root_use_segment(&binding.path) {
            Some("crate" | "self" | "super") => resolve_local_use(
                &binding.path,
                current_module_path,
                &binding.target_name,
                item_index,
                crate_roots,
                false,
            )
            .unwrap_or_else(|| builder.add_unresolved(&binding.path, Some(NodeKind::Module))),
            Some(root) => resolve_local_use(
                &binding.path,
                current_module_path,
                &binding.target_name,
                item_index,
                crate_roots,
                crate_roots.contains_key(root),
            )
            .unwrap_or_else(|| {
                builder.add_external(root, ExternalOrigin::ImportedPackage, Some(root))
            }),
            None => builder.add_unresolved(&binding.path, Some(NodeKind::Module)),
        };

        builder.add_import_edge_with_bindings(
            file_id,
            target,
            Some(use_item.label_span),
            false,
            &binding.label,
        );
        if use_item.visibility.is_public()
            && enclosing_module_scope(current_module_path, &item_index.module_scopes).is_public()
        {
            builder.add_export_edge_with_label(
                file_id,
                target,
                Some(use_item.span),
                false,
                &binding.export_name,
            );
        }
    }
}

fn collect_public_use_aliases(
    use_item: &crate::rust::events::RustUse,
    current_module_path: &str,
    item_index: &ItemIndex,
    crate_roots: &BTreeMap<String, String>,
    out: &mut Vec<(String, NodeId)>,
) {
    if use_item.is_block_local
        || !use_item.visibility.is_public()
        || !enclosing_module_scope(current_module_path, &item_index.module_scopes).is_public()
    {
        return;
    }
    for binding in &use_item.bindings {
        let target = match root_use_segment(&binding.path) {
            Some("crate" | "self" | "super") => resolve_local_use(
                &binding.path,
                current_module_path,
                &binding.target_name,
                item_index,
                crate_roots,
                true,
            ),
            Some(root) => resolve_local_use(
                &binding.path,
                current_module_path,
                &binding.target_name,
                item_index,
                crate_roots,
                crate_roots.contains_key(root),
            ),
            None => None,
        };
        if let Some(target) = target {
            out.push((
                join_use_path(current_module_path, &binding.export_name),
                target,
            ));
        }
    }
}

fn effective_module_scopes(
    parsed: &[&ParsedFile],
    module_paths: &[String],
    crate_roots: &BTreeMap<String, String>,
) -> BTreeMap<String, VisibilityScope> {
    let mut declarations = BTreeMap::new();
    for (file, module_path) in parsed.iter().zip(module_paths) {
        collect_module_declarations(&file.items, module_path, module_path, &mut declarations);
    }

    let mut declarations = declarations.into_values().collect::<Vec<_>>();
    declarations.sort_by_key(|declaration| declaration.path.matches("::").count());
    let mut scopes = BTreeMap::new();
    for declaration in declarations {
        let enclosing_scope = enclosing_module_scope(&declaration.defining_module, &scopes);
        let scope = declared_visibility_scope(
            &declaration.visibility,
            &declaration.defining_module,
            crate_roots,
        )
        .intersect(&enclosing_scope);
        scopes.insert(declaration.path, scope);
    }
    scopes
}

#[derive(Debug)]
struct ModuleDeclaration {
    path: String,
    defining_module: String,
    visibility: RustVisibility,
}

fn collect_module_declarations(
    items: &[RustItem],
    parent_path: &str,
    module_path: &str,
    declarations: &mut BTreeMap<String, ModuleDeclaration>,
) {
    for item in items {
        let item_path = join_use_path(parent_path, &item.name);
        let child_namespace_path = namespace_path_for_children(parent_path, item);
        let child_module_path = if item.kind == RustItemKind::Module {
            declarations.insert(
                item_path.clone(),
                ModuleDeclaration {
                    path: item_path.clone(),
                    defining_module: module_path.to_string(),
                    visibility: item.visibility.clone(),
                },
            );
            item_path.as_str()
        } else {
            module_path
        };
        collect_module_declarations(
            &item.children,
            &child_namespace_path,
            child_module_path,
            declarations,
        );
    }
}

// Conservative Rust contract rule for inherent impl methods: a method becomes a
// live contract entity only when the method is `pub` and the impl target resolves
// to a type declared as public through its own module path in this extraction.
#[derive(Debug, Default)]
struct ItemIndex {
    by_name: BTreeMap<String, Option<NodeId>>,
    by_path: BTreeMap<String, NodeId>,
    all_by_path: BTreeMap<String, NodeId>,
    imported_by_path: BTreeMap<String, Option<ImportedBinding>>,
    glob_sources_by_module: BTreeMap<String, BTreeSet<GlobImport>>,
    visibility_by_node: BTreeMap<NodeId, VisibilityScope>,
    module_scopes: BTreeMap<String, VisibilityScope>,
    public_contract_type_nodes: BTreeSet<NodeId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum VisibilityScope {
    Public,
    Module(String),
    Hidden,
}

impl VisibilityScope {
    fn allows(&self, requester_module: &str) -> bool {
        match self {
            Self::Public => true,
            Self::Module(scope) => module_is_within(requester_module, scope),
            Self::Hidden => false,
        }
    }

    fn intersect(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Hidden, _) | (_, Self::Hidden) => Self::Hidden,
            (Self::Public, scope) | (scope, Self::Public) => scope.clone(),
            (Self::Module(left), Self::Module(right)) if module_is_within(left, right) => {
                Self::Module(left.clone())
            }
            (Self::Module(left), Self::Module(right)) if module_is_within(right, left) => {
                Self::Module(right.clone())
            }
            (Self::Module(_), Self::Module(_)) => Self::Hidden,
        }
    }

    fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }
}

fn enclosing_module_scope(
    module_path: &str,
    module_scopes: &BTreeMap<String, VisibilityScope>,
) -> VisibilityScope {
    // Standalone target files are valid extraction roots even when their
    // declaring `mod` item is outside the selected corpus.
    module_scopes
        .get(module_path)
        .cloned()
        .unwrap_or(VisibilityScope::Public)
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ImportedBinding {
    target: NodeId,
    scope: VisibilityScope,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct GlobImport {
    source_module: String,
    scope: VisibilityScope,
}

fn declared_visibility_scope(
    visibility: &RustVisibility,
    defining_module: &str,
    crate_roots: &BTreeMap<String, String>,
) -> VisibilityScope {
    match visibility {
        RustVisibility::Public => VisibilityScope::Public,
        RustVisibility::Private | RustVisibility::SelfModule => {
            VisibilityScope::Module(defining_module.to_string())
        }
        RustVisibility::Crate => {
            VisibilityScope::Module(scoped_crate_path(defining_module, "crate"))
        }
        RustVisibility::Super => VisibilityScope::Module(parent_module_path(defining_module)),
        RustVisibility::In(path) => absolute_local_use_path(path, defining_module, crate_roots)
            .map(VisibilityScope::Module)
            .unwrap_or(VisibilityScope::Hidden),
    }
}

fn module_is_within(module: &str, scope: &str) -> bool {
    module == scope
        || module
            .strip_prefix(scope)
            .is_some_and(|suffix| suffix.starts_with("::"))
}

fn node_is_visible(target: NodeId, requester_module: &str, item_index: &ItemIndex) -> bool {
    item_index
        .visibility_by_node
        .get(&target)
        .is_some_and(|scope| scope.allows(requester_module))
}

fn direct_visible_node(
    path: &str,
    requester_module: &str,
    item_index: &ItemIndex,
) -> Option<NodeId> {
    item_index
        .all_by_path
        .get(path)
        .or_else(|| item_index.by_path.get(path))
        .copied()
        .filter(|target| node_is_visible(*target, requester_module, item_index))
}

struct RustRefResolver<'a> {
    item_index: &'a ItemIndex,
    crate_roots: &'a BTreeMap<String, String>,
    suffix_index: &'a UniqueSuffixIndex,
}

#[derive(Debug)]
enum RustResolution {
    InGraph(NodeId),
    External(ExternalRustBinding),
    Unresolved,
}

#[derive(Debug)]
struct ExternalRustBinding {
    symbol: String,
    package: String,
}

#[derive(Debug)]
struct ResolutionOutcome {
    binding: RustResolution,
    qualifier: Option<NodeId>,
}

/// Resolver-owned view of every name visible in one parsed Rust file.
///
/// Module imports and block-local values share one owner because both decide
/// whether a reference is bound. The parser remains the authority for module
/// suffixes and lexical ranges; this type performs the single scope projection
/// used by external resolution and unresolved diagnostics.
struct RustFileScope {
    declared_crates: BTreeSet<String>,
    imported_paths_by_module: BTreeMap<String, BTreeMap<String, Option<ImportedExternalPath>>>,
    local_values: RustValueScopeIndex,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImportedExternalPath {
    package: String,
    canonical_path: String,
}

impl RustFileScope {
    fn from_parsed_file(
        pf: &ParsedFile,
        file_module_path: &str,
        declared_crates: BTreeSet<String>,
    ) -> Self {
        let mut scope = Self {
            declared_crates,
            imported_paths_by_module: BTreeMap::new(),
            local_values: RustValueScopeIndex::new(&pf.local_value_bindings),
        };
        for use_item in &pf.uses {
            if use_item.is_block_local {
                continue;
            }
            let module_path = join_use_path(file_module_path, &use_item.module_suffix);
            for binding in &use_item.bindings {
                if matches!(binding.export_name.as_str(), "" | "*" | "_") {
                    continue;
                }
                let candidate = root_use_segment(&binding.path)
                    .filter(|root| scope.is_declared_crate(root))
                    .map(|root| ImportedExternalPath {
                        package: root.to_string(),
                        canonical_path: binding.path.clone(),
                    });
                scope
                    .imported_paths_by_module
                    .entry(module_path.clone())
                    .or_default()
                    .entry(binding.export_name.clone())
                    .and_modify(|existing| {
                        if *existing != candidate {
                            *existing = None;
                        }
                    })
                    .or_insert(candidate);
            }
        }
        scope
    }

    fn binds_name(&self, name: &str, offset: u32, current_module_path: &str) -> bool {
        self.imported_paths_by_module
            .get(current_module_path)
            .is_some_and(|imports| imports.contains_key(name))
            || self.local_values.binds_name(name, offset)
    }

    fn resolve_external_path(
        &self,
        path: &str,
        current_module_path: &str,
    ) -> Option<ExternalRustBinding> {
        let root = root_use_segment(path)?;
        if self.is_declared_crate(root) {
            return Some(ExternalRustBinding {
                symbol: path.to_string(),
                package: root.to_string(),
            });
        }
        let imported = self
            .imported_paths_by_module
            .get(current_module_path)?
            .get(root)?
            .as_ref()?;
        let suffix = path.strip_prefix(root)?.trim_start_matches("::");
        let symbol = if suffix.is_empty() {
            imported.canonical_path.clone()
        } else {
            join_use_path(&imported.canonical_path, suffix)
        };
        Some(ExternalRustBinding {
            symbol,
            package: imported.package.clone(),
        })
    }

    fn is_declared_crate(&self, root: &str) -> bool {
        matches!(root, "std" | "core" | "alloc") || self.declared_crates.contains(root)
    }
}

#[derive(Debug, Default)]
struct UniqueSuffixIndex {
    by_path_suffix: BTreeMap<String, Option<NodeId>>,
}

impl UniqueSuffixIndex {
    fn from_item_paths(paths: &BTreeMap<String, NodeId>) -> Self {
        let mut index = Self::default();
        for (path, node) in paths {
            index.insert_path(path, *node);
        }
        index
    }

    fn unique(&self, path: &str) -> Option<NodeId> {
        if !path.contains("::") {
            return None;
        }
        self.by_path_suffix.get(path).and_then(|target| *target)
    }

    fn insert_path(&mut self, path: &str, node: NodeId) {
        let segments = path
            .split("::")
            .filter(|segment| !segment.trim().is_empty())
            .collect::<Vec<_>>();
        if segments.len() < 3 {
            return;
        }
        for start in 1..(segments.len() - 1) {
            insert_unique_node(
                &mut self.by_path_suffix,
                &segments[start..].join("::"),
                node,
            );
        }
    }
}

fn resolve_local_use(
    path: &str,
    current_module_path: &str,
    target_name: &str,
    item_index: &ItemIndex,
    crate_roots: &BTreeMap<String, String>,
    allow_name_fallback: bool,
) -> Option<NodeId> {
    let target_path = absolute_local_use_path(path, current_module_path, crate_roots);
    let by_path = target_path.as_ref().and_then(|path| {
        match resolve_indexed_path(path, current_module_path, item_index) {
            IndexedPathResolution::Unique(target) => Some(target),
            IndexedPathResolution::Missing | IndexedPathResolution::Ambiguous => None,
        }
    });
    if allow_name_fallback {
        by_path.or_else(|| {
            unique_named_item(item_index, target_name)
                .filter(|target| node_is_visible(*target, current_module_path, item_index))
        })
    } else {
        by_path
    }
}

fn collect_import_aliases(
    parsed: &[&ParsedFile],
    module_paths: &[String],
    crate_roots: &BTreeMap<String, String>,
    item_index: &mut ItemIndex,
) {
    let mut aliases = Vec::new();
    let mut glob_sources = Vec::new();
    for (file_idx, pf) in parsed.iter().enumerate() {
        let module_path = &module_paths[file_idx];
        for use_item in &pf.uses {
            if use_item.is_block_local {
                continue;
            }
            let use_module_path = join_use_path(module_path, &use_item.module_suffix);
            let enclosing_scope =
                enclosing_module_scope(&use_module_path, &item_index.module_scopes);
            let import_scope =
                declared_visibility_scope(&use_item.visibility, &use_module_path, crate_roots)
                    .intersect(&enclosing_scope);
            for binding in &use_item.bindings {
                if binding.export_name == "*" {
                    let source_path = binding.path.strip_suffix("::*").unwrap_or(&binding.path);
                    if let Some(source_module) =
                        absolute_local_use_path(source_path, &use_module_path, crate_roots)
                    {
                        glob_sources.push((
                            use_module_path.clone(),
                            GlobImport {
                                source_module,
                                scope: import_scope.clone(),
                            },
                        ));
                    }
                    continue;
                }
                let Some(target) =
                    resolve_import_alias_target(binding, &use_module_path, item_index, crate_roots)
                else {
                    continue;
                };
                aliases.push((
                    join_use_path(&use_module_path, &binding.export_name),
                    ImportedBinding {
                        target,
                        scope: import_scope.clone(),
                    },
                ));
            }
        }
    }
    for (path, binding) in aliases {
        insert_unique_import(&mut item_index.imported_by_path, &path, binding);
    }
    for (module_path, glob_import) in glob_sources {
        item_index
            .glob_sources_by_module
            .entry(module_path)
            .or_default()
            .insert(glob_import);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndexedPathResolution {
    Missing,
    Unique(NodeId),
    Ambiguous,
}

fn resolve_indexed_path(
    path: &str,
    requester_module: &str,
    item_index: &ItemIndex,
) -> IndexedPathResolution {
    if let Some(target) = direct_visible_node(path, requester_module, item_index) {
        return IndexedPathResolution::Unique(target);
    }
    if item_index.all_by_path.contains_key(path) || item_index.by_path.contains_key(path) {
        return IndexedPathResolution::Missing;
    }

    match item_index.imported_by_path.get(path) {
        Some(Some(binding))
            if binding.scope.allows(requester_module)
                && node_is_visible(binding.target, requester_module, item_index) =>
        {
            IndexedPathResolution::Unique(binding.target)
        }
        Some(Some(_)) => IndexedPathResolution::Missing,
        Some(None) => IndexedPathResolution::Ambiguous,
        None => IndexedPathResolution::Missing,
    }
}

fn resolve_scoped_glob_import(
    path: &str,
    current_module_path: &str,
    item_index: &ItemIndex,
) -> IndexedPathResolution {
    if path.contains("::") {
        return IndexedPathResolution::Missing;
    }
    let Some(sources) = item_index.glob_sources_by_module.get(current_module_path) else {
        return IndexedPathResolution::Missing;
    };
    // Each queued module comes from one recorded glob edge, so the total edge
    // count is a hard traversal bound even when the import graph contains cycles.
    let max_steps = item_index
        .glob_sources_by_module
        .values()
        .try_fold(0_usize, |total, sources| total.checked_add(sources.len()));
    let max_steps = max_steps.expect("glob edge count must fit in usize");
    let mut pending = sources.iter().collect::<VecDeque<_>>();
    let mut visited = BTreeSet::from([current_module_path]);
    let mut resolved = None;

    for _ in 0..max_steps {
        let Some(glob_import) = pending.pop_front() else {
            break;
        };
        if !glob_import.scope.allows(current_module_path)
            || !visited.insert(glob_import.source_module.as_str())
        {
            continue;
        }
        let candidate = join_use_path(&glob_import.source_module, path);
        match resolve_indexed_path(&candidate, current_module_path, item_index) {
            IndexedPathResolution::Unique(target) => match resolved {
                Some(existing) if existing != target => {
                    return IndexedPathResolution::Ambiguous;
                }
                Some(_) => {}
                None => resolved = Some(target),
            },
            IndexedPathResolution::Ambiguous => return IndexedPathResolution::Ambiguous,
            IndexedPathResolution::Missing => {
                if let Some(nested_sources) = item_index
                    .glob_sources_by_module
                    .get(&glob_import.source_module)
                {
                    pending.extend(nested_sources);
                }
            }
        }
    }

    assert!(pending.is_empty(), "glob traversal exceeded its edge bound");
    resolved.map_or(
        IndexedPathResolution::Missing,
        IndexedPathResolution::Unique,
    )
}

fn resolve_import_alias_target(
    binding: &RustUseBinding,
    current_module_path: &str,
    item_index: &ItemIndex,
    crate_roots: &BTreeMap<String, String>,
) -> Option<NodeId> {
    let root = root_use_segment(&binding.path)?;
    resolve_local_use(
        &binding.path,
        current_module_path,
        &binding.target_name,
        item_index,
        crate_roots,
        crate_roots.contains_key(root),
    )
}

fn resolve_rust_call(
    path: &str,
    current_module_path: &str,
    _target_name: &str,
    item_index: &ItemIndex,
    crate_roots: &BTreeMap<String, String>,
    suffix_index: &UniqueSuffixIndex,
) -> Option<NodeId> {
    if let Some(absolute_path) = absolute_local_use_path(path, current_module_path, crate_roots) {
        match resolve_indexed_path(&absolute_path, current_module_path, item_index) {
            IndexedPathResolution::Unique(target) => return Some(target),
            IndexedPathResolution::Ambiguous => return None,
            IndexedPathResolution::Missing => {}
        }
    }

    match resolve_scoped_glob_import(path, current_module_path, item_index) {
        IndexedPathResolution::Unique(target) => Some(target),
        IndexedPathResolution::Ambiguous => None,
        IndexedPathResolution::Missing => suffix_index
            .unique(path)
            .filter(|target| node_is_visible(*target, current_module_path, item_index)),
    }
}

fn resolve_rust_binding(
    path: &str,
    current_module_path: &str,
    resolver: &RustRefResolver<'_>,
    file_scope: &RustFileScope,
) -> RustResolution {
    resolve_rust_call(
        path,
        current_module_path,
        &target_use_segment(path),
        resolver.item_index,
        resolver.crate_roots,
        resolver.suffix_index,
    )
    .map(RustResolution::InGraph)
    .or_else(|| {
        file_scope
            .resolve_external_path(path, current_module_path)
            .map(RustResolution::External)
    })
    .unwrap_or(RustResolution::Unresolved)
}

fn resolve_rust_reference(
    reference: &RustRef,
    parent_path: &str,
    current_module_path: &str,
    resolver: &RustRefResolver<'_>,
    file_scope: &RustFileScope,
) -> ResolutionOutcome {
    let (binding, qualifier) = match &reference.target {
        RustRefTarget::MethodCall {
            receiver,
            receiver_type,
            method,
        } => (
            resolve_rust_method_call(
                receiver,
                receiver_type.as_deref(),
                method,
                parent_path,
                current_module_path,
                resolver,
            )
            .map(RustResolution::InGraph)
            .unwrap_or(RustResolution::Unresolved),
            None,
        ),
        RustRefTarget::Path { path, .. } => {
            let binding = if let Some(rest) = path.strip_prefix("Self::") {
                let target_path = join_use_path(parent_path, rest);
                direct_visible_node(&target_path, current_module_path, resolver.item_index)
                    .map(RustResolution::InGraph)
                    .unwrap_or_else(|| {
                        resolve_rust_binding(path, current_module_path, resolver, file_scope)
                    })
            } else {
                resolve_rust_binding(path, current_module_path, resolver, file_scope)
            };
            let qualifier = resolve_rust_path_qualifier(
                path,
                current_module_path,
                resolver.item_index,
                resolver.crate_roots,
            );
            (binding, qualifier)
        }
        RustRefTarget::QualifiedTraitCall {
            trait_path, method, ..
        } => {
            let local_method_path = join_use_path(trait_path, method);
            let binding = resolve_rust_binding(
                &local_method_path,
                current_module_path,
                resolver,
                file_scope,
            );
            (binding, None)
        }
    };
    ResolutionOutcome { binding, qualifier }
}

fn resolve_rust_path_qualifier(
    path: &str,
    current_module_path: &str,
    item_index: &ItemIndex,
    crate_roots: &BTreeMap<String, String>,
) -> Option<NodeId> {
    let (mut qualifier, _) = path.rsplit_once("::")?;
    loop {
        if qualifier == "Self" {
            return None;
        }
        if let Some(target) = resolve_local_path_in_index(
            qualifier,
            current_module_path,
            item_index,
            crate_roots,
            true,
        ) {
            return Some(target);
        }
        let (parent, _) = qualifier.rsplit_once("::")?;
        qualifier = parent;
    }
}

fn resolve_rust_method_call(
    receiver: &str,
    receiver_type: Option<&str>,
    method_name: &str,
    parent_path: &str,
    current_module_path: &str,
    resolver: &RustRefResolver<'_>,
) -> Option<NodeId> {
    if receiver == "self" {
        let target_path = join_use_path(parent_path, method_name);
        return direct_visible_node(&target_path, current_module_path, resolver.item_index);
    }
    if let Some(receiver_type) = receiver_type {
        if receiver_type == "Self" {
            let target_path = join_use_path(parent_path, method_name);
            return direct_visible_node(&target_path, current_module_path, resolver.item_index);
        }
        let typed_method_path = format!("{receiver_type}::{method_name}");
        if let Some(target) =
            direct_visible_node(&typed_method_path, current_module_path, resolver.item_index)
        {
            return Some(target);
        }
        if let Some(target) = absolute_local_use_path(
            &typed_method_path,
            current_module_path,
            resolver.crate_roots,
        )
        .as_ref()
        .and_then(|path| direct_visible_node(path, current_module_path, resolver.item_index))
        {
            return Some(target);
        }
        if let Some(target) = resolver
            .suffix_index
            .unique(&typed_method_path)
            .filter(|target| node_is_visible(*target, current_module_path, resolver.item_index))
        {
            return Some(target);
        }
        return None;
    }
    None
}

fn insert_unique(map: &mut BTreeMap<String, Option<NodeId>>, name: &str, node: NodeId) {
    match map.get_mut(name) {
        Some(slot) => *slot = None,
        None => {
            map.insert(name.to_string(), Some(node));
        }
    }
}

fn insert_unique_node(map: &mut BTreeMap<String, Option<NodeId>>, path: &str, node: NodeId) {
    match map.get_mut(path) {
        Some(slot) if *slot == Some(node) => {}
        Some(slot) => *slot = None,
        None => {
            map.insert(path.to_string(), Some(node));
        }
    }
}

fn insert_unique_import(
    map: &mut BTreeMap<String, Option<ImportedBinding>>,
    path: &str,
    binding: ImportedBinding,
) {
    match map.get_mut(path) {
        Some(slot) if *slot == Some(binding.clone()) => {}
        Some(slot) => *slot = None,
        None => {
            map.insert(path.to_string(), Some(binding));
        }
    }
}

fn unique_named_item(item_index: &ItemIndex, name: &str) -> Option<NodeId> {
    item_index.by_name.get(name).and_then(|target| *target)
}

fn absolute_local_use_path(
    path: &str,
    current_module_path: &str,
    crate_roots: &BTreeMap<String, String>,
) -> Option<String> {
    let target = path.trim();
    let mut parts = target.split("::").filter(|part| !part.trim().is_empty());
    let first = parts.next()?.trim();
    let rest = parts.map(str::trim).collect::<Vec<_>>();
    match first {
        "crate" => {
            let logical_path = join_parts(std::iter::once("crate").chain(rest.iter().copied()));
            Some(scoped_crate_path(current_module_path, &logical_path))
        }
        "self" => Some(join_use_path(current_module_path, &rest.join("::"))),
        "super" => {
            let mut base = parent_module_path(current_module_path);
            let mut suffix = Vec::new();
            let mut saw_non_super = false;
            for part in rest {
                if part == "super" && !saw_non_super {
                    base = parent_module_path(&base);
                } else {
                    saw_non_super = true;
                    suffix.push(part);
                }
            }
            Some(join_use_path(&base, &suffix.join("::")))
        }
        _ if !rest.is_empty() => crate_roots
            .get(first)
            .map(|root| join_use_path(root, &rest.join("::")))
            .or_else(|| Some(join_use_path(current_module_path, target))),
        _ => Some(join_use_path(current_module_path, first)),
    }
}

fn join_use_path(prefix: &str, suffix: &str) -> String {
    let prefix = prefix.trim().trim_end_matches("::").trim();
    let suffix = suffix.trim().trim_start_matches("::").trim();
    match (prefix.is_empty(), suffix.is_empty()) {
        (true, true) => String::new(),
        (true, false) => suffix.to_string(),
        (false, true) => prefix.to_string(),
        (false, false) => format!("{prefix}::{suffix}"),
    }
}

fn join_parts<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
    parts
        .into_iter()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("::")
}

fn parent_module_path(path: &str) -> String {
    if path == "crate" || path.ends_with("::crate") {
        return path.to_string();
    }
    path.rsplit_once("::")
        .map(|(parent, _)| parent.to_string())
        .unwrap_or_else(|| "crate".to_string())
}

fn scoped_crate_path(current_module_path: &str, logical_path: &str) -> String {
    let scope = current_module_path
        .split_once("::crate")
        .map(|(scope, _)| scope)
        .unwrap_or("");
    if scope.is_empty() {
        logical_path.to_string()
    } else {
        format!("{scope}::{logical_path}")
    }
}

fn node_kind_for_item(kind: RustItemKind) -> NodeKind {
    match kind {
        RustItemKind::Module => NodeKind::Module,
        RustItemKind::ExternBlock => NodeKind::Module,
        RustItemKind::Struct => NodeKind::Struct,
        RustItemKind::Union => NodeKind::Union,
        RustItemKind::Impl => NodeKind::Module,
        RustItemKind::Trait => NodeKind::Interface,
        RustItemKind::Enum => NodeKind::Enum,
        RustItemKind::TypeAlias | RustItemKind::AssociatedType => NodeKind::TypeAlias,
        RustItemKind::Function | RustItemKind::Macro => NodeKind::Function,
        RustItemKind::Const
        | RustItemKind::AnonymousConst
        | RustItemKind::Static
        | RustItemKind::AssociatedConst => NodeKind::Variable,
        RustItemKind::Method => NodeKind::Property,
    }
}

/// Canonical graph identity for one projected Rust item.
///
/// Source-facing names remain unchanged. Items that Rust deliberately makes
/// non-addressable receive snapshot-local identities so repeated declarations
/// cannot overwrite one another in the resolver index.
pub fn graph_item_name(item: &RustItem) -> String {
    match item.kind {
        RustItemKind::Impl => format!("impl {}", item.name),
        RustItemKind::AnonymousConst => format!("const _@{}", item.decl_span.start()),
        _ => item.name.clone(),
    }
}

fn indexed_item_path(parent_path: &str, item: &RustItem) -> String {
    join_use_path(parent_path, &graph_item_name(item))
}

fn namespace_path_for_children(parent_path: &str, item: &RustItem) -> String {
    if item.kind == RustItemKind::ExternBlock {
        parent_path.to_string()
    } else {
        join_use_path(parent_path, &item.name)
    }
}

fn is_use_addressable_item(kind: RustItemKind) -> bool {
    !matches!(
        kind,
        RustItemKind::AnonymousConst
            | RustItemKind::ExternBlock
            | RustItemKind::Impl
            | RustItemKind::Method
    )
}

fn is_public_contract_type_kind(kind: RustItemKind) -> bool {
    matches!(
        kind,
        RustItemKind::Struct | RustItemKind::Union | RustItemKind::Enum
    )
}

fn resolve_mod_file(
    current_path: &str,
    mod_name: &str,
    path_to_file: &BTreeMap<String, (usize, NodeId)>,
) -> Option<NodeId> {
    for candidate in rust_mod_candidates(current_path, mod_name) {
        let key = normalize_graph_path(&candidate);
        if let Some((_, file)) = path_to_file.get(&key) {
            return Some(*file);
        }
    }
    None
}

fn rust_mod_candidates(current_path: &str, mod_name: &str) -> Vec<String> {
    let path = current_path.trim_start_matches("./");
    let current = std::path::Path::new(path);
    let parent = current.parent().unwrap_or_else(|| std::path::Path::new(""));
    let stem = current.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let base = if stem == "lib" || stem == "main" || stem == "mod" {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    };
    vec![
        base.join(format!("{mod_name}.rs"))
            .to_string_lossy()
            .replace('\\', "/"),
        base.join(mod_name)
            .join("mod.rs")
            .to_string_lossy()
            .replace('\\', "/"),
    ]
}

fn root_use_segment(label: &str) -> Option<&str> {
    label
        .split("::")
        .next()
        .map(|segment| segment.trim_matches(|c: char| c == '{' || c == '}').trim())
        .filter(|segment| !segment.is_empty())
}

fn target_use_segment(label: &str) -> String {
    let target = label
        .rsplit_once(" as ")
        .map(|(target, _)| target)
        .unwrap_or(label);
    target
        .rsplit("::")
        .next()
        .unwrap_or(target)
        .trim_matches(|c: char| c == '{' || c == '}' || c == ';')
        .trim()
        .to_string()
}

pub fn module_path_for_file(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let path = normalized.trim_start_matches("./");
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    let src_idx = parts.iter().rposition(|part| *part == "src");
    let crate_scope = src_idx
        .map(|idx| parts[..idx].join("/"))
        .unwrap_or_default();
    let start = src_idx.map(|idx| idx + 1).unwrap_or(0);

    let mut modules = Vec::new();
    for (idx, part) in parts[start..].iter().enumerate() {
        let is_last = idx + start + 1 == parts.len();
        if is_last {
            let stem = part.strip_suffix(".rs").unwrap_or(part);
            if !matches!(stem, "lib" | "main" | "mod") {
                modules.push(stem);
            }
        } else {
            modules.push(part);
        }
    }

    let logical_path = if modules.is_empty() {
        "crate".to_string()
    } else {
        format!("crate::{}", modules.join("::"))
    };

    if crate_scope.is_empty() {
        logical_path
    } else {
        format!("{crate_scope}::{logical_path}")
    }
}

fn rust_crate_roots(module_paths: &[String]) -> BTreeMap<String, String> {
    let mut roots = BTreeMap::new();
    for module_path in module_paths {
        let Some(scope) = module_path.strip_suffix("::crate") else {
            continue;
        };
        if scope.contains("::") {
            continue;
        }
        let Some(crate_dir) = scope.rsplit('/').next().filter(|part| !part.is_empty()) else {
            continue;
        };
        roots
            .entry(crate_dir.replace('-', "_"))
            .or_insert_with(|| module_path.clone());
    }
    roots
}

fn normalize_graph_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    if path.starts_with("./") {
        path
    } else {
        format!("./{path}")
    }
}
