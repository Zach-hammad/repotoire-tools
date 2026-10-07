//! Project-level resolver. See spec §6.

use crate::builder::GraphBuilder;
use crate::ids::NodeId;
use crate::spans::Span;
use crate::ts::diagnostics::Diagnostic;
use crate::ts::environment::{
    is_language_type_builtin, is_language_value_builtin, is_platform_type_global,
    is_platform_value_global,
};
use crate::ts::events::{BindingKind, ImportBinding, ParsedFile};
use crate::ts::parser::parse_file;
use std::collections::{BTreeMap, BTreeSet};

/// FU2 (v0.1.0-beta.1): format the binding set of one `import` statement
/// into a single label string for renderer consumption.
///
/// Shape rules:
/// - default-only:        `default as <local>`
/// - namespace-only:      `* as <local>`
/// - named-only:          `{ <a>, <b as c>, ... }` (`type` modifier
///   preserved on per-binding inline type-only entries)
/// - mixed default+named: `default as <D>, { ... }`
/// - mixed default+ns:    `default as <D>, * as <ns>`
/// - side-effect / empty: empty string (renderer keeps bare specifier)
///
/// Source order is preserved within the named-binding set. The default
/// and namespace clauses come first because that matches TypeScript's
/// own import-statement grammar — `import D, { a, b } from '...'`.
fn format_import_bindings_label(bindings: &[ImportBinding]) -> String {
    let mut default_seg: Option<String> = None;
    let mut namespace_seg: Option<String> = None;
    let mut named: Vec<String> = Vec::new();
    for b in bindings {
        match b.kind {
            BindingKind::SideEffect => continue,
            BindingKind::Default => {
                default_seg = Some(format!("default as {}", b.local));
            }
            BindingKind::Namespace => {
                namespace_seg = Some(format!("* as {}", b.local));
            }
            BindingKind::Named => {
                let prefix = if b.is_type_only { "type " } else { "" };
                let entry = if b.exported == b.local {
                    format!("{prefix}{}", b.local)
                } else {
                    format!("{prefix}{} as {}", b.exported, b.local)
                };
                named.push(entry);
            }
        }
    }
    let mut parts: Vec<String> = Vec::new();
    if let Some(d) = default_seg {
        parts.push(d);
    }
    if let Some(ns) = namespace_seg {
        parts.push(ns);
    }
    if !named.is_empty() {
        parts.push(format!("{{ {} }}", named.join(", ")));
    }
    parts.join(", ")
}

/// Canonical identity name for an `External(ImportedPackage)` node minted from
/// an import binding.
///
/// Federation — and any consumer that identifies an imported symbol by node
/// name — matches this against the peer repo's exported surface
/// (`federation.rs` `external_refs_from_graph` Calls branch /
/// `surface.export_name`). It must therefore be the **exported** name
/// (`greet`/`default`), never the local alias (`g`/`def`): a call to
/// `import { greet as g }` / `import def from 'pkg'` must resolve against the
/// peer's `greet`/`default` export, not the importer-local binding.
///
/// For namespace imports `exported == local` (the parser stores the alias in
/// both fields — there is no single exported member), so this is the same
/// string there. Routing every import-binding external-creation site through
/// this one rule is what keeps the two parallel resolution blocks from drifting
/// apart again — that drift (one block using `local`, the other `exported`) was
/// the call-path over-flag root cause (the call-path sibling of finding #6).
fn import_binding_external_name(binding: &ImportBinding) -> &str {
    &binding.exported
}

fn is_non_code_asset_specifier(specifier: &str) -> bool {
    let path = crate::ts::canonicalize::specifier_path(specifier);
    let Some(ext) = path.rsplit('.').next() else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "css"
            | "scss"
            | "sass"
            | "less"
            | "styl"
            | "svg"
            | "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "avif"
            | "ico"
            | "bmp"
            | "woff"
            | "woff2"
            | "ttf"
            | "otf"
            | "eot"
            | "json"
            | "jsonl"
    )
}

fn export_target_is_value_shaped(kind: crate::schema::NodeKind) -> bool {
    use crate::schema::NodeKind;
    matches!(
        kind,
        NodeKind::Function
            | NodeKind::Variable
            | NodeKind::Class
            | NodeKind::Enum
            | NodeKind::Unresolved
            | NodeKind::Module
            | NodeKind::External
    )
}

fn export_target_is_type_shaped(kind: crate::schema::NodeKind) -> bool {
    use crate::schema::NodeKind;
    matches!(
        kind,
        NodeKind::Interface
            | NodeKind::TypeAlias
            | NodeKind::Class
            | NodeKind::Enum
            | NodeKind::Unresolved
            | NodeKind::Module
            | NodeKind::External
    )
}

fn default_import_recovery_target(
    local_name: &str,
    canonical_path: Option<&str>,
    target_idx: Option<usize>,
    per_file_all_decls: &[BTreeMap<String, NodeId>],
    node_kinds: &[crate::schema::NodeKind],
) -> Option<NodeId> {
    let target_idx = target_idx?;
    let canonical_path = canonical_path?;
    let stem = std::path::Path::new(canonical_path)
        .file_stem()
        .and_then(|s| s.to_str())?;
    if stem != local_name {
        return None;
    }
    let node = *per_file_all_decls[target_idx].get(local_name)?;
    let kind = node_kinds[node.as_usize()];
    matches!(
        kind,
        crate::schema::NodeKind::Function
            | crate::schema::NodeKind::Variable
            | crate::schema::NodeKind::Class
            | crate::schema::NodeKind::Enum
    )
    .then_some(node)
}

#[derive(Debug)]
pub struct ExtractResult {
    pub file_ids: Vec<NodeId>,
    pub diagnostics: Vec<Diagnostic>,
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
    /// Two inputs normalize to the same project path. Rejected rather than
    /// silently letting the second File node shadow the first in
    /// `path_to_idx` (which would make every relative import to that path
    /// resolve to whichever input came last). `path` is the collided
    /// normalized form.
    DuplicatePath {
        path: String,
    },
}

impl From<crate::spans::SourceEncodingError> for ExtractError {
    fn from(e: crate::spans::SourceEncodingError) -> Self {
        let crate::spans::SourceEncodingError::NotUtf8 {
            path,
            invalid_byte_offset,
        } = e;
        ExtractError::SourceEncoding {
            path,
            invalid_byte_offset,
        }
    }
}

/// Options for extraction. `alias_map` carries tsconfig path aliases resolved
/// by the CLI; `known_project_paths` lets scoped extractors distinguish
/// first-party alias misses from package imports without linking files outside
/// the extraction unit. `default()` (empty) reproduces today's relative-only
/// behavior.
#[derive(Debug, Clone, Default)]
pub struct ExtractOptions {
    pub alias_map: crate::ts::alias::AliasMap,
    pub known_project_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct NativeEvidenceUnit<'a> {
    pub path: &'a str,
    pub bytes: &'a [u8],
    pub parsed: &'a ParsedFile,
}

#[derive(Debug, Default)]
struct AmbientDeclarationNames {
    values: BTreeSet<String>,
    types: BTreeSet<String>,
}

impl AmbientDeclarationNames {
    fn from_units(units: &[NativeEvidenceUnit<'_>]) -> Self {
        let mut names = Self::default();
        for unit in units {
            names.extend_from_parsed(unit.parsed);
        }
        names
    }

    fn extend_from_parsed(&mut self, parsed: &ParsedFile) {
        use crate::ts::events::{DeclEvent, Event, RefEvent};

        let declaration_file = parsed.path.ends_with(".d.ts")
            || parsed.path.ends_with(".d.mts")
            || parsed.path.ends_with(".d.cts");
        if !declaration_file {
            return;
        }

        let external_module = !parsed.exports.is_empty()
            || parsed.events.iter().any(|event| {
                matches!(
                    event,
                    Event::Ref(RefEvent::Import {
                        makes_external_module: true,
                        ..
                    })
                )
            });
        let explicit_ambient_names = if external_module {
            parsed
                .ambient_global_decl_names
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        } else {
            BTreeSet::new()
        };
        if external_module && explicit_ambient_names.is_empty() {
            return;
        }

        for event in &parsed.events {
            let Event::Decl(decl) = event else { continue };
            let Some((name, value_visible, type_visible)) = ambient_decl_visibility(decl) else {
                continue;
            };
            if external_module && !explicit_ambient_names.contains(name) {
                continue;
            }
            if value_visible {
                insert_ambient_name(&mut self.values, name);
            }
            if type_visible {
                insert_ambient_name(&mut self.types, name);
            }
        }

        fn ambient_decl_visibility(decl: &DeclEvent) -> Option<(&str, bool, bool)> {
            match decl {
                DeclEvent::Function { name, .. } => Some((name.as_str(), true, false)),
                DeclEvent::Class { name, .. } => Some((name.as_str(), true, true)),
                DeclEvent::Interface { name, .. } => Some((name.as_str(), false, true)),
                DeclEvent::Namespace { name, .. } => Some((name.as_str(), true, true)),
                DeclEvent::TypeAlias { name, .. } => Some((name.as_str(), false, true)),
                DeclEvent::Enum { name, .. } => Some((name.as_str(), true, true)),
                DeclEvent::Variable { name, .. } => Some((name.as_str(), true, false)),
                DeclEvent::Method { .. } | DeclEvent::ServiceMember { .. } => None,
            }
        }
    }
}

fn insert_ambient_name(names: &mut BTreeSet<String>, name: &str) {
    names.insert(name.to_string());
    if let Some((root, _)) = name.split_once('.') {
        names.insert(root.to_string());
    }
}

fn insert_ambient_node(map: &mut BTreeMap<String, NodeId>, name: &str, node: NodeId) {
    map.entry(name.to_string()).or_insert(node);
    if let Some((root, _)) = name.split_once('.') {
        map.entry(root.to_string()).or_insert(node);
    }
}

/// Extract a project from a set of source files into the given builder.
///
/// **Order-sensitivity (audit-5 R5-3).** The order of `files` is
/// reflected in the resulting graph: a file at `files[i]` becomes node
/// `file_ids[i]`, and downstream NodeId assignment (per-file decls,
/// imports, exports, etc.) is *call-order-deterministic*. Two calls
/// with the same files in a *different* order produce structurally
/// equivalent graphs whose frozen-byte representation **differs**
/// because NodeId assignments shift.
///
/// For byte-reproducible output across callers that may receive files
/// in OS-dependent order (glob results, parallel file walkers,
/// distributed builds), sort `files` by path before calling this
/// function — e.g. `files.sort_by_key(|(p, _)| *p)`.
///
/// Determinism is guaranteed per (builder, input-order) pair: the
/// audit-5 R4-A stress harness verified byte-identical output across
/// 500+ trials with the same input order (5 corpora × 100 trials +
/// 1000-file synthetic × 50).
pub fn extract_project(
    builder: &mut GraphBuilder,
    files: &[(&str, &[u8])],
) -> Result<ExtractResult, ExtractError> {
    extract_project_with_options(builder, files, &ExtractOptions::default())
}

pub fn extract_project_with_options(
    builder: &mut GraphBuilder,
    files: &[(&str, &[u8])],
    options: &ExtractOptions,
) -> Result<ExtractResult, ExtractError> {
    // UTF-8 pre-validation. The parser reads identifier text via
    // `from_utf8(...).expect(...)` on byte slices it carves out of the
    // source; on non-UTF-8 input that would panic before we ever reach
    // `add_file` (the IR's UTF-8 gatekeeper). Validate up front so we
    // surface the typed error and the parser never sees bad bytes.
    for (path, bytes) in files {
        if let Err(e) = std::str::from_utf8(bytes) {
            return Err(ExtractError::SourceEncoding {
                path: (*path).to_string(),
                invalid_byte_offset: e.valid_up_to(),
            });
        }
    }
    let parsed: Vec<ParsedFile> = files.iter().map(|(p, b)| parse_file(p, b)).collect();
    resolve_and_emit(builder, files, &parsed, options)
}

pub fn resolve_native_evidence_units(
    builder: &mut GraphBuilder,
    units: &[NativeEvidenceUnit<'_>],
) -> Result<ExtractResult, ExtractError> {
    resolve_native_evidence_units_with_options(builder, units, &ExtractOptions::default())
}

pub fn resolve_native_evidence_units_with_options(
    builder: &mut GraphBuilder,
    units: &[NativeEvidenceUnit<'_>],
    options: &ExtractOptions,
) -> Result<ExtractResult, ExtractError> {
    resolve_native_evidence_units_with_resolver_units(builder, units, &[], options)
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
    resolve_native_evidence_units_with_resolver_units(builder, &units, &[], options)
}

fn canonicalize_available_import(
    importing_path: &str,
    specifier: &str,
    available_project_files: &std::collections::BTreeMap<String, usize>,
    known_project_files: &std::collections::BTreeMap<String, usize>,
    alias_map: &crate::ts::alias::AliasMap,
    alias_candidates: &mut Vec<String>,
) -> (Option<String>, bool) {
    let canonical = crate::ts::canonicalize::canonicalize_import_with_scratch(
        importing_path,
        specifier,
        available_project_files,
        alias_map,
        alias_candidates,
    );
    if canonical.is_some() {
        return (canonical, false);
    }

    let known_first_party = crate::ts::canonicalize::canonicalize_import_with_scratch(
        importing_path,
        specifier,
        known_project_files,
        alias_map,
        alias_candidates,
    )
    .is_some();
    (None, known_first_party)
}

pub fn resolve_native_evidence_units_with_resolver_units(
    builder: &mut GraphBuilder,
    units: &[NativeEvidenceUnit<'_>],
    resolver_only_units: &[NativeEvidenceUnit<'_>],
    options: &ExtractOptions,
) -> Result<ExtractResult, ExtractError> {
    let files = units
        .iter()
        .map(|unit| (unit.path, unit.bytes))
        .collect::<Vec<_>>();
    let parsed = units.iter().map(|unit| unit.parsed).collect::<Vec<_>>();

    use crate::schema::{EdgeKind, NodeKind, TypeRefPosition};
    use crate::spans::NodeSpans;
    use crate::ts::events::{BindingEvent, DeclEvent, Event, MemberKind, ScopeId};
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    let resolver_only_ambient_names = AmbientDeclarationNames::from_units(resolver_only_units);

    // ---- Pass 1: register files ----
    //
    // Normalize input paths to the same `./...` form `canonicalize_import`
    // produces, so a caller passing `src/a.ts` and an import specifier
    // `./a` from `src/main.ts` both resolve to the same key
    // `./src/a.ts`. Without this, callers who hand the resolver raw
    // relative paths would see every relative import become a phantom.
    use crate::ts::canonicalize::normalize_path;
    let mut file_ids: Vec<NodeId> = Vec::with_capacity(files.len());
    let mut path_to_idx: BTreeMap<String, usize> = BTreeMap::new();
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    for (idx, ((path, bytes), _pf)) in files.iter().zip(parsed.iter()).enumerate() {
        let canon = normalize_path(path);
        // Reject duplicate normalized paths before adding a second File node:
        // a silent overwrite of `path_to_idx` would make relative imports to
        // this path resolve to whichever input came last.
        if path_to_idx.contains_key(&canon) {
            return Err(ExtractError::DuplicatePath { path: canon });
        }
        let id = builder.add_file(path, bytes)?; // routes via From<SourceEncodingError> defined in Task 16
        file_ids.push(id);
        path_to_idx.insert(canon, idx);
    }
    let mut known_project_path_to_idx = path_to_idx.clone();
    for path in &options.known_project_paths {
        known_project_path_to_idx
            .entry(normalize_path(path))
            .or_insert(usize::MAX);
    }

    // ---- Pass 2: declarations + per-file decl tables ----
    //
    // Three views per file, split by TypeScript namespace:
    //   * `per_file_value_decls` — decls usable in value position. Function,
    //     Variable, Class, Enum, Namespace.
    //   * `per_file_type_decls`  — decls usable in type position. Interface,
    //     TypeAlias, Class, Enum, Namespace.
    //   * `per_file_all_decls`   — every decl regardless of namespace; used
    //     for "find this decl by name" queries (Direct seed, heritage
    //     class_node lookup).
    //
    // Class, Enum, and Namespace are dual-namespace per TS semantics.
    // Interface and TypeAlias are type-only — they erase at runtime, so they
    // MUST NOT satisfy a value-position Call/ValueRef. Function and Variable
    // are value-only (no `typeof Function` analog that puts them in type
    // namespace as a direct binding; type-position consumers reach them via
    // the local_type_refs → local_value_refs typeof fallback in Pass 3).
    let mut per_file_value_decls: Vec<BTreeMap<String, NodeId>> =
        (0..files.len()).map(|_| BTreeMap::new()).collect();
    let mut per_file_type_decls: Vec<BTreeMap<String, NodeId>> =
        (0..files.len()).map(|_| BTreeMap::new()).collect();
    let mut per_file_all_decls: Vec<BTreeMap<String, NodeId>> =
        (0..files.len()).map(|_| BTreeMap::new()).collect();

    // v0.4 L2 — decl_index → NodeId per file, populated in order as we
    // walk DeclEvents during pass 2. Method emission needs to look up
    // its parent Class node by `owner_class_decl_index`; this table is
    // the lookup. Indices are dense (every DeclEvent pushes one entry).
    let mut per_file_decl_node_ids: Vec<Vec<NodeId>> =
        (0..files.len()).map(|_| Vec::new()).collect();

    // v0.4 L3 — node kind + per-class method tables. The GraphBuilder
    // doesn't expose graph-read APIs (those live on the immutable
    // CodeGraph view), so the MemberCall-resolution pass at the bottom
    // of this fn can't introspect the graph it's building. These two
    // sidecar tables capture exactly what L3 needs:
    //   * per_file_node_kinds: NodeId → NodeKind, populated as each
    //     decl node is created in Pass 2. Used to check `is this a
    //     Class?` and `is this owner a Property/Method?`.
    //   * methods_of_class (v0.5 commit 1): a SINGLE global map
    //     keyed by Class NodeId. Per-class inner map keys by
    //     `(is_static, MemberKind, name)` so the Pattern-5 lookup
    //     gates instance vs static dispatch instead of matching by
    //     name only (the v0.4 overmatch). NodeId is globally unique,
    //     so promoting to a single global map (rather than per-file
    //     Vec) is correct — and required for cross-file member
    //     dispatch in later commits.
    type MemberBuckets = HashMap<(bool, MemberKind), HashMap<String, NodeId>>;
    type ScopeBindings<'a> = HashMap<ScopeId, HashMap<String, &'a BindingEvent>>;
    type ScopedLocalValueDecls = HashMap<ScopeId, HashMap<String, NodeId>>;

    let mut per_file_node_kinds: Vec<HashMap<NodeId, NodeKind>> =
        (0..files.len()).map(|_| HashMap::new()).collect();
    let mut methods_of_class: HashMap<NodeId, MemberBuckets> = HashMap::new();
    // G1.7 Fix 2 — member table for TYPE-shaped receivers (Interface /
    // TypeAlias), the `methods_of_class` twin. Keyed by the type decl's
    // NodeId; values map member name → the member's Property NodeId
    // (minted from the parser's function-typed-member ServiceMember
    // events). No (is_static, MemberKind) bucketing: type members are all
    // call-shaped (MemberKind::Method) and types have no static surface.
    let mut members_of_type: HashMap<NodeId, HashMap<String, NodeId>> = HashMap::new();
    // G1.7 Fix 1 — reverse map for the reserved `"()"` call-signature
    // members: member Property NodeId → its parent Interface/TypeAlias
    // NodeId. Consumed by the Pass-3 recording of
    // `call_sig_param_targets` (a call-sig member's ParamAnnotation
    // targets accumulate under the PARENT type, since the projection is
    // "the TYPE's own call-signature parameter surface").
    let mut call_sig_member_parent: HashMap<NodeId, NodeId> = HashMap::new();

    // v0.5 commit 5 — per-file binding index for scope-aware
    // `MemberReceiver::Name` lookup. Keyed by `(ScopeId, name)`,
    // values are references into `parsed[file_idx].bindings`. The
    // scope-walk helper `lookup_binding_in_scope_chain` iterates
    // `ScopeInfo.parent` chains starting at the access-site scope,
    // returning the closest binding for a name. Duplicate
    // declarations in the same scope (TS error, but the parser
    // tolerates them) collapse to last-wins, which matches what
    // a TypeScript checker would surface at the second declaration.
    let bindings_by_scope: Vec<ScopeBindings<'_>> = parsed
        .iter()
        .map(|pf| {
            let mut map: ScopeBindings<'_> = HashMap::new();
            for binding in &pf.bindings {
                map.entry(binding.scope)
                    .or_default()
                    .insert(binding.name.clone(), binding);
            }
            map
        })
        .collect();
    let local_value_decl_scopes: Vec<HashMap<u32, (ScopeId, Option<u32>)>> = parsed
        .iter()
        .map(|pf| {
            pf.local_value_decls
                .iter()
                .map(|decl| (decl.decl_index, (decl.scope, decl.owner_decl_index)))
                .collect()
        })
        .collect();
    let mut scoped_local_value_decls: Vec<ScopedLocalValueDecls> =
        (0..files.len()).map(|_| HashMap::new()).collect();

    // Per-file set of function-local type alias names (e.g. `type X = …` inside
    // a function body). These are NOT graph nodes — they suppress External(Unknown)
    // in the type-position miss path without creating any node or shifting decl counts.
    let per_file_local_type_names: Vec<BTreeSet<String>> = parsed
        .iter()
        .map(|pf| pf.local_type_names.iter().cloned().collect())
        .collect();

    for (file_idx, pf) in parsed.iter().enumerate() {
        let file_id = file_ids[file_idx];
        for event in &pf.events {
            let Event::Decl(d) = event else { continue };
            let decl_index = per_file_decl_node_ids[file_idx].len() as u32;
            let local_decl_info = local_value_decl_scopes[file_idx].get(&decl_index).copied();
            let (kind, name, spans, value_visible, type_visible) = match d {
                DeclEvent::Function {
                    name,
                    name_span,
                    decl_span,
                    body_span,
                } => (
                    NodeKind::Function,
                    name.clone(),
                    NodeSpans {
                        name: Some(*name_span),
                        decl: Some(*decl_span),
                        body: Some(*body_span),
                    },
                    true,
                    false,
                ),
                DeclEvent::Class {
                    name,
                    name_span,
                    decl_span,
                    body_span,
                    ..
                } => (
                    NodeKind::Class,
                    name.clone(),
                    NodeSpans {
                        name: Some(*name_span),
                        decl: Some(*decl_span),
                        body: Some(*body_span),
                    },
                    true,
                    true,
                ),
                DeclEvent::Interface {
                    name,
                    name_span,
                    decl_span,
                    body_span,
                    ..
                } => (
                    NodeKind::Interface,
                    name.clone(),
                    NodeSpans {
                        name: Some(*name_span),
                        decl: Some(*decl_span),
                        body: Some(*body_span),
                    },
                    false,
                    true,
                ),
                DeclEvent::Namespace {
                    name,
                    name_span,
                    decl_span,
                    body_span,
                } => (
                    NodeKind::Module,
                    name.clone(),
                    NodeSpans {
                        name: Some(*name_span),
                        decl: Some(*decl_span),
                        body: Some(*body_span),
                    },
                    true,
                    true,
                ),
                DeclEvent::TypeAlias {
                    name,
                    name_span,
                    decl_span,
                } => (
                    NodeKind::TypeAlias,
                    name.clone(),
                    NodeSpans {
                        name: Some(*name_span),
                        decl: Some(*decl_span),
                        body: None,
                    },
                    false,
                    true,
                ),
                DeclEvent::Enum {
                    name,
                    name_span,
                    decl_span,
                    body_span,
                } => (
                    NodeKind::Enum,
                    name.clone(),
                    NodeSpans {
                        name: Some(*name_span),
                        decl: Some(*decl_span),
                        body: Some(*body_span),
                    },
                    true,
                    true,
                ),
                DeclEvent::Variable {
                    name,
                    name_span,
                    decl_span,
                } => (
                    NodeKind::Variable,
                    name.clone(),
                    NodeSpans {
                        name: Some(*name_span),
                        decl: Some(*decl_span),
                        body: None,
                    },
                    true,
                    false,
                ),
                DeclEvent::Method {
                    name,
                    name_span,
                    decl_span,
                    body_span,
                    ..
                } => (
                    // Class methods materialize as `Property` nodes
                    // (the existing schema slot for class members).
                    NodeKind::Property,
                    name.clone(),
                    NodeSpans {
                        name: Some(*name_span),
                        decl: Some(*decl_span),
                        // Abstract / overload signatures emit Span::ABSENT
                        // from the parser; preserve that here so
                        // `node_body_span` returns None and `signature_hash`
                        // treats the whole decl as the surface (correct
                        // for body-less methods).
                        body: if body_span.length() == 0 {
                            None
                        } else {
                            Some(*body_span)
                        },
                    },
                    // Methods are accessed via member dispatch, not as
                    // top-level identifiers in either value or type
                    // namespace. They must NOT enter per_file_value_decls
                    // (else `foo()` calls in a different scope would
                    // wrongly resolve to a class method).
                    false,
                    false,
                ),
                DeclEvent::ServiceMember {
                    name,
                    name_span,
                    decl_span,
                    body_span,
                    ..
                } => (
                    NodeKind::Property,
                    name.clone(),
                    NodeSpans {
                        name: Some(*name_span),
                        decl: Some(*decl_span),
                        body: if body_span.length() == 0 {
                            None
                        } else {
                            Some(*body_span)
                        },
                    },
                    false,
                    false,
                ),
            };
            let node_id = builder.add_node(kind, &name, spans);
            // v0.4 L2: methods are Contained by their owning Class, not
            // by the File. Every other decl kind is Contained by File
            // per the v0.2 invariant. The per_file_decl_node_ids vec
            // gives us O(1) lookup of the class NodeId from its
            // decl_index (which the parser stamped on the Method
            // event).
            let contains_parent = if let Some((_, Some(owner_decl_index))) = local_decl_info {
                per_file_decl_node_ids[file_idx]
                    .get(owner_decl_index as usize)
                    .copied()
                    .unwrap_or(file_id)
            } else {
                match d {
                    DeclEvent::Method {
                        owner_class_decl_index,
                        ..
                    } => {
                        // Defensive: if the class wasn't seen yet (parser
                        // bug), fall back to file containment so the node
                        // isn't orphaned. The parser invariant is that
                        // Method events follow their Class event in the
                        // same file's stream.
                        per_file_decl_node_ids[file_idx]
                            .get(*owner_class_decl_index as usize)
                            .copied()
                            .unwrap_or(file_id)
                    }
                    DeclEvent::ServiceMember {
                        owner_decl_index, ..
                    } => per_file_decl_node_ids[file_idx]
                        .get(*owner_decl_index as usize)
                        .copied()
                        .unwrap_or(file_id),
                    _ => file_id,
                }
            };
            builder.add_edge(contains_parent, EdgeKind::Contains, node_id, None);
            per_file_decl_node_ids[file_idx].push(node_id);
            per_file_node_kinds[file_idx].insert(node_id, kind);
            // v0.4 L3 / v0.5 commit 1 — when this decl is a class
            // member, record it in the class's per-member map under
            // `(is_static, MemberKind, name)`. Pattern-5 lookups gate
            // to `(true, Method, …)`; Pattern-4 (`this.m()`) gates to
            // `(false, Method, …)`. Read/Write access shapes (commit
            // 4) compose against Getter/Setter/Field entries.
            if let DeclEvent::Method {
                owner_class_decl_index,
                is_static,
                kind,
                ..
            } = d
            {
                if let Some(class_id) = per_file_decl_node_ids[file_idx]
                    .get(*owner_class_decl_index as usize)
                    .copied()
                {
                    methods_of_class
                        .entry(class_id)
                        .or_default()
                        .entry((*is_static, *kind))
                        .or_default()
                        .insert(name.clone(), node_id);
                }
            }
            // G1.7 Fix 2 — register interface/alias function-typed members
            // in `members_of_type`. Classic object-literal service members
            // (owner = Variable/Function decl) are excluded by the owner
            // NodeKind check, and only Method-kind entries register — the
            // parser mints type members exclusively as Method.
            if let DeclEvent::ServiceMember {
                owner_decl_index,
                kind: crate::ts::events::MemberKind::Method,
                ..
            } = d
            {
                if let Some(owner_id) = per_file_decl_node_ids[file_idx]
                    .get(*owner_decl_index as usize)
                    .copied()
                {
                    if matches!(
                        builder.node_kinds.get(owner_id.as_usize()).copied(),
                        Some(NodeKind::Interface) | Some(NodeKind::TypeAlias)
                    ) {
                        members_of_type
                            .entry(owner_id)
                            .or_default()
                            .insert(name.clone(), node_id);
                        // G1.7 Fix 1 — the reserved call-signature member
                        // feeds the projection's parent lookup.
                        if name == "()" {
                            call_sig_member_parent.insert(node_id, owner_id);
                        }
                    }
                }
            }
            if local_decl_info.is_none() {
                per_file_all_decls[file_idx].insert(name.clone(), node_id);
            }
            if let Some((scope, _)) = local_decl_info {
                if value_visible {
                    scoped_local_value_decls[file_idx]
                        .entry(scope)
                        .or_default()
                        .insert(name.clone(), node_id);
                }
            } else if value_visible {
                per_file_value_decls[file_idx].insert(name.clone(), node_id);
            }
            if type_visible {
                per_file_type_decls[file_idx].insert(name, node_id);
            }
        }
        diagnostics.extend(pf.diagnostics.iter().cloned());
    }

    let mut ambient_global_value_decls: BTreeMap<String, NodeId> = BTreeMap::new();
    let mut ambient_global_type_decls: BTreeMap<String, NodeId> = BTreeMap::new();
    for (file_idx, pf) in parsed.iter().enumerate() {
        let declaration_file = pf.path.ends_with(".d.ts")
            || pf.path.ends_with(".d.mts")
            || pf.path.ends_with(".d.cts");
        let external_module = !pf.exports.is_empty()
            || pf.events.iter().any(|event| {
                matches!(
                    event,
                    Event::Ref(crate::ts::events::RefEvent::Import {
                        makes_external_module: true,
                        ..
                    })
                )
            });
        if !declaration_file {
            continue;
        }
        let explicit_ambient_names = if external_module {
            pf.ambient_global_decl_names
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        } else {
            BTreeSet::new()
        };
        if external_module && explicit_ambient_names.is_empty() {
            continue;
        }
        for (name, node) in &per_file_value_decls[file_idx] {
            if external_module && !explicit_ambient_names.contains(name) {
                continue;
            }
            insert_ambient_node(&mut ambient_global_value_decls, name, *node);
        }
        for (name, node) in &per_file_type_decls[file_idx] {
            if external_module && !explicit_ambient_names.contains(name) {
                continue;
            }
            insert_ambient_node(&mut ambient_global_type_decls, name, *node);
        }
    }

    // ---- Pass 2.5: exports fixpoint ----
    use crate::ts::canonicalize::{is_external_uri_specifier, is_relative_specifier};
    use crate::ts::diagnostics::DiagnosticKind;
    use crate::ts::events::ExportEntry;

    #[derive(Clone)]
    enum ResolvedExport {
        Local {
            node: NodeId,
            /// True when this export is type-only (`export type { X }` /
            /// `export { type X }`, or any hop of a re-export chain was). A
            /// type-only export must not satisfy a value-position import.
            type_only: bool,
        },
        DualLocal {
            value_node: NodeId,
            type_node: NodeId,
            /// True when the export path itself is type-only. The type target
            /// remains importable, but the value target must not satisfy a
            /// runtime/value-position import.
            type_only: bool,
        },
        Forwarded {
            target_idx: usize,
            target_name: String,
            type_only: bool,
        },
        NamespaceObject {
            target_idx: usize,
            node: NodeId,
            type_only: bool,
        },
        Unresolved(UnresolvedReason),
    }

    #[derive(Clone)]
    enum UnresolvedReason {
        // These variants mark *why* an export is unresolved. They are
        // constructed in Pass 2.5 but the specific reason is never read back
        // (Pass 3 matches `ResolvedExport::Unresolved(_)` without inspecting
        // it; the user-facing diagnostics — PhantomImport, DeadExport,
        // ReExportCycle — are emitted at construction time here, not derived
        // from the stored reason). They are kept as fieldless markers for
        // readability/intent; `PhantomFrom` deliberately carries NO data
        // (the earlier `specifier: String` field was never read → dead_code).
        DeadExport,
        PhantomFrom,
        Cycle,
        Ambiguous,
    }

    fn export_type_only(export: &ResolvedExport) -> bool {
        match export {
            ResolvedExport::Local { type_only, .. }
            | ResolvedExport::DualLocal { type_only, .. }
            | ResolvedExport::Forwarded { type_only, .. }
            | ResolvedExport::NamespaceObject { type_only, .. } => *type_only,
            ResolvedExport::Unresolved(_) => false,
        }
    }

    fn export_value_node(
        export: &ResolvedExport,
        node_kinds: &[crate::schema::NodeKind],
    ) -> Option<NodeId> {
        match export {
            ResolvedExport::Local { node, type_only } => {
                let kind = node_kinds[node.as_usize()];
                (!*type_only && export_target_is_value_shaped(kind)).then_some(*node)
            }
            ResolvedExport::DualLocal {
                value_node,
                type_only,
                ..
            } => (!*type_only).then_some(*value_node),
            ResolvedExport::NamespaceObject {
                node, type_only, ..
            } => (!*type_only).then_some(*node),
            ResolvedExport::Forwarded { .. } | ResolvedExport::Unresolved(_) => None,
        }
    }

    fn export_type_node(
        export: &ResolvedExport,
        node_kinds: &[crate::schema::NodeKind],
    ) -> Option<NodeId> {
        match export {
            ResolvedExport::Local { node, .. } => {
                let kind = node_kinds[node.as_usize()];
                export_target_is_type_shaped(kind).then_some(*node)
            }
            ResolvedExport::DualLocal { type_node, .. } => Some(*type_node),
            ResolvedExport::NamespaceObject { node, .. } => Some(*node),
            ResolvedExport::Forwarded { .. } | ResolvedExport::Unresolved(_) => None,
        }
    }

    fn export_type_query_node(
        export: &ResolvedExport,
        node_kinds: &[crate::schema::NodeKind],
    ) -> Option<NodeId> {
        match export {
            ResolvedExport::Local { node, .. } => {
                let kind = node_kinds[node.as_usize()];
                export_target_is_value_shaped(kind).then_some(*node)
            }
            ResolvedExport::DualLocal { value_node, .. } => Some(*value_node),
            ResolvedExport::NamespaceObject { node, .. } => Some(*node),
            ResolvedExport::Forwarded { .. } | ResolvedExport::Unresolved(_) => None,
        }
    }

    fn direct_export_node(
        d: &DeclEvent,
        local_name: &str,
        file_idx: usize,
        per_file_value_decls: &[BTreeMap<String, NodeId>],
        per_file_type_decls: &[BTreeMap<String, NodeId>],
        per_file_all_decls: &[BTreeMap<String, NodeId>],
    ) -> Option<NodeId> {
        match d {
            DeclEvent::Function { .. } | DeclEvent::Variable { .. } => {
                per_file_value_decls[file_idx].get(local_name).copied()
            }
            DeclEvent::Interface { .. } | DeclEvent::TypeAlias { .. } => {
                per_file_type_decls[file_idx].get(local_name).copied()
            }
            DeclEvent::Class { .. } | DeclEvent::Namespace { .. } | DeclEvent::Enum { .. } => {
                per_file_value_decls[file_idx]
                    .get(local_name)
                    .copied()
                    .or_else(|| per_file_type_decls[file_idx].get(local_name).copied())
            }
            DeclEvent::Method { .. } | DeclEvent::ServiceMember { .. } => {
                per_file_all_decls[file_idx].get(local_name).copied()
            }
        }
    }

    fn local_named_export(
        local: &str,
        is_type_only: bool,
        file_idx: usize,
        per_file_value_decls: &[BTreeMap<String, NodeId>],
        per_file_type_decls: &[BTreeMap<String, NodeId>],
        per_file_all_decls: &[BTreeMap<String, NodeId>],
    ) -> Option<ResolvedExport> {
        if is_type_only {
            return per_file_type_decls[file_idx]
                .get(local)
                .copied()
                .or_else(|| per_file_value_decls[file_idx].get(local).copied())
                .or_else(|| per_file_all_decls[file_idx].get(local).copied())
                .map(|node| ResolvedExport::Local {
                    node,
                    type_only: true,
                });
        }

        let value_node = per_file_value_decls[file_idx].get(local).copied();
        let type_node = per_file_type_decls[file_idx].get(local).copied();
        match (value_node, type_node) {
            (Some(value_node), Some(type_node)) if value_node != type_node => {
                Some(ResolvedExport::DualLocal {
                    value_node,
                    type_node,
                    type_only: false,
                })
            }
            (Some(node), _) => Some(ResolvedExport::Local {
                node,
                type_only: false,
            }),
            (None, Some(node)) => Some(ResolvedExport::Local {
                node,
                type_only: false,
            }),
            (None, None) => per_file_all_decls[file_idx]
                .get(local)
                .copied()
                .map(|node| ResolvedExport::Local {
                    node,
                    type_only: false,
                }),
        }
    }

    fn merge_local_exports(
        existing: ResolvedExport,
        incoming: ResolvedExport,
        node_kinds: &[crate::schema::NodeKind],
    ) -> ResolvedExport {
        let localish = |export: &ResolvedExport| {
            matches!(
                export,
                ResolvedExport::Local { .. } | ResolvedExport::DualLocal { .. }
            )
        };
        if !localish(&existing) || !localish(&incoming) {
            return incoming;
        }

        let value_node = export_value_node(&incoming, node_kinds)
            .or_else(|| export_value_node(&existing, node_kinds));
        let type_node = export_type_node(&incoming, node_kinds)
            .or_else(|| export_type_node(&existing, node_kinds));
        let type_only = export_type_only(&existing) && export_type_only(&incoming);
        match (value_node, type_node) {
            (Some(value_node), Some(type_node)) if value_node != type_node => {
                ResolvedExport::DualLocal {
                    value_node,
                    type_node,
                    type_only,
                }
            }
            (Some(node), _) | (_, Some(node)) => ResolvedExport::Local { node, type_only },
            (None, None) => incoming,
        }
    }

    fn insert_export(
        map: &mut BTreeMap<String, ResolvedExport>,
        name: String,
        incoming: ResolvedExport,
        node_kinds: &[crate::schema::NodeKind],
    ) {
        let merged = match map.remove(&name) {
            Some(existing) => merge_local_exports(existing, incoming, node_kinds),
            None => incoming,
        };
        map.insert(name, merged);
    }

    let mut exports_map: Vec<BTreeMap<String, ResolvedExport>> =
        (0..files.len()).map(|_| BTreeMap::new()).collect();

    // Names this file *explicitly* exports (via Direct, Named, or NamedFrom).
    // Populated during the seed phase below. Used during `export *`
    // propagation so that an explicit local export silently wins over a
    // star-export of the same name — per TS semantics — without emitting
    // AmbiguousReExport. AmbiguousReExport fires ONLY when two namespace
    // re-exports contribute the same name and neither file has an explicit
    // export for it.
    let mut explicit_export_names: Vec<std::collections::BTreeSet<String>> = (0..files.len())
        .map(|_| std::collections::BTreeSet::new())
        .collect();

    // Queue of NamespaceEntries to process during fixpoint. The `from_span`
    // is carried so AmbiguousReExport / ReExportCycle diagnostics can point
    // at the actual `export *` clause rather than a synthetic position.
    let mut pending_namespace: Vec<Vec<(usize, String, crate::spans::Span)>> =
        (0..files.len()).map(|_| Vec::new()).collect();

    // (P2 round 4) Per-name origin span for star-resolved exports. When the
    // fixpoint copies a name from a star-target's exports_map into this
    // file's exports_map, also record the `from_span` of the originating
    // namespace clause. Used during the post-pass that synthesizes
    // Exports edges for star re-exports so that each resolved name's edge
    // points at the actual `export * from './...'` it came from, not the
    // first clause in the file.
    let mut star_origin_spans: Vec<BTreeMap<String, crate::spans::Span>> =
        (0..files.len()).map(|_| BTreeMap::new()).collect();

    // (P1 round 4) Bare-package star re-exports (`export * from 'external-pkg'`).
    // Tracked separately because canonicalize_import can't resolve a package,
    // so they never enter the fixpoint. Recorded here in source order, then
    // emitted by the post-pass as one Exports edge per entry targeting the
    // External node, with the parser-supplied label "*". This surfaces the
    // public forwarding boundary the IR was otherwise hiding.
    //
    // (Round 6) Each entry carries the External node id (created at seed
    // time via `add_external`) so the round-6 Forwarded resolver can
    // synthesize `ResolvedExport::Local { node: ext, ... }` for
    // `export { foo as publicFoo } from './leaf'` that forwards through
    // an opaque external boundary — without that synthesis, publicFoo
    // would be falsely marked `Unresolved(DeadExport)` and the rendered
    // barrel would silently lose the named opaque forwarding.
    let mut bare_package_namespace_exports: Vec<Vec<(String, crate::spans::Span, NodeId)>> =
        (0..files.len()).map(|_| Vec::new()).collect();

    // Per-file decls in source order, indexed by `decl_index`. Built once so
    // resolving a `Direct` export is an O(1) index instead of an O(n) rescan
    // of `pf.events` per export (which was O(n²) for files with many inline
    // `export`-ed decls — barrels / generated code).
    let decls_by_file: Vec<Vec<&DeclEvent>> = parsed
        .iter()
        .map(|pf| {
            pf.events
                .iter()
                .filter_map(|e| match e {
                    Event::Decl(d) => Some(d),
                    _ => None,
                })
                .collect()
        })
        .collect();

    let mut alias_candidates: Vec<String> = Vec::new();

    let mut imported_export_bindings: Vec<BTreeMap<String, ResolvedExport>> =
        (0..files.len()).map(|_| BTreeMap::new()).collect();
    for (file_idx, pf) in parsed.iter().enumerate() {
        let importing_path = &pf.path;
        for event in &pf.events {
            let Event::Ref(RefEvent::Import {
                specifier,
                bindings,
                is_type_only,
                ..
            }) = event
            else {
                continue;
            };
            let (canonical, known_first_party_miss) = canonicalize_available_import(
                importing_path,
                specifier,
                &path_to_idx,
                &known_project_path_to_idx,
                &options.alias_map,
                &mut alias_candidates,
            );
            let is_uri = is_external_uri_specifier(specifier);
            let is_bare_package = canonical.is_none()
                && !known_first_party_miss
                && !is_relative_specifier(specifier)
                && !is_uri;
            let is_non_code_asset = canonical.is_none()
                && is_relative_specifier(specifier)
                && is_non_code_asset_specifier(specifier);

            for binding in bindings {
                let binding_type_only = *is_type_only || binding.is_type_only;
                match binding.kind {
                    BindingKind::SideEffect => continue,
                    BindingKind::Namespace => {
                        if let Some(target_idx) = canonical
                            .as_ref()
                            .and_then(|canon| path_to_idx.get(canon))
                            .copied()
                        {
                            let node =
                                builder.add_unresolved(&binding.local, Some(NodeKind::Variable));
                            imported_export_bindings[file_idx].insert(
                                binding.local.clone(),
                                ResolvedExport::NamespaceObject {
                                    target_idx,
                                    node,
                                    type_only: binding_type_only,
                                },
                            );
                        } else if is_bare_package || is_non_code_asset || is_uri {
                            let origin = if is_bare_package {
                                crate::schema::ExternalOrigin::ImportedPackage
                            } else {
                                crate::schema::ExternalOrigin::Unknown
                            };
                            let package_origin = is_bare_package.then_some(specifier.as_str());
                            let ext = builder.add_external(
                                import_binding_external_name(binding),
                                origin,
                                package_origin,
                            );
                            imported_export_bindings[file_idx].insert(
                                binding.local.clone(),
                                ResolvedExport::Local {
                                    node: ext,
                                    type_only: binding_type_only,
                                },
                            );
                        }
                    }
                    BindingKind::Named | BindingKind::Default => {
                        if let Some(target_idx) = canonical
                            .as_ref()
                            .and_then(|canon| path_to_idx.get(canon))
                            .copied()
                        {
                            imported_export_bindings[file_idx].insert(
                                binding.local.clone(),
                                ResolvedExport::Forwarded {
                                    target_idx,
                                    target_name: binding.exported.clone(),
                                    type_only: binding_type_only,
                                },
                            );
                        } else if is_bare_package || is_non_code_asset || is_uri {
                            let origin = if is_bare_package {
                                crate::schema::ExternalOrigin::ImportedPackage
                            } else {
                                crate::schema::ExternalOrigin::Unknown
                            };
                            let package_origin = is_bare_package.then_some(specifier.as_str());
                            let ext = builder.add_external(
                                import_binding_external_name(binding),
                                origin,
                                package_origin,
                            );
                            imported_export_bindings[file_idx].insert(
                                binding.local.clone(),
                                ResolvedExport::Local {
                                    node: ext,
                                    type_only: binding_type_only,
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    // Seed.
    for (file_idx, pf) in parsed.iter().enumerate() {
        let importing_path = &pf.path;
        for export in &pf.exports {
            match export {
                ExportEntry::Direct {
                    decl_index,
                    exported,
                } => {
                    if let Some(d) = decls_by_file[file_idx].get(*decl_index as usize) {
                        let local_name = decl_name(d);
                        if let Some(node) = direct_export_node(
                            d,
                            local_name,
                            file_idx,
                            &per_file_value_decls,
                            &per_file_type_decls,
                            &per_file_all_decls,
                        ) {
                            // A direct decl export (`export class C`) is never type-only.
                            insert_export(
                                &mut exports_map[file_idx],
                                exported.clone(),
                                ResolvedExport::Local {
                                    node,
                                    type_only: false,
                                },
                                &builder.node_kinds,
                            );
                            explicit_export_names[file_idx].insert(exported.clone());
                        }
                    }
                }
                ExportEntry::Named {
                    local,
                    exported,
                    ref_span,
                    is_type_only,
                } => {
                    explicit_export_names[file_idx].insert(exported.clone());
                    if let Some(resolved) = local_named_export(
                        local,
                        *is_type_only,
                        file_idx,
                        &per_file_value_decls,
                        &per_file_type_decls,
                        &per_file_all_decls,
                    ) {
                        insert_export(
                            &mut exports_map[file_idx],
                            exported.clone(),
                            resolved,
                            &builder.node_kinds,
                        );
                    } else if let Some(imported) = imported_export_bindings[file_idx].get(local) {
                        let resolved = match imported {
                            ResolvedExport::Local { node, type_only } => ResolvedExport::Local {
                                node: *node,
                                type_only: *type_only || *is_type_only,
                            },
                            ResolvedExport::DualLocal {
                                value_node,
                                type_node,
                                type_only,
                            } => ResolvedExport::DualLocal {
                                value_node: *value_node,
                                type_node: *type_node,
                                type_only: *type_only || *is_type_only,
                            },
                            ResolvedExport::Forwarded {
                                target_idx,
                                target_name,
                                type_only,
                            } => ResolvedExport::Forwarded {
                                target_idx: *target_idx,
                                target_name: target_name.clone(),
                                type_only: *type_only || *is_type_only,
                            },
                            ResolvedExport::NamespaceObject {
                                target_idx,
                                node,
                                type_only,
                            } => ResolvedExport::NamespaceObject {
                                target_idx: *target_idx,
                                node: *node,
                                type_only: *type_only || *is_type_only,
                            },
                            ResolvedExport::Unresolved(reason) => {
                                ResolvedExport::Unresolved(reason.clone())
                            }
                        };
                        insert_export(
                            &mut exports_map[file_idx],
                            exported.clone(),
                            resolved,
                            &builder.node_kinds,
                        );
                    } else {
                        exports_map[file_idx].insert(
                            exported.clone(),
                            ResolvedExport::Unresolved(UnresolvedReason::DeadExport),
                        );
                        diagnostics.push(Diagnostic {
                            kind: DiagnosticKind::DeadExport {
                                name: local.clone(),
                            },
                            file_path: importing_path.clone(),
                            span: *ref_span,
                        });
                    }
                }
                ExportEntry::NamedFrom {
                    local,
                    exported,
                    from,
                    from_span,
                    is_type_only,
                    ..
                } => {
                    explicit_export_names[file_idx].insert(exported.clone());
                    let (canonical, known_first_party_miss) = canonicalize_available_import(
                        importing_path,
                        from,
                        &path_to_idx,
                        &known_project_path_to_idx,
                        &options.alias_map,
                        &mut alias_candidates,
                    );
                    match canonical {
                        Some(canon) => {
                            let target_idx = *path_to_idx.get(&canon).unwrap();
                            exports_map[file_idx].insert(
                                exported.clone(),
                                ResolvedExport::Forwarded {
                                    target_idx,
                                    target_name: local.clone(),
                                    type_only: *is_type_only,
                                },
                            );
                        }
                        None if known_first_party_miss || is_relative_specifier(from) => {
                            // Missing first-party re-export → genuine phantom.
                            exports_map[file_idx].insert(
                                exported.clone(),
                                ResolvedExport::Unresolved(UnresolvedReason::PhantomFrom),
                            );
                            diagnostics.push(Diagnostic {
                                kind: DiagnosticKind::PhantomImport {
                                    specifier: from.clone(),
                                },
                                file_path: importing_path.clone(),
                                span: *from_span,
                            });
                        }
                        None => {
                            // Bare external re-export (`export { x as y } from 'pkg'`):
                            // resolve to an External(ImportedPackage, pkg) symbol,
                            // NOT a phantom. Round-8 carries the package_origin so
                            // `foo from pkg-a` and `foo from pkg-b` get distinct
                            // NodeIds — without it, cross-pkg same-alias dedup'd to
                            // one node and the renderer/resolver couldn't tell them
                            // apart.
                            let ext = builder.add_external(
                                local,
                                crate::schema::ExternalOrigin::ImportedPackage,
                                Some(from),
                            );
                            exports_map[file_idx].insert(
                                exported.clone(),
                                ResolvedExport::Local {
                                    node: ext,
                                    type_only: *is_type_only,
                                },
                            );
                        }
                    }
                }
                ExportEntry::Namespace { from, from_span } => {
                    let (canonical, known_first_party_miss) = canonicalize_available_import(
                        importing_path,
                        from,
                        &path_to_idx,
                        &known_project_path_to_idx,
                        &options.alias_map,
                        &mut alias_candidates,
                    );
                    if let Some(canon) = canonical {
                        let target_idx = *path_to_idx.get(&canon).unwrap();
                        pending_namespace[file_idx].push((target_idx, from.clone(), *from_span));
                    } else if known_first_party_miss || is_relative_specifier(from) {
                        // Missing first-party `export * from './x'` → phantom.
                        diagnostics.push(Diagnostic {
                            kind: DiagnosticKind::PhantomImport {
                                specifier: from.clone(),
                            },
                            file_path: importing_path.clone(),
                            span: *from_span,
                        });
                    } else {
                        // Bare `export * from 'pkg'`: an external package's
                        // exports can't be enumerated, but we MUST preserve
                        // the public forwarding boundary in the persisted
                        // IR (otherwise the renderer reports an empty
                        // module — a silent false claim about the public
                        // API surface). Create the External node up front
                        // so the round-6 Forwarded resolver can synthesize
                        // Local entries for named opaque forwarding
                        // (`export { foo as publicFoo } from './leaf'`).
                        // `add_external` is deduplicated by (name, origin,
                        // package_origin) so repeated bare stars to the same
                        // pkg share one node. Round 8: pass pkg as
                        // package_origin for round-trip provenance.
                        let ext = builder.add_external(
                            from,
                            crate::schema::ExternalOrigin::ImportedPackage,
                            Some(from),
                        );
                        bare_package_namespace_exports[file_idx].push((
                            from.clone(),
                            *from_span,
                            ext,
                        ));
                    }
                }
                ExportEntry::NamespaceAs {
                    local,
                    from,
                    local_span: _,
                    from_span,
                } => {
                    let (canonical, known_first_party_miss) = canonicalize_available_import(
                        importing_path,
                        from,
                        &path_to_idx,
                        &known_project_path_to_idx,
                        &options.alias_map,
                        &mut alias_candidates,
                    );
                    if let Some(canon) = canonical {
                        let target_idx = *path_to_idx.get(&canon).unwrap();
                        let node = builder.add_unresolved(local, Some(NodeKind::Variable));
                        exports_map[file_idx].insert(
                            local.clone(),
                            ResolvedExport::NamespaceObject {
                                target_idx,
                                node,
                                type_only: false,
                            },
                        );
                    } else if known_first_party_miss {
                        diagnostics.push(Diagnostic {
                            kind: DiagnosticKind::PhantomImport {
                                specifier: from.clone(),
                            },
                            file_path: importing_path.clone(),
                            span: *from_span,
                        });
                        let node = builder.add_unresolved(local, Some(NodeKind::Variable));
                        exports_map[file_idx].insert(
                            local.clone(),
                            ResolvedExport::NamespaceObject {
                                target_idx: usize::MAX,
                                node,
                                type_only: false,
                            },
                        );
                    } else if is_relative_specifier(from) && !is_non_code_asset_specifier(from) {
                        diagnostics.push(Diagnostic {
                            kind: DiagnosticKind::PhantomImport {
                                specifier: from.clone(),
                            },
                            file_path: importing_path.clone(),
                            span: *from_span,
                        });
                        exports_map[file_idx].insert(
                            local.clone(),
                            ResolvedExport::Unresolved(UnresolvedReason::PhantomFrom),
                        );
                    } else {
                        let is_bare_package =
                            !is_relative_specifier(from) && !is_external_uri_specifier(from);
                        let origin = if is_bare_package {
                            crate::schema::ExternalOrigin::ImportedPackage
                        } else {
                            crate::schema::ExternalOrigin::Unknown
                        };
                        let package_origin = is_bare_package.then_some(from.as_str());
                        let ext = builder.add_external(local, origin, package_origin);
                        exports_map[file_idx].insert(
                            local.clone(),
                            ResolvedExport::Local {
                                node: ext,
                                type_only: false,
                            },
                        );
                    }
                }
            }
        }
    }

    // Fixpoint iteration.
    let max_rounds = 2 * files.len().max(1);
    for _ in 0..max_rounds {
        let mut changed = false;
        for file_idx in 0..files.len() {
            // Chase Forwarded chains.
            let keys: Vec<String> = exports_map[file_idx].keys().cloned().collect();
            for key in keys {
                let cur = exports_map[file_idx].get(&key).cloned().unwrap();
                if let ResolvedExport::Forwarded {
                    target_idx,
                    target_name,
                    type_only: fwd_type_only,
                } = cur
                {
                    match exports_map[target_idx].get(&target_name).cloned() {
                        Some(ResolvedExport::Local { node, type_only }) => {
                            // Compose: the chain is type-only if THIS hop or the
                            // resolved target is type-only.
                            exports_map[file_idx].insert(
                                key,
                                ResolvedExport::Local {
                                    node,
                                    type_only: fwd_type_only || type_only,
                                },
                            );
                            changed = true;
                        }
                        Some(ResolvedExport::DualLocal {
                            value_node,
                            type_node,
                            type_only,
                        }) => {
                            exports_map[file_idx].insert(
                                key,
                                ResolvedExport::DualLocal {
                                    value_node,
                                    type_node,
                                    type_only: fwd_type_only || type_only,
                                },
                            );
                            changed = true;
                        }
                        Some(ResolvedExport::NamespaceObject {
                            target_idx: ns_target_idx,
                            node,
                            type_only,
                        }) => {
                            exports_map[file_idx].insert(
                                key,
                                ResolvedExport::NamespaceObject {
                                    target_idx: ns_target_idx,
                                    node,
                                    type_only: fwd_type_only || type_only,
                                },
                            );
                            changed = true;
                        }
                        Some(ResolvedExport::Unresolved(r)) => {
                            exports_map[file_idx].insert(key, ResolvedExport::Unresolved(r));
                            changed = true;
                        }
                        None => {
                            // Round 6 Fix 1: if the target file has an opaque
                            // external-star boundary, the name might forward
                            // through it. We can't prove which package's
                            // export supplies the name, but the chain is NOT
                            // dead — claim it as opaque-external. Synthesize
                            // a Local entry pointing at the first
                            // bare-package External node (deterministic by
                            // source order) so the rendered edge surfaces
                            // `<label> (external) (re-exported)` with the
                            // package visible via the renderer's special
                            // case for External targets.
                            //
                            // Ordering: if the target still has unprocessed
                            // pending_namespace clauses, those might
                            // contribute a bare-pkg boundary via round-5
                            // propagation in a later fixpoint round. Don't
                            // prematurely mark DeadExport — leave as
                            // Forwarded so the next round re-checks. Only
                            // conclude DeadExport when both sides are
                            // drained.
                            //
                            // Round 8 multi-candidate: when the target has
                            // exactly ONE bare-pkg boundary, the synthesized
                            // Local can honestly point at that pkg's External
                            // (which now carries package_origin). With MORE
                            // than one bare-pkg, attribution is genuinely
                            // uncertain — pointing at the first would
                            // source-order-depend the rendered "from `<pkg>`"
                            // suffix. Route to a provenance-less sentinel
                            // External so the renderer's no-provenance
                            // branch correctly suppresses the suffix.
                            let bare = &bare_package_namespace_exports[target_idx];
                            if bare.len() == 1 {
                                let ext = bare[0].2;
                                exports_map[file_idx].insert(
                                    key,
                                    ResolvedExport::Local {
                                        node: ext,
                                        type_only: fwd_type_only,
                                    },
                                );
                                changed = true;
                            } else if !bare.is_empty() {
                                let sentinel = builder.add_external(
                                    "<opaque>",
                                    crate::schema::ExternalOrigin::Unknown,
                                    None,
                                );
                                exports_map[file_idx].insert(
                                    key,
                                    ResolvedExport::Local {
                                        node: sentinel,
                                        type_only: fwd_type_only,
                                    },
                                );
                                changed = true;
                            } else if pending_namespace[target_idx].is_empty() {
                                exports_map[file_idx].insert(
                                    key,
                                    ResolvedExport::Unresolved(UnresolvedReason::DeadExport),
                                );
                                changed = true;
                            }
                            // else: target may still gain a bare-pkg
                            // boundary; leave Forwarded for the next round.
                            // The existing cycle-cleanup pass below handles
                            // Forwarded entries that survive the fixpoint.
                        }
                        Some(ResolvedExport::Forwarded { .. }) => { /* not yet resolved */ }
                    }
                }
            }
            // Process Namespace queue. A target is "ready to copy from" only if
            // (a) it has no remaining Forwarded entries to chase AND (b) its own
            // pending_namespace is empty (otherwise it might still gain new
            // entries). Without (b), pure `export * from` cycles (a↔b with no
            // other exports) would copy-nothing on round 1, get retained-as-
            // empty, and silently disappear from the queue without a cycle
            // diagnostic.
            let pending: Vec<_> = pending_namespace[file_idx].clone();
            let mut processed_indices: Vec<usize> = Vec::new();
            for (i, (target_idx, source_path, from_span)) in pending.iter().enumerate() {
                let target_ready = !exports_map[*target_idx]
                    .values()
                    .any(|v| matches!(v, ResolvedExport::Forwarded { .. }))
                    && pending_namespace[*target_idx].is_empty();
                if !target_ready {
                    continue;
                }
                let target_entries: Vec<(String, ResolvedExport)> = exports_map[*target_idx]
                    .iter()
                    // ES/TS rule: `export * from './x'` does NOT re-export
                    // `./x`'s default export. Without this skip, a barrel's
                    // star would forward `default` and an importer's
                    // `import foo from './barrel'` would silently resolve
                    // through. Explicit re-exports (`export { default as X }
                    // from './x'`) use Named/NamedFrom, not Namespace —
                    // those paths are not affected by this filter.
                    .filter(|(k, _)| k.as_str() != "default")
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                for (k, v) in target_entries {
                    if exports_map[file_idx].contains_key(&k) {
                        if explicit_export_names[file_idx].contains(&k) {
                            // Explicit local export silently wins over a
                            // star-re-exported name of the same key — TS rule.
                            // No diagnostic; we don't overwrite the explicit
                            // entry.
                            continue;
                        }
                        // Same-binding diamond is NOT ambiguous: two star
                        // paths that resolve to the SAME NodeId are what
                        // native ES modules expose as one export. With the
                        // round-8 External provenance fix, NodeId equality
                        // is once again sound binding identity even across
                        // External targets — `foo from pkg-a` and
                        // `foo from pkg-b` now get DISTINCT NodeIds (dedup
                        // by (name, origin, package_origin)), so the
                        // round-7 "not External" conservative exclusion
                        // is no longer needed and would block the
                        // legitimate same-pkg same-alias External diamond.
                        let existing = exports_map[file_idx].get(&k).cloned();
                        if let (
                            Some(ResolvedExport::Local {
                                node: old_node,
                                type_only: old_to,
                            }),
                            ResolvedExport::Local {
                                node: new_node,
                                type_only: new_to,
                            },
                        ) = (&existing, &v)
                        {
                            if old_node == new_node {
                                // Merge type-only conservatively: the export
                                // is type-only only if EVERY path is
                                // type-only; if any path is runtime, the
                                // merged export is runtime.
                                exports_map[file_idx].insert(
                                    k,
                                    ResolvedExport::Local {
                                        node: *old_node,
                                        type_only: *old_to && *new_to,
                                    },
                                );
                                continue;
                            }
                        }
                        if let (
                            Some(ResolvedExport::DualLocal {
                                value_node: old_value,
                                type_node: old_type,
                                type_only: old_to,
                            }),
                            ResolvedExport::DualLocal {
                                value_node: new_value,
                                type_node: new_type,
                                type_only: new_to,
                            },
                        ) = (&existing, &v)
                        {
                            if old_value == new_value && old_type == new_type {
                                exports_map[file_idx].insert(
                                    k,
                                    ResolvedExport::DualLocal {
                                        value_node: *old_value,
                                        type_node: *old_type,
                                        type_only: *old_to && *new_to,
                                    },
                                );
                                continue;
                            }
                        }
                        // The existing entry was itself contributed by another
                        // `export *` — two star-re-exports colliding on the
                        // same name with DIFFERENT bindings. This is the
                        // genuinely ambiguous case. Per TS semantics the name
                        // is NOT validly importable through the barrel, so
                        // overwrite with Unresolved: otherwise importers
                        // would resolve to whichever star source landed
                        // first, masking the ambiguity with a false edge.
                        diagnostics.push(Diagnostic {
                            kind: DiagnosticKind::AmbiguousReExport {
                                name: k.clone(),
                                sources: vec![source_path.clone()],
                            },
                            file_path: parsed[file_idx].path.clone(),
                            span: *from_span,
                        });
                        exports_map[file_idx]
                            .insert(k, ResolvedExport::Unresolved(UnresolvedReason::Ambiguous));
                        changed = true;
                        continue;
                    }
                    // Record this name's originating namespace span before
                    // inserting. P2 round 4: each star-re-exported name's
                    // edge must point at its own `export * from './…'`
                    // clause, not the first one in the file.
                    star_origin_spans[file_idx].insert(k.clone(), *from_span);
                    exports_map[file_idx].insert(k, v);
                    changed = true;
                }
                // P1 round 5: transitive bare-package boundary propagation.
                // The target's bare-package star clauses (kept outside
                // exports_map because they aren't per-name entries) must
                // ALSO flow through `export * from './target'`. Without
                // this, `index.ts: export * from './leaf'` where
                // `leaf.ts: export * from 'external-pkg'` would render
                // index.ts as silently empty. Use THIS file's
                // `from_span` so the propagated edge points at
                // index.ts's own clause — that's the source position a
                // reader of index.ts would expect. The External node id
                // propagates verbatim (add_external is dedup'd by name,
                // so the same pkg is the same node across files). Dedup
                // by package name so multiple paths to the same pkg
                // collapse to one forwarding edge from this file.
                let propagated: Vec<(String, NodeId)> = bare_package_namespace_exports[*target_idx]
                    .iter()
                    .map(|(pkg, _, ext)| (pkg.clone(), *ext))
                    .collect();
                for (pkg, ext) in propagated {
                    if !bare_package_namespace_exports[file_idx]
                        .iter()
                        .any(|(p, _, _)| p == &pkg)
                    {
                        bare_package_namespace_exports[file_idx].push((pkg, *from_span, ext));
                        changed = true;
                    }
                }
                processed_indices.push(i);
            }
            // Drop only the entries we actually processed; everything else stays
            // queued so a later round (or cycle cleanup) sees it.
            for i in processed_indices.iter().rev() {
                pending_namespace[file_idx].swap_remove(*i);
            }
        }
        if !changed {
            break;
        }
    }

    // Cycle cleanup. Two classes of residue indicate a cycle:
    //   (a) Forwarded entries that never resolved (named-from chain cycles).
    //   (b) pending_namespace entries that never found a "ready" target
    //       (pure `export * from` cycles).
    // Both → ReExportCycle, with the involved files listed. The diagnostic's
    // own span/file points at the first encountered residue's source location
    // (a Namespace `from_span` if available; otherwise the first cycle file
    // with a positive byte 0 placeholder) — picking deterministically so the
    // gate's "diagnostics are stable across runs" invariant holds.
    let mut cycle_files: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut cycle_diag_file: Option<String> = None;
    let mut cycle_diag_span: Option<crate::spans::Span> = None;
    for (file_idx, m) in exports_map.iter_mut().enumerate() {
        let keys: Vec<String> = m
            .iter()
            .filter_map(|(k, v)| {
                if matches!(v, ResolvedExport::Forwarded { .. }) {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        if !keys.is_empty() {
            cycle_files.insert(parsed[file_idx].path.clone());
            for k in keys {
                m.insert(k, ResolvedExport::Unresolved(UnresolvedReason::Cycle));
            }
        }
    }
    for (file_idx, queue) in pending_namespace.iter().enumerate() {
        if let Some((_, _, span)) = queue.first() {
            cycle_files.insert(parsed[file_idx].path.clone());
            if cycle_diag_file.is_none() {
                cycle_diag_file = Some(parsed[file_idx].path.clone());
                cycle_diag_span = Some(*span);
            }
        }
    }
    if !cycle_files.is_empty() {
        diagnostics.push(Diagnostic {
            kind: DiagnosticKind::ReExportCycle {
                files: cycle_files.into_iter().collect(),
            },
            // Pure `export *` cycle: prefer the first residue Namespace entry's span.
            // Forwarded-chain cycle (no pending residue): fall back to the first
            // cycle file's path + a zero-length span at byte 0 (no single concrete
            // span captures a chain across files).
            file_path: cycle_diag_file.unwrap_or_else(|| parsed[0].path.clone()),
            span: cycle_diag_span.unwrap_or_else(|| crate::spans::Span::new(0, 0)),
        });
    }

    fn decl_name(d: &DeclEvent) -> &str {
        match d {
            DeclEvent::Function { name, .. }
            | DeclEvent::Class { name, .. }
            | DeclEvent::Interface { name, .. }
            | DeclEvent::Namespace { name, .. }
            | DeclEvent::TypeAlias { name, .. }
            | DeclEvent::Enum { name, .. }
            | DeclEvent::Variable { name, .. }
            | DeclEvent::Method { name, .. }
            | DeclEvent::ServiceMember { name, .. } => name,
        }
    }

    /// Resolve a ref's `owner` to the node that should source its edge:
    /// the enclosing decl node, or (for top-level `owner == None`) a lazily
    /// created per-file `ModuleInit` node linked `File --Contains--> ModuleInit`.
    /// Only call this when an edge is actually being emitted, so files with no
    /// top-level behavioral ref get no `ModuleInit` node.
    fn owner_node(
        builder: &mut GraphBuilder,
        owner: Option<u32>,
        file_id: NodeId,
        file_idx: usize,
        per_file_decl_node_ids: &[Vec<NodeId>],
        module_init: &mut Option<NodeId>,
    ) -> NodeId {
        match owner {
            Some(idx) => per_file_decl_node_ids[file_idx]
                .get(idx as usize)
                .copied()
                .unwrap_or(file_id),
            None => *module_init.get_or_insert_with(|| {
                let mi = builder.add_node(
                    NodeKind::ModuleInit,
                    "<module>",
                    crate::spans::NodeSpans::ABSENT,
                );
                builder.add_edge(file_id, EdgeKind::Contains, mi, None);
                mi
            }),
        }
    }

    // ---- Pass 3: emit reference edges ----
    use crate::schema::ExternalOrigin;
    use crate::ts::events::{BindingKind, RefEvent};
    // G1.7 Fix 1 — a TYPE's own call-signature parameter surface, recorded
    // as Pass 3 emits TypeRef edges: `type node → [ParamAnnotation
    // targets]`. Two source shapes accumulate under a type node: (a) the
    // reserved `"()"` call-signature member's ParamAnnotation edges (object
    // aliases / interfaces with call signatures — member params were lifted
    // onto their own member nodes by Fix 2, so they can NEVER land here);
    // (b) ParamAnnotation edges whose source IS the Interface/TypeAlias
    // node itself (pure function-type aliases like
    // `type Instance = (opts: ProbeOpts) => string`, whose params still
    // attribute to the alias — there is no member to lift onto).
    // Consumed by the factory-return projection post-pass below Pass 3.
    let mut call_sig_param_targets: HashMap<NodeId, Vec<NodeId>> = HashMap::new();

    // Two binding namespaces, per spec §2.4 / §6.6:
    // - `local_value_refs`: bindings usable in value position (Call / ValueRef).
    // - `local_type_refs`:  bindings usable in type position (TypeRef / heritage).
    //
    // `import type { X } from './t'` populates ONLY the type map (X cannot be
    // called or used as a value at runtime — it erases). A plain
    // `import { X } from './v'` populates BOTH maps (in TS, a non-type-only
    // named import can name either a value or a type depending on what `./v`
    // actually exports, so we treat the binding as live in both namespaces).
    // `per_file_value_decls` / `per_file_type_decls` (built in Pass 2) split
    // the file's own decls by TS namespace: Function/Variable → value only,
    // Interface/TypeAlias → type only, Class/Enum → both. Lookups fall back
    // to the namespace-appropriate map so an `interface I {}` can never
    // silently satisfy a value-position `I()` call.
    let mut local_value_refs: Vec<BTreeMap<String, NodeId>> =
        (0..files.len()).map(|_| BTreeMap::new()).collect();
    let mut local_type_refs: Vec<BTreeMap<String, NodeId>> =
        (0..files.len()).map(|_| BTreeMap::new()).collect();
    let mut local_type_query_refs: Vec<BTreeMap<String, NodeId>> =
        (0..files.len()).map(|_| BTreeMap::new()).collect();
    let mut namespace_import_targets: Vec<BTreeMap<String, usize>> =
        (0..files.len()).map(|_| BTreeMap::new()).collect();

    for (file_idx, pf) in parsed.iter().enumerate() {
        let file_id = file_ids[file_idx];
        let importing_path = &pf.path;
        // ---- Imports ----
        for ev in &pf.events {
            let Event::Ref(RefEvent::Import {
                specifier,
                specifier_span,
                bindings,
                is_type_only,
                ..
            }) = ev
            else {
                continue;
            };
            let (canonical, known_first_party_miss) = canonicalize_available_import(
                importing_path,
                specifier,
                &path_to_idx,
                &known_project_path_to_idx,
                &options.alias_map,
                &mut alias_candidates,
            );
            // A non-relative specifier that didn't canonicalize is a bare npm
            // package import (`idb`, `react`, `@scope/pkg`, `node:fs`) — an
            // External(ImportedPackage), NOT a phantom. A relative specifier that
            // fails to canonicalize IS a phantom (missing local file → Leg B).
            let is_uri = is_external_uri_specifier(specifier);
            let is_bare_package = canonical.is_none()
                && !known_first_party_miss
                && !is_relative_specifier(specifier)
                && !is_uri;
            let is_non_code_asset = canonical.is_none()
                && is_relative_specifier(specifier)
                && is_non_code_asset_specifier(specifier);
            let target_id = match canonical {
                Some(ref canon) => file_ids[path_to_idx[canon]],
                // Web/URI specifier (#28): a real external dependency but NOT an
                // npm package — tag Unknown so it doesn't inflate package counts.
                None if is_uri => {
                    builder.add_external(specifier, ExternalOrigin::Unknown, Some(specifier))
                }
                // Style/image/font imports are real module-boundary facts in
                // frontend repos, but they are not TS/JS source files. Keep the
                // import edge and local bindings without emitting phantom noise.
                None if is_non_code_asset => {
                    builder.add_external(specifier, ExternalOrigin::Unknown, Some(specifier))
                }
                None if is_bare_package => builder.add_external(
                    specifier,
                    ExternalOrigin::ImportedPackage,
                    Some(specifier),
                ),
                None => {
                    let id = builder.add_unresolved(specifier, Some(NodeKind::Module));
                    diagnostics.push(Diagnostic {
                        kind: DiagnosticKind::PhantomImport {
                            specifier: specifier.clone(),
                        },
                        file_path: importing_path.clone(),
                        span: *specifier_span,
                    });
                    id
                }
            };
            // Statement-level `import type { … }` makes the module dependency
            // edge type-only. A mixed `import { type X, y }` is NOT a type-only
            // statement (it still emits `import { y }`), so the module edge
            // survives — the per-binding `type` modifier is resolved separately
            // below and does not affect this edge.
            // FU2 (v0.1.0-beta.1): format the import statement's bindings
            // into a single label string and attach it to the Imports edge.
            // Empty for `import './side-effect';` — that case keeps the
            // existing bare-specifier render.
            let bindings_label = format_import_bindings_label(bindings);
            builder.add_import_edge_with_bindings(
                file_id,
                target_id,
                Some(*specifier_span),
                *is_type_only,
                &bindings_label,
            );
            // Resolve each binding into the appropriate namespace(s).
            for b in bindings {
                let target_idx = canonical.as_ref().and_then(|c| path_to_idx.get(c)).copied();
                // Bare package bindings resolve to External(ImportedPackage)
                // symbols — they're real imports, not UnresolvedBinding /
                // NamespaceImportOpaque. Available in both namespaces unless the
                // binding is type-only. The node is named via
                // `import_binding_external_name` (the exported name, NOT the
                // local alias) so the federation Calls branch can match the
                // peer's exported surface; the lookup maps below stay keyed by
                // `b.local`.
                if is_bare_package {
                    if matches!(b.kind, BindingKind::SideEffect) {
                        continue;
                    }
                    let id = builder.add_external(
                        import_binding_external_name(b),
                        ExternalOrigin::ImportedPackage,
                        Some(specifier),
                    );
                    if !*is_type_only && !b.is_type_only {
                        local_value_refs[file_idx].insert(b.local.clone(), id);
                    }
                    local_type_refs[file_idx].insert(b.local.clone(), id);
                    continue;
                }
                if is_non_code_asset {
                    if matches!(b.kind, BindingKind::SideEffect) {
                        continue;
                    }
                    // Non-code assets (`import styles from './x.css'`) are
                    // `ExternalOrigin::Unknown` and are never federated, so the
                    // exported-name identity rule above does not apply: there is
                    // no cross-repo exported symbol to match. The node keeps the
                    // local binding name; the asset's specifier is carried
                    // separately as the package origin.
                    let id =
                        builder.add_external(&b.local, ExternalOrigin::Unknown, Some(specifier));
                    if !*is_type_only && !b.is_type_only {
                        local_value_refs[file_idx].insert(b.local.clone(), id);
                    }
                    local_type_refs[file_idx].insert(b.local.clone(), id);
                    continue;
                }
                match b.kind {
                    BindingKind::SideEffect => continue,
                    BindingKind::Namespace => {
                        // Namespace imports still have no first-class Namespace
                        // node in v0. Keep a placeholder for refs to the namespace
                        // object itself, but remember the target file when the
                        // import resolves locally so `ns.exported` member refs can
                        // resolve through that file's export map.
                        let id = match imported_export_bindings[file_idx].get(&b.local) {
                            Some(ResolvedExport::NamespaceObject { node, .. }) => *node,
                            _ => builder.add_unresolved(&b.local, Some(NodeKind::Variable)),
                        };
                        if let Some(t_idx) = target_idx {
                            namespace_import_targets[file_idx].insert(b.local.clone(), t_idx);
                        } else {
                            diagnostics.push(Diagnostic {
                                kind: DiagnosticKind::NamespaceImportOpaque {
                                    local: b.local.clone(),
                                    from: specifier.clone(),
                                },
                                file_path: importing_path.clone(),
                                span: b.local_span,
                            });
                        }
                        if !*is_type_only && !b.is_type_only {
                            local_value_refs[file_idx].insert(b.local.clone(), id);
                        }
                        local_type_refs[file_idx].insert(b.local.clone(), id);
                    }
                    BindingKind::Named | BindingKind::Default => {
                        let namespace_resolved: Option<(usize, NodeId, bool)> = match target_idx {
                            Some(t_idx) => match exports_map[t_idx].get(&b.exported).cloned() {
                                Some(ResolvedExport::NamespaceObject {
                                    target_idx,
                                    node,
                                    type_only,
                                }) => Some((target_idx, node, type_only)),
                                _ => None,
                            },
                            None => None,
                        };
                        if let Some((namespace_target_idx, id, export_type_only)) =
                            namespace_resolved
                        {
                            let binding_type_only = *is_type_only || b.is_type_only;
                            if !binding_type_only && !export_type_only {
                                local_value_refs[file_idx].insert(b.local.clone(), id);
                            }
                            local_type_refs[file_idx].insert(b.local.clone(), id);
                            namespace_import_targets[file_idx]
                                .insert(b.local.clone(), namespace_target_idx);
                            continue;
                        }

                        let resolved_export: Option<ResolvedExport> = match target_idx {
                            Some(t_idx) => match exports_map[t_idx].get(&b.exported).cloned() {
                                Some(ResolvedExport::Local { .. })
                                | Some(ResolvedExport::DualLocal { .. }) => {
                                    exports_map[t_idx].get(&b.exported).cloned()
                                }
                                Some(ResolvedExport::Unresolved(_)) | None => None,
                                Some(
                                    ResolvedExport::Forwarded { .. }
                                    | ResolvedExport::NamespaceObject { .. },
                                ) => None,
                            },
                            None => None,
                        }
                        .or_else(|| {
                            if matches!(b.kind, BindingKind::Default) && b.exported == "default" {
                                default_import_recovery_target(
                                    &b.local,
                                    canonical.as_deref(),
                                    target_idx,
                                    &per_file_all_decls,
                                    &builder.node_kinds,
                                )
                                .map(|node| {
                                    ResolvedExport::Local {
                                        node,
                                        type_only: false,
                                    }
                                })
                            } else {
                                None
                            }
                        });
                        let resolved_export = match resolved_export {
                            Some(resolved_export) => resolved_export,
                            None => {
                                diagnostics.push(Diagnostic {
                                    kind: DiagnosticKind::UnresolvedBinding {
                                        binding: b.exported.clone(),
                                        from_file: specifier.clone(),
                                    },
                                    file_path: importing_path.clone(),
                                    span: b.local_span,
                                });
                                ResolvedExport::Local {
                                    node: builder
                                        .add_unresolved(&b.exported, Some(NodeKind::Function)),
                                    type_only: false,
                                }
                            }
                        };
                        let binding_type_only = *is_type_only || b.is_type_only;
                        if !binding_type_only {
                            if let Some(value_node) =
                                export_value_node(&resolved_export, &builder.node_kinds)
                            {
                                local_value_refs[file_idx].insert(b.local.clone(), value_node);
                            }
                        }
                        if let Some(type_node) =
                            export_type_node(&resolved_export, &builder.node_kinds)
                        {
                            local_type_refs[file_idx].insert(b.local.clone(), type_node);
                        }
                        if binding_type_only {
                            if let Some(type_query_node) =
                                export_type_query_node(&resolved_export, &builder.node_kinds)
                            {
                                local_type_query_refs[file_idx]
                                    .insert(b.local.clone(), type_query_node);
                            }
                        }
                    }
                }
            }
        }
        // ---- Calls / ValueRefs / TypeRefs ----
        // Resolution decision on a miss (spec §3.1/§3.2, §4.3):
        //  - resolves locally/imported          → edge from the OWNER node
        //  - known locally, wrong namespace      → UnresolvedReference (real drift,
        //      e.g. `interface I` used as `I()`, or a value-only `Foo` used as a type)
        //  - miss + language builtin             → drop silently (ubiquitous noise)
        //  - miss + curated runtime global       → External(AmbientGlobal)
        //  - miss + VALUE, otherwise             → UnresolvedReference (undefined
        //      var / typo — the phantom-detection signal the gate's Leg B checks)
        //  - miss + TYPE, otherwise              → External(Unknown) (ambient lib
        //      type like IDBValidKey, indistinguishable from a typo without lib.d.ts)
        // The value/type asymmetry resolves the spec's own tension between §3.1
        // ("Unknown absorbs typos") and the Leg B falsifiability gate: undefined
        // VALUE refs stay a signal; undefined TYPE refs are treated as ambient.
        // Owner node is resolved lazily so files with no emitted ref get no
        // ModuleInit node.
        let mut module_init: Option<NodeId> = None;
        #[derive(Clone, Copy)]
        enum RefSpace {
            Value,
            Type,
            TypeQuery,
        }
        for ev in &pf.events {
            let (
                name,
                owner,
                scope,
                span,
                edge_kind,
                ref_space,
                type_ref_position,
                argument_anchors,
            ) = match ev {
                Event::Ref(RefEvent::Call {
                    name,
                    call_span,
                    owner,
                    scope,
                    argument_anchors,
                }) => (
                    name,
                    *owner,
                    *scope,
                    *call_span,
                    EdgeKind::Calls,
                    RefSpace::Value,
                    None,
                    argument_anchors.clone(),
                ),
                Event::Ref(RefEvent::ValueRef {
                    name,
                    ref_span,
                    owner,
                    scope,
                }) => (
                    name,
                    *owner,
                    *scope,
                    *ref_span,
                    EdgeKind::ValueRef,
                    RefSpace::Value,
                    None,
                    Vec::new(),
                ),
                Event::Ref(RefEvent::TypeQueryRef {
                    name,
                    ref_span,
                    owner,
                    scope,
                }) => (
                    name,
                    *owner,
                    *scope,
                    *ref_span,
                    EdgeKind::ValueRef,
                    RefSpace::TypeQuery,
                    None,
                    Vec::new(),
                ),
                Event::Ref(RefEvent::TypeRef {
                    name,
                    ref_span,
                    owner,
                    scope,
                    // F2-3: parse-time position discriminant now threaded
                    // through to `GraphBuilder::add_type_ref_edge` below.
                    position,
                }) => (
                    name,
                    *owner,
                    *scope,
                    *ref_span,
                    EdgeKind::TypeRef,
                    RefSpace::Type,
                    Some(*position),
                    Vec::new(),
                ),
                _ => continue,
            };

            let resolved = match ref_space {
                RefSpace::Value => lookup_value_in_scope(
                    name,
                    file_idx,
                    scope,
                    &scoped_local_value_decls,
                    &pf.scopes,
                    &local_value_refs,
                    &per_file_value_decls,
                )
                .or_else(|| ambient_global_value_decls.get(name).copied()),
                RefSpace::Type => {
                    lookup_type(name, file_idx, &local_type_refs, &per_file_type_decls)
                        .or_else(|| ambient_global_type_decls.get(name).copied())
                }
                RefSpace::TypeQuery => lookup_value_in_scope(
                    name,
                    file_idx,
                    scope,
                    &scoped_local_value_decls,
                    &pf.scopes,
                    &local_value_refs,
                    &per_file_value_decls,
                )
                .or_else(|| ambient_global_value_decls.get(name).copied())
                .or_else(|| local_type_query_refs[file_idx].get(name).copied())
                .or_else(|| lookup_type(name, file_idx, &local_type_refs, &per_file_type_decls))
                .or_else(|| ambient_global_type_decls.get(name).copied()),
            };

            let unresolved = |builder: &mut GraphBuilder, diagnostics: &mut Vec<Diagnostic>| {
                // Position is value/type; the expected-kind hint mirrors the
                // pre-unification behavior per edge: Calls→Function (callee),
                // ValueRef→Variable, TypeRef→Interface.
                let (position, kind) = match edge_kind {
                    EdgeKind::Calls => (
                        crate::ts::diagnostics::RefPosition::Value,
                        NodeKind::Function,
                    ),
                    EdgeKind::ValueRef => (
                        crate::ts::diagnostics::RefPosition::Value,
                        NodeKind::Variable,
                    ),
                    _ => (
                        crate::ts::diagnostics::RefPosition::Type,
                        NodeKind::Interface,
                    ),
                };
                diagnostics.push(Diagnostic {
                    kind: DiagnosticKind::UnresolvedReference {
                        name: name.clone(),
                        position,
                    },
                    file_path: importing_path.clone(),
                    span,
                });
                builder.add_unresolved(name, Some(kind))
            };

            let target = match resolved {
                Some(t) => Some(t),
                None => {
                    let is_value_like = matches!(ref_space, RefSpace::Value | RefSpace::TypeQuery);
                    let known_lexical_binding = is_value_like
                        && lookup_binding_in_scope_chain(
                            name,
                            file_idx,
                            scope,
                            &bindings_by_scope,
                            &pf.scopes,
                        )
                        .is_some();
                    let has_local_value = lookup_scoped_local_value(
                        name,
                        file_idx,
                        scope,
                        &scoped_local_value_decls,
                        &pf.scopes,
                    )
                    .is_some()
                        || local_value_refs[file_idx].contains_key(name)
                        || per_file_value_decls[file_idx].contains_key(name);
                    let curated_global = match ref_space {
                        RefSpace::Value => is_platform_value_global(name),
                        RefSpace::Type => is_platform_type_global(name),
                        RefSpace::TypeQuery => {
                            is_platform_value_global(name) || is_platform_type_global(name)
                        }
                    };
                    let resolver_only_ambient_global = match ref_space {
                        RefSpace::Value => resolver_only_ambient_names.values.contains(name),
                        RefSpace::Type => resolver_only_ambient_names.types.contains(name),
                        RefSpace::TypeQuery => {
                            resolver_only_ambient_names.values.contains(name)
                                || resolver_only_ambient_names.types.contains(name)
                        }
                    };
                    // Known locally (own decl or imported binding, EITHER
                    // namespace) but not usable here → cross-namespace drift.
                    let known_own_decl = per_file_all_decls[file_idx]
                        .get(name)
                        .and_then(|node| per_file_node_kinds[file_idx].get(node))
                        .is_some_and(|kind| *kind != NodeKind::Property);
                    let known_locally = has_local_value
                        || known_own_decl
                        || local_type_refs[file_idx].contains_key(name)
                        || local_type_query_refs[file_idx].contains_key(name);
                    let is_builtin = match ref_space {
                        RefSpace::Value => is_language_value_builtin(name),
                        RefSpace::Type => is_language_type_builtin(name),
                        RefSpace::TypeQuery => {
                            is_language_value_builtin(name) || is_language_type_builtin(name)
                        }
                    };
                    let function_local_type_alias = matches!(ref_space, RefSpace::Type)
                        && per_file_local_type_names[file_idx].contains(name.as_str());
                    if known_lexical_binding || is_builtin {
                        None // drop lexical locals and ubiquitous language builtins
                    } else if function_local_type_alias {
                        // Function-local type alias (e.g. `type X = ...`
                        // inside a function body): drop the ref silently.
                        // These names never produce graph nodes. This check
                        // must happen before `known_locally` so a same-name
                        // value binding (`const X = ...; type X = ...`) does
                        // not look like cross-namespace drift.
                        None
                    } else if is_value_like
                        && (curated_global || resolver_only_ambient_global)
                        && !has_local_value
                    {
                        // A type-only local declaration named like a runtime lib
                        // global (for example `interface File {}` plus
                        // `input instanceof File`) should not block the ambient
                        // value. Actual local value bindings resolve before this
                        // miss path or set `has_local_value`.
                        Some(builder.add_external(name, ExternalOrigin::AmbientGlobal, None))
                    } else if known_locally {
                        Some(unresolved(builder, &mut diagnostics))
                    } else if curated_global || resolver_only_ambient_global {
                        Some(builder.add_external(name, ExternalOrigin::AmbientGlobal, None))
                    } else if is_value_like {
                        // undefined value: keep the phantom-detection signal
                        Some(unresolved(builder, &mut diagnostics))
                    } else {
                        // undefined type: treat as an ambient lib type
                        Some(builder.add_external(name, ExternalOrigin::Unknown, None))
                    }
                }
            };

            if let Some(target) = target {
                let src = owner_node(
                    builder,
                    owner,
                    file_id,
                    file_idx,
                    &per_file_decl_node_ids,
                    &mut module_init,
                );
                if edge_kind == EdgeKind::TypeRef {
                    // F2-3: carry the parse-time position discriminant onto
                    // the edge so `collect_compiler_pressure` can key its
                    // type_dependency demotion rule off it. `type_ref_position`
                    // is always `Some` on this arm (see the `TypeRef` match
                    // above); `unwrap_or(Other)` is a defensive fallback, not
                    // a reachable path.
                    builder.add_type_ref_edge(
                        src,
                        target,
                        Some(span),
                        type_ref_position.unwrap_or(TypeRefPosition::Other),
                    );
                    // G1.7 Fix 1 — record the type's own call-signature
                    // parameter surface (see `call_sig_param_targets`'s
                    // declaration for the two source shapes).
                    if type_ref_position == Some(TypeRefPosition::ParamAnnotation) {
                        let type_key = if matches!(
                            builder.node_kinds.get(src.as_usize()).copied(),
                            Some(NodeKind::Interface) | Some(NodeKind::TypeAlias)
                        ) {
                            Some(src)
                        } else {
                            call_sig_member_parent.get(&src).copied()
                        };
                        if let Some(type_key) = type_key {
                            let targets = call_sig_param_targets.entry(type_key).or_default();
                            if !targets.contains(&target) {
                                targets.push(target);
                            }
                        }
                    }
                } else if edge_kind == EdgeKind::Calls {
                    // G1.6 fork (a): carry the parse-time argument-interior
                    // anchors onto the edge (empty for the overwhelming
                    // majority of calls) so `SpanView::
                    // call_argument_anchors_from_in` can read them back.
                    builder.add_calls_edge_with_argument_anchors(
                        src,
                        target,
                        Some(span),
                        argument_anchors,
                    );
                } else {
                    builder.add_edge(src, edge_kind, target, Some(span));
                }
            }
        }
        for ev in &pf.events {
            let Event::Ref(RefEvent::TypeMemberAccess {
                namespace,
                member,
                ref_span,
                owner,
                position,
                ..
            }) = ev
            else {
                continue;
            };
            let Some(target_idx) = namespace_import_targets[file_idx].get(namespace).copied()
            else {
                continue;
            };
            let Some(node) = exports_map[target_idx]
                .get(member)
                .and_then(|export| export_type_node(export, &builder.node_kinds))
            else {
                continue;
            };
            let src = owner_node(
                builder,
                *owner,
                file_id,
                file_idx,
                &per_file_decl_node_ids,
                &mut module_init,
            );
            // G1.5 F2-4 Part C: sibling TypeRef edge emission for `NS.Type`
            // qualified references. `RefEvent::TypeMemberAccess` now carries
            // the same parse-time `TypeRefPosition` its sibling head
            // `TypeRef(NS)` does (F2-4 extended the parser's emit site to
            // populate it from the identical classification context), so
            // this edge threads through `add_type_ref_edge` exactly like the
            // plain-`TypeRef` arm above instead of a position-less
            // `add_edge`.
            builder.add_type_ref_edge(src, node, Some(*ref_span), *position);
        }
        // ---- Heritage refs ----
        // Two distinct resolution policies, because the three heritage positions
        // have different namespace semantics (audit5, 2026-05-23):
        //
        //   `class X extends Y`                — Y is evaluated at RUNTIME as a
        //                                        constructor → VALUE-side lookup first.
        //                                        Local `const Alias = Base; class D extends Alias`
        //                                        must resolve to the local Variable. A local
        //                                        `const Error = Base` must SHADOW the
        //                                        ambient Error builtin (lookup_value first
        //                                        guarantees this).
        //
        //   `class X implements Z`             — Z is a TYPE (interface or compatible)
        //   `interface I extends J`            — J is a TYPE (interface or compatible)
        //                                        → TYPE-side lookup; value-side bindings
        //                                        are NOT valid here (TS would reject).
        //
        // Both policies share the same miss-fallback ladder:
        //   1. miss + TYPE-builtin (Error/Map/Set/Promise/all Error subclasses/...) →
        //        External(AmbientGlobal); preserves the Extends/Implements edge.
        //   2. miss, otherwise → UnresolvedReference(Heritage) + Unresolved node.
        //
        // We deliberately do NOT consult is_language_value_builtin in the fallback: it
        // includes value-only functions like parseInt/isNaN/encodeURI that have no
        // type semantics. `class C implements parseInt {}` must NOT be silently
        // accepted (audit3, 2026-05-23). For class-extends, the value-builtin
        // constructor classes ALL appear in is_language_type_builtin already (the same
        // list serves both type-position and value-position constructor needs),
        // so the type-builtin check covers Error/Map/Set/Promise even for class-extends.
        let heritage_miss_fallback = |h_name: &str,
                                      h_span: Span,
                                      expected_kind: NodeKind,
                                      builder: &mut GraphBuilder,
                                      diagnostics: &mut Vec<Diagnostic>|
         -> NodeId {
            if is_language_type_builtin(h_name)
                || is_platform_type_global(h_name)
                || resolver_only_ambient_names.types.contains(h_name)
            {
                return builder.add_external(h_name, ExternalOrigin::AmbientGlobal, None);
            }
            if h_span.length() > h_name.len() as u32 {
                return builder.add_external(h_name, ExternalOrigin::Unknown, None);
            }
            diagnostics.push(Diagnostic {
                kind: DiagnosticKind::UnresolvedReference {
                    name: h_name.to_string(),
                    position: crate::ts::diagnostics::RefPosition::Heritage,
                },
                file_path: importing_path.clone(),
                span: h_span,
            });
            builder.add_unresolved(h_name, Some(expected_kind))
        };
        // `class X extends Y` — value-first.
        let resolve_class_extends = |h_name: &str,
                                     h_span,
                                     scope: Option<crate::ts::events::ScopeId>,
                                     builder: &mut GraphBuilder,
                                     diagnostics: &mut Vec<Diagnostic>|
         -> Option<NodeId> {
            if let Some(t) = scope
                .and_then(|scope| {
                    lookup_scoped_local_value(
                        h_name,
                        file_idx,
                        scope,
                        &scoped_local_value_decls,
                        &pf.scopes,
                    )
                })
                .or_else(|| {
                    lookup_value(h_name, file_idx, &local_value_refs, &per_file_value_decls)
                })
                .or_else(|| ambient_global_value_decls.get(h_name).copied())
            {
                return Some(t);
            }
            if resolver_only_ambient_names.values.contains(h_name) {
                return Some(builder.add_external(h_name, ExternalOrigin::AmbientGlobal, None));
            }
            if scope
                .and_then(|scope| {
                    lookup_binding_in_scope_chain(
                        h_name,
                        file_idx,
                        scope,
                        &bindings_by_scope,
                        &pf.scopes,
                    )
                })
                .is_some()
            {
                return None;
            }
            Some(heritage_miss_fallback(
                h_name,
                h_span,
                NodeKind::Class,
                builder,
                diagnostics,
            ))
        };
        // `class X implements Z` / `interface I extends J` — type-only.
        let resolve_type_heritage = |h_name: &str,
                                     h_span,
                                     expected_kind: NodeKind,
                                     builder: &mut GraphBuilder,
                                     diagnostics: &mut Vec<Diagnostic>|
         -> NodeId {
            if let Some(t) = lookup_type(h_name, file_idx, &local_type_refs, &per_file_type_decls)
                .or_else(|| ambient_global_type_decls.get(h_name).copied())
            {
                return t;
            }
            if resolver_only_ambient_names.types.contains(h_name) {
                return builder.add_external(h_name, ExternalOrigin::AmbientGlobal, None);
            }
            heritage_miss_fallback(h_name, h_span, expected_kind, builder, diagnostics)
        };
        let mut decl_index = 0usize;
        for ev in &pf.events {
            let Event::Decl(d) = ev else { continue };
            match d {
                DeclEvent::Class {
                    extends,
                    implements,
                    ..
                } => {
                    let Some(class_node) =
                        per_file_decl_node_ids[file_idx].get(decl_index).copied()
                    else {
                        decl_index += 1;
                        continue;
                    };
                    let local_class_scope = local_value_decl_scopes[file_idx]
                        .get(&(decl_index as u32))
                        .map(|(scope, _)| *scope);
                    for h in extends {
                        if let Some(target) = resolve_class_extends(
                            &h.name,
                            h.ref_span,
                            local_class_scope,
                            builder,
                            &mut diagnostics,
                        ) {
                            builder.add_edge(
                                class_node,
                                EdgeKind::Extends,
                                target,
                                Some(h.ref_span),
                            );
                        }
                    }
                    for h in implements {
                        let target = resolve_type_heritage(
                            &h.name,
                            h.ref_span,
                            NodeKind::Interface,
                            builder,
                            &mut diagnostics,
                        );
                        builder.add_edge(
                            class_node,
                            EdgeKind::Implements,
                            target,
                            Some(h.ref_span),
                        );
                    }
                }
                DeclEvent::Interface { name, extends, .. } => {
                    let iface_node = per_file_all_decls[file_idx][name];
                    for h in extends {
                        let target = resolve_type_heritage(
                            &h.name,
                            h.ref_span,
                            NodeKind::Interface,
                            builder,
                            &mut diagnostics,
                        );
                        builder.add_edge(iface_node, EdgeKind::Extends, target, Some(h.ref_span));
                    }
                }
                _ => {}
            }
            decl_index += 1;
        }
        // ---- Exports edges for every named export shape (spec §6.6 step 6,
        //      source-spans spec §3.7 line 151 — "Exports spans Always present"). ----
        //
        // Direct      → target = the decl node;             span = decl's name_span
        // Named       → target = the local decl node;       span = ref_span
        // NamedFrom   → target = post-fixpoint resolution;  span = ref_span
        // Namespace   → no single named export; skip
        // NamespaceAs → punted (no Namespace node kind); skip
        //
        // For NamedFrom the target is whatever the exports_map resolves
        // `exported` to after the fixpoint. If the resolution is still
        // `Forwarded` (cycle survived) or `Unresolved` (phantom from / dead),
        // we skip the edge — those errors already produced diagnostics in
        // Pass 2.5; an extra Exports edge to a phantom node would just be noise.
        for export in &pf.exports {
            match export {
                ExportEntry::Direct {
                    decl_index,
                    exported,
                } => {
                    if let Some(d) = decls_by_file[file_idx].get(*decl_index as usize) {
                        let name = decl_name(d);
                        let name_span = decl_name_span(d);
                        if let Some(node) = direct_export_node(
                            d,
                            name,
                            file_idx,
                            &per_file_value_decls,
                            &per_file_type_decls,
                            &per_file_all_decls,
                        ) {
                            // Pass the parser's `exported` label so the renderer
                            // can show "default" for `export default function Impl()`
                            // and the correct alias for any other Direct export.
                            builder.add_export_edge_with_label(
                                file_id,
                                node,
                                Some(name_span),
                                false,
                                exported,
                            );
                        }
                    }
                }
                ExportEntry::Named {
                    local,
                    exported,
                    ref_span,
                    is_type_only,
                } => {
                    if let Some(resolved) = local_named_export(
                        local,
                        *is_type_only,
                        file_idx,
                        &per_file_value_decls,
                        &per_file_type_decls,
                        &per_file_all_decls,
                    ) {
                        if let Some(node) = export_value_node(&resolved, &builder.node_kinds) {
                            builder.add_export_edge_with_label(
                                file_id,
                                node,
                                Some(*ref_span),
                                *is_type_only || export_type_only(&resolved),
                                exported,
                            );
                        }
                        if let Some(node) = export_type_node(&resolved, &builder.node_kinds) {
                            if Some(node) != export_value_node(&resolved, &builder.node_kinds) {
                                builder.add_export_edge_with_label(
                                    file_id,
                                    node,
                                    Some(*ref_span),
                                    *is_type_only || export_type_only(&resolved),
                                    exported,
                                );
                            }
                        }
                    } else if let Some(ResolvedExport::Local { node, type_only }) =
                        exports_map[file_idx].get(exported)
                    {
                        builder.add_export_edge_with_label(
                            file_id,
                            *node,
                            Some(*ref_span),
                            *is_type_only || *type_only,
                            exported,
                        );
                    } else if let Some(ResolvedExport::DualLocal {
                        value_node,
                        type_node,
                        type_only,
                    }) = exports_map[file_idx].get(exported)
                    {
                        builder.add_export_edge_with_label(
                            file_id,
                            *value_node,
                            Some(*ref_span),
                            *is_type_only || *type_only,
                            exported,
                        );
                        builder.add_export_edge_with_label(
                            file_id,
                            *type_node,
                            Some(*ref_span),
                            *is_type_only || *type_only,
                            exported,
                        );
                    } else if let Some(ResolvedExport::NamespaceObject {
                        node, type_only, ..
                    }) = exports_map[file_idx].get(exported)
                    {
                        builder.add_export_edge_with_label(
                            file_id,
                            *node,
                            Some(*ref_span),
                            *is_type_only || *type_only,
                            exported,
                        );
                    }
                    // No edge if `local` isn't declared — Pass 2.5 already emitted
                    // DeadExport with the same span.
                }
                ExportEntry::NamedFrom {
                    exported,
                    ref_span,
                    is_type_only,
                    ..
                } => {
                    match exports_map[file_idx].get(exported) {
                        Some(ResolvedExport::Local { node, .. }) => {
                            // Syntactic per-edge marker: true when the specifier
                            // is type-only — either list-level `export type { X }`
                            // or per-specifier `export { type X }`. This is the
                            // local syntactic flag, NOT the re-export-chain
                            // fixpoint (verbatimModuleSyntax fidelity — spec §2).
                            builder.add_export_edge_with_label(
                                file_id,
                                *node,
                                Some(*ref_span),
                                *is_type_only,
                                exported,
                            );
                        }
                        Some(ResolvedExport::DualLocal {
                            value_node,
                            type_node,
                            ..
                        }) => {
                            builder.add_export_edge_with_label(
                                file_id,
                                *value_node,
                                Some(*ref_span),
                                *is_type_only,
                                exported,
                            );
                            builder.add_export_edge_with_label(
                                file_id,
                                *type_node,
                                Some(*ref_span),
                                *is_type_only,
                                exported,
                            );
                        }
                        Some(ResolvedExport::NamespaceObject { node, .. }) => {
                            builder.add_export_edge_with_label(
                                file_id,
                                *node,
                                Some(*ref_span),
                                *is_type_only,
                                exported,
                            );
                        }
                        _ => { /* Forwarded survivor or Unresolved — skip. */ }
                    }
                }
                ExportEntry::Namespace { .. } => {
                    // export * — handled in the post-pass below, which walks
                    // the fixpoint-resolved exports_map for names that don't
                    // appear in explicit_export_names.
                }
                ExportEntry::NamespaceAs {
                    local, local_span, ..
                } => {
                    match exports_map[file_idx].get(local) {
                        Some(ResolvedExport::Local { node, type_only }) => {
                            builder.add_export_edge_with_label(
                                file_id,
                                *node,
                                Some(*local_span),
                                *type_only,
                                local,
                            );
                        }
                        Some(ResolvedExport::DualLocal {
                            value_node,
                            type_node,
                            type_only,
                        }) => {
                            builder.add_export_edge_with_label(
                                file_id,
                                *value_node,
                                Some(*local_span),
                                *type_only,
                                local,
                            );
                            builder.add_export_edge_with_label(
                                file_id,
                                *type_node,
                                Some(*local_span),
                                *type_only,
                                local,
                            );
                        }
                        Some(ResolvedExport::NamespaceObject {
                            node, type_only, ..
                        }) => {
                            builder.add_export_edge_with_label(
                                file_id,
                                *node,
                                Some(*local_span),
                                *type_only,
                                local,
                            );
                        }
                        _ => {
                            // Phantom/missing namespace target — diagnostic already emitted.
                        }
                    }
                }
            }
        }

        // ---- Star re-export edge emission (P1 #2 + round-4 P2 fix).
        //
        // `export * from './x'` doesn't appear as one-name-per-edge in the
        // parser's `pf.exports`, but the fixpoint pass populates
        // `exports_map[file_idx]` with one `ResolvedExport::Local` entry per
        // re-exported name (filtered to skip `default` — star re-exports do
        // not propagate it per ES spec). Walk exports_map and emit one
        // labeled Exports edge per resolved name that was NOT explicitly
        // exported by this file — those are exactly the star-re-exported
        // names. Use `star_origin_spans[file_idx]` so each name's edge
        // points at its OWN originating namespace clause.
        let star_emissions: Vec<(String, NodeId, bool, Option<crate::spans::Span>)> = exports_map
            [file_idx]
            .iter()
            .flat_map(|(k, v)| {
                if explicit_export_names[file_idx].contains(k) {
                    return Vec::new();
                }
                let span = star_origin_spans[file_idx].get(k).copied();
                match v {
                    ResolvedExport::Local { node, type_only }
                    | ResolvedExport::NamespaceObject {
                        node, type_only, ..
                    } => vec![(k.clone(), *node, *type_only, span)],
                    ResolvedExport::DualLocal {
                        value_node,
                        type_node,
                        type_only,
                    } => vec![
                        (k.clone(), *value_node, *type_only, span),
                        (k.clone(), *type_node, *type_only, span),
                    ],
                    _ => Vec::new(),
                }
            })
            .collect();
        for (name, node, type_only, span) in star_emissions {
            builder.add_export_edge_with_label(file_id, node, span, type_only, &name);
        }

        // ---- Bare-package star re-export boundary (P1 round 4 fix).
        //
        // `export * from 'external-pkg'` cannot be enumerated, but the
        // forwarding boundary must be visible to consumers — otherwise
        // a barrel renders as an empty public module. Emit one Exports
        // edge per entry targeting the External(ImportedPackage) node
        // recorded at seed time, with the label `"*"`. The renderer
        // surfaces the package name via its External-target special case.
        for (_pkg, span, ext) in &bare_package_namespace_exports[file_idx] {
            builder.add_export_edge_with_label(file_id, *ext, Some(*span), false, "*");
        }
    }

    // ---- v0.6 commit 4 — global function-returns + method-returns index ----
    //
    // For `FactoryRef::Plain { name }` lookups, we need to map
    // `name` (resolved via `lookup_value` to a Function/Variable
    // NodeId, possibly cross-file via imports) to the class name
    // the factory declared as its return type. The parser
    // populates a per-file `function_returns: Vec<FunctionReturn>`
    // sidecar; here we project it to a global `NodeId → String`
    // map keyed by the Function or Variable decl's NodeId.
    //
    // For `FactoryRef::Static { class_name, method_name }`
    // lookups (commit 5), the resolver walks `methods_of_class`
    // to find the Property NodeId for the static method, then
    // consults `method_return_class` to read the declared return
    // class. Built here from `DeclEvent::Method.return_class_name`
    // for symmetry with `function_returns_by_node_id`.
    //
    // Both maps key off NodeIds materialized in Pass 2, so this
    // build must come AFTER Pass 2 and BEFORE the MemberAccess
    // resolution pass below. Cross-file resolution composes for
    // free through the existing `lookup_value` / `lookup_type`
    // chained-import behavior — no separate cross-file lookup
    // logic needed.
    // v0.6 commit 4 — values carry both the declared return-class
    // name AND the file_idx of the factory's own file. The class
    // name is resolved against the *factory's* file's type
    // namespace (where the return-type Ident is named), not the
    // consumer's. Without the file_idx, cross-file Pattern F
    // breaks: a consumer importing only `makeClient` doesn't have
    // `Client` in its own type namespace, so a consumer-file
    // `lookup_type("Client", consumer_file_idx, …)` always fails.
    // Storing the factory's file_idx lets the resolver call
    // `lookup_type("Client", factory_file_idx, …)` correctly.
    let mut function_returns_by_node_id: std::collections::HashMap<NodeId, (String, usize)> =
        std::collections::HashMap::new();
    // G1.7 Fix 2 — the coupled-closer side table: module-scope variables
    // with an EXPLICIT type annotation (`const api: Api = …`), keyed by the
    // variable decl's NodeId, valued (type name, declaring file_idx) — the
    // same shape as `function_returns_by_node_id`, resolved against the
    // DECLARING file's type namespace. Consumed by the no-binding member-
    // dispatch arm: a consumer-file `api.get(...)` whose receiver resolves
    // (cross-file, via imports) to that Variable chases this edge into
    // `members_of_type`. ScopeId(0) is always the module top-level
    // (`ParsedFile::scopes` doc), and the restriction matters: a FUNCTION-
    // LOCAL `const api: Local = …` binding must never be attributed to a
    // same-named module-level Variable node.
    let mut variable_declared_type_by_node_id: std::collections::HashMap<NodeId, (String, usize)> =
        std::collections::HashMap::new();
    for (file_idx, pf) in parsed.iter().enumerate() {
        for binding in &pf.bindings {
            if binding.scope != 0 {
                continue;
            }
            let Some(crate::ts::events::ClassOrigin::ExplicitType { class_name }) = &binding.origin
            else {
                continue;
            };
            if let Some(node_id) = per_file_value_decls[file_idx].get(&binding.name).copied() {
                variable_declared_type_by_node_id.insert(node_id, (class_name.clone(), file_idx));
            }
        }
    }
    let mut method_return_class: std::collections::HashMap<NodeId, (String, usize)> =
        std::collections::HashMap::new();
    // v0.7 commit 4 — global field-type-class index for
    // property-chain resolution. Same shape as
    // method_return_class: keyed by Property NodeId, value
    // carries (declared field class name, file_idx of the field's
    // defining class — i.e., the file whose type namespace the
    // class name should be resolved in). Populated from
    // `DeclEvent::Method.field_type_class` for `kind ==
    // MemberKind::Field` members in the same Pass 2 walk that
    // builds the function/method-return indexes.
    let mut field_type_class_by_property_node: std::collections::HashMap<NodeId, (String, usize)> =
        std::collections::HashMap::new();
    for (file_idx, pf) in parsed.iter().enumerate() {
        for fr in &pf.function_returns {
            if let Some(node_id) = per_file_decl_node_ids[file_idx]
                .get(fr.decl_index as usize)
                .copied()
            {
                function_returns_by_node_id.insert(node_id, (fr.class_name.clone(), file_idx));
            }
        }
        let mut decl_counter: u32 = 0;
        for ev in &pf.events {
            if let Event::Decl(d) = ev {
                if let DeclEvent::Method {
                    return_class_name: Some(rcn),
                    is_static: true,
                    ..
                } = d
                {
                    if let Some(node_id) = per_file_decl_node_ids[file_idx]
                        .get(decl_counter as usize)
                        .copied()
                    {
                        method_return_class.insert(node_id, (rcn.clone(), file_idx));
                    }
                }
                // v0.7 commit 4 — populate field-type index.
                // Only Field-kind members carry field_type_class;
                // other kinds always have None there per parser
                // commit 2's gate.
                if let DeclEvent::Method {
                    field_type_class: Some(ftc),
                    kind: crate::ts::events::MemberKind::Field,
                    ..
                } = d
                {
                    if let Some(node_id) = per_file_decl_node_ids[file_idx]
                        .get(decl_counter as usize)
                        .copied()
                    {
                        field_type_class_by_property_node.insert(node_id, (ftc.clone(), file_idx));
                    }
                }
                decl_counter += 1;
            }
        }
    }

    // ---- G1.7 Fix 1 — factory-return type propagation ----
    //
    // (a) `variable_factory_return_type_by_node_id`: module-scope variables
    // initialized from a PLAIN factory call (`const ky = createInstance()`)
    // whose factory has a DECLARED return type — keyed by the variable's
    // NodeId, valued (declared type name, factory's file_idx), the same
    // shape as `variable_declared_type_by_node_id`. Inferred-return
    // factories populate no `function_returns` entry, so they are inert
    // here by construction (the v0.6 Q9 exclusion, review condition F7).
    // Static-method factories (`FactoryRef::Static`) are a disclosed
    // deferral — ky's shape is Plain.
    //
    // DETERMINISM: this table is ITERATED by the projection post-pass
    // below, and every iteration emits edges into the builder — so it must
    // be a `BTreeMap`, never a `HashMap` (whose `RandomState` order would
    // reshuffle edge emission per run and break the frozen graph's
    // byte-determinism — caught by
    // `ts_corpus_gate::defu_corpus_is_clean_and_deterministic` on the
    // first multi-projection corpus). The sibling `*_by_node_id` tables
    // stay `HashMap` because they are only ever `.get()`-consulted.
    let mut variable_factory_return_type_by_node_id: std::collections::BTreeMap<
        NodeId,
        (String, usize),
    > = std::collections::BTreeMap::new();
    for (file_idx, pf) in parsed.iter().enumerate() {
        for binding in &pf.bindings {
            if binding.scope != 0 {
                continue;
            }
            let Some(crate::ts::events::ClassOrigin::FactoryReturn {
                factory_ref: crate::ts::events::FactoryRef::Plain { name: factory_name },
            }) = &binding.origin
            else {
                continue;
            };
            let Some(var_node) = per_file_value_decls[file_idx].get(&binding.name).copied() else {
                continue;
            };
            let Some(factory_node) = lookup_value(
                factory_name.as_str(),
                file_idx,
                &local_value_refs,
                &per_file_value_decls,
            ) else {
                continue;
            };
            if let Some((type_name, factory_file_idx)) =
                function_returns_by_node_id.get(&factory_node)
            {
                variable_factory_return_type_by_node_id
                    .insert(var_node, (type_name.clone(), *factory_file_idx));
            }
        }
    }
    // (b) The walk-side lever: mint the variable's declared-type edge and
    // project ONLY the type's own call-signature ParamAnnotation surface
    // (`call_sig_param_targets` — member params can never appear there,
    // Fix 2 lifted them onto member nodes; review condition F1) onto the
    // variable. The variable then becomes an eligible consumer callable
    // through the walk's EXISTING ParamAnnotation gate — zero walk
    // changes. Spans are None: these are derived edges with no source
    // text of their own.
    for (var_node, (type_name, factory_file_idx)) in &variable_factory_return_type_by_node_id {
        let Some(type_node) = lookup_type(
            type_name.as_str(),
            *factory_file_idx,
            &local_type_refs,
            &per_file_type_decls,
        ) else {
            continue;
        };
        if !matches!(
            builder.node_kinds.get(type_node.as_usize()).copied(),
            Some(NodeKind::Interface) | Some(NodeKind::TypeAlias)
        ) {
            continue;
        }
        builder.add_type_ref_edge(*var_node, type_node, None, TypeRefPosition::Annotation);
        if let Some(targets) = call_sig_param_targets.get(&type_node) {
            for target in targets {
                builder.add_type_ref_edge(
                    *var_node,
                    *target,
                    None,
                    TypeRefPosition::ParamAnnotation,
                );
            }
        }
    }

    // ---- v0.4 M1.L3 / v0.5 commit 4 — MemberAccess resolution ----
    //
    // After the main ref-event pass, walk every `RefEvent::MemberAccess`
    // emitted by the parser and try to resolve `receiver` to a Class
    // node. When the receiver scopes to a class AND that class has a
    // matching member (gated by `(is_static_gate, MemberKind::Method,
    // member)` in commit 4), emit a `Calls` edge from the call's
    // enclosing decl to the member's Property node.
    //
    // Commit-4 receiver coverage (unchanged from v0.4 / commit-1):
    //   * `MemberReceiver::This` — `this.m()` inside a class body
    //     (Pattern 4). We walk up the call's `owner` decl_index to
    //     find the enclosing class.
    //   * `MemberReceiver::Name { name, .. }` — `ClassName.m()` when
    //     `name` resolves to a Class in the value namespace
    //     (Pattern 5 / Pattern 7 genuine static dispatch). The
    //     `scope` field is parsed and carried through but commit 4
    //     does NOT walk the BindingEvent chain — that's commit 5's
    //     scope-walk path.
    //   * `MemberReceiver::Constructed { .. }` — `new C().m()`
    //     (Pattern 1). Commit 4 silently drops; commit 5 wires.
    //
    // Commit-4 access coverage: only `AccessKind::Call` resolves to
    // a Calls edge. `Read` and `Write` are emitted by the parser
    // but silently dropped here — commit 5 wires Getter/Setter/
    // Field candidate-kind composition.
    //
    // Unresolved MemberAccess events produce no IR edge and no
    // diagnostic — they continue to be silently invisible per the
    // documented Limitation::MemberDispatch.
    let mut module_init_l3: Vec<Option<NodeId>> = vec![None; files.len()];
    // G1.7 Fix 2 — the resolved receiver of a member access is no longer
    // always a Class. `Class` keeps the entire pre-G1.7 pipeline
    // (methods_of_class buckets, static gate, property-chain refinement)
    // byte-for-byte; `TypeMembers` is the new Interface/TypeAlias path
    // that dispatches through `members_of_type` (Call access only, no
    // static surface, no chain refinement — chains through type members
    // silently drop, same as every other unresolved member shape).
    enum MemberDispatchTarget {
        Class {
            class_id: NodeId,
            is_static_gate: bool,
        },
        TypeMembers {
            type_id: NodeId,
        },
    }
    for (file_idx, pf) in parsed.iter().enumerate() {
        let file_id = file_ids[file_idx];
        for ev in &pf.events {
            let Event::Ref(RefEvent::MemberAccess {
                receiver,
                member,
                access,
                site_span,
                owner,
                argument_anchors,
            }) = ev
            else {
                continue;
            };

            // v0.5 commit 5 — resolve receiver to (Class NodeId,
            // is_static_gate). The static gate decides whether the
            // member lookup matches static or instance members:
            //   * `this.m()` (Pattern 4) → instance gate (false).
            //   * `Class.m()` where `Class` is a value-namespace
            //     Class AND no shadowing binding exists at the
            //     access scope (Pattern 7) → static gate (true).
            //   * `new C().m()` (Pattern 1) → resolve `C` in the
            //     value namespace; instance gate (false).
            //   * `x.m()` where `x` is a local binding (Patterns
            //     2/3a/3b/P) → walk `ScopeInfo.parent` chain for a
            //     BindingEvent; ExplicitType origin resolves via
            //     the type namespace, Construction origin via the
            //     value namespace, None origin blocks fallback
            //     (per the locked shadowing rule).
            // The v0.4 Pattern-5 overmatch closes via the static
            // gate AND the commit-1 (is_static, MemberKind, name)
            // member-lookup key; commit 5 adds the binding-chain
            // resolution for the local / typed-param shapes.
            //
            // v0.7 commit 4 — peel any `PropertyChain` hops off
            // the receiver BEFORE the existing match runs. The
            // peeled root resolves via the existing v0.5/v0.6
            // logic; the chain hops are then walked
            // innermost-first via field-type lookups
            // (field_type_class_by_property_node + lookup_type
            // against the field's defining file's type namespace).
            // Bounded by MAX_PROPERTY_CHAIN_DEPTH per v0.7 Q1.
            const MAX_PROPERTY_CHAIN_DEPTH: usize = 4;
            let mut chain_hops: Vec<String> = Vec::new();
            let mut root_receiver = receiver;
            while let crate::ts::events::MemberReceiver::PropertyChain {
                base,
                member: hop_member,
            } = root_receiver
            {
                chain_hops.push(hop_member.clone());
                root_receiver = base.as_ref();
            }
            if chain_hops.len() > MAX_PROPERTY_CHAIN_DEPTH {
                // Silently drop deeper chains per the documented
                // Limitation. Real-world chains rarely exceed
                // 2-3 hops (zod ParseInputLazyPath is 1 hop; the
                // canonical NestJS `this.service.method()` is 1
                // hop); the cap is structural insurance.
                continue;
            }
            if chain_hops.is_empty() {
                if let crate::ts::events::MemberReceiver::Name { name, .. } = root_receiver {
                    if let Some(target_idx) = namespace_import_targets[file_idx].get(name).copied()
                    {
                        if let Some(node) = exports_map[target_idx]
                            .get(member)
                            .and_then(|export| export_value_node(export, &builder.node_kinds))
                        {
                            let owner_id = owner_node(
                                builder,
                                *owner,
                                file_id,
                                file_idx,
                                &per_file_decl_node_ids,
                                &mut module_init_l3[file_idx],
                            );
                            let edge_kind = match access {
                                crate::ts::events::AccessKind::Call => EdgeKind::Calls,
                                crate::ts::events::AccessKind::Read
                                | crate::ts::events::AccessKind::Write => EdgeKind::ValueRef,
                            };
                            builder.add_edge(owner_id, edge_kind, node, Some(*site_span));
                            continue;
                        }
                    }
                }
            }
            let dispatch_target: Option<MemberDispatchTarget> = match root_receiver {
                crate::ts::events::MemberReceiver::This => {
                    // Local initializer declarations inherit their enclosing
                    // receiver. Stop at a function declaration: its `this` is
                    // independent of any enclosing class.
                    owner.and_then(|mut owner_idx| loop {
                        match decls_by_file[file_idx].get(owner_idx as usize)? {
                            DeclEvent::Variable { .. } => {
                                let parent = local_value_decl_scopes[file_idx].get(&owner_idx)?.1?;
                                if parent >= owner_idx {
                                    return None;
                                }
                                owner_idx = parent;
                            }
                            DeclEvent::Method {
                                owner_class_decl_index,
                                is_static,
                                ..
                            } => {
                                return Some(MemberDispatchTarget::Class {
                                    class_id: *per_file_decl_node_ids[file_idx]
                                        .get(*owner_class_decl_index as usize)?,
                                    is_static_gate: *is_static,
                                });
                            }
                            DeclEvent::Class { .. } => {
                                return Some(MemberDispatchTarget::Class {
                                    class_id: *per_file_decl_node_ids[file_idx]
                                        .get(owner_idx as usize)?,
                                    is_static_gate: false,
                                });
                            }
                            _ => return None,
                        }
                    })
                }
                crate::ts::events::MemberReceiver::Name { name, scope } => {
                    // v0.5 commit 5 scope-walk: search the
                    // `ScopeInfo.parent` chain starting at the
                    // access-site scope for a BindingEvent with a
                    // matching name. The first match decides the
                    // outcome — even a `None` origin binding short-
                    // circuits the search (the locked shadowing
                    // rule: `const C = factory()` BLOCKS the outer
                    // `class C` from being found as a Pattern-7
                    // static-dispatch fallback).
                    let mut current: Option<crate::ts::events::ScopeId> = Some(*scope);
                    let mut found: Option<&crate::ts::events::BindingEvent> = None;
                    while let Some(scope_id) = current {
                        if let Some(b) = bindings_by_scope[file_idx]
                            .get(&scope_id)
                            .and_then(|by_name| by_name.get(name.as_str()))
                        {
                            found = Some(*b);
                            break;
                        }
                        current = pf.scopes.get(scope_id as usize).and_then(|s| s.parent);
                    }
                    // Class-kind filter that works for both same-file
                    // decls AND cross-file imports. `per_file_node_kinds`
                    // is only populated at the DECLARING file; imports
                    // alias an imported NodeId through `local_*_refs`
                    // but don't populate the per-file kind map. Reading
                    // `builder.node_kinds[id.as_usize()]` is universal
                    // because NodeIds are globally unique.
                    let is_class = |id: NodeId| -> bool {
                        builder.node_kinds.get(id.as_usize()).copied() == Some(NodeKind::Class)
                    };
                    match found {
                        Some(binding) => match &binding.origin {
                            Some(crate::ts::events::ClassOrigin::ExplicitType { class_name }) => {
                                // Patterns 3a / 3b / P / typed locals.
                                // Declared-type wins per the locked
                                // conflict rule. Resolve via the TYPE
                                // namespace (chained import + decl
                                // lookup). G1.7 Fix 2: a Class keeps the
                                // pre-existing path; an Interface/
                                // TypeAlias now dispatches through
                                // `members_of_type` instead of being
                                // rejected by the old class-only filter.
                                lookup_type(
                                    class_name.as_str(),
                                    file_idx,
                                    &local_type_refs,
                                    &per_file_type_decls,
                                )
                                .and_then(|id| {
                                    if is_class(id) {
                                        Some(MemberDispatchTarget::Class {
                                            class_id: id,
                                            is_static_gate: false,
                                        })
                                    } else if matches!(
                                        builder.node_kinds.get(id.as_usize()).copied(),
                                        Some(NodeKind::Interface) | Some(NodeKind::TypeAlias)
                                    ) {
                                        Some(MemberDispatchTarget::TypeMembers { type_id: id })
                                    } else {
                                        None
                                    }
                                })
                            }
                            Some(crate::ts::events::ClassOrigin::Construction { class_name }) => {
                                // Pattern 2: `const x = new C(); x.m()`.
                                // Resolve via the VALUE namespace
                                // (constructors live there) — chained
                                // import + decl lookup.
                                lookup_value(
                                    class_name.as_str(),
                                    file_idx,
                                    &local_value_refs,
                                    &per_file_value_decls,
                                )
                                .filter(|id| is_class(*id))
                                .map(|c| {
                                    MemberDispatchTarget::Class {
                                        class_id: c,
                                        is_static_gate: false,
                                    }
                                })
                            }
                            None => {
                                // Locked shadowing rule: a None-origin
                                // binding (e.g. `const x = factory()`,
                                // `let y = "literal"`) BLOCKS the
                                // outer-scope class-name fallback.
                                // Without this short-circuit, an inner
                                // `const C = factory()` would silently
                                // resolve `C.staticM()` to the outer
                                // `class C` — wrong, and exactly the
                                // shadow-correctness case the goal-doc
                                // calls out.
                                None
                            }
                            Some(crate::ts::events::ClassOrigin::FactoryReturn { factory_ref }) => {
                                // v0.6 commit 4 — Pattern F resolution.
                                // Dispatches on FactoryRef variant:
                                //   * Plain { name } — look up `name` in
                                //     value namespace (chained import-
                                //     aware), find the Function or
                                //     Variable NodeId, consult
                                //     function_returns_by_node_id for
                                //     the declared return class, then
                                //     resolve that class via type-
                                //     namespace lookup.
                                //   * Static { class_name, method_name }
                                //     — commit 5 (silently drops in
                                //     commit 4 — Static-factory
                                //     resolution requires the
                                //     `method_return_class` lookup,
                                //     which is built here but not yet
                                //     consumed in this arm).
                                //
                                // The instance gate is `false` (mirrors
                                // ExplicitType / Construction — a
                                // factory returns an instance, so the
                                // receiver dispatches on instance
                                // members).
                                match factory_ref {
                                    crate::ts::events::FactoryRef::Plain { name: factory_name } => {
                                        lookup_value(
                                            factory_name.as_str(),
                                            file_idx,
                                            &local_value_refs,
                                            &per_file_value_decls,
                                        )
                                        .and_then(|factory_node| {
                                            // Look up the factory's
                                            // declared return-class +
                                            // the file_idx of the
                                            // factory's own file (where
                                            // the class name is in
                                            // scope).
                                            function_returns_by_node_id.get(&factory_node).cloned()
                                        })
                                        .and_then(|(class_name, factory_file_idx)| {
                                            // Resolve the class in the
                                            // FACTORY's file's type
                                            // namespace, not the
                                            // consumer's — see the
                                            // function_returns_by_node_id
                                            // value-shape comment.
                                            lookup_type(
                                                class_name.as_str(),
                                                factory_file_idx,
                                                &local_type_refs,
                                                &per_file_type_decls,
                                            )
                                        })
                                        .and_then(|id| {
                                            // G1.7 Fix 1 — M0-J break 1's
                                            // `:3472` drop point: a Plain
                                            // factory whose declared
                                            // return resolves to an
                                            // Interface/TypeAlias (ky's
                                            // KyInstance) now dispatches
                                            // through members_of_type
                                            // instead of being rejected
                                            // by the class-only filter.
                                            if is_class(id) {
                                                Some(MemberDispatchTarget::Class {
                                                    class_id: id,
                                                    is_static_gate: false,
                                                })
                                            } else if matches!(
                                                builder.node_kinds.get(id.as_usize()).copied(),
                                                Some(NodeKind::Interface)
                                                    | Some(NodeKind::TypeAlias)
                                            ) {
                                                Some(MemberDispatchTarget::TypeMembers {
                                                    type_id: id,
                                                })
                                            } else {
                                                None
                                            }
                                        })
                                    }
                                    crate::ts::events::FactoryRef::Static {
                                        class_name: factory_class_name,
                                        method_name: factory_method_name,
                                    } => {
                                        // v0.6 commit 5 — Static-method
                                        // factory: `const x = S.create()`.
                                        // 1. Resolve `S` in value
                                        //    namespace (Class lives there
                                        //    too — chained import-aware).
                                        // 2. Use methods_of_class to find
                                        //    the Property node for
                                        //    (is_static=true, Method,
                                        //    method_name). This composes
                                        //    with the v0.5 MethodKind
                                        //    gate: only static methods
                                        //    qualify as factories.
                                        // 3. Read method_return_class for
                                        //    the Property NodeId → get
                                        //    (return_class_name, factory_
                                        //    class_file_idx). The factory
                                        //    class is the *defining* class
                                        //    of the static method, which
                                        //    is where the return-type
                                        //    Ident is named.
                                        // 4. Resolve the returned class
                                        //    in that file's type
                                        //    namespace.
                                        lookup_value(
                                            factory_class_name.as_str(),
                                            file_idx,
                                            &local_value_refs,
                                            &per_file_value_decls,
                                        )
                                        .filter(|id| is_class(*id))
                                        .and_then(|class_node| {
                                            methods_of_class
                                                .get(&class_node)
                                                .and_then(|m| {
                                                    m.get(&(
                                                        true,
                                                        crate::ts::events::MemberKind::Method,
                                                    ))
                                                })
                                                .and_then(|by_name| {
                                                    by_name
                                                        .get(factory_method_name.as_str())
                                                        .copied()
                                                })
                                        })
                                        .and_then(|prop_node| {
                                            method_return_class.get(&prop_node).cloned()
                                        })
                                        .and_then(|(rcn, factory_class_file_idx)| {
                                            lookup_type(
                                                rcn.as_str(),
                                                factory_class_file_idx,
                                                &local_type_refs,
                                                &per_file_type_decls,
                                            )
                                        })
                                        .filter(|id| is_class(*id))
                                        .map(|c| {
                                            MemberDispatchTarget::Class {
                                                class_id: c,
                                                is_static_gate: false,
                                            }
                                        })
                                    }
                                }
                            }
                        },
                        None => {
                            // No binding for `name` anywhere in the
                            // scope chain → fall back to value-
                            // namespace lookup (chained, so cross-file
                            // imports resolve). A Class dispatches with
                            // the static gate (Pattern 7), exactly as
                            // before.
                            //
                            // G1.7 Fix 2 — the committed coupled closer
                            // (PR #234 design review, condition F2): a
                            // VARIABLE receiver (e.g. a default-imported
                            // `api` whose origin decl is
                            // `const api: Api = …` in the declaring
                            // file) chases the variable's declared-type
                            // edge (`variable_declared_type_by_node_id`,
                            // resolved in the DECLARING file's type
                            // namespace) into `members_of_type`. Without
                            // the chase, the looked-up node IS the
                            // Variable — no type to dispatch through —
                            // which was M0-J break 1's `:3557` drop
                            // point. G1.7 Fix 1 (J1b) extends the chase
                            // to FACTORY-RETURN-typed variables
                            // (`variable_factory_return_type_by_node_id`)
                            // — shape B, ky's actual 125-class.
                            lookup_value(
                                name.as_str(),
                                file_idx,
                                &local_value_refs,
                                &per_file_value_decls,
                            )
                            .and_then(|id| {
                                if is_class(id) {
                                    return Some(MemberDispatchTarget::Class {
                                        class_id: id,
                                        is_static_gate: true,
                                    });
                                }
                                let (type_name, declaring_file_idx) =
                                    variable_declared_type_by_node_id.get(&id).or_else(|| {
                                        variable_factory_return_type_by_node_id.get(&id)
                                    })?;
                                lookup_type(
                                    type_name.as_str(),
                                    *declaring_file_idx,
                                    &local_type_refs,
                                    &per_file_type_decls,
                                )
                                .filter(|tid| {
                                    matches!(
                                        builder.node_kinds.get(tid.as_usize()).copied(),
                                        Some(NodeKind::Interface) | Some(NodeKind::TypeAlias)
                                    )
                                })
                                .map(|tid| MemberDispatchTarget::TypeMembers { type_id: tid })
                            })
                        }
                    }
                }
                crate::ts::events::MemberReceiver::Constructed { class_name } => {
                    // Pattern 1: `new C().m()`. Look up `C` in the
                    // value namespace (`new` uses the constructor,
                    // which is value-space) — chained import + decl
                    // lookup so cross-file `new C()` resolves too.
                    // The freshly-constructed receiver dispatches as
                    // an instance (is_static=false).
                    let is_class = |id: NodeId| -> bool {
                        builder.node_kinds.get(id.as_usize()).copied() == Some(NodeKind::Class)
                    };
                    lookup_value(
                        class_name.as_str(),
                        file_idx,
                        &local_value_refs,
                        &per_file_value_decls,
                    )
                    .filter(|id| is_class(*id))
                    .map(|c| MemberDispatchTarget::Class {
                        class_id: c,
                        is_static_gate: false,
                    })
                }
                crate::ts::events::MemberReceiver::PropertyChain { .. } => {
                    // v0.7 commit 4 — unreachable here because the
                    // peeling loop above strips all PropertyChain
                    // wrappers off the receiver before this match.
                    // The root_receiver bound for matching is
                    // guaranteed to be one of This / Name /
                    // Constructed at this point.
                    unreachable!(
                        "PropertyChain receivers are peeled before this match runs; this arm is for exhaustiveness only"
                    )
                }
            };

            // v0.7 commit 4 — walk chain_hops innermost-first to
            // refine the root-class into the chain-tail class. Each
            // hop: look up the field on the current class, read its
            // declared field_type_class, resolve that name in the
            // field's defining-file type namespace. The
            // (class_name, file_idx) pair stored in
            // field_type_class_by_property_node is the same shape
            // as v0.6's method_return_class — the file_idx is the
            // field's own class's file, where the type Ident is
            // named.
            //
            // If any hop fails (field not found, no declared type,
            // type doesn't resolve to a class), the whole chain
            // bails and the MemberAccess silently drops, per the
            // documented Limitation. A static-gated base (Pattern 7
            // `Class.field…`) also bails — static-receiver chains
            // are out of scope (Q4 — field chains apply to instance
            // receivers only).
            let dispatch_target = dispatch_target.and_then(|target| {
                let (class_id, gate) = match target {
                    MemberDispatchTarget::Class {
                        class_id,
                        is_static_gate,
                    } => (class_id, is_static_gate),
                    MemberDispatchTarget::TypeMembers { type_id } => {
                        // G1.7 Fix 2 — property chains THROUGH a type-
                        // shaped receiver (`api.sub.get(...)`) are out of
                        // scope: silently drop, per the documented
                        // Limitation, exactly like every other
                        // unresolvable chain hop.
                        return if chain_hops.is_empty() {
                            Some(MemberDispatchTarget::TypeMembers { type_id })
                        } else {
                            None
                        };
                    }
                };
                let is_class = |id: NodeId| -> bool {
                    builder.node_kinds.get(id.as_usize()).copied() == Some(NodeKind::Class)
                };
                let mut current_class = class_id;
                let mut current_gate = gate;
                for member_name in chain_hops.iter().rev() {
                    if current_gate {
                        return None;
                    }
                    let prop_node = methods_of_class
                        .get(&current_class)
                        .and_then(|m| m.get(&(false, crate::ts::events::MemberKind::Field)))
                        .and_then(|by_name| by_name.get(member_name.as_str()).copied())?;
                    let (field_type, field_file_idx) =
                        field_type_class_by_property_node.get(&prop_node).cloned()?;
                    let resolved = lookup_type(
                        field_type.as_str(),
                        field_file_idx,
                        &local_type_refs,
                        &per_file_type_decls,
                    )
                    .filter(|id| is_class(*id))?;
                    current_class = resolved;
                    current_gate = false;
                }
                Some(MemberDispatchTarget::Class {
                    class_id: current_class,
                    is_static_gate: current_gate,
                })
            });

            let Some(dispatch_target) = dispatch_target else {
                continue;
            };

            // v0.5 commit 5 — access-kind candidate gate. Each access
            // kind compose against a set of MemberKind candidates;
            // we try each in order and emit the first match. Field
            // declarations satisfy both Read and Write because a
            // declared property is intrinsically both readable and
            // writable (modulo `readonly`, which v0.5 treats as
            // Field for impact-analysis purposes — the TS checker
            // is the arbiter of legality).
            let method_node = match dispatch_target {
                MemberDispatchTarget::Class {
                    class_id,
                    is_static_gate,
                } => {
                    let candidate_kinds: &[crate::ts::events::MemberKind] = match access {
                        crate::ts::events::AccessKind::Call => {
                            &[crate::ts::events::MemberKind::Method]
                        }
                        crate::ts::events::AccessKind::Read => &[
                            crate::ts::events::MemberKind::Getter,
                            crate::ts::events::MemberKind::Field,
                        ],
                        crate::ts::events::AccessKind::Write => &[
                            crate::ts::events::MemberKind::Setter,
                            crate::ts::events::MemberKind::Field,
                        ],
                    };
                    candidate_kinds.iter().find_map(|kind| {
                        methods_of_class
                            .get(&class_id)
                            .and_then(|m| m.get(&(is_static_gate, *kind)))
                            .and_then(|by_name| by_name.get(member.as_str()).copied())
                    })
                }
                // G1.7 Fix 2 — type members are all call-shaped (the parser
                // mints function-typed members only); Read/Write access on
                // a type-shaped receiver silently drops like any other
                // unmatched member shape.
                MemberDispatchTarget::TypeMembers { type_id } => match access {
                    crate::ts::events::AccessKind::Call => members_of_type
                        .get(&type_id)
                        .and_then(|by_name| by_name.get(member.as_str()).copied()),
                    crate::ts::events::AccessKind::Read | crate::ts::events::AccessKind::Write => {
                        None
                    }
                },
            };
            let method_node = match method_node {
                Some(m) => m,
                None => {
                    // No matching member on this class. Either:
                    //   * The class member exists but doesn't match
                    //     the static gate (Pattern-5 overmatch fix —
                    //     instance method called via class name).
                    //   * The candidate kinds don't include the
                    //     member's actual kind (e.g., a getter-only
                    //     accessor `x.foo` Write-accessed has no
                    //     Setter to bind to).
                    //   * Cross-file dispatch where the class node
                    //     isn't reachable from this file's value or
                    //     type namespace (no matching import).
                    // Silently drop, per `Limitation::MemberDispatch`.
                    continue;
                }
            };

            // Resolve the call's owner to a NodeId (Module-init for
            // top-level MemberCalls). Reuse the existing helper.
            let owner_id = owner_node(
                builder,
                *owner,
                file_id,
                file_idx,
                &per_file_decl_node_ids,
                &mut module_init_l3[file_idx],
            );

            // G1.9 S1 — carry the parser's argument-interior anchors onto
            // the promoted edge for `AccessKind::Call` (mirrors the
            // direct-call threading above, resolver.rs ~:2759-2769); `Read`/
            // `Write` promotions never scanned an argument list (the parser
            // leaves `argument_anchors` empty for them), so they keep the
            // plain `add_edge` path.
            match access {
                crate::ts::events::AccessKind::Call => {
                    builder.add_calls_edge_with_argument_anchors(
                        owner_id,
                        method_node,
                        Some(*site_span),
                        argument_anchors.clone(),
                    );
                }
                crate::ts::events::AccessKind::Read | crate::ts::events::AccessKind::Write => {
                    builder.add_edge(owner_id, EdgeKind::Calls, method_node, Some(*site_span));
                }
            }
        }
    }

    /// Returns the `name_span` of a `DeclEvent`. Mirror of `decl_name`.
    fn decl_name_span(d: &DeclEvent) -> crate::spans::Span {
        match d {
            DeclEvent::Function { name_span, .. }
            | DeclEvent::Class { name_span, .. }
            | DeclEvent::Interface { name_span, .. }
            | DeclEvent::Namespace { name_span, .. }
            | DeclEvent::TypeAlias { name_span, .. }
            | DeclEvent::Enum { name_span, .. }
            | DeclEvent::Variable { name_span, .. }
            | DeclEvent::Method { name_span, .. }
            | DeclEvent::ServiceMember { name_span, .. } => *name_span,
        }
    }

    fn lookup_binding_in_scope_chain<'a>(
        name: &str,
        file_idx: usize,
        scope: ScopeId,
        bindings_by_scope: &[ScopeBindings<'a>],
        scopes: &[crate::ts::events::ScopeInfo],
    ) -> Option<&'a BindingEvent> {
        let mut current = Some(scope);
        while let Some(scope_id) = current {
            if let Some(binding) = bindings_by_scope[file_idx]
                .get(&scope_id)
                .and_then(|by_name| by_name.get(name))
                .copied()
            {
                return Some(binding);
            }
            current = scopes.get(scope_id as usize).and_then(|s| s.parent);
        }
        None
    }

    fn lookup_scoped_local_value(
        name: &str,
        file_idx: usize,
        scope: ScopeId,
        scoped_local_value_decls: &[HashMap<ScopeId, HashMap<String, NodeId>>],
        scopes: &[crate::ts::events::ScopeInfo],
    ) -> Option<NodeId> {
        let mut current = Some(scope);
        while let Some(scope_id) = current {
            if let Some(node) = scoped_local_value_decls[file_idx]
                .get(&scope_id)
                .and_then(|by_name| by_name.get(name))
                .copied()
            {
                return Some(node);
            }
            current = scopes.get(scope_id as usize).and_then(|s| s.parent);
        }
        None
    }

    fn lookup_value_in_scope(
        name: &str,
        file_idx: usize,
        scope: ScopeId,
        scoped_local_value_decls: &[HashMap<ScopeId, HashMap<String, NodeId>>],
        scopes: &[crate::ts::events::ScopeInfo],
        local_value_refs: &[BTreeMap<String, NodeId>],
        per_file_value_decls: &[BTreeMap<String, NodeId>],
    ) -> Option<NodeId> {
        lookup_scoped_local_value(name, file_idx, scope, scoped_local_value_decls, scopes)
            .or_else(|| lookup_value(name, file_idx, local_value_refs, per_file_value_decls))
    }

    fn lookup_value(
        name: &str,
        file_idx: usize,
        local_value_refs: &[BTreeMap<String, NodeId>],
        per_file_value_decls: &[BTreeMap<String, NodeId>],
    ) -> Option<NodeId> {
        // Value-position lookup. Interface and TypeAlias decls are NOT in
        // per_file_value_decls — they erase at runtime — so a `interface I {}`
        // can no longer accidentally satisfy `I()`.
        local_value_refs[file_idx]
            .get(name)
            .copied()
            .or_else(|| per_file_value_decls[file_idx].get(name).copied())
    }

    fn lookup_type(
        name: &str,
        file_idx: usize,
        local_type_refs: &[BTreeMap<String, NodeId>],
        per_file_type_decls: &[BTreeMap<String, NodeId>],
    ) -> Option<NodeId> {
        // Type-position lookup is STRICTLY type-space: type-imports → type
        // decls. We deliberately do NOT fall back to value-space; doing so
        // would let `let x: Foo` resolve to a value-only `function Foo()`,
        // silently masking a real type error. Class and Enum are
        // dual-namespace (Pass 2 inserts them into per_file_type_decls), so
        // their type-side use cases still resolve.
        //
        // `typeof X` is routed through RefEvent::TypeQueryRef instead of this
        // plain type lookup, so ordinary type positions stay strict.
        local_type_refs[file_idx]
            .get(name)
            .copied()
            .or_else(|| per_file_type_decls[file_idx].get(name).copied())
    }

    Ok(ExtractResult {
        file_ids,
        diagnostics,
    })
}
