use crate::archive::{encode_archive, OwnedSourceArchive};
use crate::csr::{
    encode_header_and_section_table, section_kind, OwnedGraph, SectionEntry,
    CALL_ARGUMENT_ANCHOR_ENTRY_SIZE, HEADER_SIZE, SECTION_ENTRY_SIZE,
};
use crate::hash::sha256;
use crate::ids::{NodeId, StringId};
use crate::interner::StringInterner;
use crate::schema::{CallArgumentAnchor, EdgeKind, NodeKind, TypeRefPosition};
use crate::spans::{NodeSpans, SourceEncodingError, Span};

/// Grouped optional per-edge-kind metadata for `add_edge_inner`. Keeps the
/// shared edge-insertion path under clippy's `too_many_arguments` threshold as
/// side channels accumulate (type-only bit, Exports/Imports label, TypeRef
/// position) — each new side channel is a field here, not a new positional
/// parameter. Every field defaults to "plain edge, no metadata".
#[derive(Default)]
struct EdgeExtras {
    type_only: bool,
    label: Option<StringId>,
    position: Option<TypeRefPosition>,
    /// G1.6 fork (a): call-argument interior anchors, parser-side (parallel
    /// to `edges`, only ever non-empty for `Calls` — enforced by
    /// `add_edge_inner`).
    argument_anchors: Vec<CallArgumentAnchor>,
}

/// Per-File-node source content registered via `add_file`. Held by the builder
/// until `freeze` consumes it into the IR's SOURCE_METADATA section and the
/// sibling source archive (the archive build lands in Task 19/20).
pub(crate) struct FileContent {
    pub(crate) file_node_id: NodeId,
    pub(crate) content_length: u64,
    pub(crate) sha256: [u8; 32],
    pub(crate) content: Option<Vec<u8>>,
}

pub struct GraphBuilder {
    pub(crate) intern: StringInterner,
    pub(crate) node_kinds: Vec<NodeKind>,
    pub(crate) node_expected_kinds: Vec<u16>,
    pub(crate) node_names: Vec<StringId>,
    pub(crate) edges: Vec<(NodeId, EdgeKind, NodeId)>,

    // NEW for spans milestone (Task 6). Parallel to node_kinds — every node
    // adds exactly one entry here, defaulting to None when the constructor
    // doesn't know the span yet (add_node + add_unresolved). Task 7 will
    // change add_node to accept explicit NodeSpans.
    pub(crate) node_name_spans: Vec<Option<Span>>,
    pub(crate) node_decl_spans: Vec<Option<Span>>,
    pub(crate) node_body_spans: Vec<Option<Span>>,

    // NEW: per-edge spans, parallel to `edges`. Always None for now; Task 8
    // will change add_edge to accept Option<Span>.
    pub(crate) edge_spans: Vec<Option<Span>>,

    // NEW: per-edge syntactic type-only marker, parallel to `edges`. Only set
    // for Imports/Exports (the kinds with a syntactic `type` modifier);
    // enforced by add_edge_inner's guard. Persisted as EDGE_TYPE_ONLY_<kind>.
    pub(crate) edge_type_only: Vec<bool>,

    // NEW (G1.5 Fix 2 §3.2/2b): per-edge parse-time TypeRefPosition
    // discriminant, parallel to `edges`. Only ever `Some` for `TypeRef` edges
    // — enforced by add_edge_inner's guard, mirroring edge_type_only's
    // Imports/Exports restriction. Persisted as
    // `EDGE_TYPE_REF_POSITION_<kind>`. No parser/renderer reads this yet;
    // this task adds carriage only.
    pub(crate) type_ref_positions: Vec<Option<TypeRefPosition>>,

    // NEW (G1.6 fork (a)): per-edge call-argument interior anchors, parallel
    // to `edges`. Only ever non-empty for `Calls` edges — enforced by
    // add_edge_inner's guard, mirroring type_ref_positions'/edge_type_only's
    // per-kind restrictions. Persisted as `CALL_ARGUMENT_ANCHOR_OFFSETS_<kind>`
    // + `CALL_ARGUMENT_ANCHOR_ENTRIES_<kind>`. No walk reads this yet (W1,
    // a later PR); this task adds carriage only.
    pub(crate) call_argument_anchors: Vec<Vec<CallArgumentAnchor>>,

    // Per-edge public-facing label, parallel to `edges`. Preserves the
    // parser's `ExportEntry::*.exported` label on Exports edges. Persisted
    // into the byte-stable IR via the `EDGE_LABEL_<kind>` section (kind
    // 0x0704 for Exports) — labels survive `OwnedGraph::as_bytes` ->
    // `view_from_bytes` round-trip and are queried via
    // `CodeGraph::edge_label_str`. Default None for edges that don't carry
    // a label (every non-Exports edge in v1).
    pub(crate) edge_labels: Vec<Option<StringId>>,

    // NEW: source bytes registered via add_file, keyed by File NodeId.
    pub(crate) file_contents: Vec<FileContent>,
    store_file_content: bool,

    // NEW (real-package readiness): External-node origin tags, pushed in
    // node-creation order (ascending node_id). Persisted as the EXTERNAL_ORIGINS
    // section. `external_dedup` ensures one External node per
    // (name, origin, package_origin).
    pub(crate) external_origins: Vec<(u32, u8)>,
    external_dedup: std::collections::HashMap<(String, u8, Option<String>), NodeId>,

    // (Round 8 - provenance gap) External-node package origin tags. Sparse
    // mapping from node_id -> StringId of the package specifier the node
    // was created from. Populated by add_external when `package_origin`
    // is Some(_). Persisted as the EXTERNAL_PACKAGE_ORIGINS section so the
    // information survives `as_bytes` -> `view_from_bytes` round-trip,
    // letting the renderer surface "from `<pkg>`" honestly for direct
    // NamedFrom external re-exports.
    pub(crate) external_package_origins: Vec<(u32, StringId)>,
}

impl Default for GraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphBuilder {
    pub fn new() -> Self {
        Self {
            intern: StringInterner::new(),
            node_kinds: Vec::new(),
            node_expected_kinds: Vec::new(),
            node_names: Vec::new(),
            edges: Vec::new(),
            node_name_spans: Vec::new(),
            node_decl_spans: Vec::new(),
            node_body_spans: Vec::new(),
            edge_spans: Vec::new(),
            edge_type_only: Vec::new(),
            type_ref_positions: Vec::new(),
            call_argument_anchors: Vec::new(),
            edge_labels: Vec::new(),
            file_contents: Vec::new(),
            store_file_content: true,
            external_origins: Vec::new(),
            external_dedup: std::collections::HashMap::new(),
            external_package_origins: Vec::new(),
        }
    }

    /// Create a builder for graph-only consumers. File nodes still record
    /// SOURCE_METADATA (content length + hash), but source bytes are not
    /// retained for sibling archive construction.
    pub fn new_graph_only() -> Self {
        Self {
            store_file_content: false,
            ..Self::new()
        }
    }

    /// Add (or reuse) an `External` node for `name` with `origin` and an
    /// optional `package_origin` (the package specifier the binding came
    /// from). Deduped by (name, origin, package_origin) so repeated
    /// references share one node, but distinct package origins yield
    /// distinct NodeIds — without this round-8 fix, `foo` from `pkg-a`
    /// and `foo` from `pkg-b` collided on the same node and the resolver
    /// could not tell them apart.
    ///
    /// `package_origin = Some(pkg)` for ImportedPackage Externals
    /// (NamedFrom, import bindings, bare-pkg stars). `None` for ambient
    /// globals and Unknown-origin nodes that have no package context.
    pub fn add_external(
        &mut self,
        name: &str,
        origin: crate::schema::ExternalOrigin,
        package_origin: Option<&str>,
    ) -> NodeId {
        let key = (
            name.to_string(),
            origin as u8,
            package_origin.map(str::to_string),
        );
        if let Some(&id) = self.external_dedup.get(&key) {
            return id;
        }
        let id = NodeId(
            u32::try_from(self.node_kinds.len())
                .expect("Repotoire v0 format limit: node count must fit in u32"),
        );
        self.node_kinds.push(NodeKind::External);
        self.node_expected_kinds.push(0);
        self.node_names.push(self.intern.intern(name));
        self.node_name_spans.push(None);
        self.node_decl_spans.push(None);
        self.node_body_spans.push(None);
        self.external_origins.push((id.0, origin as u8));
        if let Some(pkg) = package_origin {
            let sid = self.intern.intern(pkg);
            self.external_package_origins.push((id.0, sid));
        }
        self.external_dedup.insert(key, id);
        id
    }

    /// General node insertion with spans.
    ///
    /// Panics if `kind` is `NodeKind::File` (use `add_file`) or
    /// `NodeKind::Unresolved` (use `add_unresolved`). `NodeSpans::ABSENT` is
    /// the legal value for span-less node instances (e.g., implicit-per-file
    /// Module).
    pub fn add_node(&mut self, kind: NodeKind, name: &str, spans: NodeSpans) -> NodeId {
        assert!(
            kind != NodeKind::Unresolved,
            "use add_unresolved() for Unresolved nodes"
        );
        assert!(kind != NodeKind::File, "use add_file() for File nodes");
        assert!(
            kind != NodeKind::External,
            "use add_external() for External nodes"
        );
        let id = NodeId(
            u32::try_from(self.node_kinds.len())
                .expect("Repotoire v0 format limit: node count must fit in u32"),
        );
        self.node_kinds.push(kind);
        self.node_expected_kinds.push(0);
        self.node_names.push(self.intern.intern(name));
        self.node_name_spans.push(spans.name);
        self.node_decl_spans.push(spans.decl);
        self.node_body_spans.push(spans.body);
        id
    }

    /// `expected = None` encodes "Unresolved with unknown expected kind"
    /// (`expected_kind` = 0 in the row); `Some(k)` encodes the extractor's guess.
    pub fn add_unresolved(&mut self, name: &str, expected: Option<NodeKind>) -> NodeId {
        let id = NodeId(
            u32::try_from(self.node_kinds.len())
                .expect("Repotoire v0 format limit: node count must fit in u32"),
        );
        self.node_kinds.push(NodeKind::Unresolved);
        self.node_expected_kinds
            .push(expected.map_or(0, |k| k as u16));
        self.node_names.push(self.intern.intern(name));
        // Unresolved nodes never have spans (they're phantoms).
        self.node_name_spans.push(None);
        self.node_decl_spans.push(None);
        self.node_body_spans.push(None);
        id
    }

    /// Registers a File node with its source content.
    ///
    /// Validates UTF-8 eagerly — `add_file` is the single choke point per
    /// spec §5/§6.1. Computes SHA-256 of `content` immediately so the hash is
    /// available for SOURCE_METADATA emission and the sibling archive at
    /// freeze time.
    ///
    /// Returns `SourceEncodingError::NotUtf8` if `content` is not valid UTF-8;
    /// no node is created in that case.
    pub fn add_file(&mut self, path: &str, content: &[u8]) -> Result<NodeId, SourceEncodingError> {
        if let Err(e) = std::str::from_utf8(content) {
            return Err(SourceEncodingError::NotUtf8 {
                path: path.to_string(),
                invalid_byte_offset: e.valid_up_to(),
            });
        }

        let id = NodeId(
            u32::try_from(self.node_kinds.len())
                .expect("Repotoire v0 format limit: node count must fit in u32"),
        );
        self.node_kinds.push(NodeKind::File);
        self.node_expected_kinds.push(0);
        self.node_names.push(self.intern.intern(path));
        // File nodes have no spans (filename isn't in source, body is implicit
        // (0, content_length) recoverable from SOURCE_METADATA).
        self.node_name_spans.push(None);
        self.node_decl_spans.push(None);
        self.node_body_spans.push(None);

        self.file_contents.push(FileContent {
            file_node_id: id,
            content_length: content.len() as u64,
            sha256: sha256(content),
            content: self.store_file_content.then(|| content.to_vec()),
        });

        Ok(id)
    }

    pub(crate) fn add_file_metadata(
        &mut self,
        path: &str,
        content_length: u64,
        sha256: [u8; 32],
    ) -> NodeId {
        assert!(
            !self.store_file_content,
            "metadata-only files require a graph-only builder"
        );
        let id = NodeId(
            u32::try_from(self.node_kinds.len())
                .expect("Repotoire v0 format limit: node count must fit in u32"),
        );
        self.node_kinds.push(NodeKind::File);
        self.node_expected_kinds.push(0);
        self.node_names.push(self.intern.intern(path));
        self.node_name_spans.push(None);
        self.node_decl_spans.push(None);
        self.node_body_spans.push(None);
        self.file_contents.push(FileContent {
            file_node_id: id,
            content_length,
            sha256,
            content: None,
        });
        id
    }

    /// Edge insertion with optional span. `Some(_)` means "the source location
    /// of the relationship is at this span"; `None` means no span is available
    /// (synthetic / structural edges). Span coordinates are in the source
    /// endpoint's file (`file_of(from)`) per spec §3.7. The edge is recorded as
    /// NOT type-only — use `add_type_only_edge` for type-only edges.
    pub fn add_edge(&mut self, from: NodeId, kind: EdgeKind, to: NodeId, span: Option<Span>) {
        self.add_edge_inner(from, kind, to, span, EdgeExtras::default());
    }

    /// Insert a syntactically type-only edge. Reads "add a type-only edge".
    /// Only valid for `Imports`/`Exports` — panics otherwise. Callers pass
    /// `true` for a statement-level `import type { … }` (Imports) or a type-only
    /// export specifier `export type { X }` / `export { type X }` (Exports). A
    /// per-binding `import { type X, y }` is NOT a type-only edge — its module
    /// dependency survives at runtime — so use `add_edge` for it.
    pub fn add_type_only_edge(
        &mut self,
        from: NodeId,
        kind: EdgeKind,
        to: NodeId,
        span: Option<Span>,
    ) {
        self.add_edge_inner(
            from,
            kind,
            to,
            span,
            EdgeExtras {
                type_only: true,
                ..Default::default()
            },
        );
    }

    /// Insert an `Exports` edge that carries the parser's public-facing label.
    ///
    /// The label is the `exported` field from the parser's `ExportEntry`
    /// variant — `"default"` for default exports, the alias for
    /// `export { local as alias }`, the local name for `export { local }`,
    /// the decl's own name for `export function foo`. The renderer uses this
    /// to display the truthful public API surface; without it, aliased and
    /// default exports show their *local* declaration name, which is the
    /// wrong public API.
    ///
    /// The label IS persisted in the byte-stable IR via the
    /// `EDGE_LABEL_Exports` section (section kind `0x0704` =
    /// `EDGE_LABEL_BASE | EdgeKind::Exports`). Labels survive
    /// `OwnedGraph::as_bytes()` → `CodeGraph::view_from_bytes` round-trip
    /// and are queried via `CodeGraph::edge_label_str(EdgeKind::Exports,
    /// slot)`. No side-channel is needed by the renderer.
    pub fn add_export_edge_with_label(
        &mut self,
        from: NodeId,
        to: NodeId,
        span: Option<Span>,
        type_only: bool,
        public_label: &str,
    ) {
        let sid = self.intern.intern(public_label);
        self.add_edge_inner(
            from,
            EdgeKind::Exports,
            to,
            span,
            EdgeExtras {
                type_only,
                label: Some(sid),
                ..Default::default()
            },
        );
    }

    /// FU2 (v0.1.0-beta.1): attach a binding-set label to an Imports edge.
    ///
    /// The label is a single string summarizing every binding the source
    /// `import` statement pulls from this module — e.g. `{ Foo, Bar }`,
    /// `default as D`, `* as ns`, `{ type Foo, Bar }`, or a combined
    /// `default as D, { Foo, Bar }` for mixed-form imports. The renderer
    /// emits this as `<label> from <specifier>` so the model can read
    /// which names cross the boundary without opening the source file.
    ///
    /// Empty `bindings_label` is allowed (used for `import './polyfill'`
    /// side-effect statements) and stored as the empty string; the
    /// renderer treats absent / empty as "no binding info, render the
    /// specifier alone".
    pub fn add_import_edge_with_bindings(
        &mut self,
        from: NodeId,
        to: NodeId,
        span: Option<Span>,
        type_only: bool,
        bindings_label: &str,
    ) {
        let sid = self.intern.intern(bindings_label);
        self.add_edge_inner(
            from,
            EdgeKind::Imports,
            to,
            span,
            EdgeExtras {
                type_only,
                label: Some(sid),
                ..Default::default()
            },
        );
    }

    /// Insert a `TypeRef` edge carrying a parse-time position discriminant
    /// (G1.5 Fix 2 §3.2/2b — see `TypeRefPosition`). Position is recorded
    /// inline at edge-creation time, the same shape as
    /// `add_export_edge_with_label`'s label parameter, rather than a
    /// "set for the next edge" builder mode — there is no existing precedent
    /// in this builder for stateful next-edge setters, and an inline
    /// parameter can't be forgotten or misordered relative to the edge it
    /// describes.
    ///
    /// This task adds carriage only: no parser or renderer reads the
    /// position yet.
    pub fn add_type_ref_edge(
        &mut self,
        from: NodeId,
        to: NodeId,
        span: Option<Span>,
        position: TypeRefPosition,
    ) {
        self.add_edge_inner(
            from,
            EdgeKind::TypeRef,
            to,
            span,
            EdgeExtras {
                position: Some(position),
                ..Default::default()
            },
        );
    }

    /// Insert a `Calls` edge carrying G1.6 fork (a) argument-interior anchors
    /// (callback-literal head spans and object-literal key paths found while
    /// generically scanning this call's argument list — see
    /// `CallArgumentAnchor`'s doc comment). `anchors` may be empty (the
    /// overwhelmingly common case); an empty `Vec` and "no anchors recorded"
    /// are the same thing on the read side (`SpanView::
    /// call_argument_anchors_from_in` returns an empty `Vec` either way — see
    /// its doc comment for why that's never ambiguous with "no info").
    ///
    /// Same inline-parameter shape as `add_type_ref_edge`/
    /// `add_export_edge_with_label` — anchors are recorded at edge-creation
    /// time, not via a stateful "set for the next edge" builder mode.
    pub fn add_calls_edge_with_argument_anchors(
        &mut self,
        from: NodeId,
        to: NodeId,
        span: Option<Span>,
        anchors: Vec<CallArgumentAnchor>,
    ) {
        self.add_edge_inner(
            from,
            EdgeKind::Calls,
            to,
            span,
            EdgeExtras {
                argument_anchors: anchors,
                ..Default::default()
            },
        );
    }

    /// Shared edge-insertion path. Bounds-checks the endpoints, enforces that
    /// `type_only` is only set for Imports/Exports, that `position` is only
    /// set for `TypeRef`, that `argument_anchors` is only non-empty for
    /// `Calls`, and pushes to the parallel edge vecs in lockstep.
    fn add_edge_inner(
        &mut self,
        from: NodeId,
        kind: EdgeKind,
        to: NodeId,
        span: Option<Span>,
        extras: EdgeExtras,
    ) {
        let EdgeExtras {
            type_only,
            label,
            position,
            argument_anchors,
        } = extras;
        assert!(
            from.as_usize() < self.node_kinds.len(),
            "from NodeId out of range"
        );
        assert!(
            to.as_usize() < self.node_kinds.len(),
            "to NodeId out of range"
        );
        assert!(
            !type_only || matches!(kind, EdgeKind::Imports | EdgeKind::Exports),
            "type-only marker is only valid for Imports/Exports edges, got {kind:?}"
        );
        assert!(
            label.is_none() || matches!(kind, EdgeKind::Exports | EdgeKind::Imports),
            "edge label is only valid for Exports/Imports edges, got {kind:?}"
        );
        assert!(
            position.is_none() || matches!(kind, EdgeKind::TypeRef),
            "type-ref position marker is only valid for TypeRef edges, got {kind:?}"
        );
        assert!(
            argument_anchors.is_empty() || matches!(kind, EdgeKind::Calls),
            "call-argument anchors are only valid for Calls edges, got {kind:?}"
        );
        self.edges.push((from, kind, to));
        self.edge_spans.push(span);
        self.edge_type_only.push(type_only);
        self.edge_labels.push(label);
        self.type_ref_positions.push(position);
        self.call_argument_anchors.push(argument_anchors);
    }

    pub fn node_count(&self) -> u32 {
        u32::try_from(self.node_kinds.len())
            .expect("Repotoire v0 format limit: node count must fit in u32")
    }
}

impl GraphBuilder {
    /// Build the IR section of the output. Borrows `self` mutably (sorts
    /// `file_contents` in place during SOURCE_METADATA emission per Task 11)
    /// but does NOT consume — the same builder produces the source archive
    /// next via `build_source_archive` without redoing this work.
    fn freeze_to_ir(&mut self) -> OwnedGraph {
        let n_usize = self.node_kinds.len();
        // Fail loudly before writing bytes if the graph exceeds the u32-indexed format.
        u32::try_from(n_usize).expect("Repotoire v0 format limit: node count must fit in u32");
        debug_assert_eq!(
            self.edges.len(),
            self.edge_spans.len(),
            "edge parallel vecs misaligned: edge_spans"
        );
        debug_assert_eq!(
            self.edges.len(),
            self.edge_type_only.len(),
            "edge parallel vecs misaligned: edge_type_only"
        );
        debug_assert_eq!(
            self.edges.len(),
            self.edge_labels.len(),
            "edge parallel vecs misaligned: edge_labels"
        );
        debug_assert_eq!(
            self.edges.len(),
            self.type_ref_positions.len(),
            "edge parallel vecs misaligned: type_ref_positions"
        );
        debug_assert_eq!(
            self.edges.len(),
            self.call_argument_anchors.len(),
            "edge parallel vecs misaligned: call_argument_anchors"
        );

        let nodes_section = encode_nodes_section(
            &self.node_kinds,
            &self.node_expected_kinds,
            &self.node_names,
        );

        // Pass 1: scan edges once to find used edge kinds and count per-(kind, node) degrees.
        // Only allocate degree arrays for kinds that actually appear — empties stay None.
        let mut edge_kinds_seen = [false; EdgeKind::COUNT];
        let mut out_degree: [Option<Vec<u32>>; EdgeKind::COUNT] = Default::default();
        let mut in_degree: [Option<Vec<u32>>; EdgeKind::COUNT] = Default::default();
        for (from, kind, to) in &self.edges {
            let k = (*kind as usize) - 1;
            if !edge_kinds_seen[k] {
                edge_kinds_seen[k] = true;
                out_degree[k] = Some(vec![0u32; n_usize]);
                in_degree[k] = Some(vec![0u32; n_usize]);
            }
            let out_d = out_degree[k].as_mut().unwrap();
            out_d[from.as_usize()] = out_d[from.as_usize()]
                .checked_add(1)
                .expect("Repotoire v0 format limit: edge count must fit in u32");
            let in_d = in_degree[k].as_mut().unwrap();
            in_d[to.as_usize()] = in_d[to.as_usize()]
                .checked_add(1)
                .expect("Repotoire v0 format limit: edge count must fit in u32");
        }

        // Pass 1b (Task 10): scan edge_spans to find which kinds have at least one
        // Some(span). Only those kinds get a permuted spans vec allocated below.
        let mut any_span_for_kind = [false; EdgeKind::COUNT];
        for (idx, (_from, kind, _to)) in self.edges.iter().enumerate() {
            if self.edge_spans[idx].is_some() {
                any_span_for_kind[(*kind as usize) - 1] = true;
            }
        }

        // Pass 1c: scan edge_type_only to find which kinds have ≥1 type-only
        // edge. Only those kinds get a permuted bitset allocated + emitted.
        let mut any_type_only_for_kind = [false; EdgeKind::COUNT];
        for (idx, (_from, kind, _to)) in self.edges.iter().enumerate() {
            if self.edge_type_only[idx] {
                any_type_only_for_kind[(*kind as usize) - 1] = true;
            }
        }

        // Pass 1d (P1 #1 follow-up): scan edge_labels for the Exports kind.
        // Only Exports carries labels in v1 (asserted in add_edge_inner), but
        // detect per-kind generically in case that changes.
        let mut any_label_for_kind = [false; EdgeKind::COUNT];
        for (idx, (_from, kind, _to)) in self.edges.iter().enumerate() {
            if self.edge_labels[idx].is_some() {
                any_label_for_kind[(*kind as usize) - 1] = true;
            }
        }

        // Pass 1e (G1.5 Fix 2 §3.2/2b): scan type_ref_positions to find which
        // kinds have ≥1 Some(position). Only TypeRef ever sets one (enforced
        // in add_edge_inner), but detect per-kind generically to mirror the
        // label/type-only scans above.
        let mut any_position_for_kind = [false; EdgeKind::COUNT];
        for (idx, (_from, kind, _to)) in self.edges.iter().enumerate() {
            if self.type_ref_positions[idx].is_some() {
                any_position_for_kind[(*kind as usize) - 1] = true;
            }
        }

        // Pass 1f (G1.6 fork (a)): scan call_argument_anchors to find which
        // kinds have ≥1 non-empty anchor list. Only Calls ever sets one
        // (enforced in add_edge_inner), but detect per-kind generically to
        // mirror the position/label/type-only scans above.
        let mut any_argument_anchors_for_kind = [false; EdgeKind::COUNT];
        for (idx, (_from, kind, _to)) in self.edges.iter().enumerate() {
            if !self.call_argument_anchors[idx].is_empty() {
                any_argument_anchors_for_kind[(*kind as usize) - 1] = true;
            }
        }

        // Pass 2 prep: prefix-sum the degrees into offsets bytes + a parallel
        // cursor array (used in pass 3 to track the next write position per node).
        // Allocate exactly the right size for the targets buffer up front.
        let mut out_offsets: [Option<Vec<u8>>; EdgeKind::COUNT] = Default::default();
        let mut in_offsets: [Option<Vec<u8>>; EdgeKind::COUNT] = Default::default();
        let mut out_cursors: [Option<Vec<u32>>; EdgeKind::COUNT] = Default::default();
        let mut in_cursors: [Option<Vec<u32>>; EdgeKind::COUNT] = Default::default();
        let mut out_targets: [Option<Vec<u8>>; EdgeKind::COUNT] = Default::default();
        let mut in_targets: [Option<Vec<u8>>; EdgeKind::COUNT] = Default::default();
        // Permuted edge spans, indexed by OUT slot. Only allocated for kinds where
        // any_span_for_kind[k] is true; kinds with no spans stay None.
        let mut permuted_edge_spans: [Option<Vec<Option<Span>>>; EdgeKind::COUNT] =
            Default::default();
        // Permuted type-only bitset, indexed by OUT slot. Only allocated for kinds
        // where any_type_only_for_kind[k] is true; all-runtime kinds stay None.
        let mut permuted_edge_type_only: [Option<Vec<bool>>; EdgeKind::COUNT] = Default::default();
        // Permuted edge labels (StringId), indexed by OUT slot. Only allocated
        // for kinds where any_label_for_kind[k] is true. Serialized as
        // `EDGE_LABEL_<kind>` (4 bytes per slot + presence bitmap) below;
        // labels round-trip through CSR bytes via `CodeGraph::edge_label`.
        let mut permuted_edge_labels: [Option<Vec<Option<StringId>>>; EdgeKind::COUNT] =
            Default::default();
        // Permuted TypeRef position discriminants, indexed by OUT slot. Only
        // allocated for kinds where any_position_for_kind[k] is true (TypeRef
        // only, in practice). Serialized as `EDGE_TYPE_REF_POSITION_<kind>`
        // below; positions round-trip through CSR bytes via
        // `SpanView::type_ref_position_from_in`.
        let mut permuted_type_ref_positions: [Option<Vec<Option<TypeRefPosition>>>;
            EdgeKind::COUNT] = Default::default();
        // Permuted call-argument anchors (G1.6 fork (a)), indexed by OUT slot.
        // Only allocated for kinds where any_argument_anchors_for_kind[k] is
        // true (Calls only, in practice). Encoded into the OFFSETS+ENTRIES
        // section pair AFTER Pass 3 (below) — unlike the fixed-size sidecars
        // above, encoding needs `&mut self.intern` to resolve name/path
        // StringIds, so it can't happen inside this same allocation loop.
        let mut permuted_call_argument_anchors: [Option<Vec<Vec<CallArgumentAnchor>>>;
            EdgeKind::COUNT] = Default::default();
        for k_idx in 0..EdgeKind::COUNT {
            if !edge_kinds_seen[k_idx] {
                continue;
            }
            let (off, cur, tgt) = prefix_sum_into_csr(out_degree[k_idx].as_ref().unwrap());
            let m_kind = tgt.len() / 4;
            out_offsets[k_idx] = Some(off);
            out_cursors[k_idx] = Some(cur);
            out_targets[k_idx] = Some(tgt);
            let (off, cur, tgt) = prefix_sum_into_csr(in_degree[k_idx].as_ref().unwrap());
            in_offsets[k_idx] = Some(off);
            in_cursors[k_idx] = Some(cur);
            in_targets[k_idx] = Some(tgt);
            if any_span_for_kind[k_idx] {
                permuted_edge_spans[k_idx] = Some(vec![None; m_kind]);
            }
            if any_type_only_for_kind[k_idx] {
                permuted_edge_type_only[k_idx] = Some(vec![false; m_kind]);
            }
            if any_label_for_kind[k_idx] {
                permuted_edge_labels[k_idx] = Some(vec![None; m_kind]);
            }
            if any_position_for_kind[k_idx] {
                permuted_type_ref_positions[k_idx] = Some(vec![None; m_kind]);
            }
            if any_argument_anchors_for_kind[k_idx] {
                permuted_call_argument_anchors[k_idx] = Some(vec![Vec::new(); m_kind]);
            }
        }

        // Pass 3: walk edges in insertion order, placing each (from -> to) at the
        // current cursor slot for that (kind, source) and (kind, target). For each
        // OUT slot we write, also write the corresponding edge_span into the
        // permuted vec at the same slot — keeping EDGE_SPANS_<kind> addressable
        // by the same OUT slot index a consumer uses for OUT_TARGETS_<kind>.
        for (idx, (from, kind, to)) in self.edges.iter().enumerate() {
            let k_idx = (*kind as usize) - 1;
            let cursors = out_cursors[k_idx].as_mut().unwrap();
            let out_slot = cursors[from.as_usize()] as usize;
            cursors[from.as_usize()] += 1;
            let buf = out_targets[k_idx].as_mut().unwrap();
            buf[out_slot * 4..out_slot * 4 + 4].copy_from_slice(&to.to_le_bytes());
            if let Some(spans) = permuted_edge_spans[k_idx].as_mut() {
                spans[out_slot] = self.edge_spans[idx];
            }
            if let Some(tos) = permuted_edge_type_only[k_idx].as_mut() {
                tos[out_slot] = self.edge_type_only[idx];
            }
            if let Some(labels) = permuted_edge_labels[k_idx].as_mut() {
                labels[out_slot] = self.edge_labels[idx];
            }
            if let Some(positions) = permuted_type_ref_positions[k_idx].as_mut() {
                positions[out_slot] = self.type_ref_positions[idx];
            }
            if let Some(anchors) = permuted_call_argument_anchors[k_idx].as_mut() {
                anchors[out_slot] = std::mem::take(&mut self.call_argument_anchors[idx]);
            }

            let cursors = in_cursors[k_idx].as_mut().unwrap();
            let slot = cursors[to.as_usize()] as usize;
            cursors[to.as_usize()] += 1;
            let buf = in_targets[k_idx].as_mut().unwrap();
            buf[slot * 4..slot * 4 + 4].copy_from_slice(&from.to_le_bytes());
        }

        // G1.6 fork (a): encode the OFFSETS+ENTRIES section pair for each
        // kind with recorded anchors, BEFORE the interner is taken below —
        // ObjectKey entries intern their name/path strings here (the only
        // sidecar section that needs the interner at encode time; every
        // fixed-size sidecar above needed only data movement).
        let mut call_argument_anchor_offsets: [Option<Vec<u8>>; EdgeKind::COUNT] =
            Default::default();
        let mut call_argument_anchor_entries: [Option<Vec<u8>>; EdgeKind::COUNT] =
            Default::default();
        for k_idx in 0..EdgeKind::COUNT {
            if let Some(permuted) = &permuted_call_argument_anchors[k_idx] {
                let (offsets, entries) =
                    encode_call_argument_anchor_sections(permuted, &mut self.intern);
                call_argument_anchor_offsets[k_idx] = Some(offsets);
                call_argument_anchor_entries[k_idx] = Some(entries);
            }
        }

        // mem::take leaves self.intern in default-empty state so freeze_to_ir
        // can borrow &mut self without consuming the whole builder — lets
        // freeze() call build_source_archive(&self) right after.
        let (arena, index_bytes) = std::mem::take(&mut self.intern).into_byte_sections();

        let mut payloads: Vec<(u16, Vec<u8>)> = Vec::new();
        payloads.push((section_kind::STRINGS_ARENA, arena));
        payloads.push((section_kind::STRING_INDEX, index_bytes));
        payloads.push((section_kind::NODES, nodes_section));

        // Combined per-node spans section (Task 9, refactored). Single section
        // carrying all three spans (name + decl + body) per node in AoS layout.
        // Emitted iff at least one node has ANY span kind set.
        let any_node_span = self.node_name_spans.iter().any(|s| s.is_some())
            || self.node_decl_spans.iter().any(|s| s.is_some())
            || self.node_body_spans.iter().any(|s| s.is_some());
        if any_node_span {
            payloads.push((
                section_kind::NODE_SPANS,
                encode_node_spans(
                    &self.node_name_spans,
                    &self.node_decl_spans,
                    &self.node_body_spans,
                ),
            ));
        }

        // SOURCE_METADATA (Task 11): one 48-byte entry per File node, sorted by
        // file_node_id. Only emitted when at least one add_file was called.
        // file_contents is sorted in place by encode_source_metadata.
        if !self.file_contents.is_empty() {
            payloads.push((
                section_kind::SOURCE_METADATA,
                encode_source_metadata(&mut self.file_contents),
            ));
        }

        // EXTERNAL_ORIGINS (real-package readiness): sparse (node_id, origin)
        // list for External nodes, in ascending node_id order (creation order).
        // Only emitted when at least one External node exists.
        if !self.external_origins.is_empty() {
            payloads.push((
                section_kind::EXTERNAL_ORIGINS,
                encode_external_origins(&self.external_origins),
            ));
        }

        // EXTERNAL_PACKAGE_ORIGINS (round 8): sparse mapping from External
        // node_id -> StringId of the package specifier. Only emitted for
        // External nodes whose `package_origin` was Some at construction;
        // ambient globals and Unknown-origin nodes are not in this list.
        // Entries in ascending node_id order (creation order); the loader
        // asserts ascending+distinct.
        if !self.external_package_origins.is_empty() {
            payloads.push((
                section_kind::EXTERNAL_PACKAGE_ORIGINS,
                encode_external_package_origins(&self.external_package_origins),
            ));
        }

        for k_idx in 0..EdgeKind::COUNT {
            if !edge_kinds_seen[k_idx] {
                continue;
            }
            let edge_kind_u16 = (k_idx as u16) + 1;
            payloads.push((
                section_kind::out_offsets(edge_kind_u16),
                out_offsets[k_idx].take().unwrap(),
            ));
            payloads.push((
                section_kind::out_targets(edge_kind_u16),
                out_targets[k_idx].take().unwrap(),
            ));
            payloads.push((
                section_kind::in_offsets(edge_kind_u16),
                in_offsets[k_idx].take().unwrap(),
            ));
            payloads.push((
                section_kind::in_targets(edge_kind_u16),
                in_targets[k_idx].take().unwrap(),
            ));
            // EDGE_SPANS_<kind> (Task 10): emit only for kinds whose edges have
            // at least one Some(span). Sections appear AFTER their paired OUT/IN
            // sections so a sequential reader sees adjacency before its spans.
            if let Some(permuted) = permuted_edge_spans[k_idx].take() {
                payloads.push((
                    section_kind::edge_spans(edge_kind_u16),
                    encode_span_section(&permuted),
                ));
            }
            // EDGE_TYPE_ONLY_<kind>: emit only for kinds with ≥1 type-only edge.
            // Placed after EDGE_SPANS_<kind> so a sequential reader sees
            // adjacency → spans → type-only for each kind.
            if let Some(permuted) = permuted_edge_type_only[k_idx].take() {
                payloads.push((
                    section_kind::edge_type_only(edge_kind_u16),
                    encode_type_only_section(&permuted),
                ));
            }
            // EDGE_LABEL_<kind>: emit only for kinds with ≥1 labeled edge.
            // In v1 only Exports carries labels; CSR view validates that
            // invariant on load.
            if let Some(permuted) = permuted_edge_labels[k_idx].take() {
                payloads.push((
                    section_kind::edge_labels(edge_kind_u16),
                    encode_label_section(&permuted),
                ));
            }
            // EDGE_TYPE_REF_POSITION_<kind>: emit only for kinds with ≥1
            // recorded position (TypeRef only, in v1). Placed after
            // EDGE_LABEL_<kind> so a sequential reader sees
            // adjacency → spans → type-only → labels → positions.
            if let Some(permuted) = permuted_type_ref_positions[k_idx].take() {
                payloads.push((
                    section_kind::edge_type_ref_position(edge_kind_u16),
                    encode_type_ref_position_section(&permuted),
                ));
            }
            // CALL_ARGUMENT_ANCHOR_OFFSETS_<kind>/_ENTRIES_<kind> (G1.6 fork
            // (a)): emit only for kinds with ≥1 recorded anchor (Calls only,
            // in v1). Placed after EDGE_TYPE_REF_POSITION_<kind> so a
            // sequential reader sees adjacency -> spans -> type-only ->
            // labels -> positions -> argument anchors; offsets before
            // entries, matching every other offsets/targets pairing.
            if let (Some(offsets), Some(entries)) = (
                call_argument_anchor_offsets[k_idx].take(),
                call_argument_anchor_entries[k_idx].take(),
            ) {
                payloads.push((
                    section_kind::call_argument_anchor_offsets(edge_kind_u16),
                    offsets,
                ));
                payloads.push((
                    section_kind::call_argument_anchor_entries(edge_kind_u16),
                    entries,
                ));
            }
        }

        let mut entries = Vec::with_capacity(payloads.len());
        let mut cursor = HEADER_SIZE + payloads.len() * SECTION_ENTRY_SIZE;
        for (kind, payload) in &payloads {
            entries.push(SectionEntry {
                kind: *kind,
                offset: cursor as u64,
                len: payload.len() as u64,
            });
            cursor += payload.len();
        }
        let mut buf = encode_header_and_section_table(&entries);
        for (_, payload) in &payloads {
            buf.extend_from_slice(payload);
        }
        OwnedGraph::from_bytes(buf)
    }

    /// Build the sibling source archive from `file_contents`. Reads-only —
    /// the file_contents Vec is unchanged. Pairs with `freeze_to_ir` to
    /// produce the two halves of the freeze output without re-doing work.
    fn build_source_archive(&self) -> OwnedSourceArchive {
        let blob_refs: Vec<(&[u8; 32], &[u8])> = self
            .file_contents
            .iter()
            .map(|fc| {
                let content = fc
                    .content
                    .as_deref()
                    .expect("GraphBuilder::freeze requires source archive content");
                (&fc.sha256, content)
            })
            .collect();
        let archive_bytes = encode_archive(&blob_refs);
        OwnedSourceArchive::from_bytes(archive_bytes)
    }

    /// Build BOTH the IR and the sibling source archive. Consumes the
    /// builder. Use this when you want both halves of the freeze output
    /// (the demo, real workflows, anything that wants source-byte resolution).
    pub fn freeze(mut self) -> (OwnedGraph, OwnedSourceArchive) {
        let ir = self.freeze_to_ir();
        let archive = self.build_source_archive();
        (ir, archive)
    }

    /// Build the IR only — does NOT construct the sibling source archive.
    /// Use this when source bytes aren't needed (re-query-only callers,
    /// tests that exercise graph structure without source resolution).
    ///
    /// Saves O(total_source_bytes) of archive encoding work that
    /// `self.freeze_graph().0` would otherwise pay and then discard.
    pub fn freeze_graph(mut self) -> OwnedGraph {
        self.freeze_to_ir()
    }
}

/// Encode the EXTERNAL_ORIGINS section: u32 LE count, then `count` records of
/// (u32 LE node_id, u8 origin). Entries are already in ascending node_id order
/// (creation order), so the section is deterministic without sorting.
fn encode_external_origins(entries: &[(u32, u8)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + entries.len() * 5);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (node_id, origin) in entries {
        out.extend_from_slice(&node_id.to_le_bytes());
        out.push(*origin);
    }
    out
}

/// Encode the EXTERNAL_PACKAGE_ORIGINS section: u32 LE count, then `count`
/// records of (u32 LE node_id, u32 LE StringId). Entries are in ascending
/// node_id order (creation order) — the loader rejects any non-ascending
/// or duplicate node_id. Total: 4 + 8 * count bytes.
fn encode_external_package_origins(entries: &[(u32, StringId)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + entries.len() * 8);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (node_id, sid) in entries {
        out.extend_from_slice(&node_id.to_le_bytes());
        out.extend_from_slice(&sid.to_le_bytes());
    }
    out
}

fn encode_nodes_section(kinds: &[NodeKind], expected_kinds: &[u16], names: &[StringId]) -> Vec<u8> {
    let mut out = Vec::with_capacity(kinds.len() * 8);
    for i in 0..kinds.len() {
        out.extend_from_slice(&(kinds[i] as u16).to_le_bytes());
        out.extend_from_slice(&expected_kinds[i].to_le_bytes());
        out.extend_from_slice(&names[i].to_le_bytes());
    }
    out
}

/// Encode the combined NODE_SPANS section payload per spec §3.2.
///
/// Layout (Array-of-Structs spans + three concatenated presence bitsets):
/// - `24 * N` bytes: for each node `i`, write 24 contiguous bytes —
///   bytes 0..8 are `name_span`, 8..16 are `decl_span`, 16..24 are `body_span`,
///   each as `(start: u32 LE, length: u32 LE)`. Absent slots are zero-filled.
/// - `3 * ceil(N/8)` bytes: three concatenated presence bitsets in
///   `(name, decl, body)` order. Each bitset is LSB-first per byte; unused
///   high bits in the final byte stay zero (zero-init of the bitset Vec).
///
/// Total length: `24 * N + 3 * ceil(N/8)` bytes.
///
/// Combined into one section (was three: NODE_NAME_SPANS / NODE_DECL_SPANS /
/// NODE_BODY_SPANS) for cache locality on multi-span-per-node access and to
/// halve the parser code surface.
fn encode_node_spans(
    name_spans: &[Option<Span>],
    decl_spans: &[Option<Span>],
    body_spans: &[Option<Span>],
) -> Vec<u8> {
    debug_assert_eq!(name_spans.len(), decl_spans.len());
    debug_assert_eq!(name_spans.len(), body_spans.len());
    let n = name_spans.len();
    let bitset_len = n.div_ceil(8);
    let mut out = Vec::with_capacity(24 * n + 3 * bitset_len);

    // Spans array, AoS: name, decl, body for each node in turn.
    for i in 0..n {
        for span_opt in [&name_spans[i], &decl_spans[i], &body_spans[i]] {
            match span_opt {
                Some(s) => {
                    out.extend_from_slice(&s.start().to_le_bytes());
                    out.extend_from_slice(&s.length().to_le_bytes());
                }
                None => out.extend_from_slice(&[0u8; 8]),
            }
        }
    }

    // Three concatenated presence bitsets in (name, decl, body) order.
    for span_array in [name_spans, decl_spans, body_spans] {
        let mut bitset = vec![0u8; bitset_len];
        for (i, s) in span_array.iter().enumerate() {
            if s.is_some() {
                bitset[i / 8] |= 1 << (i % 8);
            }
        }
        out.extend_from_slice(&bitset);
    }

    out
}

/// Encode a per-edge-kind type-only presence bitset: `ceil(N/8)` bytes,
/// LSB-first per byte; bit i set ⟺ OUT slot i is syntactically type-only.
/// Unused high bits in the final byte stay zero (zero-init buffer).
fn encode_type_only_section(type_only: &[bool]) -> Vec<u8> {
    let n = type_only.len();
    let mut bitset = vec![0u8; n.div_ceil(8)];
    for (i, &t) in type_only.iter().enumerate() {
        if t {
            bitset[i / 8] |= 1 << (i % 8);
        }
    }
    bitset
}

/// Encode a per-edge-kind label section payload:
///   - 4 bytes per slot: StringId u32 LE (zero when absent)
///   - ceil(N/8) bytes presence bitset, LSB-first per byte
///
/// Total length: `4 * N + ceil(N/8)` bytes. Used only for EDGE_LABEL_<kind>
/// sections (Exports only in v1).
fn encode_label_section(labels: &[Option<StringId>]) -> Vec<u8> {
    let n = labels.len();
    let bitset_len = n.div_ceil(8);
    let mut out = Vec::with_capacity(n * 4 + bitset_len);
    for sid in labels {
        match sid {
            Some(s) => out.extend_from_slice(&s.to_le_bytes()),
            None => out.extend_from_slice(&[0u8; 4]),
        }
    }
    let mut bitset = vec![0u8; bitset_len];
    for (i, sid) in labels.iter().enumerate() {
        if sid.is_some() {
            bitset[i / 8] |= 1 << (i % 8);
        }
    }
    out.extend_from_slice(&bitset);
    out
}

/// Encode a per-edge-kind `EDGE_TYPE_REF_POSITION_<kind>` payload
/// (G1.5 Fix 2 §3.2/2b):
///   - 1 byte per slot: `TypeRefPosition as u8` (zero when absent — note 0 is
///     also `Annotation`'s discriminant, so the presence bit, not the byte
///     value, is the sole authority on absence; mirrors `encode_span_section`
///     zero-filling absent (start, length) even though (0, 0) could in
///     principle be a real span)
///   - `ceil(N/8)` bytes presence bitset, LSB-first per byte
///
/// Total length: `N + ceil(N/8)` bytes. Used only for
/// `EDGE_TYPE_REF_POSITION_<kind>` sections.
fn encode_type_ref_position_section(positions: &[Option<TypeRefPosition>]) -> Vec<u8> {
    let n = positions.len();
    let bitset_len = n.div_ceil(8);
    let mut out = Vec::with_capacity(n + bitset_len);
    for p in positions {
        out.push(p.map_or(0u8, |v| v as u8));
    }
    let mut bitset = vec![0u8; bitset_len];
    for (i, p) in positions.iter().enumerate() {
        if p.is_some() {
            bitset[i / 8] |= 1 << (i % 8);
        }
    }
    out.extend_from_slice(&bitset);
    out
}

/// Encode the `CALL_ARGUMENT_ANCHOR_OFFSETS_<kind>`/`_ENTRIES_<kind>` section
/// pair (G1.6 fork (a)) for one edge kind. `anchors` is indexed by OUT slot
/// (`anchors[i]` = the anchor list for slot `i`, possibly empty). Interns
/// each `ObjectKey`'s `name`/`path` strings via `intern` — the only sidecar
/// encoder in this file that needs the interner, since every fixed-size
/// sidecar carries no string data of its own.
///
/// Returns `(offsets_bytes, entries_bytes)`:
/// - `offsets_bytes`: `(anchors.len() + 1)` x `u32` LE prefix-sum offsets.
/// - `entries_bytes`: flat `CALL_ARGUMENT_ANCHOR_ENTRY_SIZE`-byte records, in
///   the same slot order as `anchors`, then within a slot in `anchors[i]`'s
///   own order.
fn encode_call_argument_anchor_sections(
    anchors: &[Vec<CallArgumentAnchor>],
    intern: &mut StringInterner,
) -> (Vec<u8>, Vec<u8>) {
    let m = anchors.len();
    let mut offsets = Vec::with_capacity((m + 1) * 4);
    let mut running: u32 = 0;
    offsets.extend_from_slice(&running.to_le_bytes());
    let total_entries: usize = anchors.iter().map(Vec::len).sum();
    let mut entries = Vec::with_capacity(total_entries * CALL_ARGUMENT_ANCHOR_ENTRY_SIZE);
    for slot_anchors in anchors {
        for a in slot_anchors {
            match a {
                CallArgumentAnchor::CallbackHead { arg_index, span } => {
                    entries.push(0u8);
                    entries.extend_from_slice(&arg_index.to_le_bytes());
                    entries.extend_from_slice(&span.start().to_le_bytes());
                    entries.extend_from_slice(&span.length().to_le_bytes());
                    entries.extend_from_slice(&0u32.to_le_bytes()); // name (unused)
                    entries.extend_from_slice(&0u32.to_le_bytes()); // path (unused)
                }
                CallArgumentAnchor::ObjectKey {
                    arg_index,
                    name,
                    span,
                    path,
                } => {
                    let name_id = intern.intern(name);
                    let path_id = intern.intern(path);
                    entries.push(1u8);
                    entries.extend_from_slice(&arg_index.to_le_bytes());
                    entries.extend_from_slice(&span.start().to_le_bytes());
                    entries.extend_from_slice(&span.length().to_le_bytes());
                    entries.extend_from_slice(&name_id.raw().to_le_bytes());
                    entries.extend_from_slice(&path_id.raw().to_le_bytes());
                }
            }
            running += 1;
        }
        offsets.extend_from_slice(&running.to_le_bytes());
    }
    debug_assert_eq!(
        entries.len(),
        total_entries * CALL_ARGUMENT_ANCHOR_ENTRY_SIZE
    );
    (offsets, entries)
}

/// Encode a per-edge-kind span section payload per spec §3.3:
///   - 8 bytes per slot: (start: u32 LE, length: u32 LE), zero-filled when absent
///   - ceil(N / 8) bytes presence bitset, LSB-first per byte
///
/// Total length: `8 * N + ceil(N/8)` bytes. Used only for EDGE_SPANS_<kind>
/// sections — node spans use `encode_node_spans` (combined layout).
fn encode_span_section(spans: &[Option<Span>]) -> Vec<u8> {
    let n = spans.len();
    let bitset_len = n.div_ceil(8);
    let mut out = Vec::with_capacity(n * 8 + bitset_len);

    // Span array — zero-fill absent.
    for s in spans {
        match s {
            Some(span) => {
                out.extend_from_slice(&span.start().to_le_bytes());
                out.extend_from_slice(&span.length().to_le_bytes());
            }
            None => out.extend_from_slice(&[0u8; 8]),
        }
    }

    // Presence bitset — LSB-first per byte; unused high bits in the final byte
    // remain zero because the buffer was just allocated from zero-init.
    let mut bitset = vec![0u8; bitset_len];
    for (i, s) in spans.iter().enumerate() {
        if s.is_some() {
            bitset[i / 8] |= 1 << (i % 8);
        }
    }
    out.extend_from_slice(&bitset);

    out
}

/// Encode the SOURCE_METADATA section payload per spec §3.4: one 48-byte entry
/// per File node, sorted ascending by file_node_id.
///
/// Layout per entry:
///   offset  size   field
///      0     8     content_length: u64 LE
///      8     4     file_node_id:   u32 LE
///     12     4     _padding = 0   (canonical: must be zero, validated reader-side)
///     16    32     sha256:         raw FIPS 180-4 digest bytes
///
/// Sorts `file_contents` in place by `file_node_id`. add_file assigns NodeIds
/// in call order so this is typically a no-op, but extractors that interleave
/// add_file with add_node could produce non-ascending file NodeIds.
fn encode_source_metadata(file_contents: &mut [FileContent]) -> Vec<u8> {
    file_contents.sort_by_key(|fc| fc.file_node_id.0);

    let mut out = Vec::with_capacity(file_contents.len() * 48);
    for fc in file_contents.iter() {
        out.extend_from_slice(&fc.content_length.to_le_bytes()); // 8
        out.extend_from_slice(&fc.file_node_id.0.to_le_bytes()); // 4
        out.extend_from_slice(&[0u8; 4]); // padding
        out.extend_from_slice(&fc.sha256); // 32
    }
    out
}

/// For a per-node `degrees` array, build:
///   - `offsets_bytes`: (n+1) u32-LE entries, prefix-sum of degrees in bytes
///   - `cursors`: per-node starting write positions (initially equal to `offsets[i]`),
///     used during pass 3 to track where to place the next target
///   - `targets_buf`: zeroed `Vec<u8>` of exactly `total_edges * 4` bytes
fn prefix_sum_into_csr(degrees: &[u32]) -> (Vec<u8>, Vec<u32>, Vec<u8>) {
    let n = degrees.len();
    let mut offsets = Vec::with_capacity((n + 1) * 4);
    let mut cursors = Vec::with_capacity(n);
    let mut running: u32 = 0;
    offsets.extend_from_slice(&running.to_le_bytes());
    for &deg in degrees {
        cursors.push(running);
        running = running
            .checked_add(deg)
            .expect("Repotoire v0 format limit: edge count must fit in u32");
        offsets.extend_from_slice(&running.to_le_bytes());
    }
    let targets = vec![0u8; (running as usize) * 4];
    (offsets, cursors, targets)
}
