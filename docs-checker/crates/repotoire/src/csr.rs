use crate::ids::{NodeId, StringId};
use crate::interner::resolve_string;
use crate::schema::{EdgeKind, NodeKind, TypeRefPosition};
use crate::spans::{SourceMetadata, Span};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, Copy)]
struct ResolvedSection<'a> {
    bytes: &'a [u8],
}

#[derive(Debug)]
pub struct CodeGraph<'a> {
    strings_arena: ResolvedSection<'a>,
    string_index: ResolvedSection<'a>,
    nodes: ResolvedSection<'a>,
    out_offsets: [Option<ResolvedSection<'a>>; EdgeKind::COUNT],
    out_targets: [Option<ResolvedSection<'a>>; EdgeKind::COUNT],
    in_offsets: [Option<ResolvedSection<'a>>; EdgeKind::COUNT],
    in_targets: [Option<ResolvedSection<'a>>; EdgeKind::COUNT],

    // ---- Spans milestone (Task 13) ----
    /// Materialized per-node kinds. Existing node-validation loop pushes each
    /// validated kind here; downstream tasks (15 file_of, 16 nodes_by_kind, 18
    /// cross-section validation) consume this Vec.
    pub(crate) node_kinds: Vec<NodeKind>,
    /// Raw NODE_SPANS section bytes (24*N AoS spans + 3 presence bitsets), or
    /// `None` when the section is absent. Node spans are decoded LAZILY, O(1)
    /// per query, from this slice — graph-only consumers never pay the
    /// `Vec<Option<Span>>` materialization. Validated in full (transiently) at
    /// `view_from_bytes` time; see `decode_node_span`.
    pub(crate) node_spans_bytes: Option<&'a [u8]>,
    /// Raw `EDGE_SPANS_<kind>` section payloads, indexed parallel to
    /// `OUT_TARGETS_<kind>` (`None` = whole section absent). Edge spans are
    /// decoded LAZILY, O(1) per query, from these slices — graph-only consumers
    /// never pay the `Vec<Option<Span>>` materialization, mirroring
    /// `node_spans_bytes`. Each slice is validated in full (transiently) at
    /// `view_from_bytes` time; see `decode_edge_span`.
    pub(crate) edge_spans_bytes: [Option<&'a [u8]>; EdgeKind::COUNT],
    /// Raw `EDGE_TYPE_ONLY_<kind>` presence-bitset payloads, indexed parallel to
    /// `OUT_TARGETS_<kind>` (`None` = section absent ⟺ all edges of the kind are
    /// runtime). Decoded LAZILY, O(1) per query, like `edge_spans_bytes`.
    /// Validated in full (length + canonical high bits + orphan + supported
    /// kind) at `view_from_bytes` time; see `decode_edge_type_only`.
    pub(crate) edge_type_only_bytes: [Option<&'a [u8]>; EdgeKind::COUNT],
    /// Raw `EDGE_LABEL_<kind>` payloads, indexed parallel to `OUT_TARGETS_<kind>`
    /// (`None` = section absent ⟺ no edge of the kind carries a label).
    /// Decoded LAZILY, O(1) per query — see `decode_edge_label`. Only meaningful
    /// for `Exports` in v1; load-time validation rejects other kinds.
    pub(crate) edge_labels_bytes: [Option<&'a [u8]>; EdgeKind::COUNT],
    /// Raw `EDGE_TYPE_REF_POSITION_<kind>` payloads (G1.5 Fix 2 §3.2/2b),
    /// indexed parallel to `OUT_TARGETS_<kind>` (`None` = section absent ⟺ no
    /// edge of the kind carries a recorded position). Decoded LAZILY, O(1) per
    /// query — see `decode_edge_type_ref_position`. Only meaningful for
    /// `TypeRef`; load-time validation rejects other kinds.
    pub(crate) edge_type_ref_position_bytes: [Option<&'a [u8]>; EdgeKind::COUNT],
    /// Raw `CALL_ARGUMENT_ANCHOR_OFFSETS_<kind>`/`_ENTRIES_<kind>` payload
    /// pair (G1.6 fork (a)), indexed parallel to `OUT_TARGETS_<kind>` (`None`
    /// = section absent ⟺ no edge of the kind carries any recorded anchor).
    /// Decoded LAZILY, O(1) offsets lookup + O(k) entries slice per query —
    /// see `decode_call_argument_anchors`. Only meaningful for `Calls`;
    /// load-time validation rejects other kinds.
    pub(crate) call_argument_anchor_offsets_bytes: [Option<&'a [u8]>; EdgeKind::COUNT],
    pub(crate) call_argument_anchor_entries_bytes: [Option<&'a [u8]>; EdgeKind::COUNT],

    // ---- Spans milestone (Task 14: SOURCE_METADATA) ----
    /// Per-File-node metadata (content_length + sha256), sorted ascending by
    /// the file's NodeId. `None` when SOURCE_METADATA is absent from the IR.
    /// Per spec §2.6 / §4.1 invariant 10, when this is Some it is COMPLETE:
    /// every File node in the graph has exactly one entry.
    pub(crate) source_metadata: Option<Vec<SourceMetadata>>,
    /// O(1) lookup: `source_metadata_index[node_id]` returns the index into
    /// `source_metadata` for that File node, or `u32::MAX` for non-File nodes
    /// (and for all nodes when `source_metadata` is None). Built in the same
    /// pass as `source_metadata` per spec §7.2 — folded forward from the
    /// original Task 16 plan since the data is structurally needed alongside
    /// the parsed metadata Vec.
    pub(crate) source_metadata_index: Vec<u32>,

    // ---- Spans milestone (Task 15: file_of) ----
    /// For each node, its File ancestor reached via Contains-IN walk. File
    /// nodes have themselves as the ancestor. Orphan nodes (no Contains
    /// parents reaching a File) and nodes in Contains cycles have None.
    /// Length = node_count. Built once at view_from_bytes time.
    pub(crate) file_of: Vec<Option<NodeId>>,

    // ---- Spans milestone (Task 16: nodes_by_kind) ----
    /// Per-kind NodeId list, ascending. `nodes_by_kind[k]` contains every node
    /// whose kind discriminant is `k + 1` (NodeKind discriminants are 1-indexed;
    /// 0 is reserved as invalid). Total bytes across all kind sub-Vecs = 4 × N.
    /// Built O(N) by walking node_kinds during view construction.
    pub(crate) nodes_by_kind: [Vec<NodeId>; NodeKind::COUNT],

    // ---- Real-package readiness: External origins ----
    /// `node_id -> ExternalOrigin` for External nodes, parsed from the
    /// EXTERNAL_ORIGINS section. Empty when the section is absent.
    pub(crate) external_origins: std::collections::HashMap<u32, crate::schema::ExternalOrigin>,

    /// (Round 8) `node_id -> StringId` for External nodes that carry a
    /// package_origin (NamedFrom from a bare package, bare-pkg stars,
    /// import bindings). Empty when EXTERNAL_PACKAGE_ORIGINS is absent.
    /// Resolved through the interner by `external_package_origin`.
    pub(crate) external_package_origins: std::collections::HashMap<u32, StringId>,
}

/// A call-argument interior anchor decoded from the
/// `CALL_ARGUMENT_ANCHOR_OFFSETS_Calls`/`_ENTRIES_Calls` CSR sections (G1.6
/// fork (a)). Owned-string mirror of `ts::events::CallArgumentAnchor` —
/// `name`/`path` are resolved through the string arena rather than carried
/// as interned `StringId`s, since this is the READ-side (consumer-facing)
/// shape; W1 (the closure walk, a later PR) is the intended consumer, via
/// `SpanView::call_argument_anchors_from_in`. Fields are named plainly per
/// the design brief: `callback_heads`/`object_keys` groupings live one level
/// up wherever a caller wants them split (this type stays a flat per-anchor
/// enum, matching every other CSR-decoded per-edge datum in this module).
///
/// Byte spans, not resolved line numbers — consistent with every other span
/// this crate returns (`edge_span_from_in`, node spans, …): line resolution
/// needs source bytes, which `SpanView`/`CodeGraph` deliberately don't hold;
/// callers resolve via `bundle.line_col(span)` the same way `impact/
/// evidence.rs` already does for every other compiler-pressure span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallArgumentAnchorView {
    CallbackHead {
        arg_index: u16,
        span: Span,
    },
    ObjectKey {
        arg_index: u16,
        name: String,
        span: Span,
        path: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameLocation {
    pub node: NodeId,
    pub kind: NodeKind,
    pub file: Option<NodeId>,
    pub name_span: Option<Span>,
    pub decl_span: Option<Span>,
    pub body_span: Option<Span>,
}

/// Opt-in derived index for repeated name lookups.
///
/// The frozen graph keeps node rows compact by storing `StringId`s. This index
/// keeps that persisted shape unchanged while letting hot query paths resolve a
/// name once and reuse the matching nodes plus location facts.
#[derive(Debug)]
pub struct NameIndex<'a> {
    locations_by_name: BTreeMap<&'a str, Vec<NameLocation>>,
}

impl<'a> NameIndex<'a> {
    pub fn build(graph: &CodeGraph<'a>) -> Self {
        let mut locations_by_name: BTreeMap<&'a str, Vec<NameLocation>> = BTreeMap::new();
        for raw in 0..graph.node_count() {
            let node = NodeId::from_raw(raw);
            let name = graph.node_name(node);
            locations_by_name
                .entry(name)
                .or_default()
                .push(NameLocation {
                    node,
                    kind: graph.node_kind(node),
                    file: graph.file_of(node),
                    name_span: graph.node_name_span(node),
                    decl_span: graph.node_decl_span(node),
                    body_span: graph.node_body_span(node),
                });
        }
        Self { locations_by_name }
    }

    pub fn locations_named(&self, name: &str) -> &[NameLocation] {
        self.locations_by_name
            .get(name)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

impl OwnedGraph {
    pub fn as_view(&self) -> CodeGraph<'_> {
        CodeGraph::view_from_bytes(&self.bytes).expect("OwnedGraph bytes must always parse")
    }
}

impl<'a> CodeGraph<'a> {
    pub fn view_from_bytes(buf: &'a [u8]) -> Result<Self, GraphError> {
        let (table, _) = parse_header_and_section_table(buf)?;

        let mut strings_arena: Option<ResolvedSection<'a>> = None;
        let mut string_index: Option<ResolvedSection<'a>> = None;
        let mut nodes: Option<ResolvedSection<'a>> = None;
        let mut out_offsets: [Option<ResolvedSection<'a>>; EdgeKind::COUNT] = Default::default();
        let mut out_targets: [Option<ResolvedSection<'a>>; EdgeKind::COUNT] = Default::default();
        let mut in_offsets: [Option<ResolvedSection<'a>>; EdgeKind::COUNT] = Default::default();
        let mut in_targets: [Option<ResolvedSection<'a>>; EdgeKind::COUNT] = Default::default();

        // Spans-milestone (Task 13): raw byte slices collected here, parsed
        // after the section-table walk completes (we need node_count + per-kind
        // M_kind for length validation, which only become known once the walk
        // is done).
        let mut node_spans_raw: Option<ResolvedSection<'a>> = None;
        let mut source_metadata_raw: Option<ResolvedSection<'a>> = None;
        let mut external_origins_raw: Option<ResolvedSection<'a>> = None;
        let mut external_package_origins_raw: Option<ResolvedSection<'a>> = None;
        let mut edge_spans_raw: [Option<ResolvedSection<'a>>; EdgeKind::COUNT] = Default::default();
        let mut edge_type_only_raw: [Option<ResolvedSection<'a>>; EdgeKind::COUNT] =
            Default::default();
        let mut edge_labels_raw: [Option<ResolvedSection<'a>>; EdgeKind::COUNT] =
            Default::default();
        let mut edge_type_ref_position_raw: [Option<ResolvedSection<'a>>; EdgeKind::COUNT] =
            Default::default();
        let mut call_argument_anchor_offsets_raw: [Option<ResolvedSection<'a>>; EdgeKind::COUNT] =
            Default::default();
        let mut call_argument_anchor_entries_raw: [Option<ResolvedSection<'a>>; EdgeKind::COUNT] =
            Default::default();

        for e in &table {
            let off = e.offset as usize;
            let end = off
                .checked_add(e.len as usize)
                .ok_or(GraphError::BufferTooShort)?;
            if end > buf.len() {
                return Err(GraphError::BufferTooShort);
            }
            let bytes = &buf[off..end];
            let slot = ResolvedSection { bytes };
            match e.kind {
                section_kind::STRINGS_ARENA => {
                    if strings_arena.is_some() {
                        return Err(GraphError::DuplicateSection(e.kind));
                    }
                    strings_arena = Some(slot);
                }
                section_kind::STRING_INDEX => {
                    if string_index.is_some() {
                        return Err(GraphError::DuplicateSection(e.kind));
                    }
                    if !slot.bytes.len().is_multiple_of(STRING_INDEX_ENTRY_SIZE) {
                        return Err(GraphError::StringIndexMisaligned);
                    }
                    string_index = Some(slot);
                }
                section_kind::NODES => {
                    if nodes.is_some() {
                        return Err(GraphError::DuplicateSection(e.kind));
                    }
                    if !slot.bytes.len().is_multiple_of(NODE_ROW_SIZE) {
                        return Err(GraphError::NodesSectionMisaligned);
                    }
                    nodes = Some(slot);
                }
                section_kind::NODE_SPANS => {
                    if node_spans_raw.is_some() {
                        return Err(GraphError::DuplicateSection(e.kind));
                    }
                    node_spans_raw = Some(slot);
                }
                section_kind::SOURCE_METADATA => {
                    // Task 14 parses + stores; Task 13 only enforces dedup.
                    if source_metadata_raw.is_some() {
                        return Err(GraphError::DuplicateSection(e.kind));
                    }
                    source_metadata_raw = Some(slot);
                }
                section_kind::EXTERNAL_ORIGINS => {
                    if external_origins_raw.is_some() {
                        return Err(GraphError::DuplicateSection(e.kind));
                    }
                    external_origins_raw = Some(slot);
                }
                section_kind::EXTERNAL_PACKAGE_ORIGINS => {
                    if external_package_origins_raw.is_some() {
                        return Err(GraphError::DuplicateSection(e.kind));
                    }
                    external_package_origins_raw = Some(slot);
                }
                k => {
                    let high = k & 0xFF00;
                    let low = k & 0x00FF;
                    if !(1..=EdgeKind::COUNT as u16).contains(&low) {
                        continue; // unknown kind: tolerate as opaque (additive-extensibility)
                    }
                    let idx = (low - 1) as usize;
                    if !slot.bytes.len().is_multiple_of(4) {
                        if high == section_kind::OUT_OFFSETS_BASE
                            || high == section_kind::IN_OFFSETS_BASE
                        {
                            return Err(GraphError::AdjacencyOffsetsMisaligned);
                        }
                        if high == section_kind::OUT_TARGETS_BASE
                            || high == section_kind::IN_TARGETS_BASE
                        {
                            return Err(GraphError::AdjacencyTargetsMisaligned);
                        }
                    }
                    let target_slot = match high {
                        section_kind::OUT_OFFSETS_BASE => &mut out_offsets[idx],
                        section_kind::OUT_TARGETS_BASE => &mut out_targets[idx],
                        section_kind::IN_OFFSETS_BASE => &mut in_offsets[idx],
                        section_kind::IN_TARGETS_BASE => &mut in_targets[idx],
                        section_kind::EDGE_SPANS_BASE => &mut edge_spans_raw[idx],
                        section_kind::EDGE_TYPE_ONLY_BASE => &mut edge_type_only_raw[idx],
                        section_kind::EDGE_LABEL_BASE => &mut edge_labels_raw[idx],
                        section_kind::EDGE_TYPE_REF_POSITION_BASE => {
                            &mut edge_type_ref_position_raw[idx]
                        }
                        section_kind::CALL_ARGUMENT_ANCHOR_OFFSETS_BASE => {
                            &mut call_argument_anchor_offsets_raw[idx]
                        }
                        section_kind::CALL_ARGUMENT_ANCHOR_ENTRIES_BASE => {
                            &mut call_argument_anchor_entries_raw[idx]
                        }
                        _ => continue, // unknown high byte: tolerate
                    };
                    if target_slot.is_some() {
                        return Err(GraphError::DuplicateSection(e.kind));
                    }
                    *target_slot = Some(slot);
                }
            }
        }
        let nodes_slot = nodes.ok_or(GraphError::MissingRequiredSection(section_kind::NODES))?;
        let n = nodes_slot.bytes.len() / NODE_ROW_SIZE;
        // Materialize NodeKind list (Task 13). Existing v0 validated kinds and
        // discarded them; downstream tasks need the materialized Vec.
        let mut node_kinds_vec: Vec<NodeKind> = Vec::with_capacity(n);
        for i in 0..n {
            let base = i * NODE_ROW_SIZE;
            let k = u16::from_le_bytes(nodes_slot.bytes[base..base + 2].try_into().unwrap());
            let node_kind =
                NodeKind::from_u16(k).ok_or(GraphError::InvalidNodeKindDiscriminant(k))?;
            node_kinds_vec.push(node_kind);
            let exp = u16::from_le_bytes(nodes_slot.bytes[base + 2..base + 4].try_into().unwrap());
            if exp != 0 && NodeKind::from_u16(exp).is_none() {
                return Err(GraphError::InvalidNodeKindDiscriminant(exp));
            }
            let name_id =
                StringId::from_le_bytes(nodes_slot.bytes[base + 4..base + 8].try_into().unwrap());
            // Force resolution to catch bad string IDs at parse time.
            resolve_string(
                strings_arena
                    .as_ref()
                    .ok_or(GraphError::MissingRequiredSection(
                        section_kind::STRINGS_ARENA,
                    ))?
                    .bytes,
                string_index
                    .as_ref()
                    .ok_or(GraphError::MissingRequiredSection(
                        section_kind::STRING_INDEX,
                    ))?
                    .bytes,
                name_id,
            )?;
        }
        // Validate adjacency section pairing, offsets length, monotonicity, target count.
        for kind_idx in 0..EdgeKind::COUNT {
            let edge_kind_u16 = (kind_idx as u16) + 1;
            validate_adjacency_pair(
                n,
                out_offsets[kind_idx].as_ref(),
                out_targets[kind_idx].as_ref(),
                section_kind::out_offsets(edge_kind_u16),
                section_kind::out_targets(edge_kind_u16),
            )?;
            validate_adjacency_pair(
                n,
                in_offsets[kind_idx].as_ref(),
                in_targets[kind_idx].as_ref(),
                section_kind::in_offsets(edge_kind_u16),
                section_kind::in_targets(edge_kind_u16),
            )?;
        }
        // adjacency targets must all be < n for in-bounds queries
        for kind_idx in 0..EdgeKind::COUNT {
            if let Some(targets) = &out_targets[kind_idx] {
                for t_off in (0..targets.bytes.len()).step_by(4) {
                    let t =
                        NodeId::from_le_bytes(targets.bytes[t_off..t_off + 4].try_into().unwrap());
                    if t.as_usize() >= n {
                        return Err(GraphError::NodeIdOutOfBounds);
                    }
                }
            }
            if let Some(targets) = &in_targets[kind_idx] {
                for t_off in (0..targets.bytes.len()).step_by(4) {
                    let t =
                        NodeId::from_le_bytes(targets.bytes[t_off..t_off + 4].try_into().unwrap());
                    if t.as_usize() >= n {
                        return Err(GraphError::NodeIdOutOfBounds);
                    }
                }
            }
        }
        // OUT and IN must describe the same edge multiset per kind.
        // Targets are now known to be in-bounds, so any (from, to) pair we
        // pack into a u64 is well-formed; mismatch here means a structurally
        // inconsistent IR, not corruption we already caught.
        for kind_idx in 0..EdgeKind::COUNT {
            let edge_kind_u16 = (kind_idx as u16) + 1;
            validate_adjacency_mirror(
                n,
                out_offsets[kind_idx].as_ref(),
                out_targets[kind_idx].as_ref(),
                in_offsets[kind_idx].as_ref(),
                in_targets[kind_idx].as_ref(),
                edge_kind_u16,
            )?;
        }

        // ---- Task 13: parse NODE_SPANS (combined) + EDGE_SPANS_<kind> ----
        // Keep the raw slice for lazy per-query decode (Plan2-a); the parsed
        // triple below is TRANSIENT — used only for full validation + the
        // orphan / decl-vs-body consistency checks, then dropped (not stored).
        let node_spans_bytes: Option<&'a [u8]> = node_spans_raw.map(|s| s.bytes);
        let (node_name_spans, node_decl_spans, node_body_spans) = match node_spans_bytes {
            Some(bytes) => {
                let (n_spans, d_spans, b_spans) = parse_node_spans(bytes, n)?;
                (Some(n_spans), Some(d_spans), Some(b_spans))
            }
            None => (None, None, None),
        };

        // Keep the raw slices for lazy per-query decode (mirrors node_spans_bytes);
        // the parsed `edge_spans_parsed` triple below is TRANSIENT — used only for
        // full canonical validation + the Check-3 file-bounds walk, then dropped.
        let mut edge_spans_bytes: [Option<&'a [u8]>; EdgeKind::COUNT] = Default::default();
        let mut edge_spans_parsed: [Option<Vec<Option<Span>>>; EdgeKind::COUNT] =
            Default::default();
        for k_idx in 0..EdgeKind::COUNT {
            if let Some(slot) = edge_spans_raw[k_idx] {
                let edge_kind_disc = (k_idx as u16) + 1;
                let span_kind = section_kind::edge_spans(edge_kind_disc);
                // Orphan check: edge spans require their paired OUT_TARGETS +
                // OUT_OFFSETS to be present (we'd otherwise have no way to
                // determine M_kind for length validation).
                if out_targets[k_idx].is_none() || out_offsets[k_idx].is_none() {
                    return Err(GraphError::OrphanEdgeSpansSection {
                        edge_kind: span_kind,
                    });
                }
                let m_kind = out_targets[k_idx].as_ref().unwrap().bytes.len() / 4;
                edge_spans_parsed[k_idx] = Some(parse_edge_spans(slot.bytes, m_kind, span_kind)?);
                edge_spans_bytes[k_idx] = Some(slot.bytes);
            }
        }

        // EDGE_TYPE_ONLY_<kind>: enforce the format invariant that the marker is
        // only valid on Imports/Exports (no other edge kind has a syntactic
        // `type` modifier), then validate length + canonical high bits + orphan,
        // then keep the raw slice for lazy per-query decode (presence-only, so
        // no transient parsed array is needed).
        let mut edge_type_only_bytes: [Option<&'a [u8]>; EdgeKind::COUNT] = Default::default();
        for k_idx in 0..EdgeKind::COUNT {
            if let Some(slot) = edge_type_only_raw[k_idx] {
                let edge_kind_disc = (k_idx as u16) + 1;
                let type_only_section_kind = section_kind::edge_type_only(edge_kind_disc);
                if !matches!(
                    EdgeKind::from_u16(edge_kind_disc),
                    Some(EdgeKind::Imports) | Some(EdgeKind::Exports)
                ) {
                    return Err(GraphError::TypeOnlySectionOnUnsupportedKind {
                        edge_kind: type_only_section_kind,
                    });
                }
                if out_targets[k_idx].is_none() || out_offsets[k_idx].is_none() {
                    return Err(GraphError::OrphanTypeOnlySection {
                        edge_kind: type_only_section_kind,
                    });
                }
                let m_kind = out_targets[k_idx].as_ref().unwrap().bytes.len() / 4;
                validate_type_only_section(slot.bytes, m_kind, type_only_section_kind)?;
                edge_type_only_bytes[k_idx] = Some(slot.bytes);
            }
        }

        // EDGE_LABEL_<kind>: only valid for Exports in v1 (the only edge kind
        // whose parser captures a distinct public-facing label). Validate
        // (orphan + supported-kind + length + StringId-resolves), then keep
        // the raw slice for lazy per-query decode.
        let mut edge_labels_bytes: [Option<&'a [u8]>; EdgeKind::COUNT] = Default::default();
        for k_idx in 0..EdgeKind::COUNT {
            if let Some(slot) = edge_labels_raw[k_idx] {
                let edge_kind_disc = (k_idx as u16) + 1;
                let label_section_kind = section_kind::edge_labels(edge_kind_disc);
                if !matches!(
                    EdgeKind::from_u16(edge_kind_disc),
                    Some(EdgeKind::Exports) | Some(EdgeKind::Imports)
                ) {
                    return Err(GraphError::LabelSectionOnUnsupportedKind {
                        edge_kind: label_section_kind,
                    });
                }
                if out_targets[k_idx].is_none() || out_offsets[k_idx].is_none() {
                    return Err(GraphError::OrphanLabelSection {
                        edge_kind: label_section_kind,
                    });
                }
                let m_kind = out_targets[k_idx].as_ref().unwrap().bytes.len() / 4;
                let bitset_len = m_kind.div_ceil(8);
                let expected = m_kind * 4 + bitset_len;
                if slot.bytes.len() != expected {
                    return Err(GraphError::LabelSectionMalformed {
                        edge_kind: label_section_kind,
                    });
                }
                let bitset_off = m_kind * 4;
                // Canonical-bits check: unused high bits in the final bitmap
                // byte MUST be zero, mirroring validate_type_only_section.
                // Without this, two distinct byte encodings yield the same
                // logical graph — a corruption-detection gap.
                if !m_kind.is_multiple_of(8) && bitset_len > 0 {
                    let used_bits = m_kind % 8;
                    let mask = !((1u8 << used_bits) - 1);
                    if slot.bytes[bitset_off + bitset_len - 1] & mask != 0 {
                        return Err(GraphError::NonCanonicalPresenceBitset {
                            kind: label_section_kind,
                        });
                    }
                }
                // Validate every slot. Present slots: the StringId payload
                // must resolve via the arena/index sections (captured above
                // and required for NODES parsing). Absent slots: the 4
                // payload bytes MUST be canonical zero (the encoder
                // zero-fills, so any nonzero value is a non-canonical
                // encoding of the same logical graph — same corruption-
                // detection gap as the bitmap canonical-bits check).
                let arena_slot = strings_arena.as_ref().unwrap();
                let index_slot = string_index.as_ref().unwrap();
                for i in 0..m_kind {
                    let present = (slot.bytes[bitset_off + i / 8] >> (i % 8)) & 1 == 1;
                    let off = i * 4;
                    let payload = &slot.bytes[off..off + 4];
                    if !present {
                        if payload != [0u8; 4] {
                            return Err(GraphError::LabelSectionMalformed {
                                edge_kind: label_section_kind,
                            });
                        }
                        continue;
                    }
                    let sid = StringId::from_le_bytes(payload.try_into().unwrap());
                    resolve_string(arena_slot.bytes, index_slot.bytes, sid).map_err(|_| {
                        GraphError::LabelStringIdOutOfBounds {
                            edge_kind: label_section_kind,
                            string_id: sid.raw(),
                        }
                    })?;
                }
                edge_labels_bytes[k_idx] = Some(slot.bytes);
            }
        }

        // EDGE_TYPE_REF_POSITION_<kind> (G1.5 Fix 2 §3.2/2b): only valid for
        // TypeRef — no other edge kind carries a parse-time type-position
        // discriminant (format invariant, mirrors the type-only/label
        // supported-kind checks above). Validate (orphan + supported-kind +
        // length + canonical bitset + per-slot discriminant), then keep the
        // raw slice for lazy per-query decode.
        let mut edge_type_ref_position_bytes: [Option<&'a [u8]>; EdgeKind::COUNT] =
            Default::default();
        for k_idx in 0..EdgeKind::COUNT {
            if let Some(slot) = edge_type_ref_position_raw[k_idx] {
                let edge_kind_disc = (k_idx as u16) + 1;
                let position_section_kind = section_kind::edge_type_ref_position(edge_kind_disc);
                if !matches!(EdgeKind::from_u16(edge_kind_disc), Some(EdgeKind::TypeRef)) {
                    return Err(GraphError::TypeRefPositionSectionOnUnsupportedKind {
                        edge_kind: position_section_kind,
                    });
                }
                if out_targets[k_idx].is_none() || out_offsets[k_idx].is_none() {
                    return Err(GraphError::OrphanTypeRefPositionSection {
                        edge_kind: position_section_kind,
                    });
                }
                let m_kind = out_targets[k_idx].as_ref().unwrap().bytes.len() / 4;
                let bitset_len = m_kind.div_ceil(8);
                let expected = m_kind + bitset_len;
                if slot.bytes.len() != expected {
                    return Err(GraphError::TypeRefPositionSectionMalformed {
                        edge_kind: position_section_kind,
                    });
                }
                let bitset_off = m_kind;
                // Canonical-bits check: unused high bits in the final bitmap
                // byte MUST be zero — same corruption-detection gap as the
                // span/label sections' canonical-bits checks.
                if !m_kind.is_multiple_of(8) && bitset_len > 0 {
                    let used_bits = m_kind % 8;
                    let mask = !((1u8 << used_bits) - 1);
                    if slot.bytes[bitset_off + bitset_len - 1] & mask != 0 {
                        return Err(GraphError::NonCanonicalPresenceBitset {
                            kind: position_section_kind,
                        });
                    }
                }
                // Validate every slot. Present slots: the byte must decode via
                // TypeRefPosition::from_u8 — an unrecognized discriminant is
                // corruption (or a forward-incompatible writer), not a value
                // this reader can silently pass through. Absent slots: the
                // payload byte MUST be canonical zero — 0 also happens to be
                // `Annotation`'s discriminant, but the presence bit (not the
                // byte value) is the sole authority on absence, so a nonzero
                // byte behind an unset bit is still a non-canonical encoding
                // of the same logical graph.
                for i in 0..m_kind {
                    let present = (slot.bytes[bitset_off + i / 8] >> (i % 8)) & 1 == 1;
                    let byte = slot.bytes[i];
                    if !present {
                        if byte != 0 {
                            return Err(GraphError::TypeRefPositionSectionMalformed {
                                edge_kind: position_section_kind,
                            });
                        }
                        continue;
                    }
                    if TypeRefPosition::from_u8(byte).is_none() {
                        return Err(GraphError::TypeRefPositionInvalidDiscriminant {
                            edge_kind: position_section_kind,
                            slot: i as u32,
                            value: byte,
                        });
                    }
                }
                edge_type_ref_position_bytes[k_idx] = Some(slot.bytes);
            }
        }

        // CALL_ARGUMENT_ANCHOR_OFFSETS_<kind>/_ENTRIES_<kind> (G1.6 fork (a)):
        // only valid for `Calls`. Both halves of the pair must be present
        // together (offsets-without-entries or vice versa is malformed —
        // there is no legitimate "zero anchors ever" reason to emit one
        // without the other; the whole pair is simply omitted in that case,
        // as every other optional sidecar section does).
        let mut call_argument_anchor_offsets_bytes: [Option<&'a [u8]>; EdgeKind::COUNT] =
            Default::default();
        let mut call_argument_anchor_entries_bytes: [Option<&'a [u8]>; EdgeKind::COUNT] =
            Default::default();
        for k_idx in 0..EdgeKind::COUNT {
            let offsets_slot = call_argument_anchor_offsets_raw[k_idx];
            let entries_slot = call_argument_anchor_entries_raw[k_idx];
            if offsets_slot.is_none() && entries_slot.is_none() {
                continue;
            }
            let edge_kind_disc = (k_idx as u16) + 1;
            let offsets_section_kind = section_kind::call_argument_anchor_offsets(edge_kind_disc);
            let entries_section_kind = section_kind::call_argument_anchor_entries(edge_kind_disc);
            if !matches!(EdgeKind::from_u16(edge_kind_disc), Some(EdgeKind::Calls)) {
                return Err(GraphError::CallArgumentAnchorSectionOnUnsupportedKind {
                    edge_kind: offsets_section_kind,
                });
            }
            if out_targets[k_idx].is_none() || out_offsets[k_idx].is_none() {
                return Err(GraphError::OrphanCallArgumentAnchorSection {
                    edge_kind: offsets_section_kind,
                });
            }
            let (Some(offsets_slot), Some(entries_slot)) = (offsets_slot, entries_slot) else {
                return Err(GraphError::CallArgumentAnchorSectionMalformed {
                    edge_kind: offsets_section_kind,
                });
            };
            let m_kind = out_targets[k_idx].as_ref().unwrap().bytes.len() / 4;
            if offsets_slot.bytes.len() != (m_kind + 1) * 4 {
                return Err(GraphError::CallArgumentAnchorSectionMalformed {
                    edge_kind: offsets_section_kind,
                });
            }
            let mut prev = 0u32;
            for i in 0..=m_kind {
                let off =
                    u32::from_le_bytes(offsets_slot.bytes[i * 4..i * 4 + 4].try_into().unwrap());
                if i == 0 && off != 0 {
                    return Err(GraphError::CallArgumentAnchorSectionMalformed {
                        edge_kind: offsets_section_kind,
                    });
                }
                if off < prev {
                    return Err(GraphError::CallArgumentAnchorSectionMalformed {
                        edge_kind: offsets_section_kind,
                    });
                }
                prev = off;
            }
            let total_entries = prev as usize;
            if entries_slot.bytes.len() != total_entries * CALL_ARGUMENT_ANCHOR_ENTRY_SIZE {
                return Err(GraphError::CallArgumentAnchorSectionMalformed {
                    edge_kind: entries_section_kind,
                });
            }
            let arena_slot = strings_arena
                .as_ref()
                .ok_or(GraphError::MissingRequiredSection(
                    section_kind::STRINGS_ARENA,
                ))?;
            let index_slot = string_index
                .as_ref()
                .ok_or(GraphError::MissingRequiredSection(
                    section_kind::STRING_INDEX,
                ))?;
            for i in 0..total_entries {
                let base = i * CALL_ARGUMENT_ANCHOR_ENTRY_SIZE;
                let entry = &entries_slot.bytes[base..base + CALL_ARGUMENT_ANCHOR_ENTRY_SIZE];
                let anchor_kind = entry[0];
                if anchor_kind == 1 {
                    // ObjectKey: name/path StringIds must resolve.
                    let name_id = StringId::from_le_bytes(entry[11..15].try_into().unwrap());
                    let path_id = StringId::from_le_bytes(entry[15..19].try_into().unwrap());
                    resolve_string(arena_slot.bytes, index_slot.bytes, name_id).map_err(|_| {
                        GraphError::CallArgumentAnchorSectionMalformed {
                            edge_kind: entries_section_kind,
                        }
                    })?;
                    resolve_string(arena_slot.bytes, index_slot.bytes, path_id).map_err(|_| {
                        GraphError::CallArgumentAnchorSectionMalformed {
                            edge_kind: entries_section_kind,
                        }
                    })?;
                } else if anchor_kind != 0 {
                    return Err(GraphError::CallArgumentAnchorInvalidDiscriminant {
                        edge_kind: entries_section_kind,
                        slot: i as u32,
                        value: anchor_kind,
                    });
                }
            }
            call_argument_anchor_offsets_bytes[k_idx] = Some(offsets_slot.bytes);
            call_argument_anchor_entries_bytes[k_idx] = Some(entries_slot.bytes);
        }

        // Task 14: parse SOURCE_METADATA + build the O(1) source_metadata_index
        // in one pass. Both fields are populated together because they share
        // structural data (the sorted file_node_id list); splitting would
        // duplicate work.
        let (source_metadata, source_metadata_index) = match source_metadata_raw {
            Some(slot) => {
                let parsed = parse_source_metadata(slot.bytes, &node_kinds_vec)?;
                // Build O(1) lookup index: source_metadata_index[node_id] = i
                // for the i-th entry in `parsed`, or u32::MAX for non-File nodes.
                let mut index = vec![u32::MAX; n];
                for (i, (file_node_id, _meta)) in parsed.iter().enumerate() {
                    index[*file_node_id as usize] = i as u32;
                }
                let metadata: Vec<SourceMetadata> = parsed.into_iter().map(|(_id, m)| m).collect();
                (Some(metadata), index)
            }
            None => (None, vec![u32::MAX; n]),
        };

        // Task 15: build file_of by walking Contains-IN edges. Built from raw
        // byte slices here (rather than going through the typed accessors that
        // require &CodeGraph) because the CodeGraph isn't constructed yet.
        let contains_idx = (EdgeKind::Contains as usize) - 1;
        let file_of = build_file_of(
            &node_kinds_vec,
            in_offsets[contains_idx].as_ref().map(|s| s.bytes),
            in_targets[contains_idx].as_ref().map(|s| s.bytes),
        );

        // ---- Task 18: cross-section validation ----
        //
        // Three checks, all gated on the relevant sections being present.
        // file_of and source_metadata exist by this point — we can verify
        // that every span actually fits within its file.

        // Check 1: node spans file-bounds. For each present per-node span
        // (name/decl/body), look up the node's file via file_of, then the
        // file's content_length via source_metadata. Assert span fits.
        if let Some(metadata) = source_metadata.as_ref() {
            for spans in [&node_name_spans, &node_decl_spans, &node_body_spans]
                .into_iter()
                .flatten()
            {
                {
                    for (node, maybe_span) in spans.iter().enumerate() {
                        if let Some(span) = maybe_span {
                            let file = file_of[node].ok_or(GraphError::SpanOnOrphanNode {
                                node_id: node as u32,
                            })?;
                            // Completeness invariant (spec §4.1 invariant 10,
                            // enforced by parse_source_metadata in Task 14):
                            // if SOURCE_METADATA is present, every File node
                            // has an entry. file is always a File node here
                            // (file_of returns the File ancestor), so meta_idx
                            // is guaranteed != u32::MAX. Crash loudly if the
                            // invariant ever breaks rather than silently skip.
                            let meta_idx = source_metadata_index[file.as_usize()];
                            assert_ne!(
                                meta_idx,
                                u32::MAX,
                                "completeness invariant: File node {} missing SOURCE_METADATA",
                                file.0
                            );
                            let content_length = metadata[meta_idx as usize].content_length;
                            if (span.start() as u64) + (span.length() as u64) > content_length {
                                return Err(GraphError::SpanOutOfBounds {
                                    section_kind: section_kind::NODE_SPANS,
                                    node_or_slot: node as u32,
                                });
                            }
                        }
                    }
                }
            }
        }

        // Check 2: body ⊆ decl (spec §4.2 invariant 13). For each node where
        // both body and decl presence bits are set, body must be contained
        // within decl.
        if let (Some(decl), Some(body)) = (node_decl_spans.as_ref(), node_body_spans.as_ref()) {
            for (node, (d, b)) in decl.iter().zip(body.iter()).enumerate() {
                if let (Some(d), Some(b)) = (d, b) {
                    if b.start() < d.start() || b.end() > d.end() {
                        return Err(GraphError::BodySpanOutsideDecl {
                            node_id: node as u32,
                        });
                    }
                }
            }
        }

        // Check 3: edge spans file-bounds. For each spanned edge kind, build
        // an EPHEMERAL edge_owner (which Vec we drop at end of inner scope)
        // and validate each present span fits within its from-node's file.
        // SpanView::build (Task 17) re-runs this work when explicitly invoked;
        // here we discard the local Vec so view_from_bytes returns lean.
        if let Some(metadata) = source_metadata.as_ref() {
            for (k_idx, spans_opt) in edge_spans_parsed.iter().enumerate() {
                if let Some(spans) = spans_opt {
                    let m_kind = spans.len();
                    let off_section = out_offsets[k_idx]
                        .as_ref()
                        .expect("OrphanEdgeSpansSection invariant: validated earlier");
                    let mut owner: Vec<NodeId> = vec![NodeId(0); m_kind];
                    for node in 0..n {
                        let start = u32::from_le_bytes(
                            off_section.bytes[node * 4..(node + 1) * 4]
                                .try_into()
                                .unwrap(),
                        ) as usize;
                        let end = u32::from_le_bytes(
                            off_section.bytes[(node + 1) * 4..(node + 2) * 4]
                                .try_into()
                                .unwrap(),
                        ) as usize;
                        for owner_slot in owner.iter_mut().take(end).skip(start) {
                            *owner_slot = NodeId(node as u32);
                        }
                    }
                    for (slot, maybe_span) in spans.iter().enumerate() {
                        if let Some(span) = maybe_span {
                            let from = owner[slot];
                            let file = file_of[from.as_usize()]
                                .ok_or(GraphError::SpanOnOrphanNode { node_id: from.0 })?;
                            // Same completeness invariant as the node-span
                            // check above — see comment there.
                            let meta_idx = source_metadata_index[file.as_usize()];
                            assert_ne!(
                                meta_idx,
                                u32::MAX,
                                "completeness invariant: File node {} missing SOURCE_METADATA",
                                file.0
                            );
                            let content_length = metadata[meta_idx as usize].content_length;
                            if (span.start() as u64) + (span.length() as u64) > content_length {
                                return Err(GraphError::EdgeSpanOutOfBounds {
                                    edge_kind: section_kind::edge_spans((k_idx as u16) + 1),
                                    slot: slot as u32,
                                });
                            }
                        }
                    }
                    // `owner` drops at end of this scope — RAM freed before
                    // view_from_bytes returns. SpanView::build rebuilds when
                    // explicitly invoked.
                }
            }
        }

        // Task 16: build nodes_by_kind by walking node_kinds in NodeId order.
        // Each NodeId lands in exactly one sub-Vec; total bytes = 4 * N.
        let mut nodes_by_kind: [Vec<NodeId>; NodeKind::COUNT] = Default::default();
        for (i, &k) in node_kinds_vec.iter().enumerate() {
            let kind_idx = (k as usize) - 1; // NodeKind discriminants are 1-indexed
            nodes_by_kind[kind_idx].push(NodeId(i as u32));
        }

        // Real-package readiness: parse EXTERNAL_ORIGINS — u32 count, then
        // count × (u32 node_id, u8 origin). Empty map when the section is absent.
        let mut external_origins: std::collections::HashMap<u32, crate::schema::ExternalOrigin> =
            std::collections::HashMap::new();
        if let Some(slot) = external_origins_raw {
            let b = slot.bytes;
            if b.len() < 4 {
                return Err(GraphError::BufferTooShort);
            }
            let count = u32::from_le_bytes(b[0..4].try_into().unwrap()) as usize;
            let expected = 4 + count * 5;
            if b.len() != expected {
                return Err(GraphError::BufferTooShort);
            }
            // Canonical form: strictly ascending node ids, each an actual
            // External node, no duplicates.
            let mut prev: Option<u32> = None;
            for i in 0..count {
                let base = 4 + i * 5;
                let node_id = u32::from_le_bytes(b[base..base + 4].try_into().unwrap());
                if node_id as usize >= n {
                    return Err(GraphError::BufferTooShort);
                }
                if let Some(p) = prev {
                    if node_id <= p {
                        // non-ascending (covers duplicates too)
                        return Err(GraphError::ExternalOriginsInvalid);
                    }
                }
                prev = Some(node_id);
                if node_kinds_vec[node_id as usize] != NodeKind::External {
                    return Err(GraphError::ExternalOriginsInvalid);
                }
                let origin = crate::schema::ExternalOrigin::from_u8(b[base + 4])
                    .ok_or(GraphError::BufferTooShort)?;
                external_origins.insert(node_id, origin);
            }
        }

        // (Round 8) Parse EXTERNAL_PACKAGE_ORIGINS — u32 count, then
        // count × (u32 node_id, u32 StringId). Validate: ascending+distinct
        // node_ids, each an actual External node, each StringId resolves.
        let mut external_package_origins: std::collections::HashMap<u32, StringId> =
            std::collections::HashMap::new();
        if let Some(slot) = external_package_origins_raw {
            let b = slot.bytes;
            if b.len() < 4 {
                return Err(GraphError::BufferTooShort);
            }
            let count = u32::from_le_bytes(b[0..4].try_into().unwrap()) as usize;
            let expected = 4 + count * 8;
            if b.len() != expected {
                return Err(GraphError::ExternalPackageOriginsInvalid);
            }
            let arena_slot = strings_arena.as_ref().unwrap();
            let index_slot = string_index.as_ref().unwrap();
            let mut prev: Option<u32> = None;
            for i in 0..count {
                let base = 4 + i * 8;
                let node_id = u32::from_le_bytes(b[base..base + 4].try_into().unwrap());
                if node_id as usize >= n {
                    return Err(GraphError::ExternalPackageOriginsInvalid);
                }
                if let Some(p) = prev {
                    if node_id <= p {
                        return Err(GraphError::ExternalPackageOriginsInvalid);
                    }
                }
                prev = Some(node_id);
                if node_kinds_vec[node_id as usize] != NodeKind::External {
                    return Err(GraphError::ExternalPackageOriginsInvalid);
                }
                let sid = StringId::from_le_bytes(b[base + 4..base + 8].try_into().unwrap());
                resolve_string(arena_slot.bytes, index_slot.bytes, sid)
                    .map_err(|_| GraphError::ExternalPackageOriginsInvalid)?;
                external_package_origins.insert(node_id, sid);
            }
        }

        Ok(CodeGraph {
            strings_arena: strings_arena.ok_or(GraphError::MissingRequiredSection(
                section_kind::STRINGS_ARENA,
            ))?,
            string_index: string_index.ok_or(GraphError::MissingRequiredSection(
                section_kind::STRING_INDEX,
            ))?,
            nodes: nodes_slot,
            out_offsets,
            out_targets,
            in_offsets,
            in_targets,
            node_kinds: node_kinds_vec,
            node_spans_bytes,
            edge_spans_bytes,
            edge_type_only_bytes,
            edge_labels_bytes,
            edge_type_ref_position_bytes,
            call_argument_anchor_offsets_bytes,
            call_argument_anchor_entries_bytes,
            source_metadata,
            source_metadata_index,
            file_of,
            nodes_by_kind,
            external_origins,
            external_package_origins,
        })
    }

    /// Internal: bounds-check a `NodeId` against `node_count`. Panicking is the
    /// documented contract for all O(1) node queries — every public accessor
    /// that takes a `NodeId` calls this first so the bounds check happens
    /// uniformly regardless of which optional sections are present.
    #[inline]
    fn assert_node_in_range(&self, node: NodeId) {
        let n = self.node_count();
        assert!(
            node.0 < n,
            "Repotoire: NodeId {} out of range (node_count = {})",
            node.0,
            n
        );
    }

    /// Internal: bounds-check an OUT slot against `out_edge_count(kind)`.
    /// A kind with no adjacency in this graph has count 0, so every slot is
    /// out of range — the assertion catches "you tried to address an edge of
    /// a kind the graph doesn't contain" the same as "slot past the end."
    #[inline]
    fn assert_out_slot_in_range(&self, kind: EdgeKind, slot: u32) {
        let count = self.out_edge_count(kind) as u32;
        assert!(
            slot < count,
            "Repotoire: OUT slot {} out of range for edge kind {:?} (count = {})",
            slot,
            kind,
            count
        );
    }

    /// Returns the name span for a node, if NODE_SPANS is present AND the
    /// per-row presence bit is set.
    ///
    /// **Panics** on out-of-range `NodeId` regardless of whether NODE_SPANS
    /// is present — programmer error per the documented query contract.
    pub fn node_name_span(&self, id: NodeId) -> Option<Span> {
        self.assert_node_in_range(id);
        self.decode_node_span(id, 0)
    }

    /// O(1) lazy decode of one node span from `node_spans_bytes`. `sub` selects
    /// the span kind (0=name, 1=decl, 2=body). Layout (validated at load): 24*N
    /// bytes of (start:u32, length:u32) triples, then 3 presence bitsets of
    /// ceil(N/8) bytes (name, decl, body). Returns None if the section is
    /// absent or the presence bit is unset.
    fn decode_node_span(&self, id: NodeId, sub: usize) -> Option<Span> {
        let bytes = self.node_spans_bytes?;
        let n = self.node_count() as usize;
        let i = id.as_usize();
        let span_off = i * 24 + sub * 8;
        let start = u32::from_le_bytes(bytes[span_off..span_off + 4].try_into().unwrap());
        let length = u32::from_le_bytes(bytes[span_off + 4..span_off + 8].try_into().unwrap());
        let bitset_len = n.div_ceil(8);
        let bitset = &bytes[24 * n + sub * bitset_len..24 * n + (sub + 1) * bitset_len];
        let present = (bitset[i / 8] >> (i % 8)) & 1 == 1;
        present.then_some(Span::new(start, length))
    }

    /// Returns the decl span for a node, if NODE_SPANS is present AND the
    /// per-row presence bit is set.
    ///
    /// **Panics** on out-of-range `NodeId` regardless of whether NODE_SPANS
    /// is present.
    pub fn node_decl_span(&self, id: NodeId) -> Option<Span> {
        self.assert_node_in_range(id);
        self.decode_node_span(id, 1)
    }

    /// Returns the body span for a node, if NODE_SPANS is present AND the
    /// per-row presence bit is set.
    ///
    /// **Panics** on out-of-range `NodeId` regardless of whether NODE_SPANS
    /// is present.
    pub fn node_body_span(&self, id: NodeId) -> Option<Span> {
        self.assert_node_in_range(id);
        self.decode_node_span(id, 2)
    }

    /// Returns the span for an OUT-direction edge slot. `None` when
    /// `EDGE_SPANS_<kind>` is absent or the per-slot presence bit is 0.
    /// For IN-direction span queries, use `SpanView::edge_span_from_in`.
    ///
    /// **Panics** on out-of-range slot regardless of whether `EDGE_SPANS_<kind>`
    /// is present. A kind without adjacency has zero slots — any call panics.
    pub fn edge_span(&self, kind: EdgeKind, out_slot: u32) -> Option<Span> {
        self.assert_out_slot_in_range(kind, out_slot);
        self.decode_edge_span(kind, out_slot)
    }

    /// O(1) lazy decode of one edge span from `edge_spans_bytes`. Layout
    /// (validated transiently at load): `8 * m_kind` bytes of (start:u32,
    /// length:u32) per slot, then a `ceil(m_kind / 8)`-byte presence bitset.
    /// `m_kind` is recovered from `out_edge_count(kind)`. Returns None if the
    /// section is absent or the per-slot presence bit is unset. Does NOT
    /// bounds-check `out_slot` — callers panic via `assert_out_slot_in_range`.
    fn decode_edge_span(&self, kind: EdgeKind, out_slot: u32) -> Option<Span> {
        let k = (kind as usize) - 1;
        let bytes = self.edge_spans_bytes[k]?;
        let i = out_slot as usize;
        let m_kind = self.out_edge_count(kind);
        let off = i * 8;
        let start = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let length = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap());
        let bitset = &bytes[8 * m_kind..];
        let present = (bitset[i / 8] >> (i % 8)) & 1 == 1;
        present.then_some(Span::new(start, length))
    }

    /// O(1) lazy decode of one edge's type-only bit from `edge_type_only_bytes`.
    /// Returns false when the section is absent or the per-slot bit is 0. Does
    /// NOT bounds-check `out_slot` — callers panic via `assert_out_slot_in_range`.
    fn decode_edge_type_only(&self, kind: EdgeKind, out_slot: u32) -> bool {
        let k = (kind as usize) - 1;
        let Some(bytes) = self.edge_type_only_bytes[k] else {
            return false;
        };
        let i = out_slot as usize;
        (bytes[i / 8] >> (i % 8)) & 1 == 1
    }

    /// True iff the OUT-direction edge at `out_slot` of `kind` is syntactically
    /// type-only. For `Imports` this means a statement-level `import type { … }`
    /// (a per-binding `import { type X, y }` keeps a runtime side-effect import,
    /// so the module edge is NOT type-only). For `Exports` it means a type-only
    /// specifier (`export type { X }` / `export { type X }`). False when the
    /// section is absent or the bit is 0.
    ///
    /// **Panics** on out-of-range slot regardless of whether the section is
    /// present — consistent with `edge_span`. A kind without adjacency has zero
    /// slots, so any call panics.
    pub fn edge_is_type_only(&self, kind: EdgeKind, out_slot: u32) -> bool {
        self.assert_out_slot_in_range(kind, out_slot);
        self.decode_edge_type_only(kind, out_slot)
    }

    /// O(1) lazy decode of one edge's label StringId. Returns `None` when the
    /// section is absent or the per-slot presence bit is 0. Does NOT
    /// bounds-check `out_slot` — callers panic via `assert_out_slot_in_range`.
    fn decode_edge_label(&self, kind: EdgeKind, out_slot: u32) -> Option<StringId> {
        let k = (kind as usize) - 1;
        let bytes = self.edge_labels_bytes[k]?;
        let i = out_slot as usize;
        let m_kind = self.out_edge_count(kind);
        let bitset = &bytes[m_kind * 4..];
        let present = (bitset[i / 8] >> (i % 8)) & 1 == 1;
        if !present {
            return None;
        }
        let off = i * 4;
        Some(StringId::from_le_bytes(
            bytes[off..off + 4].try_into().unwrap(),
        ))
    }

    /// The persisted public-facing label for an Exports edge, if any. Set by
    /// the resolver from the parser's `ExportEntry::*.exported` field:
    /// `"default"` for default exports, the alias for `export { local as
    /// alias }`, the decl's own name for `export function foo`, etc.
    ///
    /// **Panics** on out-of-range slot (consistent with `edge_span` /
    /// `edge_is_type_only`).
    pub fn edge_label(&self, kind: EdgeKind, out_slot: u32) -> Option<StringId> {
        self.assert_out_slot_in_range(kind, out_slot);
        self.decode_edge_label(kind, out_slot)
    }

    /// `edge_label` resolved through the string interner. Returns `None` when
    /// the label is absent. **Panics** on out-of-range slot.
    pub fn edge_label_str(&self, kind: EdgeKind, out_slot: u32) -> Option<&'a str> {
        let sid = self.edge_label(kind, out_slot)?;
        resolve_string(self.strings_arena.bytes, self.string_index.bytes, sid).ok()
    }

    /// O(1) lazy decode of one `TypeRef` edge's parse-time position
    /// discriminant (G1.5 Fix 2 §3.2/2b). Returns `None` when
    /// `EDGE_TYPE_REF_POSITION_TypeRef` is absent or the per-slot presence bit
    /// is 0. Not generic over `kind` — `TypeRefPosition` is only ever recorded
    /// on `TypeRef` edges (enforced at both write time, `GraphBuilder::
    /// add_edge_inner`, and load time, `view_from_bytes`), so there is no
    /// other kind this could meaningfully be called with. Does NOT
    /// bounds-check `out_slot` — the sole caller, `SpanView::
    /// type_ref_position_from_in`, only ever passes a slot produced by
    /// `in_to_out`, which is already bounds-safe by construction.
    fn decode_edge_type_ref_position(&self, out_slot: u32) -> Option<TypeRefPosition> {
        let k = (EdgeKind::TypeRef as usize) - 1;
        let bytes = self.edge_type_ref_position_bytes[k]?;
        let i = out_slot as usize;
        let m_kind = self.out_edge_count(EdgeKind::TypeRef);
        let bitset = &bytes[m_kind..];
        let present = (bitset[i / 8] >> (i % 8)) & 1 == 1;
        if !present {
            return None;
        }
        Some(TypeRefPosition::from_u8(bytes[i]).expect("validated by view_from_bytes"))
    }

    /// Returns the OUT-direction `TypeRefPosition` for a `TypeRef` edge slot.
    /// `None` when `EDGE_TYPE_REF_POSITION_TypeRef` is absent or the per-slot
    /// presence bit is 0 (G1.5 F2-4 Part B — used by graph-fragment-assembly
    /// replay to thread positions through `RuntimeEvidenceGraphAssembler`,
    /// mirroring `edge_span`/`edge_is_type_only`/`edge_label_str`).
    ///
    /// **Panics** on out-of-range slot (consistent with `edge_span`/
    /// `edge_is_type_only`). No `kind` parameter: `TypeRefPosition` is never
    /// recorded on any edge kind other than `TypeRef` (see
    /// `decode_edge_type_ref_position`), so callers must only invoke this
    /// for slots of `EdgeKind::TypeRef`.
    pub fn edge_type_ref_position(&self, out_slot: u32) -> Option<TypeRefPosition> {
        self.assert_out_slot_in_range(EdgeKind::TypeRef, out_slot);
        self.decode_edge_type_ref_position(out_slot)
    }

    /// O(k) lazy decode of one `Calls` edge's argument-interior anchors
    /// (G1.6 fork (a)), `k` = that edge's own anchor count. Empty `Vec` when
    /// the section pair is absent or the slot's own range is empty (no
    /// anchors recorded for this call) — never a distinct "no info" state,
    /// since parse-time capture is unconditional for every call (an empty
    /// result IS the answer "this call has no interior anchors", not "we
    /// don't know"). Not generic over `kind` — mirrors
    /// `decode_edge_type_ref_position`; anchors are only ever recorded on
    /// `Calls` edges (enforced at both write time, `GraphBuilder::
    /// add_edge_inner`, and load time, `view_from_bytes`).
    fn decode_call_argument_anchors(&self, out_slot: u32) -> Vec<CallArgumentAnchorView> {
        let k = (EdgeKind::Calls as usize) - 1;
        let (Some(offsets), Some(entries)) = (
            self.call_argument_anchor_offsets_bytes[k],
            self.call_argument_anchor_entries_bytes[k],
        ) else {
            return Vec::new();
        };
        let i = out_slot as usize;
        let start = u32::from_le_bytes(offsets[i * 4..i * 4 + 4].try_into().unwrap()) as usize;
        let end =
            u32::from_le_bytes(offsets[(i + 1) * 4..(i + 1) * 4 + 4].try_into().unwrap()) as usize;
        let mut out = Vec::with_capacity(end - start);
        for slot in start..end {
            let base = slot * CALL_ARGUMENT_ANCHOR_ENTRY_SIZE;
            let entry = &entries[base..base + CALL_ARGUMENT_ANCHOR_ENTRY_SIZE];
            let arg_index = u16::from_le_bytes(entry[1..3].try_into().unwrap());
            let span = Span::new(
                u32::from_le_bytes(entry[3..7].try_into().unwrap()),
                u32::from_le_bytes(entry[7..11].try_into().unwrap()),
            );
            out.push(if entry[0] == 1 {
                let name_id = StringId::from_le_bytes(entry[11..15].try_into().unwrap());
                let path_id = StringId::from_le_bytes(entry[15..19].try_into().unwrap());
                let name =
                    resolve_string(self.strings_arena.bytes, self.string_index.bytes, name_id)
                        .expect("validated by view_from_bytes")
                        .to_string();
                let path =
                    resolve_string(self.strings_arena.bytes, self.string_index.bytes, path_id)
                        .expect("validated by view_from_bytes")
                        .to_string();
                CallArgumentAnchorView::ObjectKey {
                    arg_index,
                    name,
                    span,
                    path,
                }
            } else {
                CallArgumentAnchorView::CallbackHead { arg_index, span }
            });
        }
        out
    }

    /// The argument-interior anchors recorded for a `Calls` edge (G1.6 fork
    /// (a)). **Panics** on out-of-range slot (consistent with
    /// `edge_type_ref_position`/`edge_span`).
    pub fn call_argument_anchors(&self, out_slot: u32) -> Vec<CallArgumentAnchorView> {
        self.assert_out_slot_in_range(EdgeKind::Calls, out_slot);
        self.decode_call_argument_anchors(out_slot)
    }

    /// Iterate the OUT slot indexes for `(node, kind)` in CSR-insertion order.
    /// Empty iterator if the kind has no adjacency.
    ///
    /// **Panics** on out-of-range `NodeId` regardless of whether the kind has
    /// adjacency in this graph — consistent with the other O(1) node queries.
    pub fn out_slots(&self, node: NodeId, kind: EdgeKind) -> impl Iterator<Item = u32> + '_ {
        self.assert_node_in_range(node);
        let start = self.out_offset_u32(kind, node.as_usize());
        let end = self.out_offset_u32(kind, node.as_usize() + 1);
        start..end
    }

    /// Iterate the IN slot indexes for `(node, kind)` in CSR-insertion order.
    /// Empty iterator if the kind has no adjacency.
    ///
    /// **Panics** on out-of-range `NodeId` regardless of whether the kind has
    /// adjacency in this graph.
    ///
    /// New code that only needs the resolved source/span/position for each
    /// slot should prefer `SpanView::in_edges`, which walks this same range.
    pub fn in_slots(&self, node: NodeId, kind: EdgeKind) -> impl Iterator<Item = u32> + '_ {
        self.assert_node_in_range(node);
        let start = self.in_offset_u32(kind, node.as_usize());
        let end = self.in_offset_u32(kind, node.as_usize() + 1);
        start..end
    }

    /// Read the destination NodeId for an OUT slot. Panics on out-of-range
    /// slot or kind without adjacency.
    pub fn out_target(&self, kind: EdgeKind, out_slot: u32) -> NodeId {
        NodeId(self.out_target_u32(kind, out_slot as usize))
    }

    /// Read the source NodeId for an IN slot. Panics on out-of-range slot
    /// or kind without adjacency.
    ///
    /// New code should prefer `SpanView::in_edges`'s `InEdge::source`, which
    /// reads this same value alongside the edge's span/position.
    pub fn in_source(&self, kind: EdgeKind, in_slot: u32) -> NodeId {
        NodeId(self.in_target_u32(kind, in_slot as usize))
    }

    /// O(1) lookup for per-File-node metadata.
    ///
    /// Returns `Some` only when (a) SOURCE_METADATA is present in the IR AND
    /// (b) `file` is a File node. Per spec §2.6 completeness, when the section
    /// is present every File node has an entry — non-File nodes always return
    /// `None`, and a File node never accidentally returns `None`.
    ///
    /// **Panics** on out-of-range `NodeId` regardless of whether
    /// SOURCE_METADATA is present.
    pub fn source_metadata(&self, file: NodeId) -> Option<&SourceMetadata> {
        self.assert_node_in_range(file);
        let metadata = self.source_metadata.as_ref()?;
        let idx = self.source_metadata_index[file.as_usize()];
        if idx == u32::MAX {
            return None;
        }
        metadata.get(idx as usize)
    }

    /// Returns the File ancestor of `node` via Contains-IN walk (precomputed
    /// during view_from_bytes). For File nodes, returns the node itself.
    /// Returns None for orphan nodes (no File ancestor reachable) and for
    /// nodes inside Contains cycles.
    ///
    /// **Panics** on out-of-range `NodeId` — "no File ancestor" and "the
    /// caller asked about a node that doesn't exist" are different errors
    /// and the latter is always a programmer bug.
    pub fn file_of(&self, node: NodeId) -> Option<NodeId> {
        self.assert_node_in_range(node);
        self.file_of[node.as_usize()]
    }

    // ---- Task 16: nodes_by_kind accessors ----

    /// Iterate every node of the given kind in NodeId-ascending order.
    /// O(M_kind) total — direct slice walk over only the matching nodes,
    /// no per-element kind filter.
    pub fn nodes_of_kind(&self, kind: NodeKind) -> impl Iterator<Item = NodeId> + '_ {
        self.nodes_by_kind[(kind as usize) - 1].iter().copied()
    }

    /// O(1) count of nodes of the given kind. Useful for "how many functions
    /// are in this codebase" analytics that don't need to iterate.
    pub fn nodes_of_kind_count(&self, kind: NodeKind) -> u32 {
        self.nodes_by_kind[(kind as usize) - 1].len() as u32
    }

    /// Origin tag for an External node, or `None` if `id` is not an External
    /// node (or the EXTERNAL_ORIGINS section was absent).
    pub fn external_origin(&self, id: NodeId) -> Option<crate::schema::ExternalOrigin> {
        self.external_origins.get(&id.0).copied()
    }

    /// Package-origin specifier for an External node, or `None` if the node
    /// has no recorded package_origin (ambient global, Unknown-origin, or
    /// EXTERNAL_PACKAGE_ORIGINS section absent). The returned string is the
    /// package specifier the node was created from — e.g., for
    /// `export { foo as publicFoo } from 'external-pkg'`, the External
    /// `foo` returns `Some("external-pkg")`. Resolves through the interner.
    pub fn external_package_origin(&self, id: NodeId) -> Option<&'a str> {
        let sid = self.external_package_origins.get(&id.0).copied()?;
        resolve_string(self.strings_arena.bytes, self.string_index.bytes, sid).ok()
    }

    /// Random-access slice into the per-kind NodeId list. Escape hatch for
    /// consumers that want to pass the slice to a custom algorithm or
    /// index directly (e.g., "give me the 5th Function").
    pub fn nodes_of_kind_slice(&self, kind: NodeKind) -> &[NodeId] {
        &self.nodes_by_kind[(kind as usize) - 1]
    }

    // ---- Task 17: typed adjacency accessors (consumed by SpanView::build) ----
    //
    // Crate-private — these decode u32 LE values from the raw byte
    // ResolvedSection storage. They're infrastructure for SpanView's
    // edge_owner + in_to_out construction in this task, and for Task 18's
    // public query methods (out_slots / in_slots / out_target / in_source).

    /// Read offset at slot `i` from OUT_OFFSETS_<kind>. Returns 0 if the kind
    /// has no adjacency in this graph (callers should check `has_adjacency`
    /// when 0 isn't a valid sentinel for their use case).
    pub(crate) fn out_offset_u32(&self, kind: EdgeKind, i: usize) -> u32 {
        let k = (kind as usize) - 1;
        match &self.out_offsets[k] {
            Some(s) => u32::from_le_bytes(s.bytes[i * 4..(i + 1) * 4].try_into().unwrap()),
            None => 0,
        }
    }
    /// Read target NodeId u32 at slot `slot` from OUT_TARGETS_<kind>. Panics
    /// if the kind has no adjacency (programmer error — callers should check
    /// `has_adjacency` first).
    pub(crate) fn out_target_u32(&self, kind: EdgeKind, slot: usize) -> u32 {
        let k = (kind as usize) - 1;
        let s = self.out_targets[k]
            .as_ref()
            .expect("kind has no out adjacency");
        u32::from_le_bytes(s.bytes[slot * 4..(slot + 1) * 4].try_into().unwrap())
    }
    pub(crate) fn in_offset_u32(&self, kind: EdgeKind, i: usize) -> u32 {
        let k = (kind as usize) - 1;
        match &self.in_offsets[k] {
            Some(s) => u32::from_le_bytes(s.bytes[i * 4..(i + 1) * 4].try_into().unwrap()),
            None => 0,
        }
    }
    pub(crate) fn in_target_u32(&self, kind: EdgeKind, slot: usize) -> u32 {
        let k = (kind as usize) - 1;
        let s = self.in_targets[k]
            .as_ref()
            .expect("kind has no in adjacency");
        u32::from_le_bytes(s.bytes[slot * 4..(slot + 1) * 4].try_into().unwrap())
    }
    /// Number of out-edges of `kind` = OUT_TARGETS_<kind>.len() / 4.
    pub(crate) fn out_edge_count(&self, kind: EdgeKind) -> usize {
        let k = (kind as usize) - 1;
        self.out_targets[k]
            .as_ref()
            .map(|s| s.bytes.len() / 4)
            .unwrap_or(0)
    }
    // (in_edge_count was originally planned alongside out_edge_count, but no
    // consumer needs it — SpanView's IN walk uses in_offset_u32 for bounds,
    // and Task 18's in_slots will too. Add it if a future consumer materializes.)
    /// Does this graph have any adjacency for the given edge kind? (Checks
    /// OUT_TARGETS_<kind> — the orphan-section invariant from Task 13's
    /// view_from_bytes guarantees OUT_TARGETS and OUT_OFFSETS appear together.)
    pub(crate) fn has_adjacency(&self, kind: EdgeKind) -> bool {
        let k = (kind as usize) - 1;
        self.out_targets[k].is_some()
    }

    /// **Panics** on out-of-range `NodeId` regardless of whether the kind has
    /// adjacency in this graph — consistent with `out_slots` and the other O(1)
    /// node queries. An empty iterator means "no edges of this kind," never
    /// "node doesn't exist."
    pub fn outgoing(&self, node: NodeId, kind: EdgeKind) -> AdjacencyIter<'a> {
        self.assert_node_in_range(node);
        adjacency_iter(
            node,
            self.out_offsets[(kind as usize) - 1].as_ref(),
            self.out_targets[(kind as usize) - 1].as_ref(),
        )
    }

    /// **Panics** on out-of-range `NodeId` regardless of whether the kind has
    /// adjacency in this graph — consistent with `in_slots`.
    pub fn incoming(&self, node: NodeId, kind: EdgeKind) -> AdjacencyIter<'a> {
        self.assert_node_in_range(node);
        adjacency_iter(
            node,
            self.in_offsets[(kind as usize) - 1].as_ref(),
            self.in_targets[(kind as usize) - 1].as_ref(),
        )
    }

    pub fn node_count(&self) -> u32 {
        u32::try_from(self.nodes.bytes.len() / NODE_ROW_SIZE)
            .expect("Repotoire v0 format limit: node count must fit in u32")
    }

    fn node_row(&self, node: NodeId) -> (u16, u16, StringId) {
        let base = node.as_usize() * NODE_ROW_SIZE;
        let row = &self.nodes.bytes[base..base + NODE_ROW_SIZE];
        let kind = u16::from_le_bytes(row[0..2].try_into().unwrap());
        let expected = u16::from_le_bytes(row[2..4].try_into().unwrap());
        let name = StringId::from_le_bytes(row[4..8].try_into().unwrap());
        (kind, expected, name)
    }

    pub fn node_kind(&self, node: NodeId) -> NodeKind {
        // Direct array lookup from self.node_kinds (populated + validated
        // during view_from_bytes). Faster than re-decoding the NODES byte
        // row + u16 -> NodeKind conversion on every call.
        self.node_kinds[node.as_usize()]
    }

    pub fn node_name(&self, node: NodeId) -> &'a str {
        let (_, _, name_id) = self.node_row(node);
        resolve_string(self.strings_arena.bytes, self.string_index.bytes, name_id)
            .expect("validated by view_from_bytes")
    }

    pub fn node_expected_kind(&self, node: NodeId) -> Option<NodeKind> {
        let (kind, expected, _) = self.node_row(node);
        if kind != NodeKind::Unresolved as u16 {
            return None;
        }
        NodeKind::from_u16(expected)
    }
}

// ---- Task 17: SpanView ----

/// Opt-in wrapper over `&CodeGraph<'a>` that adds derived indexes for
/// span-direction queries (`edge_owner`, `in_to_out`, `edge_span_from_in`).
///
/// **Why this is separate from `CodeGraph`:** `edge_owner` + `in_to_out`
/// together cost ~8 MB for a 1M-edge graph. The AI-compiler hot path (graph
/// traversal + verification) does NOT need them — they're only used by
/// diagnostic emitters that ask "for this Unresolved node's incoming Imports
/// edges, what spans do they have?" Bundling them onto `CodeGraph` would tax
/// the hot path 8 MB of RAM it never uses.
///
/// The indexes are built **per adjacency-bearing kind**, not per spanned kind.
/// This is the load-bearing fix from spec brainstorm round 1: the demo's
/// graceful-degradation path needs `in_to_out` to work even when
/// `EDGE_SPANS_<kind>` is absent (so it can emit `"no span available"`
/// diagnostics without panicking). `edge_span_from_in` returns `None` when
/// spans are absent; `in_to_out` itself works as long as the adjacency exists.
pub struct SpanView<'a> {
    graph: &'a CodeGraph<'a>,
    /// `edge_owner[k][slot]` = from-node for OUT slot `slot` of edge kind
    /// discriminant `k + 1`. `None` for kinds with no adjacency.
    edge_owner: [Option<Vec<NodeId>>; EdgeKind::COUNT],
    /// `in_to_out[k][in_slot]` = corresponding OUT slot index. Maps the k-th
    /// IN-occurrence of `(from, to)` to the k-th OUT-occurrence (insertion-
    /// order matching guaranteed by the v0 builder + spec §3.3).
    in_to_out: [Option<Vec<u32>>; EdgeKind::COUNT],
}

impl<'a> SpanView<'a> {
    /// Build a SpanView indexing ALL adjacency-bearing edge kinds.
    ///
    /// **Cost:** `O(M log M)` time per kind (M = that kind's edge count) — the
    /// IN↔OUT match stable-sorts two `(u64, u32)` key lists. **Retained** memory
    /// is `edge_owner` (4 B/edge) + `in_to_out` (4 B/edge) ≈ 8 B/edge (~8 MB for
    /// 1M edges). **Transient** build memory peaks higher: the two sort buffers
    /// are 12 B/edge each (~24 MB/1M edges for the largest kind), freed before
    /// `build` returns. Build once, reuse across many queries. Callers that
    /// query only one or two kinds (e.g. a phantom-import reporter needs only
    /// `Imports`) should prefer `build_for` to skip large `Calls`/refs tables.
    pub fn build(graph: &'a CodeGraph<'a>) -> Self {
        Self::build_for(graph, &EdgeKind::ALL)
    }

    /// True if `kind` was indexed in this view (built and adjacency-bearing).
    /// `edge_owner`/`in_to_out` panic for un-indexed kinds.
    pub fn has_kind(&self, kind: EdgeKind) -> bool {
        self.edge_owner[(kind as usize) - 1].is_some()
    }

    /// Build a SpanView indexing ONLY the requested edge kinds. Kinds not in
    /// `kinds` (or absent from the graph) are left unindexed — `has_kind`
    /// returns false and the span-direction queries panic for them. Lets a
    /// caller avoid building large tables it never queries.
    pub fn build_for(graph: &'a CodeGraph<'a>, kinds: &[EdgeKind]) -> Self {
        Self::build_for_until(graph, kinds, || Ok::<(), std::convert::Infallible>(()))
            .expect("the explicit no-deadline check cannot fail")
    }

    /// Build the requested indexes while observing the caller's stop token.
    ///
    /// The callback is invoked inside each graph-sized loop and around the
    /// stable sorts. It owns no thread or clock, so callers keep one deadline
    /// policy while this derived index remains cooperatively interruptible.
    pub fn build_for_until<E, F>(
        graph: &'a CodeGraph<'a>,
        kinds: &[EdgeKind],
        mut check: F,
    ) -> Result<Self, E>
    where
        F: FnMut() -> Result<(), E>,
    {
        let mut edge_owner: [Option<Vec<NodeId>>; EdgeKind::COUNT] = Default::default();
        let mut in_to_out: [Option<Vec<u32>>; EdgeKind::COUNT] = Default::default();

        let n = graph.node_count() as usize;

        for &edge_kind in kinds {
            check()?;
            let k = (edge_kind as usize) - 1;
            if !graph.has_adjacency(edge_kind) {
                // Real control flow: kinds with no edges get no derived
                // indexes built. NOT a defensive skip.
                continue;
            }
            let m_kind = graph.out_edge_count(edge_kind);

            // edge_owner: walk OUT_OFFSETS_<kind>. For each from-node, every
            // slot in its [start, end) range is owned by that node.
            let mut owner = vec![NodeId(0); m_kind];
            for node in 0..n {
                check()?;
                let start = graph.out_offset_u32(edge_kind, node) as usize;
                let end = graph.out_offset_u32(edge_kind, node + 1) as usize;
                for owner_slot in owner.iter_mut().take(end).skip(start) {
                    *owner_slot = NodeId(node as u32);
                }
            }

            // in_to_out via flat occurrence-order matching (no per-pair
            // allocation — owner-attribution multiplies unique (from,to) pairs,
            // which the old HashMap<(u32,u32),VecDeque> punished with a queue per
            // pair). Build two flat lists keyed by (from<<32)|to and STABLY sort:
            // stable sort preserves slot order = occurrence order within a group,
            // so the k-th IN matches the k-th OUT. Same pattern as
            // validate_adjacency_mirror; transient memory is ~16*M_kind bytes.
            let key = |from: u32, to: u32| ((from as u64) << 32) | (to as u64);
            let mut in_keyed: Vec<(u64, u32)> = Vec::with_capacity(m_kind);
            for to in 0..n {
                check()?;
                let start = graph.in_offset_u32(edge_kind, to) as usize;
                let end = graph.in_offset_u32(edge_kind, to + 1) as usize;
                for slot in start..end {
                    let from = graph.in_target_u32(edge_kind, slot);
                    in_keyed.push((key(from, to as u32), slot as u32));
                }
            }
            let mut out_keyed: Vec<(u64, u32)> = Vec::with_capacity(m_kind);
            for (out_slot, owner_node) in owner.iter().enumerate() {
                check()?;
                let to = graph.out_target_u32(edge_kind, out_slot);
                out_keyed.push((key(owner_node.0, to), out_slot as u32));
            }
            check()?;
            in_keyed.sort_by_key(|(k, _)| *k);
            out_keyed.sort_by_key(|(k, _)| *k);
            check()?;
            debug_assert_eq!(
                in_keyed.len(),
                out_keyed.len(),
                "OUT/IN mirror invariant: equal edge counts"
            );
            let mut mapping = vec![0u32; m_kind];
            for ((ik, in_slot), (ok, out_slot)) in in_keyed.iter().zip(out_keyed.iter()) {
                check()?;
                debug_assert_eq!(
                    ik, ok,
                    "OUT/IN mirror mismatch — view_from_bytes should have caught this"
                );
                mapping[*in_slot as usize] = *out_slot;
            }

            edge_owner[k] = Some(owner);
            in_to_out[k] = Some(mapping);
        }

        check()?;
        Ok(Self {
            graph,
            edge_owner,
            in_to_out,
        })
    }

    /// Borrow the underlying graph for non-span queries.
    pub fn graph(&self) -> &CodeGraph<'a> {
        self.graph
    }

    /// Returns the from-node owning the given OUT slot. Panics if the kind
    /// has no adjacency in this graph (programmer error — kinds without
    /// adjacency have no slots to address), or if the slot is out of range.
    pub fn edge_owner(&self, kind: EdgeKind, out_slot: u32) -> NodeId {
        let k = (kind as usize) - 1;
        let owner = self.edge_owner[k]
            .as_ref()
            .expect("Repotoire: kind has no adjacency in this graph");
        owner[out_slot as usize]
    }

    /// Maps an IN slot to the corresponding OUT slot via the occurrence-order
    /// invariant. Panics on out-of-range slot or kind without adjacency.
    /// Does NOT panic when `EDGE_SPANS_<kind>` is absent — the mapping is built
    /// from adjacency, not from spans.
    pub fn in_to_out(&self, kind: EdgeKind, in_slot: u32) -> u32 {
        let k = (kind as usize) - 1;
        let mapping = self.in_to_out[k]
            .as_ref()
            .expect("Repotoire: kind has no adjacency in this graph");
        mapping[in_slot as usize]
    }

    /// Span-direction convenience: given an IN slot, look up the corresponding
    /// OUT slot then read its span (or None if `EDGE_SPANS_<kind>` is absent).
    ///
    /// New code should prefer `SpanView::in_edges`'s `InEdge::span`, which
    /// reads this same value alongside the edge's source/position.
    pub fn edge_span_from_in(&self, kind: EdgeKind, in_slot: u32) -> Option<Span> {
        let out_slot = self.in_to_out(kind, in_slot);
        self.graph.decode_edge_span(kind, out_slot)
    }

    /// Position-direction convenience (G1.5 Fix 2 §3.2/2b): given an IN slot
    /// on the `TypeRef` edge kind, look up the corresponding OUT slot via the
    /// same occurrence-order mapping `edge_span_from_in` uses, then read its
    /// parse-time `TypeRefPosition` (or `None` if
    /// `EDGE_TYPE_REF_POSITION_TypeRef` is absent or the per-slot presence bit
    /// is unset). TypeRef-only and NOT generic over `kind` — unlike
    /// `edge_span_from_in`, which is meaningful for every edge kind,
    /// `TypeRefPosition` is only ever recorded on `TypeRef` edges, so a `kind`
    /// parameter would just be dead weight callers could get wrong.
    ///
    /// **Panics** if `TypeRef` has no adjacency in this graph (consistent with
    /// `in_to_out`/`edge_span_from_in` — a kind without adjacency has no IN
    /// slots to address).
    ///
    /// New code should prefer `SpanView::in_edges`'s `InEdge::position`,
    /// which reads this same value alongside the edge's source/span.
    pub fn type_ref_position_from_in(&self, in_slot: u32) -> Option<TypeRefPosition> {
        let out_slot = self.in_to_out(EdgeKind::TypeRef, in_slot);
        self.graph.decode_edge_type_ref_position(out_slot)
    }

    /// Argument-anchor-direction convenience (G1.6 fork (a)): given an IN
    /// slot on the `Calls` edge kind, look up the corresponding OUT slot via
    /// the same occurrence-order mapping `edge_span_from_in`/
    /// `type_ref_position_from_in` use, then read its recorded
    /// argument-interior anchors (empty `Vec` if none were recorded, or if
    /// the section pair is absent). `Calls`-only and NOT generic over `kind`
    /// for the same reason `type_ref_position_from_in` isn't — anchors are
    /// never recorded on any other edge kind.
    ///
    /// Complements `in_edges` rather than replacing it: W1 (the G1.6
    /// consumer-call-site walk) is expected to iterate
    /// `in_edges(callable, EdgeKind::Calls)` for the per-edge
    /// source/span triple, and separately call this per-slot lookup (zipped
    /// against the same `in_slots(callable, EdgeKind::Calls)` range) for the
    /// anchors — a variable-length auxiliary payload deliberately kept off
    /// the fixed-shape `InEdge`.
    ///
    /// **Panics** if `Calls` has no adjacency in this graph (consistent with
    /// `in_to_out`/`edge_span_from_in`).
    pub fn call_argument_anchors_from_in(&self, in_slot: u32) -> Vec<CallArgumentAnchorView> {
        let out_slot = self.in_to_out(EdgeKind::Calls, in_slot);
        self.graph.decode_call_argument_anchors(out_slot)
    }

    /// Deep in-edge interface (PR-B of the impact collector seam design,
    /// `docs/superpowers/specs/2026-07-06-impact-collector-seam-design.md`,
    /// decision 2): one `InEdge` per IN slot of `(node, kind)`, in slot
    /// (insertion) order — the same order `in_slots`/`in_source` walk.
    /// Collapses the `in_slots` → `in_source` → `edge_span_from_in` →
    /// `type_ref_position_from_in` chain every impact-ring collector used to
    /// re-derive by hand into a single iteration. `position` is populated
    /// only for `kind == EdgeKind::TypeRef` (`None` for every other kind,
    /// unconditionally — `TypeRefPosition` is never recorded on non-TypeRef
    /// edges). Callers that also need the OUT slot (e.g. to read an edge
    /// label via `edge_label_str`) still get it from `in_to_out(kind, slot)`
    /// against the same `in_slots(node, kind)` range — `InEdge` does not
    /// carry the slot index itself, only the derived `source`/`span`/
    /// `position` triple.
    ///
    /// **Panics** if `kind` has no adjacency in this graph (consistent with
    /// `in_slots`/`in_to_out` — a kind without adjacency has no IN slots to
    /// address).
    pub fn in_edges(&self, node: NodeId, kind: EdgeKind) -> impl Iterator<Item = InEdge> + '_ {
        self.graph.in_slots(node, kind).map(move |slot| {
            let source = self.graph.in_source(kind, slot);
            let span = self.edge_span_from_in(kind, slot);
            let position = if kind == EdgeKind::TypeRef {
                self.type_ref_position_from_in(slot)
            } else {
                None
            };
            InEdge {
                source,
                span,
                position,
            }
        })
    }
}

/// One IN-direction edge, as yielded by `SpanView::in_edges`. `position` is
/// `None` both when the source graph never recorded one (parser didn't emit
/// it, or the section is entirely absent) AND, unconditionally, for every
/// non-`TypeRef` kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InEdge {
    pub source: NodeId,
    pub span: Option<Span>,
    /// Always `None` for non-`TypeRef` kinds. For `TypeRef` edges, `None`
    /// means "no position was recorded" — distinct from
    /// `Some(TypeRefPosition::Other)`. Use `position_or_fail_open()` to
    /// collapse that distinction; match on this field directly when "no
    /// information" must stay distinguishable from `Other` (e.g. G1.6's
    /// consumer-call-site walk).
    pub position: Option<TypeRefPosition>,
}

impl InEdge {
    /// Fail-open accessor for `position` (moved here from the G1.5 Fix 2
    /// (F2-3) call site in `impact/compiler_pressure.rs`'s
    /// `collect_compiler_pressure`, which used to inline
    /// `.unwrap_or(TypeRefPosition::Other)` at the point of use). This is now
    /// the ONE place that policy lives: when no `TypeRefPosition` was
    /// recorded for this edge — the parser didn't emit one, or the
    /// `EDGE_TYPE_REF_POSITION_TypeRef` section is absent entirely — treat it
    /// as `TypeRefPosition::Other`, the same fail-open bucket used for shapes
    /// the parser integration hasn't been taught to distinguish yet. Callers
    /// must treat `Other` (recorded or defaulted) as "no signal," never as a
    /// positive classification on its own.
    ///
    /// Do NOT use this when "no information" needs to stay distinguishable
    /// from a recorded `Other` — match on the raw `position` field instead
    /// (this is why `in_edges`/`InEdge` keep the `Option` visible rather than
    /// fail-opening inside the iterator itself).
    pub fn position_or_fail_open(&self) -> TypeRefPosition {
        self.position.unwrap_or(TypeRefPosition::Other)
    }
}

/// Validate one (offsets, targets) pair for a single edge kind and direction.
/// Enforces: both-or-neither presence, offsets length == (n+1)*4, monotonic offsets,
/// and final offset == target count (in u32 entries).
/// Verify the OUT and IN adjacency sections for one edge kind describe the
/// same `(from, to)` multiset.
///
/// `validate_adjacency_pair` checks each direction is *internally* consistent
/// (offsets monotone, target_count matches offsets[n]), but says nothing
/// about whether OUT and IN agree on which edges exist. `SpanView::build`
/// (and any future consumer that pairs OUT slots with IN slots) relies on
/// that mirror invariant — without this check, a hand-crafted IR can satisfy
/// `validate_adjacency_pair` and still panic later when the mapping is built.
///
/// Cost: O(M_kind log M_kind) per kind via two `Vec<u64>` sorts. Memory is
/// transient (released before the next kind), peaking at `16 * M_kind` bytes
/// for the largest kind.
///
/// Callers must have already run `validate_adjacency_pair` on both sides so
/// offsets are known to be well-formed (length, monotonicity, target-count
/// match) — this function reads them without re-validating.
fn validate_adjacency_mirror(
    n: usize,
    out_offsets: Option<&ResolvedSection<'_>>,
    out_targets: Option<&ResolvedSection<'_>>,
    in_offsets: Option<&ResolvedSection<'_>>,
    in_targets: Option<&ResolvedSection<'_>>,
    edge_kind: u16,
) -> Result<(), GraphError> {
    // `validate_adjacency_pair` enforces symmetry *within* each direction
    // (OUT_OFFSETS present iff OUT_TARGETS present; same for IN). It does
    // NOT enforce symmetry *across* directions. So by the time we reach
    // this function the only legal states are:
    //   - all four sections absent → kind unused, nothing to mirror
    //   - all four sections present → compare multisets below
    //   - exactly one direction's pair present → structural corruption
    //     (e.g., OUT-only adjacency that SpanView::build can't pair with IN
    //     slots). Reject.
    let (out_off, out_tgt, in_off, in_tgt) =
        match (out_offsets, out_targets, in_offsets, in_targets) {
            (None, None, None, None) => return Ok(()),
            (Some(oo), Some(ot), Some(io), Some(it)) => (oo, ot, io, it),
            _ => return Err(GraphError::AdjacencyMirrorMismatch { edge_kind }),
        };

    // Both sides report the same edge count, otherwise the sorted vecs will
    // differ in length and the final slice equality fails. We do the cheap
    // check first to short-circuit on the common mismatch.
    let m_out = out_tgt.bytes.len() / 4;
    let m_in = in_tgt.bytes.len() / 4;
    if m_out != m_in {
        return Err(GraphError::AdjacencyMirrorMismatch { edge_kind });
    }

    // Pack each (from, to) as u64 = (from << 32) | to so we can sort with a
    // single primitive comparator. Both vecs are released at function exit.
    let mut out_pairs: Vec<u64> = Vec::with_capacity(m_out);
    for from in 0..n {
        let slice_start =
            u32::from_le_bytes(out_off.bytes[from * 4..from * 4 + 4].try_into().unwrap()) as usize;
        let slice_end = u32::from_le_bytes(
            out_off.bytes[(from + 1) * 4..(from + 1) * 4 + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        for slot in slice_start..slice_end {
            let to = u32::from_le_bytes(out_tgt.bytes[slot * 4..slot * 4 + 4].try_into().unwrap());
            out_pairs.push(((from as u64) << 32) | (to as u64));
        }
    }

    let mut in_pairs: Vec<u64> = Vec::with_capacity(m_in);
    for to in 0..n {
        let slice_start =
            u32::from_le_bytes(in_off.bytes[to * 4..to * 4 + 4].try_into().unwrap()) as usize;
        let slice_end = u32::from_le_bytes(
            in_off.bytes[(to + 1) * 4..(to + 1) * 4 + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        for slot in slice_start..slice_end {
            let from = u32::from_le_bytes(in_tgt.bytes[slot * 4..slot * 4 + 4].try_into().unwrap());
            in_pairs.push(((from as u64) << 32) | (to as u64));
        }
    }

    out_pairs.sort_unstable();
    in_pairs.sort_unstable();
    if out_pairs != in_pairs {
        return Err(GraphError::AdjacencyMirrorMismatch { edge_kind });
    }
    Ok(())
}

fn validate_adjacency_pair(
    n: usize,
    offsets: Option<&ResolvedSection<'_>>,
    targets: Option<&ResolvedSection<'_>>,
    offsets_kind: u16,
    targets_kind: u16,
) -> Result<(), GraphError> {
    match (offsets, targets) {
        (None, None) => Ok(()),
        (Some(_), None) => Err(GraphError::OrphanAdjacencySection(offsets_kind)),
        (None, Some(_)) => Err(GraphError::OrphanAdjacencySection(targets_kind)),
        (Some(off), Some(tgt)) => {
            let expected_len = (n + 1) * 4;
            if off.bytes.len() != expected_len {
                return Err(GraphError::AdjacencyOffsetsWrongLength(offsets_kind));
            }
            let mut prev: u32 = 0;
            for i in 0..=n {
                let cur = u32::from_le_bytes(off.bytes[i * 4..i * 4 + 4].try_into().unwrap());
                if i == 0 && cur != 0 {
                    // First entry must be 0; a non-zero start makes the first
                    // `cur` targets unreachable from any node's slice.
                    return Err(GraphError::AdjacencyOffsetsMustStartAtZero(offsets_kind));
                }
                if i > 0 && cur < prev {
                    return Err(GraphError::AdjacencyOffsetsNonMonotonic);
                }
                prev = cur;
            }
            // `prev` is now offsets[n] = total edges declared.
            // tgt.bytes.len() is a multiple of 4 (alignment was checked at section parse time).
            let target_count = tgt.bytes.len() / 4;
            if prev as usize != target_count {
                return Err(GraphError::AdjacencyOffsetsTargetMismatch(offsets_kind));
            }
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    BadMagic,
    BadVersion(u32),
    BadEndian,
    HeaderTooShort,
    SectionTableOOB,
    DuplicateSection(u16),
    MissingRequiredSection(u16),
    NodesSectionMisaligned,
    StringIndexMisaligned,
    StringIndexOutOfBounds,
    StringArenaOutOfBounds,
    Utf8Error,
    AdjacencyOffsetsMisaligned,
    AdjacencyOffsetsNonMonotonic,
    AdjacencyOffsetsMustStartAtZero(u16),
    AdjacencyOffsetsWrongLength(u16),
    AdjacencyOffsetsTargetMismatch(u16),
    OrphanAdjacencySection(u16),
    /// OUT and IN adjacency for `edge_kind` describe different `(from, to)`
    /// multisets. The view validator catches this so downstream consumers
    /// (notably `SpanView::build`) can rely on the OUT-IN mirror invariant.
    AdjacencyMirrorMismatch {
        edge_kind: u16,
    },
    AdjacencyTargetsMisaligned,
    NodeIdOutOfBounds,
    InvalidNodeKindDiscriminant(u16),
    InvalidEdgeKindDiscriminant(u16),
    BufferTooShort,
    /// EXTERNAL_ORIGINS section references a non-External node, repeats a
    /// node id, or is not in ascending node-id order (canonical form).
    ExternalOriginsInvalid,
    /// EXTERNAL_PACKAGE_ORIGINS section is malformed: wrong length, OOB
    /// node id, non-External target, non-ascending order, duplicate, or
    /// StringId that does not resolve.
    ExternalPackageOriginsInvalid,

    // ---- Spans milestone (Task 5) ----
    // Span format invariants (apply to NODE_NAME_SPANS, NODE_DECL_SPANS,
    // NODE_BODY_SPANS, and EDGE_SPANS_<kind>):
    SpanSectionMalformed {
        kind: u16,
    },
    NonCanonicalPresenceBitset {
        kind: u16,
    },
    NonCanonicalAbsentSpan {
        kind: u16,
        slot: u32,
    },
    SpanOverflow {
        kind: u16,
        slot: u32,
    },
    OrphanEdgeSpansSection {
        edge_kind: u16,
    },

    // ---- type-only marker milestone ----
    TypeOnlySectionMalformed {
        edge_kind: u16,
    },
    OrphanTypeOnlySection {
        edge_kind: u16,
    },
    /// `EDGE_TYPE_ONLY_<kind>` present for a kind other than Imports/Exports —
    /// no other edge kind carries a syntactic type modifier (format invariant).
    TypeOnlySectionOnUnsupportedKind {
        edge_kind: u16,
    },

    // ---- edge label milestone ----
    LabelSectionMalformed {
        edge_kind: u16,
    },
    OrphanLabelSection {
        edge_kind: u16,
    },
    /// `EDGE_LABEL_<kind>` present for a kind other than Exports — in v1, only
    /// Exports edges carry parser-supplied public labels (format invariant).
    LabelSectionOnUnsupportedKind {
        edge_kind: u16,
    },
    /// A StringId in an `EDGE_LABEL_<kind>` payload doesn't resolve in the
    /// STRING_INDEX — file corruption or builder bug.
    LabelStringIdOutOfBounds {
        edge_kind: u16,
        string_id: u32,
    },

    // ---- TypeRef position milestone (G1.5 Fix 2 §3.2/2b) ----
    TypeRefPositionSectionMalformed {
        edge_kind: u16,
    },
    OrphanTypeRefPositionSection {
        edge_kind: u16,
    },
    /// `EDGE_TYPE_REF_POSITION_<kind>` present for a kind other than
    /// `TypeRef` — no other edge kind carries a parse-time type-position
    /// discriminant (format invariant).
    TypeRefPositionSectionOnUnsupportedKind {
        edge_kind: u16,
    },
    /// A present slot's byte doesn't decode via `TypeRefPosition::from_u8` —
    /// file corruption or a forward-incompatible writer.
    TypeRefPositionInvalidDiscriminant {
        edge_kind: u16,
        slot: u32,
        value: u8,
    },

    // ---- Call-argument interior-anchor milestone (G1.6 fork (a)) ----
    /// `CALL_ARGUMENT_ANCHOR_OFFSETS_<kind>`/`_ENTRIES_<kind>` malformed:
    /// wrong length, non-monotonic/non-zero-started offsets, an entries
    /// section whose length doesn't match the offsets' total, or an
    /// ObjectKey entry whose name/path StringId doesn't resolve.
    CallArgumentAnchorSectionMalformed {
        edge_kind: u16,
    },
    /// The offsets/entries pair is present but its paired OUT_TARGETS/
    /// OUT_OFFSETS adjacency section (needed to know `M_kind`) is absent.
    OrphanCallArgumentAnchorSection {
        edge_kind: u16,
    },
    /// `CALL_ARGUMENT_ANCHOR_OFFSETS_<kind>`/`_ENTRIES_<kind>` present for a
    /// kind other than `Calls` — no other edge kind carries argument
    /// anchors (format invariant).
    CallArgumentAnchorSectionOnUnsupportedKind {
        edge_kind: u16,
    },
    /// A present entry's kind byte is neither 0 (CallbackHead) nor 1
    /// (ObjectKey) — file corruption or a forward-incompatible writer.
    CallArgumentAnchorInvalidDiscriminant {
        edge_kind: u16,
        slot: u32,
        value: u8,
    },

    // SOURCE_METADATA format invariants:
    SourceMetadataMalformed,
    NonCanonicalSourceMetadata,
    SourceMetadataNotSorted,
    SourceMetadataPointsAtNonFile {
        node_id: u32,
    },
    SourceMetadataIncomplete {
        expected: u32,
        actual: u32,
    },

    // Cross-section invariants (when SOURCE_METADATA + spans both present):
    SpanOnOrphanNode {
        node_id: u32,
    },
    SpanOutOfBounds {
        section_kind: u16,
        node_or_slot: u32,
    },
    EdgeSpanOutOfBounds {
        edge_kind: u16,
        slot: u32,
    },
    BodySpanOutsideDecl {
        node_id: u32,
    },
}

impl std::fmt::Display for GraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GraphError::BadMagic => write!(f, "Invalid magic number in graph file"),
            GraphError::BadVersion(v) => write!(f, "Unsupported graph version: {}", v),
            GraphError::BadEndian => write!(f, "Graph file has wrong endianness"),
            GraphError::HeaderTooShort => write!(f, "Graph file header is too short"),
            GraphError::SectionTableOOB => write!(f, "Section table is out of bounds"),
            GraphError::DuplicateSection(id) => write!(f, "Duplicate section with ID {}", id),
            GraphError::MissingRequiredSection(id) => {
                write!(f, "Missing required section with ID {}", id)
            }
            GraphError::NodesSectionMisaligned => write!(f, "Nodes section is misaligned"),
            GraphError::StringIndexMisaligned => write!(f, "String index section is misaligned"),
            GraphError::StringIndexOutOfBounds => write!(f, "String index entry is out of bounds"),
            GraphError::StringArenaOutOfBounds => write!(f, "String arena entry is out of bounds"),
            GraphError::Utf8Error => write!(f, "Invalid UTF-8 in string arena"),
            GraphError::AdjacencyOffsetsMisaligned => {
                write!(f, "Adjacency offsets section is misaligned")
            }
            GraphError::AdjacencyOffsetsNonMonotonic => {
                write!(f, "Adjacency offsets are not strictly increasing")
            }
            GraphError::AdjacencyOffsetsMustStartAtZero(k) => {
                write!(f, "Adjacency offsets section 0x{:04X} must start at 0", k)
            }
            GraphError::AdjacencyOffsetsWrongLength(k) => write!(
                f,
                "Adjacency offsets section 0x{:04X} length != (node_count+1) * 4",
                k
            ),
            GraphError::AdjacencyOffsetsTargetMismatch(k) => write!(
                f,
                "Adjacency offsets section 0x{:04X} final value disagrees with target count",
                k
            ),
            GraphError::OrphanAdjacencySection(k) => write!(
                f,
                "Adjacency section 0x{:04X} present without its paired counterpart",
                k
            ),
            GraphError::AdjacencyMirrorMismatch { edge_kind } => write!(
                f,
                "OUT and IN adjacency for edge kind {} describe different edge multisets",
                edge_kind
            ),
            GraphError::AdjacencyTargetsMisaligned => {
                write!(f, "Adjacency targets section is misaligned")
            }
            GraphError::NodeIdOutOfBounds => {
                write!(f, "Node ID in adjacency list is out of bounds")
            }
            GraphError::InvalidNodeKindDiscriminant(d) => {
                write!(f, "Invalid node kind discriminant: {}", d)
            }
            GraphError::InvalidEdgeKindDiscriminant(d) => {
                write!(f, "Invalid edge kind discriminant: {}", d)
            }
            GraphError::BufferTooShort => write!(f, "Buffer is too short to contain expected data"),
            GraphError::ExternalPackageOriginsInvalid => write!(
                f,
                "EXTERNAL_PACKAGE_ORIGINS section is malformed: wrong length, OOB/duplicate/non-ascending node_id, non-External target, or unresolved StringId"
            ),
            GraphError::ExternalOriginsInvalid => write!(
                f,
                "EXTERNAL_ORIGINS references a non-External node, a duplicate, or is unsorted"
            ),

            // ---- Spans milestone (Task 5) ----
            GraphError::SpanSectionMalformed { kind } => write!(
                f,
                "Span section 0x{:04X} has wrong payload length",
                kind
            ),
            GraphError::NonCanonicalPresenceBitset { kind } => write!(
                f,
                "Span section 0x{:04X} has non-canonical presence bitset (unused high bits non-zero)",
                kind
            ),
            GraphError::NonCanonicalAbsentSpan { kind, slot } => write!(
                f,
                "Span section 0x{:04X} slot {} has presence=0 but span bytes non-zero",
                kind, slot
            ),
            GraphError::SpanOverflow { kind, slot } => write!(
                f,
                "Span section 0x{:04X} slot {} has start + length overflowing u32",
                kind, slot
            ),
            GraphError::OrphanEdgeSpansSection { edge_kind } => write!(
                f,
                "Edge-spans section 0x{:04X} present without paired OUT_TARGETS/OUT_OFFSETS",
                edge_kind
            ),
            GraphError::TypeOnlySectionMalformed { edge_kind } => write!(
                f,
                "Type-only section 0x{:04X} has wrong payload length",
                edge_kind
            ),
            GraphError::OrphanTypeOnlySection { edge_kind } => write!(
                f,
                "Type-only section 0x{:04X} present without paired OUT_TARGETS/OUT_OFFSETS",
                edge_kind
            ),
            GraphError::TypeOnlySectionOnUnsupportedKind { edge_kind } => write!(
                f,
                "Type-only section 0x{:04X} on an edge kind that cannot be type-only (only Imports/Exports)",
                edge_kind
            ),
            GraphError::LabelSectionMalformed { edge_kind } => write!(
                f,
                "Label section 0x{:04X} payload is malformed (wrong length for declared M_kind)",
                edge_kind
            ),
            GraphError::OrphanLabelSection { edge_kind } => write!(
                f,
                "Label section 0x{:04X} present without paired OUT_TARGETS/OUT_OFFSETS",
                edge_kind
            ),
            GraphError::LabelSectionOnUnsupportedKind { edge_kind } => write!(
                f,
                "Label section 0x{:04X} on an edge kind that cannot carry labels (only Exports)",
                edge_kind
            ),
            GraphError::LabelStringIdOutOfBounds { edge_kind, string_id } => write!(
                f,
                "Label section 0x{:04X} references string id {} that does not resolve",
                edge_kind, string_id
            ),
            GraphError::TypeRefPositionSectionMalformed { edge_kind } => write!(
                f,
                "TypeRef-position section 0x{:04X} payload is malformed (wrong length, or a non-canonical zero-fill for an absent slot)",
                edge_kind
            ),
            GraphError::OrphanTypeRefPositionSection { edge_kind } => write!(
                f,
                "TypeRef-position section 0x{:04X} present without paired OUT_TARGETS/OUT_OFFSETS",
                edge_kind
            ),
            GraphError::TypeRefPositionSectionOnUnsupportedKind { edge_kind } => write!(
                f,
                "TypeRef-position section 0x{:04X} on an edge kind that cannot carry a type-ref position (only TypeRef)",
                edge_kind
            ),
            GraphError::TypeRefPositionInvalidDiscriminant { edge_kind, slot, value } => write!(
                f,
                "TypeRef-position section 0x{:04X} slot {} has unrecognized discriminant {}",
                edge_kind, slot, value
            ),
            GraphError::CallArgumentAnchorSectionMalformed { edge_kind } => write!(
                f,
                "Call-argument-anchor section 0x{:04X} payload is malformed (wrong length, non-monotonic offsets, or an unresolved name/path string id)",
                edge_kind
            ),
            GraphError::OrphanCallArgumentAnchorSection { edge_kind } => write!(
                f,
                "Call-argument-anchor section 0x{:04X} present without paired OUT_TARGETS/OUT_OFFSETS",
                edge_kind
            ),
            GraphError::CallArgumentAnchorSectionOnUnsupportedKind { edge_kind } => write!(
                f,
                "Call-argument-anchor section 0x{:04X} on an edge kind that cannot carry argument anchors (only Calls)",
                edge_kind
            ),
            GraphError::CallArgumentAnchorInvalidDiscriminant { edge_kind, slot, value } => write!(
                f,
                "Call-argument-anchor section 0x{:04X} entry {} has unrecognized kind byte {}",
                edge_kind, slot, value
            ),
            GraphError::SourceMetadataMalformed => write!(
                f,
                "SOURCE_METADATA payload length is not a multiple of 48"
            ),
            GraphError::NonCanonicalSourceMetadata => write!(
                f,
                "SOURCE_METADATA entry has non-zero padding bytes"
            ),
            GraphError::SourceMetadataNotSorted => write!(
                f,
                "SOURCE_METADATA entries are not strictly ascending by file_node_id"
            ),
            GraphError::SourceMetadataPointsAtNonFile { node_id } => write!(
                f,
                "SOURCE_METADATA references node {} which is not a File",
                node_id
            ),
            GraphError::SourceMetadataIncomplete { expected, actual } => write!(
                f,
                "SOURCE_METADATA has {} entries but graph has {} File nodes",
                actual, expected
            ),
            GraphError::SpanOnOrphanNode { node_id } => write!(
                f,
                "Node {} has a span but no File ancestor via Contains",
                node_id
            ),
            GraphError::SpanOutOfBounds {
                section_kind,
                node_or_slot,
            } => write!(
                f,
                "Span section 0x{:04X} entry {} exceeds its file's content_length",
                section_kind, node_or_slot
            ),
            GraphError::EdgeSpanOutOfBounds { edge_kind, slot } => write!(
                f,
                "Edge-spans section 0x{:04X} slot {} exceeds its from-node's file content_length",
                edge_kind, slot
            ),
            GraphError::BodySpanOutsideDecl { node_id } => write!(
                f,
                "Node {} has body_span not contained within decl_span",
                node_id
            ),
        }
    }
}
impl std::error::Error for GraphError {}

pub const MAGIC: [u8; 4] = *b"RPTG";
pub const VERSION: u32 = 1;
pub const ENDIAN_CHECK: u32 = 0x0102_0304;
pub const HEADER_SIZE: usize = 16;
pub const SECTION_ENTRY_SIZE: usize = 20;
pub const NODE_ROW_SIZE: usize = 8;
pub const STRING_INDEX_ENTRY_SIZE: usize = 8;
/// Fixed byte width of one `CALL_ARGUMENT_ANCHOR_ENTRIES_<kind>` record (G1.6
/// fork (a)). See `section_kind::CALL_ARGUMENT_ANCHOR_ENTRIES_BASE` for the
/// field layout.
pub const CALL_ARGUMENT_ANCHOR_ENTRY_SIZE: usize = 19;

pub mod section_kind {
    pub const STRINGS_ARENA: u16 = 0x0001;
    pub const STRING_INDEX: u16 = 0x0002;
    pub const NODES: u16 = 0x0003;
    pub const SOURCE_METADATA: u16 = 0x0004; // NEW (was unallocated)
    pub const EXTERNAL_ORIGINS: u16 = 0x0005; // NEW (real-package readiness)
    /// Per-External-node package_origin StringId. Sparse — only Externals
    /// with `Some(pkg)` at construction appear. Layout: u32 LE count + count
    /// records of (u32 LE node_id, u32 LE StringId). Entries strictly
    /// ascending by node_id. Lets the renderer surface "from `<pkg>`" for
    /// direct NamedFrom external re-exports where the target node's
    /// `node_name` is the member, not the package.
    pub const EXTERNAL_PACKAGE_ORIGINS: u16 = 0x0006;

    /// Combined per-node spans section: 24 bytes per node (name + decl + body)
    /// in Array-of-Structs layout, followed by three concatenated presence
    /// bitsets (name, decl, body). Total payload = 24*N + 3*ceil(N/8) bytes.
    ///
    /// Previously split into NODE_NAME_SPANS / NODE_DECL_SPANS / NODE_BODY_SPANS;
    /// merged for cache locality on multi-span-per-node access and to halve the
    /// parser code surface (one helper instead of three). Discriminants 0x0011
    /// and 0x0012 are intentionally left unallocated.
    pub const NODE_SPANS: u16 = 0x0010;

    pub const OUT_OFFSETS_BASE: u16 = 0x0100;
    pub const OUT_TARGETS_BASE: u16 = 0x0200;
    pub const IN_OFFSETS_BASE: u16 = 0x0300;
    pub const IN_TARGETS_BASE: u16 = 0x0400;
    pub const EDGE_SPANS_BASE: u16 = 0x0500;

    /// Per-edge-kind syntactic type-only marker (presence-only bitset).
    /// `ceil(M_kind/8)` bytes, LSB-first; bit i = OUT slot i is syntactically
    /// type-only. Only meaningful for Imports/Exports. An `Imports` edge is
    /// type-only iff the statement is `import type { … }` (a per-binding
    /// `import { type X, y }` still emits a runtime side-effect import, so the
    /// module edge survives). An `Exports` edge is type-only iff its specifier
    /// is type-only (`export type { X }` or `export { type X }` — exports are
    /// modeled per-name, no side-effect form). Absent section ⟺ all edges of
    /// the kind are runtime.
    pub const EDGE_TYPE_ONLY_BASE: u16 = 0x0600;

    /// Per-edge public-facing label (StringId), persisted to survive
    /// load-from-bytes. Only valid for `Exports` in v1 (the only edge
    /// kind whose parser captures a user-visible label distinct from
    /// the target node's name — `export { local as alias }` and
    /// `export default function Impl()`).
    ///
    /// Layout per spec §3.8:
    /// - 4 bytes per slot: StringId u32 LE (zero when absent)
    /// - ceil(M_kind/8) bytes presence bitset, LSB-first per byte
    ///
    /// Total: `4 * M_kind + ceil(M_kind/8)` bytes.
    pub const EDGE_LABEL_BASE: u16 = 0x0700;

    /// Per-edge parse-time `TypeRefPosition` discriminant (G1.5 Fix 2
    /// §3.2/2b), persisted to survive load-from-bytes. Only valid for
    /// `TypeRef` — no other edge kind carries a type-position classification.
    ///
    /// Layout:
    /// - 1 byte per slot: `TypeRefPosition as u8` (zero when absent)
    /// - `ceil(M_kind/8)` bytes presence bitset, LSB-first per byte
    ///
    /// Total: `M_kind + ceil(M_kind/8)` bytes.
    pub const EDGE_TYPE_REF_POSITION_BASE: u16 = 0x0800;

    /// Per-edge call-argument interior-anchor SIDECAR, offsets half (G1.6
    /// fork (a) — see `ts::events::CallArgumentAnchor`). Only valid for
    /// `Calls`. Unlike every fixed-size-per-slot section above, one Calls
    /// edge can carry an UNBOUNDED number of anchors, so this follows the
    /// adjacency-list pattern (`OUT_OFFSETS`/`OUT_TARGETS`) generalized from
    /// per-NODE degree to per-EDGE-SLOT anchor count, rather than a
    /// fixed-width-plus-bitset layout: sparsity is already expressed by an
    /// empty `offsets[i]..offsets[i+1]` range, so no separate presence
    /// bitset is needed.
    ///
    /// Layout: `(M_kind + 1)` x `u32 LE` prefix-sum offsets into
    /// `CALL_ARGUMENT_ANCHOR_ENTRIES_<kind>`, indexed by OUT slot.
    /// `offsets[0] == 0`; `offsets[M_kind]` == total entry count.
    pub const CALL_ARGUMENT_ANCHOR_OFFSETS_BASE: u16 = 0x0900;

    /// Per-edge call-argument interior-anchor SIDECAR, entries half. Flat
    /// array of fixed-size 19-byte records, sliced per OUT slot by the
    /// paired `CALL_ARGUMENT_ANCHOR_OFFSETS_<kind>` section:
    /// - 1 byte: anchor kind (0 = CallbackHead, 1 = ObjectKey)
    /// - 2 bytes: arg_index (`u16` LE)
    /// - 8 bytes: span (start: `u32` LE, length: `u32` LE)
    /// - 4 bytes: name `StringId` (`u32` LE; unused/zero for CallbackHead)
    /// - 4 bytes: path `StringId` (`u32` LE; unused/zero for CallbackHead)
    ///
    /// Total per entry: 19 bytes. Total section length:
    /// `19 * offsets[M_kind]` bytes.
    pub const CALL_ARGUMENT_ANCHOR_ENTRIES_BASE: u16 = 0x0A00;

    pub const fn out_offsets(edge_kind: u16) -> u16 {
        OUT_OFFSETS_BASE | edge_kind
    }
    pub const fn out_targets(edge_kind: u16) -> u16 {
        OUT_TARGETS_BASE | edge_kind
    }
    pub const fn in_offsets(edge_kind: u16) -> u16 {
        IN_OFFSETS_BASE | edge_kind
    }
    pub const fn in_targets(edge_kind: u16) -> u16 {
        IN_TARGETS_BASE | edge_kind
    }
    pub const fn edge_spans(edge_kind: u16) -> u16 {
        EDGE_SPANS_BASE | edge_kind
    }
    pub const fn edge_type_only(edge_kind: u16) -> u16 {
        EDGE_TYPE_ONLY_BASE | edge_kind
    }
    pub const fn edge_labels(edge_kind: u16) -> u16 {
        EDGE_LABEL_BASE | edge_kind
    }
    pub const fn edge_type_ref_position(edge_kind: u16) -> u16 {
        EDGE_TYPE_REF_POSITION_BASE | edge_kind
    }
    pub const fn call_argument_anchor_offsets(edge_kind: u16) -> u16 {
        CALL_ARGUMENT_ANCHOR_OFFSETS_BASE | edge_kind
    }
    pub const fn call_argument_anchor_entries(edge_kind: u16) -> u16 {
        CALL_ARGUMENT_ANCHOR_ENTRIES_BASE | edge_kind
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionEntry {
    pub kind: u16,
    pub offset: u64,
    pub len: u64,
}

pub fn encode_header_and_section_table(entries: &[SectionEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_SIZE + entries.len() * SECTION_ENTRY_SIZE);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&ENDIAN_CHECK.to_le_bytes());
    let section_count = u16::try_from(entries.len())
        .expect("Repotoire v0 format limit: section count must fit in u16");
    out.extend_from_slice(&section_count.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // _reserved
    for e in entries {
        out.extend_from_slice(&e.kind.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // _pad
        out.extend_from_slice(&e.offset.to_le_bytes());
        out.extend_from_slice(&e.len.to_le_bytes());
    }
    out
}

pub fn parse_header_and_section_table(
    buf: &[u8],
) -> Result<(Vec<SectionEntry>, usize), GraphError> {
    if buf.len() < HEADER_SIZE {
        return Err(GraphError::HeaderTooShort);
    }
    if buf[0..4] != MAGIC {
        return Err(GraphError::BadMagic);
    }
    let version = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    if version != VERSION {
        return Err(GraphError::BadVersion(version));
    }
    let endian = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    if endian != ENDIAN_CHECK {
        return Err(GraphError::BadEndian);
    }
    let count = u16::from_le_bytes(buf[12..14].try_into().unwrap()) as usize;
    let table_end = HEADER_SIZE
        .checked_add(
            count
                .checked_mul(SECTION_ENTRY_SIZE)
                .ok_or(GraphError::SectionTableOOB)?,
        )
        .ok_or(GraphError::SectionTableOOB)?;
    if table_end > buf.len() {
        return Err(GraphError::SectionTableOOB);
    }
    let mut table = Vec::with_capacity(count);
    for i in 0..count {
        let base = HEADER_SIZE + i * SECTION_ENTRY_SIZE;
        let kind = u16::from_le_bytes(buf[base..base + 2].try_into().unwrap());
        let offset = u64::from_le_bytes(buf[base + 4..base + 12].try_into().unwrap());
        let len = u64::from_le_bytes(buf[base + 12..base + 20].try_into().unwrap());
        table.push(SectionEntry { kind, offset, len });
    }
    Ok((table, table_end))
}

#[derive(Clone)]
pub struct OwnedGraph {
    pub(crate) bytes: Arc<[u8]>,
}

impl OwnedGraph {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Arc::from(bytes),
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

pub struct AdjacencyIter<'a> {
    targets_bytes: &'a [u8],
    cursor: usize,
    end: usize,
}

impl<'a> Iterator for AdjacencyIter<'a> {
    type Item = NodeId;
    fn next(&mut self) -> Option<NodeId> {
        if self.cursor >= self.end {
            return None;
        }
        let bytes: [u8; 4] = self.targets_bytes[self.cursor..self.cursor + 4]
            .try_into()
            .unwrap();
        self.cursor += 4;
        Some(NodeId::from_le_bytes(bytes))
    }
}

fn adjacency_iter<'a>(
    node: NodeId,
    offsets: Option<&ResolvedSection<'a>>,
    targets: Option<&ResolvedSection<'a>>,
) -> AdjacencyIter<'a> {
    let offsets = match offsets {
        Some(o) => o,
        None => return empty_iter(),
    };
    let targets = match targets {
        Some(t) => t,
        None => return empty_iter(),
    };
    let i = node.as_usize();
    let lo_off = i * 4;
    let hi_off = lo_off + 4;
    if hi_off + 4 > offsets.bytes.len() {
        return empty_iter();
    }
    let lo = u32::from_le_bytes(offsets.bytes[lo_off..lo_off + 4].try_into().unwrap()) as usize;
    let hi = u32::from_le_bytes(offsets.bytes[hi_off..hi_off + 4].try_into().unwrap()) as usize;
    AdjacencyIter {
        targets_bytes: targets.bytes,
        cursor: lo * 4,
        end: hi * 4,
    }
}

fn empty_iter<'a>() -> AdjacencyIter<'a> {
    AdjacencyIter {
        targets_bytes: &[],
        cursor: 0,
        end: 0,
    }
}

/// Parse the combined NODE_SPANS section payload per spec §3.2.
///
/// Layout: `24 * node_count` bytes of (name, decl, body) AoS spans followed
/// by three concatenated `ceil(node_count / 8)`-byte presence bitsets in
/// `(name, decl, body)` order.
///
/// Validates: total payload length; canonical-encoding of each bitset (unused
/// high bits in final byte = 0); zero-fill of absent slots; per-slot
/// `start + length` doesn't overflow u32.
///
/// Returns `(name_spans, decl_spans, body_spans)` — each a `Vec<Option<Span>>`
/// of length `node_count`. Cross-section validation (bounds against File
/// content_length) lands in Task 18.
/// Convenience alias for parse_node_spans's return — three parallel
/// `Vec<Option<Span>>` for (name, decl, body).
type NodeSpansTriple = (Vec<Option<Span>>, Vec<Option<Span>>, Vec<Option<Span>>);

fn parse_node_spans(payload: &[u8], node_count: usize) -> Result<NodeSpansTriple, GraphError> {
    let bitset_len = node_count.div_ceil(8);
    let expected = 24 * node_count + 3 * bitset_len;
    if payload.len() != expected {
        return Err(GraphError::SpanSectionMalformed {
            kind: section_kind::NODE_SPANS,
        });
    }
    let spans_end = 24 * node_count;
    let bitsets = [
        &payload[spans_end..spans_end + bitset_len],
        &payload[spans_end + bitset_len..spans_end + 2 * bitset_len],
        &payload[spans_end + 2 * bitset_len..],
    ];

    // Canonical: if node_count is not a multiple of 8, the unused high bits
    // of each bitset's final byte must be zero. (When node_count == 0 the
    // bitset_len is 0 and there's nothing to check.)
    if !node_count.is_multiple_of(8) && bitset_len > 0 {
        let used_bits = node_count % 8;
        let mask = !((1u8 << used_bits) - 1);
        for bs in &bitsets {
            if bs[bitset_len - 1] & mask != 0 {
                return Err(GraphError::NonCanonicalPresenceBitset {
                    kind: section_kind::NODE_SPANS,
                });
            }
        }
    }

    let mut name_spans: Vec<Option<Span>> = Vec::with_capacity(node_count);
    let mut decl_spans: Vec<Option<Span>> = Vec::with_capacity(node_count);
    let mut body_spans: Vec<Option<Span>> = Vec::with_capacity(node_count);

    for i in 0..node_count {
        let slot_base = i * 24;
        // Iterate (sub_kind, bitset_for_that_kind, dest_vec) in lockstep. sub_kind
        // and the routing match would otherwise require integer indexing into
        // both `bitsets` and `[&mut name_spans, &mut decl_spans, &mut body_spans]`,
        // which clippy::needless_range_loop flags.
        for (sub, (bitset, dest)) in bitsets
            .iter()
            .zip([&mut name_spans, &mut decl_spans, &mut body_spans])
            .enumerate()
        {
            let span_off = slot_base + sub * 8;
            let start = u32::from_le_bytes(payload[span_off..span_off + 4].try_into().unwrap());
            let length =
                u32::from_le_bytes(payload[span_off + 4..span_off + 8].try_into().unwrap());
            let bit_set = (bitset[i / 8] >> (i % 8)) & 1 == 1;
            // Slot identifier in errors: (node_index * 3 + sub) uniquely names
            // one of the 3N span slots in the combined section.
            let slot_id = (i * 3 + sub) as u32;
            if bit_set {
                if start.checked_add(length).is_none() {
                    return Err(GraphError::SpanOverflow {
                        kind: section_kind::NODE_SPANS,
                        slot: slot_id,
                    });
                }
                dest.push(Some(Span::new(start, length)));
            } else {
                if start != 0 || length != 0 {
                    return Err(GraphError::NonCanonicalAbsentSpan {
                        kind: section_kind::NODE_SPANS,
                        slot: slot_id,
                    });
                }
                dest.push(None);
            }
        }
    }
    Ok((name_spans, decl_spans, body_spans))
}

/// Parse a per-edge-kind EDGE_SPANS_<kind> section payload per spec §3.3.
///
/// Layout: `8 * m_kind` bytes of `(start, length)` per slot, then a single
/// `ceil(m_kind / 8)`-byte presence bitset (LSB-first).
///
/// Validates: total payload length; bitset canonical encoding; zero-fill of
/// absent slots; per-slot overflow check. `section_kind_for_error` is the
/// full `EDGE_SPANS_BASE | edge_kind` discriminant — used only in error
/// variants to identify which kind failed.
fn parse_edge_spans(
    payload: &[u8],
    m_kind: usize,
    section_kind_for_error: u16,
) -> Result<Vec<Option<Span>>, GraphError> {
    let bitset_len = m_kind.div_ceil(8);
    let expected = 8 * m_kind + bitset_len;
    if payload.len() != expected {
        return Err(GraphError::SpanSectionMalformed {
            kind: section_kind_for_error,
        });
    }
    let spans_bytes = &payload[..8 * m_kind];
    let bitset = &payload[8 * m_kind..];

    if !m_kind.is_multiple_of(8) && bitset_len > 0 {
        let used_bits = m_kind % 8;
        let mask = !((1u8 << used_bits) - 1);
        if bitset[bitset_len - 1] & mask != 0 {
            return Err(GraphError::NonCanonicalPresenceBitset {
                kind: section_kind_for_error,
            });
        }
    }

    let mut out: Vec<Option<Span>> = Vec::with_capacity(m_kind);
    for i in 0..m_kind {
        let off = i * 8;
        let start = u32::from_le_bytes(spans_bytes[off..off + 4].try_into().unwrap());
        let length = u32::from_le_bytes(spans_bytes[off + 4..off + 8].try_into().unwrap());
        let bit_set = (bitset[i / 8] >> (i % 8)) & 1 == 1;
        if bit_set {
            if start.checked_add(length).is_none() {
                return Err(GraphError::SpanOverflow {
                    kind: section_kind_for_error,
                    slot: i as u32,
                });
            }
            out.push(Some(Span::new(start, length)));
        } else {
            if start != 0 || length != 0 {
                return Err(GraphError::NonCanonicalAbsentSpan {
                    kind: section_kind_for_error,
                    slot: i as u32,
                });
            }
            out.push(None);
        }
    }
    Ok(out)
}

/// Validate an EDGE_TYPE_ONLY_<kind> presence-bitset payload: exactly
/// `ceil(M_kind/8)` bytes, with the unused high bits of the final byte zero
/// (canonical). Presence-only — no per-slot payload to check.
fn validate_type_only_section(
    payload: &[u8],
    m_kind: usize,
    section_kind_for_error: u16,
) -> Result<(), GraphError> {
    let bitset_len = m_kind.div_ceil(8);
    if payload.len() != bitset_len {
        return Err(GraphError::TypeOnlySectionMalformed {
            edge_kind: section_kind_for_error,
        });
    }
    if !m_kind.is_multiple_of(8) && bitset_len > 0 {
        let used_bits = m_kind % 8;
        let mask = !((1u8 << used_bits) - 1);
        if payload[bitset_len - 1] & mask != 0 {
            return Err(GraphError::NonCanonicalPresenceBitset {
                kind: section_kind_for_error,
            });
        }
    }
    Ok(())
}

/// Parse the SOURCE_METADATA section payload per spec §3.4 + §4.1 invariants 6–10.
///
/// Layout: one 48-byte entry per File node, sorted ascending by `file_node_id`.
/// Each entry: content_length (u64 LE, 8) + file_node_id (u32 LE, 4) + 4-byte
/// zero padding + sha256 ([u8; 32]).
///
/// Validates:
/// - Total length is a multiple of 48 (`SourceMetadataMalformed`).
/// - All 4 padding bytes per entry are zero (`NonCanonicalSourceMetadata`).
/// - `file_node_id` values are strictly ascending (`SourceMetadataNotSorted`).
/// - Each `file_node_id` references a valid node with kind == File
///   (`SourceMetadataPointsAtNonFile`).
/// - Total entry count equals the number of File nodes in the graph
///   (`SourceMetadataIncomplete`) — spec §2.6 completeness.
///
/// Returns the parsed entries paired with their file_node_ids, in input order
/// (which is the sorted order — invariant 8 guarantees ascending). The caller
/// uses the file_node_ids to build the O(1) source_metadata_index lookup.
fn parse_source_metadata(
    payload: &[u8],
    node_kinds: &[NodeKind],
) -> Result<Vec<(u32, SourceMetadata)>, GraphError> {
    if !payload.len().is_multiple_of(48) {
        return Err(GraphError::SourceMetadataMalformed);
    }
    let entry_count = payload.len() / 48;
    let mut out = Vec::with_capacity(entry_count);
    let mut last_id: Option<u32> = None;

    for i in 0..entry_count {
        let base = i * 48;
        let content_length = u64::from_le_bytes(payload[base..base + 8].try_into().unwrap());
        let file_node_id = u32::from_le_bytes(payload[base + 8..base + 12].try_into().unwrap());
        let padding = &payload[base + 12..base + 16];
        if padding != [0u8; 4] {
            return Err(GraphError::NonCanonicalSourceMetadata);
        }
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&payload[base + 16..base + 48]);

        // Strictly ascending file_node_id.
        if let Some(prev) = last_id {
            if file_node_id <= prev {
                return Err(GraphError::SourceMetadataNotSorted);
            }
        }
        last_id = Some(file_node_id);

        // Points at a File node (also implicitly bounds-checks the NodeId).
        let node_idx = file_node_id as usize;
        if node_idx >= node_kinds.len() || node_kinds[node_idx] != NodeKind::File {
            return Err(GraphError::SourceMetadataPointsAtNonFile {
                node_id: file_node_id,
            });
        }

        out.push((
            file_node_id,
            SourceMetadata {
                content_length,
                sha256,
            },
        ));
    }

    // Completeness: entry count equals the count of File nodes in the graph.
    let expected = node_kinds.iter().filter(|k| **k == NodeKind::File).count() as u32;
    if out.len() as u32 != expected {
        return Err(GraphError::SourceMetadataIncomplete {
            expected,
            actual: out.len() as u32,
        });
    }

    Ok(out)
}

/// Build the per-node `file_of` index by walking Contains-IN edges upward.
///
/// For each non-File node, follow the first Contains-IN edge until we hit a
/// resolved node (File ancestor known, or known orphan/cycle). Memoize via
/// `resolved: Vec<bool>` — using `None` in `file_of` as the memo sentinel
/// would conflate "unvisited" with "known orphan" and re-walk on every visit,
/// blowing up to O(N²) on long chains.
///
/// Cycle defense: bound the walk by `n` steps. Any legitimate Contains chain
/// through `n` distinct nodes terminates in at most `n` hops; exceeding the
/// bound proves a cycle, and the visited nodes get marked orphan.
///
/// `contains_in_offsets_bytes` and `contains_in_targets_bytes` are the raw
/// section payloads for IN_OFFSETS_CONTAINS and IN_TARGETS_CONTAINS, or None
/// when the kind has no adjacency at all (which means every non-File node is
/// trivially an orphan).
fn build_file_of(
    node_kinds: &[NodeKind],
    contains_in_offsets_bytes: Option<&[u8]>,
    contains_in_targets_bytes: Option<&[u8]>,
) -> Vec<Option<NodeId>> {
    let n = node_kinds.len();
    let mut file_of: Vec<Option<NodeId>> = vec![None; n];
    let mut resolved: Vec<bool> = vec![false; n];

    // File nodes are their own File ancestor — seed and mark resolved.
    for (i, k) in node_kinds.iter().enumerate() {
        if *k == NodeKind::File {
            file_of[i] = Some(NodeId(i as u32));
            resolved[i] = true;
        }
    }

    let (in_off, in_tgt) = match (contains_in_offsets_bytes, contains_in_targets_bytes) {
        (Some(o), Some(t)) => (o, t),
        _ => {
            // No Contains adjacency at all — every non-File node is orphan,
            // and they all stay None/false. Mark them resolved so the empty
            // walk loop below terminates correctly (defensive — the loop's
            // outer "if resolved[i]" check would skip them anyway).
            resolved.fill(true);
            return file_of;
        }
    };

    let read_offset =
        |i: usize| -> u32 { u32::from_le_bytes(in_off[i * 4..(i + 1) * 4].try_into().unwrap()) };
    let read_target = |slot: usize| -> u32 {
        u32::from_le_bytes(in_tgt[slot * 4..(slot + 1) * 4].try_into().unwrap())
    };

    for i in 0..n {
        if resolved[i] {
            continue;
        }

        let mut current = i;
        let mut path: Vec<usize> = Vec::new();
        let mut hit_cycle = false;
        let mut hit_orphan_terminator = false;
        let mut steps = 0usize;
        while steps < n {
            if resolved[current] {
                break;
            }
            path.push(current);

            let start = read_offset(current) as usize;
            let end = read_offset(current + 1) as usize;
            if start == end {
                hit_orphan_terminator = true;
                break;
            }
            // First parent in IN_TARGETS — single-ancestor convention per spec §4.3.
            let parent = read_target(start) as usize;
            if parent == current {
                // Self-loop — treat as cycle.
                hit_cycle = true;
                break;
            }
            current = parent;
            steps += 1;
        }
        if steps == n {
            // Walked n steps without resolving — definitely a cycle.
            hit_cycle = true;
        }

        let ancestor = if hit_cycle || hit_orphan_terminator {
            None
        } else {
            file_of[current]
        };
        for &node_in_path in &path {
            file_of[node_in_path] = ancestor;
            resolved[node_in_path] = true;
        }
    }

    file_of
}
