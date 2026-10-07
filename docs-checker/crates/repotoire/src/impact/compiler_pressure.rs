//! Compiler-pressure collector: `TypeRef`/`Extends`/`Implements` in-edge scan
//! plus a dependent-file import scan, classified into a `CompilerPressure*`
//! evidence row.
//!
//! Pure-moved out of `impact/evidence.rs` (design doc:
//! `docs/superpowers/specs/2026-07-06-impact-collector-seam-design.md`,
//! decision 1 — behavior-only move). The `CompilerPressure*` evidence types
//! stay in `evidence.rs` (Impact Evidence owns the row schema, CONTEXT.md);
//! this module is the third collector adapter on the same seam as
//! `service_dispatch.rs` and `provider_context.rs`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;

use crate::archive::SourceBundle;
use crate::csr::{CallArgumentAnchorView, CodeGraph, SpanView};
use crate::ids::NodeId;
use crate::impact::deadline::{ImpactDeadline, ImpactDeadlineExceeded};
use crate::schema::{EdgeKind, NodeKind, TypeRefPosition};
use crate::spans::Span;

use super::evidence::{
    any_identifier_occurrence, import_label_mentions_named, import_slots_for_decl_until,
    line_mentions_identifier, source_line_at_offset, source_lines, CompilerPressureEvidence,
    CompilerPressureLevel, CompilerPressureReason, CompilerPressureSubChannel, ImportSlot,
    ROUTE_CALLBACK_HEAD_PROBE_MEMBER,
};
use super::walk_dumps::{append_jsonl, CallableRef, PathHopInput, RouteBranch, WalkDumps};

struct CompilerPressureCandidate {
    evidence: CompilerPressureEvidence,
    sort_key: (u8, u8, String),
}

/// G1.9 Task S2 consumption gate: `G19_ALIAS_MEMBER_CHAIN`. Fail-closed,
/// default OFF — ON only when the var is set to EXACTLY `"1"` (any other
/// value, including "true"/"0"/empty, reads OFF). This is the plan's
/// Global Constraints requirement: with the var unset,
/// `collect_consumer_call_site_pressure`'s return value must be
/// byte-identical to the pre-S2 binary's (historically checked at M0-V0 and
/// MR Pass A/B; the original `ky_alias_shape_flag_off_emits_call_head_rows_only`
/// test is no longer maintained). This semantic experiment switch is
/// independent of the output-only dump paths. Read exactly once per walk
/// invocation by the caller (mirrors `WalkDumps::from_env`'s precedent in
/// `walk_dumps.rs`), never re-read mid-walk.
fn alias_member_chain_gate_enabled() -> bool {
    std::env::var("G19_ALIAS_MEMBER_CHAIN").ok().as_deref() == Some("1")
}

pub(crate) fn collect_compiler_pressure<D: ImpactDeadline + ?Sized>(
    bundle: &SourceBundle<'_>,
    span_view: &SpanView<'_>,
    decl: NodeId,
    decl_file: Option<NodeId>,
    name: &str,
    all_decls: &[NodeId],
    deadline: &D,
) -> Result<Vec<CompilerPressureEvidence>, ImpactDeadlineExceeded> {
    let graph = &bundle.graph;
    let mut rows = Vec::new();

    // exp(gate1) separability measurement (Task 1): env-gated, off-by-default
    // `TypeRefPosition` dump. Read the destination path ONCE per collection
    // invocation (same discipline as `WalkDumps::from_env`); when unset this
    // is `None` and every hook below is a no-op — zero behavior change to the
    // returned rows, no file touched. Additive diagnostic only.
    let sep_position_dump_path = std::env::var("REPOTOIRE_SEP_POSITION_DUMP").ok();

    for kind in [EdgeKind::TypeRef, EdgeKind::Extends, EdgeKind::Implements] {
        for edge in span_view.in_edges(decl, kind) {
            deadline.check()?;
            let source = edge.source;
            let Some(source_file) = graph.file_of(source) else {
                continue;
            };
            let Some(span) = edge.span else {
                continue;
            };
            let Some(lc) = bundle.line_col(source_file, span.start()) else {
                continue;
            };
            let line_text = source_line_at_offset(bundle, source_file, span.start());
            let Some((level, reason)) =
                classify_compiler_pressure(kind, line_text.as_deref().unwrap_or(""), name)
            else {
                continue;
            };
            let source_kind = graph.node_kind(source);
            let owner = if matches!(source_kind, NodeKind::ModuleInit | NodeKind::File) {
                None
            } else {
                Some(graph.node_name(source).to_string())
            };
            let direct_evidence =
                line_mentions_identifier(line_text.as_deref().unwrap_or(""), name);
            let sub_channel = if kind == EdgeKind::TypeRef {
                // G1.5 Fix 2 (F2-3): demote ConstraintDecl/CompositionMember
                // TypeRef positions to the report-only `type_dependency`
                // sub-channel (spec Appendix A demotion rule, pre-registered
                // verbatim). Annotation/ReturnType/ValuePosition/Other/
                // ParamAnnotation (and the absent-position fail-open case,
                // see `InEdge::position_or_fail_open`) all stay
                // `type_surface` — widening the demotion to bare
                // annotations would strip real annotation pressure Fix 1
                // just rescued (see the task brief's rationale); this is
                // the pre-registered recall-protective trade-off.
                // G1.9 S2: `AliasMemberAnnotation` joins this same
                // non-demoted bucket — it is, like `Other`, not a positive
                // pressure signal on its own (see that variant's doc
                // comment on `TypeRefPosition`); pinned by
                // `compiler_pressure_keeps_alias_member_annotation_type_ref_as_type_surface`
                // in `evidence.rs`.
                let position = edge.position_or_fail_open();
                // exp(gate1) separability dump: emit this TypeRef row's
                // assigned `TypeRefPosition` when the dump is enabled. Skip
                // Transitive rows (`!direct_evidence`) — those never mention
                // the symbol on their own line, so they carry no
                // measurement-relevant position. Purely additive: the row
                // pushed below is byte-identical whether or not this fires.
                if let Some(dump_path) = &sep_position_dump_path {
                    if direct_evidence {
                        append_sep_position_dump(
                            dump_path,
                            name,
                            graph.node_name(source_file),
                            lc.line,
                            position,
                        );
                    }
                }
                let demoted = matches!(
                    position,
                    TypeRefPosition::ConstraintDecl | TypeRefPosition::CompositionMember
                );
                if !direct_evidence {
                    CompilerPressureSubChannel::Transitive
                } else if demoted {
                    CompilerPressureSubChannel::TypeDependency
                } else {
                    CompilerPressureSubChannel::TypeSurface
                }
            } else {
                // Extends/Implements edges never carry a TypeRefPosition (it
                // is only ever recorded on TypeRef edges) — fail-open: keep
                // the pre-F2-3 direct/transitive split unchanged, never
                // demoted to type_dependency.
                if direct_evidence {
                    CompilerPressureSubChannel::TypeSurface
                } else {
                    CompilerPressureSubChannel::Transitive
                }
            };
            rows.push(CompilerPressureCandidate {
                evidence: CompilerPressureEvidence {
                    file: graph.node_name(source_file).to_string(),
                    line: lc.line,
                    level,
                    reason,
                    owner,
                    sub_channel,
                    direct_evidence,
                },
                sort_key: (level.sort_rank(), 0, graph.node_name(source).to_string()),
            });
        }
    }

    // Import edges prove "this dependent file names the symbol", even when
    // the lightweight TypeScript extractor misses the downstream TypeRef in
    // a generic call or satisfies expression. Scan those dependent files for
    // compiler-sensitive lines that mention the imported symbol.
    if let Some(decl_file_id) = decl_file {
        for import in import_slots_for_decl_until(span_view, decl, decl_file, name, deadline)? {
            deadline.check()?;
            let ImportSlot {
                slot,
                edge,
                direct_decl_import,
                public_name,
            } = import;
            let importer = edge.source;
            if graph.file_of(importer) == Some(decl_file_id) {
                continue;
            }
            let out_slot = span_view.in_to_out(EdgeKind::Imports, slot);
            let Some(label) = graph.edge_label_str(EdgeKind::Imports, out_slot) else {
                continue;
            };
            let imported_name = public_name.as_deref().unwrap_or(name);
            if !direct_decl_import && !import_label_mentions_named(label, imported_name) {
                continue;
            }
            let local_name = super::evidence::python_import_local_name(label, imported_name)
                .unwrap_or(imported_name);
            for (line, text) in source_lines(bundle, importer) {
                deadline.check()?;
                if !line_mentions_identifier(&text, local_name) {
                    continue;
                }
                let Some((level, reason)) = classify_type_ref_pressure_line(&text, local_name)
                else {
                    continue;
                };
                rows.push(CompilerPressureCandidate {
                    evidence: CompilerPressureEvidence {
                        file: graph.node_name(importer).to_string(),
                        line,
                        level,
                        reason,
                        owner: None,
                        // F2-3: this row is synthesized from an Imports edge
                        // scan (no TypeRef edge exists for it), so there is
                        // no TypeRefPosition to key a demotion off of.
                        // Fail-open: keep TypeSurface unchanged, never
                        // demoted to type_dependency.
                        sub_channel: CompilerPressureSubChannel::TypeSurface,
                        direct_evidence: true,
                    },
                    sort_key: (level.sort_rank(), 1, "import-dependent".to_string()),
                });
            }
        }
    }

    // G1.6 W1 (spec D2+D3+D5): the consumer-call-site walk, seeded from
    // every decl sharing `name`'s bare identity (`all_decls`), appended
    // BEFORE the shared sort/dedup below so these rows fold into the exact
    // same ordering/dedup discipline every other compiler-pressure row
    // already gets. This is purely ADDITIVE — the scan above (which still
    // keys off the single `decl`/`decl_file`) is untouched, which is the
    // hard invariant `consumer_call_site_walk.rs` pins: with the walk
    // active, every EXISTING `type_surface`/`transitive`/`type_dependency`
    // row is byte-identical to before.
    rows.extend(collect_consumer_call_site_pressure(
        bundle, span_view, all_decls, deadline,
    )?);

    rows.sort_by(|a, b| {
        a.evidence
            .file
            .cmp(&b.evidence.file)
            .then(a.evidence.line.cmp(&b.evidence.line))
            .then(a.sort_key.0.cmp(&b.sort_key.0))
            .then(a.sort_key.1.cmp(&b.sort_key.1))
            .then(a.evidence.reason.label().cmp(b.evidence.reason.label()))
            .then(a.sort_key.2.cmp(&b.sort_key.2))
    });
    rows.dedup_by(|a, b| {
        let same = a.evidence.file == b.evidence.file
            && a.evidence.line == b.evidence.line
            && a.evidence.level == b.evidence.level
            && a.evidence.reason == b.evidence.reason;
        // G1.10 D1 route-preserving collapse: `dedup_by` passes `a` =
        // the LATER element (removed on `true`) and `b` = the earlier
        // survivor. A qualifying CallbackHead row that shares its
        // (file, line, level, reason) with an earlier consumer row (a
        // call-head or ObjectKey row at the same source line — e.g. an
        // inline `beforeRequest: [cb]` one-liner) would otherwise vanish
        // WITH its token, silently shrinking the §4-P route population
        // the D2 scorer consumes (measured on the ky BeforeRequestHook
        // held-out probe: 6 of M0's 59 route keys collapse this way).
        // Carrying the token onto the surviving row keeps the rendered
        // route population location-identical to M0's enumerated one.
        // Fail-closed by construction: with `G19_ALIAS_MEMBER_CHAIN`
        // unset every `route` is `None`, so this arm never fires and the
        // collapse is byte-identical to pre-D1. The survivor keeps its
        // own `depth` (identical on every observed collision — both rows
        // come from the same walk closure; disclosed, not asserted).
        if same {
            if let CompilerPressureSubChannel::ConsumerCallSite {
                route: Some(route), ..
            } = a.evidence.sub_channel
            {
                if let CompilerPressureSubChannel::ConsumerCallSite {
                    route: existing @ None,
                    ..
                } = &mut b.evidence.sub_channel
                {
                    *existing = Some(route);
                }
            }
        }
        same
    });
    deadline.check()?;
    Ok(rows.into_iter().map(|row| row.evidence).collect())
}

/// exp(gate1) separability measurement (Task 1): one dumped `TypeRef`
/// position record. Serialized as a single JSON line per emitted
/// non-Transitive `TypeRef` compiler-pressure row when
/// `REPOTOIRE_SEP_POSITION_DUMP` is set. Field order is stable
/// (`symbol,file,line,position`) so the Python harvest can grep positions
/// directly. This is throwaway diagnostic scaffolding, never read by the
/// tool itself.
#[derive(serde::Serialize)]
struct SepPositionDumpRow<'a> {
    symbol: &'a str,
    file: &'a str,
    line: u32,
    position: String,
}

/// Append one separability position-dump line to `path` (append-create).
/// Best-effort: any I/O, capacity, or serialization error is reported — this
/// is an off-by-default diagnostic surface and must never affect the
/// returned evidence or fail the collection. `position` is serialized via
/// its `Debug` form (e.g. `ConstraintDecl`, `ValuePosition`), matching the
/// enum variant names the a-priori partition keys off.
fn append_sep_position_dump(
    path: &str,
    symbol: &str,
    file: &str,
    line: u32,
    position: TypeRefPosition,
) {
    let row = SepPositionDumpRow {
        symbol,
        file,
        line,
        position: format!("{position:?}"),
    };
    if let Err(error) = append_jsonl(std::path::Path::new(path), std::slice::from_ref(&row)) {
        // Diagnostic reporting must remain best-effort even when stderr fails.
        let _ = writeln!(
            std::io::stderr().lock(),
            "REPOTOIRE_SEP_POSITION_DUMP: failed to write {path}: {error}"
        );
    }
}

/// G1.6 Task W1 — the `consumer_call_site` sub-channel: a type-closure ∘
/// `Calls` join that surfaces the call sites (and, per the locked §7 fork
/// (a), multi-line argument-interior anchors) of callables whose parameter
/// surface transitively references the queried symbol through the type
/// graph. Spec: `docs/superpowers/specs/2026-07-06-gate1-g16-consumer-call-site-design.md`
/// §4 D2/D3/D5.
///
/// **The walk (D2).** Seeds from EVERY node in `all_decls` (multi-decl
/// seeding — two decls sharing a bare name in different files each carry
/// their own, otherwise-disconnected, closure) at depth 0, then does a BFS
/// over `[TypeRef, Extends, Implements]` IN-edges up to depth 4. A reached
/// node becomes an eligible callable when BOTH (a) its `NodeKind` is in the
/// callable set (`is_callable_node_kind`: Function, Class, Variable, or
/// Property) AND (b) the edge that reached it is a `TypeRef` edge whose
/// RECORDED position (not fail-opened — see the `is_param`/
/// `is_property_annotation` comment below) is `ParamAnnotation` — i.e. this
/// edge specifically means "the edge's source has the walked node as its
/// OWN parameter type", not merely "mentions it somewhere". Every REACHED
/// (depth >= 1 — never a seed; see the F1 gate comment at the expansion
/// site) Class/Interface/TypeAlias CONTAINER also expands its direct
/// `Contains` children into the eligible set at the SAME depth (hop-neutral
/// — Contains expansion is not itself a TypeRef-closure hop, so it never
/// increments the depth counter; every emitted depth tag is therefore
/// 1..=4). This expansion is load-bearing, not defensive-only: this
/// codebase's parser attributes a class METHOD's own parameter-annotation
/// `TypeRef` edge to the ENCLOSING CLASS node, never to the method's own
/// `Property` node (confirmed against the emittery-shape fixture), so
/// without Contains-expansion a method callable would never become
/// eligible even when its own parameter directly names the queried symbol.
///
/// **The member-level Contains guard (G1.7).** Contains-expansion is no
/// longer unconditional: a reached container's child member is admitted
/// only if the member's OWN surface involves the probe's reached type
/// closure (spec
/// `docs/superpowers/specs/2026-07-06-gate1-g17-join-and-guard-design.md`
/// §4 "G"; PR #232 design-review conditions C-1..C-4). Mechanism: while
/// walking, every `TypeRef`/`Extends`/`Implements` edge that lands on a
/// closure node and whose SOURCE is a container has its span recorded
/// under that container — the qualifying condition is "an edge from the
/// container to ANY node in the probe's reached closure", never just the
/// probe itself (C-2; a member reaching the probe through an alias chain
/// qualifies — emittery-fanout-depth2 fixture). Admission is decided in a
/// POST-BFS pass over the complete accumulator, never inline at
/// expansion/pop time (C-1): a container reached via a shallow member's
/// edge pops BEFORE a deeper member's qualifying edge is discovered, so an
/// inline filter would wrongly drop that member. A child is PINNED when
/// its own `node_decl_span` contains at least one of its container's
/// recorded spans (the parser misattributes the edge's source to the
/// class, but `edge.span` is the reference's true location, which sits
/// inside the involved member's own declaration bytes). Recall fallback
/// (C-4): if NO child of a container is pinned (heritage-header reach,
/// decorator-argument reach, span-less edges, spans-absent graphs), ALL
/// children are admitted — exactly the pre-G1.7 behavior — so the guard is
/// a pure precision filter that can never drop a container's admitted set
/// below the unconditional baseline unless at least one sibling is
/// positively pinned; a child with no decl span of its own is likewise
/// always admitted. Containment is only ever checked between a container's
/// OWN recorded spans and that SAME container's children (C-3): `Span`
/// carries no file identity, so a pooled/global span comparison would
/// manufacture cross-file false containment from coincidentally
/// overlapping byte offsets.
///
/// Disclosed guard residuals (over-admission only, never under-admission):
/// heritage-/decorator-reached containers retain unconditional admission
/// via the C-4 fallback, and a member whose BODY (not signature) references
/// the closure pins itself — `node_decl_span` includes the body bytes.
///
/// **The chain (also D2).** While walking, `Annotation`-position `TypeRef`
/// edges (property/body-local annotation heads — never a callable's own
/// parameter) accumulate a property-name segment per hop, extracted from
/// the source text immediately preceding the reference (`ident:` or
/// `ident?:`). This produces, per eligible callable, the dotted key path
/// (in REVERSED order — outermost-first, matching how a caller would
/// actually nest an object literal) from the callable's own parameter type
/// down to the queried symbol.
///
/// G1.9 S2 (fail-closed, `G19_ALIAS_MEMBER_CHAIN=1`, read once per walk
/// invocation via [`alias_member_chain_gate_enabled`]): when the gate is
/// on, `AliasMemberAnnotation`-position `TypeRef` edges (object-literal
/// TYPE-ALIAS members — see that variant's doc comment) ALSO accumulate a
/// segment, by the identical mechanism as the `Annotation` case above —
/// this is chain COLLECTION only, never eligibility (`mark_eligible` stays
/// exclusively gated on `is_param`/`ParamAnnotation`; see
/// `arrival_route_matches_eligibility`'s doc comment). With the gate
/// unset (the default), an `AliasMemberAnnotation` edge contributes
/// nothing, exactly like `Other` always has — the walk's return value is
/// byte-identical to the pre-S2 binary's.
///
/// **The probe-member route flag (G1.10 D1).** Alongside the chain, the
/// walk threads a per-node `probe_member_first_hop: bool` (same map, same
/// first-arrival discipline): minted `true` IFF the seed-adjacent (d0->d1)
/// hop pushed a chain segment via the `AliasMemberAnnotation` arm —
/// AMA-ONLY, the frozen §4-P width pin (spec
/// `docs/superpowers/specs/2026-07-07-gate1-g110-hook-callback-discrimination-design.md`);
/// an `Annotation` (interface-member) seed hop never mints — and inherited
/// unchanged on every other hop. At the join below, a `CallbackHead`-branch
/// row from a flag-true callable carries
/// ` route=callback_head_probe_member`
/// ([`ROUTE_CALLBACK_HEAD_PROBE_MEMBER`]); `CallHead`/`ObjectKey` rows
/// never do. Because minting lives inside the S2 gate
/// (`is_alias_member_annotation` is `false` with `G19_ALIAS_MEMBER_CHAIN`
/// unset), the token cannot exist in default output — no new env var is
/// read. `WalkParent`/`parent_of` (the `G19_PATH_DUMP` diagnostics) are
/// deliberately NOT consulted: dump state must never become a semantic
/// dependency of emitted rows.
///
/// **The join (D3).** For each eligible callable, iterates
/// `in_edges(callable, Calls)` — member-dispatch-promoted method-call edges
/// included, since those are ordinary `Calls` in-edges by the time this
/// reads the graph, no special-casing needed. Always emits a row at the
/// call-head line. When the chain is non-empty, ALSO scans
/// `call_argument_anchors_from_in` for that same call: an `ObjectKey`
/// anchor whose full dotted `path` matches the chain emits a row at the
/// key's line (the "chain-key precision guard" — an unrelated key never
/// matches, however similarly named its OWN trailing segment is), and any
/// `CallbackHead` anchor(s) nested under that SAME matching key (grouped by
/// anchor-emission order, which always places a callback immediately before
/// the `ObjectKey` anchor for whatever contains it — see the parser's
/// `scan_argument_value_for_anchors` doc comment) also get a row. When the
/// chain is empty (the callable's own parameter type directly names, or is,
/// the reached node — hono-shape, emittery-shape), no anchor scan is
/// needed: the call-head row alone is the "direct hit".
///
/// **`direct_evidence`** is always `false` — none of these rows' own lines
/// mention the queried symbol; that is the entire premise of a transitive
/// consumer site (spec §2). **`depth`** is the callable's own eligible
/// depth (1..=4), reused for every row this join emits from it, whichever
/// anchor mechanism produced the row.
fn collect_consumer_call_site_pressure<D: ImpactDeadline + ?Sized>(
    bundle: &SourceBundle<'_>,
    span_view: &SpanView<'_>,
    all_decls: &[NodeId],
    deadline: &D,
) -> Result<Vec<CompilerPressureCandidate>, ImpactDeadlineExceeded> {
    const MAX_DEPTH: u8 = 4;
    let graph = &bundle.graph;

    // G19 Task S0: env-gated diagnostic dump surface. `dumps` is read
    // once, at the top of this walk invocation; every hook site below is
    // a no-op when its own env var is unset (see `WalkDumps`'s doc
    // comment for the byte-identity contract).
    let mut dumps = WalkDumps::from_env();

    // G19 Task S2: fail-closed alias-member chain-collection gate, read
    // once per walk invocation (same discipline as `WalkDumps::from_env`
    // above) — see `alias_member_chain_gate_enabled`'s doc comment.
    let alias_member_chain_gate_on = alias_member_chain_gate_enabled();

    let mut visited: HashSet<NodeId> = HashSet::new();
    // G1.10 D1: `bool` alongside the chain is `probe_member_first_hop` —
    // true iff the d0->d1 hop that first reached this node was the AMA arm
    // (`is_alias_member_annotation`, AMA-ONLY per the frozen §4-P width
    // pin) off the SEED. Threaded in lockstep with the chain (same map,
    // same insertion sites, same first-arrival discipline) so it can never
    // drift out of sync with `chain_of`'s own visited-gated semantics —
    // see the mint site at the TypeRef/Extends/Implements hop loop below.
    let mut chain_of: HashMap<NodeId, (Vec<String>, bool)> = HashMap::new();
    let mut queue: VecDeque<(NodeId, u8)> = VecDeque::new();
    let mut eligible: HashMap<NodeId, (u8, Vec<String>, bool)> = HashMap::new();
    // G19 Task S0 (`G19_PATH_DUMP` only): first-arrival BFS parent per
    // node, mirroring `chain_of`'s own visited-gated semantics — see
    // `WalkParent`'s doc comment for the documented min-depth-tie-break
    // caveat this implies. Populated only when the path dump is enabled.
    let mut parent_of: HashMap<NodeId, WalkParent> = HashMap::new();
    // G19 Task S0 (`G19_PATH_DUMP` only): every (container, child)
    // membership the G1.7 post-BFS admission pass ACTUALLY ADMITTED —
    // recorded at the admission site so `arrival_route_matches_eligibility`
    // checks the admission OUTCOME, never re-derives (and drifts from)
    // the guard's rules. Populated only when the path dump is enabled.
    let mut admitted_contains: HashSet<(NodeId, NodeId)> = HashSet::new();
    // G1.7 guard bookkeeping (see the doc comment). EVERY qualifying edge
    // span is recorded per container source (C-2's multi-span accumulator —
    // two different members independently referencing the closure must both
    // pin), consumed by the post-BFS admission pass below (C-1).
    let mut container_probe_spans: HashMap<NodeId, Vec<Span>> = HashMap::new();
    // Containers that Contains-expanded, in pop order, with the
    // depth/chain/flag they expanded at. Each node pops at most once
    // (visited gates the queue), so no container appears twice.
    let mut expanded_containers: Vec<(NodeId, u8, Vec<String>, bool)> = Vec::new();

    for &seed in all_decls {
        deadline.check()?;
        if visited.insert(seed) {
            // A seed is never d0->d1 itself, so its own flag is always
            // `false` — minting only ever happens on a hop OFF a seed
            // (`depth == 0` at the mint site below), never on the seed's
            // own entry.
            chain_of.insert(seed, (Vec::new(), false));
            queue.push_back((seed, 0));
        }
    }

    while let Some((node, depth)) = queue.pop_front() {
        deadline.check()?;
        // Contains-expansion (hop-neutral): see the function doc comment.
        // `depth >= 1` gates it to REACHED containers only — NEVER the seed
        // (review finding F1 on PR #225): a seed pops at depth 0, and
        // expanding it would make every member of the QUERIED class an
        // eligible callable at depth 0, bypassing the ParamAnnotation gate
        // entirely (`class Widget { doThing(x: Unrelated) {} }` queried as
        // `Widget` would emit rows at `w.doThing(...)` call sites even
        // though `doThing`'s parameter surface never references `Widget` —
        // violating the spec §3 claim AND the 1..=4 depth-tag contract,
        // and poisoning the later depth-cutoff fit with depth-0 rows that
        // satisfy every candidate cutoff). A container reached at depth
        // >= 1 got there through a real ParamAnnotation/heritage edge, so
        // its member expansion is the documented, pre-registered trade-off
        // — the seed has no such edge.
        if depth >= 1 && is_container_node_kind(graph.node_kind(node)) {
            let (container_chain, container_probe_member_flag) =
                chain_of.get(&node).cloned().unwrap_or_default();
            for child in graph.outgoing(node, EdgeKind::Contains) {
                deadline.check()?;
                if !is_callable_node_kind(graph.node_kind(child)) {
                    continue;
                }
                if visited.insert(child) {
                    // Contains-expansion never mints (it only ever fires
                    // at `depth >= 1`, so its source is never the seed) —
                    // the child simply inherits the container's own flag,
                    // exactly mirroring the chain's own inheritance.
                    chain_of.insert(
                        child,
                        (container_chain.clone(), container_probe_member_flag),
                    );
                    queue.push_back((child, depth));
                    if dumps.path_enabled() {
                        parent_of.insert(
                            child,
                            WalkParent {
                                parent: node,
                                edge_kind: EdgeKind::Contains,
                                position: None,
                                depth,
                            },
                        );
                    }
                }
                // G1.7: admission (`mark_eligible`) is deferred to the
                // post-BFS pass below (review condition C-1) — deciding
                // here would wrongly drop a member whose qualifying edge
                // is only discovered after this container pops (a
                // container reached via a shallow member's edge pops
                // before a deeper member's edge is walked; see the
                // emittery-fanout-depth2 fixture). The reachability/
                // enqueue handling above is byte-identical to pre-G1.7.
            }
            expanded_containers.push((node, depth, container_chain, container_probe_member_flag));
        }

        if depth >= MAX_DEPTH {
            continue;
        }

        for kind in [EdgeKind::TypeRef, EdgeKind::Extends, EdgeKind::Implements] {
            for edge in span_view.in_edges(node, kind) {
                deadline.check()?;
                let source = edge.source;
                let next_depth = depth + 1;

                // G1.7 guard bookkeeping (C-2): `node` is in the probe's
                // reached closure (that's why it was popped), so an in-edge
                // landing on it whose source is a container is a qualifying
                // "this container's source text references the closure"
                // pin. Closure-aware by construction — the walk only ever
                // pops closure nodes, so recording here covers edges to ANY
                // closure node, never just the probe itself. Recording is
                // position-agnostic; the post-BFS span-containment check is
                // what decides which member (if any) the reference belongs
                // to.
                if is_container_node_kind(graph.node_kind(source)) {
                    if let Some(span) = edge.span {
                        container_probe_spans.entry(source).or_default().push(span);
                    }
                }

                // Match the RECORDED position, never `position_or_fail_open`
                // — None ("no info") and Some(Other) must NOT be treated as
                // a positive parameter-surface signal (see `InEdge::position`'s
                // own doc comment on why the two stay distinguishable here).
                let is_param = kind == EdgeKind::TypeRef
                    && edge.position == Some(TypeRefPosition::ParamAnnotation);
                let is_property_annotation =
                    kind == EdgeKind::TypeRef && edge.position == Some(TypeRefPosition::Annotation);
                // G19 Task S2 (fail-closed): mirrors `is_property_annotation`
                // for CHAIN COLLECTION only — `alias_member_chain_gate_on`
                // is read once above, so with the gate unset this is always
                // `false` and the branch below is byte-identical to pre-S2.
                // Never feeds `is_param`/`mark_eligible` — see the function
                // doc comment's S2 paragraph.
                let is_alias_member_annotation = alias_member_chain_gate_on
                    && kind == EdgeKind::TypeRef
                    && edge.position == Some(TypeRefPosition::AliasMemberAnnotation);

                let (parent_chain, parent_probe_member_flag) =
                    chain_of.get(&node).cloned().unwrap_or_default();
                let mut source_chain = parent_chain;
                let mut ama_segment_minted = false;
                if is_property_annotation || is_alias_member_annotation {
                    if let Some(prop_name) =
                        property_key_before_type_ref(bundle, graph, source, edge.span)
                    {
                        source_chain.push(prop_name);
                        ama_segment_minted = is_alias_member_annotation;
                    }
                }

                // G1.10 D1: mint `probe_member_first_hop` ONLY on the
                // seed-adjacent (d0->d1) hop, and only when this hop
                // actually MINTED a chain segment via the AMA arm —
                // AMA-ONLY per the frozen §4-P width pin (a plain
                // `Annotation` hop off the seed, e.g. an INTERFACE member,
                // must NOT mint; see the interface-member negative
                // fixture). Tying the mint to the pushed segment (not the
                // bare position) keeps the flag co-extensive with the
                // chain provenance the emitted row's dotted path is built
                // from — a d1 AMA edge whose property key could not be
                // extracted contributes nothing to the path, so it also
                // asserts nothing about the row. `depth == 0` here means
                // `node` IS a seed: Contains-expansion is gated to
                // `depth >= 1` above, so depth-0 pops are exclusively the
                // seeds themselves — this check is equivalent to "the
                // parent is the seed" without needing a separate seed set.
                // Every other hop simply inherits the parent's own flag
                // (computed above, identical discipline to
                // `source_chain`), so once a closure's first hop off the
                // seed fails to mint, the flag can never become `true`
                // later at any deeper hop. With the S2 gate OFF,
                // `is_alias_member_annotation` is always `false`, so the
                // flag is `false` everywhere — the route token can never
                // exist in default output (fail-closed, no new env read).
                let source_probe_member_flag = if depth == 0 {
                    ama_segment_minted
                } else {
                    parent_probe_member_flag
                };

                if visited.insert(source) {
                    chain_of.insert(source, (source_chain.clone(), source_probe_member_flag));
                    if next_depth <= MAX_DEPTH {
                        queue.push_back((source, next_depth));
                    }
                    if dumps.path_enabled() {
                        parent_of.insert(
                            source,
                            WalkParent {
                                parent: node,
                                edge_kind: kind,
                                position: edge.position,
                                depth: next_depth,
                            },
                        );
                    }
                }

                if is_param
                    && next_depth <= MAX_DEPTH
                    && is_callable_node_kind(graph.node_kind(source))
                {
                    mark_eligible(
                        &mut eligible,
                        source,
                        next_depth,
                        &source_chain,
                        source_probe_member_flag,
                    );
                }
            }
        }
    }

    // G1.7 post-BFS admission pass (C-1): the BFS has fully drained, so
    // `container_probe_spans` is complete — no ordering hazard. Iteration
    // is over `expanded_containers` (deterministic pop order), and
    // `mark_eligible`'s min-depth semantics make the outcome
    // order-insensitive anyway.
    for (container, depth, chain, container_probe_member_flag) in expanded_containers {
        deadline.check()?;
        let spans: &[Span] = container_probe_spans
            .get(&container)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let children: Vec<(NodeId, Option<Span>)> = graph
            .outgoing(container, EdgeKind::Contains)
            .filter(|child| is_callable_node_kind(graph.node_kind(*child)))
            .map(|child| (child, graph.node_decl_span(child)))
            .collect();
        // C-3: `spans` are byte offsets in the CONTAINER's file; a child's
        // decl span is meaningful to compare only because a Contains child
        // lives in the same file as its container. `Span` carries no file
        // identity — never pool spans across containers (a flattened global
        // span set would manufacture cross-file false containment).
        let pinned: Vec<bool> = children
            .iter()
            .map(|(child, decl_span)| {
                debug_assert_eq!(
                    graph.file_of(*child),
                    graph.file_of(container),
                    "Contains child in a different file than its container \
                     — span containment against the container's recorded \
                     edge spans would be meaningless (C-3)"
                );
                match decl_span {
                    Some(ds) => spans.iter().any(|s| span_within(*s, *ds)),
                    None => false,
                }
            })
            .collect();
        let any_pinned = pinned.iter().any(|&p| p);
        for ((child, decl_span), child_pinned) in children.iter().zip(&pinned) {
            deadline.check()?;
            // C-4 recall fallback: when NO child is pinned by any recorded
            // span (heritage-header reach, decorator-argument reach,
            // span-less edges, spans-absent graphs), admit ALL children —
            // the pre-G1.7 unconditional behavior. A child with no decl
            // span of its own can never be pinned, so it is always
            // admitted (recall-safe).
            let admit = !any_pinned || *child_pinned || decl_span.is_none();
            if admit {
                mark_eligible(
                    &mut eligible,
                    *child,
                    depth,
                    &chain,
                    container_probe_member_flag,
                );
                // G19 Task S0: record the admitted membership for the
                // PATH dump's route-consistency flag — this is the ONE
                // place admission is decided, so recording here can
                // never drift from the guard's rules.
                if dumps.path_enabled() {
                    admitted_contains.insert((container, *child));
                }
            }
        }
    }

    let mut callables: Vec<(NodeId, u8, Vec<String>, bool)> = eligible
        .into_iter()
        .map(|(node, (depth, chain, flag))| (node, depth, chain, flag))
        .collect();
    // Deterministic emission order independent of HashMap iteration.
    callables.sort_by_key(|(node, _, _, _)| node.raw());

    // G19 Task S0 (`G19_PATH_DUMP` only): one row per eligible callable,
    // independent of whether the graph even has `Calls` edges — this is
    // about type-reachability, not the join below. The route-consistency
    // flag is computed HERE, where the eligibility rules live (see
    // `arrival_route_matches_eligibility`); `record_path` only
    // serializes it.
    if dumps.path_enabled() {
        for (callable, depth, _chain, _probe_member_flag) in &callables {
            deadline.check()?;
            let hops = reconstruct_seed_to_callable_path(&parent_of, graph, *callable);
            let route_matches_eligibility = arrival_route_matches_eligibility(
                parent_of.get(callable),
                *callable,
                *depth,
                &admitted_contains,
            );
            let callable_ref = CallableRef {
                id: *callable,
                kind: graph.node_kind(*callable),
                name: graph.node_name(*callable),
            };
            dumps.record_path(callable_ref, *depth, route_matches_eligibility, hops);
        }
    }

    let mut out = Vec::new();
    if !span_view.has_kind(EdgeKind::Calls) {
        dumps.flush();
        return Ok(out);
    }
    for (callable, depth, chain, probe_member_first_hop) in callables {
        deadline.check()?;
        let reversed_chain: Vec<String> = chain.into_iter().rev().collect();
        let dotted_path = reversed_chain.join(".");
        let callable_ref = CallableRef {
            id: callable,
            kind: graph.node_kind(callable),
            name: graph.node_name(callable),
        };

        let slots: Vec<u32> = graph.in_slots(callable, EdgeKind::Calls).collect();
        for (slot, edge) in slots
            .into_iter()
            .zip(span_view.in_edges(callable, EdgeKind::Calls))
        {
            deadline.check()?;
            let Some(caller_file) = graph.file_of(edge.source) else {
                continue;
            };
            let Some(call_span) = edge.span else {
                continue;
            };
            let Some(lc) = bundle.line_col(caller_file, call_span.start()) else {
                continue;
            };
            let owner = owner_name(graph, edge.source);

            // G19 Task S0 (`G19_ANCHOR_DUMP` only): every eligible-
            // callable `Calls` IN-edge, decoded regardless of whether
            // `reversed_chain` is empty below — the dump is meant to show
            // everything the walk COULD see, not just what it emitted.
            if dumps.anchor_enabled() {
                let anchors_for_dump = span_view.call_argument_anchors_from_in(slot);
                dumps.record_anchor_edge(
                    callable_ref,
                    graph.node_name(caller_file),
                    lc.line,
                    call_span,
                    &anchors_for_dump,
                );
            }

            push_consumer_call_site_row(
                &mut out,
                graph.node_name(caller_file).to_string(),
                lc.line,
                owner.clone(),
                depth,
                None,
            );
            dumps.record_route(
                RouteBranch::CallHead,
                callable_ref,
                depth,
                &dotted_path,
                graph.node_name(caller_file),
                lc.line,
            );

            if reversed_chain.is_empty() {
                continue;
            }
            // G1.10 D1: the route token is computed ONCE per (callable,
            // caller) pair, from the frozen predicate's two inputs — the
            // consumption gate (fail-closed: never emitted unless
            // `G19_ALIAS_MEMBER_CHAIN=1`) and this callable's own
            // `probe_member_first_hop` flag (minted only on a seed-adjacent
            // AMA hop, never re-derived here) — and applied ONLY at the
            // CallbackHead push below. The `ObjectKey`/`CallHead` branches
            // never carry a route (`None`, unconditionally): the predicate
            // is defined over `branch == CallbackHead` only (spec §4-P).
            let callback_head_route = if alias_member_chain_gate_on && probe_member_first_hop {
                Some(ROUTE_CALLBACK_HEAD_PROBE_MEMBER)
            } else {
                None
            };
            let mut pending_callbacks: Vec<Span> = Vec::new();
            for anchor in span_view.call_argument_anchors_from_in(slot) {
                deadline.check()?;
                match anchor {
                    CallArgumentAnchorView::CallbackHead { span, .. } => {
                        pending_callbacks.push(span);
                    }
                    CallArgumentAnchorView::ObjectKey { span, path, .. } => {
                        if path == dotted_path {
                            if let Some(lc) = bundle.line_col(caller_file, span.start()) {
                                push_consumer_call_site_row(
                                    &mut out,
                                    graph.node_name(caller_file).to_string(),
                                    lc.line,
                                    owner.clone(),
                                    depth,
                                    None,
                                );
                                dumps.record_route(
                                    RouteBranch::ObjectKey,
                                    callable_ref,
                                    depth,
                                    &dotted_path,
                                    graph.node_name(caller_file),
                                    lc.line,
                                );
                            }
                            for cb_span in &pending_callbacks {
                                if let Some(lc) = bundle.line_col(caller_file, cb_span.start()) {
                                    push_consumer_call_site_row(
                                        &mut out,
                                        graph.node_name(caller_file).to_string(),
                                        lc.line,
                                        owner.clone(),
                                        depth,
                                        callback_head_route,
                                    );
                                    dumps.record_route(
                                        RouteBranch::CallbackHead,
                                        callable_ref,
                                        depth,
                                        &dotted_path,
                                        graph.node_name(caller_file),
                                        lc.line,
                                    );
                                }
                            }
                        }
                        // A key's scope ends here regardless of match — the
                        // next callback(s) belong to whatever key follows.
                        pending_callbacks.clear();
                    }
                }
            }
        }
    }
    dumps.flush();
    deadline.check()?;
    Ok(out)
}

/// G19 Task S0 (`G19_PATH_DUMP` only): one first-arrival BFS discovery
/// edge — `WalkParent { parent, edge_kind, position, depth }` — the same
/// visited-gated semantics as `chain_of`. NOT necessarily the same edge
/// that ultimately won `mark_eligible`'s min-depth tie-break when a node
/// is reachable via multiple routes (the Contains expansion enqueues
/// children at the container's SAME depth at the back of the queue, so
/// queue depth is non-monotonic and first-arrival can record a different
/// edge/depth than the admission winner). Any such divergence is
/// SELF-FLAGGED on the emitted record: the hook site computes
/// `route_matches_eligibility` via `arrival_route_matches_eligibility`
/// (below, next to the eligibility rules it mirrors) and passes it into
/// `WalkDumps::record_path` — see the `walk_dumps` module doc's consumer
/// contract. `G19_PATH_DUMP` remains an opt-in diagnostic, never a
/// correctness dependency of this function's return value.
struct WalkParent {
    parent: NodeId,
    edge_kind: EdgeKind,
    position: Option<TypeRefPosition>,
    depth: u8,
}

/// G19 Task S0 (`G19_PATH_DUMP` only): is the callable's FIRST-ARRIVAL
/// edge the same route that made it ELIGIBLE? Computed HERE — next to
/// the eligibility rules it mirrors — never inside `walk_dumps` (that
/// module is pure serialization; a duplicated eligibility predicate
/// there would silently go stale as admission rules evolve).
///
/// G1.9 S2 confirmation: `G19_ALIAS_MEMBER_CHAIN` (once landed) affects
/// only CHAIN COLLECTION (`is_alias_member_annotation` in
/// `collect_consumer_call_site_pressure`, mirroring `is_property_annotation`)
/// — it never feeds `mark_eligible`, which stays exclusively `is_param`
/// (`TypeRef` @ `ParamAnnotation`) / Contains-admission gated, exactly as
/// documented below. This predicate's two arms therefore stay complete and
/// unchanged by S2 — there is no third eligibility route to add.
///
/// True iff the arrival depth equals the eligibility depth AND the
/// arrival edge is an ACTUAL eligibility route:
/// - `TypeRef` at RECORDED `ParamAnnotation` position — the `is_param`
///   gate's mark_eligible.
/// - `Contains` whose exact `(container, child)` membership the G1.7
///   post-BFS admission pass ADMITTED (`admitted_contains` is recorded
///   at the admission site). Edge shape alone is NOT enough: the guard
///   can REJECT the very membership the arrival displays
///   (`admit = !any_pinned || *child_pinned || decl_span.is_none()`)
///   while the callable is independently eligible at the same depth via
///   its own param edge (that `mark_eligible` fires outside the visited
///   gate) — checking shape would read `true` for exactly that
///   misrepresenting route.
///
/// `None` arrival (a seed, or a node the parent tracking never saw)
/// reads `false` — seeds are never eligible, and "cannot verify" must
/// never report as "verified".
fn arrival_route_matches_eligibility(
    arrival: Option<&WalkParent>,
    callable: NodeId,
    eligibility_depth: u8,
    admitted_contains: &HashSet<(NodeId, NodeId)>,
) -> bool {
    let Some(arrival) = arrival else {
        return false;
    };
    if arrival.depth != eligibility_depth {
        return false;
    }
    match arrival.edge_kind {
        EdgeKind::TypeRef => arrival.position == Some(TypeRefPosition::ParamAnnotation),
        EdgeKind::Contains => admitted_contains.contains(&(arrival.parent, callable)),
        _ => false,
    }
}

/// Reconstructs the seed→`callable` path from `parent_of` (see
/// `WalkParent`'s doc comment for the first-arrival-wins caveat). The
/// first hop (index 0) is always a seed — `chain_of`/`parent_of` never
/// record an entry for a seed itself (seeds are inserted directly into
/// `visited`/`queue`, bypassing both parent-tracking insertion points
/// above).
fn reconstruct_seed_to_callable_path(
    parent_of: &HashMap<NodeId, WalkParent>,
    graph: &CodeGraph<'_>,
    callable: NodeId,
) -> Vec<PathHopInput> {
    let mut hops = Vec::new();
    let mut current = callable;
    loop {
        match parent_of.get(&current) {
            Some(edge) => {
                hops.push(PathHopInput {
                    node_id: current,
                    node_kind: graph.node_kind(current),
                    node_name: graph.node_name(current).to_string(),
                    edge_kind: Some(edge.edge_kind),
                    position: edge.position,
                    depth: edge.depth,
                });
                current = edge.parent;
            }
            None => {
                hops.push(PathHopInput {
                    node_id: current,
                    node_kind: graph.node_kind(current),
                    node_name: graph.node_name(current).to_string(),
                    edge_kind: None,
                    position: None,
                    depth: 0,
                });
                break;
            }
        }
    }
    hops.reverse();
    hops
}

fn mark_eligible(
    eligible: &mut HashMap<NodeId, (u8, Vec<String>, bool)>,
    node: NodeId,
    depth: u8,
    chain: &[String],
    probe_member_first_hop: bool,
) {
    eligible
        .entry(node)
        .and_modify(|(d, c, f)| {
            if depth < *d {
                *d = depth;
                *c = chain.to_vec();
                *f = probe_member_first_hop;
            }
        })
        .or_insert_with(|| (depth, chain.to_vec(), probe_member_first_hop));
}

/// True when `inner` lies entirely within `outer`. Both spans MUST be byte
/// offsets into the SAME file — the caller (the G1.7 post-BFS admission
/// pass) guarantees this by only ever comparing a container's own recorded
/// edge spans against decl spans of that SAME container's children (C-3):
/// `Span` carries no file identity, so comparing spans from different files
/// would manufacture false containment from coincidentally-overlapping
/// offsets.
fn span_within(inner: Span, outer: Span) -> bool {
    inner.start() >= outer.start() && inner.end() <= outer.end()
}

fn is_container_node_kind(kind: NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::Class | NodeKind::Interface | NodeKind::TypeAlias
    )
}

/// Function | Class | Variable (const-arrow) | Property (method) — spec D2's
/// callable set. `Property` also covers getters/setters/fields (this
/// codebase never persists `MemberKind` past parse time, see the function
/// doc comment above), but in practice only method-shaped properties ever
/// carry a `ParamAnnotation` in-edge at all — a getter/field/plain-setter
/// has no parameter LIST for the parser to tag, so the position gate above
/// already does the real restricting for the non-Contains-expansion path.
fn is_callable_node_kind(kind: NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::Function | NodeKind::Class | NodeKind::Variable | NodeKind::Property
    )
}

fn owner_name(graph: &CodeGraph<'_>, source: NodeId) -> Option<String> {
    match graph.node_kind(source) {
        NodeKind::ModuleInit | NodeKind::File => None,
        _ => Some(graph.node_name(source).to_string()),
    }
}

fn push_consumer_call_site_row(
    out: &mut Vec<CompilerPressureCandidate>,
    file: String,
    line: u32,
    owner: Option<String>,
    depth: u8,
    route: Option<&'static str>,
) {
    let sort_key = (
        CompilerPressureLevel::Medium.sort_rank(),
        2,
        owner.clone().unwrap_or_default(),
    );
    out.push(CompilerPressureCandidate {
        evidence: CompilerPressureEvidence {
            file,
            line,
            level: CompilerPressureLevel::Medium,
            reason: CompilerPressureReason::ConsumerCallSite,
            owner,
            sub_channel: CompilerPressureSubChannel::ConsumerCallSite { depth, route },
            direct_evidence: false,
        },
        sort_key,
    });
}

/// Extract the identifier immediately before a trailing `:`/`?:` on the
/// source line up to (not including) `span`'s start byte — i.e. the
/// property/param name a `TypeRefPosition::Annotation` edge's reference sits
/// in. Returns `None` when no such pattern precedes the reference (e.g. a
/// body-local `const x: T` still matches — the property-name extraction
/// itself doesn't distinguish local-var-vs-property; that distinction is
/// already made upstream by requiring `ParamAnnotation`, not `Annotation`,
/// for eligibility, so a body-local's spuriously-collected "name" is inert
/// dead data — the enclosing node it decorates never becomes eligible).
fn property_key_before_type_ref(
    bundle: &SourceBundle<'_>,
    graph: &CodeGraph<'_>,
    source: NodeId,
    span: Option<Span>,
) -> Option<String> {
    let span = span?;
    let file = graph.file_of(source)?;
    let bytes = bundle.source_bytes(file)?;
    let start = (span.start() as usize).min(bytes.len());
    let mut line_start = start;
    while line_start > 0 && bytes[line_start - 1] != b'\n' {
        line_start -= 1;
    }
    let prefix = String::from_utf8_lossy(&bytes[line_start..start]);
    let trimmed = prefix.trim_end();
    let before_colon = trimmed.strip_suffix(':')?;
    let key_part = before_colon.trim_end();
    let key_part = key_part.strip_suffix('?').unwrap_or(key_part).trim_end();
    let ident_start = key_part
        .char_indices()
        .rev()
        .take_while(|(_, c)| is_property_key_char(*c))
        .last()
        .map(|(i, _)| i)?;
    let ident = &key_part[ident_start..];
    if ident.is_empty() {
        None
    } else {
        Some(ident.to_string())
    }
}

fn is_property_key_char(c: char) -> bool {
    c == '_' || c == '$' || c.is_ascii_alphanumeric()
}

fn classify_compiler_pressure(
    kind: EdgeKind,
    line: &str,
    name: &str,
) -> Option<(CompilerPressureLevel, CompilerPressureReason)> {
    match kind {
        EdgeKind::Extends | EdgeKind::Implements => Some((
            CompilerPressureLevel::High,
            CompilerPressureReason::HeritageContract,
        )),
        EdgeKind::TypeRef => classify_type_ref_pressure_line(line, name).or(Some((
            CompilerPressureLevel::Low,
            CompilerPressureReason::TypeReference,
        ))),
        _ => None,
    }
}

fn classify_type_ref_pressure_line(
    line: &str,
    name: &str,
) -> Option<(CompilerPressureLevel, CompilerPressureReason)> {
    let has_satisfies = line.contains("satisfies");
    let has_layer =
        line.contains("Layer") || line.contains("Effect") || line.contains("Context.Tag");
    if has_satisfies && has_layer {
        return Some((
            CompilerPressureLevel::High,
            CompilerPressureReason::SatisfiesLayerProviderTypeContract,
        ));
    }
    if has_satisfies {
        return Some((
            CompilerPressureLevel::High,
            CompilerPressureReason::SatisfiesTypeContract,
        ));
    }
    if has_layer {
        return Some((
            CompilerPressureLevel::High,
            CompilerPressureReason::LayerProviderTypeContract,
        ));
    }
    if is_conditional_type_contract(line, name) {
        return Some((
            CompilerPressureLevel::High,
            CompilerPressureReason::ConditionalTypeContract,
        ));
    }
    if is_mapped_keyof_or_indexed_contract(line, name) {
        return Some((
            CompilerPressureLevel::High,
            CompilerPressureReason::MappedKeyofIndexedTypeContract,
        ));
    }
    if is_generic_constraint(line, name) {
        return Some((
            CompilerPressureLevel::High,
            CompilerPressureReason::GenericConstraint,
        ));
    }
    if is_return_type_contract(line, name) {
        return Some((
            CompilerPressureLevel::High,
            CompilerPressureReason::ReturnTypeContract,
        ));
    }
    if is_parameter_or_property_annotation(line, name) {
        return Some((
            CompilerPressureLevel::Medium,
            CompilerPressureReason::ParameterPropertyAnnotation,
        ));
    }
    if line.contains('<') && line.contains('>') {
        return Some((
            CompilerPressureLevel::Medium,
            CompilerPressureReason::GenericTypeArgument,
        ));
    }
    None
}

fn is_conditional_type_contract(line: &str, name: &str) -> bool {
    line_mentions_identifier(line, name) && line.contains(" extends ") && line.contains('?')
}

fn is_mapped_keyof_or_indexed_contract(line: &str, name: &str) -> bool {
    if !line_mentions_identifier(line, name) {
        return false;
    }
    let has_keyof = line_mentions_identifier(line, "keyof");
    let has_mapped = line.contains('[') && line.contains(" in ") && has_keyof;
    let has_indexed_access = any_identifier_occurrence(line, name, |_, end| {
        line[end..].trim_start().starts_with('[')
    });
    has_mapped || has_indexed_access || has_keyof
}

fn is_generic_constraint(line: &str, name: &str) -> bool {
    line_mentions_identifier(line, name)
        && line.contains('<')
        && line.contains('>')
        && line.contains(" extends ")
}

fn is_return_type_contract(line: &str, name: &str) -> bool {
    any_identifier_occurrence(line, name, |start, _| {
        let prefix = line[..start].trim_end();
        let Some(before_colon) = prefix.strip_suffix(':') else {
            return false;
        };
        before_colon.trim_end().ends_with(')')
    })
}

fn is_parameter_or_property_annotation(line: &str, name: &str) -> bool {
    any_identifier_occurrence(line, name, |start, _| {
        let prefix = line[..start].trim_end();
        if !prefix.ends_with(':') {
            return false;
        }
        !is_return_type_contract(line, name)
    })
}
