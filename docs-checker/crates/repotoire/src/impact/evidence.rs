//! Per-symbol `ImpactEvidence` extractor.
//!
//! Returns structured native evidence instead of Markdown. The shape is fixed
//! at the data layer so ordinary impact output, live deltas, and witness
//! adapters can consume it without coupling to Markdown.
//!
//! What this is NOT: a re-extraction. Both this extractor and the Markdown
//! one read the same `SourceBundle`. Behavior parity with the Markdown
//! renderer is locked by `crates/repotoire/tests/live_evidence.rs` for the
//! canonical providers.ts / index.ts case.
//!
//! `signature_hash` lives here too because the surface-bytes definition
//! ("decl span minus body span, whitespace+comments normalized") belongs
//! to the evidence layer. D2/D3 import it.

use crate::archive::SourceBundle;
use crate::csr::{CodeGraph, InEdge, SpanView};
use crate::ids::NodeId;
use crate::impact::compiler_pressure::collect_compiler_pressure;
use crate::impact::deadline::{ImpactDeadline, ImpactDeadlineExceeded, NO_IMPACT_DEADLINE};
use crate::impact::provider_context::collect_provider_context_evidence;
use crate::impact::service_dispatch::collect_service_method_dispatch;
use crate::schema::{EdgeKind, NodeKind};
use crate::source_pipeline::{source_language_for_path, SourceLanguage};
use crate::spans::{LineCol, Span};
use crate::ts::lexer::{Lexer, Token, TokenKind};
use std::collections::HashSet;
use std::path::Path;

pub use crate::impact::provider_context::{ProviderContextEvidence, ProviderContextKind};
pub use crate::impact::service_dispatch::{
    ServiceDispatchTraceStep, ServiceMethodDispatchKind, ServiceMethodDispatchSite,
};

/// Structured impact view for one symbol. Ordering of each `Vec` is
/// deterministic (see field docs); two extractions over the same bundle
/// produce equal `ImpactEvidence`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ImpactEvidence {
    /// The bare symbol name (no `:file:line` disambiguator).
    pub symbol: String,
    /// The declaration this evidence describes. A successful
    /// [`ImpactResolution::Found`] lookup always populates this.
    pub definition: Option<DefinitionEvidence>,
    /// Files that bring this name into scope via `import { name }` (named
    /// specifier, possibly aliased). Excludes namespace imports
    /// (`import * as P`) — a rename of the imported symbol doesn't touch
    /// the namespace-import line. Sorted by (file, line).
    pub imports: Vec<RelationEvidence>,
    /// Files that re-export this decl via `export { name } from …` (named)
    /// or `export * from …` (wildcard expansion). Same-file Exports edges
    /// (the original declaration) are excluded. Sorted by (file, line,
    /// public_alias).
    pub exports: Vec<RelationEvidence>,
    /// In-tree call / value-ref / type-ref / extends / implements use-sites.
    /// Same-file self-references inside the decl's own ModuleInit are
    /// suppressed to preserve ordinary impact semantics. Sorted by (file, line,
    /// kind_tag, owner).
    pub uses: Vec<RelationEvidence>,
    /// Source-level dynamic reachability evidence for the declaration's
    /// module. These rows do not replace symbol-specific imports/uses; they
    /// tell agents when the module is reachable through literal or bounded
    /// dynamic loading. Sorted by (source_file, source_line, source_span,
    /// evidence kind).
    pub dynamic_reachability: Vec<DynamicReachabilityEvidence>,
    /// Source-visible service dispatch rows inferred from module bindings,
    /// service acquisition calls, and destructured service-method bindings.
    pub service_dispatch: Vec<ServiceMethodDispatchSite>,
    /// Provider/context rows inferred by joining service dispatch rows against
    /// source-visible provider declarations and compositions.
    pub provider_context: Vec<ProviderContextEvidence>,
    /// Type-checking pressure sites inferred from source relationships, such
    /// as heritage clauses, `satisfies`, generic constraints, and type
    /// annotations. Sorted by (file, line, level, evidence source, reason).
    pub compiler_pressure: Vec<CompilerPressureEvidence>,
    /// Repo-wide lower-bound signals for unresolved call/reference sites that
    /// can make scanned dependents incomplete even when a queried symbol's
    /// resolved rows look complete.
    pub unresolved_blind_spots: Vec<UnresolvedBlindSpotEvidence>,
    /// Locked disclaimers that must reach the agent with every emission.
    /// Always non-empty; always begins with the four global limitations
    /// (External, MemberDispatch, Dynamic, UnresolvedBindings).
    pub limitations: Vec<Limitation>,
}

/// Where a symbol is declared.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DefinitionEvidence {
    /// Snapshot-local identity of the resolved declaration. Verification uses
    /// this exact node instead of resolving the raw query a second time.
    #[serde(skip)]
    pub node_id: NodeId,
    /// The declaration's own source name. This can differ from
    /// [`ImpactEvidence::symbol`] when the lookup matched an import or
    /// export alias.
    pub name: String,
    /// File path relative to the project root, as stored on the File node.
    pub file: String,
    /// 1-based line containing the declaration's source name.
    pub line: u32,
    /// What kind of declaration this is.
    pub kind: DeclKind,
    /// Outgoing `extends` / `implements` declaration names for display and
    /// disambiguation. Empty for non-heritage declarations.
    pub heritage: Vec<DefinitionHeritageEvidence>,
    /// Stable hash of the decl's *surface* bytes — decl span minus body
    /// span, whitespace and comment runs collapsed. Two extractions of the
    /// same source produce the same hash; a body-only edit does not change
    /// it; a parameter-list edit does. See [`signature_hash`].
    pub signature_hash: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct DefinitionHeritageEvidence {
    pub kind: DefinitionHeritageKind,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum DefinitionHeritageKind {
    Extends,
    Implements,
}

/// One inbound relationship to (or outbound from) a decl.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RelationEvidence {
    /// Exact incoming endpoint in this capture. Never a durable identifier.
    #[serde(skip)]
    pub source_node: Option<NodeId>,
    /// What kind of relationship the source file has to the decl.
    pub kind: RelationKind,
    /// File path of the relationship's source-side (the importing /
    /// re-exporting / calling file). For self-edges (rare), this is the
    /// decl's own file.
    pub file: String,
    /// 1-based line of the relationship's source-side span (the importing
    /// statement, the call expression, the type reference site). `0` only
    /// if the span couldn't be located — defensive; should not happen for
    /// post-resolver edges.
    pub line: u32,
    /// Source-side declaration name qualified by its recorded lexical
    /// containers, e.g. `Some("Panel.render")`. This identifies the graph's
    /// call-site owner, not a runtime receiver or method-resolution result.
    /// `None` for ModuleInit / File sources or an unprovable containment path.
    pub owner: Option<String>,
}

/// Dynamic reachability row for one impacted declaration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DynamicReachabilityEvidence {
    pub source_file: String,
    pub source_line: u32,
    pub source_span: SourceSpanOffsets,
    pub target_file: String,
    pub caveat: DynamicReachabilityCaveat,
    pub kind: DynamicReachabilityKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub struct SourceSpanOffsets {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum DynamicReachabilityKind {
    VerifiedModuleLoad {
        loader: DynamicLoader,
    },
    PossibleTemplateModuleLoad {
        loader: DynamicLoader,
        pattern: String,
    },
    VerifiedRegistryExport {
        key: String,
        export_name: String,
        loader: DynamicLoader,
    },
    PossibleTemplateRegistryExport {
        key: String,
        export_name: String,
        loader: DynamicLoader,
        pattern: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum DynamicLoader {
    ImportCall,
    RequireCall,
}

impl DynamicLoader {
    pub fn label(self) -> &'static str {
        match self {
            DynamicLoader::ImportCall => "import()",
            DynamicLoader::RequireCall => "require()",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum DynamicReachabilityCaveat {
    ExportDispatchNotProven,
    RuntimeKeySelectionNotProven,
}

/// Source-grounded compiler/type-checking pressure for one declaration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CompilerPressureEvidence {
    pub file: String,
    pub line: u32,
    pub level: CompilerPressureLevel,
    pub reason: CompilerPressureReason,
    pub owner: Option<String>,
    pub sub_channel: CompilerPressureSubChannel,
    pub direct_evidence: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
pub enum CompilerPressureLevel {
    Low,
    Medium,
    High,
}

impl CompilerPressureLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub(super) fn sort_rank(self) -> u8 {
        match self {
            Self::High => 0,
            Self::Medium => 1,
            Self::Low => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
pub enum CompilerPressureReason {
    HeritageContract,
    SatisfiesLayerProviderTypeContract,
    SatisfiesTypeContract,
    LayerProviderTypeContract,
    ConditionalTypeContract,
    MappedKeyofIndexedTypeContract,
    GenericConstraint,
    ReturnTypeContract,
    ParameterPropertyAnnotation,
    GenericTypeArgument,
    TypeReference,
    /// G1.6 W1 — a consumer call site (or argument-interior anchor) reached
    /// by the type-closure ∘ Calls join in `collect_consumer_call_site_pressure`.
    /// Distinct from every other reason above: those all classify a DIRECT
    /// textual reference to the queried symbol; this one never does (the
    /// call site's own line never mentions the symbol — `direct_evidence`
    /// is always `false` for these rows, see that field's row).
    ConsumerCallSite,
}

impl CompilerPressureReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::HeritageContract => "heritage contract",
            Self::SatisfiesLayerProviderTypeContract => "satisfies Layer/provider type contract",
            Self::SatisfiesTypeContract => "satisfies type contract",
            Self::LayerProviderTypeContract => "Layer/provider type contract",
            Self::ConditionalTypeContract => "conditional type contract",
            Self::MappedKeyofIndexedTypeContract => "mapped/keyof/indexed type contract",
            Self::GenericConstraint => "generic constraint",
            Self::ReturnTypeContract => "return type contract",
            Self::ParameterPropertyAnnotation => "parameter/property annotation",
            Self::GenericTypeArgument => "generic type argument",
            Self::TypeReference => "type reference",
            Self::ConsumerCallSite => "consumer call site (transitive parameter surface)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
pub enum CompilerPressureSubChannel {
    TypeSurface,
    Transitive,
    /// G1.5 Fix 2 (F2-3): report-only demotion for `TypeRef` sites whose
    /// parse-time position is `ConstraintDecl` or `CompositionMember` (spec
    /// Appendix A demotion rule) — dependency-shaped, not necessarily under
    /// compiler PRESSURE (spec §2.2). Rows stay in the rendered report but
    /// are excluded from `type_surface` gating (the existing `sub_channel
    /// != "type_surface"` filter in the gate1 python scorer already treats
    /// any non-`type_surface` label this way — no gate-side change needed).
    TypeDependency,
    /// G1.6 W1 (spec D5): a consumer call site (or argument-interior
    /// anchor) reached by the type-closure ∘ Calls join in
    /// `compiler_pressure::collect_consumer_call_site_pressure` — see that
    /// function's doc comment for the walk. `depth` is the TypeRef-closure
    /// hop count from the queried symbol to the callable whose `Calls`
    /// in-edge produced this row (Contains-expansion hops are hop-neutral
    /// and do not increment it; capped at 4).
    ///
    /// Distinct label (`"consumer_call_site"`, never `"type_surface"`) is
    /// the ENTIRE basis-OFF mechanism (spec D6): the gate1 scorer's
    /// existing `sub_channel != "type_surface"` filter already excludes any
    /// non-`type_surface` label from the certified set, so this sub-channel
    /// needs no scorer change to stay non-gating — a later task (H1) adds
    /// the opt-in scoring lever that flips it ON at a fitted depth cutoff.
    ///
    /// `route` (G1.10 D1): `Some(ROUTE_CALLBACK_HEAD_PROBE_MEMBER)` on a
    /// `CallbackHead`-branch row whose eligible callable's probe-adjacent
    /// (d0->d1) walk hop is a member-annotation `TypeRef` — the frozen
    /// predicate in `docs/superpowers/specs/2026-07-07-gate1-g110-hook-callback-discrimination-design.md`
    /// §4-P (AMA-only width pin). `None` on every other row, and on EVERY
    /// row when `G19_ALIAS_MEMBER_CHAIN` is unset (fail-closed — see
    /// `compiler_pressure::alias_member_chain_gate_enabled`). This field is
    /// render-side data only, never persisted (no `serde` derive on this
    /// type; D1's no-persistence audit — GRAPH/EVENTS format versions are
    /// unaffected).
    ConsumerCallSite {
        depth: u8,
        route: Option<&'static str>,
    },
}

/// G1.10 D1: the sole route token, threaded from
/// `compiler_pressure::collect_consumer_call_site_pressure`'s CallbackHead
/// emission site through `CompilerPressureSubChannel::ConsumerCallSite`'s
/// `route` field to the render site
/// (`render::impact`, the ` route={token}` text token next to ` depth=N`).
/// One named constant, not a literal repeated at each use site, so the
/// Rust-side token and any future consumer can never drift from each other.
pub const ROUTE_CALLBACK_HEAD_PROBE_MEMBER: &str = "callback_head_probe_member";

impl CompilerPressureSubChannel {
    pub fn label(self) -> &'static str {
        match self {
            Self::TypeSurface => "type_surface",
            Self::Transitive => "transitive",
            Self::TypeDependency => "type_dependency",
            Self::ConsumerCallSite { .. } => "consumer_call_site",
        }
    }
}

/// Ambient unresolved-site lower bound for the scanned tree.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UnresolvedBlindSpotEvidence {
    pub scope: UnresolvedBlindSpotScope,
    pub unresolved_callsite_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum UnresolvedBlindSpotScope {
    RepoWide,
}

/// Decl kinds that an impact briefing's symbol can resolve to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum DeclKind {
    Module,
    Class,
    Struct,
    Union,
    Interface,
    TypeAlias,
    Enum,
    Function,
    Variable,
    Property,
}

impl DeclKind {
    /// Subset of [`NodeKind`] that maps to a briefable decl. Returns
    /// `None` for File / EnumMember / Unresolved / ModuleInit / External —
    /// those don't have an "impact" the live runtime tracks.
    pub fn from_node_kind(k: NodeKind) -> Option<Self> {
        Some(match k {
            NodeKind::Class => Self::Class,
            NodeKind::Struct => Self::Struct,
            NodeKind::Union => Self::Union,
            NodeKind::Module => Self::Module,
            NodeKind::Interface => Self::Interface,
            NodeKind::TypeAlias => Self::TypeAlias,
            NodeKind::Enum => Self::Enum,
            NodeKind::Function => Self::Function,
            NodeKind::Variable => Self::Variable,
            NodeKind::Property => Self::Property,
            _ => return None,
        })
    }

    /// Human-readable keyword for the additional-context renderer (D4).
    pub fn as_keyword(self) -> &'static str {
        match self {
            Self::Module => "module",
            Self::Class => "class",
            Self::Struct => "struct",
            Self::Union => "union",
            Self::Interface => "interface",
            Self::TypeAlias => "type",
            Self::Enum => "enum",
            Self::Function => "function",
            Self::Variable => "variable",
            Self::Property => "property",
        }
    }
}

/// The kind of relationship a file has to a decl.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub enum RelationKind {
    /// `import { name }` or `import { name as Local }` — must edit on rename.
    NamedImport,
    /// `export { name } from "./mod"` (or aliased `export { name as Public }`).
    /// `public_alias` is the public-facing name (`Public`) when aliased,
    /// otherwise `name`. A rename of the decl requires editing this line.
    NamedReExport { public_alias: String },
    /// `export * from "./mod"` — picks up the new name automatically; no
    /// edit needed for a rename.
    WildcardReExport,
    /// Call expression.
    Call,
    /// Value-position reference (read, write, init use).
    ValueRef,
    /// Type-position reference.
    TypeRef,
    /// `class Derived extends Base`.
    Extends,
    /// `class Impl implements Iface`.
    Implements,
}

impl RelationKind {
    /// Sort-tag for deterministic ordering within a single (file, line).
    /// Lower tags sort first.
    fn sort_tag(&self) -> u8 {
        match self {
            Self::NamedImport => 0,
            Self::NamedReExport { .. } => 1,
            Self::WildcardReExport => 2,
            Self::Call => 3,
            Self::ValueRef => 4,
            Self::TypeRef => 5,
            Self::Extends => 6,
            Self::Implements => 7,
        }
    }
}

/// One disclaimer line. The four locked global limitations are emitted for
/// every result. `TsxNotScanned` remains deserializable for v1 compatibility
/// but is not emitted now that `.tsx` uses the supported TypeScript backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Limitation {
    /// This result covers admitted inputs only, irrespective of hidden rows.
    RestrictedReadScope,
    /// The producer does not retain a complete admitted-input proof.
    ProvenanceUnavailable {
        family: String,
    },
    ExternalConsumers,
    MemberDispatch,
    Dynamic,
    UnresolvedBindings,
    /// Preserved v1 variant for historical evidence written before `.tsx`
    /// used the supported TypeScript backend.
    TsxNotScanned,
    /// Extraction produced diagnostics that may weaken confidence in the
    /// evidence. Carries a deduped count for the renderer to surface.
    Diagnostics {
        count: u32,
    },
}

/// v0.7 commit 6a — per-capability member-dispatch limitation variants.
///
/// The monolithic `MEMBER_DISPATCH_LIMITATION_TEXT` (~1700 chars at
/// v0.7) had grown past the 2 KB payload cap, triggering Coverage-
/// block truncation. The fix: split into per-capability variants,
/// each with a short summary (~80 bytes, emitted in the Coverage
/// bullet) and a longer canonical text (~200-300 bytes, written to
/// `~/.repotoire/limitations/<id>.md` for agent on-demand `Read`).
///
/// Steady-state per-payload Coverage cost: ~9 × 80 bytes ≈ 720 bytes.
/// Each new milestone adds a new variant (~80 bytes summary) without
/// growing the cumulative monolith.
///
/// Variant taxonomy:
/// - Tier 1 (Resolved): four variants summarize what the IR resolves
///   today, grouped by milestone-introduced capability.
/// - Tier 2 (Out of scope): five variants summarize what the IR does
///   NOT resolve, grouped by underlying flow-analysis class.
///
/// The byte-equality CI (`tests/limitation_copy_consistency.rs`)
/// asserts each variant's summary appears verbatim in all three
/// agent-facing surfaces (live render, static impact briefing,
/// plugin skill SKILL.md). Drift on any single variant fails CI.
///
/// File-based lazy-load (per the v0.7 design): renderers write the
/// canonical text to `~/.repotoire/limitations/<id>.md` (idempotent;
/// content overwrites only when canonical changes). Coverage bullets
/// emit the summary + the path. Agents have the `Read` tool and can
/// dereference any path on demand — no protocol invention; no new
/// agent-runtime contract.
///
/// MCP forward-compat note: if repotoire later exposes an MCP server
/// (v0.9+ candidate), the canonical-text files become MCP Resource
/// content directly. Variant IDs become Resource URIs
/// (`repotoire://limitations/<id>`). Zero rework — wrap the existing
/// files in an MCP server interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum MemberDispatchVariant {
    /// v0.5 — receiver-pattern shapes resolved (Patterns 1, 2, 3a,
    /// 3b, P, 4, 7).
    ReceiverPatterns,
    /// v0.6 — factory-return inference (Pattern F).
    FactoryReturn,
    /// v0.7 — property-chain receivers (Pattern PC).
    PropertyChain,
    /// v0.5 — accessors (getter Read / setter Write), fields,
    /// compound assignments (read+write at same site), and the
    /// declared-type-wins conflict rule.
    AccessorsFieldsAndConflictRule,
    /// Out of scope: factory-shape gaps (aliased, chained,
    /// instance-method, body-inferred, overloaded, union/non-Ident,
    /// subclass-returning factories).
    OutOfScopeFactoryGaps,
    /// Out of scope: chain-shape gaps (depth > 4 and reassigned fields).
    OutOfScopeChainGaps,
    /// Out of scope: inheritance + generics (subclass dynamic
    /// dispatch, generics beyond strip-and-capture).
    OutOfScopeInheritanceGenerics,
    /// Out of scope: dynamic shapes + remaining parser gaps
    /// (non-constant bracket keys, eval/dynamic property access,
    /// computed decorators / decorated abstract declarations).
    OutOfScopeDynamicAndDecorators,
    /// Out of scope: miscellaneous (destructured binders, return-
    /// value flow, visibility modifiers).
    OutOfScopeMisc,
}

impl MemberDispatchVariant {
    /// Every variant in canonical iteration order. Order is stable:
    /// Resolved first (Tier 1), Out of scope second (Tier 2), each
    /// group ordered by introduction milestone. Renderers iterate
    /// this slice.
    pub fn all() -> &'static [MemberDispatchVariant] {
        use MemberDispatchVariant::*;
        &[
            ReceiverPatterns,
            FactoryReturn,
            PropertyChain,
            AccessorsFieldsAndConflictRule,
            OutOfScopeFactoryGaps,
            OutOfScopeChainGaps,
            OutOfScopeInheritanceGenerics,
            OutOfScopeDynamicAndDecorators,
            OutOfScopeMisc,
        ]
    }

    /// Stable kebab-case identifier. Doubles as the filename stem
    /// for on-disk canonical text (`<id>.md`) and as the
    /// future-MCP-Resource URI segment (`repotoire://limitations/<id>`).
    /// MUST be stable across releases — agents cache by ID.
    pub fn id(&self) -> &'static str {
        use MemberDispatchVariant::*;
        match self {
            ReceiverPatterns => "receiver-patterns",
            FactoryReturn => "factory-return",
            PropertyChain => "property-chain",
            AccessorsFieldsAndConflictRule => "accessors-fields-conflict-rule",
            OutOfScopeFactoryGaps => "out-of-scope-factory-gaps",
            OutOfScopeChainGaps => "out-of-scope-chain-gaps",
            OutOfScopeInheritanceGenerics => "out-of-scope-inheritance-generics",
            OutOfScopeDynamicAndDecorators => "out-of-scope-dynamic-and-decorators",
            OutOfScopeMisc => "out-of-scope-misc",
        }
    }

    /// Short summary for the Coverage bullet. ~50-70 bytes per
    /// variant — sized to the per-bullet design budget so 9
    /// variants + 4 other limitations + scaffold + 2 KB-cap
    /// safety margin all fit under MAX_PAYLOAD_BYTES with
    /// headroom for dependent enumeration. Each summary is
    /// byte-stable across releases (the byte-equality CI
    /// enforces this); update only when a real capability ships.
    /// Full per-variant detail (examples, edge cases) lives in
    /// `canonical()` and is exposed via lazy-load.
    pub fn summary(&self) -> &'static str {
        use MemberDispatchVariant::*;
        match self {
            ReceiverPatterns => "Resolved: `this` / static / `new C()` / `const x = new C()` / typed binder.",
            FactoryReturn => "Resolved: factory return (plain / const-arrow / generic / static-method).",
            PropertyChain => "Resolved: `this.f.m()` / `obj.f.m()` chains, depth ≤ 4, including init/return/arg.",
            AccessorsFieldsAndConflictRule => "Resolved: accessors / fields / compound assigns; declared-type wins.",
            OutOfScopeFactoryGaps => "Out of scope: aliased / chained / instance-method / body-inferred / union factories.",
            OutOfScopeChainGaps => "Out of scope: chains > 4 hops and reassigned fields.",
            OutOfScopeInheritanceGenerics => "Out of scope: subclass dynamic dispatch, generics beyond strip-and-capture.",
            OutOfScopeDynamicAndDecorators => "Out of scope: dynamic bracket keys, eval, computed/abstract decorator gaps.",
            OutOfScopeMisc => "Out of scope: destructured binders, return-value flow, visibility modifiers.",
        }
    }

    /// Full canonical text for the on-disk file. Longer-form
    /// explanation with concrete examples. Written to
    /// `~/.repotoire/limitations/<id>.md`. Stable across releases
    /// per the byte-equality CI; update only when capability ships.
    pub fn canonical(&self) -> &'static str {
        use MemberDispatchVariant::*;
        match self {
            ReceiverPatterns => "# Member-dispatch: receiver patterns resolved (v0.5)\n\nRepotoire resolves `x.m()` / `x.m` / `x.m = …` (including `x['m']` bracket access) when the receiver is one of:\n\n- `this` (Pattern 4 — `this.method()` inside a class body)\n- A class name for genuine static dispatch (Pattern 7 — `Class.staticM()`)\n- `new C(…)` directly (Pattern 1 — `new C().m()`)\n- `const x = new C(…)` local (Pattern 2 — Construction-origin binding)\n- `let x: C` or `const x: C = …` (Patterns 3a / 3b — ExplicitType binding)\n- `function f(x: C)` typed parameter (Pattern P)\n\nCross-file shapes resolve through value-namespace import lookup (for class-name receivers + Constructed origins) or type-namespace import lookup (for ExplicitType origins). The MethodKind gate enforces `is_static` matching so an instance method called via the class name does NOT resolve.\n",
            FactoryReturn => "# Member-dispatch: factory-return inference (v0.6 — Pattern F)\n\nRepotoire resolves `x.m()` when `x` is initialized by a factory call whose declared return type is a plain-Ident class:\n\n- Plain function factory: `function makeClient(): Client { … }; const c = makeClient(); c.send()`\n- Const-arrow factory: `const makeClient = (): Client => …; const c = makeClient(); c.send()`\n- Generic factory (strip-and-capture): `function makeBox<T>(): Box<T> { … }` resolves to `Box`\n- Static-method factory: `class Schema { static create(): Schema { … } }; const s = Schema.create(); s.parse()`\n\nCross-file factories resolve through value-namespace import lookup + the factory-file's type namespace (the return-class Ident is named in the factory's own file, not the consumer's). Conflict rule: explicit declared type wins (`const x: Base = makeDerived()` resolves via Base).\n",
            PropertyChain => "# Member-dispatch: property chains (v0.7 — Pattern PC)\n\nRepotoire resolves `expr.field.method()` chains when each intermediate field has a declared plain-Ident class type:\n\n- `this.client.send()` — most common shape (e.g., NestJS service injection via constructor parameter property)\n- `obj.field.method()` where `obj` has a known class via Pattern 3a/3b/F\n- `new C().field.method()` — Constructed base\n- Multi-hop chains up to depth 4: `this.a.b.c.method()` resolves through successive field-type lookups\n\nCross-file chains resolve through the FIELD's defining-file type namespace (each field type's Ident is named in the field's class's own file). The shared member-access transition runs in statement and nested expression positions, including initializers, returns, call arguments, optional calls, and optional generic calls.\n",
            AccessorsFieldsAndConflictRule => "# Member-dispatch: accessors, fields, compound assigns, conflict rule (v0.5)\n\n- **Read access on getters**: `x.foo` where `class C { get foo(): T }` emits a Calls edge to the Getter Property node (MemberKind::Getter).\n- **Write access on setters**: `x.foo = expr` emits a Calls edge to the Setter Property node.\n- **Field access**: `x.foo` and `x.foo = …` both emit when `foo` is a Field on x's class (fields are intrinsically read+write).\n- **Compound assignments**: `x.foo += …`, `x.foo &&= …`, etc. emit BOTH Read AND Write at the same site (semantically read-then-write).\n- **Conflict rule (declared-type-wins)**: `const x: Base = new Derived()` and `const x: Base = makeDerived()` both resolve via Base, not Derived. Matches TypeScript's nominal-via-declared-type semantics; avoids subclass guessing.\n",
            OutOfScopeFactoryGaps => "# Member-dispatch: factory-shape gaps (out of scope)\n\nFactory patterns that v0.6 Pattern F does NOT resolve:\n\n- **Aliased factories**: `const obj = z.object; const s = obj({…}); s.parse()` — aliasing the factory through a binding requires reassignment-derived inference (Q5 of v0.6 plan-doc, out of scope).\n- **Factory chains**: `a().b().c()` — chained factories require expression-typed-receiver resolution (paired with v0.7 property chains for similar shape, but chain-of-factories specifically deferred to v0.8+).\n- **Instance-method factories**: `factory.create()` where `factory` is a binding — instance-method dispatch through a property chain is technically resolvable now via Pattern PC, but only when the field type is statically known.\n- **Body-inferred returns**: `function f() { return new C() }` — no declared return type; whole-function flow analysis required (Q9, out of scope).\n- **Overloaded factory returns**: multiple overload signatures with different return types — skipped per ambiguity.\n- **Union / non-Ident factory returns**: `function f(): C | null` — narrowing tracking required (Q1, out of scope).\n- **Subclass-returning factories**: `function f(): Base { return new Derived() }` — declared-type wins (resolves to Base.m, not Derived.m).\n",
            OutOfScopeChainGaps => "# Member-dispatch: property-chain gaps (out of scope)\n\nProperty-chain patterns that v0.7 Pattern PC does NOT resolve:\n\n- **Chains deeper than 4 hops**: `this.a.b.c.d.e.method()` silently drops past the MAX_PROPERTY_CHAIN_DEPTH cap (Q1 of v0.7 plan-doc). Real-world chains rarely exceed 2-3 hops; the cap is structural insurance.\n- **Reassigned fields**: `x.field = newClient(); x.field.send()` — reassignment-derived inference (out of scope; same rule as v0.5/v0.6).\n",
            OutOfScopeInheritanceGenerics => "# Member-dispatch: inheritance and generics (out of scope)\n\n- **Subclass dynamic dispatch**: `class B extends A; let x: A = new B(); x.m()` — dispatching to `B.m()` (the concrete subclass method) requires open-world inheritance tracking. Resolves conservatively via the declared type (`A.m`) per the conflict rule; dispatch to `B.m` is out of scope.\n- **Generics beyond strip-and-capture**: `class C<T> { m(t: T) {} }; let x: C<string>; x.m()` — generic type-parameter receivers are stripped (we resolve to `C`, not `C<string>`); type-parameter-substituted method signatures are not tracked. `ReturnType<typeof factory>` and other type-level operators are out of scope.\n",
            OutOfScopeDynamicAndDecorators => "# Member-dispatch: dynamic shapes + parser-level gaps (out of scope)\n\n- **Non-constant bracket-key access**: `x[varName]()`, `x[`prefix${y}`]()` — only string-literal and no-expression template-literal bracket keys normalize to dot-access (e.g., `x['foo']()` → `x.foo()`). Computed keys remain unresolved.\n- **`eval` and dynamic property access**: `obj[name]`, `eval(`x.${m}()`)`, dynamic-import access — not tracked.\n- **Decorator edge cases**: ordinary class/member decorators are supported enough for extraction (`@Injectable() class S {}` survives, decorator base refs and call-arg refs are captured). Remaining parser gaps include computed decorator expressions such as `@[expr]` and decorated declarations whose underlying statement is still unsupported, such as `@D abstract class C {}`.\n",
            OutOfScopeMisc => "# Member-dispatch: miscellaneous (out of scope)\n\n- **Destructured binders**: `const { a } = new C(); a.m()`, `const [x] = arr; x.m()` — destructured binders aren't tracked as class-origin. Out of scope.\n- **Return-value flow**: `getClient().send()` — the receiver is an unbound call result. Pattern F resolves bindings initialized by declared factory returns, but it does not infer the class of a bare call result.\n- **Visibility modifiers**: `private`, `protected`, `public`, `abstract`, `override` modifiers are emitted with the underlying `(is_static, kind, name)` shape but visibility is not separately classified. Renaming a `private` method still emits a Calls edge to any in-tree reference; TS's accessibility model is not enforced.\n",
        }
    }
}

/// Resolution result. `Found` is the common success case and carries limitations
/// inside [`ImpactEvidence`]. `Ambiguous` carries the structured disambiguation
/// surface. `NotFound` carries the missing-symbol state. Every arm carries
/// limitations so result packets remain self-contained when consumed out of
/// context.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum ImpactResolution {
    Found(Box<ImpactEvidence>),
    Ambiguous {
        candidates: Vec<DeclLocation>,
        limitations: Vec<Limitation>,
    },
    NotFound {
        limitations: Vec<Limitation>,
    },
}

impl ImpactResolution {
    pub fn limitations(&self) -> &[Limitation] {
        match self {
            ImpactResolution::Found(evidence) => &evidence.limitations,
            ImpactResolution::Ambiguous { limitations, .. }
            | ImpactResolution::NotFound { limitations } => limitations,
        }
    }
}

/// `(file, line, kind, name)` for one decl when multiple share a name.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DeclLocation {
    pub file: String,
    pub line: u32,
    pub kind: DeclKind,
    pub name: String,
    pub heritage: Vec<DefinitionHeritageEvidence>,
}

/// Resolve `symbol_arg` (bare `name` or `name:file:line` disambiguator)
/// against the bundle. The bare form returns `Ambiguous` when more than one
/// decl in the scanned tree shares the name; pass a disambiguated arg to
/// pin a specific decl.
///
/// Determinism: identical bundles produce equal results, including the
/// order of `imports` / `exports` / `uses` and the ambiguous-candidate list.
pub fn extract_evidence_for_symbol(
    bundle: &SourceBundle<'_>,
    symbol_arg: &str,
) -> ImpactResolution {
    extract_evidence_for_symbol_with_node_filter(bundle, symbol_arg, |_| true, &NO_IMPACT_DEADLINE)
        .expect("the explicit no-deadline token cannot expire")
}

pub(crate) fn extract_evidence_for_symbol_with_node_filter<F, D>(
    bundle: &SourceBundle<'_>,
    symbol_arg: &str,
    include_node: F,
    deadline: &D,
) -> Result<ImpactResolution, ImpactDeadlineExceeded>
where
    F: Fn(NodeId) -> bool,
    D: ImpactDeadline + ?Sized,
{
    deadline.check()?;
    let (name, disambig) = parse_symbol_arg(symbol_arg);

    let mut candidates = resolve_symbol_nodes_from_parts_until(bundle, name, disambig, deadline)?;
    let mut retained = Vec::with_capacity(candidates.len());
    for node in candidates.drain(..) {
        deadline.check()?;
        if include_node(node) {
            retained.push(node);
        }
    }
    candidates = retained;

    let resolution = match candidates.len() {
        0 => ImpactResolution::NotFound {
            limitations: standard_limitations(),
        },
        1 => ImpactResolution::Found(Box::new(build_single_until(
            bundle,
            name,
            candidates[0],
            deadline,
        )?)),
        _ => ImpactResolution::Ambiguous {
            candidates: build_multi_until(bundle, &candidates, deadline)?,
            limitations: standard_limitations(),
        },
    };
    Ok(resolution)
}

/// Resolve a `name` or `name:file:line` symbol argument to matching decl nodes.
/// Shared by render adapters that need NodeIds for ranking/focus behavior.
pub fn resolve_symbol_nodes(bundle: &SourceBundle<'_>, symbol_arg: &str) -> Vec<NodeId> {
    let (name, disambig) = parse_symbol_arg(symbol_arg);
    resolve_symbol_nodes_from_parts_until(bundle, name, disambig, &NO_IMPACT_DEADLINE)
        .expect("the explicit no-deadline token cannot expire")
}

pub fn symbol_name_from_arg(arg: &str) -> &str {
    parse_symbol_arg(arg).0
}

/// Return the explicitly disambiguated file in `name:file:line`, if present.
/// Consumers use this accessor so admission and resolution share one symbol
/// grammar instead of re-parsing user input independently.
pub fn symbol_file_from_arg(arg: &str) -> Option<&str> {
    parse_symbol_arg(arg).1.map(|(file, _line)| file)
}

/// Normalization primitive: strip a single leading `./`, matching the exact
/// inline behavior that lived at the two `strip_prefix("./")` sites. Shared by
/// `file_is_indexed`, `resolve_symbol_nodes_from_parts`, and `canonical_rel_path`
/// so there is one copy, not three (fix the mechanism, not the instances).
pub fn strip_leading_dot_slash(path: &str) -> &str {
    path.strip_prefix("./").unwrap_or(path)
}

/// Canonical project-relative inventory grammar for the checkpoint deletion
/// rule (rule D). Returns the normalized rel-path ONLY when `raw` is already
/// canonical: relative, `/`-separated, no `.`/`..` segments, not absolute, no
/// backslashes. Returns `None` for every non-canonical form so rule D fails
/// safe to UNVERIFIABLE (an agent-supplied anchor that is a typo, absolute
/// path, or case/separator variant can never be declared "deleted").
pub fn canonical_rel_path(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.contains('\\') {
        return None;
    }
    let norm = strip_leading_dot_slash(raw);

    // Check for . and .. segments by literal string matching on segment
    // boundaries. This is deliberately stricter than `Path::components`
    // (which silently collapses `.` segments and coalesces repeated `/`):
    // an empty segment here also rejects a bare leading `/` (Unix-style
    // absolute path, e.g. "/abs/a.ts" -> ["", "abs", "a.ts"]) AND any
    // double-slash ("a//b.ts"), neither of which is a canonical rel-path.
    for segment in norm.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return None;
        }
    }

    // NOT provably redundant with the segment check above, so kept: the
    // segment check only catches a Unix-style leading `/` via its empty
    // first segment. `Path::is_absolute` also rejects platform-absolute
    // forms the segment check cannot see on its own, e.g. a Windows
    // drive-letter path like "C:/abs/a.ts" (no empty segment, no
    // backslash) when this binary targets a platform where that form is
    // absolute. Removing this check would let such paths through.
    let p = std::path::Path::new(norm);
    if p.is_absolute() {
        return None;
    }

    Some(norm.to_string())
}

/// Whether `file_path` genuinely contributed declarations to `bundle`'s
/// graph — the positive-evidence signal a caller needs before treating an
/// empty [`resolve_symbol_nodes`] result as "the symbol used to be here and
/// is now gone" (STALE) rather than "this file was never analyzed" (which
/// should be UNVERIFIABLE, never STALE — a symbol that was never indexed
/// can't have gone stale).
///
/// A file is "indexed" here iff a `File` node exists whose stored path
/// matches `file_path` under the SAME normalization
/// [`resolve_symbol_nodes`]'s disambiguator uses (an optional leading `./`
/// stripped on both sides — bundles built in-memory keep it, the CLI
/// walker strips it), AND that `File` node has at least one outgoing
/// `Contains` edge (i.e. it contributed at least one declaration).
///
/// Two files return `false` here: (1) a file whose language repotoire's
/// graph doesn't walk into declarations at all (e.g. Rust — no `File` node
/// exists for it), and (2) a real, walked, supported-language file that
/// happens to have zero declarations (a `File` node exists but is
/// childless). Case (2) is intentionally folded into "not indexed": there
/// is nothing to verify a symbol against in a declaration-less file
/// either, so the same fail-closed UNVERIFIABLE applies.
pub fn file_is_indexed(bundle: &SourceBundle<'_>, file_path: &str) -> bool {
    let graph = &bundle.graph;
    let want_norm = strip_leading_dot_slash(file_path);
    graph.nodes_of_kind(NodeKind::File).any(|file_node| {
        let name = graph.node_name(file_node);
        let name_norm = strip_leading_dot_slash(name);
        name_norm == want_norm
            && graph
                .outgoing(file_node, EdgeKind::Contains)
                .next()
                .is_some()
    })
}

fn resolve_symbol_nodes_from_parts_until<D: ImpactDeadline + ?Sized>(
    bundle: &SourceBundle<'_>,
    name: &str,
    disambig: Option<(&str, u32)>,
    deadline: &D,
) -> Result<Vec<NodeId>, ImpactDeadlineExceeded> {
    let graph = &bundle.graph;
    let mut candidates = collect_decls_with_name_until(graph, name, deadline)?;
    if let Some((wanted_file, wanted_line)) = disambig {
        // Path-form tolerance: bundles built in-memory keep the `./`
        // prefix on File-node names (test fixtures); bundles built by
        // the CLI walker strip it. Strip on both sides so the
        // disambiguator works regardless of which form the caller
        // passed. Mirrors `delta::find_file_node`.
        let want_norm = strip_leading_dot_slash(wanted_file);
        let mut retained = Vec::with_capacity(candidates.len());
        for node in candidates.drain(..) {
            deadline.check()?;
            let matches = match symbol_location(bundle, node) {
                Some((f, line_col)) => {
                    let f_norm = strip_leading_dot_slash(&f).to_string();
                    f_norm == want_norm && line_col.line == wanted_line
                }
                None => false,
            };
            if matches {
                retained.push(node);
            }
        }
        candidates = retained;
    }
    Ok(candidates)
}

/// Stable, normalized hash of the *surface* bytes of a decl.
///
/// Surface = decl span minus body span. Functions, methods, classes,
/// namespaces, interfaces, AND enums all carve a real `body_span` from the
/// resolver (see `ts::resolver`) — for every one of those kinds, the `{
/// … }` block is excluded from the surface, so member adds/removes/
/// reorders inside it do NOT change the hash; only the signature outside
/// the braces (name, type parameters, `extends`/`implements` clause) does.
/// Only decl kinds the resolver gives `body: None` — type aliases and
/// top-level variables — have no body span to strip, so surface = the
/// whole decl span and ANY change to their RHS changes the hash.
/// TypeScript and Rust normalization uses their language tokenizers: literal
/// bytes are preserved, comments are removed, and trivia gaps become one space.
/// Other languages, uncertain JSX/regex surfaces, and reported lexical errors
/// retain their exact bytes. This is not semantic equivalence or syntax validation.
///
/// Matching hashes are surface fingerprints, not proof of statement truth or
/// behavior (nor collision-free byte identity). Body-only edits (including
/// interface and enum member changes) do not change the hash. Where token
/// normalization applies, trivia-only edits within existing gaps do not change
/// it either. Conservative byte-preserving paths can report formatting changes.
///
/// Returns 0 when the decl span or file bytes are unavailable (defensive
/// — D2 treats 0 as "missing", not "equal"; see baseline serialization).
pub fn signature_hash(bundle: &SourceBundle<'_>, node: NodeId) -> u64 {
    let Some(normalized) = normalized_signature_bytes(bundle, node) else {
        return 0;
    };
    fnv1a_64(&normalized)
}

/// Persisted signature hashes must carry this normalization and hash identity.
/// Change the identity whenever surface extraction or normalization changes.
/// Unprefixed hashes cannot be upgraded without their original source bytes.
pub const SIGNATURE_HASH_PREFIX: &str = "surface-v2:fnv1a64:";

/// The human-readable surface signature TEXT — the exact bytes
/// [`signature_hash`] hashes, normalized according to its language policy
/// and rendered as a `String`.
///
/// This is the decl-minus-body surface (fn header, interface head, type
/// alias, etc.). A signature change (added parameter, changed return
/// type, renamed alias RHS) changes both. Returns `None` when the decl
/// span or file bytes are unavailable — the SAME missing-input condition
/// [`signature_hash`] treats as `0` — so callers can render `old → new`
/// only when both sides are present, and disclose "signature text
/// unavailable" otherwise rather than inventing a spurious diff.
pub fn signature_text(bundle: &SourceBundle<'_>, node: NodeId) -> Option<String> {
    let normalized = normalized_signature_bytes(bundle, node)?;
    Some(String::from_utf8_lossy(&normalized).into_owned())
}

/// Extract and normalize the surface bytes (decl span minus body span) for `node`.
/// Shared by [`signature_hash`] (which hashes the normalized form) and
/// [`signature_text`] (which renders it). `None` on any missing-input or
/// malformed-span condition — the single source of the "0 means missing"
/// invariant both callers rely on.
fn normalized_signature_bytes(bundle: &SourceBundle<'_>, node: NodeId) -> Option<Vec<u8>> {
    let graph = &bundle.graph;
    let decl = graph.node_decl_span(node)?;
    let file = graph.file_of(node)?;
    let bytes = bundle.source_bytes(file)?;

    let body = graph.node_body_span(node);
    let surface_bytes: Vec<u8> = if let Some(body) = body {
        // body is always contained in decl per IR invariant; defensive
        // bounds-check against malformed inputs.
        let decl_s = decl.start() as usize;
        let decl_e = (decl.start() + decl.length()) as usize;
        let body_s = body.start() as usize;
        let body_e = (body.start() + body.length()) as usize;
        if !(decl_s <= body_s && body_e <= decl_e && decl_e <= bytes.len()) {
            return None;
        }
        let mut out = Vec::with_capacity(decl_e - decl_s - (body_e - body_s));
        out.extend_from_slice(&bytes[decl_s..body_s]);
        out.extend_from_slice(&bytes[body_e..decl_e]);
        out
    } else {
        let s = decl.start() as usize;
        let e = (decl.start() + decl.length()) as usize;
        if e > bytes.len() {
            return None;
        }
        bytes[s..e].to_vec()
    };
    let language = source_language_for_path(Path::new(graph.node_name(file)));
    Some(normalize_signature(&surface_bytes, language))
}

/// Normalize trivia only; never reinterpret literal contents. Unsupported
/// contexts and reported lexer errors retain bytes instead of erasing guesses.
fn normalize_signature(bytes: &[u8], language: SourceLanguage) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut previous_end = 0;
    let mut append = |range: std::ops::Range<usize>| {
        assert!(previous_end <= range.start && range.start < range.end);
        assert!(range.end <= bytes.len());
        if !out.is_empty() && previous_end < range.start {
            out.push(b' ');
        }
        out.extend_from_slice(&bytes[range.clone()]);
        previous_end = range.end;
    };
    match language {
        SourceLanguage::TypeScript => {
            let mut lexer = Lexer::new(bytes);
            // Every non-EOF token consumes at least one byte.
            for _ in 0..=bytes.len() {
                let token = lexer.next();
                match token.kind {
                    TokenKind::Eof => {
                        return if lexer.unterminated_block_comment().is_some() {
                            bytes.to_vec()
                        } else {
                            out
                        };
                    }
                    // JSX text needs parser context: `//` can be literal text.
                    // Slash tokens also need parser context: after `if (x)`,
                    // `/a  b/` is a regex, not division. Retain uncertain
                    // surfaces (including generics and division) rather than
                    // build a second parser or erase possible literal bytes.
                    TokenKind::Error | TokenKind::Lt | TokenKind::Slash | TokenKind::SlashEq => {
                        return bytes.to_vec();
                    }
                    _ => {
                        let start = token.span.start() as usize;
                        append(start..start + token.span.length() as usize);
                    }
                }
            }
            unreachable!("lexer must reach EOF within the source byte bound");
        }
        SourceLanguage::Rust => {
            let Ok(text) = std::str::from_utf8(bytes) else {
                return bytes.to_vec();
            };
            let lexed = ra_ap_parser::LexedStr::new(ra_ap_parser::Edition::CURRENT, text);
            if lexed.errors().next().is_some() {
                return bytes.to_vec();
            }
            for i in 0..lexed.len() {
                if !matches!(
                    lexed.kind(i),
                    ra_ap_parser::SyntaxKind::WHITESPACE | ra_ap_parser::SyntaxKind::COMMENT
                ) {
                    append(lexed.text_range(i));
                }
            }
        }
        SourceLanguage::Python | SourceLanguage::Unknown => return bytes.to_vec(),
    }
    out
}

/// FNV-1a 64-bit. Stable across architectures and Rust versions — that
/// matters because we persist hashes in the live state directory between
/// pre-edit snapshot and post-edit comparison.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h: u64 = OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

fn parse_symbol_arg(arg: &str) -> (&str, Option<(&str, u32)>) {
    let parts: Vec<&str> = arg.rsplitn(3, ':').collect();
    if parts.len() == 3 {
        if let Ok(line) = parts[0].parse::<u32>() {
            return (parts[2], Some((parts[1], line)));
        }
    }
    (arg, None)
}

/// How many source declarations named `name` the snapshot contains, under a
/// census DELIBERATELY WIDER than the briefable one
/// [`extract_evidence_for_symbol`] resolves against.
///
/// The briefable census answers "which declaration should `impact <name>`
/// brief?" and narrows on purpose: [`collect_decls_with_name`] drops
/// type-signature members (G1.7 Fix 2) so a concrete `Logger.info` outranks an
/// interface's `info(): void`. That narrowing is right for BRIEFING — but it
/// means a briefable result of exactly one match does NOT establish that the
/// name is unique in the tree, and a caller that converts "exactly one" into
/// WRITE AUTHORITY would grant it over one file while a same-named declaration
/// sits unmentioned in another.
///
/// This count exists for exactly that check. It walks every `Contains`
/// descendant of every `File` node and counts each node whose name matches and
/// whose kind is a briefable decl kind OR `EnumMember`, with no
/// type-signature-member exclusion. Alias collection is deliberately omitted:
/// export/import aliases resolve to declarations already walked here, so
/// counting them would double-count one declaration rather than find another.
/// `EnumMember` is accepted for schema completeness only — no walker currently
/// mints one, so today it contributes nothing.
///
/// Bounded by what the graph CONTAINS, which is a different thing from what the
/// census FILTERS. A declaration the walker never minted a node for — a file in
/// a language with no `File` node, or an enum member — cannot be counted here by
/// any widening. That residue is disclosed (unsupported-language census), not
/// counted, and it is why this returns a lower bound rather than a guarantee.
pub fn same_name_declaration_census(bundle: &SourceBundle<'_>, name: &str) -> usize {
    let graph = &bundle.graph;
    let mut seen = HashSet::new();
    for file in graph.nodes_of_kind(NodeKind::File) {
        count_same_name_descendants(graph, file, name, &mut seen);
    }
    seen.len()
}

fn count_same_name_descendants(
    graph: &CodeGraph<'_>,
    parent: NodeId,
    name: &str,
    seen: &mut HashSet<u32>,
) {
    for child in graph.outgoing(parent, EdgeKind::Contains) {
        let kind = graph.node_kind(child);
        let counts =
            DeclKind::from_node_kind(kind).is_some() || matches!(kind, NodeKind::EnumMember);
        if counts && graph.node_name(child) == name {
            seen.insert(child.raw());
        }
        count_same_name_descendants(graph, child, name, seen);
    }
}

fn collect_decls_with_name_until<D: ImpactDeadline + ?Sized>(
    graph: &CodeGraph<'_>,
    name: &str,
    deadline: &D,
) -> Result<Vec<NodeId>, ImpactDeadlineExceeded> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for file in graph.nodes_of_kind(NodeKind::File) {
        deadline.check()?;
        collect_briefable_descendants_until(graph, file, name, &mut out, &mut seen, deadline)?;
    }
    collect_export_label_aliases_until(graph, name, &mut out, &mut seen, deadline)?;
    collect_import_local_aliases_until(graph, name, &mut out, &mut seen, deadline)?;
    // Interface / type-alias members are `Property` nodes minted (G1.7 Fix 2)
    // solely as member-dispatch substrate (`members_of_type`); they are not
    // independently briefable bare-name declarations. Surfacing them here
    // would turn every `impact <name>` / `prove <name>` where a concrete
    // method and a same-named type-signature member coexist (e.g. a class
    // `Logger.info` alongside `LoggerInterface.info`) into a spurious
    // same-name ambiguity, disabling the single-decl source-reference
    // path. Drop them so bare-name resolution stays pointed at the concrete
    // declaration, exactly as before Fix 2 minted these nodes.
    out.retain(|&node| !is_type_signature_member(graph, node));
    out.sort_by_key(|n| n.raw());
    deadline.check()?;
    Ok(out)
}

/// Whether `node` is a function-typed member of an interface or type alias —
/// a `Property` decl node whose `Contains` parent is an `Interface` or
/// `TypeAlias`. These are minted as dispatch substrate, not as independent
/// bare-name impact targets (see [`collect_decls_with_name`]). Class members
/// (`Property` parented by a `Class`) are NOT type-signature members and are
/// retained.
fn is_type_signature_member(graph: &CodeGraph<'_>, node: NodeId) -> bool {
    graph.node_kind(node) == NodeKind::Property
        && graph.incoming(node, EdgeKind::Contains).any(|parent| {
            matches!(
                graph.node_kind(parent),
                NodeKind::Interface | NodeKind::TypeAlias
            )
        })
}

fn collect_briefable_descendants_until<D: ImpactDeadline + ?Sized>(
    graph: &CodeGraph<'_>,
    parent: NodeId,
    name: &str,
    out: &mut Vec<NodeId>,
    seen: &mut HashSet<u32>,
    deadline: &D,
) -> Result<(), ImpactDeadlineExceeded> {
    for child in graph.outgoing(parent, EdgeKind::Contains) {
        deadline.check()?;
        if DeclKind::from_node_kind(graph.node_kind(child)).is_some()
            && graph.node_name(child) == name
        {
            push_unique_decl(out, seen, child);
        }
        collect_briefable_descendants_until(graph, child, name, out, seen, deadline)?;
    }
    Ok(())
}

fn push_unique_decl(out: &mut Vec<NodeId>, seen: &mut HashSet<u32>, node: NodeId) {
    if seen.insert(node.raw()) {
        out.push(node);
    }
}

fn collect_export_label_aliases_until<D: ImpactDeadline + ?Sized>(
    graph: &CodeGraph<'_>,
    name: &str,
    out: &mut Vec<NodeId>,
    seen: &mut HashSet<u32>,
    deadline: &D,
) -> Result<(), ImpactDeadlineExceeded> {
    for file in graph.nodes_of_kind(NodeKind::File) {
        deadline.check()?;
        for decl in briefable_decls_in_file(graph, file) {
            deadline.check()?;
            if export_label_points_to_decl(graph, decl, None, name) {
                push_unique_decl(out, seen, decl);
            }
        }
    }
    Ok(())
}

fn collect_import_local_aliases_until<D: ImpactDeadline + ?Sized>(
    graph: &CodeGraph<'_>,
    name: &str,
    out: &mut Vec<NodeId>,
    seen: &mut HashSet<u32>,
    deadline: &D,
) -> Result<(), ImpactDeadlineExceeded> {
    for importer in graph.nodes_of_kind(NodeKind::File) {
        deadline.check()?;
        for out_slot in graph.out_slots(importer, EdgeKind::Imports) {
            deadline.check()?;
            let Some(label) = graph.edge_label_str(EdgeKind::Imports, out_slot) else {
                continue;
            };
            let target_file = graph.out_target(EdgeKind::Imports, out_slot);
            if graph.node_kind(target_file) != NodeKind::File {
                continue;
            }
            for exported_name in import_label_exported_names_for_local_alias(label, name) {
                for decl in decls_exported_from_file_as(graph, target_file, &exported_name) {
                    deadline.check()?;
                    push_unique_decl(out, seen, decl);
                }
            }
        }
    }
    Ok(())
}

fn briefable_decls_in_file(graph: &CodeGraph<'_>, file: NodeId) -> Vec<NodeId> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    collect_briefable_decls_in_subtree(graph, file, &mut out, &mut seen);
    out
}

fn collect_briefable_decls_in_subtree(
    graph: &CodeGraph<'_>,
    parent: NodeId,
    out: &mut Vec<NodeId>,
    seen: &mut HashSet<u32>,
) {
    for child in graph.outgoing(parent, EdgeKind::Contains) {
        if DeclKind::from_node_kind(graph.node_kind(child)).is_some() {
            push_unique_decl(out, seen, child);
        }
        collect_briefable_decls_in_subtree(graph, child, out, seen);
    }
}

fn decls_exported_from_file_as(
    graph: &CodeGraph<'_>,
    file: NodeId,
    public_name: &str,
) -> Vec<NodeId> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for source in export_source_nodes_for_file(graph, file) {
        for out_slot in graph.out_slots(source, EdgeKind::Exports) {
            if graph.edge_label_str(EdgeKind::Exports, out_slot) != Some(public_name) {
                continue;
            }
            let target = graph.out_target(EdgeKind::Exports, out_slot);
            if DeclKind::from_node_kind(graph.node_kind(target)).is_some() {
                push_unique_decl(&mut out, &mut seen, target);
            }
        }
    }
    out
}

fn export_label_points_to_decl(
    graph: &CodeGraph<'_>,
    decl: NodeId,
    source_file_filter: Option<NodeId>,
    public_name: &str,
) -> bool {
    for slot in graph.in_slots(decl, EdgeKind::Exports) {
        if let Some(source_file) = source_file_filter {
            let source = graph.in_source(EdgeKind::Exports, slot);
            if source != source_file && graph.file_of(source) != Some(source_file) {
                continue;
            }
        }
        let source = graph.in_source(EdgeKind::Exports, slot);
        let out_slot = graph
            .out_slots(source, EdgeKind::Exports)
            .find(|s| graph.out_target(EdgeKind::Exports, *s) == decl);
        if out_slot.and_then(|s| graph.edge_label_str(EdgeKind::Exports, s)) == Some(public_name) {
            return true;
        }
    }
    false
}

fn export_source_nodes_for_file(graph: &CodeGraph<'_>, file: NodeId) -> Vec<NodeId> {
    let mut out = vec![file];
    for child in graph.outgoing(file, EdgeKind::Contains) {
        out.push(child);
    }
    out
}

fn import_label_exported_names_for_local_alias(label: &str, local_name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let prefix = label.split('{').next().unwrap_or(label);
    for segment in prefix.split(',') {
        let segment = segment.trim();
        if let Some(local) = segment.strip_prefix("default as ") {
            if local.trim() == local_name {
                out.push("default".to_string());
            }
        }
    }
    let Some(brace_start) = label.find('{') else {
        return out;
    };
    let Some(brace_end) = label[brace_start..].find('}') else {
        return out;
    };
    let inside = &label[brace_start + 1..brace_start + brace_end];
    for entry in inside.split(',') {
        let entry = entry.trim();
        let entry = entry.strip_prefix("type ").unwrap_or(entry);
        let mut parts = entry.split_whitespace();
        let Some(exported) = parts.next() else {
            continue;
        };
        match (parts.next(), parts.next()) {
            (None, None) if exported == local_name => out.push(exported.to_string()),
            (Some("as"), Some(local)) if local == local_name => out.push(exported.to_string()),
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Resolve the canonical location of a symbol from its exact declared name.
/// Impact output, disambiguation, CodebaseView focus, and checkpoint anchors
/// all use this one identity. Declaration spans remain the separate owner of
/// surface hashing and source-range extraction.
pub fn symbol_location(bundle: &SourceBundle<'_>, node: NodeId) -> Option<(String, LineCol)> {
    let graph = &bundle.graph;
    let file = graph.file_of(node)?;
    let span = graph.node_name_span(node)?;
    let line_col = bundle.line_col(file, span.start())?;
    Some((graph.node_name(file).to_string(), line_col))
}

fn definition_heritage(graph: &CodeGraph<'_>, node: NodeId) -> Vec<DefinitionHeritageEvidence> {
    let mut out = Vec::new();
    for target in graph.outgoing(node, EdgeKind::Extends) {
        out.push(DefinitionHeritageEvidence {
            kind: DefinitionHeritageKind::Extends,
            name: graph.node_name(target).to_string(),
        });
    }
    for target in graph.outgoing(node, EdgeKind::Implements) {
        out.push(DefinitionHeritageEvidence {
            kind: DefinitionHeritageKind::Implements,
            name: graph.node_name(target).to_string(),
        });
    }
    out
}

fn build_multi_until<D: ImpactDeadline + ?Sized>(
    bundle: &SourceBundle<'_>,
    candidates: &[NodeId],
    deadline: &D,
) -> Result<Vec<DeclLocation>, ImpactDeadlineExceeded> {
    let graph = &bundle.graph;
    let mut rows = Vec::with_capacity(candidates.len());
    for node in candidates {
        deadline.check()?;
        let Some((file, line_col)) = symbol_location(bundle, *node) else {
            continue;
        };
        let Some(kind) = DeclKind::from_node_kind(graph.node_kind(*node)) else {
            continue;
        };
        rows.push(DeclLocation {
            file,
            line: line_col.line,
            kind,
            name: graph.node_name(*node).to_string(),
            heritage: definition_heritage(graph, *node),
        });
    }
    rows.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    deadline.check()?;
    Ok(rows)
}

pub(super) fn build_single_until<D: ImpactDeadline + ?Sized>(
    bundle: &SourceBundle<'_>,
    name: &str,
    decl: NodeId,
    deadline: &D,
) -> Result<ImpactEvidence, ImpactDeadlineExceeded> {
    let graph = &bundle.graph;
    let span_view = SpanView::build_for_until(
        graph,
        &[
            EdgeKind::Calls,
            EdgeKind::ValueRef,
            EdgeKind::TypeRef,
            EdgeKind::Exports,
            EdgeKind::Extends,
            EdgeKind::Implements,
            EdgeKind::Imports,
        ],
        || deadline.check(),
    )?;

    let definition = symbol_location(bundle, decl).and_then(|(file, line_col)| {
        let kind = DeclKind::from_node_kind(graph.node_kind(decl))?;
        Some(DefinitionEvidence {
            node_id: decl,
            name: graph.node_name(decl).to_string(),
            file,
            line: line_col.line,
            kind,
            heritage: definition_heritage(graph, decl),
            signature_hash: signature_hash(bundle, decl),
        })
    });

    let decl_file = graph.file_of(decl);
    deadline.check()?;
    let imports = collect_imports_until(bundle, &span_view, decl, decl_file, name, deadline)?;
    deadline.check()?;
    let exports = collect_exports_until(bundle, &span_view, decl_file, decl, name, deadline)?;
    deadline.check()?;
    let uses = collect_uses_until(bundle, &span_view, decl, decl_file, deadline)?;
    deadline.check()?;
    let dynamic_reachability =
        collect_dynamic_reachability_until(bundle, &span_view, decl_file, decl, name, deadline)?;
    deadline.check()?;
    let service_dispatch =
        collect_service_method_dispatch(bundle, &span_view, decl, decl_file, name, deadline)?;
    deadline.check()?;
    let provider_context = collect_provider_context_evidence(bundle, &service_dispatch, deadline)?;
    deadline.check()?;
    let compiler_pressure = if is_typescript_like_decl(graph, decl_file) {
        // G1.6 W1 (spec D2) — seed the consumer-call-site walk from EVERY
        // decl node sharing this symbol's bare name, not just the one the
        // caller's (possibly disambiguated) lookup resolved to. This is the
        // "seed-all-decls plumbing" the task brief calls for: two decls
        // named identically in different files (the hono-shape multi-decl
        // case) each carry their own, otherwise-disconnected, TypeRef
        // in-edges — seeding from only the resolved `decl` would silently
        // miss consumer sites that reference the sibling decl. Every OTHER
        // row in `compiler_pressure` below still keys off the single
        // resolved `decl`, unchanged.
        let all_decls = collect_decls_with_name_until(graph, name, deadline)?;
        collect_compiler_pressure(
            bundle, &span_view, decl, decl_file, name, &all_decls, deadline,
        )?
    } else {
        Vec::new()
    };
    deadline.check()?;
    let unresolved_blind_spots = collect_unresolved_blind_spots_until(&span_view, deadline)?;
    let limitations = standard_limitations();

    deadline.check()?;
    Ok(ImpactEvidence {
        symbol: name.to_string(),
        definition,
        imports,
        exports,
        uses,
        dynamic_reachability,
        service_dispatch,
        provider_context,
        compiler_pressure,
        unresolved_blind_spots,
        limitations,
    })
}

fn collect_imports_until<D: ImpactDeadline + ?Sized>(
    bundle: &SourceBundle<'_>,
    span_view: &SpanView<'_>,
    decl: NodeId,
    decl_file: Option<NodeId>,
    name: &str,
    deadline: &D,
) -> Result<Vec<RelationEvidence>, ImpactDeadlineExceeded> {
    let graph = &bundle.graph;
    if decl_file.is_none() {
        return Ok(Vec::new());
    }
    let mut out: Vec<RelationEvidence> = Vec::new();
    for import in import_slots_for_decl_until(span_view, decl, decl_file, name, deadline)? {
        deadline.check()?;
        let ImportSlot {
            slot,
            edge,
            direct_decl_import,
            public_name,
        } = import;
        let source_file = graph.file_of(edge.source);
        let Some(sf) = source_file else { continue };
        let out_slot = span_view.in_to_out(EdgeKind::Imports, slot);
        let label = match graph.edge_label_str(EdgeKind::Imports, out_slot) {
            Some(s) => s,
            None if direct_decl_import => "",
            None => continue,
        };
        let imported_name = public_name.as_deref().unwrap_or(name);
        if !direct_decl_import && !import_label_mentions_named(label, imported_name) {
            continue;
        }
        // Attribute each relation through its own edge span. Rust and Python
        // spans contain the imported token; TypeScript specifier spans anchor
        // a bounded search inside that same import statement.
        let line = import_line_from_source(bundle, sf, imported_name, edge.span, deadline)?
            .or_else(|| {
                edge.span
                    .and_then(|s| bundle.line_col(sf, s.start()))
                    .map(|lc| lc.line)
            })
            .unwrap_or(0);
        out.push(RelationEvidence {
            source_node: None,
            kind: RelationKind::NamedImport,
            file: graph.node_name(sf).to_string(),
            line,
            owner: None,
        });
    }
    out.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    out.dedup_by(|a, b| a.file == b.file && a.line == b.line);
    deadline.check()?;
    Ok(out)
}

pub(super) struct ImportSlot {
    pub(super) slot: u32,
    pub(super) edge: InEdge,
    pub(super) direct_decl_import: bool,
    pub(super) public_name: Option<String>,
}

pub(super) fn import_slots_for_decl_until<D: ImpactDeadline + ?Sized>(
    span_view: &SpanView<'_>,
    decl: NodeId,
    decl_file: Option<NodeId>,
    name: &str,
    deadline: &D,
) -> Result<Vec<ImportSlot>, ImpactDeadlineExceeded> {
    let graph = span_view.graph();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    if let Some(file) = decl_file {
        if is_python_file(graph.node_name(file)) {
            // Python makes an imported binding available as a module attribute
            // even when the module does not publish it through `__all__`.
            // Imports therefore remain module-topology edges; Impact joins the
            // named binding chain here instead of minting declaration-targeted
            // Imports or false Exports edges in the parser.
            let mut pending = vec![(file, name.to_string())];
            let mut visited = HashSet::new();
            let mut remaining = graph.out_edge_count(EdgeKind::Imports).saturating_add(1);
            while let Some((target_file, target_name)) = pending.pop() {
                deadline.check()?;
                if remaining == 0 || !visited.insert((target_file.raw(), target_name.clone())) {
                    continue;
                }
                remaining -= 1;
                for (slot, edge) in graph
                    .in_slots(target_file, EdgeKind::Imports)
                    .zip(span_view.in_edges(target_file, EdgeKind::Imports))
                {
                    deadline.check()?;
                    let out_slot = span_view.in_to_out(EdgeKind::Imports, slot);
                    let Some(label) = graph.edge_label_str(EdgeKind::Imports, out_slot) else {
                        continue;
                    };
                    let Some(local_name) = python_import_local_name(label, &target_name) else {
                        continue;
                    };
                    if seen.insert((target_file.raw(), slot, Some(target_name.clone()))) {
                        out.push(ImportSlot {
                            slot,
                            edge,
                            direct_decl_import: false,
                            public_name: Some(target_name.clone()),
                        });
                    }
                    let Some(importer_file) = graph.file_of(edge.source) else {
                        continue;
                    };
                    if is_python_file(graph.node_name(importer_file)) {
                        pending.push((importer_file, local_name.to_string()));
                    }
                }
            }
        } else {
            for (slot, edge) in graph
                .in_slots(file, EdgeKind::Imports)
                .zip(span_view.in_edges(file, EdgeKind::Imports))
            {
                deadline.check()?;
                if seen.insert((file.raw(), slot, None)) {
                    out.push(ImportSlot {
                        slot,
                        edge,
                        direct_decl_import: false,
                        public_name: None,
                    });
                }
            }
        }
    }

    // A named import from a barrel targets the barrel file, while the
    // barrel's Exports edge targets the origin declaration. Join those two
    // persisted relationships here so every consumer sees the same import
    // evidence regardless of whether it names the origin module or any
    // resolved re-export surface.
    for export_slot in graph.in_slots(decl, EdgeKind::Exports) {
        deadline.check()?;
        let export_source = graph.in_source(EdgeKind::Exports, export_slot);
        let Some(export_file) = graph.file_of(export_source) else {
            continue;
        };
        if Some(export_file) == decl_file {
            continue;
        }
        let out_slot = span_view.in_to_out(EdgeKind::Exports, export_slot);
        let public_name = graph
            .edge_label_str(EdgeKind::Exports, out_slot)
            .map(str::to_string);
        for (slot, edge) in graph
            .in_slots(export_file, EdgeKind::Imports)
            .zip(span_view.in_edges(export_file, EdgeKind::Imports))
        {
            deadline.check()?;
            if seen.insert((export_file.raw(), slot, public_name.clone())) {
                out.push(ImportSlot {
                    slot,
                    edge,
                    direct_decl_import: false,
                    public_name: public_name.clone(),
                });
            }
        }
    }

    for (slot, edge) in graph
        .in_slots(decl, EdgeKind::Imports)
        .zip(span_view.in_edges(decl, EdgeKind::Imports))
    {
        deadline.check()?;
        if seen.insert((decl.raw(), slot, None)) {
            out.push(ImportSlot {
                slot,
                edge,
                direct_decl_import: true,
                public_name: None,
            });
        }
    }
    Ok(out)
}

fn collect_exports_until<D: ImpactDeadline + ?Sized>(
    bundle: &SourceBundle<'_>,
    span_view: &SpanView<'_>,
    decl_file: Option<NodeId>,
    decl: NodeId,
    name: &str,
    deadline: &D,
) -> Result<Vec<RelationEvidence>, ImpactDeadlineExceeded> {
    let graph = &bundle.graph;
    let mut out: Vec<RelationEvidence> = Vec::new();
    for (slot, edge) in graph
        .in_slots(decl, EdgeKind::Exports)
        .zip(span_view.in_edges(decl, EdgeKind::Exports))
    {
        deadline.check()?;
        let source_file = graph.file_of(edge.source);
        if source_file == decl_file {
            continue;
        }
        let Some(sf) = source_file else { continue };
        let span = edge.span;
        let line = span
            .and_then(|s| bundle.line_col(sf, s.start()))
            .map(|lc| lc.line)
            .unwrap_or(0);
        let out_slot = span_view.in_to_out(EdgeKind::Exports, slot);
        let label = graph
            .edge_label_str(EdgeKind::Exports, out_slot)
            .map(|s| s.to_string());

        let kind = match span {
            Some(s) if line_at_span_is_wildcard_export(bundle, sf, s) => {
                RelationKind::WildcardReExport
            }
            _ => RelationKind::NamedReExport {
                public_alias: label.unwrap_or_else(|| name.to_string()),
            },
        };

        out.push(RelationEvidence {
            source_node: None,
            kind,
            file: graph.node_name(sf).to_string(),
            line,
            owner: None,
        });
    }
    out.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.kind.sort_tag().cmp(&b.kind.sort_tag()))
            .then_with(|| match (&a.kind, &b.kind) {
                (
                    RelationKind::NamedReExport { public_alias: la },
                    RelationKind::NamedReExport { public_alias: lb },
                ) => la.cmp(lb),
                _ => std::cmp::Ordering::Equal,
            })
    });
    out.dedup_by(|a, b| a.file == b.file && a.line == b.line && a.kind == b.kind);
    deadline.check()?;
    Ok(out)
}

fn collect_uses_until<D: ImpactDeadline + ?Sized>(
    bundle: &SourceBundle<'_>,
    span_view: &SpanView<'_>,
    decl: NodeId,
    decl_file: Option<NodeId>,
    deadline: &D,
) -> Result<Vec<RelationEvidence>, ImpactDeadlineExceeded> {
    let graph = &bundle.graph;
    let mut out: Vec<RelationEvidence> = Vec::new();

    for (edge_kind, rel_kind) in [
        (EdgeKind::Calls, RelationKind::Call),
        (EdgeKind::ValueRef, RelationKind::ValueRef),
        (EdgeKind::TypeRef, RelationKind::TypeRef),
        (EdgeKind::Extends, RelationKind::Extends),
        (EdgeKind::Implements, RelationKind::Implements),
    ] {
        deadline.check()?;
        for edge in span_view.in_edges(decl, edge_kind) {
            deadline.check()?;
            let source = edge.source;
            // Skip the decl's own recursive self-ref to preserve ordinary impact semantics.
            if graph.file_of(source) == decl_file && source == decl {
                continue;
            }
            let Some(source_file) = graph.file_of(source) else {
                continue;
            };
            let Some(span) = edge.span else {
                continue;
            };
            let Some(lc) = bundle.line_col(source_file, span.start()) else {
                continue;
            };
            let owner = relation_owner_until(graph, source, deadline)?;
            out.push(RelationEvidence {
                source_node: Some(source),
                kind: rel_kind.clone(),
                file: graph.node_name(source_file).to_string(),
                line: lc.line,
                owner,
            });
        }
    }

    out.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.kind.sort_tag().cmp(&b.kind.sort_tag()))
            .then(a.owner.cmp(&b.owner))
            .then(a.source_node.cmp(&b.source_node))
    });
    out.dedup_by(|a, b| {
        a.file == b.file
            && a.line == b.line
            && a.kind == b.kind
            && a.owner == b.owner
            && a.source_node == b.source_node
    });
    deadline.check()?;
    Ok(out)
}

/// Preserve the owner already recorded by extraction. Only Contains edges
/// qualify it: call targets and inheritance edges cannot establish ownership.
pub(crate) fn relation_owner_until<D: ImpactDeadline + ?Sized>(
    graph: &CodeGraph<'_>,
    source: NodeId,
    deadline: &D,
) -> Result<Option<String>, ImpactDeadlineExceeded> {
    if matches!(
        graph.node_kind(source),
        NodeKind::ModuleInit | NodeKind::File
    ) {
        return Ok(None);
    }
    let mut parts = Vec::new();
    let mut seen = HashSet::new();
    let mut current = source;
    for _ in 0..graph.node_count() {
        deadline.check()?;
        if !seen.insert(current) {
            return Ok(None);
        }
        match graph.node_kind(current) {
            NodeKind::File => {
                parts.reverse();
                return Ok(Some(parts.join(".")));
            }
            NodeKind::ModuleInit => return Ok(None),
            _ => parts.push(graph.node_name(current)),
        }
        let mut parents = graph.incoming(current, EdgeKind::Contains);
        let Some(parent) = parents.next() else {
            return Ok(None);
        };
        for other in parents {
            deadline.check()?;
            if other != parent {
                return Ok(None);
            }
        }
        current = parent;
    }
    Ok(None)
}

/// Find `name` inside the source statement owned by one Imports edge.
///
/// Rust and Python spans cover the statement. TypeScript spans cover the
/// module specifier, so the second phase walks back to that statement's
/// `import` keyword. Neither phase can borrow a token from another import.
fn import_line_from_source<D: ImpactDeadline + ?Sized>(
    bundle: &SourceBundle<'_>,
    file: NodeId,
    name: &str,
    edge_span: Option<Span>,
    deadline: &D,
) -> Result<Option<u32>, ImpactDeadlineExceeded> {
    const MAX_IMPORT_STATEMENT_LINES: usize = 1_024;

    deadline.check()?;
    let Some(edge_span) = edge_span else {
        return Ok(None);
    };
    let Some(span_start_line) = bundle
        .line_col(file, edge_span.start())
        .map(|line| line.line)
    else {
        return Ok(None);
    };
    let span_end_offset = edge_span
        .end()
        .saturating_sub(u32::from(edge_span.length() > 0));
    let Some(span_end_line) = bundle.line_col(file, span_end_offset).map(|line| line.line) else {
        return Ok(None);
    };
    let Some(bytes) = bundle.source_bytes(file) else {
        return Ok(None);
    };
    let text = String::from_utf8_lossy(bytes);
    let first_relevant_line = span_start_line.saturating_sub(MAX_IMPORT_STATEMENT_LINES as u32);
    let mut lines = Vec::new();
    for (index, source) in text.lines().take(span_end_line as usize).enumerate() {
        deadline.check()?;
        let line = (index + 1) as u32;
        if line >= first_relevant_line {
            lines.push((line, source));
        }
    }

    for (line, source) in &lines {
        deadline.check()?;
        if *line >= span_start_line
            && *line <= span_end_line
            && line_mentions_identifier(source, name)
        {
            return Ok(Some(*line));
        }
    }

    let mut statement_start_line = None;
    for (line, source) in lines
        .iter()
        .filter(|(line, _)| *line <= span_start_line)
        .rev()
        .take(MAX_IMPORT_STATEMENT_LINES)
    {
        deadline.check()?;
        if starts_static_import_statement(source) {
            statement_start_line = Some(*line);
            break;
        }
    }
    let Some(statement_start_line) = statement_start_line else {
        return Ok(None);
    };

    for (line, source) in &lines {
        deadline.check()?;
        if *line >= statement_start_line
            && *line <= span_end_line
            && line_mentions_identifier(source, name)
        {
            return Ok(Some(*line));
        }
    }
    Ok(None)
}

pub(super) fn source_lines(bundle: &SourceBundle<'_>, file: NodeId) -> Vec<(u32, String)> {
    let Some(bytes) = bundle.source_bytes(file) else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(bytes);
    text.lines()
        .enumerate()
        .map(|(idx, line)| ((idx + 1) as u32, line.to_string()))
        .collect()
}

fn starts_static_import_statement(line: &str) -> bool {
    let trimmed = line.trim_start();
    let Some(rest) = trimmed.strip_prefix("import") else {
        return false;
    };
    rest.chars()
        .next()
        .is_none_or(|character| !is_ident_char(character))
}

pub(super) fn line_mentions_identifier(line: &str, name: &str) -> bool {
    any_identifier_occurrence(line, name, |_, _| true)
}

pub(super) fn any_identifier_occurrence(
    line: &str,
    name: &str,
    predicate: impl FnMut(usize, usize) -> bool,
) -> bool {
    identifier_occurrence(line, name, predicate).is_some()
}

fn identifier_occurrence(
    line: &str,
    name: &str,
    mut predicate: impl FnMut(usize, usize) -> bool,
) -> Option<(usize, usize)> {
    if name.is_empty() {
        return None;
    }
    let mut search_from = 0;
    while let Some(pos) = line[search_from..].find(name) {
        let start = search_from + pos;
        let end = start + name.len();
        let before = line[..start].chars().next_back();
        let after = line[end..].chars().next();
        if !before.is_some_and(is_ident_char)
            && !after.is_some_and(is_ident_char)
            && predicate(start, end)
        {
            return Some((start, end));
        }
        search_from = end;
    }
    None
}

fn is_ident_char(ch: char) -> bool {
    ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()
}

fn is_typescript_like_decl(graph: &CodeGraph<'_>, decl_file: Option<NodeId>) -> bool {
    decl_file
        .map(|file| is_typescript_like_path(graph.node_name(file)))
        .unwrap_or(false)
}

fn is_typescript_like_path(path: &str) -> bool {
    source_language_for_path(Path::new(path)) == SourceLanguage::TypeScript
}

pub(super) fn source_line_at_offset(
    bundle: &SourceBundle<'_>,
    file: NodeId,
    byte_offset: u32,
) -> Option<String> {
    let bytes = bundle.source_bytes(file)?;
    let start = byte_offset as usize;
    if start >= bytes.len() {
        return None;
    }
    let mut line_start = start;
    while line_start > 0 && bytes[line_start - 1] != b'\n' {
        line_start -= 1;
    }
    let mut line_end = start;
    while line_end < bytes.len() && bytes[line_end] != b'\n' {
        line_end += 1;
    }
    Some(String::from_utf8_lossy(&bytes[line_start..line_end]).to_string())
}

fn collect_unresolved_blind_spots_until<D: ImpactDeadline + ?Sized>(
    span_view: &SpanView<'_>,
    deadline: &D,
) -> Result<Vec<UnresolvedBlindSpotEvidence>, ImpactDeadlineExceeded> {
    let unresolved_callsite_count =
        count_unresolved_callsites_in_scanned_files_until(span_view, deadline)?;
    if unresolved_callsite_count == 0 {
        return Ok(Vec::new());
    }
    Ok(vec![UnresolvedBlindSpotEvidence {
        scope: UnresolvedBlindSpotScope::RepoWide,
        unresolved_callsite_count,
    }])
}

/// Count call/reference sites IN THE SCANNED FILES that the resolver could not
/// bind to any declaration. These are exactly the references the resolver tried
/// and failed to resolve: undefined values, member-dispatch / dynamic access on
/// unbound receivers, and unresolved heritage/type positions. The resolver
/// materializes each such miss as an edge from a real-file source node into a
/// phantom `NodeKind::Unresolved` target (see `add_unresolved` in the
/// resolvers).
///
/// Each of these sites contributes NO dependent edge to any declaration, so the
/// "Internal Uses In Scanned Files" list can look complete while omitting them.
/// Surface this as an honest lower bound: the true number of blind spots is at
/// least this many. Lower, not exact: a single unresolved name may back several
/// sites, and external-package references are intentionally covered by the
/// external-consumers limitation rather than parser blindness.
fn count_unresolved_callsites_in_scanned_files_until<D: ImpactDeadline + ?Sized>(
    span_view: &SpanView<'_>,
    deadline: &D,
) -> Result<usize, ImpactDeadlineExceeded> {
    let graph = span_view.graph();
    let mut count = 0usize;
    for unresolved in graph.nodes_of_kind(NodeKind::Unresolved) {
        deadline.check()?;
        for kind in [EdgeKind::Calls, EdgeKind::ValueRef, EdgeKind::TypeRef] {
            for edge in span_view.in_edges(unresolved, kind) {
                deadline.check()?;
                if graph.file_of(edge.source).is_some() {
                    count += 1;
                }
            }
        }
    }
    Ok(count)
}

#[derive(Clone, PartialEq, Eq, serde::Serialize)]
enum DynamicModuleLoadEvidence {
    VerifiedRegistryExport {
        key: String,
        export_name: String,
        kind: DynamicLoader,
    },
    PossibleTemplateRegistryExport {
        key: String,
        export_name: String,
        pattern: String,
    },
    Verified {
        kind: DynamicLoader,
    },
    PossibleTemplateImport {
        pattern: String,
    },
}

impl DynamicModuleLoadEvidence {
    fn sort_key(&self) -> String {
        match self {
            DynamicModuleLoadEvidence::VerifiedRegistryExport {
                key,
                export_name,
                kind,
            } => {
                format!("0:{key}:{export_name}:{}", kind.label())
            }
            DynamicModuleLoadEvidence::PossibleTemplateRegistryExport {
                key,
                export_name,
                pattern,
            } => {
                format!("1:{key}:{export_name}:{pattern}")
            }
            DynamicModuleLoadEvidence::Verified { kind } => {
                format!("2:{}", kind.label())
            }
            DynamicModuleLoadEvidence::PossibleTemplateImport { pattern } => {
                format!("3:{pattern}")
            }
        }
    }

    fn into_public_kind(self) -> DynamicReachabilityKind {
        match self {
            DynamicModuleLoadEvidence::VerifiedRegistryExport {
                key,
                export_name,
                kind,
            } => DynamicReachabilityKind::VerifiedRegistryExport {
                key,
                export_name,
                loader: kind,
            },
            DynamicModuleLoadEvidence::PossibleTemplateRegistryExport {
                key,
                export_name,
                pattern,
            } => DynamicReachabilityKind::PossibleTemplateRegistryExport {
                key,
                export_name,
                loader: DynamicLoader::ImportCall,
                pattern,
            },
            DynamicModuleLoadEvidence::Verified { kind } => {
                DynamicReachabilityKind::VerifiedModuleLoad { loader: kind }
            }
            DynamicModuleLoadEvidence::PossibleTemplateImport { pattern } => {
                DynamicReachabilityKind::PossibleTemplateModuleLoad {
                    loader: DynamicLoader::ImportCall,
                    pattern,
                }
            }
        }
    }
}

struct DynamicModuleLoadRow {
    source_file: NodeId,
    file: String,
    line: u32,
    source_span: Span,
    import_span: Option<Span>,
    evidence: DynamicModuleLoadEvidence,
}

/// Iteration 22: the set of source files that resolve a SPECIFIC export of
/// `decl_file_id` through a member-access edge — `m.foo()` via a dynamic-import
/// namespace binding (the fix), `ns.foo()` via `import * as ns`, or a named
/// import call. Any such precise `Calls`/`ValueRef` edge into this module means
/// the source's use of it is export-level known, so the module-level dynamic
/// reachability hedge (which over-attributes the load to every export) is
/// suppressed for that source. A source with no resolved edge into this module
/// keeps the honest hedge under every export.
fn dynamic_dispatch_resolving_sources_until<D: ImpactDeadline + ?Sized>(
    span_view: &SpanView<'_>,
    decl_file_id: NodeId,
    deadline: &D,
) -> Result<HashSet<NodeId>, ImpactDeadlineExceeded> {
    let graph = span_view.graph();
    let mut sources = HashSet::new();
    for member in graph.outgoing(decl_file_id, EdgeKind::Contains) {
        deadline.check()?;
        for kind in [EdgeKind::Calls, EdgeKind::ValueRef] {
            for edge in span_view.in_edges(member, kind) {
                deadline.check()?;
                if let Some(source_file) = graph.file_of(edge.source) {
                    if source_file != decl_file_id {
                        sources.insert(source_file);
                    }
                }
            }
        }
    }
    Ok(sources)
}

fn collect_dynamic_reachability_until<D: ImpactDeadline + ?Sized>(
    bundle: &SourceBundle<'_>,
    span_view: &SpanView<'_>,
    decl_file: Option<NodeId>,
    decl: NodeId,
    export_name: &str,
    deadline: &D,
) -> Result<Vec<DynamicReachabilityEvidence>, ImpactDeadlineExceeded> {
    let graph = &bundle.graph;
    let Some(decl_file_id) = decl_file else {
        return Ok(Vec::new());
    };

    let mut dynamic_rows: Vec<DynamicModuleLoadRow> =
        collect_registry_export_rows(bundle, span_view, decl_file_id, decl, export_name);
    deadline.check()?;
    let registry_verified_spans: HashSet<(NodeId, Span)> = dynamic_rows
        .iter()
        .filter_map(|row| row.import_span.map(|span| (row.source_file, span)))
        .collect();
    let registry_lines: HashSet<(String, u32)> = dynamic_rows
        .iter()
        .map(|row| (row.file.clone(), row.line))
        .collect();

    // Iteration 22 (dynamic-import export-level precision): source files that
    // resolve a SPECIFIC export of this module via member access — `m.foo()`
    // through a `const m = await import('./mod')` namespace binding (the fix),
    // `ns.foo()` through `import * as ns`, or a named import call — carry a
    // precise `Calls`/`ValueRef` edge into this file and are already attributed
    // to the exact export they touch under "Internal Uses In Scanned Files".
    // For those sources the module-level "verified_dynamic module load" hedge
    // (which attributes the load to EVERY export) is redundant and wrong for
    // the non-accessed exports, so it is suppressed. Sources with NO resolved
    // edge into this file — an escaping `m`, a dynamic specifier `import(expr)`,
    // or whole-object use — keep the honest hedge under every export, so recall
    // is never traded for the precision gain.
    let export_resolving_sources =
        dynamic_dispatch_resolving_sources_until(span_view, decl_file_id, deadline)?;

    for edge in span_view.in_edges(decl_file_id, EdgeKind::Imports) {
        deadline.check()?;
        let Some(source_file) = graph.file_of(edge.source) else {
            continue;
        };
        if source_file == decl_file_id {
            continue;
        }
        if export_resolving_sources.contains(&source_file) {
            continue;
        }
        let Some(span) = edge.span else {
            continue;
        };
        if registry_verified_spans.contains(&(source_file, span)) {
            continue;
        }
        let Some(kind) = classify_dynamic_module_load(bundle, source_file, span) else {
            continue;
        };
        let Some(lc) = bundle.line_col(source_file, span.start()) else {
            continue;
        };
        dynamic_rows.push(DynamicModuleLoadRow {
            source_file,
            file: graph.node_name(source_file).to_string(),
            line: lc.line,
            source_span: span,
            import_span: Some(span),
            evidence: DynamicModuleLoadEvidence::Verified { kind },
        });
    }

    for row in collect_possible_template_import_rows(bundle, decl_file_id) {
        deadline.check()?;
        if registry_lines.contains(&(row.file.clone(), row.line)) {
            continue;
        }
        dynamic_rows.push(row);
    }

    dynamic_rows.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.source_span.start().cmp(&b.source_span.start()))
            .then(a.evidence.sort_key().cmp(&b.evidence.sort_key()))
    });
    dynamic_rows.dedup_by(|a, b| {
        a.file == b.file
            && a.line == b.line
            && a.source_span == b.source_span
            && a.evidence == b.evidence
    });
    deadline.check()?;

    let target_file = graph.node_name(decl_file_id).to_string();
    let mut rows = Vec::with_capacity(dynamic_rows.len());
    for row in dynamic_rows {
        deadline.check()?;
        let caveat = match &row.evidence {
            DynamicModuleLoadEvidence::VerifiedRegistryExport { .. }
            | DynamicModuleLoadEvidence::PossibleTemplateRegistryExport { .. } => {
                DynamicReachabilityCaveat::RuntimeKeySelectionNotProven
            }
            DynamicModuleLoadEvidence::Verified { .. }
            | DynamicModuleLoadEvidence::PossibleTemplateImport { .. } => {
                DynamicReachabilityCaveat::ExportDispatchNotProven
            }
        };
        rows.push(DynamicReachabilityEvidence {
            source_file: row.file,
            source_line: row.line,
            source_span: SourceSpanOffsets {
                start: row.source_span.start(),
                end: row.source_span.end(),
            },
            target_file: target_file.clone(),
            caveat,
            kind: row.evidence.into_public_kind(),
        });
    }
    Ok(rows)
}

fn classify_dynamic_module_load(
    bundle: &SourceBundle<'_>,
    file: NodeId,
    specifier_span: Span,
) -> Option<DynamicLoader> {
    let bytes = bundle.source_bytes(file)?;
    let start = specifier_span.start() as usize;
    if start > bytes.len() {
        return None;
    }

    let mut line_start = start;
    while line_start > 0 && bytes[line_start - 1] != b'\n' {
        line_start -= 1;
    }
    let prefix = &bytes[line_start..start];
    if contains_call_keyword(prefix, b"import", false) {
        Some(DynamicLoader::ImportCall)
    } else if contains_call_keyword(prefix, b"require", true) {
        Some(DynamicLoader::RequireCall)
    } else {
        None
    }
}

fn contains_call_keyword(prefix: &[u8], keyword: &[u8], allow_resolve_member: bool) -> bool {
    if keyword.is_empty() || prefix.len() < keyword.len() {
        return false;
    }
    for i in 0..=prefix.len() - keyword.len() {
        if &prefix[i..i + keyword.len()] != keyword {
            continue;
        }
        if i > 0 && is_ident_byte(prefix[i - 1]) {
            continue;
        }
        let mut p = i + keyword.len();
        if p < prefix.len() && is_ident_byte(prefix[p]) {
            continue;
        }
        if allow_resolve_member && prefix[p..].starts_with(b".resolve") {
            p += b".resolve".len();
        }
        while p < prefix.len() && matches!(prefix[p], b' ' | b'\t') {
            p += 1;
        }
        if prefix.get(p) == Some(&b'(') {
            return true;
        }
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'$')
}

fn collect_registry_export_rows(
    bundle: &SourceBundle<'_>,
    span_view: &SpanView<'_>,
    decl_file_id: NodeId,
    decl: NodeId,
    export_name: &str,
) -> Vec<DynamicModuleLoadRow> {
    let graph = &bundle.graph;
    if !decl_is_exported_from_own_file(span_view, decl, decl_file_id) {
        return Vec::new();
    }

    let mut literal_edges: Vec<(NodeId, Span, DynamicLoader)> = Vec::new();
    for edge in span_view.in_edges(decl_file_id, EdgeKind::Imports) {
        let Some(source_file) = graph.file_of(edge.source) else {
            continue;
        };
        if source_file == decl_file_id {
            continue;
        }
        let Some(span) = edge.span else {
            continue;
        };
        let Some(kind) = classify_dynamic_module_load(bundle, source_file, span) else {
            continue;
        };
        literal_edges.push((source_file, span, kind));
    }

    let target_path = graph.node_name(decl_file_id);
    let mut rows = Vec::new();
    for source_file in graph.nodes_of_kind(NodeKind::File) {
        if source_file == decl_file_id {
            continue;
        }
        let Some(source_bytes) = bundle.source_bytes(source_file) else {
            continue;
        };
        if !source_bytes.contains(&b'{')
            || (!contains_subslice(source_bytes, b"import")
                && !contains_subslice(source_bytes, b"require"))
        {
            continue;
        }
        let source_path = graph.node_name(source_file);
        let specifier_variants = relative_specifier_variants(source_path, target_path);
        let entries = registry_import_entries(source_bytes);
        for entry in entries {
            match entry.import {
                RegistryImport::Literal {
                    kind,
                    specifier_span,
                } => {
                    if !literal_edges
                        .iter()
                        .any(|(edge_file, edge_span, edge_kind)| {
                            *edge_file == source_file
                                && *edge_span == specifier_span
                                && *edge_kind == kind
                        })
                    {
                        continue;
                    }
                    let Some(lc) = bundle.line_col(source_file, entry.key_span.start()) else {
                        continue;
                    };
                    rows.push(DynamicModuleLoadRow {
                        source_file,
                        file: source_path.to_string(),
                        line: lc.line,
                        source_span: entry.key_span,
                        import_span: Some(specifier_span),
                        evidence: DynamicModuleLoadEvidence::VerifiedRegistryExport {
                            key: entry.key,
                            export_name: export_name.to_string(),
                            kind,
                        },
                    });
                }
                RegistryImport::Template { pattern } => {
                    if specifier_variants.is_empty()
                        || !specifier_variants
                            .iter()
                            .any(|candidate| template_pattern_matches(&pattern, candidate))
                    {
                        continue;
                    }
                    let Some(lc) = bundle.line_col(source_file, entry.key_span.start()) else {
                        continue;
                    };
                    rows.push(DynamicModuleLoadRow {
                        source_file,
                        file: source_path.to_string(),
                        line: lc.line,
                        source_span: entry.key_span,
                        import_span: None,
                        evidence: DynamicModuleLoadEvidence::PossibleTemplateRegistryExport {
                            key: entry.key,
                            export_name: export_name.to_string(),
                            pattern: pattern.display(),
                        },
                    });
                }
            }
        }
    }
    rows
}

fn decl_is_exported_from_own_file(
    span_view: &SpanView<'_>,
    decl: NodeId,
    decl_file_id: NodeId,
) -> bool {
    let graph = span_view.graph();
    span_view
        .in_edges(decl, EdgeKind::Exports)
        .any(|edge| graph.file_of(edge.source) == Some(decl_file_id))
}

#[derive(Debug, Clone, serde::Serialize)]
struct RegistryImportEntry {
    key: String,
    key_span: Span,
    import: RegistryImport,
}

#[derive(Debug, Clone, serde::Serialize)]
enum RegistryImport {
    Literal {
        kind: DynamicLoader,
        specifier_span: Span,
    },
    Template {
        pattern: TemplateImportPattern,
    },
}

fn registry_import_entries(source: &[u8]) -> Vec<RegistryImportEntry> {
    let mut lexer = Lexer::new(source);
    let mut entries = Vec::new();
    let mut prev_kind: Option<TokenKind> = None;
    loop {
        let token = lexer.next();
        match token.kind {
            TokenKind::Eof => break,
            TokenKind::LBrace if can_start_object_literal(prev_kind) => {
                scan_registry_object_entries(source, &mut lexer, &mut entries);
                prev_kind = Some(TokenKind::RBrace);
            }
            _ => {
                prev_kind = Some(token.kind);
            }
        }
    }
    entries
}

fn can_start_object_literal(prev_kind: Option<TokenKind>) -> bool {
    matches!(
        prev_kind,
        Some(
            TokenKind::Eq
                | TokenKind::LParen
                | TokenKind::LBracket
                | TokenKind::Comma
                | TokenKind::Colon
                | TokenKind::Return
        )
    )
}

fn scan_registry_object_entries(
    source: &[u8],
    lexer: &mut Lexer<'_>,
    entries: &mut Vec<RegistryImportEntry>,
) {
    loop {
        let token = lexer.next();
        match token.kind {
            TokenKind::Eof | TokenKind::RBrace => break,
            TokenKind::Comma | TokenKind::Semi => continue,
            TokenKind::Spread => {
                let ended_object = scan_registry_value_imports(source, lexer).1;
                if ended_object {
                    break;
                }
            }
            _ => {
                let Some(key) = property_key_text(source, &token) else {
                    continue;
                };
                if !matches!(lexer.next().kind, TokenKind::Colon) {
                    continue;
                }
                let (imports, ended_object) = scan_registry_value_imports(source, lexer);
                for import in imports {
                    entries.push(RegistryImportEntry {
                        key: key.clone(),
                        key_span: token.span,
                        import,
                    });
                }
                if ended_object {
                    break;
                }
            }
        }
    }
}

fn scan_registry_value_imports(
    source: &[u8],
    lexer: &mut Lexer<'_>,
) -> (Vec<RegistryImport>, bool) {
    let mut imports = Vec::new();
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    loop {
        let token = lexer.next();
        match token.kind {
            TokenKind::Eof => return (imports, true),
            TokenKind::Comma if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 => {
                return (imports, false);
            }
            TokenKind::RBrace if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 => {
                return (imports, true);
            }
            TokenKind::LBrace => brace_depth += 1,
            TokenKind::RBrace => brace_depth = brace_depth.saturating_sub(1),
            TokenKind::LParen => paren_depth += 1,
            TokenKind::RParen => paren_depth = paren_depth.saturating_sub(1),
            TokenKind::LBracket => bracket_depth += 1,
            TokenKind::RBracket => bracket_depth = bracket_depth.saturating_sub(1),
            TokenKind::Import => {
                if let Some(import) =
                    read_registry_dynamic_call(source, lexer, DynamicLoader::ImportCall)
                {
                    imports.push(import);
                }
            }
            TokenKind::Ident if token_text(source, token.span) == Some("require") => {
                if let Some(import) =
                    read_registry_dynamic_call(source, lexer, DynamicLoader::RequireCall)
                {
                    imports.push(import);
                }
            }
            _ => {}
        }
    }
}

fn read_registry_dynamic_call(
    source: &[u8],
    lexer: &mut Lexer<'_>,
    kind: DynamicLoader,
) -> Option<RegistryImport> {
    let saved = lexer.checkpoint();
    if !matches!(lexer.next().kind, TokenKind::LParen) {
        lexer.restore(saved);
        return None;
    }

    let arg = lexer.next();
    let import = match arg.kind {
        TokenKind::Str => {
            string_inner_span(source, arg.span).map(|specifier_span| RegistryImport::Literal {
                kind,
                specifier_span,
            })
        }
        TokenKind::TemplateStart if kind == DynamicLoader::ImportCall => {
            read_one_hole_template_import(source, arg.span, lexer)
                .map(|pattern| RegistryImport::Template { pattern })
        }
        _ => None,
    };
    skip_to_matching_paren(lexer);
    import
}

fn skip_to_matching_paren(lexer: &mut Lexer<'_>) {
    let mut depth = 1usize;
    while depth > 0 {
        let token = lexer.next();
        match token.kind {
            TokenKind::Eof => break,
            TokenKind::LParen => depth += 1,
            TokenKind::RParen => depth -= 1,
            _ => {}
        }
    }
}

fn property_key_text(source: &[u8], token: &Token) -> Option<String> {
    match token.kind {
        TokenKind::Ident => token_text(source, token.span).map(str::to_string),
        TokenKind::Str => string_literal_text(source, token.span),
        kind if is_keyword_property_key(kind) => token_text(source, token.span).map(str::to_string),
        _ => None,
    }
}

fn is_keyword_property_key(kind: TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Import
            | TokenKind::Export
            | TokenKind::From
            | TokenKind::As
            | TokenKind::Type
            | TokenKind::Interface
            | TokenKind::Class
            | TokenKind::Enum
            | TokenKind::Function
            | TokenKind::Const
            | TokenKind::Let
            | TokenKind::Var
            | TokenKind::If
            | TokenKind::Else
            | TokenKind::For
            | TokenKind::While
            | TokenKind::Do
            | TokenKind::Switch
            | TokenKind::Case
            | TokenKind::Default
            | TokenKind::Return
            | TokenKind::Break
            | TokenKind::Continue
            | TokenKind::Throw
            | TokenKind::Try
            | TokenKind::Catch
            | TokenKind::Finally
            | TokenKind::New
            | TokenKind::Typeof
            | TokenKind::In
            | TokenKind::Of
            | TokenKind::Instanceof
            | TokenKind::Void
            | TokenKind::Delete
            | TokenKind::Yield
            | TokenKind::Async
            | TokenKind::Await
    )
}

fn token_text(source: &[u8], span: Span) -> Option<&str> {
    let start = span.start() as usize;
    let end = span.end() as usize;
    std::str::from_utf8(source.get(start..end)?).ok()
}

fn string_literal_text(source: &[u8], span: Span) -> Option<String> {
    let inner = string_inner_span(source, span)?;
    let start = inner.start() as usize;
    let end = inner.end() as usize;
    Some(String::from_utf8_lossy(source.get(start..end)?).into_owned())
}

fn string_inner_span(source: &[u8], span: Span) -> Option<Span> {
    let start = span.start() as usize;
    let end = span.end() as usize;
    if end > source.len() || end < start + 2 {
        return None;
    }
    Some(Span::new((start + 1) as u32, (end - start - 2) as u32))
}

#[derive(Debug, Clone, serde::Serialize)]
struct TemplateImportPattern {
    prefix: String,
    suffix: String,
    span: Span,
}

fn collect_possible_template_import_rows(
    bundle: &SourceBundle<'_>,
    decl_file_id: NodeId,
) -> Vec<DynamicModuleLoadRow> {
    let graph = &bundle.graph;
    let target_path = graph.node_name(decl_file_id);
    let mut rows = Vec::new();
    for source_file in graph.nodes_of_kind(NodeKind::File) {
        if source_file == decl_file_id {
            continue;
        }
        let Some(source_bytes) = bundle.source_bytes(source_file) else {
            continue;
        };
        if !source_bytes.contains(&b'`') || !contains_subslice(source_bytes, b"import") {
            continue;
        }
        let source_path = graph.node_name(source_file);
        let specifier_variants = relative_specifier_variants(source_path, target_path);
        if specifier_variants.is_empty() {
            continue;
        }
        for pattern in template_import_patterns(source_bytes) {
            if !specifier_variants
                .iter()
                .any(|candidate| template_pattern_matches(&pattern, candidate))
            {
                continue;
            }
            let Some(lc) = bundle.line_col(source_file, pattern.span.start()) else {
                continue;
            };
            rows.push(DynamicModuleLoadRow {
                source_file,
                file: source_path.to_string(),
                line: lc.line,
                source_span: pattern.span,
                import_span: None,
                evidence: DynamicModuleLoadEvidence::PossibleTemplateImport {
                    pattern: pattern.display(),
                },
            });
        }
    }
    rows
}

impl TemplateImportPattern {
    fn display(&self) -> String {
        format!("{}${{...}}{}", self.prefix, self.suffix)
    }
}

fn template_import_patterns(source: &[u8]) -> Vec<TemplateImportPattern> {
    let mut lexer = Lexer::new(source);
    let mut out = Vec::new();
    loop {
        let token = lexer.next();
        match token.kind {
            TokenKind::Eof => break,
            TokenKind::Import => {
                if !matches!(lexer.next().kind, TokenKind::LParen) {
                    continue;
                }
                let template = lexer.next();
                if !matches!(template.kind, TokenKind::TemplateStart) {
                    continue;
                }
                if let Some(pattern) =
                    read_one_hole_template_import(source, template.span, &mut lexer)
                {
                    out.push(pattern);
                }
            }
            _ => {}
        }
    }
    out
}

fn read_one_hole_template_import(
    source: &[u8],
    start_span: Span,
    lexer: &mut Lexer<'_>,
) -> Option<TemplateImportPattern> {
    let prefix = read_template_start_prefix(source, start_span)?;
    let end_span = loop {
        let token = lexer.next();
        match token.kind {
            TokenKind::TemplateEnd => {
                break token.span;
            }
            TokenKind::TemplateMid | TokenKind::Eof => return None,
            _ => {}
        }
    };
    let suffix = read_template_end_suffix(source, end_span)?;
    if prefix.is_empty() || prefix.as_bytes().contains(&b'\\') || suffix.as_bytes().contains(&b'\\')
    {
        return None;
    }
    Some(TemplateImportPattern {
        prefix,
        suffix,
        span: start_span,
    })
}

fn read_template_start_prefix(source: &[u8], span: Span) -> Option<String> {
    let start = span.start() as usize;
    let end = (span.start() + span.length()) as usize;
    let bytes = source.get(start..end)?;
    if bytes.first() != Some(&b'`') || !bytes.ends_with(b"${") {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[1..bytes.len() - 2]).into_owned())
}

fn read_template_end_suffix(source: &[u8], span: Span) -> Option<String> {
    let start = span.start() as usize;
    let end = (span.start() + span.length()) as usize;
    let bytes = source.get(start..end)?;
    if bytes.first() != Some(&b'}') || bytes.last() != Some(&b'`') {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[1..bytes.len() - 1]).into_owned())
}

fn template_pattern_matches(pattern: &TemplateImportPattern, candidate: &str) -> bool {
    candidate.starts_with(&pattern.prefix)
        && candidate.ends_with(&pattern.suffix)
        && candidate.len() > pattern.prefix.len() + pattern.suffix.len()
}

fn relative_specifier_variants(importing_path: &str, target_path: &str) -> Vec<String> {
    let rel = relative_path_from_importer(importing_path, target_path);
    let mut out = Vec::new();
    push_unique(&mut out, rel.clone());
    if let Some(no_ext) = strip_supported_extension(&rel) {
        push_unique(&mut out, no_ext);
    }
    if let Some(index_parent) = strip_index_file(&rel) {
        push_unique(&mut out, index_parent);
    }
    out
}

fn push_unique(out: &mut Vec<String>, value: String) {
    if !out.iter().any(|existing| existing == &value) {
        out.push(value);
    }
}

fn relative_path_from_importer(importing_path: &str, target_path: &str) -> String {
    let importing_dir = importing_path
        .rsplit_once('/')
        .map(|(d, _)| d)
        .unwrap_or(".");
    let from = path_components(importing_dir);
    let to = path_components(target_path);
    let mut common = 0usize;
    while common < from.len() && common < to.len() && from[common] == to[common] {
        common += 1;
    }
    let mut parts: Vec<String> = Vec::new();
    for _ in common..from.len() {
        parts.push("..".to_string());
    }
    for part in &to[common..] {
        parts.push((*part).to_string());
    }
    if parts.is_empty() {
        return ".".to_string();
    }
    let joined = parts.join("/");
    if joined.starts_with("../") {
        joined
    } else {
        format!("./{joined}")
    }
}

fn path_components(path: &str) -> Vec<&str> {
    path.trim_start_matches("./")
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect()
}

fn strip_supported_extension(path: &str) -> Option<String> {
    for ext in [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"] {
        if let Some(stripped) = path.strip_suffix(ext) {
            return Some(stripped.to_string());
        }
    }
    None
}

fn strip_index_file(path: &str) -> Option<String> {
    for ext in [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"] {
        let suffix = format!("/index{ext}");
        if let Some(stripped) = path.strip_suffix(&suffix) {
            return Some(stripped.to_string());
        }
    }
    None
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Graph limitations that apply to every evidence projection.
pub fn standard_limitations() -> Vec<Limitation> {
    vec![
        Limitation::ExternalConsumers,
        Limitation::MemberDispatch,
        Limitation::Dynamic,
        Limitation::UnresolvedBindings,
    ]
}

/// Returns true when an import-edge label names the queried symbol, including
/// default-import aliases encoded as `default as Local`.
pub(super) fn import_label_mentions_named(label: &str, name: &str) -> bool {
    if !label.contains('{') {
        for entry in label.split(',') {
            let entry = entry.trim().strip_prefix("type ").unwrap_or(entry.trim());
            let source_name = entry.split(" as ").next().unwrap_or(entry).trim();
            if source_name == name {
                return true;
            }
        }
    }

    let prefix = label.split('{').next().unwrap_or(label);
    for segment in prefix.split(',') {
        let segment = segment.trim();
        if let Some(local) = segment.strip_prefix("default as ") {
            if local.trim() == name {
                return true;
            }
        }
    }

    let Some(brace_start) = label.find('{') else {
        return false;
    };
    let Some(brace_end) = label[brace_start..].find('}') else {
        return false;
    };
    let inside = &label[brace_start + 1..brace_start + brace_end];
    for entry in inside.split(',') {
        let entry = entry.trim();
        let entry = entry.strip_prefix("type ").unwrap_or(entry);
        let source_name = entry.split_whitespace().next().unwrap_or(entry);
        if source_name == name {
            return true;
        }
    }
    false
}

fn is_python_file(path: &str) -> bool {
    path.ends_with(".py") || path.ends_with(".pyi")
}

pub(super) fn python_import_local_name<'a>(label: &'a str, imported_name: &str) -> Option<&'a str> {
    if label.contains('{') || label.contains(',') {
        return None;
    }
    let label = label.trim();
    let (source_name, local_name) = label
        .split_once(" as ")
        .map_or((label, label), |(source, local)| {
            (source.trim(), local.trim())
        });
    (source_name == imported_name).then_some(local_name)
}

/// Source-byte check for wildcard exports. The resolver materializes
/// `export *` as one labeled edge per resolved name, so the persisted edge
/// label alone can't distinguish wildcard from named re-export syntax.
fn line_at_span_is_wildcard_export(bundle: &SourceBundle<'_>, file: NodeId, span: Span) -> bool {
    let bytes = match bundle.source_bytes(file) {
        Some(b) => b,
        None => return false,
    };
    let start = span.start() as usize;
    if start >= bytes.len() {
        return false;
    }
    let mut line_start = start;
    while line_start > 0 && bytes[line_start - 1] != b'\n' {
        line_start -= 1;
    }
    let mut p = line_start;
    while p < bytes.len() && matches!(bytes[p], b' ' | b'\t') {
        p += 1;
    }
    const EXPORT_KW: &[u8] = b"export";
    if !bytes[p..].starts_with(EXPORT_KW) {
        return false;
    }
    p += EXPORT_KW.len();
    if !bytes.get(p).is_some_and(|b| matches!(b, b' ' | b'\t')) {
        return false;
    }
    while p < bytes.len() && matches!(bytes[p], b' ' | b'\t') {
        p += 1;
    }
    if bytes[p..].starts_with(b"type") {
        let after = p + 4;
        if bytes.get(after).is_some_and(|b| matches!(b, b' ' | b'\t')) {
            p = after;
            while p < bytes.len() && matches!(bytes[p], b' ' | b'\t') {
                p += 1;
            }
        }
    }
    bytes.get(p) == Some(&b'*')
}
