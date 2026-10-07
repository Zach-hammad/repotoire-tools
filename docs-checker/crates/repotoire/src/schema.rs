use crate::spans::Span;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeKind {
    File = 1,
    Module = 2,
    Class = 3,
    Interface = 4,
    TypeAlias = 5,
    Enum = 6,
    EnumMember = 7,
    Function = 8,
    Property = 9,
    Variable = 10,
    Unresolved = 11,
    ModuleInit = 12,
    External = 13,
    Decorator = 14,
    Route = 15,
    Test = 16,
    Query = 17,
    Tenant = 18,
    QueryParameter = 19,
    TenantValidation = 20,
    QueryLabel = 21,
    QueryRelationship = 22,
    QueryProperty = 23,
    Struct = 24,
    Union = 25,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    Contains = 1,
    Calls = 2,
    Imports = 3,
    Exports = 4,
    Extends = 5,
    Implements = 6,
    ValueRef = 7,
    TypeRef = 8,
    DecoratedBy = 9,
    DefinesRoute = 10,
    EmbedsQuery = 11,
    MentionsTenant = 12,
    BindsParameter = 13,
    ValidatesTenant = 14,
    MentionsQueryLabel = 15,
    MentionsQueryRelationship = 16,
    MentionsQueryProperty = 17,
}

/// Parse-time position discriminant for a `TypeRef` edge (G1.5 Fix 2 §3.2,
/// option 2b). Records WHERE in the source a type reference occurred —
/// annotation head, return-type position, a declaration-site constraint,
/// a union/intersection/conditional/infer/mapped composition member, or an
/// expression-position generic argument (`satisfies`/`as`). This is parse-time
/// classification only; it says nothing yet about whether the reference is
/// under compiler PRESSURE (spec §2.2) — that judgment is Fix 2's later task
/// (F2-3), which reads this discriminant to decide how to weight/report a
/// `type_surface` site. `Other` is the deliberate fail-open bucket for shapes
/// this task's parser integration hasn't been taught to distinguish yet —
/// consumers must treat it exactly like "no information," never as a signal.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[repr(u8)]
pub enum TypeRefPosition {
    /// Annotation head of unknown/other enclosure, e.g. a property or
    /// body-local variable annotation `x: T`. Kept as discriminant 0 for
    /// legacy-data compatibility; parameter-position annotations now use
    /// `ParamAnnotation` instead (G1.6 D4) — see that variant's doc comment
    /// for exactly which shapes route here vs. there.
    Annotation = 0,
    /// Function/method return-type position, e.g. `(): T`.
    ReturnType = 1,
    /// Type-parameter constraint in a DECLARATION, e.g. `<T extends X>`.
    ConstraintDecl = 2,
    /// Direct member of a union/intersection, or inside a conditional/infer/
    /// mapped type-level expression.
    CompositionMember = 3,
    /// `satisfies` / `as` / expression-position generic type arguments.
    ValuePosition = 4,
    /// Anything else — fail-open to pressure (see F2-3); never a positive
    /// signal on its own. Also the `#[default]` so any legacy serialized
    /// `TypeRef` event without a `position` field deserializes as "no info".
    #[default]
    Other = 5,
    /// Parameter type-annotation head of a callable's own parameter list
    /// (G1.6 D4): function declarations/expressions/arrows, class methods
    /// (incl. object-method shorthand and interface method signatures),
    /// constructors (incl. param-property fields), and the parameter list
    /// of a function-TYPE expression (`type H = (s: State) => R`, and any
    /// nested function-type wherever it appears). Distinguishes "T is part
    /// of a callable's parameter surface" from `Annotation`'s body-local /
    /// property annotation, which the walk-side alone (M0-B) cannot tell
    /// apart — both previously shared discriminant 0.
    ParamAnnotation = 6,
    /// Member of an object-literal TYPE-ALIAS body whose inherited base
    /// would otherwise have been `Other` (G1.9 S2): `type Hooks = {
    /// beforeRequest?: Hook[] }` — `Hook` records `AliasMemberAnnotation`,
    /// not `Other`. Scope, precisely:
    /// - Applies ONLY to object-literal members reached from
    ///   `parse_object_or_mapped_type` whose currently-inherited
    ///   `pos_stack` top is `Other` at the point the member's value type is
    ///   parsed — i.e. exactly the shapes that recorded `Other` before this
    ///   variant existed. That population is BROADER than type-alias
    ///   members alone: (a) alias-rooted object literals (the alias RHS's
    ///   own top-level object literal, and any object literal nested
    ///   inside one, however deep, as long as no intervening context
    ///   pushed a different base), AND (b) any other context whose
    ///   inherited base is `Other` — currently object literals inside a
    ///   TYPE-POSITION generic-argument list (`const x: Foo<{ a: Bar }>`,
    ///   `type T = Foo<{ Variables: V }>`), because `parse_type_args`
    ///   deliberately resets the base to `Other` for argument subtrees
    ///   (F2-2). Disclosed-population pin:
    ///   `ts::parser::tests::alias_member_annotation_generic_argument_object_member_is_a_disclosed_population_member`.
    ///   Consumers (the M0/D2 measurement tasks in particular) must
    ///   interpret the chain-collection population as inherited-`Other`,
    ///   not alias-only.
    /// - Does NOT apply to the alias RHS's own head reference (`type A =
    ///   B` — `B` stays `Other`), to interface properties
    ///   (`parse_interface_body_emitting_refs` is separate code and keeps
    ///   `Annotation`), or to an object-literal member reached from any
    ///   OTHER inherited base — e.g. a parameter's inline object type
    ///   (`function f(o: { a: X }) {}`, base `ParamAnnotation`) or a
    ///   `satisfies`/`as` object type (base `ValuePosition`) keep their
    ///   current base unchanged. This is the additivity constraint: the
    ///   re-arm fires IFF the inherited base was `Other`, never widening
    ///   into an already-classified context.
    ///
    /// Like `Other`, this is NOT a positive pressure signal on its own —
    /// `collect_compiler_pressure`'s F2-3 sub_channel discriminant keeps it
    /// in the same non-demoted `type_surface` bucket `Other` occupies.
    /// Consumers that want to treat it as a signal must opt in explicitly:
    /// the consumer-call-site chain accumulator
    /// (`compiler_pressure::collect_consumer_call_site_pressure`) only
    /// collects a chain segment off this position when the fail-closed
    /// `G19_ALIAS_MEMBER_CHAIN=1` env gate is set; with the gate unset
    /// (the default) a `TypeRef` recorded at this position is inert,
    /// exactly like `Other`.
    AliasMemberAnnotation = 7,
}

impl TypeRefPosition {
    pub const COUNT: usize = 8;

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(TypeRefPosition::Annotation),
            1 => Some(TypeRefPosition::ReturnType),
            2 => Some(TypeRefPosition::ConstraintDecl),
            3 => Some(TypeRefPosition::CompositionMember),
            4 => Some(TypeRefPosition::ValuePosition),
            5 => Some(TypeRefPosition::Other),
            6 => Some(TypeRefPosition::ParamAnnotation),
            7 => Some(TypeRefPosition::AliasMemberAnnotation),
            _ => None,
        }
    }
}

/// One argument-interior anchor captured at parse time for a `Call`'s
/// argument list (G1.6 spec §7 fork resolution (a): parse-time interior
/// anchors, folded into the same format-version bump as D4's
/// `TypeRefPosition::ParamAnnotation`). Lives here (not in `ts::events`)
/// because both the parser-event shape (`ts::events::RefEvent::Call`) and
/// the builder/CSR layer (`builder.rs`, `csr.rs`) need it — the same
/// cross-cutting reason `TypeRefPosition` above lives in this module rather
/// than `ts::events`.
///
/// Capture is GENERIC over every call: no type knowledge and no chain
/// filtering happen here — a later walk (G1.6 W1) decides which anchors are
/// under compiler pressure. This parser-side pass only answers "where, in
/// this call's argument list, might a compiler-relevant line live?":
///
/// - [`CallArgumentAnchor::CallbackHead`] — the head span of a
///   function-expression/arrow literal found while descending an argument's
///   literal structure: directly as an argument, as an element of an
///   array-literal argument, or nested inside an object-literal argument
///   (bounded by the same depth as `ObjectKey` below). "Head span" is
///   deliberately minimal — the literal's own first token — because only
///   line granularity is needed downstream (`bundle.line_col`).
/// - [`CallArgumentAnchor::ObjectKey`] — an object-literal property key
///   whose value transitively contains a callback (directly, nested inside
///   further objects up to depth 4, or via an array of callbacks — the
///   ky-hooks shape `{ hooks: { beforeRetry: [cb] } }` yields exactly one
///   `ObjectKey` at `beforeRetry` with `path == "hooks.beforeRetry"`, plus a
///   sibling `CallbackHead` for `cb`). A key whose value never leads to a
///   callback (`{ method: 'POST' }`) yields no anchor — precision-friendly,
///   rows only at compiler-plausible positions (spec §7).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CallArgumentAnchor {
    CallbackHead {
        /// 0-based index of the top-level call argument this callback was
        /// found within (the callback itself may be nested inside that
        /// argument's array/object structure).
        arg_index: u16,
        span: Span,
    },
    ObjectKey {
        /// 0-based index of the top-level call argument this key's
        /// containing object literal is (nested inside of, or is).
        arg_index: u16,
        /// The key's own name (last path segment) — e.g. `"beforeRetry"`.
        name: String,
        span: Span,
        /// Dotted key path from the argument root to this key, e.g.
        /// `"hooks.beforeRetry"`. Depth (dot count + 1) is bounded to 4,
        /// mirroring Pattern PC's property-chain depth discipline.
        path: String,
    },
}

/// Origin classification for an `External` node — best-effort, used for
/// querying "what runtime/platform APIs does this code touch?". See spec
/// §3.1: `ImportedPackage` is provable; `AmbientGlobal` comes from a small
/// curated common-globals list (tagging-only, never filtering, so
/// incompleteness is harmless); `Unknown` is where most ambient DOM types
/// AND genuine typos land (cannot be distinguished without lib.d.ts).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalOrigin {
    ImportedPackage = 1,
    AmbientGlobal = 2,
    Unknown = 3,
}

impl ExternalOrigin {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(ExternalOrigin::ImportedPackage),
            2 => Some(ExternalOrigin::AmbientGlobal),
            3 => Some(ExternalOrigin::Unknown),
            _ => None,
        }
    }
}

impl NodeKind {
    pub const COUNT: usize = 25;

    pub fn is_type_container(self) -> bool {
        matches!(self, Self::Class | Self::Struct | Self::Union)
    }

    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(NodeKind::File),
            2 => Some(NodeKind::Module),
            3 => Some(NodeKind::Class),
            4 => Some(NodeKind::Interface),
            5 => Some(NodeKind::TypeAlias),
            6 => Some(NodeKind::Enum),
            7 => Some(NodeKind::EnumMember),
            8 => Some(NodeKind::Function),
            9 => Some(NodeKind::Property),
            10 => Some(NodeKind::Variable),
            11 => Some(NodeKind::Unresolved),
            12 => Some(NodeKind::ModuleInit),
            13 => Some(NodeKind::External),
            14 => Some(NodeKind::Decorator),
            15 => Some(NodeKind::Route),
            16 => Some(NodeKind::Test),
            17 => Some(NodeKind::Query),
            18 => Some(NodeKind::Tenant),
            19 => Some(NodeKind::QueryParameter),
            20 => Some(NodeKind::TenantValidation),
            21 => Some(NodeKind::QueryLabel),
            22 => Some(NodeKind::QueryRelationship),
            23 => Some(NodeKind::QueryProperty),
            24 => Some(NodeKind::Struct),
            25 => Some(NodeKind::Union),
            _ => None,
        }
    }
}

impl EdgeKind {
    pub const COUNT: usize = 17;

    pub const ALL: [EdgeKind; EdgeKind::COUNT] = [
        EdgeKind::Contains,
        EdgeKind::Calls,
        EdgeKind::Imports,
        EdgeKind::Exports,
        EdgeKind::Extends,
        EdgeKind::Implements,
        EdgeKind::ValueRef,
        EdgeKind::TypeRef,
        EdgeKind::DecoratedBy,
        EdgeKind::DefinesRoute,
        EdgeKind::EmbedsQuery,
        EdgeKind::MentionsTenant,
        EdgeKind::BindsParameter,
        EdgeKind::ValidatesTenant,
        EdgeKind::MentionsQueryLabel,
        EdgeKind::MentionsQueryRelationship,
        EdgeKind::MentionsQueryProperty,
    ];

    pub fn from_u16(value: u16) -> Option<EdgeKind> {
        match value {
            1 => Some(EdgeKind::Contains),
            2 => Some(EdgeKind::Calls),
            3 => Some(EdgeKind::Imports),
            4 => Some(EdgeKind::Exports),
            5 => Some(EdgeKind::Extends),
            6 => Some(EdgeKind::Implements),
            7 => Some(EdgeKind::ValueRef),
            8 => Some(EdgeKind::TypeRef),
            9 => Some(EdgeKind::DecoratedBy),
            10 => Some(EdgeKind::DefinesRoute),
            11 => Some(EdgeKind::EmbedsQuery),
            12 => Some(EdgeKind::MentionsTenant),
            13 => Some(EdgeKind::BindsParameter),
            14 => Some(EdgeKind::ValidatesTenant),
            15 => Some(EdgeKind::MentionsQueryLabel),
            16 => Some(EdgeKind::MentionsQueryRelationship),
            17 => Some(EdgeKind::MentionsQueryProperty),
            _ => None,
        }
    }
}
