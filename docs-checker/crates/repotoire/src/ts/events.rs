//! Event types emitted by the parser. See spec §5.3.

use crate::schema::TypeRefPosition;
use crate::spans::Span;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::cell::Cell;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedFile {
    pub path: String,
    pub events: Vec<Event>,
    pub exports: Vec<ExportEntry>,
    /// Parse diagnostics are evidence about omitted or recovered source, so
    /// they are part of the reusable parse result. Cache reuse must preserve
    /// them exactly: downstream diagnostic health and impact trust consume the
    /// same `ParsedFile` evidence as graph resolution.
    pub diagnostics: Vec<crate::ts::diagnostics::Diagnostic>,
    /// Names of `type X = …` declarations found inside function/method bodies.
    /// These are not emitted as top-level `DeclEvent::TypeAlias` entries (they
    /// are function-local and don't create graph nodes), but references to them
    /// from type-annotation positions inside the same body must be suppressed
    /// rather than leaked as `External(Unknown)`.
    pub local_type_names: Vec<String>,
    /// Names declared inside `declare global { ... }` blocks. Declaration
    /// files with real imports are external modules, but TypeScript still
    /// exposes declarations inside explicit `declare global` blocks as ambient
    /// globals.
    pub ambient_global_decl_names: Vec<String>,
    /// v0.5 commit 2 — lexical-scope sidecar. `ScopeId(0)` is always the
    /// file's module top-level. Function/method/arrow body opens, block
    /// statement opens, for/while/if/catch body opens push new ScopeIds;
    /// `ScopeInfo.parent` chains back through the lexical nesting.
    /// Consumed by the resolver starting in commit 5 for
    /// `MemberReceiver::Name { scope, .. }` lookups; commit 2 emits the
    /// stack but no consumer reads it yet (pure plumbing).
    pub scopes: Vec<ScopeInfo>,
    /// v0.5 commit 3 — binding-emission sidecar. Lexical binding facts
    /// emitted alongside (but distinct from) the events stream. Top-level
    /// `let`/`const` emit BOTH a `DeclEvent::Variable` (graph node) AND
    /// a `BindingEvent` (lexical fact); ordinary local variable declarations
    /// do the same, with lexical visibility in `local_value_decls`. Parameter,
    /// catch and loop-header bindings remain binding-only. None-origin bindings are
    /// still emitted because they block outer-scope fallback per the
    /// shadowing rule. Consumed by the resolver scope-walk in commit 5;
    /// commit 3 only emits — no consumer reads them yet.
    pub bindings: Vec<BindingEvent>,
    /// Local value declarations that are graph-visible but lexical in
    /// lookup scope. Used for nested helpers such as React component-local
    /// `function handleSave() {}` declarations: impact should find the helper,
    /// while ordinary call resolution should only see it through the scope
    /// chain where it is actually bound.
    pub local_value_decls: Vec<LocalValueDecl>,
    /// v0.6 commit 1 — per-file function-return-type sidecar for
    /// factory-return inference (Pattern F). Each entry names a
    /// plain-function or const-arrow declaration in this file along
    /// with the plain-Ident class name from its declared return type.
    /// Static-method return types are NOT in this sidecar — they live
    /// on `DeclEvent::Method.return_class_name`. Populated by the
    /// parser in v0.6 commit 2; consumed by the resolver in v0.6
    /// commit 4 to resolve `FactoryRef::Plain { name }` lookups.
    /// Empty in commit 1 (no extraction yet).
    pub function_returns: Vec<FunctionReturn>,
}

#[cfg(test)]
thread_local! {
    static PARSED_FILE_CLONE_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_parsed_file_clone_count() {
    PARSED_FILE_CLONE_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn parsed_file_clone_count() -> usize {
    PARSED_FILE_CLONE_COUNT.with(|count| count.get())
}

impl Clone for ParsedFile {
    fn clone(&self) -> Self {
        #[cfg(test)]
        PARSED_FILE_CLONE_COUNT.with(|count| count.set(count.get() + 1));

        Self {
            path: self.path.clone(),
            events: self.events.clone(),
            exports: self.exports.clone(),
            diagnostics: self.diagnostics.clone(),
            local_type_names: self.local_type_names.clone(),
            ambient_global_decl_names: self.ambient_global_decl_names.clone(),
            scopes: self.scopes.clone(),
            bindings: self.bindings.clone(),
            local_value_decls: self.local_value_decls.clone(),
            function_returns: self.function_returns.clone(),
        }
    }
}

/// A lexical scope. `ScopeId(0)` is the file's module top-level. Modules
/// don't share lexical scope so numbering is per-file (decision Q3 in
/// the plan doc). Indexed into `ParsedFile.scopes` to read
/// `ScopeInfo.parent` / `enclosing_decl`.
pub type ScopeId = u32;

/// A single record in the per-file scope sidecar. The `parent` chain
/// captures lexical nesting; `enclosing_decl` (optional) names the
/// owning declaration so the resolver can attribute scoped lookups to
/// the right owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeInfo {
    /// `None` for `ScopeId(0)` (module top-level). Otherwise points at
    /// the immediately enclosing lexical scope.
    pub parent: Option<ScopeId>,
    /// `decl_index` of the enclosing declaration when the scope's
    /// opener is a decl boundary (function body, method body, etc.).
    /// `None` for plain block statements / control-flow bodies whose
    /// scope doesn't correspond to a declaration. Independent of
    /// `parent`: a `{ … }` block inside a function body has
    /// `enclosing_decl: None` but `parent: <the function's scope>`.
    pub enclosing_decl: Option<u32>,
}

/// Origin of a class-typed binding, captured at parse time. Drives the
/// resolver's `MemberReceiver::Name` lookup in commit 5: ExplicitType
/// wins over Construction (and over FactoryReturn) per the locked
/// conflict rule (declared type takes precedence over initializer).
/// Computed at emit time for `let x: C`, `const x = new C()`,
/// `function f(x: C)`, `const x = f(…)` where `f` is a factory, etc.
/// `None` — expressed via `BindingEvent.origin: Option<ClassOrigin>`
/// — covers bindings without a class-resolvable origin (still emitted
/// to block outer-scope fallback per the shadowing rule).
///
/// v0.6 conflict-rule precedence (locked in
/// `docs/v0.6-factory-return-inference-goal.md` §"Conflict rule"):
///
/// ```text
/// ExplicitType   wins over   Construction   wins over   FactoryReturn
/// ```
///
/// In practice Construction and FactoryReturn cannot collide at the
/// same emission site because the initializer expression is exactly
/// one of `new C()` (Construction) or `f(…)` (FactoryReturn) — the
/// precedence order is structural insurance against future parser
/// refactors that might accidentally double-emit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClassOrigin {
    /// `let x: C` / `const x: C = …` / `function f(x: C)`. Explicit
    /// declared type wins over any initializer.
    ExplicitType { class_name: String },
    /// `const x = new C()` / `let x = new C()` — no type annotation.
    Construction { class_name: String },
    /// v0.6 commit 1 — `const x = f(…)` or `const x = S.create(…)`
    /// where `f` / `S.create`'s declared return type is a plain-Ident
    /// class name. The factory's identity is captured at parse time
    /// (`FactoryRef`); the class lookup happens at resolve time by
    /// walking the project's global function-returns index (built from
    /// per-file `function_returns` sidecars + `DeclEvent::Method`
    /// `return_class_name` fields).
    ///
    /// Resolver path lands in commit 4 (`FactoryRef::Plain`) and
    /// commit 5 (`FactoryRef::Static`). Commit 1 is data-shape only —
    /// no parser emission, no resolver consumption yet.
    FactoryReturn { factory_ref: FactoryRef },
}

/// v0.6 commit 1 — identity of the factory whose declared return type
/// determines a `FactoryReturn`-origin binding's class. Two variants
/// because plain-function factories and static-method factories
/// resolve via different lookup paths (per-file `function_returns`
/// sidecar vs class-walk to `DeclEvent::Method.return_class_name`).
///
/// Both variants are emitted by the parser optimistically — without
/// checking whether the named factory is actually in scope. The
/// resolver returns `None` if the lookup fails (matching the v0.5
/// pattern for unresolvable receivers).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactoryRef {
    /// `const x = f(…)` — `name` is the bare function ident at the
    /// call site. Resolver looks it up in the current file's
    /// `function_returns` sidecar first; if not found, walks the
    /// value-namespace import table for `name` and looks up the
    /// imported file's sidecar.
    Plain { name: String },
    /// `const x = S.create(…)` — receiver is a Class name in value
    /// position; member is a static method on the class. Resolver
    /// looks up `class_name` in the value-namespace (existing v0.5
    /// path), finds the Class node, walks its `Contains` edges to
    /// the matching `Property` node with `(name = method_name,
    /// is_static = true)`, and reads `Property.return_class_name`.
    Static {
        class_name: String,
        method_name: String,
    },
}

/// v0.6 commit 1 — per-file sidecar entry capturing the declared
/// return type of a plain-function or const-arrow declaration. Only
/// plain-Ident return types are captured (mirrors v0.5's
/// `ExplicitType` rule); union returns (`: C | null`), generic inner
/// returns (`: Promise<C>`), object-literal returns (`: { client:
/// C }`), and bodies without a declared return type produce no entry.
///
/// Generic factories with a plain-Ident inner type
/// (`function f<T>(): C<T> {…}`) are normalized at extraction time:
/// generics are stripped, the inner `C` is captured.
///
/// Class methods are NOT in this sidecar — their return types live
/// on `DeclEvent::Method.return_class_name`. Static-method factory
/// resolution composes through the Class node + Property walk, not
/// through this sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionReturn {
    /// Bare function name. For `const f = (): C => …`, this is `f`
    /// (the binding name, not the arrow's anonymous identity).
    pub name: String,
    /// Plain-Ident class name from the declared return type.
    pub class_name: String,
    /// `decl_index` of the function-like declaration this entry
    /// describes. For plain functions this is the
    /// `DeclEvent::Function`'s decl_index; for const-arrow factories
    /// this is the synthesized `DeclEvent::Variable`'s decl_index.
    pub decl_index: u32,
}

/// A lexical-binding fact emitted by the parser. Not a graph node —
/// these are ephemeral records the resolver consumes to gate
/// `MemberAccess` receiver lookups. Top-level `let`/`const` continue
/// to emit `DeclEvent::Variable` (graph-visible) in addition to a
/// `BindingEvent` (lexical-only). Function-body bindings emit only the
/// `BindingEvent` (no graph node). Emission lands in commit 3; the
/// type is declared in commit 2 for the future emitters to attach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingEvent {
    pub name: String,
    pub scope: ScopeId,
    /// `Some(origin)` when the binding has a class-resolvable origin
    /// (annotation or `new C()` initializer). `None` when present but
    /// not class-typed — still emitted so the resolver's shadowing
    /// rule can short-circuit at this binding instead of walking past
    /// it to an outer-scope class of the same name.
    pub origin: Option<ClassOrigin>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalValueDecl {
    pub name: String,
    pub scope: ScopeId,
    pub decl_index: u32,
    pub owner_decl_index: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    Decl(DeclEvent),
    Ref(RefEvent),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeclEvent {
    Function {
        name: String,
        name_span: Span,
        decl_span: Span,
        body_span: Span,
    },
    Class {
        name: String,
        name_span: Span,
        decl_span: Span,
        body_span: Span,
        extends: Vec<HeritageRef>,
        implements: Vec<HeritageRef>,
    },
    Interface {
        name: String,
        name_span: Span,
        decl_span: Span,
        body_span: Span,
        extends: Vec<HeritageRef>,
    },
    Namespace {
        name: String,
        name_span: Span,
        decl_span: Span,
        body_span: Span,
    },
    TypeAlias {
        name: String,
        name_span: Span,
        decl_span: Span,
    },
    Enum {
        name: String,
        name_span: Span,
        decl_span: Span,
        body_span: Span,
    },
    Variable {
        name: String,
        name_span: Span,
        decl_span: Span,
    },
    /// A class member: instance/static method, getter, setter, or
    /// field. Emitted by the parser when a class-body element has a
    /// resolvable name shape (plain Ident, computed-name with a
    /// string-literal bracket key, or `#`-prefixed private name).
    ///
    /// v0.5 commit 1 widened this from "Ident-named methods only" to
    /// cover all class members. `is_static` is captured from the
    /// `static` modifier; `kind` distinguishes method/getter/setter/
    /// field. Parameter-property fields in constructors
    /// (`constructor(public foo: T)`) emit Field DeclEvents at the
    /// class level with `is_static=false`. The carrier variant keeps
    /// the historical name `Method` — a wider rename to `Member`
    /// awaits the v0.5 commit-4 enum rename (per plan doc).
    ///
    /// The resolver creates a `NodeKind::Property` node from this
    /// event with a **`Contains` edge from the owning Class node**
    /// (not the File). Lookup by `decl_index` of the parent class —
    /// the parser sets `owner_class_decl_index` when the class is
    /// currently on its owner stack.
    Method {
        name: String,
        name_span: Span,
        decl_span: Span,
        /// `Span::ABSENT` for abstract methods, overload signatures,
        /// and fields (no `{ … }` body) — otherwise the body braces
        /// span. Fields always emit Span::ABSENT here even though
        /// they may have an initializer expression; the body_span
        /// slot encodes presence-of-braces, not presence-of-content.
        body_span: Span,
        /// `decl_index` of the enclosing Class's DeclEvent — set by
        /// the parser when this method is emitted while a Class is on
        /// the parser's owner stack. Resolver uses it to look up the
        /// already-created Class NodeId and wire the Contains edge.
        owner_class_decl_index: u32,
        /// `true` when the member carries a `static` modifier. The
        /// resolver gates `Class.m()` dispatch (Pattern 5) to
        /// `is_static=true` only — instance-method-via-class-name
        /// no longer resolves (v0.4 overmatch fix).
        is_static: bool,
        /// Member-shape classification — drives the resolver's
        /// access-kind gate (Call → Method, Read → Getter/Field,
        /// Write → Setter/Field). v0.5 commit 1 emits all four
        /// variants; commit-4+ wires Read/Write access shapes.
        kind: MemberKind,
        /// v0.6 commit 1 — plain-Ident class name from the method's
        /// declared return type, when present. `None` when the
        /// method has no annotation, returns a non-Ident type, or
        /// returns void/never/primitive. Only populated for
        /// `is_static: true` methods per v0.6 Q4 (instance-method
        /// factories are out of scope, paired with v0.7 property
        /// chains). Empty in commit 1 (parser extraction lands in
        /// commit 2); consumed by the resolver in commit 5
        /// (`FactoryRef::Static` arm).
        return_class_name: Option<String>,
        /// v0.7 commit 1 — plain-Ident class name from the
        /// member's declared field type, when present and the
        /// member's `kind` is `MemberKind::Field`. `None` for
        /// methods, getters, setters, and fields with no
        /// annotation / union / non-Ident type. Same plain-Ident
        /// + generic-strip rules as v0.6 `return_class_name`.
        ///
        /// Resolver builds `field_type_class_by_property_node:
        /// HashMap<NodeId, (String, file_idx)>` from this field
        /// at Pass 2 + the existing post-pass index build, in
        /// the same shape as v0.6 `method_return_class`. Consumed
        /// by the resolver's `MemberReceiver::PropertyChain`
        /// recursive arm (commit 4).
        ///
        /// Commit 1 data shape only; parser populates in commit 2.
        field_type_class: Option<String>,
    },
    /// A function-valued member of an object literal owned by an
    /// enclosing declaration. This covers service-shaped TypeScript
    /// implementations such as Effect `Layer.effect(..., () => ({
    /// confirm: (...) => ... }))` and factories returning object APIs.
    ///
    /// The resolver materializes this as `NodeKind::Property` with a
    /// `Contains` edge from `owner_decl_index`'s node, not from the File.
    /// It does not enter value or type namespaces; it is queryable through
    /// impact lookup as a nested property surface.
    ServiceMember {
        name: String,
        name_span: Span,
        decl_span: Span,
        body_span: Span,
        owner_decl_index: u32,
        kind: MemberKind,
    },
}

/// Class-member shape classification. Emitted by the parser on each
/// class-body element and used by the resolver to gate
/// `MemberAccess` lookups against the correct candidate member.
///
/// `Method` covers plain instance/static methods. `Getter`/`Setter`
/// cover `get foo()` / `set foo(v)` accessors. `Field` covers
/// declared properties (`foo = 1`, `foo: T`, `static foo = …`,
/// parameter-property fields, `#`-prefixed private fields). The
/// resolver semantics for read/write access composition land in
/// commit 4; commit 1 emits the classification and gates Pattern-5
/// dispatch to (is_static=true, Method) only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemberKind {
    Method,
    Getter,
    Setter,
    Field,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeritageRef {
    pub name: String,
    pub ref_span: Span,
}

/// One argument-interior anchor captured at parse time for a `Call`'s
/// argument list (G1.6 spec §7 fork resolution (a)). Defined in
/// `crate::schema` (not here) for the same cross-cutting reason
/// `TypeRefPosition` lives there rather than in this module: both the
/// parser-event shape (here) and the builder/CSR layer (`builder.rs`,
/// `csr.rs`) need it, and `schema` is the shared home neither layer has to
/// reach "up" or "down" out of its own layering to depend on.
pub use crate::schema::CallArgumentAnchor;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefEvent {
    Import {
        specifier: String,
        specifier_span: Span,
        bindings: Vec<ImportBinding>,
        is_type_only: bool,
        /// True only for static `import ...` declarations, whose presence makes
        /// a TypeScript file an external module. Synthetic import edges from
        /// triple-slash directives, `declare module "x"`, and dynamic
        /// `import("x")`/`require("x")` calls still model dependency edges but
        /// must not change declaration-file global scoping.
        makes_external_module: bool,
    },
    Call {
        name: String,
        call_span: Span,
        /// Enclosing declaration's `decl_index`, or `None` for top-level
        /// (module-init) refs. Set by the parser's owner stack.
        owner: Option<u32>,
        /// Lexical scope at the call site. Used by the resolver for
        /// function-local declarations before falling back to file-level
        /// declarations and imports.
        scope: ScopeId,
        /// G1.6 fork (a) interior anchors: callback-literal head spans and
        /// object-literal key paths found while GENERICALLY scanning this
        /// call's argument list (no type knowledge, no chain filtering —
        /// that's the walk side's job later). Empty for the overwhelming
        /// majority of calls (`Vec::new()` does not allocate). Patched in
        /// after the argument list is scanned, alongside `call_span` above.
        argument_anchors: Vec<CallArgumentAnchor>,
    },
    ValueRef {
        name: String,
        ref_span: Span,
        owner: Option<u32>,
        scope: ScopeId,
    },
    /// `typeof Foo` in a type position. Syntactically this names the value
    /// namespace first, but TypeScript also permits type-only imports and
    /// declarations to appear under `typeof` in declaration files and inferred
    /// type surfaces. The resolver treats this as a value-first lookup with a
    /// type-namespace fallback instead of a plain runtime ValueRef.
    TypeQueryRef {
        name: String,
        ref_span: Span,
        owner: Option<u32>,
        scope: ScopeId,
    },
    TypeRef {
        name: String,
        ref_span: Span,
        owner: Option<u32>,
        scope: ScopeId,
        /// Parse-time classification of WHERE this type reference occurred
        /// (annotation head, return-type, declaration-site constraint,
        /// union/intersection/conditional composition member, or expression
        /// position). G1.5 Fix 2 (F2-2): set by the parser at emit time; read
        /// by the resolver (F2-3) to weight `type_surface` pressure. `Other`
        /// is fail-open ("no information"). `#[serde(default)]` keeps legacy
        /// serialized events (pre-F2-2, no field) decoding as `Other`.
        #[serde(default)]
        position: TypeRefPosition,
    },
    /// Qualified type reference through a namespace-like receiver:
    /// `NS.Type`. The parser still emits the root `TypeRef(NS)` for
    /// compatibility; this sidecar lets the resolver connect the member name
    /// when `NS` is a local `import * as NS from './module'` binding.
    TypeMemberAccess {
        namespace: String,
        member: String,
        ref_span: Span,
        owner: Option<u32>,
        scope: ScopeId,
        /// Parse-time `TypeRefPosition` classification (G1.5 F2-4 Part C),
        /// captured from the SAME base classification context as the
        /// sibling root `TypeRef(NS)` emitted alongside it, and retagged to
        /// `CompositionMember` by the same union/intersection mechanism
        /// (F2-2b) when `NS.Type` is a bare union/intersection member —
        /// e.g. `core.$ZodIPv4Params` in `string | core.$ZodIPv4Params`.
        /// `#[serde(default)]` keeps legacy serialized events (pre-F2-4, no
        /// field) decoding as `Other` (fail-open, never a signal).
        #[serde(default)]
        position: TypeRefPosition,
    },
    /// Property access on a receiver: call (`x.m(…)` /
    /// `x['m'](…)`), read (`x.m`), or write (`x.m = …`). The
    /// parser normalizes string-literal bracket access to its
    /// dot-access form at emit time. Receiver provenance is
    /// captured by `MemberReceiver`.
    ///
    /// **v0.5 commit 4 scope (data-shape unification):**
    /// MemberAccess events are emitted for all receiver shapes
    /// (This / Name / Constructed) and all access kinds (Call /
    /// Read / Write), but the resolver only converts Call-access
    /// with a receiver that resolves to a Class into a `Calls`
    /// edge. Name receivers go through the scope-walk + binding
    /// lookup chain in commit 5 (resolver-scoped-lookup); for
    /// commit 4, Name receivers continue to resolve only when
    /// the name itself is a Class in the value namespace
    /// (preserves the v0.4 / commit-1 Pattern-5 / Pattern-7
    /// behavior). Constructed receivers and Read/Write access
    /// shapes silently drop in commit 4.
    MemberAccess {
        receiver: MemberReceiver,
        member: String,
        access: AccessKind,
        site_span: Span,
        owner: Option<u32>,
        /// G1.9 S1: the same §7 fork (a) argument-interior anchors
        /// `RefEvent::Call::argument_anchors` carries, scanned generically
        /// (no type knowledge, no chain filtering) from this member call's
        /// own argument list when `access == AccessKind::Call`. Empty for
        /// `Read`/`Write` (no argument list exists) and for the
        /// overwhelming majority of `Call` accesses (`Vec::new()` does not
        /// allocate). Patched in after the argument list is scanned,
        /// mirroring `Call`'s own placeholder-then-patch shape.
        argument_anchors: Vec<CallArgumentAnchor>,
    },
}

/// Receiver of a `MemberAccess` event. Captures enough provenance
/// for the resolver to scope the receiver to a `Class` node. The
/// scope-walk that resolves `Name` receivers through the binding
/// chain lands in commit 5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberReceiver {
    /// `this.member` — resolved via owner-stack walk to enclosing
    /// class. Implies instance dispatch (`is_static_gate = false`).
    This,
    /// `name.member` where `name` is a bare ident in value position.
    /// `scope` is the lexical scope at the access site; commit 5
    /// uses it to walk the BindingEvent chain for
    /// shadowing-correct lookup. Commit 4 ignores `scope` and
    /// falls back to the pre-existing class-name-in-value-namespace
    /// lookup so behavior matches the v0.4 Pattern-5 / commit-1
    /// Pattern-7 surface.
    Name { name: String, scope: ScopeId },
    /// `new ClassName(...).member` — class name captured at the
    /// `new` keyword. Implies instance dispatch on the freshly-
    /// constructed receiver. Resolver wires in commit 5.
    Constructed { class_name: String },
    /// v0.7 commit 1 — `expr.foo.method()` where `expr.foo` is a
    /// property-access receiver. `base` is the MemberReceiver for
    /// `expr` (recursively, so `a.b.c.method()` nests as
    /// `PropertyChain { base: PropertyChain { base: Name {a, …},
    /// member: "b" }, member: "c" }`). `member` is the field name
    /// being walked off `base`.
    ///
    /// Resolver walks `base` to a class via the v0.5/v0.6 path
    /// (recursive), looks up `member` as a `(_, Field, member)`
    /// Property on that class, reads the field's
    /// `field_type_class`, and uses the resulting class as the
    /// receiver for the next chain step (or the final method
    /// dispatch). Bounded by `MAX_PROPERTY_CHAIN_DEPTH` at the
    /// resolver to prevent pathological inputs from blowing the
    /// resolver-time budget.
    ///
    /// Commit 1 data shape only — no parser emission, no resolver
    /// consumption. Parser emission lands in commit 3, resolver
    /// in commit 4.
    PropertyChain {
        base: Box<MemberReceiver>,
        member: String,
    },
}

/// Access shape of a `MemberAccess` event. Drives the resolver's
/// member-kind gate in commit 5: Call→Method, Read→Getter/Field,
/// Write→Setter/Field. In commit 4 only `Call` resolves; `Read`
/// and `Write` are emitted but silently dropped by the resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessKind {
    /// `x.m(...)` — gates to `MemberKind::Method`.
    Call,
    /// `x.m` (no parens, not on assignment LHS) — gates to
    /// `MemberKind::Getter` or `MemberKind::Field`.
    Read,
    /// `x.m = expr` (assignment LHS, including compound assigns
    /// like `+=`/`**=`/`&&=`/`||=`/`??=`) — gates to
    /// `MemberKind::Setter` or `MemberKind::Field`.
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportBinding {
    pub local: String,
    pub exported: String,
    pub local_span: Span,
    pub kind: BindingKind,
    /// True for an inline per-binding type-only import (`import { type Foo }`)
    /// — distinct from the file-level `RefEvent::Import.is_type_only`. A
    /// type-only binding populates only the type namespace at resolve time.
    pub is_type_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingKind {
    Named,
    Default,
    Namespace,
    SideEffect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportEntry {
    /// `export function foo` / `export class C` / `export const x` /
    /// `export default ...`. `exported` is the externally-visible name:
    /// usually the decl's own name, or `"default"` for default-exported
    /// decls (both `export default function foo` AND anonymous
    /// `export default <expr>`). Anonymous default exports synthesize a
    /// `DeclEvent::Variable { name: "default", ... }` so this variant —
    /// not `Named` — always represents them (see Task 13 r3).
    Direct {
        decl_index: u32,
        exported: String,
    },
    Named {
        local: String,
        exported: String,
        ref_span: Span,
        /// `export type { X }` / `export { type X }` — re-exported in the type
        /// namespace only.
        is_type_only: bool,
    },
    NamedFrom {
        local: String,
        exported: String,
        from: String,
        ref_span: Span,
        from_span: Span,
        is_type_only: bool,
    },
    Namespace {
        from: String,
        from_span: Span,
    },
    NamespaceAs {
        local: String,
        from: String,
        local_span: Span,
        from_span: Span,
    },
}
