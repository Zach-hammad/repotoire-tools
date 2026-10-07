use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::source_pipeline::{source_language_for_path, SourceLanguage};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Language {
    #[serde(rename = "typescript")]
    TypeScript,
    #[serde(rename = "rust")]
    Rust,
    #[serde(rename = "python")]
    Python,
}

impl Language {
    pub fn from_key(value: &str) -> Option<Self> {
        match value {
            "typescript" => Some(Language::TypeScript),
            "rust" => Some(Language::Rust),
            "python" => Some(Language::Python),
            _ => None,
        }
    }

    pub const fn key(self) -> &'static str {
        match self {
            Language::TypeScript => "typescript",
            Language::Rust => "rust",
            Language::Python => "python",
        }
    }

    pub fn subsystem(self) -> &'static str {
        match self {
            Language::TypeScript => "typescript graph extraction",
            Language::Rust => "rust graph extraction",
            Language::Python => "python graph extraction",
        }
    }
}

/// Classify a source path once, then convert the canonical source-pipeline
/// language into the truth model used by observers and compiler adapters.
pub fn language_for_source_path(path: &Path) -> Option<Language> {
    match source_language_for_path(path) {
        SourceLanguage::TypeScript => Some(Language::TypeScript),
        SourceLanguage::Rust => Some(Language::Rust),
        SourceLanguage::Python => Some(Language::Python),
        SourceLanguage::Unknown => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceSpan {
    pub start: u32,
    pub len: u32,
}

impl SourceSpan {
    pub const fn new(start: u32, len: u32) -> Self {
        Self { start, len }
    }

    pub const fn end(&self) -> u32 {
        self.start + self.len
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthSource {
    pub name: String,
    pub version: String,
    pub docs_url: String,
}

impl TruthSource {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        docs_url: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            docs_url: docs_url.into(),
        }
    }

    pub fn typescript_compiler(version: impl Into<String>) -> Self {
        Self::new(
            "typescript-compiler",
            version,
            "https://github.com/microsoft/TypeScript/wiki/Using-the-Compiler-API",
        )
    }

    pub fn tsserver(version: impl Into<String>) -> Self {
        Self::new(
            "tsserver",
            version,
            "https://github.com/microsoft/TypeScript/wiki/Standalone-Server-%28tsserver%29",
        )
    }

    pub fn oxc_shadow(version: impl Into<String>) -> Self {
        Self::new(
            "oxc-shadow",
            version,
            "https://oxc.rs/docs/guide/usage/parser.html",
        )
    }

    pub fn rust_analyzer(version: impl Into<String>) -> Self {
        Self::new(
            "rust-analyzer",
            version,
            "https://rust-analyzer.github.io/manual.html",
        )
    }

    pub fn rustdoc_json(version: impl Into<String>) -> Self {
        Self::new(
            "rustdoc-json",
            version,
            "https://doc.rust-lang.org/rustdoc/json.html",
        )
    }

    pub fn cargo_metadata(version: impl Into<String>) -> Self {
        Self::new(
            "cargo-metadata",
            version,
            "https://doc.rust-lang.org/cargo/commands/cargo-metadata.html",
        )
    }

    pub fn rustc_diagnostics(version: impl Into<String>) -> Self {
        Self::new(
            "rustc-diagnostics",
            version,
            "https://doc.rust-lang.org/rustc/json.html",
        )
    }

    pub fn cpython_ast(version: impl Into<String>) -> Self {
        Self::new(
            "cpython-ast",
            version,
            "https://docs.python.org/3/library/ast.html",
        )
    }

    pub fn importlib_modulegraph(version: impl Into<String>) -> Self {
        Self::new(
            "importlib-modulegraph",
            version,
            "https://docs.python.org/3/library/importlib.html",
        )
    }

    pub fn pytest_runtime_witness(version: impl Into<String>) -> Self {
        Self::new(
            "pytest-runtime-witness",
            version,
            "https://docs.pytest.org/",
        )
    }

    pub fn runtime_witness(version: impl Into<String>) -> Self {
        Self::new("runtime-witness", version, "https://docs.rs/repotoire")
    }

    pub fn repotoire(version: impl Into<String>) -> Self {
        Self::new("repotoire", version, "https://github.com/")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthSourceAssumption {
    pub source: TruthSource,
    pub assumption: String,
    pub evidence_url: String,
}

impl TruthSourceAssumption {
    pub fn new(
        source: TruthSource,
        assumption: impl Into<String>,
        evidence_url: impl Into<String>,
    ) -> Self {
        Self {
            source,
            assumption: assumption.into(),
            evidence_url: evidence_url.into(),
        }
    }

    pub fn typescript_compiler() -> Self {
        Self::new(
            TruthSource::typescript_compiler("recorded-at-runtime"),
            "TypeScript compiler AST and checker output are authoritative for parseable TypeScript syntax and symbol binding.",
            "https://github.com/microsoft/TypeScript/wiki/Using-the-Compiler-API",
        )
    }

    pub fn tsserver() -> Self {
        Self::new(
            TruthSource::tsserver("recorded-at-runtime"),
            "tsserver reference and navigation responses are authority for editor-visible TypeScript symbol relationships.",
            "https://github.com/microsoft/TypeScript/wiki/Standalone-Server-%28tsserver%29",
        )
    }

    pub fn oxc_shadow() -> Self {
        Self::new(
            TruthSource::oxc_shadow("recorded-at-runtime"),
            "Oxc shadow parsing is corroborating parser evidence, not a replacement for TypeScript compiler truth.",
            "https://oxc.rs/docs/guide/usage/parser.html",
        )
    }

    pub fn rust_analyzer() -> Self {
        Self::new(
            TruthSource::rust_analyzer("recorded-at-runtime"),
            "rust-analyzer syntax samples are authority for parseable Rust item structure.",
            "https://rust-analyzer.github.io/manual.html",
        )
    }

    pub fn rustdoc_json() -> Self {
        Self::new(
            TruthSource::rustdoc_json("recorded-at-runtime"),
            "rustdoc JSON is authority for exported Rust API surface when available.",
            "https://doc.rust-lang.org/rustdoc/json.html",
        )
    }

    pub fn cargo_metadata() -> Self {
        Self::new(
            TruthSource::cargo_metadata("recorded-at-runtime"),
            "cargo metadata is authority for Rust package and module graph context.",
            "https://doc.rust-lang.org/cargo/commands/cargo-metadata.html",
        )
    }

    pub fn rustc_diagnostics() -> Self {
        Self::new(
            TruthSource::rustc_diagnostics("recorded-at-runtime"),
            "rustc diagnostics explain syntax/type gaps that RepoToire must not guess through.",
            "https://doc.rust-lang.org/rustc/json.html",
        )
    }

    pub fn cpython_ast() -> Self {
        Self::new(
            TruthSource::cpython_ast("recorded-at-runtime"),
            "CPython ast output is authority for parseable Python syntax structure.",
            "https://docs.python.org/3/library/ast.html",
        )
    }

    pub fn importlib_modulegraph() -> Self {
        Self::new(
            TruthSource::importlib_modulegraph("recorded-at-runtime"),
            "importlib/modulegraph evidence is authority for import resolution when static AST is insufficient.",
            "https://docs.python.org/3/library/importlib.html",
        )
    }

    pub fn runtime_witness() -> Self {
        Self::new(
            TruthSource::runtime_witness("recorded-at-runtime"),
            "Runtime witness traces are authority for observed dynamic behavior in the recorded run.",
            "https://docs.rs/repotoire",
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphFactKind {
    Node,
    Edge,
    Span,
    Kind,
    Owner,
    Import,
    Export,
    Call,
    TypeRef,
    ModuleRef,
    Route,
    Query,
    Test,
    DynamicWitness,
    CrossFileDependent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphFactSource {
    pub role: GraphFactSourceRole,
    pub truth_source: TruthSource,
}

impl GraphFactSource {
    pub fn truth(truth_source: TruthSource) -> Self {
        Self {
            role: GraphFactSourceRole::Truth,
            truth_source,
        }
    }

    pub fn repotoire(version: impl Into<String>) -> Self {
        Self {
            role: GraphFactSourceRole::RepoToire,
            truth_source: TruthSource::repotoire(version),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphFactSourceRole {
    RepoToire,
    Truth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphFact {
    pub kind: GraphFactKind,
    pub file: String,
    pub graph_kind: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub span: SourceSpan,
    pub fact_source: GraphFactSource,
}

impl GraphFact {
    /// Canonical capability surface for this semantic fact.
    ///
    /// Parsers, truth adapters, readiness, and calibration all consume this
    /// mapping so language-specific producers cannot drift into separate
    /// surface taxonomies.
    pub fn surface_key(&self, language: Language) -> Option<&'static str> {
        let kind = match self.kind {
            GraphFactKind::Import => "import",
            GraphFactKind::Export => "export",
            GraphFactKind::Call => "call",
            GraphFactKind::TypeRef => "type_ref",
            GraphFactKind::ModuleRef => "module_ref",
            GraphFactKind::CrossFileDependent => "cross_file_dependent",
            GraphFactKind::Route => "route",
            GraphFactKind::Query => "query",
            GraphFactKind::Test => "test",
            _ => self.graph_kind.as_str(),
        };
        surface_key_for_fact_kind(language, kind)
    }

    pub fn node(
        file: impl Into<String>,
        graph_kind: impl Into<String>,
        name: impl Into<String>,
        owner: Option<&str>,
        span: SourceSpan,
        fact_source: GraphFactSource,
    ) -> Self {
        Self {
            kind: GraphFactKind::Node,
            file: file.into(),
            graph_kind: graph_kind.into(),
            name: name.into(),
            owner: owner.map(str::to_string),
            source: None,
            target: None,
            span,
            fact_source,
        }
    }

    pub fn edge(
        file: impl Into<String>,
        graph_kind: impl Into<String>,
        source: impl Into<String>,
        target: impl Into<String>,
        owner: Option<&str>,
        span: SourceSpan,
        fact_source: GraphFactSource,
    ) -> Self {
        let graph_kind = graph_kind.into();
        let source = source.into();
        let target = target.into();
        Self {
            kind: edge_fact_kind(&graph_kind),
            file: file.into(),
            graph_kind: graph_kind.clone(),
            name: graph_kind,
            owner: owner.map(str::to_string),
            source: Some(source),
            target: Some(target),
            span,
            fact_source,
        }
    }

    pub fn dynamic_witness(
        file: impl Into<String>,
        evidence_kind: impl Into<String>,
        target: impl Into<String>,
        span: SourceSpan,
        fact_source: GraphFactSource,
    ) -> Self {
        let evidence_kind = evidence_kind.into();
        Self {
            kind: GraphFactKind::DynamicWitness,
            file: file.into(),
            graph_kind: evidence_kind.clone(),
            name: evidence_kind,
            owner: None,
            source: None,
            target: Some(target.into()),
            span,
            fact_source,
        }
    }

    pub fn route(
        file: impl Into<String>,
        route: impl Into<String>,
        owner: Option<&str>,
        span: SourceSpan,
        fact_source: GraphFactSource,
    ) -> Self {
        Self {
            kind: GraphFactKind::Route,
            file: file.into(),
            graph_kind: "route".to_string(),
            name: route.into(),
            owner: owner.map(str::to_string),
            source: None,
            target: None,
            span,
            fact_source,
        }
    }

    pub fn query(
        file: impl Into<String>,
        query: impl Into<String>,
        owner: Option<&str>,
        span: SourceSpan,
        fact_source: GraphFactSource,
    ) -> Self {
        Self {
            kind: GraphFactKind::Query,
            file: file.into(),
            graph_kind: "query".to_string(),
            name: query.into(),
            owner: owner.map(str::to_string),
            source: None,
            target: None,
            span,
            fact_source,
        }
    }

    pub fn test(
        file: impl Into<String>,
        name: impl Into<String>,
        owner: Option<&str>,
        span: SourceSpan,
        fact_source: GraphFactSource,
    ) -> Self {
        Self {
            kind: GraphFactKind::Test,
            file: file.into(),
            graph_kind: "test".to_string(),
            name: name.into(),
            owner: owner.map(str::to_string),
            source: None,
            target: None,
            span,
            fact_source,
        }
    }

    fn semantic_key(&self) -> FactKey {
        FactKey {
            kind: self.kind,
            file: self.file.clone(),
            graph_kind: self.graph_kind.clone(),
            name: self.name.clone(),
            owner: self.owner.clone(),
            source: self.source.clone(),
            target: self.target.clone(),
            span: self.span.clone(),
        }
    }

    fn identity_key(&self) -> FactIdentity {
        FactIdentity {
            kind: self.kind,
            file: self.file.clone(),
            name: self.name.clone(),
            source: self.source.clone(),
        }
    }

    fn is_node_like(&self) -> bool {
        matches!(
            self.kind,
            GraphFactKind::Node
                | GraphFactKind::Span
                | GraphFactKind::Kind
                | GraphFactKind::Owner
                | GraphFactKind::Route
                | GraphFactKind::Query
                | GraphFactKind::Test
        )
    }
}

/// Canonical `(language, fact kind) -> capability surface` mapping.
///
/// This is also used when readiness decodes serialized truth facts, so stored
/// reports and live [`GraphFact`] values cannot drift into separate taxonomies.
pub fn surface_key_for_fact_kind(language: Language, kind: &str) -> Option<&'static str> {
    match (language, kind) {
        (Language::TypeScript, "import" | "imports") => Some("typescript.imports"),
        (Language::TypeScript, "export" | "exports") => Some("typescript.exports"),
        (Language::TypeScript, "call" | "calls") => Some("typescript.calls"),
        (Language::TypeScript, "type_ref" | "type_refs") => Some("typescript.type_refs"),
        (Language::TypeScript, "module_ref" | "module_refs") => Some("typescript.module_refs"),
        (Language::TypeScript, "cross_file_dependent" | "cross_file_dependents") => {
            Some("typescript.cross_file_dependents")
        }
        (Language::TypeScript, "route" | "routes") => Some("typescript.routes"),
        (Language::TypeScript, "query" | "queries") => Some("typescript.queries"),
        (Language::Rust, "import" | "imports") => Some("rust.imports"),
        (Language::Rust, "call" | "calls") => Some("rust.calls"),
        (Language::Rust, "type_ref" | "type_refs") => Some("rust.type_refs"),
        (Language::Rust, "module_ref" | "module_refs") => Some("rust.module_refs"),
        (
            Language::Rust,
            "item" | "items" | "module" | "impl" | "struct" | "union" | "enum" | "trait" | "type"
            | "type_alias" | "function" | "const" | "static" | "extern_block" | "macro"
            | "associated_type" | "associated_const" | "method",
        ) => Some("rust.items"),
        (
            Language::Rust,
            "package" | "packages" | "cargo_package" | "cargo_packages" | "cargo_target:lib"
            | "cargo_target",
        ) => Some("rust.packages"),
        (Language::Rust, "macro_expansion" | "macro_expansions") => Some("rust.macro_expansion"),
        (Language::Rust, "test" | "tests") => Some("rust.tests"),
        (Language::Python, "import" | "imports") => Some("python.imports"),
        (Language::Python, "export" | "exports") => Some("python.exports"),
        (Language::Python, "call" | "calls") => Some("python.calls"),
        (Language::Python, "type_ref" | "type_refs") => Some("python.type_refs"),
        (Language::Python, "module_ref" | "module_refs") => Some("python.module_refs"),
        (Language::Python, "cross_file_dependent" | "cross_file_dependents") => {
            Some("python.cross_file_dependents")
        }
        (Language::Python, "route" | "routes") => Some("python.routes"),
        (Language::Python, "query" | "queries") => Some("python.queries"),
        (Language::Python, "test" | "tests") => Some("python.tests"),
        _ => None,
    }
}

fn edge_fact_kind(graph_kind: &str) -> GraphFactKind {
    match graph_kind {
        "imports" => GraphFactKind::Import,
        "exports" => GraphFactKind::Export,
        "calls" => GraphFactKind::Call,
        "type_ref" | "type_refs" => GraphFactKind::TypeRef,
        "module_ref" | "module_refs" => GraphFactKind::ModuleRef,
        "cross_file_dependent" | "cross_file_dependents" => GraphFactKind::CrossFileDependent,
        _ => GraphFactKind::Edge,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FactKey {
    kind: GraphFactKind,
    file: String,
    graph_kind: String,
    name: String,
    owner: Option<String>,
    source: Option<String>,
    target: Option<String>,
    span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FactIdentity {
    kind: GraphFactKind,
    file: String,
    name: String,
    source: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphDiffKind {
    MissingNode,
    ExtraNode,
    MissingEdge,
    ExtraEdge,
    WrongSpan,
    WrongKind,
    WrongOwner,
    WrongTarget,
    WrongCrossFileDependent,
    StaleDynamicEvidence,
    UnsupportedConstruct,
    SemanticLimit,
    TruthSourceGap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffClassification {
    BugToFix,
    UnsupportedConstruct,
    SemanticLimit,
    TruthSourceGap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationKind {
    UnsupportedConstruct,
    SemanticLimit,
    TruthSourceGap,
}

impl ExplanationKind {
    fn diff_kind(self) -> GraphDiffKind {
        match self {
            ExplanationKind::UnsupportedConstruct => GraphDiffKind::UnsupportedConstruct,
            ExplanationKind::SemanticLimit => GraphDiffKind::SemanticLimit,
            ExplanationKind::TruthSourceGap => GraphDiffKind::TruthSourceGap,
        }
    }

    fn classification(self) -> DiffClassification {
        match self {
            ExplanationKind::UnsupportedConstruct => DiffClassification::UnsupportedConstruct,
            ExplanationKind::SemanticLimit => DiffClassification::SemanticLimit,
            ExplanationKind::TruthSourceGap => DiffClassification::TruthSourceGap,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphFactMatcher {
    pub kind: GraphFactKind,
    pub graph_kind: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

impl GraphFactMatcher {
    fn from_fact(fact: &GraphFact) -> Self {
        Self {
            kind: fact.kind,
            graph_kind: fact.graph_kind.clone(),
            name: fact.name.clone(),
            owner: fact.owner.clone(),
            source: fact.source.clone(),
            target: fact.target.clone(),
        }
    }

    fn matches(&self, fact: &GraphFact) -> bool {
        self.kind == fact.kind
            && self.graph_kind == fact.graph_kind
            && self.name == fact.name
            && self.owner == fact.owner
            && self.source == fact.source
            && self.target == fact.target
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceExplanation {
    pub kind: ExplanationKind,
    pub language: Language,
    pub file: String,
    pub span: SourceSpan,
    pub diagnostic_code: String,
    pub message: String,
    pub product_impact: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_fact: Option<GraphFactMatcher>,
    pub evidence: Vec<String>,
}

impl DivergenceExplanation {
    pub fn new(
        kind: ExplanationKind,
        language: Language,
        file: impl Into<String>,
        span: SourceSpan,
        diagnostic_code: impl Into<String>,
        message: impl Into<String>,
        product_impact: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            language,
            file: file.into(),
            span,
            diagnostic_code: diagnostic_code.into(),
            message: message.into(),
            product_impact: product_impact.into(),
            graph_fact: None,
            evidence: Vec::new(),
        }
    }

    pub fn with_graph_fact(mut self, fact: &GraphFact) -> Self {
        self.file = fact.file.clone();
        self.span = fact.span.clone();
        self.graph_fact = Some(GraphFactMatcher::from_fact(fact));
        self
    }

    fn matches_fact(&self, fact: &GraphFact) -> bool {
        self.file == fact.file
            && self.span == fact.span
            && self
                .graph_fact
                .as_ref()
                .is_some_and(|matcher| matcher.matches(fact))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphDiff {
    pub kind: GraphDiffKind,
    pub classification: DiffClassification,
    pub language: Language,
    pub fixture_or_corpus_path: String,
    pub source_span: SourceSpan,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_graph_fact: Option<GraphFact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_graph_fact: Option<GraphFact>,
    pub truth_source: String,
    pub truth_source_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthDiagnostic {
    pub code: String,
    pub language: Language,
    pub file: String,
    pub span: SourceSpan,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceCard {
    pub fixture_or_corpus_path: String,
    pub language: Language,
    pub source_span: SourceSpan,
    pub expected_graph_fact: Option<GraphFact>,
    pub actual_graph_fact: Option<GraphFact>,
    pub truth_source: String,
    pub truth_source_version: String,
    pub reproduction_command: String,
    pub suspected_subsystem: String,
    pub suggested_regression_test_location: String,
    pub severity: String,
    pub product_impact: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TruthSerumScorecard {
    pub silent_divergences: u64,
    pub explained_divergences: u64,
    pub unsupported_constructs: u64,
    pub semantic_limits: u64,
    pub truth_source_gaps: u64,
    pub supported_surface_coverage: f64,
    pub truth_source_freshness: f64,
    pub fixtures_added: u64,
    pub fixed_since_last_run: u64,
    pub runtime_ms: u64,
    pub files_checked: u64,
    pub graph_facts_checked: u64,
}

impl Default for TruthSerumScorecard {
    fn default() -> Self {
        Self {
            silent_divergences: 0,
            explained_divergences: 0,
            unsupported_constructs: 0,
            semantic_limits: 0,
            truth_source_gaps: 0,
            supported_surface_coverage: 1.0,
            truth_source_freshness: 1.0,
            fixtures_added: 0,
            fixed_since_last_run: 0,
            runtime_ms: 0,
            files_checked: 1,
            graph_facts_checked: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TruthSerumPerformance {
    pub runtime_ms: u64,
    pub file_count: u64,
    pub graph_size: u64,
    pub diff_count: u64,
    pub truth_adapter_time_ms: BTreeMap<String, u64>,
    pub hot_spots: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TruthSerumReport {
    pub language: Language,
    pub fixture_or_corpus_path: String,
    pub scorecard: TruthSerumScorecard,
    pub diffs: Vec<GraphDiff>,
    pub cards: Vec<DivergenceCard>,
    pub diagnostics: Vec<TruthDiagnostic>,
    pub truth_source_assumptions: Vec<TruthSourceAssumption>,
    pub performance: TruthSerumPerformance,
}

pub fn classify_graph_facts(
    language: Language,
    fixture_or_corpus_path: &str,
    expected_truth: &[GraphFact],
    actual_repotoire: &[GraphFact],
    truth_source_assumptions: &[TruthSourceAssumption],
    explanations: &[DivergenceExplanation],
    reproduction_command: &str,
) -> TruthSerumReport {
    let mut actual_index = ActualFactIndex::new(actual_repotoire);
    actual_index.reserve_exact_matches(expected_truth);
    let mut diffs = Vec::new();
    let mut diagnostics = Vec::new();

    for expected in expected_truth {
        if let Some(actual) = actual_index.exact_match(expected) {
            if expected.kind == GraphFactKind::DynamicWitness
                && expected.fact_source.truth_source.version
                    != actual.fact_source.truth_source.version
            {
                push_diff(
                    &mut diffs,
                    &mut diagnostics,
                    PushDiffInput {
                        language,
                        fixture_or_corpus_path,
                        kind: GraphDiffKind::StaleDynamicEvidence,
                        classification: DiffClassification::BugToFix,
                        expected_graph_fact: Some(expected.clone()),
                        actual_graph_fact: Some(actual.clone()),
                        explanation: None,
                    },
                );
            }
            continue;
        }

        let (kind, actual) = actual_index
            .take_mismatch(expected)
            .map(|actual| (mismatch_kind(expected, actual), Some(actual.clone())))
            .unwrap_or_else(|| {
                (
                    if expected.is_node_like() {
                        GraphDiffKind::MissingNode
                    } else {
                        GraphDiffKind::MissingEdge
                    },
                    None,
                )
            });
        let explanation = explanations
            .iter()
            .find(|item| item.language == language && item.matches_fact(expected));
        let (kind, classification) = explanation
            .map(|explanation| {
                (
                    explanation.kind.diff_kind(),
                    explanation.kind.classification(),
                )
            })
            .unwrap_or((kind, DiffClassification::BugToFix));
        push_diff(
            &mut diffs,
            &mut diagnostics,
            PushDiffInput {
                language,
                fixture_or_corpus_path,
                kind,
                classification,
                expected_graph_fact: Some(expected.clone()),
                actual_graph_fact: actual,
                explanation,
            },
        );
    }

    let expected_semantic_keys = expected_truth
        .iter()
        .map(GraphFact::semantic_key)
        .collect::<BTreeSet<_>>();
    for actual in actual_index.unmatched_semantic_facts(&expected_semantic_keys) {
        let kind = if actual.is_node_like() {
            GraphDiffKind::ExtraNode
        } else {
            GraphDiffKind::ExtraEdge
        };
        push_diff(
            &mut diffs,
            &mut diagnostics,
            PushDiffInput {
                language,
                fixture_or_corpus_path,
                kind,
                classification: DiffClassification::BugToFix,
                expected_graph_fact: None,
                actual_graph_fact: Some(actual.clone()),
                explanation: None,
            },
        );
    }

    let cards = diffs
        .iter()
        .filter_map(|diff| build_card(diff, reproduction_command))
        .collect::<Vec<_>>();
    let scorecard = build_scorecard(expected_truth.len(), actual_repotoire.len(), &diffs);
    let performance = TruthSerumPerformance {
        runtime_ms: scorecard.runtime_ms,
        file_count: scorecard.files_checked,
        graph_size: scorecard.graph_facts_checked,
        diff_count: diffs.len() as u64,
        truth_adapter_time_ms: BTreeMap::new(),
        hot_spots: Vec::new(),
    };

    TruthSerumReport {
        language,
        fixture_or_corpus_path: fixture_or_corpus_path.to_string(),
        scorecard,
        diffs,
        cards,
        diagnostics,
        truth_source_assumptions: truth_source_assumptions.to_vec(),
        performance,
    }
}

struct ActualFactIndex<'a> {
    by_semantic: BTreeMap<FactKey, Vec<&'a GraphFact>>,
    by_identity: BTreeMap<FactIdentity, BTreeSet<FactKey>>,
    matched_semantic_keys: BTreeSet<FactKey>,
}

impl<'a> ActualFactIndex<'a> {
    fn new(facts: &'a [GraphFact]) -> Self {
        let mut by_semantic = BTreeMap::<FactKey, Vec<&GraphFact>>::new();
        let mut by_identity = BTreeMap::<FactIdentity, BTreeSet<FactKey>>::new();

        for fact in facts {
            let semantic_key = fact.semantic_key();
            by_identity
                .entry(fact.identity_key())
                .or_default()
                .insert(semantic_key.clone());
            by_semantic.entry(semantic_key).or_default().push(fact);
        }

        Self {
            by_semantic,
            by_identity,
            matched_semantic_keys: BTreeSet::new(),
        }
    }

    fn reserve_exact_matches(&mut self, expected_truth: &[GraphFact]) {
        for expected in expected_truth {
            let key = expected.semantic_key();
            if self.by_semantic.contains_key(&key) {
                self.matched_semantic_keys.insert(key);
            }
        }
    }

    fn exact_match(&self, expected: &GraphFact) -> Option<&'a GraphFact> {
        let candidates = self.by_semantic.get(&expected.semantic_key())?;
        if expected.kind == GraphFactKind::DynamicWitness {
            let expected_version = &expected.fact_source.truth_source.version;
            if let Some(actual) = candidates
                .iter()
                .copied()
                .filter(|actual| actual.fact_source.truth_source.version == *expected_version)
                .min_by(|left, right| compare_fact_sources(left, right))
            {
                return Some(actual);
            }
        }
        candidates
            .iter()
            .copied()
            .min_by(|left, right| compare_fact_sources(left, right))
    }

    fn take_mismatch(&mut self, expected: &GraphFact) -> Option<&'a GraphFact> {
        let selected_key = self
            .by_identity
            .get(&expected.identity_key())?
            .iter()
            .filter(|key| !self.matched_semantic_keys.contains(*key))
            .filter_map(|key| {
                let actual = self.representative(key)?;
                mismatch_candidate_is_eligible(expected, actual)
                    .then(|| (mismatch_rank(expected, actual), key))
            })
            .min_by(|(left_rank, left_key), (right_rank, right_key)| {
                left_rank
                    .cmp(right_rank)
                    .then_with(|| left_key.cmp(right_key))
            })
            .map(|(_, key)| key.clone())?;

        let actual = self.representative(&selected_key)?;
        let inserted = self.matched_semantic_keys.insert(selected_key);
        debug_assert!(inserted, "mismatch candidates must be consumed once");
        Some(actual)
    }

    fn representative(&self, key: &FactKey) -> Option<&'a GraphFact> {
        self.by_semantic
            .get(key)?
            .iter()
            .copied()
            .min_by(|left, right| compare_fact_sources(left, right))
    }

    fn unmatched_semantic_facts<'b>(
        &'b self,
        expected_semantic_keys: &'b BTreeSet<FactKey>,
    ) -> impl Iterator<Item = &'a GraphFact> + 'b {
        self.by_semantic
            .keys()
            .filter(|key| {
                !expected_semantic_keys.contains(*key) && !self.matched_semantic_keys.contains(*key)
            })
            .filter_map(|key| self.representative(key))
    }
}

fn compare_fact_sources(left: &GraphFact, right: &GraphFact) -> std::cmp::Ordering {
    let left_source = &left.fact_source;
    let right_source = &right.fact_source;
    left_source
        .truth_source
        .version
        .cmp(&right_source.truth_source.version)
        .then_with(|| {
            left_source
                .truth_source
                .name
                .cmp(&right_source.truth_source.name)
        })
        .then_with(|| {
            left_source
                .truth_source
                .docs_url
                .cmp(&right_source.truth_source.docs_url)
        })
        .then_with(|| {
            fact_source_role_rank(left_source.role).cmp(&fact_source_role_rank(right_source.role))
        })
}

const fn fact_source_role_rank(role: GraphFactSourceRole) -> u8 {
    match role {
        GraphFactSourceRole::RepoToire => 0,
        GraphFactSourceRole::Truth => 1,
    }
}

fn mismatch_candidate_is_eligible(expected: &GraphFact, actual: &GraphFact) -> bool {
    if expected.is_node_like() {
        return true;
    }

    (actual.span == expected.span
        && actual.source == expected.source
        && actual.owner == expected.owner)
        || (actual.target == expected.target
            && actual.source == expected.source
            && actual.owner == expected.owner
            && actual.graph_kind == expected.graph_kind)
}

fn mismatch_rank(expected: &GraphFact, actual: &GraphFact) -> (u8, u8) {
    let difference_count = u8::from(expected.kind != actual.kind)
        + u8::from(expected.graph_kind != actual.graph_kind)
        + u8::from(expected.owner != actual.owner)
        + u8::from(expected.target != actual.target)
        + u8::from(expected.span != actual.span);
    (
        difference_count,
        mismatch_kind_rank(mismatch_kind(expected, actual)),
    )
}

const fn mismatch_kind_rank(kind: GraphDiffKind) -> u8 {
    match kind {
        GraphDiffKind::WrongCrossFileDependent => 0,
        GraphDiffKind::WrongKind => 1,
        GraphDiffKind::WrongOwner => 2,
        GraphDiffKind::WrongTarget => 3,
        GraphDiffKind::WrongSpan => 4,
        _ => 5,
    }
}

fn mismatch_kind(expected: &GraphFact, actual: &GraphFact) -> GraphDiffKind {
    if expected.kind == GraphFactKind::CrossFileDependent {
        return GraphDiffKind::WrongCrossFileDependent;
    }
    if expected.graph_kind != actual.graph_kind || expected.kind != actual.kind {
        GraphDiffKind::WrongKind
    } else if expected.owner != actual.owner {
        GraphDiffKind::WrongOwner
    } else if expected.target != actual.target {
        GraphDiffKind::WrongTarget
    } else if expected.span != actual.span {
        GraphDiffKind::WrongSpan
    } else {
        GraphDiffKind::WrongTarget
    }
}

struct PushDiffInput<'a> {
    language: Language,
    fixture_or_corpus_path: &'a str,
    kind: GraphDiffKind,
    classification: DiffClassification,
    expected_graph_fact: Option<GraphFact>,
    actual_graph_fact: Option<GraphFact>,
    explanation: Option<&'a DivergenceExplanation>,
}

fn push_diff(
    diffs: &mut Vec<GraphDiff>,
    diagnostics: &mut Vec<TruthDiagnostic>,
    input: PushDiffInput<'_>,
) {
    let PushDiffInput {
        language,
        fixture_or_corpus_path,
        kind,
        classification,
        expected_graph_fact,
        actual_graph_fact,
        explanation,
    } = input;
    if let Some(explanation) = explanation {
        diagnostics.push(TruthDiagnostic {
            code: format!(
                "{}.{}",
                diagnostic_prefix(classification),
                explanation.diagnostic_code
            ),
            language: explanation.language,
            file: explanation.file.clone(),
            span: explanation.span.clone(),
            severity: "warning".to_string(),
            message: explanation.message.clone(),
        });
    }
    let source_span = expected_graph_fact
        .as_ref()
        .or(actual_graph_fact.as_ref())
        .map(|fact| fact.span.clone())
        .or_else(|| explanation.map(|explanation| explanation.span.clone()))
        .unwrap_or_else(|| SourceSpan::new(0, 0));
    let truth_source = expected_graph_fact
        .as_ref()
        .or(actual_graph_fact.as_ref())
        .map(|fact| fact.fact_source.truth_source.name.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let truth_source_version = expected_graph_fact
        .as_ref()
        .or(actual_graph_fact.as_ref())
        .map(|fact| fact.fact_source.truth_source.version.clone())
        .unwrap_or_else(|| "unknown".to_string());

    diffs.push(GraphDiff {
        kind,
        classification,
        language: explanation
            .map(|explanation| explanation.language)
            .unwrap_or(language),
        fixture_or_corpus_path: fixture_or_corpus_path.to_string(),
        source_span,
        expected_graph_fact,
        actual_graph_fact,
        truth_source,
        truth_source_version,
        diagnostic_code: explanation.map(|explanation| explanation.diagnostic_code.clone()),
        explanation: explanation.map(|explanation| explanation.message.clone()),
    });
}

fn diagnostic_prefix(classification: DiffClassification) -> &'static str {
    match classification {
        DiffClassification::BugToFix => "bug_to_fix",
        DiffClassification::UnsupportedConstruct => "unsupported_construct",
        DiffClassification::SemanticLimit => "semantic_limit",
        DiffClassification::TruthSourceGap => "truth_source_gap",
    }
}

fn build_card(diff: &GraphDiff, reproduction_command: &str) -> Option<DivergenceCard> {
    if diff.expected_graph_fact.is_none() && diff.actual_graph_fact.is_none() {
        return None;
    }
    Some(DivergenceCard {
        fixture_or_corpus_path: diff.fixture_or_corpus_path.clone(),
        language: diff.language,
        source_span: diff.source_span.clone(),
        expected_graph_fact: diff.expected_graph_fact.clone(),
        actual_graph_fact: diff.actual_graph_fact.clone(),
        truth_source: diff.truth_source.clone(),
        truth_source_version: diff.truth_source_version.clone(),
        reproduction_command: reproduction_command.to_string(),
        suspected_subsystem: diff.language.subsystem().to_string(),
        suggested_regression_test_location: "crates/repotoire/tests/parser_truth_serum.rs"
            .to_string(),
        severity: severity_for(diff.kind).to_string(),
        product_impact: product_impact_for(diff.kind).to_string(),
    })
}

fn severity_for(kind: GraphDiffKind) -> &'static str {
    match kind {
        GraphDiffKind::MissingNode
        | GraphDiffKind::MissingEdge
        | GraphDiffKind::WrongTarget
        | GraphDiffKind::WrongCrossFileDependent
        | GraphDiffKind::StaleDynamicEvidence => "high",
        GraphDiffKind::ExtraNode
        | GraphDiffKind::ExtraEdge
        | GraphDiffKind::WrongKind
        | GraphDiffKind::WrongOwner
        | GraphDiffKind::WrongSpan => "medium",
        GraphDiffKind::UnsupportedConstruct
        | GraphDiffKind::SemanticLimit
        | GraphDiffKind::TruthSourceGap => "info",
    }
}

fn product_impact_for(kind: GraphDiffKind) -> &'static str {
    match kind {
        GraphDiffKind::MissingNode => {
            "RepoToire omits a graph fact that a trusted truth source reports."
        }
        GraphDiffKind::ExtraNode => {
            "RepoToire invents a graph node that the trusted truth source does not report."
        }
        GraphDiffKind::MissingEdge => {
            "RepoToire omits a relationship that agents may need for safe repair planning."
        }
        GraphDiffKind::ExtraEdge => {
            "RepoToire invents a relationship that can mislead impact analysis."
        }
        GraphDiffKind::WrongSpan => {
            "RepoToire points agents at the wrong source bytes for a graph fact."
        }
        GraphDiffKind::WrongKind => "RepoToire assigns the wrong graph kind to a fact.",
        GraphDiffKind::WrongOwner => "RepoToire attributes a graph fact to the wrong owner.",
        GraphDiffKind::WrongTarget => {
            "RepoToire resolves a graph relationship to the wrong target."
        }
        GraphDiffKind::WrongCrossFileDependent => {
            "RepoToire reports an incorrect cross-file dependent."
        }
        GraphDiffKind::StaleDynamicEvidence => {
            "RepoToire runtime witness version does not match the trusted witness version."
        }
        GraphDiffKind::UnsupportedConstruct => {
            "RepoToire explicitly marks unsupported syntax instead of guessing."
        }
        GraphDiffKind::SemanticLimit => {
            "RepoToire documents a semantic/runtime limit backed by evidence."
        }
        GraphDiffKind::TruthSourceGap => {
            "RepoToire lacks the truth source needed to compare this graph fact."
        }
    }
}

fn build_scorecard(
    expected_count: usize,
    actual_count: usize,
    diffs: &[GraphDiff],
) -> TruthSerumScorecard {
    let mut scorecard = TruthSerumScorecard {
        graph_facts_checked: (expected_count + actual_count) as u64,
        ..TruthSerumScorecard::default()
    };
    for diff in diffs {
        match diff.classification {
            DiffClassification::BugToFix => scorecard.silent_divergences += 1,
            DiffClassification::UnsupportedConstruct => {
                scorecard.explained_divergences += 1;
                scorecard.unsupported_constructs += 1;
            }
            DiffClassification::SemanticLimit => {
                scorecard.explained_divergences += 1;
                scorecard.semantic_limits += 1;
            }
            DiffClassification::TruthSourceGap => {
                scorecard.explained_divergences += 1;
                scorecard.truth_source_gaps += 1;
            }
        }
    }
    let supported = expected_count.saturating_sub(
        diffs
            .iter()
            .filter(|diff| {
                diff.classification == DiffClassification::BugToFix
                    && diff.expected_graph_fact.is_some()
            })
            .count(),
    );
    scorecard.supported_surface_coverage = if expected_count == 0 {
        1.0
    } else {
        supported as f64 / expected_count as f64
    };
    scorecard
}
