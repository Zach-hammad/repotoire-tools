//! Diagnostic types emitted by the parser and resolver. See spec §7.

use crate::spans::Span;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Diagnostic {
    pub kind: DiagnosticKind,
    pub file_path: String,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DiagnosticKind {
    SyntaxRecovered { context: String },
    UnsupportedConstruct { construct: String },
    PhantomImport { specifier: String },
    UnresolvedBinding { binding: String, from_file: String },
    UnresolvedReference { name: String, position: RefPosition },
    AmbiguousReExport { name: String, sources: Vec<String> },
    ReExportCycle { files: Vec<String> },
    NamespaceImportOpaque { local: String, from: String },
    DeadExport { name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefPosition {
    Value,
    Type,
    Heritage,
}
