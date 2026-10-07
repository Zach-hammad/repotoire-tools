//! TypeScript extractor — hand-rolled lexer + recursive-descent parser +
//! project-level resolver. See docs/superpowers/specs/2026-05-18-ts-extractor-design.md.

pub mod alias;
pub mod canonicalize;
pub mod diagnostics;
pub mod directives;
mod environment;
pub mod events;
pub mod lexer;
#[cfg(feature = "oxc-shadow")]
pub mod oxc_shadow;
pub mod parser;
pub mod resolver;

pub use alias::{AliasEntry, AliasMap};
pub use diagnostics::{Diagnostic, DiagnosticKind, RefPosition};
pub use events::{
    BindingKind, DeclEvent, Event, ExportEntry, HeritageRef, ImportBinding, ParsedFile, RefEvent,
};
pub use parser::parse_file;
pub use resolver::{
    extract_project, extract_project_with_options, resolve_and_emit, resolve_native_evidence_units,
    resolve_native_evidence_units_with_options, resolve_native_evidence_units_with_resolver_units,
    ExtractError, ExtractOptions, ExtractResult, NativeEvidenceUnit,
};
