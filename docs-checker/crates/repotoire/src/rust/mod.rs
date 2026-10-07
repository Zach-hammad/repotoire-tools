//! Bounded Rust syntax extraction backed by rust-analyzer's parser.
//!
//! The parser rejects invalid input before producing [`ParsedFile`]. It does
//! not expand macros or perform type inference.

pub mod events;
pub mod parser;
pub mod resolver;

pub use events::{
    ParsedFile, RustItem, RustItemKind, RustMacroCall, RustUse, RustUseBinding, RustValueBinding,
};
pub use parser::{
    parse_file, RustEdition, RustParseError, RustParseMode, RustParseOptions, RustSyntaxDiagnostic,
    MAX_RUST_SOURCE_BYTES,
};
pub use resolver::{
    extract_project, graph_item_name, module_path_for_file, resolve_and_emit,
    resolve_native_evidence_units, ExtractError, ExtractOptions, ExtractResult, NativeEvidenceUnit,
};
