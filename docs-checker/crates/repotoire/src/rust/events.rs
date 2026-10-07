use crate::spans::Span;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::cell::Cell;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RustItemKind {
    Module,
    Struct,
    Union,
    Enum,
    Trait,
    Impl,
    TypeAlias,
    Function,
    Const,
    AnonymousConst,
    Static,
    ExternBlock,
    Macro,
    AssociatedType,
    AssociatedConst,
    Method,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RustVisibility {
    #[default]
    Private,
    Public,
    Crate,
    Super,
    SelfModule,
    In(String),
}

impl RustVisibility {
    pub(crate) fn is_explicit(&self) -> bool {
        !matches!(self, Self::Private)
    }

    pub(crate) fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedFile {
    pub path: String,
    pub items: Vec<RustItem>,
    pub uses: Vec<RustUse>,
    /// Value names introduced below item scope (patterns, local functions, and
    /// block-local imports). These are projected from the validated syntax tree.
    pub local_value_bindings: Vec<RustValueBinding>,
    /// Item-position macro calls whose expansion requires compiler evidence.
    #[serde(default)]
    pub macro_calls: Vec<RustMacroCall>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RustValueBinding {
    pub name: String,
    /// Exact byte range in which this value binding is visible.
    pub scope: Span,
}

/// Indexed authority for deciding whether a value name is lexically bound at
/// a source offset.
///
/// Each entry stores the maximum scope end seen up to that start position. The
/// prefix maximum preserves an outer binding after a nested shadow ends while
/// keeping every lookup logarithmic in the number of same-name bindings.
#[derive(Debug, Default)]
pub(crate) struct RustValueScopeIndex {
    max_end_by_start: BTreeMap<String, Vec<(u32, u32)>>,
}

impl RustValueScopeIndex {
    pub(crate) fn new(bindings: &[RustValueBinding]) -> Self {
        let mut ranges_by_name = BTreeMap::<String, Vec<(u32, u32)>>::new();
        for binding in bindings {
            ranges_by_name
                .entry(binding.name.clone())
                .or_default()
                .push((binding.scope.start(), binding.scope.end()));
        }

        let max_end_by_start = ranges_by_name
            .into_iter()
            .map(|(name, mut ranges)| {
                ranges.sort_unstable();
                let mut max_end = 0;
                for (_, end) in &mut ranges {
                    max_end = max_end.max(*end);
                    *end = max_end;
                }
                (name, ranges)
            })
            .collect();
        Self { max_end_by_start }
    }

    pub(crate) fn binds_name(&self, name: &str, offset: u32) -> bool {
        let Some(ranges) = self.max_end_by_start.get(name) else {
            return false;
        };
        let index = ranges.partition_point(|(start, _)| *start <= offset);
        index
            .checked_sub(1)
            .and_then(|index| ranges.get(index))
            .is_some_and(|(_, max_end)| offset < *max_end)
    }
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
            items: self.items.clone(),
            uses: self.uses.clone(),
            local_value_bindings: self.local_value_bindings.clone(),
            macro_calls: self.macro_calls.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RustMacroCall {
    pub path: String,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RustItem {
    pub kind: RustItemKind,
    pub name: String,
    pub name_span: Span,
    pub decl_span: Span,
    pub signature_span: Span,
    pub body_span: Option<Span>,
    pub refs: Vec<RustRef>,
    pub children: Vec<RustItem>,
    #[serde(default)]
    pub visibility: RustVisibility,
    /// Compatibility projection for consumers that only distinguish explicit
    /// visibility from inherited private visibility. `visibility` is authoritative.
    pub is_pub: bool,
    #[serde(default)]
    /// Compatibility projection for consumers that only distinguish restricted
    /// visibility from unrestricted `pub`. `visibility` is authoritative.
    pub pub_visibility_is_restricted: bool,
    /// The implemented trait, when this item is a trait implementation.
    ///
    /// This is projected from the same validated rust-analyzer syntax tree as
    /// the rest of the item. Consumers must not re-parse `signature_span`.
    #[serde(default)]
    pub impl_trait_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RustUse {
    pub label: String,
    pub label_span: Span,
    pub bindings: Vec<RustUseBinding>,
    pub module_suffix: String,
    /// True when the import is owned by a block rather than a module.
    ///
    /// Block imports remain graph evidence, but they must not be promoted into
    /// the module-wide alias namespace.
    #[serde(default)]
    pub is_block_local: bool,
    pub public_module_path: bool,
    pub span: Span,
    #[serde(default)]
    pub visibility: RustVisibility,
    /// Compatibility projection; `visibility` is the authoritative scope.
    pub is_pub: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RustUseBinding {
    /// Canonical target path before any `as` rename.
    pub path: String,
    /// Source-facing binding label, such as `Thing as Alias`.
    pub label: String,
    pub target_name: String,
    pub export_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RustRef {
    pub span: Span,
    pub target: RustRefTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RustPathRefKind {
    Call,
    Value,
    Type,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RustRefTarget {
    Path {
        path: String,
        kind: RustPathRefKind,
    },
    MethodCall {
        receiver: String,
        receiver_type: Option<String>,
        method: String,
    },
    QualifiedTraitCall {
        self_type: String,
        trait_path: String,
        method: String,
    },
}
